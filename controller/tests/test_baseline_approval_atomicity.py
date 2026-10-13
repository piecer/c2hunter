"""Real durable fault observers, separate from connection-protocol controls."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config


def snapshot(repo: Any) -> tuple:
    with closing(sqlite3.connect("file:" + repo._path + "?mode=ro", uri=True)) as raw:
        return tuple(
            raw.execute("SELECT * FROM " + table + " ORDER BY 1,2").fetchall()
            for table in (
                "baseline_scopes",
                "baseline_generations",
                "baseline_operations",
                "objects",
            )
        )


@pytest.mark.parametrize("fault", ["generation", "scope", "operation", "commit"])
def test_real_sqlite_publication_fault(tmp_path: Any, fault: str) -> None:
    with closing(SQLiteRepository(tmp_path / "fault.sqlite")) as repo:
        repo.create_baseline_scope(config(), "admin", START)
        request = prepare(repo)
        before = snapshot(repo)
        fired = []
        repo.connection.create_function("approval_fired", 0, lambda: fired.append(fault) or 1)
        table = {
            "generation": "baseline_generations",
            "scope": "baseline_scopes",
            "operation": "baseline_operations",
            "commit": "baseline_operations",
        }[fault]
        action = "SELECT RAISE(ABORT,'owned publication fault');"
        if fault == "commit":
            repo.connection.execute("CREATE TABLE approval_parent(id INTEGER PRIMARY KEY)")
            repo.connection.execute(
                "CREATE TABLE approval_child(id INTEGER REFERENCES "
                "approval_parent(id) DEFERRABLE INITIALLY DEFERRED)"
            )
            action = "INSERT INTO approval_child VALUES(1);"
        event = "UPDATE" if fault == "scope" else "INSERT"
        repo.connection.executescript(
            f"CREATE TEMP TRIGGER approval_fault AFTER {event} ON {table} BEGIN "
            f"SELECT approval_fired(); {action} END;"
        )
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert fired == [fault]
        assert snapshot(repo) == before
        assert not repo.connection.in_transaction
        repo.connection.execute("DROP TRIGGER approval_fault")
        repo.connection.commit()
        with ThreadPoolExecutor(max_workers=1) as pool:
            result = pool.submit(
                repo.publish_baseline_source, config().scope_id, request, "reviewer", START
            ).result(20)
        assert result.created
        receipt(
            {
                "backend": "sqlite",
                "fault": fault,
                "fired": len(fired),
                "independent_prestate": True,
                "idle": True,
                "cross_thread_reuse": True,
            }
        )


def test_cleanup_failure_preserves_primary(tmp_path: Any, monkeypatch: Any) -> None:
    with closing(SQLiteRepository(tmp_path / "cleanup.sqlite")) as repo:
        repo.create_baseline_scope(config(), "admin", START)
        request = prepare(repo)
        primary = TypeError("owned producer error")
        closed = []
        real = repo.connection

        class Connection:
            def __getattr__(self, name: str) -> Any:
                return getattr(real, name)

            def rollback(self) -> None:
                if fired:
                    raise RuntimeError("owned rollback error")
                real.rollback()

            def close(self) -> None:
                closed.append(True)
                real.close()
                raise RuntimeError("owned close error")

        fired = []

        def fail(*args: Any, **kwargs: Any) -> Any:
            fired.append(True)
            raise primary

        monkeypatch.setattr(bs.g, "produce_generation", fail)
        repo.connection = Connection()
        try:
            with pytest.raises(TypeError) as caught:
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            assert caught.value is primary and fired == [True] and closed == [True]
            with pytest.raises(sqlite3.ProgrammingError):
                real.execute("SELECT 1")
        finally:
            repo.connection = real
