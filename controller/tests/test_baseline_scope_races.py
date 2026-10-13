"""Independent connection races and real five-second database lock refusals."""

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_baseline_scope_faults import observer, receipt
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


def peer(repo: Any) -> Any:
    if hasattr(repo, "jobs"):
        return repo
    if hasattr(repo, "database_url"):
        return PostgresRepository(repo.database_url, None)
    return SQLiteRepository(repo._path)


@pytest.mark.parametrize("race", ["same-id", "last-slot"])
def test_catalog_serializes_independent_creators(scope_repo: Any, race: str) -> None:
    repo = scope_repo
    other = peer(repo)
    if hasattr(other, "connection"):
        assert other.connection is not None
    cfg = config()
    if race == "last-slot":
        for i in range(15):
            repo.create_baseline_scope(
                h.ScopeConfig.from_mapping(
                    dict(cfg.to_mapping(), scope_id=f"00000000-0000-0000-0000-{i:012d}")
                ),
                "admin",
                START,
            )
    barrier = threading.Barrier(2)
    second = (
        cfg
        if race == "same-id"
        else h.ScopeConfig.from_mapping(
            dict(cfg.to_mapping(), scope_id="ffffffff-ffff-ffff-ffff-ffffffffffff")
        )
    )

    def create(target: Any, value: Any) -> Any:
        barrier.wait(timeout=10)
        try:
            return target.create_baseline_scope(value, "admin", START)[1]
        except ValueError as error:
            return str(error)

    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(create, repo, cfg), pool.submit(create, other, second)]
            results = [f.result(timeout=15) for f in futures]
        assert results.count(True) == 1
        assert results.count(False if race == "same-id" else "BASELINE_SCOPE_LIMIT") == 1
        assert repo.page_baseline_scopes().total == (1 if race == "same-id" else 16)
    finally:
        if other is not repo:
            other.close()


@pytest.mark.parametrize("site", ["catalog", "job", "scope"])
def test_actual_sql_lock_timeout(scope_repo: Any, site: str) -> None:
    repo = scope_repo
    if hasattr(repo, "jobs"):
        pytest.skip("database lock mechanism")
    pg = hasattr(repo, "database_url")
    if not pg and site != "catalog":
        pytest.skip("SQLite has one database write-admission lock")
    repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(stored())
    blocker = observer(repo) if pg else __import__("sqlite3").connect(repo._path)
    blocker.execute("BEGIN" if pg else "BEGIN EXCLUSIVE")
    if pg:
        statements = {
            "catalog": "SELECT id FROM baseline_catalog FOR UPDATE",
            "job": "SELECT id FROM controller_objects WHERE kind='job' AND id='root' FOR UPDATE",
            "scope": "SELECT scope_id FROM baseline_scopes FOR UPDATE",
        }
        blocker.execute(statements[site])
    started = time.monotonic()
    try:
        with pytest.raises(ValueError, match="^BASELINE_BUSY$"):
            if site == "catalog":
                repo.create_baseline_scope(config(), "admin", START)
            else:
                repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
        elapsed = time.monotonic() - started
        assert 4.5 <= elapsed < 12
        assert (
            repo.connection.info.transaction_status.name == "IDLE"
            if pg
            else not repo.connection.in_transaction
        )
        receipt(
            {
                "backend": "postgres" if pg else "sqlite",
                "lock": site,
                "elapsed": elapsed,
                "fired": 1,
                "idle": True,
            }
        )
    finally:
        blocker.execute("ROLLBACK")
        blocker.close()
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(repo.preview_baseline_source, config().scope_id, "root", 0, "APPROVAL")
            .result(timeout=10)
            .admissible
        )


def test_scope_revision_rechecked_after_initial_read(scope_repo: Any, monkeypatch: Any) -> None:
    repo = scope_repo
    view, _ = repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(stored())
    if hasattr(repo, "jobs"):
        original = r._memory_acquire

        def racing(*args: Any, **kwargs: Any) -> Any:
            acquired = original(*args, **kwargs)
            repo._baseline_scopes[config().scope_id] = gview(view)
            return acquired

        monkeypatch.setattr(r, "_memory_acquire", racing)
    else:
        original = bs.sql_get

        def racing(connection: Any, identifier: str, **kwargs: Any) -> Any:
            result = original(connection, identifier, **kwargs)
            # Separate connection commits after initial snapshot is released, before jobs.
            with (
                observer(repo)
                if hasattr(repo, "database_url")
                else __import__("sqlite3").connect(repo._path) as writer
            ):
                writer.execute("UPDATE baseline_scopes SET control_revision=1")
                writer.commit()
            return result

        monkeypatch.setattr(bs, "sql_get", racing)
    with pytest.raises(ValueError, match="^BASELINE_REVISION_CONFLICT$"):
        repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")


def gview(view: Any) -> Any:
    from c2hunter_controller.historical_generation import ScopeView

    return ScopeView.from_mapping(dict(view.to_mapping(), control_revision=1))


def test_pg_scope_changes_after_jobs_before_scope(pg_repo: Any, monkeypatch: Any) -> None:
    pg_repo.create_baseline_scope(config(), "admin", START)
    pg_repo.save_job(stored())
    original = r._postgres_acquire
    fired = []

    def racing(*args: Any, **kwargs: Any) -> Any:
        acquired = original(*args, **kwargs)
        with observer(pg_repo) as writer:
            writer.execute("UPDATE baseline_scopes SET control_revision=1")
        fired.append(True)
        return acquired

    monkeypatch.setattr(r, "_postgres_acquire", racing)
    with pytest.raises(ValueError, match="^BASELINE_REVISION_CONFLICT$"):
        pg_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
    assert fired == [True]


def test_pg_parent_change_is_rejected_without_new_edge(pg_repo: Any, monkeypatch: Any) -> None:
    pg_repo.create_baseline_scope(config(), "admin", START)
    pg_repo.save_job(stored())
    original = r._pg_metadata
    calls = []

    def racing(cursor: Any, key: str) -> Any:
        calls.append(key)
        value = original(cursor, key)
        if len(calls) == 1:
            with observer(pg_repo) as writer:
                writer.execute(
                    "UPDATE controller_objects SET "
                    "data=jsonb_set(data,'{parent_job_id}','\"unlocked-new-parent\"') "
                    "WHERE kind='job' AND id='root'"
                )
        return value

    monkeypatch.setattr(r, "_pg_metadata", racing)
    with pytest.raises(ValueError, match="^BASELINE_SOURCE_CHANGED$"):
        pg_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
    assert calls == ["root", "root"]
