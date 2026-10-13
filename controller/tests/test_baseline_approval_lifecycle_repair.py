"""SQLite actual occurrence joins with independent pre-reopen full snapshots."""

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_approval_fault_inventory import Trace, restore
from tests.test_baseline_approval_retention import publish
from tests.test_baseline_approval_sql import durable, full_retention_seed
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config


def full_snapshot(repo: Any) -> tuple:
    with closing(sqlite3.connect(repo._path)) as con:
        names = [
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            )
        ]
        return tuple(
            (
                name,
                tuple(
                    sorted(
                        con.execute('SELECT * FROM "' + name.replace('"', '""') + '"').fetchall(),
                        key=repr,
                    )
                ),
            )
            for name in names
        )


class LifecycleTrace(Trace):
    def __init__(self, real: Any, repo: Any, target: int | None) -> None:
        super().__init__(real, repo, target)
        self.lifecycle: list[str] = []
        self.full_committed: list[tuple] = []

    def commit(self) -> None:
        self.lifecycle.append("commit")
        super().commit()
        self.full_committed.append(full_snapshot(self.repo))

    def rollback(self) -> None:
        self.lifecycle.append("rollback")
        self.real.rollback()

    def close(self) -> None:
        self.lifecycle.append("close")
        self.real.close()


@pytest.mark.parametrize("path", ["publish", "replay", "sources"])
def test_sqlite_full_occurrence_reopen_reuse_join(tmp_path: Any, path: str) -> None:
    repo = SQLiteRepository(tmp_path / "occurrence.sqlite")
    try:
        if path == "publish":
            full_retention_seed(repo)
            request = prepare(repo, 64)
            generation_id = None
        else:
            repo.create_baseline_scope(config(), "admin", START)
            request, result = publish(repo, 0)
            generation_id = result.receipt.generation_id
        real = repo.connection
        base = durable(repo)
        before = full_snapshot(repo)

        def call(target: Any = repo) -> Any:
            if path == "sources":
                return target.page_baseline_sources(config().scope_id, generation_id)
            return target.publish_baseline_source(config().scope_id, request, "reviewer", START)

        trace = LifecycleTrace(real, repo, None)
        repo.connection = trace
        call()
        inventory = list(trace.events)
        restore(real, False, base)
        assert full_snapshot(repo) == before
        for index, event in enumerate(inventory):
            trace = LifecycleTrace(real, repo, index)
            repo.connection = trace
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                call()
            assert trace.fired == 1 and trace.events[index] == event
            observed = full_snapshot(repo)  # Must precede reopen or any rescue/reuse.
            assert observed == (trace.full_committed[-1] if trace.full_committed else before)
            assert not real.in_transaction and not repo._baseline_publication_connection.failed
            assert "close" not in trace.lifecycle
            fault_lifecycle = list(trace.lifecycle)
            reopened = SQLiteRepository(repo._path)
            try:
                expected_revision = 65 if trace.full_committed else 64 if path == "publish" else 1
                assert (
                    reopened.get_baseline_scope(config().scope_id).control_revision
                    == expected_revision
                )
                assert full_snapshot(repo) == observed
            finally:
                reopened.close()
            with ThreadPoolExecutor(max_workers=1) as pool:
                outcome = pool.submit(call).result(30)
            assert outcome is not None and trace.fired == 1
            assert not real.in_transaction
            receipt(
                dict(
                    backend="sqlite",
                    path=path,
                    index=index,
                    **event,
                    fired=1,
                    independent_pre_reopen_sha256=hashlib.sha256(
                        repr(observed).encode()
                    ).hexdigest(),
                    full_tables=[name for name, _ in observed],
                    committed=bool(trace.full_committed),
                    lifecycle_at_fault=fault_lifecycle,
                    idle=True,
                    failed=False,
                    reopened=True,
                    cross_thread_reuse=True,
                )
            )
            restore(real, False, base)
            assert full_snapshot(repo) == before
        receipt(
            dict(
                backend="sqlite",
                path=path,
                inventory=inventory,
                joined=len(inventory),
                complete=True,
            )
        )
    finally:
        if "real" in locals():
            repo.connection = real
        repo.close()


@pytest.mark.parametrize("method", ["publish", "sources"])
def test_sqlite_actual_new_reader_busy(tmp_path: Any, method: str) -> None:
    repo = SQLiteRepository(tmp_path / "reader-busy.sqlite")
    locker = sqlite3.connect(repo._path)
    try:
        repo.create_baseline_scope(config(), "admin", START)
        request, result = publish(repo, 0)
        before = full_snapshot(repo)
        locker.execute("BEGIN EXCLUSIVE")
        attempted = []
        real = repo.connection

        class Connection:
            def __getattr__(self, name: str) -> Any:
                return getattr(real, name)

            def execute(self, sql: str, values: Any = ()) -> Any:
                attempted.append(sql)
                return real.execute(sql, values)

        repo.connection = Connection()
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
            if method == "publish":
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            else:
                repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
        assert attempted[0] == "BEGIN" and len(attempted) >= 2
        assert not real.in_transaction and not repo._baseline_publication_connection.failed
        locker.rollback()
        assert full_snapshot(repo) == before
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert (
                not pool.submit(
                    repo.publish_baseline_source, config().scope_id, request, "reviewer", START
                )
                .result(30)
                .created
            )
    finally:
        locker.close()
        repo.close()


@pytest.mark.parametrize("operation", ["publish", "sources"])
@pytest.mark.parametrize("foreign", [True, False])
def test_sqlite_foreign_custody_zero_lifecycle(
    tmp_path: Any, operation: str, foreign: bool
) -> None:
    repo = SQLiteRepository(tmp_path / "custody.sqlite")
    try:
        repo.create_baseline_scope(config(), "admin", START)
        request, result = publish(repo, 0)
        real = repo.connection
        real.execute("CREATE TEMP TABLE custody(value INTEGER)")
        if foreign:
            real.execute("BEGIN")
            real.execute("INSERT INTO custody VALUES(17)")
        else:
            real.autocommit = True
        calls = []

        class Connection:
            def __getattr__(self, name: str) -> Any:
                if name in {"commit", "rollback", "close", "execute"}:

                    def forbidden(*args: Any, **kw: Any) -> Any:
                        calls.append(name)
                        pytest.fail("caller connection lifecycle touched")

                    return forbidden
                return getattr(real, name)

        repo.connection = Connection()
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
            if operation == "publish":
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            else:
                repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
        assert calls == []
        if foreign:
            assert real.in_transaction and real.execute("SELECT * FROM custody").fetchall() == [
                (17,)
            ]
        else:
            assert real.autocommit is True
    finally:
        repo.connection = real
        if foreign:
            real.rollback()
        else:
            real.autocommit = sqlite3.LEGACY_TRANSACTION_CONTROL
        repo.close()
