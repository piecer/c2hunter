"""Enumerate and fire real SQL errors at every observed execute occurrence.

Lifecycle commit/rollback/close controls are separate tests; this inventory never
labels an unexecuted branch or DDL as exercised by the publication trace.
"""

import inspect
from collections import Counter
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_baseline_approval_retention import publish
from tests.test_baseline_approval_sql import durable, full_retention_seed
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


class Trace:
    def __init__(self, real: Any, repo: Any, target: int | None) -> None:
        self.real, self.repo, self.target = real, repo, target
        self.events: list[dict] = []
        self.counts: Counter = Counter()
        self.fired = 0
        self.committed: list[tuple] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.real, name)

    def execute_on(self, target: Any, sql: str, values: Any = ()) -> Any:
        frame = next(
            frame
            for frame in inspect.stack()
            if frame.filename.endswith(("/_baseline_storage.py", "/historical_read.py"))
        )
        site = frame.filename.rsplit("/", 1)[-1] + ":" + frame.function + ":" + str(frame.lineno)
        self.counts[(site, sql)] += 1
        self.events.append({"site": site, "statement": sql, "occurrence": self.counts[(site, sql)]})
        if len(self.events) - 1 == self.target:
            self.fired += 1
            return target.execute("SELECT * FROM owned_approval_fault_missing_relation")
        return target.execute(sql, values)

    def execute(self, sql: str, values: Any = ()) -> Any:
        return self.execute_on(self.real, sql, values)

    def cursor(self) -> Any:
        trace = self

        class Cursor:
            def __init__(self) -> None:
                self.real = trace.real.cursor()

            def __getattr__(self, name: str) -> Any:
                return getattr(self.real, name)

            def execute(self, sql: str, values: Any = ()) -> Any:
                trace.execute_on(self.real, sql, values)
                return self

            def __enter__(self) -> Any:
                return self

            def __exit__(self, *args: Any) -> None:
                self.real.close()

        return Cursor()

    def commit(self) -> None:
        self.real.commit()
        self.committed.append(durable(self.repo))


def restore(real: Any, pg: bool, snapshot: tuple) -> None:
    with bs.transaction(real, postgres=pg, write=True) as cursor:
        db = bs._SQL(cursor, pg)
        for table in ("baseline_operations", "baseline_generations", "baseline_scopes"):
            db.execute("DELETE FROM " + table)
        for table, rows in zip(
            ("baseline_scopes", "baseline_generations", "baseline_operations"),
            snapshot[:3],
            strict=True,
        ):
            for row in rows:
                db.execute(
                    "INSERT INTO " + table + " VALUES(" + ",".join("?" for _ in row) + ")",
                    tuple(row),
                )


@pytest.mark.parametrize("path", ["publish", "replay", "sources"])
def test_actual_sql_site_occurrence_faults(approval_repo: Any, path: str) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("SQL execute inventory; Memory staging tested separately")
    pg = hasattr(repo, "database_url")
    if path == "publish":
        full_retention_seed(repo)
        request = fixtures.prepare(repo, 64)
        generation_id = None
    else:
        repo.create_baseline_scope(config(), "admin", START)
        request, result = publish(repo, 0)
        generation_id = result.receipt.generation_id
    real = repo.connection
    before = durable(repo)

    def install(target: int | None) -> Trace:
        trace = Trace(real, repo, target)
        if pg:
            repo._connection = trace
        else:
            repo.connection = trace
        return trace

    def call() -> Any:
        if path == "sources":
            return repo.page_baseline_sources(config().scope_id, generation_id)
        return repo.publish_baseline_source(config().scope_id, request, "reviewer", START)

    try:
        positive = install(None)
        call()
        inventory = positive.events
        assert inventory
        restore(real, pg, before)
        for target, event in enumerate(inventory):
            trace = install(target)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                call()
            assert trace.fired == 1 and trace.events[target] == event
            observed = durable(repo)
            assert observed == (trace.committed[-1] if trace.committed else before)
            assert (real.info.transaction_status.name == "IDLE") if pg else not real.in_transaction
            receipt(
                {
                    "backend": "postgres" if pg else "sqlite",
                    "path": path,
                    "index": target,
                    **event,
                    "fired": trace.fired,
                    "committed": bool(trace.committed),
                    "independent_exact_snapshot": True,
                    "idle": True,
                }
            )
            restore(real, pg, before)
        # One unchanged real call after every fault has independently recovered.
        install(None)
        call()
    finally:
        if pg:
            repo._connection = real
        else:
            repo.connection = real
