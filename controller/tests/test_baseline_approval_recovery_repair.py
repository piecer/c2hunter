"""One-shot absent/winner recovery, real constraint negatives and custody."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_approval_lifecycle_repair import full_snapshot
from tests.test_baseline_approval_retention import publish
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config, stored


@pytest.mark.parametrize("fault", ["check", "notnull", "foreign-key", "trigger", "rowcount0"])
def test_sqlite_constraint_negative_and_cas_zero(
    tmp_path: Any, monkeypatch: Any, fault: str
) -> None:
    repo = SQLiteRepository(tmp_path / "constraint.sqlite")
    try:
        repo.create_baseline_scope(config(), "admin", START)
        publish(repo, 0)
        publish(repo, 1)
        request = prepare(repo, 2)
        before = full_snapshot(repo)
        execute = bs._SQL.execute
        lookup = bs._PublicationSQL.operation
        lookups, fired = [], []
        if fault in {"trigger", "rowcount0"}:
            repo.connection.create_function("owned_fired", 0, lambda: fired.append(True) or 1)
            statement = (
                "CREATE TEMP TRIGGER owned_fault BEFORE UPDATE ON baseline_scopes "
                "BEGIN SELECT owned_fired(); SELECT RAISE(IGNORE); END;"
                if fault == "rowcount0"
                else "CREATE TEMP TRIGGER owned_fault BEFORE INSERT ON baseline_operations "
                "BEGIN SELECT owned_fired(); SELECT RAISE(ABORT,'owned'); END;"
            )
            repo.connection.executescript(statement)

        def sql(db: Any, statement: str, values: Any = ()) -> Any:
            if fault in {"check", "notnull", "foreign-key"} and statement.startswith(
                "INSERT INTO baseline_operations"
            ):
                values = list(values)
                field, value = {
                    "check": (1, 0),
                    "notnull": (5, None),
                    "foreign-key": (0, "00000000-0000-0000-0000-000000000000"),
                }[fault]
                values[field] = value
                fired.append(True)
            return execute(db, statement, values)

        def operation(db: Any, *args: Any, **kw: Any) -> Any:
            lookups.append(True)
            return lookup(db, *args, **kw)

        with monkeypatch.context() as patch:
            patch.setattr(bs._SQL, "execute", sql)
            patch.setattr(bs._PublicationSQL, "operation", operation)
            with pytest.raises(
                bs.BaselineStorageError,
                match="^BASELINE_"
                + ("REVISION_CONFLICT" if fault == "rowcount0" else "STORAGE_UNAVAILABLE")
                + "$",
            ):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert fired == [True] and len(lookups) == (3 if fault == "rowcount0" else 2)
        assert full_snapshot(repo) == before and not repo.connection.in_transaction
        if fault in {"trigger", "rowcount0"}:
            repo.connection.execute("DROP TRIGGER owned_fault")
        reopened = SQLiteRepository(repo._path)
        try:
            assert reopened.get_baseline_scope(config().scope_id).control_revision == 2
        finally:
            reopened.close()
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert (
                pool.submit(
                    repo.publish_baseline_source, config().scope_id, request, "reviewer", START
                )
                .result(30)
                .created
            )
        receipt(
            dict(
                backend="sqlite",
                constraint=fault,
                fired=1,
                lookups=len(lookups),
                prestate=True,
                idle=True,
                reopen=True,
                cross_thread_reuse=True,
            )
        )
    finally:
        repo.close()


@pytest.mark.parametrize("recovery_error", [False, True])
def test_absent_before_winner_recovery_exactly_once(
    tmp_path: Any, monkeypatch: Any, recovery_error: bool
) -> None:
    repo = SQLiteRepository(tmp_path / "recovery.sqlite")
    peer = SQLiteRepository(repo._path)
    try:
        repo.create_baseline_scope(config(), "admin", START)
        request = prepare(repo)
        source = peer.get_job(request.source_job_id)
        exit_ = bs._publication_transaction.__exit__
        operation_ = bs._PublicationSQL.operation
        acquisition_ = r._sqlite_acquire
        reads, events, acquisitions = [], [], []

        def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
            try:
                return exit_(owner, kind, error, tb)
            finally:
                if owner.connection is repo.connection:
                    events.append((owner.write, error is None))
                    if len(events) == 1:
                        peer.delete_job(request.source_job_id)

        def lookup(db: Any, *args: Any, **kw: Any) -> Any:
            reads.append(True)
            if len(reads) == 2:
                assert events == [(False, True), (True, False)]
                if recovery_error:
                    db.execute("SELECT * FROM owned_missing_recovery_table")
            return operation_(db, *args, **kw)

        def acquire(*args: Any, **kw: Any) -> Any:
            acquisitions.append(True)
            return acquisition_(*args, **kw)

        with monkeypatch.context() as patch:
            patch.setattr(bs._publication_transaction, "__exit__", boundary)
            patch.setattr(bs._PublicationSQL, "operation", lookup)
            patch.setattr(r, "_sqlite_acquire", acquire)
            with pytest.raises(
                bs.BaselineStorageError,
                match="^BASELINE_"
                + ("STORAGE_UNAVAILABLE" if recovery_error else "SOURCE_NOT_FOUND")
                + "$",
            ):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert len(reads) == 2 and acquisitions == [True] and len(events) == 3
        assert not repo.connection.in_transaction
        assert peer.connection.execute("SELECT count(*) FROM baseline_operations").fetchone() == (
            0,
        )
        # Winner is admitted only after recovery completed: no chase/automatic retry.
        peer.save_job(source)
        winner = peer.publish_baseline_source(config().scope_id, request, "reviewer", START)
        replay = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert winner.created and not replay.created and replay.receipt == winner.receipt
    finally:
        peer.close()
        repo.close()


@pytest.mark.parametrize("missing", [False, True])
def test_private_acquisition_never_owns_caller_transaction(tmp_path: Any, missing: bool) -> None:
    repo = SQLiteRepository(tmp_path / "private.sqlite")
    try:
        repo.save_job(stored())
        con = repo.connection
        con.execute("CREATE TEMP TABLE sentinel(value INTEGER)")
        con.execute("BEGIN")
        con.execute("INSERT INTO sentinel VALUES(17)")
        calls = []
        con.set_trace_callback(calls.append)
        if missing:
            with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_NOT_FOUND$"):
                r._sqlite_acquire(con, "missing", "APPROVAL")
        else:
            assert r._sqlite_acquire(con, "root", "APPROVAL").flows
        con.set_trace_callback(None)
        assert con.in_transaction and con.execute("SELECT * FROM sentinel").fetchall() == [(17,)]
        assert not any(sql.upper().startswith(("BEGIN", "COMMIT", "ROLLBACK")) for sql in calls)
        con.rollback()
    finally:
        repo.close()
