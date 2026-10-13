"""Phase and lifecycle controls; SQL fixtures never provision a server."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import SQLiteRepository
from tests.test_baseline_approval_contract import pg_repo, prepare  # noqa: F401
from tests.test_baseline_approval_sql import durable
from tests.test_baseline_approval_transaction_repair import independent
from tests.test_baseline_approval_transaction_repair import sql_repo as sql_fixture
from tests.test_historical_source import START, config

sql_repo = sql_fixture


@pytest.mark.parametrize("phase", ["fast", "final", "recovery"])
@pytest.mark.parametrize("malformed", [False, True])
def test_retained_lookup_phase_precedence(
    sql_repo: Any, monkeypatch: Any, phase: str, malformed: bool
) -> None:
    repo = sql_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    peer = (
        SQLiteRepository(repo._path)
        if isinstance(repo, SQLiteRepository)
        else type(repo)(repo.database_url, None)
    )
    assert peer.connection is not repo.connection  # Initialize before interleaving.
    actual = bs._publication_transaction.__exit__
    events = []
    winners = []

    def winner() -> None:
        winners.append(peer.publish_baseline_source(config().scope_id, request, "reviewer", START))
        with independent(repo) as con:
            column = "receipt_sha256" if malformed else "request_sha256"
            con.execute("UPDATE baseline_operations SET " + column + "='" + "0" * 64 + "'")
        if phase == "recovery":
            peer.delete_job(request.source_job_id)

    def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        value = actual(owner, kind, error, tb)
        if owner.connection is repo.connection:
            events.append((owner.write, None if error is None else type(error).__name__))
            if len(events) == 1 and phase != "fast":
                winner()
        return value

    if phase == "fast":
        winner()
    try:
        monkeypatch.setattr(bs._publication_transaction, "__exit__", boundary)
        with pytest.raises(bs.BaselineStorageError) as caught:
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert caught.value.code == (
            "BASELINE_STORAGE_UNAVAILABLE" if malformed else "BASELINE_IDEMPOTENCY_CONFLICT"
        )
        assert len(winners) == 1
        assert len(events) == {"fast": 1, "final": 2, "recovery": 3}[phase]
        with independent(repo) as con:
            assert con.execute("SELECT count(*) FROM baseline_operations").fetchone() == (1,)
        assert not repo._baseline_publication_connection.failed
    finally:
        peer.close()


@pytest.mark.parametrize("fault", ["malformed", "busy", "programmer", "teardown"])
def test_first_readback_primary_committed_state(
    sql_repo: Any, monkeypatch: Any, fault: str
) -> None:
    repo = sql_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    actual = bs._publication_transaction.__exit__
    lookup = bs._PublicationSQL.operation
    committed, fired, closed, ids = [], [], [], []
    import uuid

    original_uuid = uuid.uuid4

    def identity() -> Any:
        value = original_uuid()
        ids.append(value)
        return value

    marker = TypeError("readback primary identity")
    real = repo.connection

    class Connection:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def rollback(self) -> None:
            real.rollback()
            if committed and fault == "teardown":
                fired.append(True)
                raise marker

        def close(self) -> None:
            closed.append(True)
            real.close()

    proxy = Connection()
    if isinstance(repo, SQLiteRepository):
        repo.connection = proxy
    else:
        repo._connection = proxy

    def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
        value = actual(owner, kind, error, tb)
        if owner.write and error is None:
            committed.append(durable(repo))
        return value

    def operation(db: Any, *args: Any, **kw: Any) -> Any:
        if committed and fault != "teardown":
            fired.append(True)
            if fault == "programmer":
                raise marker
            if fault == "busy":
                if isinstance(repo, SQLiteRepository):
                    error = sqlite3.OperationalError("not message classified")
                    error.sqlite_errorcode = sqlite3.SQLITE_BUSY
                    raise error
                import psycopg

                raise psycopg.errors.LockNotAvailable("owned readback busy")
            return None  # Missing committed operation, not ordinary absent retained key.
        return lookup(db, *args, **kw)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(uuid, "uuid4", identity)
            patch.setattr(bs._publication_transaction, "__exit__", boundary)
            patch.setattr(bs._PublicationSQL, "operation", operation)
            with pytest.raises((TypeError, bs.BaselineStorageError)) as caught:
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert fired == [True] and len(committed) == 1 and len(ids) == 2
        assert durable(repo) == committed[0]
        if fault in {"programmer", "teardown"}:
            assert caught.value is marker
        else:
            assert caught.value.code == (
                "BASELINE_BUSY" if fault == "busy" else "BASELINE_STORAGE_UNAVAILABLE"
            )
        assert bool(closed) == (fault == "teardown")
        reopened = (
            SQLiteRepository(repo._path)
            if isinstance(repo, SQLiteRepository)
            else type(repo)(repo.database_url, None)
        )
        try:
            result = reopened.publish_baseline_source(config().scope_id, request, "reviewer", START)
            assert not result.created and result.receipt.revision == 1
        finally:
            reopened.close()
        if fault == "teardown":
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            assert closed == [True]
        else:
            with ThreadPoolExecutor(max_workers=1) as pool:
                assert (
                    not pool.submit(
                        repo.publish_baseline_source, config().scope_id, request, "reviewer", START
                    )
                    .result(30)
                    .created
                )
    finally:
        if isinstance(repo, SQLiteRepository):
            repo.connection = real
        else:
            repo._connection = real


@pytest.mark.parametrize(
    "kind,code,refusal",
    [
        (sqlite3.OperationalError, sqlite3.SQLITE_BUSY, True),
        (sqlite3.OperationalError, sqlite3.SQLITE_IOERR, False),
        (sqlite3.OperationalError, sqlite3.SQLITE_LOCKED, False),
        (sqlite3.OperationalError, None, False),
        (sqlite3.DatabaseError, sqlite3.SQLITE_BUSY, False),
        (RuntimeError, sqlite3.SQLITE_BUSY, False),
    ],
)
def test_commit_refusal_is_finite_typed_code(kind: Any, code: Any, refusal: bool) -> None:
    error = kind("database is locked")
    if code is not None:
        error.sqlite_errorcode = code
    owner = bs._publication_transaction(object(), postgres=False, write=True)
    assert owner._definite_commit_refusal(error) is refusal


@pytest.mark.parametrize("close_fails", [False, True])
def test_actual_busy_failed_rollback_quarantines(
    tmp_path: Any, monkeypatch: Any, close_fails: bool
) -> None:
    repo = SQLiteRepository(tmp_path / "failed-cleanup.sqlite")
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    real = repo.connection
    reader = sqlite3.connect(repo._path)
    execute = bs._SQL.execute
    lock, rollbacks, closes = [], [], []
    before = durable(repo)

    class Connection:
        def __getattr__(self, name: str) -> Any:
            return getattr(real, name)

        def rollback(self) -> None:
            rollbacks.append(bool(lock))
            if lock:
                raise TypeError("secondary cleanup failure")
            real.rollback()

        def close(self) -> None:
            closes.append(True)
            if close_fails:
                raise TypeError("secondary close failure")
            real.close()

    def boundary(db: Any, statement: str, values: Any = ()) -> Any:
        result = execute(db, statement, values)
        if statement.startswith("SELECT revision FROM baseline_operations WHERE scope_id=? ORDER "):
            reader.execute("BEGIN")
            reader.execute("SELECT * FROM baseline_scopes").fetchall()
            lock.append(True)
        return result

    repo.connection = Connection()
    try:
        with monkeypatch.context() as patch:
            patch.setattr(bs._SQL, "execute", boundary)
            with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert lock == [True] and rollbacks == [False, True] and closes == [True]
        assert repo._baseline_publication_connection.failed
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert closes == [True]
    finally:
        reader.close()
        real.close()  # Explicit test-owner cleanup; not product success/reuse.
        repo.connection = real
        repo.close()
    assert durable(repo) == before
