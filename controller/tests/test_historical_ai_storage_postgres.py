"""PostgreSQL adapter contracts only; these tests do not run a PG server."""

import threading
from contextlib import contextmanager
from types import SimpleNamespace

import psycopg
import pytest
from psycopg.pq import TransactionStatus

from c2hunter_controller import historical_ai as dto
from c2hunter_controller.historical_ai_builder import (
    build_historical_snapshot,
    build_historical_target_snapshot,
)
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.historical_ai_fixtures import world


@pytest.mark.parametrize("backend", [MemoryRepository, SQLiteRepository, PostgresRepository])
@pytest.mark.parametrize("private", [False, True, "historical_request_json"])
def test_generic_create_refuses_before_backend_io(backend, private):
    run = build_historical_snapshot(dto.HistoricalAdmissionInput(**world(sources=0))).to_mapping()
    if private is True:
        run = {"_historical_admission": {}, "baseline_mode": "off"}
    elif private:
        run = {"historical_request_json": "private", "baseline_mode": "off"}
    repo = object.__new__(backend)
    with pytest.raises(ValueError, match="^historical admission requires atomic owner$"):
        repo.create_ai_run(run)


def test_postgres_borrowed_transaction_is_not_committed_or_rolled_back():
    repo = object.__new__(PostgresRepository)
    repo._lock = threading.RLock()
    repo._connection = SimpleNamespace(
        info=SimpleNamespace(transaction_status=TransactionStatus.INTRANS),
        autocommit=False,
        closed=False,
    )
    request = dto.HistoricalAdmissionRequest.model_validate(world(sources=0)["request"])
    with pytest.raises(ValueError, match="BASELINE_BUSY"):
        repo.admit_historical_ai_run(request, build_historical_target_snapshot)


def test_postgres_check_comparator_preserves_boolean_structure():
    from c2hunter_controller import historical_ai_sql as sql

    shape = f"({sql._shape(postgres=True)}) IS TRUE"
    assert sql._check_ast(shape) == sql._check_ast(
        shape.replace(
            "historical_request_byte_size BETWEEN 1 AND 16384",
            "(historical_request_byte_size >= 1 AND historical_request_byte_size <= 16384)",
        ).replace("'historical-ai-owner-v1'", "'historical-ai-owner-v1'::text")
    )
    assert sql._check_ast(shape) != sql._check_ast(shape.replace("16384", "16385"))
    assert sql._check_ast("(true OR false) AND false") != sql._check_ast(
        "true OR (false AND false)"
    )


@pytest.mark.parametrize("operation", ["admit", "save"])
@pytest.mark.parametrize("fault", [None, "commit", "readback"])
def test_postgres_publication_quarantine_and_independent_readback_adapter_contract(
    monkeypatch, operation, fault
):
    """Driver-boundary unit test, not PostgreSQL engine execution."""
    from contextlib import contextmanager

    import psycopg

    from c2hunter_controller import historical_ai_sql as sql
    from c2hunter_controller import historical_ai_storage as custody
    from tests.test_historical_ai_storage import prepared

    memory = MemoryRepository()
    request, _, _ = prepared(memory)
    run, _ = memory.admit_historical_ai_run(request, build_historical_target_snapshot)
    calls = []

    class Connection:
        autocommit = False
        closed = False
        info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

        def __init__(self, reader=False):
            self.reader = reader
            self.committed = False

        @contextmanager
        def transaction(self):
            yield
            self.committed = True
            if fault == "commit" and not self.reader:
                raise psycopg.OperationalError("commit response lost")

        @contextmanager
        def cursor(self):
            yield self

        def execute(self, statement, parameters=()):
            return self

        def close(self):
            self.closed = True

    writer, reader = Connection(), Connection(reader=True)

    class Store:
        def __init__(self, cursor, postgres):
            self.connection = cursor
            assert postgres

        def admit(self, *args):
            return run, True

        def save(self, submitted):
            return submitted

        def get(self, *args):
            if fault == "readback":
                raise psycopg.OperationalError("readback failed")
            return run

    def connect(database_url, *, autocommit):
        assert database_url == "postgresql://unit-contract" and not autocommit
        assert writer.committed
        calls.append(reader)
        return reader

    monkeypatch.setattr(sql, "RunSQL", Store)
    monkeypatch.setattr(psycopg, "connect", connect)
    repo = PostgresRepository("postgresql://unit-contract", object())
    repo._connection = writer

    def publish():
        if operation == "admit":
            return repo.admit_historical_ai_run(request, build_historical_target_snapshot)[0]
        return repo.save_ai_run(run)

    if fault:
        with pytest.raises(custody.HistoricalStorageOutcomeUnknown):
            publish()
        assert writer.closed and repo._connection is None
    else:
        assert publish() == run
        assert not writer.closed and repo._connection is writer
    assert calls == ([] if fault == "commit" else [reader])
    if calls:
        assert reader.closed


class InitializerConnection:
    """Driver transaction model, not a PostgreSQL catalog or SQL engine."""

    def __init__(self, *, failed_commit=None):
        self.autocommit = False
        self.closed = False
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.queries = []
        self.events = []
        self.transactions = 0
        self.failed_commit = failed_commit
        self.close_calls = 0

    @contextmanager
    def cursor(self):
        assert not self.closed
        yield self

    def execute(self, statement, parameters=()):
        self.queries.append(statement)
        if not self.autocommit:
            self.info.transaction_status = TransactionStatus.INTRANS

    def fetchall(self):
        return []

    def fetchone(self):
        if self.queries[-1] == "SELECT pg_try_advisory_lock(2026081301)":
            return (True,)
        return None

    def commit(self):
        self.events.append(("commit", self.transactions))
        self.info.transaction_status = TransactionStatus.IDLE
        if self.transactions == self.failed_commit:
            raise psycopg.OperationalError("commit response lost")

    def rollback(self):
        self.events.append(("rollback", self.transactions))
        self.info.transaction_status = TransactionStatus.IDLE

    @contextmanager
    def transaction(self):
        assert self.info.transaction_status == TransactionStatus.IDLE
        assert not self.autocommit
        self.transactions += 1
        self.events.append(("begin", self.transactions))
        self.info.transaction_status = TransactionStatus.INTRANS
        try:
            yield
        except BaseException:
            self.rollback()
            raise
        else:
            self.commit()

    def close(self):
        self.close_calls += 1
        self.closed = True


@pytest.mark.parametrize("fault", [None, "install", "verify", "commit-install", "commit-verify"])
def test_actual_owner_initializer_order_failure_and_retry(monkeypatch, fault):
    """Run real constructor, indexes, initializer and transaction helpers.

    Catalog validation and index maintenance are isolated because this driver
    models transaction ownership, not pg_catalog. Real index guards are covered
    in test_postgres_redundant_indexes. The fail-closed catalog path is retained
    separately below. This does not establish PostgreSQL engine acceptance.
    """
    from c2hunter_controller import historical_ai_sql as sql
    from c2hunter_controller import historical_ai_storage as custody

    failed_commit = {"commit-install": 1, "commit-verify": 2}.get(fault)
    first = InitializerConnection(failed_commit=failed_commit)
    healthy, unrelated = InitializerConnection(), InitializerConnection()
    available = iter((first, healthy))
    acquired, validated = [], []
    repo = PostgresRepository("postgresql://initializer.invalid/unit", object())
    other = repo.for_background_worker()
    other._connection = unrelated
    primary = custody.HistoricalStorageError()

    def connect(database_url, *, autocommit):
        assert database_url == repo.database_url and autocommit is False
        connection = next(available)
        acquired.append(connection)
        return connection

    def validate(cursor, *, install=False):
        assert repo._connection is None
        assert cursor is acquired[-1] and not cursor.closed and not cursor.autocommit
        assert cursor.info.transaction_status == TransactionStatus.INTRANS
        assert cursor.events[:4] == [("rollback", 0), ("commit", 0), ("commit", 0), ("commit", 0)]
        unlock = cursor.queries.index("SELECT pg_advisory_unlock(2026081301)")
        lock = cursor.queries.index("LOCK TABLE ai_analysis_runs IN ACCESS EXCLUSIVE MODE")
        assert unlock < lock
        assert cursor.queries[lock - 1] == "SET LOCAL lock_timeout='5s'"
        if not install:
            assert cursor.queries[-3:] == [
                "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
                "SET LOCAL lock_timeout='5s'",
                "SET TRANSACTION READ ONLY",
            ]
            assert ("commit", 1) in cursor.events
        validated.append((cursor, install))
        if cursor is first and fault == ("install" if install else "verify"):
            raise primary

    monkeypatch.setattr(psycopg, "connect", connect)
    monkeypatch.setattr(sql, "postgres_schema", validate)
    from c2hunter_controller import postgres_index_maintenance, postgres_schema

    monkeypatch.setattr(postgres_schema, "verify_layout", lambda cursor: None)
    index_calls = []

    def maintain_indexes(cursor, *, lock_timeout_seconds):
        assert cursor is acquired[-1] and not cursor.closed and not cursor.autocommit
        assert repo._connection is None and lock_timeout_seconds == 30
        assert cursor.info.transaction_status == TransactionStatus.IDLE
        assert validated[-2:] == [(cursor, True), (cursor, False)]
        index_calls.append(cursor)

    monkeypatch.setattr(postgres_index_maintenance, "remove_redundant_indexes", maintain_indexes)
    if fault:
        error = custody.HistoricalStorageOutcomeUnknown if failed_commit else type(primary)
        with pytest.raises(error) as raised:
            repo.initialize_schema()
        if not failed_commit:
            assert raised.value is primary
        assert repo._connection is None and first.closed and first.close_calls == 1
        count = 1 if fault.endswith("install") else 2
        assert first.transactions == count
        assert first.events[-1] == ("commit" if failed_commit else "rollback", count)
        assert validated == [(first, True)] + ([(first, False)] if count == 2 else [])
        assert not healthy.closed and unrelated.close_calls == 0
        assert index_calls == []
        expected = healthy
    else:
        expected = first

    repo.initialize_schema()
    assert index_calls == [expected]
    assert repo._connection is None and expected.closed
    assert acquired == ([first, healthy] if fault else [first])
    assert validated[-2:] == [(expected, True), (expected, False)]
    assert expected.events == [
        ("rollback", 0),
        ("commit", 0),
        ("commit", 0),
        ("commit", 0),
        ("begin", 1),
        ("commit", 1),
        ("begin", 2),
        ("commit", 2),
        ("commit", 2),
    ]
    assert expected.info.transaction_status == TransactionStatus.IDLE
    assert expected.closed and other.connection is unrelated
    repo.close()
    assert expected.closed and expected.close_calls == 1 and repo._connection is None
    assert unrelated.close_calls == 0
    other.close()


@pytest.mark.parametrize(
    ("status", "autocommit"),
    [
        (TransactionStatus.INTRANS, False),
        (TransactionStatus.INERROR, False),
        (TransactionStatus.IDLE, True),
    ],
)
def test_actual_owner_initializer_refuses_borrowed_or_autocommit_connection(status, autocommit):
    from c2hunter_controller import historical_ai_sql as sql
    from c2hunter_controller._baseline_storage import BaselineStorageError

    connection = InitializerConnection()
    connection.info.transaction_status = status
    connection.autocommit = autocommit
    with pytest.raises(BaselineStorageError, match="^BASELINE_BUSY$"):
        sql.initialize_postgres(connection)
    assert connection.events == [] and connection.queries == []
    assert connection.info.transaction_status == status
    assert connection.close_calls == 0


def test_actual_owner_catalog_refusal_rolls_back_and_closes_unpublished_connection(monkeypatch):
    from c2hunter_controller.historical_ai_storage import HistoricalStorageError

    connection = InitializerConnection()
    monkeypatch.setattr(psycopg, "connect", lambda *args, **kwargs: connection)
    repo = PostgresRepository("postgresql://initializer.invalid/unit", object())
    # No initializer or catalog-validator replacement: missing table metadata
    # must reach the actual fail-closed validation rather than publish a handle.
    with pytest.raises(HistoricalStorageError):
        repo.initialize_schema()
    assert "FROM pg_class" in connection.queries[-1]
    assert connection.events[-2:] == [("begin", 1), ("rollback", 1)]
    assert connection.closed and connection.close_calls == 1 and repo._connection is None
