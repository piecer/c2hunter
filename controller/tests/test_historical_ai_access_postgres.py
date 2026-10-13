"""PG adapter/SQL construction units only: no PostgreSQL engine is started."""

from contextlib import contextmanager
from types import SimpleNamespace

import pytest
from psycopg.pq import TransactionStatus

from c2hunter_controller import historical_ai_descendants as d
from c2hunter_controller import historical_ai_sql as sql
from c2hunter_controller.historical_ai_access import HistoricalAccessDenied, public_ai_access
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository
from tests.test_historical_ai_access import completed


class RecordingConnection:
    autocommit = False
    closed = False

    def __init__(self, metadata):
        self.metadata = iter(metadata)
        self.calls = []
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)

    @contextmanager
    def transaction(self):
        self.calls.append("BEGIN")
        try:
            yield
        finally:
            self.calls.append("END")

    @contextmanager
    def cursor(self):
        yield self

    def execute(self, statement, values=()):
        self.calls.append(statement)
        assert not statement.startswith("SELECT data FROM"), "private body crossed PG driver"
        return self

    def fetchone(self):
        node = next(self.metadata)
        return (
            None
            if node is None
            else (
                True,
                *(node.fields[k] for k in d.IDENTITIES),
                node.mode,
                node.historical,
                node.invalid,
                node.identity_ok,
                node.owner,
                node.size,
                node.fields["created_at"],
            )
        )


def test_pg_descendant_metadata_uses_one_owned_repeatable_read_readonly_cursor():
    memory = MemoryRepository()
    _, assessment, _ = completed(memory)
    connection = RecordingConnection(d.MemoryAccess(memory).chain("A", assessment["id"]))
    repository = PostgresRepository("postgresql://unit-only", object())
    repository._connection = connection
    with public_ai_access(1, compact_runs=True), pytest.raises(HistoricalAccessDenied):
        repository.get_ai_assessment(assessment["id"])
    assert connection.calls[:4] == [
        "BEGIN",
        "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ",
        "SET LOCAL lock_timeout='5s'",
        "SET TRANSACTION READ ONLY",
    ]
    assert connection.calls[-1] == "END"
    assert sum("jsonb_object_keys" in call for call in connection.calls) == 2
    assert "LEFT JOIN ai_analysis_runs n1 ON n0.ai_run_id=n1.run_id" in connection.calls[-2]
    assert "CASE WHEN" in connection.calls[-2] and "octet_length" in connection.calls[-2]


def test_pg_descendant_does_not_borrow_foreign_transaction():
    repository = PostgresRepository("postgresql://unit-only", object())
    connection = RecordingConnection([])
    connection.info.transaction_status = TransactionStatus.INTRANS
    repository._connection = connection
    with pytest.raises(ValueError, match="BASELINE_BUSY"):
        repository.get_ai_artifact("not-read")
    assert connection.calls == []


def test_pg_run_mutation_locks_job_before_run(monkeypatch):
    memory = MemoryRepository()
    run, _, _ = completed(memory)
    current = memory.get_ai_run(run["id"])
    store = object.__new__(sql.RunSQL)
    store.postgres = True
    store.cursor = object()
    calls = []

    class Result:
        def fetchone(self):
            return (current["analysis_job_id"],)

    def execute(statement, values=()):
        calls.append(statement)
        return Result()

    monkeypatch.setattr(store, "execute", execute)
    monkeypatch.setattr(
        d.SQLAccess, "chain", lambda self, *args: d.MemoryAccess(memory).chain("R", run["id"])
    )

    class ReachedRun(Exception):
        pass

    def get(*args, **kwargs):
        calls.append("RUN FOR UPDATE")
        raise ReachedRun()

    monkeypatch.setattr(store, "get", get)
    with pytest.raises(ReachedRun):
        store.save(current)
    assert calls[0] == "SELECT pg_advisory_xact_lock(hashtextextended('pcap-export-admission',0))"
    assert calls[1] == "SELECT id FROM controller_objects WHERE kind='job' AND id=? FOR UPDATE"
    assert calls[-1] == "RUN FOR UPDATE"
