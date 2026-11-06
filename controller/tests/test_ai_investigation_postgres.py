"""PostgreSQL public query contract; fake cursor, NOT live-PG acceptance."""

import json
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from psycopg.pq import TransactionStatus

from c2hunter_controller.production import PostgresRepository
from tests.test_ai_investigation_evidence import flow, job, read


class Connection:
    def __init__(self, *, size: int = 1000) -> None:
        self.info = SimpleNamespace(transaction_status=TransactionStatus.IDLE)
        self.closed = False
        self.autocommit = False
        self.size = size
        self.queries: list[str] = []
        self.payload_reads = 0
        self.active = False

    @contextmanager
    def transaction(self) -> Any:
        self.active = True
        try:
            yield
        finally:
            self.active = False

    def cursor(self, name: str | None = None) -> Any:
        return Cursor(self, name)


class Cursor:
    def __init__(self, connection: Connection, name: str | None) -> None:
        self.connection = connection
        self.name = name
        self.rows: list[Any] = []

    def __enter__(self) -> Any:
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def execute(self, sql: str, args: Any = None) -> None:
        assert self.connection.active
        self.connection.queries.append(sql)
        metadata = job()
        metadata.pop("flow_records")
        if sql.startswith("SET TRANSACTION"):
            assert "REPEATABLE READ" in sql and "READ ONLY" in sql
            self.rows = []
        elif sql.startswith("SET LOCAL"):
            self.rows = []
        elif "SELECT octet_length(data::text) FROM controller_objects" in sql:
            self.rows = [(len(json.dumps(metadata)),)]
        elif "SELECT data::text FROM controller_objects" in sql:
            self.rows = [(json.dumps(metadata),)]
        elif "SELECT chunk_no" in sql:
            self.rows = [(0,)]
        elif "SELECT 1 FROM job_flow_records" in sql:
            self.rows = []
        elif "SELECT 1 FROM job_flow_record_chunks" in sql:
            self.rows = [(1,)]
        elif "sum(octet_length" in sql:
            self.rows = [(self.connection.size,)]
        elif "jsonb_typeof(data)!='array'" in sql:
            self.rows = [(0,)]
        elif "sum(jsonb_array_length" in sql:
            self.rows = [(1,)]
        elif "max(octet_length" in sql:
            self.rows = [(len(json.dumps(flow())), 0)]
        elif sql.startswith("SELECT j.value::text"):
            self.connection.payload_reads += 1
            assert self.name is not None
            self.rows = [(json.dumps(flow()),)]
        else:
            raise AssertionError(sql)

    def fetchone(self) -> Any:
        return self.rows.pop(0) if self.rows else None

    def fetchmany(self, size: int) -> Any:
        result, self.rows = self.rows[:size], self.rows[size:]
        return result


def repository(connection: Connection) -> Any:
    result = object.__new__(PostgresRepository)
    result._connection = connection
    result._lock = threading.RLock()
    return result


def test_pg_read_only_snapshot_and_pretransfer_bound() -> None:
    connection = Connection()
    snapshot = read(repository(connection))
    assert snapshot.rows[0].total_bytes == 80
    assert connection.payload_reads == 1
    assert not connection.active
    assert connection.queries[0] == "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY"
    oversized = Connection(size=8 * 1024 * 1024 + 1)
    with pytest.raises(ValueError, match="^SOURCE_LIMIT$"):
        read(repository(oversized))
    assert oversized.payload_reads == 0
    assert not oversized.active
