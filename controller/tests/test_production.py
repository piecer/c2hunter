from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, cast

import pytest

from c2hunter_controller.production import MinioBlobStore, PostgresRepository


class FakeCursor:
    def __init__(self, connection: FakeConnection) -> None:
        self.connection = connection

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str) -> None:
        self.connection.queries.append(query)


class FakeConnection:
    def __init__(self, *, execute_error: Exception | None = None) -> None:
        self.closed = False
        self.execute_error = execute_error
        self.queries: list[str] = []

    def cursor(self) -> FakeCursor:
        if self.execute_error is not None:
            raise self.execute_error
        return FakeCursor(self)

    def commit(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_connection_initialization_is_thread_safe(monkeypatch: Any) -> None:
    first_connect_started = threading.Event()
    second_connect_started = threading.Event()
    second_worker_started = threading.Event()
    release_first_connect = threading.Event()
    connection_count = 0
    count_lock = threading.Lock()

    def connect(_database_url: str, *, autocommit: bool) -> FakeConnection:
        nonlocal connection_count
        assert autocommit is False
        with count_lock:
            connection_count += 1
            invocation = connection_count
        if invocation == 1:
            first_connect_started.set()
            assert release_first_connect.wait(timeout=2)
        else:
            second_connect_started.set()
        return FakeConnection()

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    def get_second_connection() -> FakeConnection:
        second_worker_started.set()
        return repository.connection

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(lambda: repository.connection)
        assert first_connect_started.wait(timeout=1)
        second = executor.submit(get_second_connection)
        assert second_worker_started.wait(timeout=1)
        initialized_twice = second_connect_started.wait(timeout=0.2)
        release_first_connect.set()
        assert not initialized_twice
        assert first.result(timeout=1) is second.result(timeout=1)

    assert connection_count == 1
    schema = "\n".join(first.result().queries)
    assert "CREATE TABLE IF NOT EXISTS job_flow_records" in schema
    assert "CREATE TABLE IF NOT EXISTS job_payload_signatures" in schema
    assert "SET data=data-'flow_records'" in schema
    assert "SET data=data-'payload_signatures'" in schema


def test_failed_connection_initialization_closes_connection_and_can_retry(monkeypatch: Any) -> None:
    failed_connection = FakeConnection(execute_error=RuntimeError("schema initialization failed"))
    successful_connection = FakeConnection()
    connections = iter((failed_connection, successful_connection))

    def connect(_database_url: str, *, autocommit: bool) -> FakeConnection:
        assert autocommit is False
        return next(connections)

    monkeypatch.setitem(sys.modules, "psycopg", SimpleNamespace(connect=connect))
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    with pytest.raises(RuntimeError, match="schema initialization failed"):
        _ = repository.connection

    assert failed_connection.closed
    assert repository.connection is successful_connection


def test_job_metadata_write_excludes_immutable_flow_payload(monkeypatch: Any) -> None:
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))
    stored: dict[str, Any] = {}

    def put(kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        stored.update({"kind": kind, "object_id": object_id, "value": value})
        return value

    monkeypatch.setattr(repository, "_put", put)

    result = repository.save_job_metadata(
        {
            "id": "job-1",
            "status": "COMPLETED",
            "flow_records": [{"large": "payload"}],
            "payload_signatures": [{"id": "signature-1"}],
        }
    )

    assert result == {"id": "job-1", "status": "COMPLETED"}
    assert stored["value"] == {"id": "job-1", "status": "COMPLETED"}
