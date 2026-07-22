from __future__ import annotations

import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, cast

import pytest

from c2hunter_controller.production import MinioBlobStore, PostgresRepository


class FakeCursor:
    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, _query: str) -> None:
        return None


class FakeConnection:
    def __init__(self, *, execute_error: Exception | None = None) -> None:
        self.closed = False
        self.execute_error = execute_error

    def cursor(self) -> FakeCursor:
        if self.execute_error is not None:
            raise self.execute_error
        return FakeCursor()

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
