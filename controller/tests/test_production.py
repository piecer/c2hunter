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
        self._last_row: tuple[object, ...] | None = None
        self._rows: list[tuple[object, ...]] = []

    def __enter__(self) -> FakeCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: tuple | None = None) -> None:
        connection = cast(FakeConnection, self.connection)
        if getattr(connection, "execute_error", None) is not None:
            raise connection.execute_error
        self.connection.queries.append(query)
        if "RETURNING job_id" in query:
            self._last_row = ("job-id",)
        elif "SELECT job_id FROM job_idempotency" in query:
            self._last_row = ("job-1",)

    def fetchone(self) -> tuple[object, ...] | None:
        return self._last_row

    def fetchall(self) -> list[tuple[object, ...]]:
        return self._rows


class FakeConnection:
    def __init__(self, *, execute_error: Exception | None = None) -> None:
        self.closed = False
        self.execute_error = execute_error
        self.queries: list[str] = []
        self.rolled_back = False

    def cursor(self) -> FakeCursor:
        return FakeCursor(self)

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


class FailingHeartbeatCursor(FakeCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        super().execute(query, params)
        if "INSERT INTO audit_events" in query:
            raise RuntimeError("audit failed")

    def fetchone(self) -> tuple[dict[str, Any]]:
        return ({"sensor_id": "sensor-a", "config_version": 7},)


class FailingHeartbeatConnection(FakeConnection):
    def __init__(self) -> None:
        super().__init__()
        self.rolled_back = False

    def cursor(self) -> FailingHeartbeatCursor:
        return FailingHeartbeatCursor(self)

    def rollback(self) -> None:
        self.rolled_back = True


class PresetCursor(FakeCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        super().execute(query, params)
        connection = cast(PresetConnection, self.connection)
        if connection.fail_audit and "INSERT INTO audit_events" in query:
            raise RuntimeError("preset audit failed")
        if connection.fail_update and "UPDATE controller_objects SET data" in query:
            raise RuntimeError("preset update failed")

    def fetchall(self) -> list[tuple[str, dict[str, Any]]]:
        return list(cast(PresetConnection, self.connection).preset_rows)


class PresetConnection(FakeConnection):
    def __init__(
        self,
        rows: list[tuple[str, dict[str, Any]]],
        *,
        fail_audit: bool = False,
        fail_update: bool = False,
    ) -> None:
        super().__init__()
        self.preset_rows = rows
        self.fail_audit = fail_audit
        self.fail_update = fail_update
        self.rolled_back = False

    def cursor(self) -> PresetCursor:
        return PresetCursor(self)

    def rollback(self) -> None:
        self.rolled_back = True


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
    assert "CREATE TABLE IF NOT EXISTS job_flow_record_chunks" in schema
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
    fake_psycopg = SimpleNamespace(connect=lambda *a, **kw: FakeConnection())
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))
    stored: dict[str, Any] = {}

    def put(kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        stored.update({kind: kind, "object_id": object_id, "value": value})
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
    # save_job_metadata now uses direct DB calls (not _put), verify queries were issued
    conn = repository.connection
    assert any("controller_objects" in q for q in conn.queries)


def test_heartbeat_update_rolls_back_failed_transaction(monkeypatch: Any) -> None:
    connection = FailingHeartbeatConnection()
    fake_psycopg = SimpleNamespace(connect=lambda *args, **kwargs: connection)
    monkeypatch.setitem(sys.modules, "psycopg", fake_psycopg)
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    with pytest.raises(RuntimeError, match="audit failed"):
        repository.update_sensor_heartbeat(
            "sensor-a", {"last_heartbeat_at": "2026-07-30T20:00:00+00:00"}
        )

    assert connection.rolled_back


def test_missing_preset_default_update_does_not_clear_existing_default(
    monkeypatch: Any,
) -> None:
    connection = PresetConnection(
        [("current", {"id": "current", "name": "Current", "is_default": True})]
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))
    _ = repository.connection
    connection.queries.clear()

    result = repository.update_detector_weight_preset("missing", {}, set_as_default=True)

    assert result is None
    assert not any("UPDATE controller_objects SET data" in query for query in connection.queries)


def test_preset_update_rolls_back_failed_audit(monkeypatch: Any) -> None:
    connection = PresetConnection(
        [("current", {"id": "current", "name": "Current", "is_default": True})],
        fail_audit=True,
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    with pytest.raises(RuntimeError, match="preset audit failed"):
        repository.update_detector_weight_preset("current", {"name": "Updated"})

    assert connection.rolled_back


def test_default_preset_save_acquires_database_wide_transaction_lock(
    monkeypatch: Any,
) -> None:
    connection = PresetConnection([])
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))
    _ = repository.connection
    connection.queries.clear()

    repository.save_detector_weight_preset({"id": "new", "name": "New", "is_default": True})

    lock_index = next(
        index for index, query in enumerate(connection.queries) if "pg_advisory_xact_lock" in query
    )
    insert_index = next(
        index
        for index, query in enumerate(connection.queries)
        if "INSERT INTO controller_objects" in query
    )
    assert lock_index < insert_index


def test_set_default_preset_rolls_back_when_update_fails(monkeypatch: Any) -> None:
    connection = PresetConnection(
        [("current", {"id": "current", "name": "Current", "is_default": True})],
        fail_update=True,
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    with pytest.raises(RuntimeError, match="preset update failed"):
        repository.set_default_detector_weight_preset("current")

    assert connection.rolled_back


def test_json_array_chunks_bounded_size() -> None:
    large_value = {"data": "x" * 100_000}
    chunks = PostgresRepository._json_array_chunks([large_value])
    for chunk in chunks:
        assert len(chunk.encode("utf-8")) <= (
            PostgresRepository._FLOW_RECORD_CHUNK_TARGET_BYTES + 1
        )


def test_replacement_splitting_large_flow_records(monkeypatch: Any) -> None:
    fake_connection = FakeConnection()
    monkeypatch.setitem(
        sys.modules, "psycopg", SimpleNamespace(connect=lambda *a, **kw: fake_connection)
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    large_record = {"flow": "z" * 20_000}
    job = {
        "id": "job-1",
        "status": "RUNNING",
        "flow_records": [large_record],
        "payload_signatures": [],
        "idempotency_key": "key-1",
    }

    repository.create_job(job)
    chunk_queries = [q for q in fake_connection.queries if "job_flow_record_chunks" in q]
    assert len(chunk_queries) >= 1


def test_replacing_job_flow_records_rolls_back_on_failure(monkeypatch: Any) -> None:
    class FlowFailCursor(FakeCursor):
        def execute(self, query, params=None):
            super().execute(query, params)
            if "DELETE FROM job_flow_record_chunks WHERE job_id" in query:
                raise RuntimeError("disk full")

    class FlowFailConnection(FakeConnection):
        def cursor(self) -> FakeCursor:
            return FlowFailCursor(self)

    failing_connection = FlowFailConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *a, **kw: failing_connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    job = {
        "id": "job-1",
        "status": "RUNNING",
        "flow_records": [{"source_ip": "10.0.0.1"}],
        "payload_signatures": [],
        "idempotency_key": "key-1",
    }

    with pytest.raises(RuntimeError, match="disk full"):
        repository.create_job(job)

    assert failing_connection.rolled_back
