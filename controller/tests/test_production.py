from __future__ import annotations

import io
import logging
import sys
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any, cast

import pytest

import c2hunter_controller.production as production
from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.repositories import (
    ArtifactAlreadyExistsError,
    ArtifactProducerError,
    ArtifactStorageError,
    ArtifactWriteResult,
    CaptureSource,
)


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
        self.autocommit = False
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


class FailingConcurrentIndexCursor(FakeCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        if "CREATE INDEX CONCURRENTLY" in query:
            self.connection.queries.append(query)
            raise RuntimeError("concurrent index failed")
        super().execute(query, params)


class FailingConcurrentIndexConnection(FakeConnection):
    def cursor(self) -> FailingConcurrentIndexCursor:
        return FailingConcurrentIndexCursor(self)


def test_background_worker_repository_uses_an_independent_connection_boundary() -> None:
    blob_store = cast(MinioBlobStore, object())
    repository = PostgresRepository("postgresql://controller", blob_store)
    worker_repository = repository.for_background_worker()
    primary_connection = FakeConnection()
    worker_connection = FakeConnection()
    repository._connection = primary_connection
    worker_repository._connection = worker_connection

    assert worker_repository is not repository
    assert worker_repository.database_url == repository.database_url
    assert worker_repository.connection is worker_connection
    assert repository.connection is primary_connection

    worker_repository.close()
    worker_repository.close()

    assert worker_connection.closed is True
    assert primary_connection.closed is False


def test_postgres_candidate_workflow_counts_are_aggregated_in_database() -> None:
    repository = PostgresRepository("postgresql://controller", cast(MinioBlobStore, object()))
    connection = FakeConnection()
    repository._connection = connection

    counts = repository.candidate_workflow_counts(
        minimum_score=50,
        severity="HIGH",
        include_suppressed=False,
    )

    sql = "\n".join(connection.queries)
    assert "WITH selected AS" in sql
    assert "COUNT(*) FILTER" in sql
    assert "current_decision" in sql
    assert counts == {
        "needs_review": 0,
        "in_review": 0,
        "action_required": 0,
        "action_in_progress": 0,
        "action_completed": 0,
        "false_positive": 0,
        "done": 0,
    }


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


class DeleteJobCursor(FakeCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        super().execute(query, params)
        self._last_row = (
            ({"id": "job-1", "idempotency_key": "job-key"},)
            if "kind='job' AND id=%s FOR UPDATE" in query
            else None
        )
        if "data->>'status' FROM ai_analysis_runs" in query:
            self._rows = [("COMPLETED",)]
        else:
            self._rows = [("exports/job-1.zip",)] if "data->>'object_key'" in query else []


class DeleteJobConnection(FakeConnection):
    def __init__(self) -> None:
        super().__init__()
        self.commit_count = 0

    def cursor(self) -> DeleteJobCursor:
        return DeleteJobCursor(self)

    def commit(self) -> None:
        self.commit_count += 1


class FailingDeleteJobCursor(DeleteJobCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        if "DELETE FROM ai_generated_artifacts" in query:
            raise RuntimeError("forced PostgreSQL retention failure")
        super().execute(query, params)


class FailingDeleteJobConnection(DeleteJobConnection):
    def cursor(self) -> FailingDeleteJobCursor:
        return FailingDeleteJobCursor(self)


class ActiveDeleteJobCursor(DeleteJobCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        super().execute(query, params)
        if "data->>'status' FROM ai_analysis_runs" in query:
            self._rows = [("ANALYZING",)]


class ActiveDeleteJobConnection(DeleteJobConnection):
    def cursor(self) -> ActiveDeleteJobCursor:
        return ActiveDeleteJobCursor(self)


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
    queries = first.result().queries
    schema = queries[0]
    concurrent_indexes = "\n".join(queries[1:])
    assert "CREATE TABLE IF NOT EXISTS job_flow_records" in schema
    assert "CREATE TABLE IF NOT EXISTS candidate_records" in schema
    assert "candidate_records_last_seen" not in schema
    assert "candidate_records_score" not in schema
    assert "candidate_records_first_seen" not in schema
    assert "candidate_records_ip" not in schema
    assert "controller_objects_candidate_workflow" not in schema
    assert "pg_advisory_lock" in concurrent_indexes
    assert "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_last_seen" in (
        concurrent_indexes
    )
    assert "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_score" in concurrent_indexes
    assert "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_first_seen" in (
        concurrent_indexes
    )
    assert "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_ip" in concurrent_indexes
    assert "CREATE INDEX CONCURRENTLY IF NOT EXISTS controller_objects_candidate_workflow" in (
        concurrent_indexes
    )
    assert "pg_advisory_unlock" in concurrent_indexes
    assert first.result().autocommit is False
    assert "WHERE candidate ? 'id'" in schema
    assert "DELETE FROM job_candidates AS legacy" in schema
    assert "record.job_id=legacy.job_id" in schema
    assert "DELETE FROM job_candidates;" not in schema
    assert "CREATE TABLE IF NOT EXISTS job_flow_record_chunks" in schema
    assert "CREATE TABLE IF NOT EXISTS job_payload_signatures" in schema
    assert "CREATE TABLE IF NOT EXISTS ai_feedback" in schema
    assert "ai_feedback_assessment_created" in schema
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


def test_failed_concurrent_index_initialization_restores_connection_state(
    monkeypatch: Any,
) -> None:
    connection = FailingConcurrentIndexConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    with pytest.raises(RuntimeError, match="concurrent index failed"):
        _ = repository.connection

    assert any("pg_advisory_unlock" in query for query in connection.queries)
    assert connection.autocommit is False
    assert connection.closed is True


def test_delete_job_cascades_ai_ledgers_before_run(monkeypatch: Any) -> None:
    connection = DeleteJobConnection()
    deleted: list[str] = []
    blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(delete=lambda object_key: deleted.append(object_key)),
    )
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", blob_store)
    _ = repository.connection
    connection.queries.clear()

    assert repository.delete_job("job-1") is True

    sql = "\n".join(connection.queries)
    assert "DELETE FROM ai_feedback" in sql
    assert "DELETE FROM ai_generated_artifacts" in sql
    assert "DELETE FROM ai_candidate_assessments" in sql
    assert "DELETE FROM ai_analysis_runs" in sql
    assert sql.index("DELETE FROM ai_feedback") < sql.index("DELETE FROM ai_analysis_runs")
    assert connection.commit_count >= 2
    assert deleted == ["exports/job-1.zip", "captures/job-1.pcap"]


def test_delete_job_refuses_active_postgresql_ai_run(monkeypatch: Any) -> None:
    connection = ActiveDeleteJobConnection()
    deleted: list[str] = []
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository(
        "postgresql://test",
        cast(MinioBlobStore, SimpleNamespace(delete=deleted.append)),
    )
    _ = repository.connection
    connection.queries.clear()

    assert repository.delete_job("job-1") is False
    assert not any(query.startswith("DELETE") for query in connection.queries)
    assert deleted == []


def test_delete_job_rolls_back_postgresql_transaction_on_ai_cascade_failure(
    monkeypatch: Any,
) -> None:
    connection = FailingDeleteJobConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))
    _ = repository.connection
    connection.rolled_back = False

    with pytest.raises(RuntimeError, match="forced PostgreSQL retention failure"):
        repository.delete_job("job-1")

    assert connection.rolled_back


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


def test_candidate_workflow_resource_uses_object_store_and_audit(monkeypatch: Any) -> None:
    connection = FakeConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *args, **kwargs: connection),
    )
    repository = PostgresRepository("postgresql://test", cast(MinioBlobStore, SimpleNamespace()))

    repository.save_candidate_decision(
        {
            "id": "decision-1",
            "candidate_id": "candidate-1",
            "verdict": "CONFIRMED_C2",
            "created_at": "2026-08-08T00:00:00+00:00",
        }
    )
    action = {
        "id": "action-1",
        "candidate_id": "candidate-1",
        "verdict_id": "decision-1",
        "status": "PENDING",
        "note": "response required",
        "created_at": "2026-08-08T00:01:00+00:00",
    }
    saved_action = repository.save_candidate_action(action)

    assert saved_action == action
    assert sum("INSERT INTO controller_objects" in query for query in connection.queries) == 2
    assert sum("INSERT INTO audit_events" in query for query in connection.queries) == 2


def test_postgres_export_save_cleans_blob_when_parent_is_missing() -> None:
    uploaded: list[tuple[str, bytes]] = []
    deleted: list[str] = []

    def put_stream(
        key: str, chunks: Iterable[bytes], *, size_hint: int, content_type: str
    ) -> ArtifactWriteResult:
        content = b"".join(chunks)
        uploaded.append((key, content))
        assert size_hint == len(content)
        assert content_type == "application/vnd.tcpdump.pcap"
        return ArtifactWriteResult(len(content), __import__("hashlib").sha256(content).hexdigest())

    blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put_stream=put_stream,
            delete=lambda key: deleted.append(key),
        ),
    )
    repository = PostgresRepository("postgresql://controller", blob_store)
    connection = FakeConnection()
    repository._connection = connection

    stored = repository.save_export(
        {"id": "export-1", "job_id": "deleted-job", "capture_format": "PCAP"},
        b"capture",
    )

    assert stored is None
    assert len(uploaded) == 1
    assert uploaded[0][0].startswith("exports/export-1/")
    assert uploaded[0][0].endswith(".pcap")
    assert uploaded[0][1] == b"capture"
    assert deleted == [uploaded[0][0]]
    assert any("FOR UPDATE" in query for query in connection.queries)
    assert not any("INSERT INTO controller_objects" in query for query in connection.queries)


class ExportPublicationCursor(FakeCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        super().execute(query, params)
        connection = cast(ExportPublicationConnection, self.connection)
        if "kind='job'" in query and "FOR UPDATE" in query:
            self._last_row = (1,)
        elif "kind='export'" in query and "FOR UPDATE" in query:
            self._last_row = (1,) if connection.duplicate else None
        if connection.fail_at and connection.fail_at in query:
            raise RuntimeError("private database fault")


class ExportPublicationConnection(FakeConnection):
    def __init__(
        self,
        *,
        duplicate: bool = False,
        fail_at: str | None = None,
        fail_commit: bool = False,
        fail_rollback: bool = False,
    ) -> None:
        super().__init__()
        self.duplicate = duplicate
        self.fail_at = fail_at
        self.fail_commit = fail_commit
        self.fail_rollback = fail_rollback

    def cursor(self) -> ExportPublicationCursor:
        return ExportPublicationCursor(self)

    def commit(self) -> None:
        if self.fail_commit:
            raise RuntimeError("private commit fault")

    def rollback(self) -> None:
        self.rolled_back = True
        if self.fail_rollback:
            raise RuntimeError("private rollback fault")


def _postgres_export_repository(
    connection: ExportPublicationConnection,
    deleted: list[str],
    *,
    delete_fails: bool = False,
) -> PostgresRepository:
    def put_stream(
        _key: str, chunks: Iterable[bytes], *, size_hint: int, content_type: str
    ) -> ArtifactWriteResult:
        content = b"".join(chunks)
        assert len(content) == size_hint
        assert content_type == "application/vnd.tcpdump.pcap"
        return ArtifactWriteResult(size_hint, __import__("hashlib").sha256(content).hexdigest())

    def delete(key: str) -> None:
        deleted.append(key)
        if delete_fails:
            raise RuntimeError("private cleanup fault")

    repository = PostgresRepository(
        "postgresql://controller",
        cast(MinioBlobStore, SimpleNamespace(put_stream=put_stream, delete=delete)),
    )
    repository._connection = connection
    return repository


def test_postgres_duplicate_cannot_replace_or_delete_published_object() -> None:
    objects = {"exports/immutable.pcap": b"ORIGINAL"}
    deleted: list[str] = []

    def put_stream(
        key: str, chunks: Iterable[bytes], *, size_hint: int, content_type: str
    ) -> ArtifactWriteResult:
        content = b"".join(chunks)
        objects[key] = content
        return ArtifactWriteResult(size_hint, __import__("hashlib").sha256(content).hexdigest())

    def delete(key: str) -> None:
        deleted.append(key)
        objects.pop(key, None)

    repository = PostgresRepository(
        "postgresql://controller",
        cast(MinioBlobStore, SimpleNamespace(put_stream=put_stream, delete=delete)),
    )
    repository._connection = ExportPublicationConnection(duplicate=True)

    with pytest.raises(ArtifactAlreadyExistsError):
        repository.save_export_stream(
            {"id": "immutable", "job_id": "job-1", "capture_format": "PCAP"},
            iter((b"REPLACED",)),
            size_hint=8,
        )

    assert objects == {"exports/immutable.pcap": b"ORIGINAL"}
    assert len(deleted) == 1
    assert deleted[0] != "exports/immutable.pcap"


def test_postgres_concurrent_duplicate_has_one_winner_and_no_orphan() -> None:
    objects: dict[str, bytes] = {}
    upload_barrier = threading.Barrier(2)

    class ConcurrentCursor(FakeCursor):
        def execute(self, query: str, params: tuple | None = None) -> None:
            super().execute(query, params)
            connection = cast(ConcurrentConnection, self.connection)
            if "kind='job'" in query and "FOR UPDATE" in query:
                self._last_row = (1,)
            elif "kind='export'" in query and "FOR UPDATE" in query:
                self._last_row = (1,) if connection.published is not None else None
            elif "INSERT INTO controller_objects" in query:
                assert params is not None
                connection.published = __import__("json").loads(params[1])

    class ConcurrentConnection(FakeConnection):
        published: dict[str, Any] | None = None

        def cursor(self) -> ConcurrentCursor:
            return ConcurrentCursor(self)

    def put_stream(
        key: str, chunks: Iterable[bytes], *, size_hint: int, content_type: str
    ) -> ArtifactWriteResult:
        content = b"".join(chunks)
        objects[key] = content
        upload_barrier.wait(timeout=2)
        return ArtifactWriteResult(size_hint, __import__("hashlib").sha256(content).hexdigest())

    blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put_stream=put_stream,
            delete=lambda key: objects.pop(key, None),
        ),
    )
    repository = PostgresRepository("postgresql://controller", blob_store)
    connection = ConcurrentConnection()
    repository._connection = connection

    def publish(content: bytes) -> str:
        try:
            repository.save_export_stream(
                {"id": "raced", "job_id": "job-1", "capture_format": "PCAP"},
                iter((content,)),
                size_hint=len(content),
            )
            return "winner"
        except ArtifactAlreadyExistsError:
            return "loser"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(publish, (b"FIRST", b"SECOND")))

    assert sorted(outcomes) == ["loser", "winner"]
    assert connection.published is not None
    winning_key = connection.published["object_key"]
    assert objects == {winning_key: objects[winning_key]}
    assert objects[winning_key] in {b"FIRST", b"SECOND"}


def test_postgres_duplicate_preserves_primary_when_rollback_and_cleanup_fail() -> None:
    deleted: list[str] = []
    repository = _postgres_export_repository(
        ExportPublicationConnection(duplicate=True, fail_rollback=True),
        deleted,
        delete_fails=True,
    )

    with pytest.raises(ArtifactAlreadyExistsError):
        repository.save_export_stream(
            {"id": "immutable", "job_id": "job-1", "capture_format": "PCAP"},
            iter((b"capture",)),
            size_hint=7,
        )

    assert len(deleted) == 1
    assert deleted[0].startswith("exports/immutable/")
    assert deleted[0].endswith(".pcap")


@pytest.mark.parametrize(
    ("connection", "failed_sql"),
    [
        (ExportPublicationConnection(fail_at="INSERT INTO controller_objects"), "metadata"),
        (ExportPublicationConnection(fail_at="INSERT INTO audit_events"), "audit"),
        (ExportPublicationConnection(fail_commit=True), "commit"),
    ],
)
def test_postgres_publication_failure_compensates_uploaded_object(
    connection: ExportPublicationConnection, failed_sql: str
) -> None:
    deleted: list[str] = []
    repository = _postgres_export_repository(connection, deleted)

    with pytest.raises(ArtifactStorageError) as caught:
        repository.save_export_stream(
            {"id": f"failed-{failed_sql}", "job_id": "job-1", "capture_format": "PCAP"},
            iter((b"capture",)),
            size_hint=7,
        )

    assert "private" not in str(caught.value)
    assert connection.rolled_back
    assert len(deleted) == 1
    assert deleted[0].startswith(f"exports/failed-{failed_sql}/")
    assert deleted[0].endswith(".pcap")
    assert any("kind='job'" in query and "FOR UPDATE" in query for query in connection.queries)
    assert any("kind='export'" in query and "FOR UPDATE" in query for query in connection.queries)


class SensorPcapListCursor(FakeCursor):
    def execute(self, query: str, params: tuple | None = None) -> None:
        super().execute(query, params)
        connection = cast(SensorPcapListConnection, self.connection)
        connection.params.append(params)
        if "kind='sensor_pcap'" in query and query.lstrip().startswith("SELECT data"):
            self._rows = [
                ({"id": "segment-a", "uploaded_at": "2026-08-21T09:00:00+00:00"},),
                ({"id": "segment-b", "uploaded_at": "2026-08-21T09:00:00+00:00"},),
            ]


class SensorPcapListConnection(FakeConnection):
    def __init__(self) -> None:
        super().__init__()
        self.params: list[tuple | None] = []

    def cursor(self) -> SensorPcapListCursor:
        return SensorPcapListCursor(self)


def test_postgres_sensor_pcap_lookup_is_job_scoped_parameterized_and_indexed() -> None:
    repository = PostgresRepository("postgresql://controller", cast(MinioBlobStore, object()))
    connection = SensorPcapListConnection()
    repository._connection = connection

    segments = repository.list_sensor_pcaps_for_job("job-a")

    query = connection.queries[-1]
    assert "kind='sensor_pcap'" in query
    assert "data->>'analysis_job_id'=%s" in query
    assert "ORDER BY data->>'uploaded_at',id" in query
    assert connection.params[-1] == ("job-a",)
    assert [segment["id"] for segment in segments] == ["segment-a", "segment-b"]


def test_postgres_schema_indexes_sensor_pcaps_by_job_and_export_order(monkeypatch: Any) -> None:
    connection = FakeConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: connection),
    )
    repository = PostgresRepository("postgresql://controller", cast(MinioBlobStore, object()))

    _ = repository.connection

    schema = connection.queries[0]
    assert "controller_objects_sensor_pcap_job_uploaded_id" in schema
    assert "data->>'analysis_job_id'" in schema
    assert "data->>'uploaded_at'" in schema


class TrackingObjectResponse:
    def __init__(self, content: bytes, headers: dict[str, str]) -> None:
        self.content = content
        self.headers = headers
        self.offset = 0
        self.read_sizes: list[int] = []
        self.close_count = 0
        self.release_count = 0

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        if size < 0:
            raise AssertionError("streaming source used an unbounded response.read")
        chunk = self.content[self.offset : self.offset + size]
        self.offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.close_count += 1

    def release_conn(self) -> None:
        self.release_count += 1


def _blob_store_with_response(response: TrackingObjectResponse) -> MinioBlobStore:
    store = MinioBlobStore.__new__(MinioBlobStore)
    store.bucket = "captures"
    store.client = SimpleNamespace(get_object=lambda bucket, key: response)
    return store


def test_minio_put_stream_uses_known_size_and_rejects_unconsumed_extra_data() -> None:
    uploads: list[tuple[int, int, str, bytes]] = []
    removed: list[str] = []
    store = MinioBlobStore.__new__(MinioBlobStore)
    store.bucket = "captures"

    def put_object(
        _bucket: str,
        _key: str,
        reader: object,
        length: int,
        *,
        content_type: str,
        part_size: int,
    ) -> None:
        uploads.append((length, part_size, content_type, reader.read(length)))  # type: ignore[attr-defined]

    store.client = SimpleNamespace(
        bucket_exists=lambda _bucket: True,
        put_object=put_object,
        remove_object=lambda _bucket, key: removed.append(key),
    )

    result = store.put_stream(
        "exports/ok.pcap", iter((b"ab", b"cd")), size_hint=4, content_type="pcap/type"
    )

    assert result == ArtifactWriteResult(4, __import__("hashlib").sha256(b"abcd").hexdigest())
    assert uploads == [(4, 5 * 1024 * 1024, "pcap/type", b"abcd")]
    with pytest.raises(ArtifactProducerError, match="more than"):
        store.put_stream(
            "exports/extra.pcap",
            iter((b"abcd", b"extra")),
            size_hint=4,
            content_type="pcap/type",
        )
    assert removed == ["exports/extra.pcap"]


def test_minio_put_stream_attempts_cleanup_after_failed_upload() -> None:
    removed: list[str] = []
    store = MinioBlobStore.__new__(MinioBlobStore)
    store.bucket = "captures"

    def fail_put(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("upload failed after partial object creation")

    store.client = SimpleNamespace(
        bucket_exists=lambda _bucket: True,
        put_object=fail_put,
        remove_object=lambda _bucket, key: removed.append(key),
    )

    with pytest.raises(Exception, match="MinIO artifact upload failed"):
        store.put_stream(
            "exports/partial.pcap",
            iter((b"abcd",)),
            size_hint=4,
            content_type="pcap/type",
        )

    assert removed == ["exports/partial.pcap"]


def test_minio_open_stream_reads_bounded_chunks_and_releases_once() -> None:
    response = TrackingObjectResponse(b"abcdefgh", {})
    store = _blob_store_with_response(response)

    with store.open_stream("exports/a.pcap", chunk_size=3) as chunks:
        assert list(chunks) == [b"abc", b"def", b"gh"]
        assert response.close_count == 1
        assert response.release_count == 1

    assert response.read_sizes == [3, 3, 3, 3]
    assert response.close_count == 1
    assert response.release_count == 1


def test_minio_open_stream_close_is_idempotent_after_cancellation() -> None:
    response = TrackingObjectResponse(b"abcdefgh", {})
    store = _blob_store_with_response(response)

    with store.open_stream("exports/a.pcap", chunk_size=3) as chunks:
        assert next(chunks) == b"abc"
        chunks.close()  # type: ignore[attr-defined]
        chunks.close()  # type: ignore[attr-defined]
        assert response.close_count == 1
        assert response.release_count == 1

    assert response.close_count == 1
    assert response.release_count == 1


def test_postgres_export_metadata_fault_is_typed_storage_error(monkeypatch: Any) -> None:
    repository = PostgresRepository("postgresql://controller", cast(MinioBlobStore, object()))
    monkeypatch.setattr(
        repository,
        "_get",
        lambda *_args: (_ for _ in ()).throw(RuntimeError("private metadata fault")),
    )

    with pytest.raises(ArtifactStorageError, match="metadata lookup") as caught:
        repository.get_export_metadata("export-1")
    assert "private" not in str(caught.value)


def test_postgres_export_metadata_cursor_fault_is_typed_storage_error() -> None:
    repository = PostgresRepository("postgresql://controller", cast(MinioBlobStore, object()))
    repository._connection = FakeConnection(execute_error=RuntimeError("private cursor fault"))

    with pytest.raises(ArtifactStorageError, match="metadata lookup") as caught:
        repository.open_export_stream("export-1")
    assert "private" not in str(caught.value)


def test_minio_open_stream_read_failure_releases_once() -> None:
    class ReadFaultResponse(TrackingObjectResponse):
        def read(self, size: int = -1) -> bytes:
            super().read(size)
            raise OSError("private read fault")

    response = ReadFaultResponse(b"bad", {})
    store = _blob_store_with_response(response)

    with pytest.raises(ArtifactStorageError, match="read failed"):
        with store.open_stream("exports/a.pcap", chunk_size=3) as chunks:
            next(chunks)

    assert response.close_count == 1
    assert response.release_count == 1


def test_minio_open_stream_close_failure_at_eof_is_typed() -> None:
    class CloseFaultResponse(TrackingObjectResponse):
        def close(self) -> None:
            super().close()
            raise OSError("private close fault")

    response = CloseFaultResponse(b"", {})
    store = _blob_store_with_response(response)

    with pytest.raises(ArtifactStorageError, match="stream close") as caught:
        with store.open_stream("exports/a.pcap", chunk_size=3) as chunks:
            list(chunks)

    assert "private" not in str(caught.value)
    assert response.close_count == 1
    assert response.release_count == 1


def test_minio_open_stream_rejects_nonbytes_without_hiding_backend_defect() -> None:
    class NonBytesResponse(TrackingObjectResponse):
        def read(self, size: int = -1) -> bytes:
            value = super().read(size)
            return bytearray(value)  # type: ignore[return-value]

    response = NonBytesResponse(b"bad", {})
    store = _blob_store_with_response(response)

    with pytest.raises(ArtifactStorageError, match="non-bytes"):
        with store.open_stream("exports/a.pcap", chunk_size=3) as chunks:
            list(chunks)

    assert response.close_count == 1
    assert response.release_count == 1


def test_minio_open_is_lazy_bounded_and_releases_connection_once() -> None:
    response = TrackingObjectResponse(b"abcdefgh", {"x-amz-version-id": "version-7"})
    store = _blob_store_with_response(response)

    source = store.open("captures/job-a.pcap")

    assert response.read_sizes == []
    assert source.version_id == "s3-version:version-7"
    assert list(source.iter_chunks(3)) == [b"abc", b"def", b"gh"]
    assert response.read_sizes == [3, 3, 3, 3]
    source.close()
    source.close()
    assert response.close_count == 1
    assert response.release_count == 1


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        (
            {"x-amz-version-id": "immutable-version", "etag": '"ignored"'},
            "s3-version:immutable-version",
        ),
        ({"ETag": '"opaque-etag"'}, "etag:opaque-etag"),
        ({"x-amz-version-id": "", "ETag": ' "empty-fallback" '}, "etag:empty-fallback"),
        ({"x-amz-version-id": "null", "ETag": '"null-fallback"'}, "etag:null-fallback"),
        ({"x-amz-version-id": " NuLl ", "ETag": '"case-fallback"'}, "etag:case-fallback"),
    ],
)
def test_minio_version_identity_prefers_version_and_normalizes_etag(
    headers: dict[str, str], expected: str
) -> None:
    response = TrackingObjectResponse(b"payload", headers)
    source = _blob_store_with_response(response).open("mutable-key")

    assert source.version_id == expected
    source.close()


def test_minio_open_without_version_identity_closes_response_and_fails() -> None:
    response = TrackingObjectResponse(b"payload", {})

    with pytest.raises(ValueError, match="version identity") as raised:
        _blob_store_with_response(response).open("mutable-key")

    assert not isinstance(raised.value, KeyError)
    assert response.read_sizes == []
    assert response.close_count == 1
    assert response.release_count == 1


def test_minio_open_releases_response_when_source_construction_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = TrackingObjectResponse(b"payload", {"etag": '"etag-a"'})

    def fail_construction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("construction failed")

    monkeypatch.setattr(production, "CaptureSource", fail_construction)

    with pytest.raises(RuntimeError, match="construction failed"):
        _blob_store_with_response(response).open("mutable-key")

    assert response.read_sizes == []
    assert response.close_count == 1
    assert response.release_count == 1


def test_minio_cleanup_failures_are_logged_without_masking_primary_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    class CleanupFailingResponse(TrackingObjectResponse):
        def close(self) -> None:
            super().close()
            raise RuntimeError("close cleanup failed")

        def release_conn(self) -> None:
            super().release_conn()
            raise RuntimeError("release cleanup failed")

    response = CleanupFailingResponse(b"payload", {"etag": '"etag-a"'})

    def fail_construction(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("primary construction failed")

    monkeypatch.setattr(production, "CaptureSource", fail_construction)
    caplog.set_level(logging.DEBUG, logger=production.__name__)

    with pytest.raises(RuntimeError, match="primary construction failed"):
        _blob_store_with_response(response).open("mutable-key")

    assert response.close_count == 1
    assert response.release_count == 1
    assert "close cleanup failed" in caplog.text
    assert "release cleanup failed" in caplog.text


def test_minio_compatibility_get_drains_and_closes_stream() -> None:
    response = TrackingObjectResponse(b"legacy-bytes", {"etag": '"etag-a"'})

    assert _blob_store_with_response(response).get("key") == b"legacy-bytes"
    assert response.close_count == 1
    assert response.release_count == 1


def test_postgres_sensor_open_uses_metadata_object_key_and_returns_copy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = {"id": "segment-a", "object_key": "custom/object.pcap", "nested": {"a": 1}}
    opened_keys: list[str] = []
    source = CaptureSource(io.BytesIO(b"sensor"), "object-version")
    blob_store = SimpleNamespace(open=lambda key: (opened_keys.append(key), source)[1])
    repository = PostgresRepository.__new__(PostgresRepository)
    repository.blob_store = blob_store
    monkeypatch.setattr(repository, "_get", lambda kind, object_id: metadata)

    opened = repository.open_sensor_pcap("segment-a")

    assert opened is not None
    opened_metadata, opened_source = opened
    metadata["nested"]["a"] = 2
    assert opened_keys == ["custom/object.pcap"]
    assert opened_metadata["nested"] == {"a": 1}
    assert opened_source.version_id == "object-version"
    opened_source.close()
