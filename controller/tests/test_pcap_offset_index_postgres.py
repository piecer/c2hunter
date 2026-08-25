from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from c2hunter_analysis.pcap_index import StructuralInterfaceEntry, StructuralPacketEntry

from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    structural_index_digest,
)
from c2hunter_controller.pcap_offset_index_queue import LiveIndexTask
from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.repositories import ArtifactStorageError, CaptureSource


class RecordingCursor:
    def __init__(self, connection: RecordingConnection) -> None:
        self.connection = connection
        self.rowcount = 1

    def __enter__(self) -> RecordingCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: object = None) -> None:
        if "MAX(packet_index)" in query and "FOR UPDATE" in query:
            raise AssertionError("PostgreSQL cannot lock an aggregate query")
        self.connection.calls.append((query, params))
        if self.connection.fail_query_contains and self.connection.fail_query_contains in query:
            raise RuntimeError("forced transactional deletion failure")
        if (
            self.connection.fail_source_version_upsert
            and "INSERT INTO pcap_capture_source_versions" in query
        ):
            raise RuntimeError("forced durable version persistence failure")

    def executemany(self, query: str, params: object) -> None:
        self.connection.calls.append((query, params))
        if "INSERT INTO pcap_offset_index_packets" in query:
            rows = list(params)  # type: ignore[arg-type]
            self.connection.next_packet_index += len(rows)

    def fetchone(self) -> tuple[Any, ...] | None:
        if self.connection.calls:
            query = self.connection.calls[-1][0]
            if "FROM controller_objects" in query and "kind='job'" in query:
                return (self.connection.job_data,) if self.connection.job_data is not None else None
            if "FROM controller_objects" in query and "kind='sensor_pcap'" in query:
                return (
                    (self.connection.sensor_pcap_data,)
                    if self.connection.sensor_pcap_data is not None
                    else None
                )
            if "FROM pcap_capture_source_versions" in query:
                return self.connection.source_version_row
            if "FROM pcap_offset_index_owners" in query:
                return (
                    (self.connection.owner_build_id,)
                    if self.connection.owner_build_id is not None
                    else None
                )
            if "state='READY'" in query and "pcap_offset_index_generations" in query:
                return self.connection.ready_generation_row
            if "state='STAGING' FOR UPDATE" in query:
                return ("build-1",)
            if "COALESCE(MAX(packet_index)+1,0)" in query:
                return (self.connection.next_packet_index,)
        return None

    def fetchall(self) -> list[tuple[Any, ...]]:
        if self.connection.calls:
            query = self.connection.calls[-1][0]
            if "kind='sensor_pcap'" in query and "analysis_job_id" in query:
                return self.connection.sensor_pcaps
            if "FROM pcap_offset_index_interfaces" in query:
                return self.connection.interfaces
            if "FROM pcap_offset_index_packets" in query and "COUNT(" not in query:
                return self.connection.packets
        return []


class RecordingConnection:
    def __init__(self) -> None:
        self.closed = False
        self.autocommit = False
        self.calls: list[tuple[str, object]] = []
        self.commits = 0
        self.rollbacks = 0
        self.next_packet_index = 0
        self.job_data: dict[str, Any] | None = None
        self.source_version_row: tuple[Any, ...] | None = None
        self.owner_build_id: str | None = None
        self.ready_generation_row: tuple[Any, ...] | None = None
        self.interfaces: list[tuple[Any, ...]] = []
        self.packets: list[tuple[Any, ...]] = []
        self.sensor_pcaps: list[tuple[Any, ...]] = []
        self.sensor_pcap_data: dict[str, Any] | None = None
        self.fail_source_version_upsert = False
        self.fail_query_contains: str | None = None

    def cursor(self) -> RecordingCursor:
        return RecordingCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


def _repository(connection: RecordingConnection) -> PostgresRepository:
    repository = PostgresRepository(
        "postgresql://stage9.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    repository._connection = connection
    return repository


def _binding() -> SourceIndexBinding:
    return SourceIndexBinding(
        source_kind="PCAP_UPLOAD",
        source_id="upload-1",
        source_version_id="sha256:" + "a" * 64,
        source_size_bytes=43,
        source_sha256="a" * 64,
        capture_format="PCAP",
    )


def _job(binding: SourceIndexBinding) -> dict[str, Any]:
    return {
        "id": binding.source_id,
        "mode": "PCAP_UPLOAD",
        "source": {
            "packet_bytes_retained": True,
            "size_bytes": binding.source_size_bytes,
            "sha256": binding.source_sha256,
            "capture_format": binding.capture_format,
        },
    }


def _source_version_row(
    binding: SourceIndexBinding, *, version_id: str | None = None
) -> tuple[Any, ...]:
    return (
        binding.source_kind,
        binding.source_id,
        f"captures/{binding.source_id}.pcap",
        version_id or binding.source_version_id,
        binding.source_size_bytes,
        binding.source_sha256,
    )


def test_postgres_migration_uses_normalized_generation_interface_packet_owner_tables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = RecordingConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: connection),
    )
    repository = PostgresRepository(
        "postgresql://stage9.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    monkeypatch.setattr(repository, "_ensure_candidate_query_indexes", lambda _connection: None)

    assert repository.connection is connection
    schema = connection.calls[0][0]
    for table in (
        "pcap_offset_index_generations",
        "pcap_offset_index_interfaces",
        "pcap_offset_index_packets",
        "pcap_offset_index_owners",
    ):
        assert f"CREATE TABLE IF NOT EXISTS {table}" in schema
    assert "source_version_id text NOT NULL" in schema
    assert "CREATE TABLE IF NOT EXISTS pcap_capture_source_versions" in schema
    source_versions = " ".join(
        schema.split("CREATE TABLE IF NOT EXISTS pcap_capture_source_versions", 1)[1]
        .split(");", 1)[0]
        .split()
    )
    for column in (
        "source_kind text NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT'))",
        "source_id text NOT NULL",
        "object_key text NOT NULL",
        "source_version_id text NOT NULL",
        "source_size_bytes bigint NOT NULL CHECK(source_size_bytes>=0)",
        "source_sha256 text NOT NULL",
        "updated_at timestamptz NOT NULL",
        "PRIMARY KEY(source_kind,source_id)",
    ):
        assert column in source_versions
    assert "raw_timestamp_ticks numeric(20,0) NOT NULL" in schema
    assert "REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE" in schema


def test_postgres_save_capture_verifies_without_lock_and_persists_durable_version() -> None:
    content = b"verified-capture"
    digest = __import__("hashlib").sha256(content).hexdigest()
    connection = RecordingConnection()
    connection.job_data = {
        "id": "upload-1",
        "mode": "PCAP_UPLOAD",
        "source": {
            "packet_bytes_retained": True,
            "size_bytes": len(content),
            "sha256": digest,
            "capture_format": "PCAP",
        },
    }
    events: list[tuple[str, str]] = []
    repository = PostgresRepository(
        "postgresql://stage9.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    repository._connection = connection

    def assert_unlocked(event: str, key: str) -> None:
        assert not repository._lock._is_owned()  # type: ignore[attr-defined]
        events.append((event, key))

    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put=lambda key, uploaded: (
                assert_unlocked("put", key),
                pytest.fail("wrong upload bytes") if uploaded != content else None,
            ),
            open=lambda key: (
                assert_unlocked("open", key),
                CaptureSource(__import__("io").BytesIO(content), "s3-version:opaque-v2"),
            )[1],
        ),
    )

    repository.save_job_capture("upload-1", content)

    assert events == [
        ("put", "captures/upload-1.pcap"),
        ("open", "captures/upload-1.pcap"),
    ]
    upsert = next(
        call for call in connection.calls if "INSERT INTO pcap_capture_source_versions" in call[0]
    )
    assert upsert[1][0:6] == (
        "PCAP_UPLOAD",
        "upload-1",
        "captures/upload-1.pcap",
        "s3-version:opaque-v2",
        len(content),
        digest,
    )
    assert connection.commits == 1
    assert connection.rollbacks == 0


def test_postgres_reads_durable_capture_version_for_stage_binding() -> None:
    binding = _binding()
    connection = RecordingConnection()
    connection.source_version_row = _source_version_row(binding)
    repository = _repository(connection)

    assert repository.get_capture_source_version(binding.source_id) == CaptureSourceVersion(
        source_kind=binding.source_kind,
        source_id=binding.source_id,
        object_key="captures/upload-1.pcap",
        source_version_id=binding.source_version_id,
        source_size_bytes=binding.source_size_bytes,
        source_sha256=binding.source_sha256,
    )
    assert connection.commits == 1


def test_postgres_save_capture_persistence_failure_queues_then_deletes_unowned_upload() -> None:
    content = b"unowned-upload"
    digest = __import__("hashlib").sha256(content).hexdigest()
    connection = RecordingConnection()
    connection.job_data = _job(
        SourceIndexBinding("PCAP_UPLOAD", "upload-1", "unused", len(content), digest, "PCAP")
    )
    connection.fail_source_version_upsert = True
    deleted: list[str] = []
    repository = _repository(connection)
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put=lambda _key, _content: None,
            open=lambda _key: CaptureSource(
                __import__("io").BytesIO(content), "s3-version:failed-upload"
            ),
            delete=deleted.append,
        ),
    )

    with pytest.raises(ArtifactStorageError, match="capture version persistence failed"):
        repository.save_job_capture("upload-1", content)

    assert deleted == ["captures/upload-1.pcap"]
    sql = "\n".join(query for query, _params in connection.calls)
    assert "VALUES('pcap_export_cleanup'" in sql
    assert "kind='pcap_export_cleanup'" in sql and "DELETE FROM controller_objects" in sql


def test_postgres_save_capture_persistence_failure_preserves_prior_authoritative_winner() -> None:
    content = b"replacement-upload"
    digest = __import__("hashlib").sha256(content).hexdigest()
    connection = RecordingConnection()
    binding = SourceIndexBinding(
        "PCAP_UPLOAD", "upload-1", "s3-version:prior", len(content), digest, "PCAP"
    )
    connection.job_data = _job(binding)
    connection.source_version_row = _source_version_row(binding)
    connection.fail_source_version_upsert = True
    deleted: list[str] = []
    repository = _repository(connection)
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put=lambda _key, _content: None,
            open=lambda _key: CaptureSource(
                __import__("io").BytesIO(content), "s3-version:replacement"
            ),
            delete=deleted.append,
        ),
    )

    with pytest.raises(ArtifactStorageError, match="capture version persistence failed"):
        repository.save_job_capture("upload-1", content)

    assert deleted == []
    assert not any("VALUES('pcap_export_cleanup'" in query for query, _ in connection.calls)


def test_postgres_staging_sql_is_parameterized_and_normalized() -> None:
    connection = RecordingConnection()
    repository = _repository(connection)
    binding = _binding()
    packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)

    repository.begin_structural_index("build-1", binding, datetime(2026, 8, 25, tzinfo=UTC))
    repository.stage_structural_index_packets("build-1", (packet,))

    sql = "\n".join(query for query, _params in connection.calls)
    assert "INSERT INTO pcap_offset_index_generations" in sql
    assert "INSERT INTO pcap_offset_index_packets" in sql
    packet_insert_columns = next(
        query
        for query, _params in connection.calls
        if "INSERT INTO pcap_offset_index_packets" in query
    ).split("VALUES", 1)[0]
    assert " data " not in packet_insert_columns
    assert ",data," not in packet_insert_columns
    assert connection.commits == 2


def test_postgres_staging_locks_generation_then_appends_two_contiguous_batches() -> None:
    connection = RecordingConnection()
    repository = _repository(connection)
    first = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1)
    second = StructuralPacketEntry(1, 43, 59, 3, 3, 19, 0, 0, 0, 2)

    repository.stage_structural_index_packets("build-1", (first,))
    repository.stage_structural_index_packets("build-1", (second,))

    queries = [query for query, _params in connection.calls]
    for offset in (0, 3):
        assert "state='STAGING' FOR UPDATE" in queries[offset]
        assert "MAX(packet_index)" in queries[offset + 1]
        assert "FOR UPDATE" not in queries[offset + 1]
    assert connection.next_packet_index == 2
    assert connection.commits == 2


def test_postgres_publication_revalidates_durable_version_before_replacing_owner() -> None:
    binding = _binding()
    connection = RecordingConnection()
    connection.job_data = _job(binding)
    connection.source_version_row = _source_version_row(
        binding, version_id="s3-version:replacement"
    )
    connection.owner_build_id = "previous-build"
    repository = _repository(connection)
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(open=lambda _key: pytest.fail("MinIO called while publishing")),
    )

    assert not repository.publish_structural_index("build-1", binding, (), 0)

    sql = "\n".join(query for query, _params in connection.calls)
    assert "FROM controller_objects" in sql and "FOR UPDATE" in sql
    assert "FROM pcap_capture_source_versions" in sql and "FOR UPDATE" in sql
    assert "INSERT INTO pcap_offset_index_owners" not in sql
    assert "DELETE FROM pcap_offset_index_generations WHERE build_id" not in sql
    assert connection.commits == 0
    assert connection.rollbacks == 1


def test_postgres_lookup_rejects_ready_generation_after_durable_capture_overwrite() -> None:
    binding = _binding()
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)
    digest = structural_index_digest(binding, (interface,), (packet,))
    connection = RecordingConnection()
    connection.job_data = _job(binding)
    connection.source_version_row = _source_version_row(
        binding, version_id="s3-version:replacement"
    )
    connection.owner_build_id = "build-1"
    connection.ready_generation_row = (
        binding.source_kind,
        binding.source_id,
        binding.source_version_id,
        binding.source_size_bytes,
        binding.source_sha256,
        binding.capture_format,
        binding.schema_version,
        binding.parser_contract_version,
        datetime(2026, 8, 25, tzinfo=UTC),
        digest,
        1,
        1,
    )
    connection.interfaces = [(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)]
    connection.packets = [(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)]
    repository = _repository(connection)
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(open=lambda _key: pytest.fail("MinIO called while looking up index")),
    )

    lookup = repository.get_structural_index(binding)

    assert lookup.availability is IndexAvailability.STALE
    assert lookup.snapshot is None
    assert any("FROM pcap_capture_source_versions" in query for query, _ in connection.calls)


def test_postgres_source_deletion_sql_cascades_only_matching_kind_generations() -> None:
    connection = RecordingConnection()
    repository = _repository(connection)

    repository.delete_structural_indexes_for_source("upload-1")
    repository.delete_structural_indexes_for_source("segment-1", source_kind="LIVE_SEGMENT")

    assert connection.calls == [
        (
            "DELETE FROM pcap_offset_index_generations WHERE source_kind=%s AND source_id=%s",
            ("PCAP_UPLOAD", "upload-1"),
        ),
        (
            "DELETE FROM pcap_offset_index_generations WHERE source_kind=%s AND source_id=%s",
            ("LIVE_SEGMENT", "segment-1"),
        ),
    ]
    assert connection.commits == 2


@pytest.mark.parametrize("stored_counts", [(999, 1), (1, 999)])
def test_postgres_snapshot_loader_rejects_persisted_count_mismatch(
    stored_counts: tuple[int, int],
) -> None:
    class SnapshotCursor:
        query = ""

        def execute(self, query: str, _params: object) -> None:
            self.query = query

        def fetchone(self) -> tuple[Any, ...] | None:
            if "pcap_offset_index_generations" not in self.query:
                return None
            binding = _binding()
            return (
                binding.source_kind,
                binding.source_id,
                binding.source_version_id,
                binding.source_size_bytes,
                binding.source_sha256,
                binding.capture_format,
                binding.schema_version,
                binding.parser_contract_version,
                datetime(2026, 8, 25, tzinfo=UTC),
                "a" * 64,
                *stored_counts,
            )

        def fetchall(self) -> list[tuple[Any, ...]]:
            if "pcap_offset_index_interfaces" in self.query:
                return [(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)]
            if "pcap_offset_index_packets" in self.query:
                return [(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)]
            return []

    with pytest.raises(ValueError, match="counts"):
        PostgresRepository._load_structural_snapshot(SnapshotCursor(), "build-1")


class ScriptedCursor(RecordingCursor):
    def __init__(self, connection: ScriptedConnection) -> None:
        super().__init__(connection)
        self.result: list[tuple[Any, ...]] = []

    def execute(self, query: str, params: object = None) -> None:
        if params not in (None, ()):
            assert "%s" in query
        if "SKIP LOCKED" in query:
            assert "FOR UPDATE SKIP LOCKED" in query
        self.connection.calls.append((query, params))
        self.result, self.rowcount = self.connection.respond(query, params)

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.result[0] if self.result else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        return list(self.result)


class ScriptedConnection(RecordingConnection):
    def __init__(self, responder: Any) -> None:
        super().__init__()
        self.respond = responder

    def cursor(self) -> ScriptedCursor:
        return ScriptedCursor(self)


def _live_task_row(
    *, status: str = "QUEUED", attempt: int = 0, lease_token: str | None = None
) -> tuple[Any, ...]:
    now = datetime.now(UTC)
    return (
        "LIVE_SEGMENT",
        "segment-1",
        "sensor-1",
        "live-1",
        "sensor-pcaps/sensor-1/segment-1.pcap",
        43,
        "a" * 64,
        "PCAP",
        1,
        1,
        status,
        attempt,
        3,
        lease_token,
        now + timedelta(seconds=30) if lease_token else None,
        now,
        now,
        now,
        None,
    )


def test_postgres_live_queue_claim_uses_skip_locked_and_returns_opaque_lease() -> None:
    def respond(query: str, params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "UPDATE pcap_offset_index_jobs AS task" in query:
            token = cast(tuple[Any, ...], params)[2]
            return [_live_task_row(status="RUNNING", attempt=1, lease_token=str(token))], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _repository(connection)
    task = repository.claim_live_segment_index(
        now=datetime(2026, 8, 25, tzinfo=UTC), lease_seconds=30
    )

    assert isinstance(task, LiveIndexTask)
    assert task.status == "RUNNING" and task.attempt == 1
    assert task.lease_token is not None and len(task.lease_token) >= 32
    claim_sql = connection.calls[0][0]
    assert "ORDER BY next_attempt_at,queued_at,source_id" in claim_sql
    assert "FOR UPDATE SKIP LOCKED LIMIT 1" in claim_sql


def test_postgres_live_queue_cas_paths_are_parameterized_and_bounded() -> None:
    now = datetime(2026, 8, 25, tzinfo=UTC)

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "RETURNING source_id,status" in query:
            return [("segment-1", "QUEUED")], 1
        if "SELECT " in query and "pcap_offset_index_jobs" in query and "FOR UPDATE" in query:
            return [_live_task_row(status="RUNNING", attempt=1, lease_token="winner")], 1
        if query.startswith("UPDATE pcap_offset_index_jobs"):
            return [], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _repository(connection)
    assert repository.heartbeat_live_segment_index(
        "segment-1", attempt=1, lease_token="winner", now=now, lease_seconds=30
    )
    assert repository.fail_live_segment_index(
        "segment-1",
        attempt=1,
        lease_token="winner",
        transient=True,
        error_code="SOURCE_READ",
        now=now,
        retry_base_seconds=5,
    )
    assert repository.recover_live_segment_indexes(now=now) == 1

    sql = "\n".join(query for query, _ in connection.calls)
    assert "attempt=%s AND lease_token=%s" in sql
    assert "lease_expires_at>%s" in sql
    assert "next_attempt_at=%s" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    intent_updates = [
        params for query, params in connection.calls if "SET data=data || %s::jsonb" in query
    ]
    assert any('"index_intent_state":"PENDING"' in str(params) for params in intent_updates)


@pytest.mark.parametrize(
    ("operation", "expected_state"),
    [("complete", "COMPLETED"), ("permanent-failure", "FAILED")],
)
def test_postgres_terminal_task_updates_persist_terminal_intent(
    operation: str, expected_state: str
) -> None:
    now = datetime.now(UTC)

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "SELECT " in query and "pcap_offset_index_jobs" in query and "FOR UPDATE" in query:
            return [_live_task_row(status="RUNNING", attempt=1, lease_token="winner")], 1
        if query.startswith("UPDATE pcap_offset_index_jobs"):
            return [], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _repository(connection)
    if operation == "complete":
        assert repository.complete_live_segment_index("segment-1", attempt=1, lease_token="winner")
    else:
        assert repository.fail_live_segment_index(
            "segment-1",
            attempt=1,
            lease_token="winner",
            transient=False,
            error_code="PERMANENT",
            now=now,
            retry_base_seconds=5,
        )
    marker = next(
        params for query, params in connection.calls if "SET data=data || %s::jsonb" in query
    )
    assert f'"index_intent_state":"{expected_state}"' in str(marker)
    assert '"index_intent_schema_version":1' in str(marker)
    assert '"index_intent_parser_contract_version":1' in str(marker)


def test_postgres_queue_depth_and_terminal_cleanup_are_bounded() -> None:
    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "GROUP BY status" in query:
            return [("QUEUED", 2), ("FAILED", 1)], 2
        if "DELETE FROM pcap_offset_index_jobs AS task" in query:
            return [("segment-1",), ("segment-2",)], 2
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _repository(connection)
    assert repository.get_live_segment_index_queue_depth() == {
        "QUEUED": 2,
        "RUNNING": 0,
        "COMPLETED": 0,
        "FAILED": 1,
    }
    assert (
        repository.cleanup_terminal_live_segment_indexes(
            before=datetime(2026, 8, 25, tzinfo=UTC), limit=2
        )
        == 2
    )
    cleanup_sql, cleanup_params = connection.calls[1]
    assert "status IN ('COMPLETED','FAILED')" in cleanup_sql
    assert "ORDER BY updated_at,source_id" in cleanup_sql
    assert "FOR UPDATE SKIP LOCKED LIMIT %s" in cleanup_sql
    assert cleanup_params == (datetime(2026, 8, 25, tzinfo=UTC), 2)


def test_postgres_reconciliation_filters_ledger_and_terminal_intent_before_limit() -> None:
    later = [(f"eligible-{index}",) for index in range(3)]

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "SELECT source.id" in query:
            normalized = " ".join(query.split())
            assert "NOT EXISTS" in normalized
            assert "pcap_offset_index_jobs" in normalized
            assert "index_intent_state" in normalized
            assert (
                normalized.index("NOT EXISTS")
                < normalized.index("ORDER BY")
                < normalized.index("LIMIT")
            )
            return later, len(later)
        return [], 0

    repository = _repository(ScriptedConnection(respond))
    admitted: list[str] = []
    repository.admit_live_segment_index = lambda source_id, **_kwargs: (  # type: ignore[method-assign]
        admitted.append(source_id)
        or __import__(
            "c2hunter_controller.pcap_offset_index_queue", fromlist=["IndexAdmission"]
        ).IndexAdmission.QUEUED
    )
    assert repository.reconcile_live_segment_indexes(capacity=10, max_attempts=3, limit=3) == 3
    assert admitted == ["eligible-0", "eligible-1", "eligible-2"]


def test_postgres_sensor_upload_uses_immutable_key_without_repository_lock() -> None:
    content = b"pcap"
    connection = RecordingConnection()
    connection.job_data = {
        "id": "live-1",
        "mode": "LIVE",
        "status": "CAPTURING",
        "capture": {"store_pcap": True},
    }
    repository = _repository(connection)
    events: list[tuple[str, str]] = []

    def put(key: str, uploaded: bytes) -> None:
        assert uploaded == content
        assert not repository._lock._is_owned()  # type: ignore[attr-defined]
        assert not any("pg_advisory_xact_lock" in query for query, _params in connection.calls)
        assert key.startswith("sensor-pcaps/sensor-1/segment-1/") and key.endswith(".pcap")
        assert key != "sensor-pcaps/sensor-1/segment-1.pcap"
        events.append(("put", key))

    repository.blob_store = cast(
        MinioBlobStore, SimpleNamespace(put=put, delete=lambda key: events.append(("delete", key)))
    )
    stored, status = repository.save_sensor_pcap_limited(
        {
            "id": "segment-1",
            "sensor_id": "sensor-1",
            "analysis_job_id": "live-1",
            "filename": "segment-1.pcap",
            "size_bytes": len(content),
            "sha256": "a" * 64,
        },
        content,
        None,
        require_open_job=True,
    )
    assert status == "OK" and stored is not None
    assert stored["object_key"] == events[0][1]
    assert stored["index_intent_state"] == "PENDING"
    assert events == [("put", stored["object_key"])]


class _SensorRaceCursor(RecordingCursor):
    def execute(self, query: str, params: object = None) -> None:
        super().execute(query, params)
        if "VALUES('sensor_pcap',%s,%s::jsonb)" in query:
            values = cast(tuple[Any, ...], params)
            with self.connection.state_lock:  # type: ignore[attr-defined]
                if self.connection.sensor_pcap_data is not None:
                    raise RuntimeError("duplicate sensor PCAP")
                self.connection.sensor_pcap_data = json.loads(str(values[1]))


class _SensorRaceConnection(RecordingConnection):
    def __init__(self) -> None:
        super().__init__()
        self.state_lock = threading.Lock()

    def cursor(self) -> RecordingCursor:
        return _SensorRaceCursor(self)


def test_postgres_concurrent_duplicate_upload_compensates_only_race_loser() -> None:
    connection = _SensorRaceConnection()
    repository = _repository(connection)
    barrier = threading.Barrier(2)
    objects: dict[str, bytes] = {}
    deleted: list[str] = []

    def put(key: str, content: bytes) -> None:
        assert not repository._lock._is_owned()  # type: ignore[attr-defined]
        objects[key] = content
        barrier.wait(timeout=2)

    def delete(key: str) -> None:
        assert not repository._lock._is_owned()  # type: ignore[attr-defined]
        deleted.append(key)
        objects.pop(key, None)

    repository.blob_store = cast(MinioBlobStore, SimpleNamespace(put=put, delete=delete))
    segment = {
        "id": "segment-1",
        "sensor_id": "sensor-1",
        "analysis_job_id": None,
        "filename": "segment-1.pcap",
        "size_bytes": 4,
        "sha256": "a" * 64,
    }
    outcomes: list[tuple[dict[str, Any] | None, str]] = []
    threads = [
        threading.Thread(
            target=lambda: outcomes.append(
                repository.save_sensor_pcap_limited(segment, b"pcap", None)
            ),
            daemon=True,
        )
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive()

    assert sorted(status for _stored, status in outcomes) == ["EXISTS", "OK"]
    winner = next(stored for stored, status in outcomes if status == "OK")
    replay = next(stored for stored, status in outcomes if status == "EXISTS")
    assert winner is not None and replay == winner
    assert deleted and deleted == [key for key in deleted if key != winner["object_key"]]
    assert objects == {winner["object_key"]: b"pcap"}


def test_postgres_sensor_upload_db_failure_compensates_exact_immutable_key() -> None:
    connection = RecordingConnection()
    connection.fail_query_contains = "VALUES('sensor_pcap',%s,%s::jsonb)"
    repository = _repository(connection)
    uploaded: list[str] = []
    deleted: list[str] = []
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put=lambda key, _content: uploaded.append(key),
            delete=deleted.append,
        ),
    )

    with pytest.raises(RuntimeError, match="transactional deletion failure"):
        repository.save_sensor_pcap_limited(
            {
                "id": "segment-1",
                "sensor_id": "sensor-1",
                "analysis_job_id": None,
                "filename": "segment-1.pcap",
                "size_bytes": 4,
                "sha256": "a" * 64,
            },
            b"pcap",
            None,
        )
    assert len(uploaded) == 1 and deleted == uploaded


def test_postgres_old_object_cleanup_cannot_delete_later_same_named_segment() -> None:
    connection = _SensorRaceConnection()
    repository = _repository(connection)
    objects: dict[str, bytes] = {}
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put=lambda key, content: objects.__setitem__(key, content),
            delete=lambda key: objects.pop(key, None),
        ),
    )
    segment = {
        "id": "segment-1",
        "sensor_id": "sensor-1",
        "analysis_job_id": None,
        "filename": "segment-1.pcap",
        "size_bytes": 4,
        "sha256": "a" * 64,
    }
    first, first_status = repository.save_sensor_pcap_limited(segment, b"old!", None)
    assert first_status == "OK" and first is not None
    old_key = str(first["object_key"])
    connection.sensor_pcap_data = None
    second, second_status = repository.save_sensor_pcap_limited(segment, b"new!", None)
    assert second_status == "OK" and second is not None
    new_key = str(second["object_key"])
    assert old_key != new_key

    repository.blob_store.delete(old_key)
    assert objects == {new_key: b"new!"}


def test_postgres_slow_sensor_blob_put_does_not_block_repository_lock() -> None:
    connection = RecordingConnection()
    repository = _repository(connection)
    entered = threading.Event()
    release = threading.Event()
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            put=lambda _key, _content: (entered.set(), release.wait(2)), delete=lambda _key: None
        ),
    )
    outcome: list[object] = []
    thread = threading.Thread(
        target=lambda: outcome.append(
            repository.save_sensor_pcap_limited(
                {
                    "id": "segment-1",
                    "sensor_id": "sensor-1",
                    "analysis_job_id": None,
                    "filename": "segment-1.pcap",
                    "size_bytes": 4,
                    "sha256": "a" * 64,
                },
                b"pcap",
                None,
            )
        ),
        daemon=True,
    )
    thread.start()
    assert entered.wait(1)
    assert repository._lock.acquire(blocking=False)
    repository._lock.release()
    release.set()
    thread.join(1)
    assert not thread.is_alive() and outcome


def test_postgres_forward_migration_replaces_arbitrarily_named_upload_only_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = RecordingConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: connection),
    )
    repository = PostgresRepository(
        "postgresql://stage10.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    monkeypatch.setattr(repository, "_ensure_candidate_query_indexes", lambda _connection: None)

    assert repository.connection is connection
    schema = connection.calls[0][0]
    assert "pg_get_constraintdef" in schema
    assert "format('ALTER TABLE %I DROP CONSTRAINT %I'" in schema
    assert "LIVE_SEGMENT" in schema


def test_postgres_live_publication_locks_and_completes_exact_attempt_atomically() -> None:
    now = datetime.now(UTC)
    binding = SourceIndexBinding("LIVE_SEGMENT", "segment-1", "etag:v1", 43, "a" * 64, "PCAP")
    source_version = CaptureSourceVersion(
        "LIVE_SEGMENT",
        "segment-1",
        "sensor-pcaps/sensor-1/segment-1.pcap",
        "etag:v1",
        43,
        "a" * 64,
    )
    segment = {
        "id": "segment-1",
        "sensor_id": "sensor-1",
        "analysis_job_id": "live-1",
        "filename": "segment-1.pcap",
        "object_key": source_version.object_key,
        "size_bytes": 43,
        "sha256": "a" * 64,
        "index_requested_at": now.isoformat(),
    }
    job = {"id": "live-1", "mode": "LIVE", "status": "CAPTURING", "capture": {"store_pcap": True}}
    sensor = {"sensor_id": "sensor-1"}
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1)

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "kind='sensor'" in query:
            return [(sensor,)], 1
        if "kind='job'" in query:
            return [(job,)], 1
        if "kind='sensor_pcap'" in query:
            return [(segment,)], 1
        if "FROM pcap_offset_index_jobs" in query:
            return [_live_task_row(status="RUNNING", attempt=1, lease_token="winner")], 1
        if "FROM pcap_capture_source_versions" in query:
            return [
                (
                    source_version.source_kind,
                    source_version.source_id,
                    source_version.object_key,
                    source_version.source_version_id,
                    source_version.source_size_bytes,
                    source_version.source_sha256,
                )
            ], 1
        if "FROM pcap_offset_index_generations" in query:
            return [(*binding.__dict__.values(), now)], 1
        if "COUNT(*) FROM pcap_offset_index_packets" in query:
            return [(1,)], 1
        if "FROM pcap_offset_index_packets" in query:
            return [tuple(packet.__dict__.values())], 1
        if "FROM pcap_offset_index_owners" in query:
            return [("previous",)], 1
        if query.startswith("UPDATE pcap_offset_index_jobs"):
            return [], 1
        return [], 1

    connection = ScriptedConnection(respond)
    repository = _repository(connection)
    repository.blob_store = cast(
        MinioBlobStore, SimpleNamespace(open=lambda _key: pytest.fail("MinIO called"))
    )

    assert repository.publish_live_structural_index(
        "build-1", binding, (interface,), 1, source_version, attempt=1, lease_token="winner"
    )
    sql = "\n".join(query for query, _ in connection.calls)
    assert "WHERE kind='sensor'" in connection.calls[0][0]
    assert "WHERE kind='job'" in connection.calls[1][0]
    assert "WHERE kind='sensor_pcap'" in connection.calls[2][0]
    assert "FOR UPDATE" in sql
    assert "status='COMPLETED'" in sql
    assert "attempt=%s AND lease_token=%s AND lease_expires_at>%s" in sql
    assert "SET data=data || %s::jsonb" in sql
    assert any(
        '"index_intent_state":"COMPLETED"' in str(params)
        for query, params in connection.calls
        if "SET data=data || %s::jsonb" in query
    )
    assert connection.commits == 1 and connection.rollbacks == 0


def test_postgres_live_job_deletion_queues_only_exact_sensor_objects() -> None:
    connection = RecordingConnection()
    connection.job_data = {
        "id": "live-1",
        "mode": "LIVE",
        "status": "COMPLETED",
        "capture": {"store_pcap": True},
    }
    connection.sensor_pcaps = [("segment-1", "sensor-pcaps/sensor-1/exact-object.pcap")]
    deleted: list[str] = []
    repository = _repository(connection)
    repository.blob_store = cast(MinioBlobStore, SimpleNamespace(delete=deleted.append))

    assert repository.delete_job("live-1")
    assert deleted == ["sensor-pcaps/sensor-1/exact-object.pcap"]
    cleanup_params = [
        params for query, params in connection.calls if "VALUES('pcap_export_cleanup'" in query
    ]
    assert any("exact-object.pcap" in str(params) for params in cleanup_params)
    assert not any("captures/live-1.pcap" in str(params) for params in cleanup_params)
    sql = "\n".join(query for query, _ in connection.calls)
    assert "DELETE FROM pcap_offset_index_jobs" in sql
    assert "source_kind='LIVE_SEGMENT'" in sql


def test_postgres_live_job_deletion_coalesces_duplicate_exact_object_cleanup() -> None:
    connection = RecordingConnection()
    connection.job_data = {
        "id": "live-1",
        "mode": "LIVE",
        "status": "COMPLETED",
        "capture": {"store_pcap": True},
    }
    connection.sensor_pcaps = [
        ("segment-1", "sensor-pcaps/sensor-1/shared.pcap"),
        ("segment-2", "sensor-pcaps/sensor-1/shared.pcap"),
        ("segment-3", None),
    ]
    deleted: list[str] = []
    repository = _repository(connection)
    repository.blob_store = cast(MinioBlobStore, SimpleNamespace(delete=deleted.append))

    assert repository.delete_job("live-1")
    assert deleted == ["sensor-pcaps/sensor-1/shared.pcap"]
    assert sum("VALUES('pcap_export_cleanup'" in call[0] for call in connection.calls) == 1
    assert any(
        call[1] == (["segment-1", "segment-2", "segment-3"],)
        for call in connection.calls
        if "DELETE FROM pcap_offset_index_jobs" in call[0]
    )


@pytest.mark.parametrize(
    "failure_query", ["VALUES('pcap_export_cleanup'", "DELETE FROM pcap_offset_index_jobs"]
)
def test_postgres_live_job_deletion_failure_rolls_back_without_blob_delete(
    failure_query: str,
) -> None:
    connection = RecordingConnection()
    connection.job_data = {
        "id": "live-1",
        "mode": "LIVE",
        "status": "COMPLETED",
        "capture": {"store_pcap": True},
    }
    connection.sensor_pcaps = [("segment-1", "sensor-pcaps/sensor-1/exact.pcap")]
    connection.fail_query_contains = failure_query
    deleted: list[str] = []
    repository = _repository(connection)
    repository.blob_store = cast(MinioBlobStore, SimpleNamespace(delete=deleted.append))

    with pytest.raises(RuntimeError, match="transactional deletion failure"):
        repository.delete_job("live-1")
    assert connection.rollbacks == 1
    assert connection.commits == 0
    assert deleted == []


def _live_lookup_connection() -> tuple[RecordingConnection, SourceIndexBinding]:
    connection = RecordingConnection()
    binding = SourceIndexBinding("LIVE_SEGMENT", "segment-1", "etag:v1", 43, "a" * 64, "PCAP")
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)
    connection.owner_build_id = "live-ready"
    connection.ready_generation_row = (
        *binding.__dict__.values(),
        datetime(2026, 8, 25, tzinfo=UTC),
        structural_index_digest(binding, (interface,), (packet,)),
        1,
        1,
    )
    connection.interfaces = [tuple(interface.__dict__.values())]
    connection.packets = [tuple(packet.__dict__.values())]
    connection.job_data = {
        "id": "live-1",
        "mode": "LIVE",
        "status": "CAPTURING",
        "capture": {"store_pcap": True},
    }
    connection.sensor_pcap_data = {
        "id": "segment-1",
        "sensor_id": "sensor-1",
        "analysis_job_id": "live-1",
        "filename": "segment-1.pcap",
        "object_key": "sensor-pcaps/sensor-1/segment-1.pcap",
        "size_bytes": 43,
        "sha256": "a" * 64,
        "index_requested_at": "2026-08-25T00:00:00+00:00",
    }
    connection.source_version_row = (
        "LIVE_SEGMENT",
        "segment-1",
        "sensor-pcaps/sensor-1/segment-1.pcap",
        "etag:v1",
        43,
        "a" * 64,
    )
    return connection, binding


def test_postgres_live_lookup_exact_ready_succeeds_without_kind_collision() -> None:
    connection, binding = _live_lookup_connection()
    lookup = _repository(connection).get_structural_index(binding)

    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None and lookup.snapshot.binding == binding
    owner_query = next(
        call for call in connection.calls if "FROM pcap_offset_index_owners" in call[0]
    )
    assert owner_query[1] == ("LIVE_SEGMENT", "segment-1")


@pytest.mark.parametrize(
    "corruption",
    [
        "source-missing",
        "source-kind",
        "source-version",
        "source-size",
        "source-sha",
        "owner-missing",
        "generation-source",
        "generation-version",
        "generation-count",
        "generation-digest",
        "interface",
        "packet",
        "canonical-size",
        "canonical-sha",
        "canonical-marker",
    ],
)
def test_postgres_live_lookup_corruption_is_wholly_unavailable(corruption: str) -> None:
    connection, binding = _live_lookup_connection()
    if corruption == "source-missing":
        connection.source_version_row = None
    elif corruption == "source-kind":
        connection.source_version_row = ("PCAP_UPLOAD", *connection.source_version_row[1:])
    elif corruption == "source-version":
        row = list(connection.source_version_row)
        row[3] = "etag:stale"
        connection.source_version_row = tuple(row)
    elif corruption == "source-size":
        row = list(connection.source_version_row)
        row[4] = 44
        connection.source_version_row = tuple(row)
    elif corruption == "source-sha":
        row = list(connection.source_version_row)
        row[5] = "b" * 64
        connection.source_version_row = tuple(row)
    elif corruption == "owner-missing":
        connection.owner_build_id = None
    elif corruption.startswith("generation-"):
        row = list(connection.ready_generation_row)
        index = {
            "generation-source": 1,
            "generation-version": 2,
            "generation-count": 10,
            "generation-digest": 9,
        }[corruption]
        row[index] = 999 if corruption == "generation-count" else "corrupt"
        connection.ready_generation_row = tuple(row)
    elif corruption == "interface":
        row = list(connection.interfaces[0])
        row[4] = 1
        connection.interfaces = [tuple(row)]
    elif corruption == "packet":
        row = list(connection.packets[0])
        row[0] = 9
        connection.packets = [tuple(row)]
    elif corruption == "canonical-size":
        connection.sensor_pcap_data["size_bytes"] = 44
    elif corruption == "canonical-sha":
        connection.sensor_pcap_data["sha256"] = "b" * 64
    else:
        connection.sensor_pcap_data.pop("index_requested_at")

    lookup = _repository(connection).get_structural_index(binding)
    assert lookup.availability is not IndexAvailability.READY
    assert lookup.snapshot is None
