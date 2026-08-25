from __future__ import annotations

import sys
from datetime import UTC, datetime
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
        self.fail_source_version_upsert = False

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
    source_versions = schema.split("CREATE TABLE IF NOT EXISTS pcap_capture_source_versions", 1)[
        1
    ].split(");", 1)[0]
    for column in (
        "source_kind text NOT NULL CHECK(source_kind='PCAP_UPLOAD')",
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


def test_postgres_source_deletion_sql_cascades_all_index_generations() -> None:
    connection = RecordingConnection()
    repository = _repository(connection)

    repository.delete_structural_indexes_for_source("upload-1")

    assert connection.calls == [
        (
            "DELETE FROM pcap_offset_index_generations WHERE source_id=%s",
            ("upload-1",),
        )
    ]
    assert connection.commits == 1


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
