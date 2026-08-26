from __future__ import annotations

import hashlib
import struct
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest
from c2hunter_analysis.pcap_index import StructuralInterfaceEntry, StructuralPacketEntry

from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexSnapshot,
    structural_index_digest,
    structural_index_identity,
    validate_structural_index,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

_CAPTURE = (
    struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    + struct.pack("<IIII", 1, 2, 3, 3)
    + b"abc"
)
_CAPTURE_SHA = hashlib.sha256(_CAPTURE).hexdigest()


def _binding(job_id: str = "upload-1") -> SourceIndexBinding:
    return SourceIndexBinding(
        source_kind="PCAP_UPLOAD",
        source_id=job_id,
        source_version_id="sha256:" + _CAPTURE_SHA,
        source_size_bytes=len(_CAPTURE),
        source_sha256=_CAPTURE_SHA,
        capture_format="PCAP",
    )


def _rows():
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)
    return interface, packet


def _pcapng_boundary_rows(raw_ticks: int):
    content = b"x" * 36
    digest = hashlib.sha256(content).hexdigest()
    binding = SourceIndexBinding(
        source_kind="PCAP_UPLOAD",
        source_id=f"pcapng-{raw_ticks}",
        source_version_id=f"sha256:{digest}",
        source_size_bytes=len(content),
        source_sha256=digest,
        capture_format="PCAPNG",
    )
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000_000, -7)
    packet = StructuralPacketEntry(0, 0, 28, 3, 3, 36, 0, 0, 0, raw_ticks)
    return content, binding, interface, packet


@pytest.mark.parametrize("raw_ticks", [(1 << 63) - 1, 1 << 63, (1 << 64) - 1])
def test_validator_accepts_full_uint64_pcapng_raw_timestamp_ticks(raw_ticks: int) -> None:
    _, binding, interface, packet = _pcapng_boundary_rows(raw_ticks)
    snapshot = StructuralIndexSnapshot(
        "boundary",
        binding,
        datetime.now(UTC),
        structural_index_digest(binding, (interface,), (packet,)),
        (interface,),
        (packet,),
    )

    assert validate_structural_index(snapshot)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("section_index", -1),
        ("section_index", True),
        ("interface_id", -1),
        ("interface_id", True),
        ("interface_ordinal", True),
        ("link_type", -1),
        ("link_type", 1 << 16),
        ("link_type", True),
        ("snaplen", 0),
        ("snaplen", 16 * 1024 * 1024 + 1),
        ("snaplen", True),
        ("timestamp_resolution_numerator", 0),
        ("timestamp_resolution_numerator", True),
        ("timestamp_resolution_denominator", 0),
        ("timestamp_resolution_denominator", True),
        ("timestamp_offset_seconds", True),
        ("timestamp_offset_seconds", -(1 << 63) - 1),
        ("timestamp_offset_seconds", 1 << 63),
    ],
)
def test_validator_rejects_digest_consistent_malformed_interface_metadata(
    field: str, value: int
) -> None:
    binding = _binding()
    interface, packet = _rows()
    malformed = replace(interface, **{field: value})
    snapshot = StructuralIndexSnapshot(
        "malformed",
        binding,
        datetime.now(UTC),
        structural_index_digest(binding, (malformed,), (packet,)),
        (malformed,),
        (packet,),
    )

    assert not validate_structural_index(snapshot)


def test_validator_rejects_digest_consistent_packet_with_unavailable_interface() -> None:
    binding = _binding()
    interface, packet = _rows()
    unavailable = replace(packet, interface_id=1)
    snapshot = StructuralIndexSnapshot(
        "unavailable",
        binding,
        datetime.now(UTC),
        structural_index_digest(binding, (interface,), (unavailable,)),
        (interface,),
        (unavailable,),
    )

    assert not validate_structural_index(snapshot)


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
@pytest.mark.parametrize("raw_ticks", [(1 << 63) - 1, 1 << 63, (1 << 64) - 1])
def test_full_uint64_pcapng_ticks_round_trip_exactly(
    tmp_path, repository_kind: str, raw_ticks: int
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / f"uint64-{raw_ticks}.sqlite")
    )
    content, binding, interface, packet = _pcapng_boundary_rows(raw_ticks)
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, content)
    repository.begin_structural_index("boundary", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("boundary", (packet,))

    assert repository.publish_structural_index("boundary", binding, (interface,), 1)
    lookup = repository.get_structural_index(binding)
    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None
    assert lookup.snapshot.packets[0].raw_timestamp_ticks == raw_ticks


def _job(binding: SourceIndexBinding) -> dict[str, object]:
    return {
        "id": binding.source_id,
        "idempotency_key": "key",
        "mode": "PCAP_UPLOAD",
        "source": {
            "packet_bytes_retained": True,
            "size_bytes": binding.source_size_bytes,
            "sha256": binding.source_sha256,
            "capture_format": binding.capture_format,
        },
    }


def test_memory_staging_is_invisible_then_publication_is_atomic() -> None:
    repository = MemoryRepository()
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()

    repository.begin_structural_index("build-1", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("build-1", (packet,))
    assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING

    assert repository.publish_structural_index("build-1", binding, (interface,), 1)
    lookup = repository.get_structural_index(binding)
    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None
    assert lookup.snapshot.packets == (packet,)


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_structural_identity_lookup_is_compact_exact_and_never_reads_children(
    tmp_path, repository_kind: str
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "structural-identity.sqlite")
    )
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)
    full = repository.get_structural_index(binding)
    assert full.snapshot is not None
    sql: list[str] = []
    if repository_kind == "sqlite":
        repository.connection.set_trace_callback(sql.append)
    else:
        repository.get_structural_index = lambda _binding: pytest.fail(  # type: ignore[method-assign]
            "compact identity lookup rematerialized the full structural snapshot"
        )

    source = repository.get_capture_source_version(binding.source_id)
    assert source is not None
    compact = repository.get_structural_index_identity(source)

    assert compact.availability is IndexAvailability.READY
    assert compact.identity == structural_index_identity(full.snapshot)
    if repository_kind == "sqlite":
        assert not any("pcap_offset_index_packets" in query for query in sql)
        assert not any("pcap_offset_index_interfaces" in query for query in sql)
        assert len(sql) <= 4
        repository.connection.set_trace_callback(None)
    repository.close()


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_structural_identity_lookup_preserves_missing_stale_and_corrupt_semantics(
    tmp_path, repository_kind: str
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "structural-identity-semantics.sqlite")
    )
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    source = repository.get_capture_source_version(binding.source_id)
    assert source is not None
    assert (
        repository.get_structural_index_identity(source).availability is IndexAvailability.MISSING
    )
    interface, packet = _rows()
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)

    stale_source = replace(source, source_version_id="s3-version:replacement")
    assert (
        repository.get_structural_index_identity(stale_source).availability
        is IndexAvailability.STALE
    )

    if isinstance(repository, MemoryRepository):
        snapshot = repository.structural_index_generations["ready"]
        repository.structural_index_generations["ready"] = replace(
            snapshot, index_sha256="not-a-digest"
        )
    else:
        repository.connection.execute(
            "UPDATE pcap_offset_index_generations SET index_sha256=? WHERE build_id=?",
            ("not-a-digest", "ready"),
        )
        repository.connection.commit()
    assert (
        repository.get_structural_index_identity(source).availability is IndexAvailability.CORRUPT
    )
    repository.close()


def test_memory_structural_identity_fence_never_touches_huge_child_collections() -> None:
    class ExplodingChildren:
        def __iter__(self) -> Any:
            pytest.fail("compact identity fence iterated structural children")

        def __len__(self) -> int:
            pytest.fail("compact identity fence counted structural children")

        def __deepcopy__(self, _memo: object) -> Any:
            pytest.fail("compact identity fence copied structural children")

    repository = MemoryRepository()
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)
    snapshot = repository.structural_index_generations["ready"]
    repository.structural_index_generations["ready"] = replace(
        snapshot,
        interfaces=cast(Any, ExplodingChildren()),
        packets=cast(Any, ExplodingChildren()),
    )
    source = repository.get_capture_source_version(binding.source_id)
    assert source is not None

    lookup = repository.get_structural_index_identity(source)

    assert lookup.availability is IndexAvailability.READY
    assert lookup.identity == structural_index_identity(snapshot)


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_source_binding_mismatch_rejects_whole_generation(tmp_path, repository_kind: str) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "index.sqlite")
    )
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("build-1", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("build-1", (packet,))
    assert repository.publish_structural_index("build-1", binding, (interface,), 1)

    changed = SourceIndexBinding(**{**binding.__dict__, "source_sha256": "b" * 64})
    assert repository.get_structural_index(changed).availability is IndexAvailability.STALE


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_retention_deletion_seam_removes_every_generation(tmp_path, repository_kind: str) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "retention.sqlite")
    )
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)
    repository.begin_structural_index("staging", binding, datetime.now(UTC))

    assert repository.delete_retained_source(binding.source_id)
    assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING
    assert repository.get_capture_source_version(binding.source_id) is None


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_capture_source_version_is_saved_with_capture_and_matches_after_reopen(
    tmp_path, repository_kind: str
) -> None:
    path = tmp_path / "capture-version.sqlite"
    repository = MemoryRepository() if repository_kind == "memory" else SQLiteRepository(path)
    binding = _binding()
    repository.create_job(_job(binding))

    repository.save_job_capture(binding.source_id, _CAPTURE)

    expected = CaptureSourceVersion(
        source_kind="PCAP_UPLOAD",
        source_id=binding.source_id,
        object_key=f"captures/{binding.source_id}.pcap",
        source_version_id=binding.source_version_id,
        source_size_bytes=binding.source_size_bytes,
        source_sha256=binding.source_sha256,
    )
    assert repository.get_capture_source_version(binding.source_id) == expected
    if repository_kind == "sqlite":
        repository.close()
        reopened = SQLiteRepository(path)
        assert reopened.get_capture_source_version(binding.source_id) == expected
        reopened.close()


def test_sqlite_ready_generation_survives_reopen(tmp_path) -> None:
    path = tmp_path / "reopen.sqlite"
    binding = _binding()
    interface, packet = _rows()
    repository = SQLiteRepository(path)
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)
    repository.close()

    reopened = SQLiteRepository(path)
    lookup = reopened.get_structural_index(binding)
    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None and lookup.snapshot.packets == (packet,)
    reopened.close()


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_corrupt_packet_row_rejects_whole_generation(tmp_path, repository_kind: str) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "corrupt.sqlite")
    )
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)
    if repository_kind == "memory":
        snapshot = repository.structural_index_generations["ready"]
        repository.structural_index_generations["ready"] = type(snapshot)(
            snapshot.build_id,
            snapshot.binding,
            snapshot.created_at,
            "0" * 64,
            snapshot.interfaces,
            snapshot.packets,
        )
    else:
        repository.connection.execute(
            "UPDATE pcap_offset_index_packets SET data=? WHERE build_id='ready'",
            ('{"packet_index":99}',),
        )
        repository.connection.commit()
    assert repository.get_structural_index(binding).availability is IndexAvailability.CORRUPT


@pytest.mark.parametrize("count_column", ["packet_count", "interface_count"])
def test_sqlite_persisted_generation_count_mismatch_is_corrupt(tmp_path, count_column: str) -> None:
    repository = SQLiteRepository(tmp_path / f"corrupt-{count_column}.sqlite")
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("ready", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("ready", (packet,))
    assert repository.publish_structural_index("ready", binding, (interface,), 1)
    repository.connection.execute(
        f"UPDATE pcap_offset_index_generations SET {count_column}=999 WHERE build_id='ready'"
    )
    repository.connection.commit()

    assert repository.get_structural_index(binding).availability is IndexAvailability.CORRUPT


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_failed_replacement_preserves_previous_ready_owner(tmp_path, repository_kind: str) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "replace.sqlite")
    )
    binding = _binding()
    repository.create_job(_job(binding))
    repository.save_job_capture(binding.source_id, _CAPTURE)
    interface, packet = _rows()
    repository.begin_structural_index("first", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("first", (packet,))
    assert repository.publish_structural_index("first", binding, (interface,), 1)
    repository.begin_structural_index("failed", binding, datetime.now(UTC))
    assert not repository.publish_structural_index("failed", binding, (interface,), 1)
    lookup = repository.get_structural_index(binding)
    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None and lookup.snapshot.build_id == "first"
