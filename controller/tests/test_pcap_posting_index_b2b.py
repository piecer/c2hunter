from __future__ import annotations

import hashlib
import io
import struct
from datetime import UTC, datetime

import pytest
from c2hunter_analysis.pcap_index import scan_structural_packet_index
from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
)

from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_offset_index import SourceIndexBinding, build_offline_upload_index
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _capture() -> bytes:
    packet = bytes.fromhex("0200000000020200000000010800") + b"\x45" + b"\x00" * 39
    return (
        struct.pack("<IHHIIII", 2712847316, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, len(packet), len(packet))
        + packet
    )


def _stage_upload(repository, source_id: str = "b2b-upload"):
    capture = _capture()
    digest = hashlib.sha256(capture).hexdigest()
    repository.create_job(
        {
            "id": source_id,
            "idempotency_key": source_id,
            "mode": "PCAP_UPLOAD",
            "source": {
                "packet_bytes_retained": True,
                "size_bytes": len(capture),
                "sha256": digest,
                "capture_format": "PCAP",
            },
        }
    )
    repository.save_job_capture(source_id, capture)
    scan = scan_structural_packet_index(io.BytesIO(capture), max_packets=10, max_interfaces=2)
    binding = SourceIndexBinding(
        "PCAP_UPLOAD", source_id, f"sha256:{digest}", len(capture), digest, "PCAP"
    )
    repository.begin_structural_index("b2b-parent", binding, datetime.now(UTC))
    repository.stage_structural_index_packets("b2b-parent", scan.packets)
    return binding, scan


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_structural_publication_atomically_requests_exact_posting_intent(tmp_path, backend: str):
    repository = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "b2b.sqlite")
    )
    binding, scan = _stage_upload(repository)

    assert repository.publish_structural_index(
        "b2b-parent",
        binding,
        scan.interfaces,
        scan.packet_count,
        request_postings=True,
        posting_schema_version=PCAP_POSTING_INDEX_SCHEMA_VERSION,
        posting_parser_contract_version=PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        filter_contract_version=PCAP_FILTER_CONTRACT_VERSION,
    )

    intent = repository.get_posting_index_intent("PCAP_UPLOAD", "b2b-upload")
    assert intent is not None
    assert intent.status.value == "PENDING"
    assert intent.spec.parent_structural_build_id == "b2b-parent"
    assert intent.spec.source_version_id == binding.source_version_id
    assert (
        intent.spec.posting_schema_version,
        intent.spec.posting_parser_contract_version,
        intent.spec.filter_contract_version,
    ) == (
        PCAP_POSTING_INDEX_SCHEMA_VERSION,
        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        PCAP_FILTER_CONTRACT_VERSION,
    )
    assert repository.get_posting_index_task("PCAP_UPLOAD", "b2b-upload") is None


def test_posting_settings_defaults_and_cross_field_boundaries():
    from c2hunter_analysis.pcap_postings import PostingBuildLimits

    settings = Settings(environment="test")
    assert settings.pcap_posting_index_enabled is False
    assert settings.pcap_posting_index_metrics_enabled is True
    assert (
        settings.pcap_posting_index_worker_concurrency <= settings.pcap_posting_index_queue_capacity
    )
    assert (
        settings.pcap_posting_index_heartbeat_interval_seconds * 2
        <= settings.pcap_posting_index_lease_seconds
    )
    assert (
        settings.pcap_posting_index_operation_timeout_seconds
        > settings.pcap_posting_index_lease_seconds
    )
    defaults = PostingBuildLimits()
    capped_fields = {
        "pcap_posting_index_build_max_packets": defaults.max_packets,
        "pcap_posting_index_build_max_memberships": defaults.max_memberships,
        "pcap_posting_index_build_max_distinct_keys": defaults.max_distinct_keys,
        "pcap_posting_index_build_max_encoded_bytes": defaults.max_encoded_bytes,
        "pcap_posting_index_build_max_chunks": defaults.max_chunks,
    }
    for field, maximum in capped_fields.items():
        assert getattr(Settings(environment="test", **{field: maximum}), field) == maximum
        with pytest.raises(ValueError):
            Settings(environment="test", **{field: maximum + 1})
    with pytest.raises(ValueError, match="heartbeat"):
        Settings(
            environment="test",
            pcap_posting_index_lease_seconds=10,
            pcap_posting_index_heartbeat_interval_seconds=6,
        )
    with pytest.raises(ValueError, match="timeout"):
        Settings(
            environment="test",
            pcap_posting_index_lease_seconds=10,
            pcap_posting_index_operation_timeout_seconds=10,
        )
    with pytest.raises(ValueError, match="concurrency"):
        Settings(
            environment="test",
            pcap_posting_index_queue_capacity=1,
            pcap_posting_index_worker_concurrency=2,
        )


def test_offline_postcommit_admission_failure_does_not_reject_source(monkeypatch):
    repository = MemoryRepository()
    capture = _capture()
    digest = hashlib.sha256(capture).hexdigest()
    repository.create_job(
        {
            "id": "accepted",
            "idempotency_key": "accepted",
            "mode": "PCAP_UPLOAD",
            "source": {
                "packet_bytes_retained": True,
                "size_bytes": len(capture),
                "sha256": digest,
                "capture_format": "PCAP",
            },
        }
    )
    repository.save_job_capture("accepted", capture)

    def unavailable(*_args, **_kwargs):
        raise OSError("queue unavailable")

    monkeypatch.setattr(repository, "admit_posting_index", unavailable)
    assert build_offline_upload_index(
        repository,
        "accepted",
        max_packets=10,
        max_interfaces=2,
        batch_size=10,
        request_postings=True,
        posting_queue_capacity=1,
        posting_max_attempts=3,
    )
    intent = repository.get_posting_index_intent("PCAP_UPLOAD", "accepted")
    assert intent is not None and intent.status.value == "PENDING"
    assert repository.get_posting_index_task("PCAP_UPLOAD", "accepted") is None
