from __future__ import annotations

import hashlib
import ipaddress
import struct
from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    build_offline_upload_index,
)
from c2hunter_controller.repositories import MemoryRepository


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _capture() -> bytes:
    udp_payload = b"stage9"
    udp = struct.pack("!HHHH", 50_000, 443, 8 + len(udp_payload), 0) + udp_payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("10.0.0.1").packed,
        ipaddress.ip_address("203.0.113.7").packed,
    )
    ipv4 = ipv4[:10] + struct.pack("!H", _checksum(ipv4)) + ipv4[12:]
    payload = bytes.fromhex("0200000000020200000000010800") + ipv4 + udp
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1_700_000_000, 123, len(payload), len(payload))
        + payload
    )


def _upload(client: TestClient, *, key: str = "stage9-key"):
    return client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "stage9", "filename": "stage9.pcap", "idempotency_key": key},
        headers={
            "content-type": "application/vnd.tcpdump.pcap",
        },
        content=_capture(),
    )


def _binding(repository: MemoryRepository, job_id: str) -> SourceIndexBinding:
    job = repository.get_job_summary(job_id)
    assert job is not None
    source = job["source"]
    assert isinstance(source, dict)
    return SourceIndexBinding(
        source_kind="PCAP_UPLOAD",
        source_id=job_id,
        source_version_id="sha256:" + hashlib.sha256(_capture()).hexdigest(),
        source_size_bytes=int(source["size_bytes"]),
        source_sha256=str(source["sha256"]),
        capture_format=str(source["capture_format"]),  # type: ignore[arg-type]
    )


def test_new_offline_upload_builds_ready_index_without_public_schema_drift() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = _upload(client)

    assert response.status_code == 201
    job_id = response.json()["id"]
    lookup = repository.get_structural_index(_binding(repository, job_id))
    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None
    assert len(lookup.snapshot.packets) == 1
    assert "index" not in response.json()
    assert "pcap_offset_index" not in str(client.get("/openapi.json").json())


def test_index_failure_is_best_effort_and_replay_does_not_rebuild(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    attempts = 0

    def fail(*_args: Any, **_kwargs: Any) -> None:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("index unavailable")

    monkeypatch.setattr(repository, "begin_structural_index", fail)
    client = TestClient(create_app(Settings(environment="test"), repository))

    first = _upload(client)
    replay = _upload(client)

    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json()["id"] == first.json()["id"]
    assert attempts == 1
    assert repository.get_job_capture(first.json()["id"]) == _capture()


def test_source_open_failure_is_best_effort_and_preserves_valid_upload(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    opens = 0

    def fail_open(_job_id: str) -> None:
        nonlocal opens
        opens += 1
        raise RuntimeError("source open unavailable")

    monkeypatch.setattr(repository, "open_job_capture", fail_open)
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = _upload(client, key="source-open-failure")

    assert response.status_code == 201
    assert opens == 1
    monkeypatch.undo()
    assert repository.get_job_capture(response.json()["id"]) == _capture()


def test_build_uses_durable_capture_version_instead_of_open_source_version() -> None:
    repository = MemoryRepository()
    digest = hashlib.sha256(_capture()).hexdigest()
    binding = SourceIndexBinding(
        source_kind="PCAP_UPLOAD",
        source_id="durable-build",
        source_version_id="durable:opaque-version",
        source_size_bytes=len(_capture()),
        source_sha256=digest,
        capture_format="PCAP",
    )
    repository.create_job(_job_for_binding(binding))
    repository.save_job_capture(binding.source_id, _capture())
    durable = CaptureSourceVersion(
        source_kind="PCAP_UPLOAD",
        source_id=binding.source_id,
        object_key=f"captures/{binding.source_id}.pcap",
        source_version_id=binding.source_version_id,
        source_size_bytes=binding.source_size_bytes,
        source_sha256=binding.source_sha256,
    )
    repository.capture_source_versions[binding.source_id] = durable

    assert build_offline_upload_index(
        repository,
        binding.source_id,
        max_packets=10,
        max_interfaces=4,
        batch_size=2,
    )
    lookup = repository.get_structural_index(binding)
    assert lookup.availability is IndexAvailability.READY


def _job_for_binding(binding: SourceIndexBinding) -> dict[str, Any]:
    return {
        "id": binding.source_id,
        "idempotency_key": f"key-{binding.source_id}",
        "mode": "PCAP_UPLOAD",
        "source": {
            "packet_bytes_retained": True,
            "size_bytes": binding.source_size_bytes,
            "sha256": binding.source_sha256,
            "capture_format": binding.capture_format,
        },
    }


@pytest.mark.parametrize(
    ("settings", "expected_status"),
    [
        (Settings(environment="test", pcap_export_execution_mode="sync_only"), 201),
        (
            Settings(
                environment="test",
                pcap_export_sync_max_source_bytes=1,
                pcap_export_sync_max_packets=1,
            ),
            202,
        ),
    ],
)
def test_sync_and_async_export_never_query_stage9_index(
    monkeypatch: Any, settings: Settings, expected_status: int
) -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(settings, repository))
    uploaded = _upload(client)
    assert uploaded.status_code == 201

    monkeypatch.setattr(
        repository,
        "get_structural_index",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("index lookup")),
    )
    exported = client.post("/api/v1/pcap-exports", json={"job_id": uploaded.json()["id"]})
    assert exported.status_code == expected_status
    if expected_status == 201:
        assert exported.json()["exported_packet_count"] == 1
    else:
        assert exported.json()["execution_mode"] == "ASYNC"
