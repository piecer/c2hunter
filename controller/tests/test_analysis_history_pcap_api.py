from __future__ import annotations

import hashlib
import ipaddress
import struct
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

from c2hunter_analysis.pcap import parse_pcap
from fastapi.testclient import TestClient
from test_analysis_job_api import api, payload, synthetic_flows

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _udp_packet(source: str, destination: str, source_port: int, ident: int) -> bytes:
    payload = b"uploaded-beacon"
    udp = struct.pack("!HHHH", source_port, 443, 8 + len(payload), 0) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        ident,
        0,
        64,
        17,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + udp


def _pcap() -> bytes:
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    epoch = int(datetime(2026, 7, 20, tzinfo=UTC).timestamp())
    for sample in range(6):
        for host in range(1, 4):
            packet = _udp_packet(f"10.0.0.{host}", "203.0.113.77", 50000 + host, sample * 10 + host)
            content.extend(
                struct.pack("<IIII", epoch + sample * 30, host * 1000, len(packet), len(packet))
            )
            content.extend(packet)
    return bytes(content)


def _legacy_packet_record(packet: bytes, index: int) -> dict[str, Any]:
    timestamp = datetime(2026, 7, 20, 12, 0, index, tzinfo=UTC).isoformat()
    return {
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.77",
        "source_port": 50001,
        "destination_port": 443,
        "protocol": "UDP",
        "raw_packet_hex": packet.hex(),
        "timestamp": timestamp,
        "raw_packet_timestamp": timestamp,
        "raw_packet_index": index,
        "raw_packet_interface_id": 0,
        "raw_packet_link_type": 1,
        "raw_packet_original_length": len(packet),
    }


def test_analysis_history_can_update_metadata_and_delete_terminal_job() -> None:
    client = api()
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="history-completed"),
    ).json()
    assert "flow_records" not in job
    original_dataset_id = job["dataset_id"]
    original_analysis = job["analysis"]
    export = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]}).json()

    updated = client.patch(
        f"/api/v1/analysis-jobs/{job['id']}",
        json={"name": "Renamed investigation", "description": "Reviewed by analyst"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed investigation"
    assert updated.json()["description"] == "Reviewed by analyst"
    assert updated.json()["dataset_id"] == original_dataset_id
    assert updated.json()["analysis"] == original_analysis
    assert "flow_records" not in updated.json()
    assert updated.json()["metadata_updates"][-1]["changes"]["name"]["from"] == "historical"

    history = client.get(
        "/api/v1/analysis-jobs",
        params={"search": "reviewed", "source_type": "SENSOR_CAPTURE"},
    ).json()
    assert history["total"] == 1
    assert "flow_records" not in history["items"][0]
    assert history["items"][0]["candidate_count"] == 1

    assert client.delete(f"/api/v1/analysis-jobs/{job['id']}").status_code == 204
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}").status_code == 404
    assert client.get(f"/api/v1/pcap-exports/{export['id']}").status_code == 404


def test_analysis_history_rejects_immutable_updates_and_active_deletion() -> None:
    client = api()
    job = client.post("/api/v1/analysis-jobs", json=payload(key="active-history")).json()

    immutable = client.patch(f"/api/v1/analysis-jobs/{job['id']}", json={"status": "COMPLETED"})
    assert immutable.status_code == 422
    deletion = client.delete(f"/api/v1/analysis-jobs/{job['id']}")
    assert deletion.status_code == 409
    assert deletion.json()["error"]["code"] == "JOB_NOT_TERMINAL"


def test_pcap_upload_runs_existing_detectors_and_appears_in_history() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    capture = _pcap()
    response = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={
            "name": "Uploaded investigation",
            "filename": "../../capture.pcap",
            "internal_networks": "10.0.0.0/8",
            "minimum_candidate_score": 0,
            "minimum_distinct_clients": 3,
            "detector_weights": '{"common_destination":0.25}',
        },
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )

    assert response.status_code == 201
    job = response.json()
    assert "flow_records" not in job
    assert job["status"] == "COMPLETED"
    assert job["mode"] == "PCAP_UPLOAD"
    assert job["source_type"] == "PCAP_UPLOAD"
    assert job["source"]["filename"] == "capture.pcap"
    assert job["source"]["capture_format"] == "PCAP"
    assert job["source"]["captured_packet_count"] == 18
    assert job["source"]["parsed_packet_count"] == 18
    assert job["flow_count"] == 18
    assert job["packet_count"] == 18
    assert job["analysis"]["detector_weights"]["common_destination"] == 0.25
    stored = repository.get_job(job["id"])
    assert stored is not None
    assert all("raw_packet_hex" not in record for record in stored["flow_records"])
    assert repository.get_job_capture(job["id"]) == capture

    candidates = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()
    assert candidates["total"] == 1
    assert candidates["items"][0]["candidate_ip"] == "203.0.113.77"
    history = client.get("/api/v1/analysis-jobs", params={"source_type": "PCAP_UPLOAD"}).json()
    assert history["items"][0]["source"]["sha256"] == job["source"]["sha256"]
    exported = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]}).json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 18

    rerun = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/reanalyze",
        json={"idempotency_key": "uploaded-rerun"},
    )
    assert rerun.status_code == 201
    assert rerun.json()["source_type"] == "PCAP_UPLOAD"
    assert rerun.json()["source"]["sha256"] == job["source"]["sha256"]


def test_pcap_export_returns_valid_packet_prefix_at_output_limit() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    output_limit = 24 + 16 + len(first_packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_max_bytes=output_limit),
            repository,
        )
    )
    capture = _pcap()
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Partial export", "filename": "partial.pcap"},
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert upload.status_code == 201

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": upload.json()["id"]},
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 18
    assert exported["exported_packet_count"] == 1
    assert exported["omitted_packet_count"] == 17
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["OUTPUT_BYTE_LIMIT"]
    assert exported["output_byte_limit"] == output_limit
    assert exported["size_bytes"] == output_limit
    assert "-partial-" in exported["filename"]
    download = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert download.status_code == 200
    assert len(download.content) == output_limit
    assert exported["sha256"] == hashlib.sha256(download.content).hexdigest()
    reparsed = parse_pcap(
        download.content,
        sensor_id="download",
        internal_networks=["10.0.0.0/8"],
        max_packets=10,
    )
    assert reparsed.captured_packet_count == 1

    repository.export_content[exported["id"]] = b"corrupt"
    corrupted = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert corrupted.status_code == 409
    assert corrupted.json()["error"]["code"] == "PCAP_EXPORT_INTEGRITY_ERROR"


def test_pcap_export_preserves_packet_prefix_at_scan_packet_limit() -> None:
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_packets=2),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Packet bounded export", "filename": "packets.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 2
    assert exported["exported_packet_count"] == 2
    assert exported["scanned_packet_count"] == 2
    assert exported["source_scan_packet_limit"] == 2
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_PACKET_LIMIT"]


def test_partial_source_scan_without_a_prefix_match_is_not_reported_as_no_match() -> None:
    repository = MemoryRepository()
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_scan_max_packets=1), repository)
    )
    packets = [
        _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1),
        _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2),
    ]
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        capture.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
        capture.extend(packet)
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Partial no-match", "filename": "partial-no-match.pcap"},
        content=bytes(capture),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": upload.json()["id"],
            "include_filters": [{"candidate_ip": "203.0.113.88"}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["error_code"] == "PCAP_SOURCE_SCAN_INCOMPLETE"
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_PACKET_LIMIT"]


def test_pcap_export_rejects_retained_segment_size_mismatch() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    capture = _pcap()
    repository.create_job(
        {
            "id": "size-mismatch-export",
            "idempotency_key": "size-mismatch-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    repository.save_sensor_pcap(
        {
            "id": "size-mismatch-segment",
            "sensor_id": "sensor-a",
            "analysis_job_id": "size-mismatch-export",
            "filename": "segment.pcap",
            "size_bytes": len(capture),
            "sha256": hashlib.sha256(capture).hexdigest(),
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )
    repository.sensor_pcaps["size-mismatch-segment"]["size_bytes"] = len(capture) - 1

    response = client.post("/api/v1/pcap-exports", json={"job_id": "size-mismatch-export"})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"


def test_pcap_export_rejects_canonical_capture_without_a_trusted_digest() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Missing digest", "filename": "missing-digest.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert upload.status_code == 201
    job_id = upload.json()["id"]
    job = repository.get_job(job_id)
    assert job is not None
    job["source"].pop("sha256")
    repository.save_job(job)

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": job_id},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"


def test_pcap_export_rejects_concurrent_memory_intensive_requests() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingRepository(MemoryRepository):
        def get_job_capture(self, job_id: str) -> bytes | None:
            content = super().get_job_capture(job_id)
            entered.set()
            release.wait(timeout=5)
            return content

    repository = BlockingRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_max_concurrent=1),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Admission", "filename": "admission.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    entered.clear()

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            client.post,
            "/api/v1/pcap-exports",
            json={"job_id": upload.json()["id"]},
        )
        assert entered.wait(timeout=2)
        second = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})
        release.set()
        assert first.result(timeout=5).status_code == 201

    assert second.status_code == 429
    assert second.json()["error"]["code"] == "PCAP_EXPORT_BUSY"


def test_legacy_pcap_export_preserves_packet_prefix_at_scan_byte_limit() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 2)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=len(first_packet)),
            repository,
        )
    )
    repository.create_job(
        {
            "id": "legacy-byte-bounded-export",
            "idempotency_key": "legacy-byte-bounded-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": [
                _legacy_packet_record(first_packet, 0),
                _legacy_packet_record(second_packet, 1),
            ],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "legacy-byte-bounded-export"})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 1
    assert exported["exported_packet_count"] == 1
    assert exported["source_total_bytes"] == len(first_packet) + len(second_packet)
    assert exported["scanned_source_bytes"] == len(first_packet)
    assert exported["scanned_packet_count"] == 1
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_pcap_export_reports_when_output_limit_cannot_fit_a_packet() -> None:
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_max_bytes=24),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Header only export", "filename": "header-only.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["matched_packet_count"] == 18
    assert exported["exported_packet_count"] == 0
    assert exported["error_code"] == "PCAP_OUTPUT_LIMIT_TOO_SMALL"
    assert exported["truncation_reasons"] == ["OUTPUT_BYTE_LIMIT"]


def test_completed_live_job_exports_associated_sensor_pcaps_with_nested_filters() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    capture = _pcap()
    repository.create_job(
        {
            "id": "live-export-job",
            "idempotency_key": "live-export-job-key",
            "name": "Live export",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    digest = hashlib.sha256(capture).hexdigest()
    repository.save_sensor_pcap(
        {
            "id": "segment-a",
            "sensor_id": "sensor-a",
            "analysis_job_id": "live-export-job",
            "filename": "segment-a.pcap",
            "size_bytes": len(capture),
            "sha256": digest,
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )
    repository.save_sensor_pcap(
        {
            "id": "unrelated",
            "sensor_id": "sensor-a",
            "analysis_job_id": "other-job",
            "filename": "other.pcap",
            "size_bytes": len(capture),
            "sha256": digest,
            "uploaded_at": "2026-08-21T09:02:00+00:00",
        },
        capture,
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "live-export-job",
            "include_filters": [{"candidate_ip": "203.0.113.0/24", "port": 443}],
            "exclude_filters": [{"source_port": 50001}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 12
    assert exported["source_capture_count"] == 1
    download = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-disposition"].endswith('.pcap"')

    no_match = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "live-export-job",
            "include_filters": [{"candidate_ip": "192.0.2.0/24"}],
        },
    )
    assert no_match.status_code == 201
    assert no_match.json()["status"] == "FAILED"
    assert no_match.json()["error_code"] == "PCAP_NO_MATCH"

    invalid = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": "live-export-job", "include_filters": [{}]},
    )
    assert invalid.status_code == 422


def test_live_export_preserves_scanned_prefix_when_source_byte_limit_is_reached() -> None:
    repository = MemoryRepository()
    capture = _pcap()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=len(capture)),
            repository,
        )
    )
    repository.create_job(
        {
            "id": "bounded-live-export",
            "idempotency_key": "bounded-live-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    digest = hashlib.sha256(capture).hexdigest()
    for index in range(2):
        repository.save_sensor_pcap(
            {
                "id": f"bounded-segment-{index}",
                "sensor_id": "sensor-a",
                "analysis_job_id": "bounded-live-export",
                "filename": f"bounded-{index}.pcap",
                "size_bytes": len(capture),
                "sha256": digest,
                "uploaded_at": f"2026-08-21T09:0{index}:00+00:00",
            },
            capture,
        )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "bounded-live-export"})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 18
    assert exported["exported_packet_count"] == 18
    assert exported["source_capture_count"] == 2
    assert exported["scanned_source_capture_count"] == 1
    assert exported["omitted_source_capture_count"] == 1
    assert exported["source_total_bytes"] == 2 * len(capture)
    assert exported["scanned_source_bytes"] == len(capture)
    assert exported["source_scan_byte_limit"] == len(capture)
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_pcap_upload_validates_media_format_size_and_packet_limit() -> None:
    assert Settings(environment="test").pcap_upload_max_bytes == 500 * 1024 * 1024
    client = api()
    params = {"name": "bad", "filename": "capture.pcap"}
    default_too_large = client.post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={
            "content-type": "application/octet-stream",
            "content-length": str(500 * 1024 * 1024 + 1),
        },
    )
    assert default_too_large.status_code == 413
    assert default_too_large.json()["error"]["code"] == "PCAP_TOO_LARGE"

    unsupported_media = client.post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={"content-type": "text/plain"},
    )
    assert unsupported_media.status_code == 415

    malformed = client.post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=b"not-a-pcap",
        headers={"content-type": "application/octet-stream"},
    )
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "INVALID_PCAP"

    invalid_weights = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={**params, "detector_weights": "not-json"},
        content=_pcap(),
        headers={"content-type": "application/octet-stream"},
    )
    assert invalid_weights.status_code == 422
    assert invalid_weights.json()["error"]["code"] == "INVALID_DETECTOR_WEIGHTS"

    too_large = TestClient(
        create_app(Settings(environment="test", pcap_upload_max_bytes=16), MemoryRepository())
    ).post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={"content-type": "application/octet-stream"},
    )
    assert too_large.status_code == 413
    assert too_large.json()["error"]["code"] == "PCAP_TOO_LARGE"

    too_many_packets = TestClient(
        create_app(Settings(environment="test", pcap_upload_max_packets=1), MemoryRepository())
    ).post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={"content-type": "application/octet-stream"},
    )
    assert too_many_packets.status_code == 413
    assert too_many_packets.json()["error"]["code"] == "PCAP_PACKET_LIMIT_EXCEEDED"


def test_sqlite_job_delete_cascades_candidates_and_exports(tmp_path: Any) -> None:
    repository = SQLiteRepository(tmp_path / "history.sqlite")
    job = {
        "id": "job-1",
        "idempotency_key": "delete-me",
        "status": "COMPLETED",
        "mode": "PCAP_UPLOAD",
        "flow_records": [{"source_ip": "10.0.0.1"}],
        "payload_signatures": [{"id": "signature-1", "version": 1}],
    }
    repository.create_job(job)
    repository.save_job_capture("job-1", b"source-pcap")
    repository.save_candidates("job-1", [{"id": "candidate-1"}])
    repository.save_export({"id": "export-1", "job_id": "job-1"}, b"pcap")

    assert "flow_records" not in repository.get_job_summary("job-1")  # type: ignore[operator]
    assert "payload_signatures" not in repository.get_job_summary("job-1")  # type: ignore[operator]
    assert "flow_records" not in repository.list_jobs()[0]
    assert "payload_signatures" not in repository.list_jobs()[0]
    assert repository.get_job("job-1")["flow_records"] == [  # type: ignore[index]
        {"source_ip": "10.0.0.1"}
    ]
    assert repository.get_job("job-1")["payload_signatures"] == [  # type: ignore[index]
        {"id": "signature-1", "version": 1}
    ]
    repository.save_job_metadata({**repository.get_job_summary("job-1"), "name": "renamed"})  # type: ignore[arg-type]
    assert repository.get_job("job-1")["flow_records"] == [  # type: ignore[index]
        {"source_ip": "10.0.0.1"}
    ]
    assert repository.get_job("job-1")["payload_signatures"] == [  # type: ignore[index]
        {"id": "signature-1", "version": 1}
    ]
    assert repository.delete_job("job-1") is True
    assert repository.get_job("job-1") is None
    assert repository.get_candidates("job-1") == []
    assert repository.get_export("export-1") is None
    assert repository.get_job_capture("job-1") is None
    assert repository.delete_job("job-1") is False
