from __future__ import annotations

import ipaddress
import struct
from datetime import UTC, datetime
from typing import Any

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
    }
    repository.create_job(job)
    repository.save_job_capture("job-1", b"source-pcap")
    repository.save_candidates("job-1", [{"id": "candidate-1"}])
    repository.save_export({"id": "export-1", "job_id": "job-1"}, b"pcap")

    assert "flow_records" not in repository.get_job_summary("job-1")  # type: ignore[operator]
    assert "flow_records" not in repository.list_jobs()[0]
    assert repository.get_job("job-1")["flow_records"] == [  # type: ignore[index]
        {"source_ip": "10.0.0.1"}
    ]
    repository.save_job_metadata({**repository.get_job_summary("job-1"), "name": "renamed"})  # type: ignore[arg-type]
    assert repository.get_job("job-1")["flow_records"] == [  # type: ignore[index]
        {"source_ip": "10.0.0.1"}
    ]
    assert repository.delete_job("job-1") is True
    assert repository.get_job("job-1") is None
    assert repository.get_candidates("job-1") == []
    assert repository.get_export("export-1") is None
    assert repository.get_job_capture("job-1") is None
    assert repository.delete_job("job-1") is False
