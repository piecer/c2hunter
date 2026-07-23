from __future__ import annotations

import ipaddress
import json
import struct
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _udp_packet(payload: bytes, external_ip: str) -> bytes:
    udp = struct.pack("!HHHH", 50000, 4444, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        7,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("10.0.0.8").packed,
        ipaddress.ip_address(external_ip).packed,
    )
    return bytes.fromhex("0200000000020200000000010800") + ipv4 + udp


def _pcap(payload: bytes, external_ip: str) -> bytes:
    packet = _udp_packet(payload, external_ip)
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1_784_544_000, 500_000, len(packet), len(packet))
        + packet
    )


def _upload(client: TestClient, payload: bytes, external_ip: str, name: str) -> dict[str, object]:
    response = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={
            "name": name,
            "filename": f"{name}.pcap",
            "internal_networks": "10.0.0.0/8",
            "minimum_candidate_score": 0,
            "minimum_distinct_clients": 3,
            "idempotency_key": str(uuid.uuid4()),
        },
        content=_pcap(payload, external_ip),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_analyst_labels_flow_and_exact_signature_finds_future_c2() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    payload = b"BOT|CMD=PING|ID=123456"
    source_job = _upload(client, payload, "203.0.113.10", "source")

    flows = client.get(
        f"/api/v1/analysis-jobs/{source_job['id']}/flows",
        params={"candidate_ip": "203.0.113.10", "has_payload": True},
    ).json()
    assert flows["total"] == 1
    selected = flows["items"][0]
    assert selected["external_ip"] == "203.0.113.10"
    assert selected["service_port"] == 4444
    assert selected["payload_length"] == len(payload)
    assert "payload_sample_hex" not in selected

    preview = client.get(
        f"/api/v1/analysis-jobs/{source_job['id']}/flows/{selected['flow_id']}/payload-preview"
    )
    assert preview.status_code == 200
    assert preview.json()["payload_hex"] == payload.hex()
    assert preview.json()["payload_ascii"] == payload.decode()

    labeled = client.post(
        f"/api/v1/analysis-jobs/{source_job['id']}/flow-labels",
        json={
            "flow_id": selected["flow_id"],
            "verdict": "C2",
            "confidence": "CONFIRMED",
            "note": "malware trace confirmed this beacon",
            "create_signature": True,
            "signature_name": "family-x beacon",
        },
    )
    assert labeled.status_code == 201, labeled.text
    signature = labeled.json()["signature"]
    assert signature["enabled"] is True
    assert signature["payload_hash"] == selected["payload_hash"]
    assert signature["source_flow_id"] == selected["flow_id"]
    assert "payload_sample_hex" not in json.dumps(labeled.json())

    future_job = _upload(client, payload, "198.51.100.77", "future")
    candidates = client.get(f"/api/v1/analysis-jobs/{future_job['id']}/candidates").json()
    candidate = next(
        item for item in candidates["items"] if item["candidate_ip"] == "198.51.100.77"
    )
    analyst_evidence = next(
        item for item in candidate["evidence"] if item["type"] == "ANALYST_PAYLOAD_SIGNATURE"
    )
    assert candidate["score"] == 80
    assert analyst_evidence["metrics"]["match_mode"] == "EXACT"
    assert not any(adjustment["kind"] == "SINGLE_HOST" for adjustment in candidate["adjustments"])

    disabled = client.patch(
        f"/api/v1/payload-signatures/{signature['id']}", json={"enabled": False}
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert disabled.json()["version"] == 2
    after_disable = _upload(client, payload, "192.0.2.88", "disabled")
    assert (
        client.get(f"/api/v1/analysis-jobs/{after_disable['id']}/candidates").json()["total"] == 0
    )


def test_benign_label_blocks_conflicting_signature_creation() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    job = _upload(client, b"normal-health-check", "203.0.113.20", "benign")
    selected = client.get(f"/api/v1/analysis-jobs/{job['id']}/flows").json()["items"][0]

    benign = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/flow-labels",
        json={
            "flow_id": selected["flow_id"],
            "verdict": "BENIGN",
            "confidence": "CONFIRMED",
            "note": "known service health check",
        },
    )
    assert benign.status_code == 201
    conflict = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/flow-labels",
        json={
            "flow_id": selected["flow_id"],
            "verdict": "C2",
            "confidence": "HIGH",
            "note": "attempted conflicting rule",
            "create_signature": True,
        },
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "BENIGN_SIGNATURE_CONFLICT"
    labels = client.get(f"/api/v1/analysis-jobs/{job['id']}/flow-labels").json()
    assert labels["total"] == 1


def test_sqlite_persists_flow_labels_and_signature_versions(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "human-guided.sqlite")
    label = {
        "id": "label-1",
        "job_id": "job-1",
        "flow_id": "0123456789abcdef01234567",
        "created_at": "2026-07-23T00:00:00+00:00",
    }
    signature = {
        "id": "signature-1",
        "name": "test",
        "enabled": True,
        "version": 1,
        "created_at": "2026-07-23T00:00:00+00:00",
    }

    repository.save_flow_label(label)
    repository.save_payload_signature(signature)
    repository.save_payload_signature({**signature, "enabled": False, "version": 2})

    assert repository.list_flow_labels("job-1") == [label]
    assert repository.get_payload_signature("signature-1")["version"] == 2  # type: ignore[index]
    assert repository.list_payload_signatures()[0]["enabled"] is False
