import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from c2hunter_controller.retention import RetentionPolicy

START = datetime(2026, 7, 20, tzinfo=UTC)


def configured_client() -> TestClient:
    repository = MemoryRepository()
    repository.upsert_sensor({"sensor_id": "s1", "name": "sensor", "derived_status": "ONLINE"})
    return TestClient(create_app(Settings(environment="test"), repository))


def job_payload(key: str = "job") -> dict[str, object]:
    raw = "00112233445566778899aabb08004500001400000000400600000a000001cb007109"
    flows = [
        {
            "sensor_id": "s1",
            "timestamp": (START + timedelta(seconds=tick * 30)).isoformat(),
            "source_ip": f"10.0.0.{host}",
            "destination_ip": "203.0.113.9",
            "source_port": 50000,
            "destination_port": 4444,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "packet_count": 1,
            "total_bytes": 60,
            "payload_hash": "sig",
            "raw_packet_hex": raw,
        }
        for tick in range(6)
        for host in range(1, 5)
    ]
    return {
        "name": "pcap job",
        "idempotency_key": key,
        "sensor_ids": ["s1"],
        "mode": "HISTORICAL",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(minutes=5)).isoformat(),
        "capture": {"directions": ["OUTBOUND"], "store_pcap": True},
        "analysis": {
            "minimum_distinct_clients": 3,
            "minimum_candidate_score": 0,
            "periodicity_min_samples": 5,
        },
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": flows,
    }


def test_allowlist_crud_normalizes_and_suppresses_calculated_candidate() -> None:
    client = configured_client()
    entry = client.post(
        "/api/v1/allowlist",
        json={"type": "CIDR", "value": "203.0.113.9/24", "description": "lab", "enabled": True},
    )
    assert entry.status_code == 201
    assert entry.json()["value"] == "203.0.113.0/24"
    assert client.get("/api/v1/allowlist?type=CIDR&sort=value").json()["total"] == 1
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["total"] == 0
    assert client.delete(f"/api/v1/allowlist/{entry.json()['id']}").status_code == 204


def test_pcap_export_applies_all_filters_and_streams_pcap() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    candidate = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["items"][0]
    export = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": job["id"],
            "candidate_id": candidate["id"],
            "internal_host_ip": "10.0.0.1",
            "start_time": START.isoformat(),
            "end_time": (START + timedelta(minutes=4)).isoformat(),
            "port": 4444,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "sensor_id": "s1",
        },
    )
    assert export.status_code == 201
    body = export.json()
    assert body["status"] == "COMPLETED"
    assert body["matched_packet_count"] == 6
    fetched = client.get(f"/api/v1/pcap-exports/{body['id']}")
    assert fetched.json()["filter"]["candidate_ip"] == "203.0.113.9"
    download = client.get(f"/api/v1/pcap-exports/{body['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert struct.unpack("<I", download.content[:4])[0] == 0xA1B2C3D4


def test_export_validation_rejects_inverted_time_range_and_unknown_job() -> None:
    client = configured_client()
    invalid = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "missing",
            "start_time": (START + timedelta(seconds=1)).isoformat(),
            "end_time": START.isoformat(),
        },
    )
    assert invalid.status_code == 422
    missing = client.post("/api/v1/pcap-exports", json={"job_id": "missing"})
    assert missing.status_code == 404


def test_retention_defaults_and_expiration_cutoffs() -> None:
    policy = RetentionPolicy()
    assert policy.days == {"pcap": 7, "flow": 30, "result": 180, "audit": 365, "heartbeat": 30}
    now = datetime(2026, 7, 20, tzinfo=UTC)
    assert policy.is_expired("pcap", now - timedelta(days=8), now)
    assert not policy.is_expired("result", now - timedelta(days=179), now)


def test_sqlite_adapter_persists_repository_contract(tmp_path: Path) -> None:
    path = tmp_path / "controller.db"
    first = SQLiteRepository(path)
    first.upsert_sensor({"sensor_id": "s1", "name": "durable"})
    first.create_group({"id": "g1", "name": "group", "sensor_ids": ["s1"]})
    first.close()
    reopened = SQLiteRepository(path)
    assert reopened.ready()
    assert reopened.get_sensor("s1")["name"] == "durable"  # type: ignore[index]
    assert reopened.list_groups()[0]["id"] == "g1"
    reopened.close()
