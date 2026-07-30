import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
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
        json={
            "type": "CIDR",
            "value": "203.0.113.9/24",
            "description": "lab",
            "enabled": True,
        },
    )
    assert entry.status_code == 201
    assert entry.json()["value"] == "203.0.113.0/24"
    assert client.get("/api/v1/allowlist?type=CIDR&sort=value").json()["total"] == 1
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["total"] == 0
    assert client.delete(f"/api/v1/allowlist/{entry.json()['id']}").status_code == 204


def test_allowlist_suppresses_existing_candidate_but_preserves_audit_record() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    endpoint = f"/api/v1/analysis-jobs/{job['id']}/candidates"
    assert client.get(endpoint).json()["total"] == 1

    entry = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.9",
            "description": "trusted infrastructure",
        },
    ).json()

    assert client.get(endpoint).json()["total"] == 0
    suppressed = client.get(endpoint, params={"include_suppressed": True}).json()
    assert suppressed["total"] == 1
    assert suppressed["items"][0]["excluded"] is True
    assert suppressed["items"][0]["suppressed_by_allowlist_id"] == entry["id"]
    assert suppressed["items"][0]["suppressed_at"]
    assert "trusted infrastructure" in suppressed["items"][0]["exclude_reason"]
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}").json()["candidate_count"] == 0


def test_trusted_dns_policy_only_discounts_matching_udp_dns_traffic() -> None:
    client = configured_client()
    response = client.post(
        "/api/v1/allowlist",
        json={
            "type": "TRUSTED_DNS",
            "value": "203.0.113.9",
            "description": "corporate resolver",
        },
    )
    assert response.status_code == 201

    request = job_payload()
    flows = request["flow_records"]
    assert isinstance(flows, list)
    for flow in flows:
        assert isinstance(flow, dict)
        flow["protocol"] = "UDP"
        flow["destination_port"] = 53
    job = client.post("/api/v1/analysis-jobs", json=request).json()
    candidate = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["items"][0]

    assert candidate["candidate_ip"] == "203.0.113.9"
    assert any(item["kind"] == "PUBLIC_DNS_NTP" for item in candidate["adjustments"])

    tcp_request = job_payload()
    tcp_request["idempotency_key"] = "storage-test-tcp-dns"
    tcp_flows = tcp_request["flow_records"]
    assert isinstance(tcp_flows, list)
    for flow in tcp_flows:
        assert isinstance(flow, dict)
        flow["protocol"] = "TCP"
        flow["destination_port"] = 53
    tcp_job = client.post("/api/v1/analysis-jobs", json=tcp_request).json()
    tcp_candidate = client.get(f"/api/v1/analysis-jobs/{tcp_job['id']}/candidates").json()["items"][
        0
    ]
    assert not any(item["kind"] == "PUBLIC_DNS_NTP" for item in tcp_candidate["adjustments"])


def test_flow_review_filters_endpoints_by_ip_or_cidr() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    endpoint = f"/api/v1/analysis-jobs/{job['id']}/flows"

    assert client.get(endpoint, params={"candidate_ip": "203.0.113.9"}).json()["total"] == 24
    assert client.get(endpoint, params={"candidate_ip": "203.0.113.0/24"}).json()["total"] == 24
    assert client.get(endpoint, params={"candidate_ip": "10.0.0.0/30"}).json()["total"] == 18
    assert client.get(endpoint, params={"candidate_ip": "not-a-cidr"}).status_code == 422


def test_flow_review_filters_external_source_and_destination_ports_independently() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    endpoint = f"/api/v1/analysis-jobs/{job['id']}/flows"

    assert client.get(endpoint, params={"port": 4444}).json()["total"] == 24
    assert client.get(endpoint, params={"source_port": 50000}).json()["total"] == 24
    assert client.get(endpoint, params={"destination_port": 4444}).json()["total"] == 24
    assert client.get(endpoint, params={"source_port": 4444}).json()["total"] == 0
    assert (
        client.get(
            endpoint,
            params={"port": 4444, "source_port": 50000, "destination_port": 4444},
        ).json()["total"]
        == 24
    )


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
    assert policy.days == {
        "pcap": 7,
        "flow": 30,
        "result": 180,
        "audit": 365,
        "heartbeat": 30,
    }
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


@pytest.mark.parametrize("operation", ["update", "set-default"])
def test_sqlite_preset_default_switch_rolls_back_on_serialization_failure(
    tmp_path: Path, operation: str
) -> None:
    repository = SQLiteRepository(tmp_path / f"preset-{operation}.sqlite")
    repository.save_detector_weight_preset({"id": "first", "name": "First", "is_default": True})
    repository.save_detector_weight_preset({"id": "second", "name": "Second", "is_default": False})
    serialize = repository._serialize
    calls = 0

    def fail_second_serialization(value: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("serialization failed")
        return serialize(value)

    repository._serialize = fail_second_serialization  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="serialization failed"):
        if operation == "update":
            repository.update_detector_weight_preset(
                "second", {"name": "Updated"}, set_as_default=True
            )
        else:
            repository.set_default_detector_weight_preset("second")

    assert not repository.connection.in_transaction
    defaults = [
        preset["id"] for preset in repository.list_detector_weight_presets() if preset["is_default"]
    ]
    assert defaults == ["first"]
    repository.close()
