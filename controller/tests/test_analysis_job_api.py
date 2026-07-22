import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.jobs import JobState, StateMachine
from c2hunter_controller.repositories import MemoryRepository

START = datetime(2026, 7, 20, tzinfo=UTC)


def api() -> TestClient:
    repository = MemoryRepository()
    app = create_app(Settings(environment="test"), repository)
    client = TestClient(app)
    token = "analysis-test-token"
    repository.upsert_sensor({"sensor_id": "s1"})
    repository.save_sensor_credential(
        {"sensor_id": "s1", "token_hash": hashlib.sha256(token.encode()).hexdigest()}
    )
    client.post(
        "/api/v1/sensors/register",
        headers={"X-Sensor-Token": token},
        json={
            "sensor_id": "s1",
            "name": "one",
            "hostname": "one",
            "agent_version": "1",
            "os_version": "Linux",
            "kernel_version": "6",
            "interfaces": [
                {"name": "eth0", "mac_address": "00:00:00:00:00:01", "direction": "OUTBOUND"}
            ],
            "capabilities": ["FLOW"],
            "current_time": START.isoformat(),
            "available_disk_bytes": 1,
            "received_packets": 0,
            "dropped_packets": 0,
        },
    )
    return client


def payload(
    *, flows: list[dict[str, object]] | None = None, key: str = "key-1"
) -> dict[str, object]:
    return {
        "name": "historical",
        "idempotency_key": key,
        "sensor_ids": ["s1"],
        "mode": "HISTORICAL",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(minutes=10)).isoformat(),
        "capture": {
            "max_packets": 10000,
            "directions": ["OUTBOUND"],
            "protocols": ["TCP"],
            "store_pcap": False,
        },
        "analysis": {
            "profile": "ddos_botnet",
            "minimum_distinct_clients": 3,
            "minimum_candidate_score": 0,
            "periodicity_min_samples": 5,
        },
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": flows or [],
    }


def synthetic_flows() -> list[dict[str, object]]:
    return [
        {
            "sensor_id": "s1",
            "timestamp": (START + timedelta(seconds=period * 30)).isoformat(),
            "source_ip": f"10.0.0.{host}",
            "destination_ip": "203.0.113.77",
            "source_port": 50000,
            "destination_port": 4444,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "packet_count": 1,
            "total_bytes": 60,
            "payload_hash": "same",
        }
        for period in range(7)
        for host in range(1, 5)
    ]


def test_state_machine_exposes_ten_states_and_rejects_backward_transition() -> None:
    assert len(JobState) == 10
    machine = StateMachine()
    state = JobState.CREATED
    for target in (
        JobState.WAITING_FOR_SENSOR,
        JobState.CAPTURING,
        JobState.UPLOADING,
        JobState.INGESTING,
        JobState.ANALYZING,
        JobState.COMPLETED,
    ):
        machine.validate(state, target)
        state = target
    with pytest.raises(ValueError):
        machine.validate(JobState.ANALYZING, JobState.CREATED)
    machine.validate(JobState.CAPTURING, JobState.CANCELLED)


def test_analysis_request_validation_rejects_time_and_missing_sensor() -> None:
    client = api()
    invalid = payload()
    invalid["end_time"] = (START - timedelta(seconds=1)).isoformat()
    assert client.post("/api/v1/analysis-jobs", json=invalid).status_code == 422
    missing = payload(key="other")
    missing["sensor_ids"] = ["absent"]
    response = client.post("/api/v1/analysis-jobs", json=missing)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SENSOR_NOT_FOUND"


def test_analysis_is_idempotent_and_candidates_are_calculated_from_flows() -> None:
    client = api()
    request = payload(flows=synthetic_flows())
    first = client.post("/api/v1/analysis-jobs", json=request)
    second = client.post("/api/v1/analysis-jobs", json=request)
    assert first.status_code == 201
    assert first.json()["id"] == second.json()["id"]
    assert first.json()["status"] == "COMPLETED"
    job_id = first.json()["id"]
    candidates = client.get(f"/api/v1/analysis-jobs/{job_id}/candidates?sort=-score").json()
    assert candidates["total"] == 1
    assert candidates["items"][0]["candidate_ip"] == "203.0.113.77"
    assert candidates["items"][0]["score"] >= 60
    assert candidates["items"][0]["internal_hosts"] == [
        "10.0.0.1",
        "10.0.0.2",
        "10.0.0.3",
        "10.0.0.4",
    ]
    assert candidates["items"][0]["sensor_ids"] == ["s1"]
    assert candidates["items"][0]["protocols"] == ["TCP"]
    assert candidates["items"][0]["ports"] == [4444]
    detail = client.get(
        f"/api/v1/analysis-jobs/{job_id}/candidates/{candidates['items'][0]['id']}"
    ).json()
    assert {item["type"] for item in detail["evidence"]} >= {
        "COMMON_DESTINATION",
        "PERIODIC_BEACON",
    }
    assert detail["flow_count"] == 28
    assert detail["packet_count"] == 28
    assert detail["byte_count"] == 1680
    assert sum(bucket["packets"] for bucket in detail["traffic_buckets"]) == 28
    assert len(first.json()["transitions"]) == 7


def test_cancel_is_idempotent_and_reanalysis_reuses_dataset_not_results() -> None:
    client = api()
    waiting = client.post("/api/v1/analysis-jobs", json=payload(key="wait")).json()
    cancelled = client.post(
        f"/api/v1/analysis-jobs/{waiting['id']}/cancel", json={"reason": "operator"}
    )
    repeated = client.post(
        f"/api/v1/analysis-jobs/{waiting['id']}/cancel", json={"reason": "again"}
    )
    assert cancelled.json()["status"] == repeated.json()["status"] == "CANCELLED"

    completed = client.post(
        "/api/v1/analysis-jobs", json=payload(flows=synthetic_flows(), key="done")
    ).json()
    rerun = client.post(
        f"/api/v1/analysis-jobs/{completed['id']}/reanalyze",
        json={"idempotency_key": "rerun", "minimum_candidate_score": 70},
    )
    assert rerun.status_code == 201
    assert rerun.json()["id"] != completed["id"]
    assert rerun.json()["dataset_id"] == completed["dataset_id"]
    assert rerun.json()["parent_job_id"] == completed["id"]
