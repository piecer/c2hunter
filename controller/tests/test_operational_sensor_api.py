import hashlib
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from httpx import Response

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.logging import render_json_log
from c2hunter_controller.repositories import MemoryRepository


def client() -> TestClient:
    return TestClient(create_app(Settings(environment="test"), MemoryRepository()))


def sensor_payload(sensor_id: str, name: str = "sensor") -> dict[str, object]:
    return {
        "sensor_id": sensor_id,
        "name": name,
        "hostname": f"{sensor_id}.local",
        "agent_version": "1.0.0",
        "os_version": "Linux",
        "kernel_version": "6.8",
        "interfaces": [
            {"name": "eth0", "mac_address": "02:00:00:00:00:01", "direction": "OUTBOUND"}
        ],
        "capabilities": ["FLOW", "PCAP"],
        "current_time": datetime.now(UTC).isoformat(),
        "available_disk_bytes": 1000000,
        "received_packets": 20,
        "dropped_packets": 1,
    }


def register(api: TestClient, payload: dict[str, object]) -> tuple[Response, str]:
    sensor_id = str(payload["sensor_id"])
    token = f"token-{sensor_id}"
    repository = api.app.state.repository
    repository.upsert_sensor({"sensor_id": sensor_id})
    repository.save_sensor_credential(
        {"sensor_id": sensor_id, "token_hash": hashlib.sha256(token.encode()).hexdigest()}
    )
    return api.post(
        "/api/v1/sensors/register", json=payload, headers={"X-Sensor-Token": token}
    ), token


def test_settings_validate_clock_threshold_and_json_log_fields() -> None:
    try:
        Settings(clock_skew_threshold_seconds=0)
    except ValueError:
        pass
    else:
        raise AssertionError("invalid threshold accepted")
    event = render_json_log("INFO", "api", "started", request_id="r1")
    assert set(event) >= {
        "timestamp",
        "level",
        "service",
        "component",
        "job_id",
        "sensor_id",
        "request_id",
        "message",
        "error",
    }
    assert event["request_id"] == "r1"


def test_health_readiness_metrics_and_structured_validation_error() -> None:
    api = client()
    assert api.get("/api/v1/health").json() == {"status": "ok"}
    assert api.get("/api/v1/ready").json()["status"] == "ready"
    metrics = api.get("/api/v1/metrics")
    assert metrics.status_code == 200
    assert "c2hunter_api_requests_total" in metrics.text
    error = api.post("/api/v1/sensors/register", json={})
    assert error.status_code == 401
    assert error.json()["error"]["code"] == "SENSOR_TOKEN_REQUIRED"
    assert error.json()["error"]["request_id"]


def test_sensor_registration_heartbeat_clock_skew_and_listing() -> None:
    api = client()
    assert register(api, sensor_payload("s2", "Zulu"))[0].status_code == 201
    assert register(api, sensor_payload("s1", "Alpha"))[0].status_code == 201
    heartbeat = {
        "reported_at": (datetime.now(UTC) - timedelta(seconds=3)).isoformat(),
        "status": "ONLINE",
        "cpu_percent": 10,
        "memory_percent": 20,
        "disk_percent": 30,
        "active_job_ids": [],
        "received_packets": 30,
        "dropped_packets": 2,
        "pending_bytes": 0,
        "last_error": None,
    }
    response = api.post(
        "/api/v1/sensors/s1/heartbeat",
        json=heartbeat,
        headers={"X-Sensor-Token": "token-s1"},
    )
    assert response.status_code == 200
    assert response.json()["derived_status"] == "DEGRADED"
    assert response.json()["clock_offset_ms"] >= 2900
    listed = api.get("/api/v1/sensors?page=1&page_size=1&sort=name&status=DEGRADED").json()
    assert listed["total"] == 1
    assert listed["items"][0]["sensor_id"] == "s1"
    assert api.get("/api/v1/sensors/s1").json()["interfaces"][0]["direction"] == "OUTBOUND"


def test_sensor_group_creation_validates_members_and_lists() -> None:
    api = client()
    register(api, sensor_payload("s1"))
    register(api, sensor_payload("s2"))
    created = api.post(
        "/api/v1/sensor-groups",
        json={"name": "Seoul", "description": "pair", "sensor_ids": ["s1", "s2"]},
    )
    assert created.status_code == 201
    assert created.json()["sensor_ids"] == ["s1", "s2"]
    assert api.get("/api/v1/sensor-groups?sort=-name").json()["total"] == 1
    missing = api.post("/api/v1/sensor-groups", json={"name": "bad", "sensor_ids": ["missing"]})
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "SENSOR_NOT_FOUND"
