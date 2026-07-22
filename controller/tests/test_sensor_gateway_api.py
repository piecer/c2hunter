from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def api_and_repo() -> tuple[TestClient, MemoryRepository]:
    repo = MemoryRepository()
    return TestClient(create_app(Settings(environment="test"), repo)), repo


def enrollment_payload(**overrides: Any) -> dict[str, Any]:
    value: dict[str, Any] = {
        "name": "edge sensor",
        "expires_in_seconds": 600,
        "capture_sources": [
            {"interface": "eth0", "direction": "OUTBOUND", "bpf_filter": "tcp", "enabled": True}
        ],
        "internal_networks": ["10.0.0.7/24", "2001:db8::1/64"],
    }
    value.update(overrides)
    return value


def claim_payload(interfaces: list[str] | None = None) -> dict[str, Any]:
    return {
        "hostname": "edge-1",
        "agent_version": "1.2.3",
        "os_version": "Linux",
        "kernel_version": "6.8",
        "capabilities": ["FLOW"],
        "discovered_interfaces": [
            {"name": name, "mac_address": "02:00:00:00:00:01"}
            for name in (interfaces if interfaces is not None else ["eth0"])
        ],
    }


def enroll_and_claim(api: TestClient) -> tuple[str, str]:
    created = api.post("/api/v1/sensor-enrollments", json=enrollment_payload())
    assert created.status_code == 201
    claimed = api.post(
        f"/api/v1/sensor-enrollments/{created.json()['enrollment_token']}/claim",
        json=claim_payload(),
    )
    assert claimed.status_code == 201
    return claimed.json()["sensor_id"], claimed.json()["agent_token"]


def test_enrollment_returns_secret_once_and_persists_only_hash() -> None:
    api, repo = api_and_repo()
    response = api.post("/api/v1/sensor-enrollments", json=enrollment_payload())
    assert response.status_code == 201
    body = response.json()
    assert body["enrollment_token"] in body["install_command"]
    assert body["expires_at"]

    persisted = repo.get_enrollment(body["enrollment_id"])
    assert persisted is not None
    assert persisted["token_hash"] != body["enrollment_token"]
    assert len(persisted["token_hash"]) == 64
    listed = api.get("/api/v1/sensor-enrollments").json()
    assert listed["total"] == 1
    assert "token_hash" not in listed["items"][0]
    assert "enrollment_token" not in listed["items"][0]
    assert listed["items"][0]["status"] == "PENDING"
    api.post(f"/api/v1/sensor-enrollments/{body['enrollment_token']}/claim", json={})
    assert body["enrollment_token"] not in api.get("/api/v1/metrics").text


@pytest.mark.parametrize(
    "changes",
    [
        {"capture_sources": [{"interface": "bad/name", "direction": "OUTBOUND", "enabled": True}]},
        {"capture_sources": [{"interface": "x" * 16, "direction": "OUTBOUND", "enabled": True}]},
        {"capture_sources": [{"interface": "eth0", "direction": "SIDEWAYS", "enabled": True}]},
        {
            "capture_sources": [
                {"interface": "eth0", "direction": "INBOUND", "enabled": True},
                {"interface": "eth0", "direction": "OUTBOUND", "enabled": True},
            ]
        },
        {"capture_sources": [{"interface": "eth0", "direction": "OUTBOUND", "enabled": False}]},
        {
            "capture_sources": [
                {
                    "interface": "eth0",
                    "direction": "OUTBOUND",
                    "bpf_filter": "x" * 2001,
                    "enabled": True,
                }
            ]
        },
        {"internal_networks": ["not-a-cidr"]},
    ],
)
def test_enrollment_configuration_validation(changes: dict[str, Any]) -> None:
    api, _ = api_and_repo()
    response = api.post("/api/v1/sensor-enrollments", json=enrollment_payload(**changes))
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "VALIDATION_ERROR"


def test_claim_rejects_undiscovered_desired_interface_without_consuming_token() -> None:
    api, _ = api_and_repo()
    created = api.post("/api/v1/sensor-enrollments", json=enrollment_payload()).json()
    url = f"/api/v1/sensor-enrollments/{created['enrollment_token']}/claim"
    rejected = api.post(url, json=claim_payload(["lo"]))
    assert rejected.status_code == 422
    assert rejected.json()["error"]["code"] == "DESIRED_INTERFACE_NOT_FOUND"

    claimed = api.post(url, json=claim_payload())
    assert claimed.status_code == 201
    body = claimed.json()
    assert body["config_version"] == 1
    assert body["capture_sources"][0]["validation_status"] == "VALID"
    assert body["internal_networks"] == ["10.0.0.0/24", "2001:db8::/64"]
    sensor = api.get(f"/api/v1/sensors/{body['sensor_id']}").json()
    assert sensor["observed_interfaces"][0]["name"] == "eth0"

    replay = api.post(url, json=claim_payload())
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "ENROLLMENT_ALREADY_CLAIMED"


def test_claim_generates_sensor_id_when_persisted_value_is_null() -> None:
    api, repo = api_and_repo()
    created = api.post("/api/v1/sensor-enrollments", json=enrollment_payload()).json()
    enrollment = repo.get_enrollment(created["enrollment_id"])
    assert enrollment is not None
    enrollment["sensor_id"] = None
    repo.save_enrollment(enrollment)

    claimed = api.post(
        f"/api/v1/sensor-enrollments/{created['enrollment_token']}/claim",
        json=claim_payload(),
    )

    assert claimed.status_code == 201
    assert claimed.json()["sensor_id"]
    assert api.get(f"/api/v1/sensors/{claimed.json()['sensor_id']}").status_code == 200


def test_memory_claim_is_atomic() -> None:
    api, _ = api_and_repo()
    token = api.post("/api/v1/sensor-enrollments", json=enrollment_payload()).json()[
        "enrollment_token"
    ]

    def claim() -> int:
        response = api.post(f"/api/v1/sensor-enrollments/{token}/claim", json=claim_payload())
        return response.status_code

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(lambda _: claim(), range(2)))
    assert sorted(statuses) == [201, 409]


def test_agent_endpoints_authenticate_rotate_and_revoke_credentials() -> None:
    api, _ = api_and_repo()
    sensor_id, token = enroll_and_claim(api)
    config_url = f"/api/v1/sensors/{sensor_id}/agent-config"
    assert api.get(config_url).status_code == 401
    assert api.get(config_url, headers={"X-Sensor-Token": "wrong"}).status_code == 401
    assert api.get(config_url, headers={"X-Sensor-Token": token}).status_code == 200

    rotated = api.post(f"/api/v1/sensors/{sensor_id}/credentials/rotate")
    assert rotated.status_code == 200
    new_token = rotated.json()["agent_token"]
    assert api.get(config_url, headers={"X-Sensor-Token": token}).status_code == 401
    assert api.get(config_url, headers={"X-Sensor-Token": new_token}).status_code == 200

    revoked = api.post(f"/api/v1/sensors/{sensor_id}/revoke")
    assert revoked.status_code == 200
    denied = api.get(config_url, headers={"X-Sensor-Token": new_token})
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "SENSOR_REVOKED"


def test_configuration_crud_uses_optimistic_version_and_agent_sees_update() -> None:
    api, _ = api_and_repo()
    sensor_id, token = enroll_and_claim(api)
    updated = api.put(
        f"/api/v1/sensors/{sensor_id}/configuration",
        json={
            "config_version": 1,
            "capture_sources": [
                {"interface": "eth0", "direction": "INBOUND", "bpf_filter": "udp", "enabled": True}
            ],
            "internal_networks": ["192.0.2.17/24"],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["config_version"] == 2
    assert updated.json()["internal_networks"] == ["192.0.2.0/24"]

    stale = api.put(
        f"/api/v1/sensors/{sensor_id}/configuration",
        json={**updated.json(), "config_version": 1},
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "CONFIG_VERSION_CONFLICT"
    polled = api.get(f"/api/v1/sensors/{sensor_id}/agent-config", headers={"X-Sensor-Token": token})
    assert polled.json()["config_version"] == 2


def test_openapi_documents_gateway_routes_and_sensor_token_header() -> None:
    api, _ = api_and_repo()
    schema = api.get("/openapi.json").json()
    paths = schema["paths"]
    assert "/api/v1/sensor-enrollments" in paths
    assert "/api/v1/sensor-enrollments/{token}/claim" in paths
    assert "/api/v1/sensors/{sensor_id}/configuration" in paths
    parameters = paths["/api/v1/sensors/{sensor_id}/agent-config"]["get"]["parameters"]
    assert any(item.get("name") == "X-Sensor-Token" and item.get("required") for item in parameters)
    assert paths["/api/v1/sensor-enrollments"]["post"]["responses"]["201"]["content"][
        "application/json"
    ]["schema"]["$ref"].endswith("/EnrollmentCreateResponse")
    assert paths["/api/v1/sensor-enrollments/{token}/claim"]["post"]["responses"]["201"]["content"][
        "application/json"
    ]["schema"]["$ref"].endswith("/EnrollmentClaimResponse")
