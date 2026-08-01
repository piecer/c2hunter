from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


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


def test_claim_preserves_per_interface_pcap_selection() -> None:
    api, _ = api_and_repo()
    payload = enrollment_payload()
    payload["capture_sources"][0]["store_pcap"] = True
    created = api.post("/api/v1/sensor-enrollments", json=payload)
    assert created.status_code == 201
    claimed = api.post(
        f"/api/v1/sensor-enrollments/{created.json()['enrollment_token']}/claim",
        json=claim_payload(),
    )
    assert claimed.status_code == 201
    assert claimed.json()["capture_sources"][0]["store_pcap"] is True


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


def test_heartbeat_refreshes_discovered_interfaces_for_configuration_updates() -> None:
    api, _ = api_and_repo()
    created = api.post("/api/v1/sensor-enrollments", json=enrollment_payload()).json()
    claimed = api.post(
        f"/api/v1/sensor-enrollments/{created['enrollment_token']}/claim",
        json=claim_payload(),
    ).json()
    sensor_id = claimed["sensor_id"]
    headers = {"X-Sensor-Token": claimed["agent_token"]}

    heartbeat = api.post(
        f"/api/v1/sensors/{sensor_id}/heartbeat",
        headers=headers,
        json={
            "reported_at": datetime.now(UTC).isoformat(),
            "status": "ONLINE",
            "cpu_percent": 10,
            "memory_percent": 20,
            "disk_percent": 30,
            "active_job_ids": [],
            "received_packets": 0,
            "dropped_packets": 0,
            "pending_bytes": 0,
            "last_error": None,
            "interfaces": [],
            "discovered_interfaces": [
                {"name": "eth0", "mac_address": "00:00:00:00:00:01"},
                {"name": "eth1", "mac_address": "00:00:00:00:00:02"},
            ],
        },
    )
    assert heartbeat.status_code == 200

    updated = api.put(
        f"/api/v1/sensors/{sensor_id}/configuration",
        json={
            "config_version": 1,
            "capture_sources": [
                {"interface": "eth0", "direction": "OUTBOUND", "enabled": True},
                {"interface": "eth1", "direction": "INBOUND", "enabled": True},
            ],
            "internal_networks": ["10.0.0.0/24"],
        },
    )
    assert updated.status_code == 200


def test_heartbeat_partial_update_preserves_sensor_configuration(tmp_path: Any) -> None:
    for repository in (MemoryRepository(), SQLiteRepository(tmp_path / "sensors.sqlite")):
        repository.upsert_sensor(
            {
                "sensor_id": "sensor-a",
                "config_version": 7,
                "capture_sources": [{"interface": "eth0", "enabled": True}],
            }
        )

        updated = repository.update_sensor_heartbeat(
            "sensor-a",
            {
                "last_heartbeat_at": "2026-07-30T20:00:00+00:00",
                "observed_interfaces": [{"name": "eth1", "mac_address": None}],
            },
        )

        assert updated is not None
        assert updated["config_version"] == 7
        assert updated["capture_sources"] == [{"interface": "eth0", "enabled": True}]
        assert updated["observed_interfaces"] == [{"name": "eth1", "mac_address": None}]


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
                {
                    "interface": "eth0",
                    "direction": "INBOUND",
                    "bpf_filter": "udp",
                    "enabled": True,
                    "store_pcap": True,
                }
            ],
            "internal_networks": ["192.0.2.17/24"],
        },
    )
    assert updated.status_code == 200
    assert updated.json()["config_version"] == 2
    assert updated.json()["internal_networks"] == ["192.0.2.0/24"]
    assert updated.json()["capture_sources"][0]["store_pcap"] is True

    stale = api.put(
        f"/api/v1/sensors/{sensor_id}/configuration",
        json={
            "config_version": 1,
            "capture_sources": updated.json()["capture_sources"],
            "internal_networks": updated.json()["internal_networks"],
        },
    )
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "CONFIG_VERSION_CONFLICT"
    polled = api.get(f"/api/v1/sensors/{sensor_id}/agent-config", headers={"X-Sensor-Token": token})
    assert polled.json()["config_version"] == 2
    assert polled.json()["capture_sources"][0]["store_pcap"] is True


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


def test_sensor_pcap_upload_is_authenticated_idempotent_listed_and_downloadable() -> None:
    api, _ = api_and_repo()
    sensor_id, token = enroll_and_claim(api)
    filename = "eth0-000001.pcap"
    segment_id = hashlib.sha256(f"{sensor_id}\0{filename}".encode()).hexdigest()
    capture = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    path = f"/api/v1/sensors/{sensor_id}/pcap-segments/{segment_id}"

    assert api.put(path, params={"filename": filename}, content=capture).status_code == 401
    invalid = api.put(
        path,
        params={"filename": "../capture.pcap"},
        content=capture,
        headers={"X-Sensor-Token": token, "content-type": "application/vnd.tcpdump.pcap"},
    )
    assert invalid.status_code == 422

    length_mismatch = api.put(
        path,
        params={"filename": filename},
        content=capture,
        headers={
            "X-Sensor-Token": token,
            "content-type": "application/vnd.tcpdump.pcap",
            "content-length": str(len(capture) + 1),
        },
    )
    assert length_mismatch.status_code == 400

    uploaded = api.put(
        path,
        params={"filename": filename},
        content=capture,
        headers={"X-Sensor-Token": token, "content-type": "application/vnd.tcpdump.pcap"},
    )
    assert uploaded.status_code == 201
    assert uploaded.json()["segment_id"] == segment_id
    assert uploaded.json()["sensor_id"] == sensor_id
    assert uploaded.json()["filename"] == "eth0-000001.pcap"
    assert uploaded.json()["size_bytes"] == len(capture)

    duplicate = api.put(
        path,
        params={"filename": filename},
        content=capture,
        headers={"X-Sensor-Token": token, "content-type": "application/vnd.tcpdump.pcap"},
    )
    assert duplicate.status_code == 201
    assert duplicate.json()["segment_id"] == segment_id
    assert duplicate.json()["id"] == segment_id

    listed = api.get(f"/api/v1/sensor-pcaps?sensor_id={sensor_id}")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1
    assert listed.json()["items"][0]["id"] == segment_id
    assert "object_key" not in listed.json()["items"][0]

    downloaded = api.get(f"/api/v1/sensor-pcaps/{segment_id}/download")
    assert downloaded.status_code == 200
    assert downloaded.content == capture
    assert downloaded.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert downloaded.headers["content-disposition"] == 'attachment; filename="eth0-000001.pcap"'
    assert downloaded.headers["x-content-type-options"] == "nosniff"


def test_sqlite_sensor_pcap_survives_repository_restart(tmp_path: Any) -> None:
    path = tmp_path / "sensor-pcaps.sqlite"
    metadata = {
        "id": "segment-a",
        "sensor_id": "sensor-a",
        "filename": "eth0.pcap",
        "size_bytes": 4,
        "sha256": "digest",
        "uploaded_at": "2026-08-01T00:00:00+00:00",
    }
    first = SQLiteRepository(path)
    first.save_sensor_pcap(metadata, b"pcap")
    first.close()

    reopened = SQLiteRepository(path)
    assert reopened.list_sensor_pcaps() == [metadata]
    assert reopened.get_sensor_pcap("segment-a") == (metadata, b"pcap")
    reopened.close()


def test_sensor_configuration_exposes_active_analysis_pcap_jobs() -> None:
    api, repo = api_and_repo()
    sensor_id, token = enroll_and_claim(api)
    repo.save_job(
        {
            "id": "job-a",
            "mode": "LIVE",
            "status": "CAPTURING",
            "sensor_ids": [sensor_id],
            "start_time": "2026-08-01T00:00:00+00:00",
            "end_time": "2026-08-01T01:00:00+00:00",
            "capture": {"store_pcap": True},
        }
    )
    response = api.get(
        f"/api/v1/sensors/{sensor_id}/agent-config",
        headers={"X-Sensor-Token": token},
    )
    assert response.status_code == 200
    assert response.json()["config_poll_interval_seconds"] == 1
    assert response.json()["capture_jobs"] == [
        {
            "job_id": "job-a",
            "start_time": "2026-08-01T00:00:00+00:00",
            "end_time": "2026-08-01T01:00:00+00:00",
            "store_pcap": True,
        }
    ]


def test_sensor_pcap_upload_is_linked_to_assigned_analysis_job() -> None:
    api, repo = api_and_repo()
    sensor_id, token = enroll_and_claim(api)
    repo.save_job(
        {
            "id": "job-a",
            "mode": "LIVE",
            "status": "UPLOADING",
            "sensor_ids": [sensor_id],
            "capture": {"store_pcap": True},
        }
    )
    filename = "job-a--eth0-outbound-000001.pcap"
    segment_id = hashlib.sha256(f"{sensor_id}\0{filename}".encode()).hexdigest()
    capture = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    path = f"/api/v1/sensors/{sensor_id}/pcap-segments/{segment_id}"
    headers = {"X-Sensor-Token": token, "content-type": "application/vnd.tcpdump.pcap"}
    rejected = api.put(
        path,
        params={"filename": filename, "analysis_job_id": "other"},
        content=capture,
        headers=headers,
    )
    assert rejected.status_code == 422
    uploaded = api.put(
        path,
        params={"filename": filename, "analysis_job_id": "job-a"},
        content=capture,
        headers=headers,
    )
    assert uploaded.status_code == 201
    assert uploaded.json()["analysis_job_id"] == "job-a"
    assert api.get("/api/v1/sensor-pcaps").json()["items"][0]["analysis_job_id"] == "job-a"

    other = {
        **repo.list_sensor_pcaps()[0],
        "id": "other-segment",
        "analysis_job_id": "job-b",
        "filename": "job-b--eth0-outbound-000001.pcap",
        "uploaded_at": "2026-08-01T02:00:00+00:00",
    }
    repo.save_sensor_pcap(other, capture)
    filtered = api.get("/api/v1/sensor-pcaps?analysis_job_id=job-a&page_size=1")
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
    assert filtered.json()["items"][0]["analysis_job_id"] == "job-a"
