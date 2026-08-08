import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from c2hunter_analysis.scoring import DEFAULT_DETECTOR_WEIGHTS
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.jobs import JobState, StateMachine
from c2hunter_controller.repositories import MemoryRepository

START = datetime(2026, 7, 20, tzinfo=UTC)


def api(repository: MemoryRepository | None = None) -> TestClient:
    repository = repository or MemoryRepository()
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


def test_analysis_request_normalizes_and_validates_detector_weights() -> None:
    client = api()
    request = payload(key="weights")
    analysis = request["analysis"]
    assert isinstance(analysis, dict)
    analysis["detector_weights"] = {"common_destination": 0.25}

    response = client.post("/api/v1/analysis-jobs", json=request)

    assert response.status_code == 201
    weights = response.json()["analysis"]["detector_weights"]
    assert weights["common_destination"] == 0.25
    assert weights["analyst_payload_signature"] == 1.0
    assert weights["tcp_session_quality"] == 1.0
    assert set(weights) == set(DEFAULT_DETECTOR_WEIGHTS)
    assert len(weights) == len(DEFAULT_DETECTOR_WEIGHTS)

    for key, value in (("unknown_detector", 1.0), ("common_destination", 2.01)):
        invalid = payload(key=f"invalid-{key}-{value}")
        invalid_analysis = invalid["analysis"]
        assert isinstance(invalid_analysis, dict)
        invalid_analysis["detector_weights"] = {key: value}
        assert client.post("/api/v1/analysis-jobs", json=invalid).status_code == 422


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


def test_inline_analysis_uses_the_allowlist_snapshot_captured_with_the_job() -> None:
    class ChangingAllowlistRepository(MemoryRepository):
        allowlist_reads = 0

        def list_allowlist(self) -> list[dict[str, object]]:
            self.allowlist_reads += 1
            if self.allowlist_reads == 1:
                return []
            return [
                {
                    "type": "IP",
                    "value": "203.0.113.77",
                    "description": "added after the job snapshot",
                    "enabled": True,
                }
            ]

    client = api(ChangingAllowlistRepository())

    response = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="snapshot-consistency"),
    )

    assert response.status_code == 201
    candidates = client.get(f"/api/v1/analysis-jobs/{response.json()['id']}/candidates").json()
    assert candidates["total"] == 1


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
        json={
            "idempotency_key": "rerun",
            "minimum_candidate_score": 70,
            "detector_weights": {"common_destination": 0.25},
        },
    )
    assert rerun.status_code == 201
    assert rerun.json()["id"] != completed["id"]
    assert rerun.json()["dataset_id"] == completed["dataset_id"]
    assert rerun.json()["parent_job_id"] == completed["id"]
    assert rerun.json()["analysis"]["detector_weights"]["common_destination"] == 0.25
    assert rerun.json()["analysis"]["detector_weights"]["periodic_beacon"] == 1.0


def test_detector_weight_presets_enforce_single_default_and_apply_to_new_jobs() -> None:
    repository = MemoryRepository()
    client = api(repository)
    first = client.post(
        "/api/v1/detector-weight-presets",
        json={
            "name": "Quiet shared services",
            "description": "Reduce broad infrastructure signals",
            "detector_weights": {"common_destination": 0.25},
            "set_as_default": True,
        },
    )
    assert first.status_code == 201
    assert first.json()["is_default"] is True
    assert first.json()["detector_weights"]["common_destination"] == 0.25
    assert first.json()["detector_weights"]["periodic_beacon"] == 1.0

    second = client.post(
        "/api/v1/detector-weight-presets",
        json={
            "name": "Beacon priority",
            "detector_weights": {"periodic_beacon": 1.5},
            "set_as_default": True,
        },
    )
    assert second.status_code == 201
    presets = client.get("/api/v1/detector-weight-presets").json()["items"]
    assert sum(preset["is_default"] for preset in presets) == 1
    assert (
        next(preset for preset in presets if preset["id"] == first.json()["id"])["is_default"]
        is False
    )

    created = client.post("/api/v1/analysis-jobs", json=payload(key="preset-default"))
    assert created.status_code == 201
    assert created.json()["analysis"]["detector_weights"]["periodic_beacon"] == 1.5

    explicit = payload(key="preset-explicit")
    assert isinstance(explicit["analysis"], dict)
    explicit["analysis"]["detector_weights"] = {"periodic_beacon": 0.5}
    created = client.post("/api/v1/analysis-jobs", json=explicit)
    assert created.status_code == 201
    assert created.json()["analysis"]["detector_weights"]["periodic_beacon"] == 0.5


def test_detector_weight_preset_update_and_delete_default() -> None:
    client = api()
    created = client.post(
        "/api/v1/detector-weight-presets",
        json={"name": "Temporary", "detector_weights": {}, "set_as_default": True},
    ).json()
    updated = client.patch(
        f"/api/v1/detector-weight-presets/{created['id']}",
        json={"name": "Reusable", "detector_weights": {"protocol_similarity": 0.4}},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Reusable"
    assert updated.json()["detector_weights"]["protocol_similarity"] == 0.4
    deleted = client.delete(f"/api/v1/detector-weight-presets/{created['id']}")
    assert deleted.status_code == 200
    assert client.get("/api/v1/detector-weight-presets").json()["items"] == []


def test_detector_weight_preset_update_rejects_null_resource_fields() -> None:
    client = api()
    created = client.post(
        "/api/v1/detector-weight-presets",
        json={"name": "Protected", "description": "Valid", "detector_weights": {}},
    ).json()

    for field in ("name", "description", "detector_weights"):
        response = client.patch(
            f"/api/v1/detector-weight-presets/{created['id']}", json={field: None}
        )
        assert response.status_code == 422

    preset = client.get("/api/v1/detector-weight-presets").json()["items"][0]
    assert preset["name"] == "Protected"
    assert preset["description"] == "Valid"
    assert preset["detector_weights"]["common_destination"] == 1.0


def test_detector_weight_preset_rejects_blank_names_and_empty_updates() -> None:
    client = api()
    created = client.post(
        "/api/v1/detector-weight-presets",
        json={"name": "   ", "detector_weights": {}},
    )
    assert created.status_code == 422

    preset = client.post(
        "/api/v1/detector-weight-presets",
        json={"name": "Valid", "detector_weights": {}},
    ).json()
    empty_update = client.patch(f"/api/v1/detector-weight-presets/{preset['id']}", json={})
    assert empty_update.status_code == 422
    assert (
        client.patch(
            f"/api/v1/detector-weight-presets/{preset['id']}", json={"name": "  "}
        ).status_code
        == 422
    )


def test_default_preset_creation_is_one_atomic_repository_operation() -> None:
    class AtomicCreationRepository(MemoryRepository):
        def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, object] | None:
            raise AssertionError(f"split default transition for {preset_id}")

    repository = AtomicCreationRepository()
    repository.save_detector_weight_preset(
        {"id": "first", "name": "First", "detector_weights": {}, "is_default": True}
    )
    client = api(repository)

    response = client.post(
        "/api/v1/detector-weight-presets",
        json={"name": "Second", "detector_weights": {}, "set_as_default": True},
    )

    assert response.status_code == 201
    defaults = [
        preset["name"]
        for preset in repository.list_detector_weight_presets()
        if preset["is_default"]
    ]
    assert defaults == ["Second"]


def test_detector_weight_preset_update_and_default_switch_are_atomic() -> None:
    class CoordinatedRepository(MemoryRepository):
        armed = False
        default_switched = threading.Event()

        def save_detector_weight_preset(self, preset: dict[str, object]) -> dict[str, object]:
            if self.armed and preset["id"] == "preset-first":
                assert self.default_switched.wait(timeout=2)
            return super().save_detector_weight_preset(preset)

        def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, object] | None:
            result = super().set_default_detector_weight_preset(preset_id)
            if self.armed and preset_id == "preset-second":
                self.default_switched.set()
            return result

    repository = CoordinatedRepository()
    repository.save_detector_weight_preset(
        {"id": "preset-first", "name": "First", "detector_weights": {}, "is_default": True}
    )
    repository.save_detector_weight_preset(
        {"id": "preset-second", "name": "Second", "detector_weights": {}, "is_default": False}
    )
    repository.armed = True
    client = api(repository)

    with ThreadPoolExecutor(max_workers=2) as executor:
        rename = executor.submit(
            client.patch,
            "/api/v1/detector-weight-presets/preset-first",
            json={"name": "Renamed"},
        )
        switch = executor.submit(
            client.patch,
            "/api/v1/detector-weight-presets/preset-second",
            json={"set_as_default": True},
        )
    assert rename.result().status_code == 200
    assert switch.result().status_code == 200
    presets = client.get("/api/v1/detector-weight-presets").json()["items"]
    assert [preset["id"] for preset in presets if preset["is_default"]] == ["preset-second"]
