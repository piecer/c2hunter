from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.storage import MemoryFlowStore

START = datetime(2026, 7, 20, tzinfo=UTC)
AGENT_TOKEN = "durable-test-token"
AGENT_HEADERS = {"X-Sensor-Token": AGENT_TOKEN}


class QueueStub:
    def __init__(self) -> None:
        self.jobs: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []
        self.acked: list[str] = []

    def ready(self) -> bool:
        return True

    def enqueue(self, job: dict[str, Any]) -> None:
        self.jobs.append(job)

    def claim_result(self, timeout: int = 0) -> dict[str, Any] | None:
        del timeout
        return self.results.pop(0) if self.results else None

    def ack_result(self, receipt: str) -> None:
        self.acked.append(receipt)

    def recover(self) -> int:
        return 0


def sensor() -> dict[str, object]:
    return {
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
    }


def register_sensor(client: TestClient) -> None:
    repository = client.app.state.repository
    repository.upsert_sensor({"sensor_id": "s1"})
    repository.save_sensor_credential(
        {"sensor_id": "s1", "token_hash": hashlib.sha256(AGENT_TOKEN.encode()).hexdigest()}
    )
    response = client.post("/api/v1/sensors/register", json=sensor(), headers=AGENT_HEADERS)
    assert response.status_code == 201


def flow(second: int = 1) -> dict[str, object]:
    return {
        "sensor_id": "s1",
        "timestamp": (START + timedelta(seconds=second)).isoformat(),
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.1",
        "source_port": 50000,
        "destination_port": 443,
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "packet_count": 1,
        "total_bytes": 60,
    }


def job_payload() -> dict[str, object]:
    return {
        "name": "stored dataset",
        "idempotency_key": "job-1",
        "sensor_ids": ["s1"],
        "mode": "HISTORICAL",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(minutes=1)).isoformat(),
        "capture": {"directions": ["OUTBOUND"]},
        "analysis": {"periodicity_min_samples": 3, "minimum_candidate_score": 0},
        "internal_networks": ["10.0.0.0/8"],
    }


def test_flow_batch_is_persisted_and_batch_id_is_deduplicated() -> None:
    store = MemoryFlowStore()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            MemoryRepository(),
            flow_store=store,
            queue=QueueStub(),
        )
    )
    register_sensor(client)
    body = {"batch_id": "batch-1", "records": [flow()]}

    first = client.post("/api/v1/sensors/s1/flow-batches", json=body, headers=AGENT_HEADERS)
    second = client.post("/api/v1/sensors/s1/flow-batches", json=body, headers=AGENT_HEADERS)

    assert first.status_code == 202
    assert first.json() == {"batch_id": "batch-1", "accepted": True, "record_count": 1}
    assert second.json() == {"batch_id": "batch-1", "accepted": False, "record_count": 1}
    assert store.record_count == 1


def test_job_references_stored_immutable_snapshot_and_is_enqueued() -> None:
    store = MemoryFlowStore()
    queue = QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            MemoryRepository(),
            flow_store=store,
            queue=queue,
        )
    )
    register_sensor(client)
    client.post(
        "/api/v1/sensors/s1/flow-batches",
        json={"batch_id": "batch-1", "records": [flow()]},
        headers=AGENT_HEADERS,
    )

    response = client.post("/api/v1/analysis-jobs", json=job_payload())

    assert response.status_code == 201
    assert response.json()["status"] == "ANALYZING"
    assert len(queue.jobs) == 1
    queued = queue.jobs[0]
    assert queued["id"] == response.json()["id"]
    assert queued["payload"]["dataset_id"] == response.json()["dataset_id"]
    assert len(queued["payload"]["flow_records"]) == 1
    assert queued["payload"]["flow_records"][0]["destination_ip"] == "203.0.113.1"
    store.ingest_batch("s1", "later", [flow(2)])
    assert len(queued["payload"]["flow_records"]) == 1


def test_live_job_waits_for_capture_end_before_enqueuing_analysis() -> None:
    queue = QueueStub()
    repository = MemoryRepository()
    app = create_app(
        Settings(
            environment="test",
            inline_flow_records_enabled=False,
            flow_ingestion_grace_seconds=60,
        ),
        repository,
        flow_store=MemoryFlowStore(),
        queue=queue,
    )
    api = TestClient(app)
    register_sensor(api)
    payload = job_payload()
    payload.update(
        {
            "mode": "LIVE",
            "start_time": datetime.now(UTC).isoformat(),
            "end_time": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
        }
    )

    created = api.post("/api/v1/analysis-jobs", json=payload)

    assert created.status_code == 201
    assert created.json()["status"] == "CAPTURING"
    assert queue.jobs == []
    job = repository.get_job(created.json()["id"])
    assert job is not None
    job["end_time"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    repository.save_job(job)
    assert app.state.process_due_live_jobs_once() is True
    assert queue.jobs == []
    uploading = repository.get_job(job["id"])
    assert uploading is not None
    assert uploading["status"] == "UPLOADING"
    uploading["end_time"] = (datetime.now(UTC) - timedelta(seconds=61)).isoformat()
    repository.save_job(uploading)
    assert app.state.process_due_live_jobs_once() is True
    assert len(queue.jobs) == 1
    updated = repository.get_job(job["id"])
    assert updated is not None
    assert updated["status"] == "ANALYZING"


def test_controller_persists_worker_result_before_ack() -> None:
    store = MemoryFlowStore()
    queue = QueueStub()
    repository = MemoryRepository()
    app = create_app(
        Settings(environment="test", inline_flow_records_enabled=False),
        repository,
        flow_store=store,
        queue=queue,
    )
    client = TestClient(app)
    register_sensor(client)
    client.post(
        "/api/v1/sensors/s1/flow-batches",
        json={"batch_id": "batch-1", "records": [flow()]},
        headers=AGENT_HEADERS,
    )
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    queue.results.append(
        {
            "receipt": "result-receipt",
            "job_id": job["id"],
            "status": "COMPLETED",
            "result": {"candidates": [{"candidate_ip": "203.0.113.1", "score": 88}]},
        }
    )

    assert app.state.process_results_once() is True
    assert repository.get_job(job["id"])["status"] == "COMPLETED"  # type: ignore[index]
    assert repository.get_candidates(job["id"])[0]["candidate_ip"] == "203.0.113.1"
    assert queue.acked == ["result-receipt"]


def test_operational_app_rejects_inline_flow_records() -> None:
    client = TestClient(
        create_app(
            Settings(environment="production", inline_flow_records_enabled=False),
            MemoryRepository(),
            flow_store=MemoryFlowStore(),
            queue=QueueStub(),
        )
    )
    register_sensor(client)
    request = job_payload()
    request["flow_records"] = [flow()]
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "INLINE_FLOWS_DISABLED"
