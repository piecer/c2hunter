"""LIVE capture snapshot survives queue loss and reaches the real async worker."""

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from test_durable_pipeline import AGENT_HEADERS, job_payload, register_sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.queueing import MemoryControllerQueue
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.storage import MemoryFlowStore


def test_live_saved_capture_recovers_with_empty_volatile_store(tmp_path, monkeypatch):
    root = Path(__file__).parents[2]
    monkeypatch.syspath_prepend(str(root / "sensor/worker/src"))
    monkeypatch.syspath_prepend(str(root / "analysis/tests"))
    from test_network_anomaly import frame, records

    database = tmp_path / "live-restart.sqlite3"
    repository = SQLiteRepository(database)
    lost_queue = MemoryControllerQueue()
    app = create_app(
        Settings(
            environment="test", inline_flow_records_enabled=False, flow_ingestion_grace_seconds=0
        ),
        repository,
        queue=lost_queue,
        flow_store=MemoryFlowStore(),
    )
    client = TestClient(app)
    register_sensor(client)
    now = datetime.now(UTC)
    body = job_payload()
    body.update(
        mode="LIVE",
        start_time=(now - timedelta(seconds=10)).isoformat(),
        end_time=(now + timedelta(minutes=1)).isoformat(),
        analysis={"module": "network_anomaly"},
    )
    posted = client.post("/api/v1/analysis-jobs", json=body)
    assert posted.status_code == 201, posted.text
    identity = posted.json()["id"]
    assert posted.json()["status"] == "CAPTURING"
    parsed = records(frame(), frame())
    for index, record in enumerate(parsed):
        record["timestamp"] = (now - timedelta(seconds=5 - index)).isoformat()
    ingested = client.post(
        "/api/v1/sensors/s1/flow-batches",
        headers=AGENT_HEADERS,
        json={"batch_id": "restart-live", "records": parsed},
    )
    assert ingested.status_code == 202, ingested.text
    job = repository.get_job(identity)
    job["end_time"] = (now - timedelta(seconds=1)).isoformat()
    repository.save_job(job)
    app.state.process_due_live_jobs_once()
    app.state.process_due_live_jobs_once()
    snapshot = repository.get_job(identity)
    assert snapshot["status"] == "ANALYZING"
    assert snapshot["flow_count"] == 2
    assert len(lost_queue.jobs) == 1

    # A new repository connection, queue and empty flow store model process loss.
    recovered = create_app(
        Settings(environment="test"),
        SQLiteRepository(database),
        flow_store=MemoryFlowStore(),
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    with TestClient(recovered) as running:
        deadline = time.monotonic() + 5
        while True:
            result = running.get(f"/api/v1/analysis-jobs/{identity}").json()
            if result["status"] in {"COMPLETED", "FAILED"} or time.monotonic() >= deadline:
                break
            time.sleep(0.01)
        assert result["status"] == "COMPLETED", result
        assert result["dataset_id"] == snapshot["dataset_id"]
        report = result["network_anomaly"]
        assert report["summary"]["scanned_records"] == 2
        assert report["summary"]["verdict"] == "anomaly_observed"
        assert [(item["pattern"], item["event_count"]) for item in report["issues"]] == [
            ("syn_retransmissions", 1)
        ]
        assert result["candidate_count"] == 0
        assert "flow_records" not in result
    assert not recovered.state.local_analysis_runtime.thread.is_alive()
    persisted = SQLiteRepository(database).get_job(identity)
    assert persisted["network_anomaly"] == report
    assert persisted["flow_records"] == snapshot["flow_records"]
