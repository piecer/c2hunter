"""Real parser → LIVE dataset → actual worker → durable report → HTTP GET."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.storage import MemoryFlowStore


def test_live_network_worker_persists_real_grouped_report(tmp_path, monkeypatch):
    root = Path(__file__).parents[2]
    monkeypatch.syspath_prepend(str(root / "sensor/worker/src"))
    monkeypatch.syspath_prepend(str(root / "analysis/tests"))
    from c2hunter_worker.analysis import execute_analysis
    from test_durable_pipeline import AGENT_HEADERS, QueueStub, job_payload, register_sensor
    from test_network_anomaly import frame, records

    path = tmp_path / "live.sqlite3"
    repo = SQLiteRepository(path)
    queue = QueueStub()
    app = create_app(
        Settings(
            environment="test", inline_flow_records_enabled=False, flow_ingestion_grace_seconds=0
        ),
        repo,
        flow_store=MemoryFlowStore(),
        queue=queue,
    )
    client = TestClient(app)
    register_sensor(client)
    now = datetime.now(UTC)
    payload = job_payload()
    payload.update(
        mode="LIVE",
        start_time=(now - timedelta(seconds=10)).isoformat(),
        end_time=(now + timedelta(minutes=1)).isoformat(),
        analysis={"module": "network_anomaly"},
    )
    response = client.post("/api/v1/analysis-jobs", json=payload)
    assert response.status_code == 201, response.text
    job_id = response.json()["id"]
    assert response.json()["status"] == "CAPTURING"
    assert queue.jobs == []
    parsed = records(frame(), frame())
    for index, record in enumerate(parsed):
        record["timestamp"] = (now - timedelta(seconds=5 - index)).isoformat()
    uploaded = client.post(
        "/api/v1/sensors/s1/flow-batches",
        json={"batch_id": "live-pattern", "records": parsed},
        headers=AGENT_HEADERS,
    )
    assert uploaded.status_code == 202, uploaded.text
    job = repo.get_job(job_id)
    job["end_time"] = (now - timedelta(seconds=1)).isoformat()
    repo.save_job(job)
    app.state.process_due_live_jobs_once()
    app.state.process_due_live_jobs_once()
    assert queue.jobs == [{"id": job_id}]
    result = execute_analysis(repo.get_job(job_id))
    report = result["network_anomaly"]
    assert report["version"] == "network-pattern-report-v1"
    assert report["summary"]["flow_count"] == 1
    assert report["summary"]["verdict"] == "anomaly_observed"
    assert report["flows"] == []
    assert [(issue["pattern"], issue["event_count"]) for issue in report["issues"]] == [
        ("syn_retransmissions", 1)
    ]
    queue.results.append(
        {
            "receipt": "live-pattern-result",
            "job_id": job_id,
            "status": "COMPLETED",
            "result": result,
        }
    )
    assert app.state.process_results_once() is True
    assert queue.acked == ["live-pattern-result"]
    # Reopen the actual SQLite path, rather than trusting the in-process job object.
    reopened = SQLiteRepository(path)
    stored_client = TestClient(create_app(Settings(environment="test"), reopened))
    stored = stored_client.get(f"/api/v1/analysis-jobs/{job_id}").json()
    assert stored["status"] == "COMPLETED"
    assert stored["candidate_count"] == 0
    assert stored["network_anomaly"] == report
    assert "flow_records" not in stored
