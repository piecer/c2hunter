"""Memory LIVE capture continuity must not become an empty successful dataset."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_durable_pipeline import AGENT_HEADERS, job_payload, register_sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.storage import MemoryFlowStore


@pytest.mark.parametrize("status", ["CAPTURING", "UPLOADING"])
@pytest.mark.parametrize("module", ["network_anomaly", "c2"])
def test_restart_fails_unsaved_live_capture(tmp_path, monkeypatch, status, module):
    root = Path(__file__).parents[2]
    monkeypatch.syspath_prepend(str(root / "sensor/worker/src"))
    monkeypatch.syspath_prepend(str(root / "analysis/tests"))
    from test_network_anomaly import frame, records

    database = tmp_path / "jobs.sqlite3"
    settings = Settings(
        environment="test", inline_flow_records_enabled=False, flow_ingestion_grace_seconds=0
    )
    repo = SQLiteRepository(database)
    first = create_app(
        settings,
        repo,
        flow_store=MemoryFlowStore(),
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    with TestClient(first) as client:
        register_sensor(client)
        now = datetime.now(UTC)
        body = job_payload()
        body.update(
            mode="LIVE",
            start_time=(now - timedelta(seconds=10)).isoformat(),
            end_time=(now + timedelta(minutes=5)).isoformat(),
            analysis={"module": module},
        )
        body["capture"]["max_packets"] = 10
        created = client.post("/api/v1/analysis-jobs", json=body)
        assert created.status_code == 201, created.text
        identity = created.json()["id"]
        parsed = records(frame(), frame())
        for record in parsed:
            record["timestamp"] = (now - timedelta(seconds=5)).isoformat()
        response = client.post(
            "/api/v1/sensors/s1/flow-batches",
            headers=AGENT_HEADERS,
            json={"batch_id": "accepted-before-crash", "records": parsed},
        )
        assert response.status_code == 202
        assert response.json()["record_count"] == 2
        saved = repo.get_job(identity)
        saved["status"] = status
        repo.save_job(saved)
        sensor = repo.get_sensor("s1")
    # Make finalization due only after the first coordinator has stopped, so
    # startup recovery races neither the test setup nor a legitimate snapshot.
    saved["end_time"] = (now - timedelta(seconds=1)).isoformat()
    repo.save_job(saved)
    repo.connection.close()

    fresh_repo = SQLiteRepository(database)
    restarted = create_app(
        settings,
        fresh_repo,
        flow_store=MemoryFlowStore(),
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    with TestClient(restarted) as client:
        result = client.get(f"/api/v1/analysis-jobs/{identity}").json()
        assert result["status"] == "FAILED", result
        assert result["error_code"] == "LIVE_CAPTURE_RESTART_INCOMPLETE"
        assert "restart" in result["error"].lower()
        assert "may have been lost" in result["error"]
        assert result["completed_at"]
        assert "flow_records" not in result
        assert "volatile_capture" not in result
        assert fresh_repo.get_sensor("s1") == sensor
        # Late raw batches are sensor-scoped; acceptance cannot revive this job.
        assert (
            client.post(
                "/api/v1/sensors/s1/flow-batches",
                headers=AGENT_HEADERS,
                json={"batch_id": "late", "records": parsed},
            ).status_code
            == 202
        )
        restarted.state.process_due_live_jobs_once()
        heartbeat = client.post(
            "/api/v1/sensors/s1/heartbeat",
            headers=AGENT_HEADERS,
            json={
                "reported_at": now.isoformat(),
                "status": "ONLINE",
                "cpu_percent": 0,
                "memory_percent": 0,
                "disk_percent": 0,
                "active_job_ids": [],
                "received_packets": 2,
                "dropped_packets": 0,
                "pending_bytes": 0,
                "completed_capture_jobs": [{"job_id": identity, "stop_reason": "MAX_PACKETS"}],
            },
        )
        assert heartbeat.status_code == 200, heartbeat.text
        assert client.get(f"/api/v1/analysis-jobs/{identity}").json() == result
        assert fresh_repo.get_job(identity)["flow_records"] == saved["flow_records"]


def test_two_local_runtimes_cannot_own_one_sqlite_database(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    database = tmp_path / "jobs.sqlite3"
    first = create_app(
        Settings(environment="test"),
        SQLiteRepository(database),
        local_analysis_worker_health_path=tmp_path / "first.json",
    )
    second = create_app(
        Settings(environment="test"),
        SQLiteRepository(database),
        local_analysis_worker_health_path=tmp_path / "second.json",
    )
    with TestClient(first):
        with pytest.raises(RuntimeError, match="already owned"):
            with TestClient(second):
                pass


@pytest.mark.parametrize(
    "case", ["legacy", "foreign", "same_store", "cancelled", "completed", "durable_source"]
)
def test_restart_recovery_scope(tmp_path, monkeypatch, case):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    repo = SQLiteRepository(tmp_path / "jobs.sqlite3")
    store = MemoryFlowStore()
    settings = Settings(environment="test", inline_flow_records_enabled=False)
    first = create_app(
        settings,
        repo,
        flow_store=store,
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    with TestClient(first) as client:
        register_sensor(client)
        now = datetime.now(UTC)
        body = job_payload()
        body.update(
            mode="LIVE",
            start_time=now.isoformat(),
            end_time=(now + timedelta(minutes=5)).isoformat(),
        )
        result = client.post("/api/v1/analysis-jobs", json=body)
        assert result.status_code == 201, result.text
        job = repo.get_job(result.json()["id"])
        assert job["status"] == "CAPTURING"
    if case == "legacy":
        job.pop("volatile_capture")
    elif case == "foreign":
        job["volatile_capture"]["owner"] = "another-runtime"
    elif case in {"cancelled", "completed"}:
        job["status"] = case.upper()
    repo.save_job(job)
    from c2hunter_controller.storage import ClickHouseFlowStore

    # No I/O is needed for an active future capture: this checks adapter scope,
    # not ClickHouse durability. Any accidental snapshot call must fail the test.
    durable = ClickHouseFlowStore("http://unused.invalid")
    monkeypatch.setattr(durable, "_request", lambda *args: pytest.fail("unexpected durable I/O"))
    restarted = create_app(
        settings,
        SQLiteRepository(tmp_path / "jobs.sqlite3"),
        flow_store=(
            durable
            if case == "durable_source"
            else store
            if case == "same_store"
            else MemoryFlowStore()
        ),
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    if case in {"legacy", "foreign"}:
        with pytest.raises(RuntimeError, match="cannot establish ownership"):
            with TestClient(restarted):
                pass
        assert restarted.state.local_analysis_runtime.ownership_file is None
    else:
        with TestClient(restarted) as client:
            assert (
                client.get(f"/api/v1/analysis-jobs/{job['id']}").json()["status"] == job["status"]
            )
    assert repo.get_job(job["id"]) == job
