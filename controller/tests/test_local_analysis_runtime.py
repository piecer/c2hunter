from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_durable_pipeline import AGENT_HEADERS, flow, job_payload, register_sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.local_analysis_runtime import LocalWorkerQueue, result_releases_inflight
from c2hunter_controller.repositories import SQLiteRepository


def test_local_worker_bridge_buffers_started_event_and_terminal_result() -> None:
    bridge = LocalWorkerQueue()

    bridge.publish_event(
        {
            "job_id": "job-1",
            "status": "EVENT",
            "event": "ANALYSIS_STARTED",
        }
    )
    bridge.complete("receipt-1", {"job_id": "job-1", "status": "COMPLETED"})

    assert bridge.results.qsize() == 2


def test_local_worker_start_event_does_not_release_inflight_job() -> None:
    assert result_releases_inflight({"status": "EVENT", "event": "ANALYSIS_STARTED"}) is False
    assert (
        result_releases_inflight({"status": "EVENT", "event": "ANALYSIS_DELIVERY_SUPERSEDED"})
        is True
    )
    assert result_releases_inflight({"status": "COMPLETED"}) is True
    assert result_releases_inflight({"status": "ERROR"}) is True


def test_live_job_is_processed_by_owned_worker(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    repo = SQLiteRepository(tmp_path / "jobs.sqlite3")
    app = create_app(
        Settings(
            environment="test", inline_flow_records_enabled=False, flow_ingestion_grace_seconds=0
        ),
        repo,
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    with TestClient(app) as client:
        register_sensor(client)
        now = datetime.now(UTC)
        body = job_payload()
        body.update(
            mode="LIVE",
            start_time=(now - timedelta(seconds=1)).isoformat(),
            end_time=(now + timedelta(seconds=1)).isoformat(),
        )
        body["analysis"] = {"module": "network_anomaly"}
        created = client.post("/api/v1/analysis-jobs", json=body)
        assert created.status_code == 201, created.text
        job = created.json()
        assert job["status"] == "CAPTURING"
        record = {**flow(), "timestamp": now.isoformat()}
        ingested = client.post(
            "/api/v1/sensors/s1/flow-batches",
            headers=AGENT_HEADERS,
            json={"batch_id": "live-worker", "records": [record]},
        )
        assert ingested.status_code == 202, ingested.text
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            result = client.get(f"/api/v1/analysis-jobs/{job['id']}").json()
            if result["status"] in {"COMPLETED", "FAILED"}:
                break
            time.sleep(0.05)
        assert result["status"] == "COMPLETED", result
        assert result["dataset_id"]
        assert result["network_anomaly"]["summary"]["scanned_records"] == 1
        assert result["network_anomaly"]["version"] == "network-pattern-report-v1"
        assert result["network_anomaly"]["summary"]["flow_count"] == 1
        assert result["network_anomaly"]["summary"]["verdict"] == "insufficient_evidence"
        assert result["network_anomaly"]["flows"] == []
        assert result["network_anomaly"]["issues"] == []
        assert len(repo.get_job(job["id"])["flow_records"]) == 1
    assert not app.state.local_analysis_runtime.thread.is_alive()


@pytest.mark.parametrize(
    "case", ["valid", "invalid", "worker_error", "cancelled", "cancel_running"]
)
def test_startup_recovers_authoritative_payload_only(tmp_path, monkeypatch, case):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    from c2hunter_controller.queueing import MemoryControllerQueue
    from c2hunter_controller.storage import MemoryFlowStore

    repo = SQLiteRepository(tmp_path / "jobs.sqlite3")
    original_queue = MemoryControllerQueue()
    first = create_app(
        Settings(environment="test", inline_flow_records_enabled=False),
        repo,
        queue=original_queue,
        flow_store=MemoryFlowStore(),
    )
    client = TestClient(first)
    register_sensor(client)
    assert (
        client.post(
            "/api/v1/sensors/s1/flow-batches",
            headers=AGENT_HEADERS,
            json={"batch_id": "saved", "records": [flow()]},
        ).status_code
        == 202
    )
    body = job_payload()
    body["analysis"] = {"module": "network_anomaly"}
    response = client.post("/api/v1/analysis-jobs", json=body)
    assert response.status_code == 201, response.text
    job = response.json()
    assert job["status"] == "ANALYZING"
    if case == "invalid":
        stored = repo.get_job(job["id"])
        stored["dataset_id"] = None
        repo.save_job(stored)
    if case == "cancelled":
        assert (
            client.post(
                f"/api/v1/analysis-jobs/{job['id']}/cancel", json={"reason": "test"}
            ).status_code
            == 200
        )
    if case == "worker_error":

        def fail(payload):
            raise ValueError("detector test failure")

        monkeypatch.setattr("c2hunter_worker.analysis.execute_analysis", fail)
    from threading import Event

    from c2hunter_worker.analysis import execute_analysis

    started, release = Event(), Event()
    if case == "cancel_running":

        def blocked(payload):
            started.set()
            assert release.wait(3), "test did not release worker"
            return execute_analysis(payload)

        monkeypatch.setattr("c2hunter_worker.analysis.execute_analysis", blocked)
    recovered = create_app(
        Settings(environment="test"),
        repo,
        local_analysis_worker_health_path=tmp_path / "worker.json",
    )
    with TestClient(recovered) as running:
        if case == "cancel_running":
            assert started.wait(2)
            # The API remains responsive while real worker execution is held.
            assert (
                running.post(
                    f"/api/v1/analysis-jobs/{job['id']}/cancel", json={"reason": "test"}
                ).status_code
                == 200
            )
            release.set()
            deadline = time.monotonic() + 3
            while recovered.state.local_analysis_runtime.inflight and time.monotonic() < deadline:
                time.sleep(0.05)
            assert not recovered.state.local_analysis_runtime.inflight
        result = job
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline:
            result = running.get(f"/api/v1/analysis-jobs/{job['id']}").json()
            if result["status"] in {"COMPLETED", "FAILED", "CANCELLED"}:
                break
            time.sleep(0.05)
        assert (
            result["status"]
            == {
                "valid": "COMPLETED",
                "invalid": "FAILED",
                "worker_error": "FAILED",
                "cancelled": "CANCELLED",
                "cancel_running": "CANCELLED",
            }[case]
        )
        if case == "valid":
            assert result["dataset_id"] == job["dataset_id"]
            assert result["network_anomaly"]["summary"]["scanned_records"] == 1
        elif case not in {"cancelled", "cancel_running"}:
            assert result["error"]
    assert not recovered.state.local_analysis_runtime.thread.is_alive()
