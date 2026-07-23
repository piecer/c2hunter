from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from c2hunter_worker.analysis import execute_analysis
from c2hunter_worker.health import check_health
from c2hunter_worker.runtime import Worker


def test_execute_analysis_runs_real_detector_pipeline() -> None:
    result = execute_analysis(
        {
            "dataset_id": "dataset-1",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"periodicity_min_samples": 3, "minimum_candidate_score": 0},
            "flow_records": [],
        }
    )
    assert result == {"candidates": []}


def test_healthcheck_accepts_live_degraded_worker_but_rejects_stopped(
    tmp_path: Path,
) -> None:
    health_path = tmp_path / "health.json"
    health_path.write_text(
        json.dumps(
            {
                "status": "DEGRADED",
                "pid": 1,
                "updated_at": "2026-01-01T00:00:00+00:00",
            }
        )
    )
    assert check_health(
        health_path, max_age_seconds=30, now="2026-01-01T00:00:10+00:00"
    )
    health_path.write_text(
        json.dumps(
            {"status": "STOPPED", "pid": 1, "updated_at": "2026-01-01T00:00:10+00:00"}
        )
    )
    assert not check_health(
        health_path, max_age_seconds=30, now="2026-01-01T00:00:11+00:00"
    )


class QueueStub:
    def __init__(self, jobs: list[dict[str, Any]]) -> None:
        self.jobs = jobs
        self.results: list[dict[str, Any]] = []
        self.acked: list[str] = []

    def receive(self, timeout: int) -> dict[str, Any] | None:
        del timeout
        return self.jobs.pop(0) if self.jobs else None

    def complete(self, receipt: str, result: dict[str, Any]) -> None:
        self.results.append(result)
        self.acked.append(receipt)

    def close(self) -> None:
        pass


class LoaderStub:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload
        self.loaded: list[str] = []
        self.closed = False

    def load(self, job_id: str) -> dict[str, Any]:
        self.loaded.append(job_id)
        return dict(self.payload)

    def close(self) -> None:
        self.closed = True


def test_worker_executes_analysis_job_and_writes_live_health(tmp_path: Path) -> None:
    queue = QueueStub([{"id": "job-1", "receipt": "claim-1", "payload": {"value": 4}}])
    stopped = threading.Event()

    def execute(payload: dict[str, Any]) -> dict[str, Any]:
        stopped.set()
        return {"doubled": payload["value"] * 2}

    health_path = tmp_path / "health.json"
    worker = Worker(queue=queue, execute=execute, health_path=health_path)
    worker.run(stopped)

    assert queue.results == [
        {"job_id": "job-1", "status": "COMPLETED", "result": {"doubled": 8}}
    ]
    assert queue.acked == ["claim-1"]
    health = json.loads(health_path.read_text())
    assert health["status"] == "STOPPED"
    assert health["processed_jobs"] == 1


def test_worker_records_failed_job_without_claiming_success(tmp_path: Path) -> None:
    queue = QueueStub([{"id": "job-2", "receipt": "claim-2", "payload": {}}])
    stopped = threading.Event()

    def fail(_: dict[str, Any]) -> dict[str, Any]:
        stopped.set()
        raise RuntimeError("detector failed")

    worker = Worker(queue=queue, execute=fail, health_path=tmp_path / "health.json")
    worker.run(stopped)

    assert queue.results == [
        {"job_id": "job-2", "status": "ERROR", "error": "detector failed"}
    ]
    assert queue.acked == ["claim-2"]


def test_worker_loads_referenced_payload_outside_redis(tmp_path: Path) -> None:
    queue = QueueStub([{"id": "job-ref", "receipt": "claim-ref"}])
    loader = LoaderStub({"value": 5})
    stopped = threading.Event()

    def execute(payload: dict[str, Any]) -> dict[str, Any]:
        stopped.set()
        return {"doubled": payload["value"] * 2}

    worker = Worker(
        queue=queue,
        execute=execute,
        health_path=tmp_path / "health.json",
        payload_loader=loader,
    )
    worker.run(stopped)

    assert loader.loaded == ["job-ref"]
    assert loader.closed is True
    assert queue.results == [
        {"job_id": "job-ref", "status": "COMPLETED", "result": {"doubled": 10}}
    ]


def test_worker_does_not_ack_when_durable_result_publish_fails(tmp_path: Path) -> None:
    class FailingQueue(QueueStub):
        def complete(self, receipt: str, result: dict[str, Any]) -> None:
            del receipt, result
            stopped.set()
            raise RuntimeError("redis unavailable")

    stopped = threading.Event()
    queue = FailingQueue([{"id": "job-3", "receipt": "claim-3", "payload": {}}])
    worker = Worker(
        queue=queue, execute=lambda _: {}, health_path=tmp_path / "health.json"
    )
    worker.run(stopped)
    assert queue.acked == []
