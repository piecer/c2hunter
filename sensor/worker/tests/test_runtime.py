from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from c2hunter_worker.analysis import execute_analysis
from c2hunter_worker.health import check_health
from c2hunter_worker.queue import RedisQueue
from c2hunter_worker.runtime import Worker


def test_redis_result_messages_are_published_fifo_for_rpop_consumers() -> None:
    class Client:
        def __init__(self) -> None:
            self.commands: list[tuple[str, str]] = []

        def lpush(self, key: str, value: str) -> None:
            self.commands.append((key, value))

        def eval(self, script: str, *_args: Any) -> None:
            assert "LPUSH" in script
            assert "RPUSH" not in script

    queue = RedisQueue.__new__(RedisQueue)
    queue.client = Client()
    queue.results_key = "results"
    queue.processing_key = "processing"
    queue.leases_key = "leases"

    queue.publish_event({"status": "EVENT", "event": "ANALYSIS_STARTED"})
    queue.complete("receipt", {"status": "COMPLETED"})

    assert json.loads(queue.client.commands[0][1])["event"] == "ANALYSIS_STARTED"


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


def test_execute_analysis_preserves_operational_syn_status_below_c2_threshold() -> None:
    result = execute_analysis(
        {
            "dataset_id": "dataset-1",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"periodicity_min_samples": 5, "minimum_candidate_score": 60},
            "flow_records": [
                {
                    "sensor_id": "sensor-a",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "203.0.113.40",
                    "source_port": 50000,
                    "destination_port": 443,
                    "protocol": "TCP",
                    "direction": "OUTBOUND",
                    "packet_count": 4,
                    "total_bytes": 240,
                    "duration_seconds": 12,
                    "tcp_flags": {"syn": 4},
                    "tcp_flags_observed": True,
                    "tcp_syn_count": 4,
                    "tcp_syn_only_count": 4,
                    "tcp_syn_only_observations": [
                        {"offset_us": 0, "sequence": 12345},
                        {"offset_us": 2_000_000, "sequence": 12345},
                        {"offset_us": 6_000_000, "sequence": 12345},
                        {"offset_us": 12_000_000, "sequence": 12345},
                    ],
                }
            ],
        }
    )

    assert len(result["candidates"]) == 1
    assert result["candidates"][0]["candidate_kind"] == "COMMUNICATION_STATUS"
    assert result["candidates"][0]["score"] == 0


def test_execute_analysis_loads_operator_configured_custom_detectors(
    tmp_path: Path, monkeypatch: Any
) -> None:
    plugin_directory = tmp_path / "detectors"
    plugin_directory.mkdir()
    (plugin_directory / "operator_rule.py").write_text(
        "from c2hunter_analysis.domain import Evidence\n"
        "DETECTOR_NAME = 'operator-rule'\n"
        "DETECTOR_VERSION = '2.0.0'\n"
        "def analyze(context):\n"
        "    return [Evidence('203.0.113.77', 'COMMON_DESTINATION', 'ignored', '0', "
        "5, 5, 'operator rule match')]\n"
    )
    monkeypatch.setenv("C2HUNTER_CUSTOM_DETECTORS_DIR", str(plugin_directory))

    result = execute_analysis(
        {
            "dataset_id": "dataset-custom",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"periodicity_min_samples": 3, "minimum_candidate_score": 0},
            "flow_records": [],
        }
    )

    assert result["candidates"][0]["candidate_ip"] == "203.0.113.77"
    finding = result["candidates"][0]["evidence"][0]
    assert finding["detector"] == "operator-rule"
    assert finding["version"] == "2.0.0"


def test_execute_analysis_treats_whitespace_detector_directory_as_unset(
    tmp_path: Path, monkeypatch: Any
) -> None:
    (tmp_path / "cwd_rule.py").write_text(
        "from c2hunter_analysis.domain import Evidence\n"
        "DETECTOR_NAME = 'cwd-worker-rule'\n"
        "def analyze(context):\n"
        "    return [Evidence('203.0.113.78', 'COMMON_DESTINATION', 'ignored', '0', "
        "5, 5, 'must not load')]\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("C2HUNTER_CUSTOM_DETECTORS_DIR", " \t ")

    result = execute_analysis(
        {
            "dataset_id": "dataset-whitespace-worker",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"periodicity_min_samples": 3, "minimum_candidate_score": 0},
            "flow_records": [],
        }
    )

    assert result == {"candidates": []}


def test_execute_analysis_suppresses_allowlisted_candidate() -> None:
    flows = [
        {
            "sensor_id": "sensor-a",
            "timestamp": f"2026-01-01T00:00:0{index}+00:00",
            "source_ip": f"10.0.0.{index}",
            "destination_ip": "203.0.113.9",
            "source_port": 50000 + index,
            "destination_port": 53,
            "protocol": "UDP",
            "direction": "OUTBOUND",
        }
        for index in range(1, 4)
    ]

    result = execute_analysis(
        {
            "dataset_id": "dataset-allowlist",
            "start_time": "2026-01-01T00:00:00+00:00",
            "end_time": "2026-01-01T01:00:00+00:00",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {
                "minimum_distinct_clients": 3,
                "periodicity_min_samples": 3,
                "minimum_candidate_score": 0,
            },
            "allowlist": [
                {
                    "type": "IP",
                    "value": "203.0.113.9",
                    "description": "trusted DNS resolver",
                    "enabled": True,
                }
            ],
            "flow_records": flows,
        }
    )

    assert result == {"candidates": []}


def test_execute_analysis_applies_detector_weights_from_job_snapshot() -> None:
    flows = [
        {
            "sensor_id": "sensor-a",
            "timestamp": f"2026-01-01T00:00:0{index}+00:00",
            "source_ip": f"10.0.0.{index}",
            "destination_ip": "203.0.113.9",
            "source_port": 50000 + index,
            "destination_port": 443,
            "protocol": "TCP",
            "direction": "OUTBOUND",
        }
        for index in range(1, 4)
    ]
    base = {
        "dataset_id": "dataset-weights",
        "start_time": "2026-01-01T00:00:00+00:00",
        "end_time": "2026-01-01T01:00:00+00:00",
        "sensor_ids": ["sensor-a"],
        "internal_networks": ["10.0.0.0/8"],
        "analysis": {
            "minimum_distinct_clients": 3,
            "periodicity_min_samples": 5,
            "minimum_candidate_score": 1,
        },
        "flow_records": flows,
    }

    assert len(execute_analysis(base)["candidates"]) == 1
    tuned = execute_analysis(
        {
            **base,
            "analysis": {
                **base["analysis"],
                "detector_weights": {"common_destination": 0.0},
            },
        }
    )
    assert tuned == {"candidates": []}


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
        self.events: list[dict[str, Any]] = []
        self.acked: list[str] = []

    def receive(self, timeout: int) -> dict[str, Any] | None:
        del timeout
        return self.jobs.pop(0) if self.jobs else None

    def complete(self, receipt: str, result: dict[str, Any]) -> None:
        self.results.append(result)
        self.acked.append(receipt)

    def publish_event(self, event: dict[str, Any]) -> None:
        self.events.append(event)

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

    def claim_analysis(
        self,
        job_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> tuple[str, str | None]:
        del job_id, attempt, lease_token, lease_seconds
        return ("CLAIMED", "analysis-claim")

    def renew_analysis(
        self, job_id: str, *, claim_token: str, lease_seconds: int
    ) -> bool:
        del job_id, claim_token, lease_seconds
        return True

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
    assert queue.events == [
        {
            "job_id": "job-1",
            "status": "EVENT",
            "event": "ANALYSIS_STARTED",
            "occurred_at": queue.events[0]["occurred_at"],
        }
    ]
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
        {
            "job_id": "job-2",
            "status": "ERROR",
            "error_code": "ANALYSIS_EXECUTION_FAILED",
            "error": "worker analysis failed",
        }
    ]
    assert "detector failed" not in str(queue.results)
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


def test_worker_skips_superseded_preparation_delivery(tmp_path: Path) -> None:
    loader = LoaderStub(
        {
            "status": "ANALYZING",
            "processing": {
                "phase": "ANALYSIS_ENQUEUE_PENDING",
                "attempt": 2,
                "lease_token": "current-token",
            },
        }
    )
    executed = False

    def execute(_: dict[str, Any]) -> dict[str, Any]:
        nonlocal executed
        executed = True
        return {}

    worker = Worker(
        queue=QueueStub([]),
        execute=execute,
        health_path=tmp_path / "health.json",
        payload_loader=loader,
    )
    result = worker._execute_job(
        {
            "id": "job-stale",
            "preparation_attempt": 1,
            "preparation_lease_token": "stale-token",
        }
    )

    assert executed is False
    assert result["status"] == "EVENT"
    assert result["event"] == "ANALYSIS_DELIVERY_SUPERSEDED"


def test_worker_atomically_claims_a_preparation_generation_once(tmp_path: Path) -> None:
    class ClaimingLoader(LoaderStub):
        claimed = False

        def claim_analysis(
            self,
            job_id: str,
            *,
            attempt: int,
            lease_token: str,
            lease_seconds: int,
        ) -> tuple[str, str | None]:
            del job_id, attempt, lease_token, lease_seconds
            if self.claimed:
                return ("ACTIVE", None)
            self.claimed = True
            self.payload["processing"]["phase"] = "ANALYSIS_CLAIMED"
            return ("CLAIMED", "analysis-claim")

    loader = ClaimingLoader(
        {
            "status": "ANALYZING",
            "processing": {"phase": "ANALYSIS_QUEUED", "attempt": 1},
        }
    )
    executions = 0

    def execute(_: dict[str, Any]) -> dict[str, Any]:
        nonlocal executions
        executions += 1
        return {}

    worker = Worker(
        queue=QueueStub([]),
        execute=execute,
        health_path=tmp_path / "health.json",
        payload_loader=loader,
    )
    envelope = {
        "id": "job-once",
        "preparation_attempt": 1,
        "preparation_lease_token": "token",
    }

    assert worker._execute_job(envelope)["status"] == "COMPLETED"
    assert worker._execute_job(envelope)["status"] == "RETRY"
    assert executions == 1


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


def test_worker_progress_publish_failure_does_not_replace_analysis_result(
    tmp_path: Path,
) -> None:
    stopped = threading.Event()

    class ProgressFailingQueue(QueueStub):
        def publish_event(self, event: dict[str, Any]) -> None:
            del event
            raise RuntimeError("progress channel unavailable")

        def complete(self, receipt: str, result: dict[str, Any]) -> None:
            super().complete(receipt, result)
            stopped.set()

    queue = ProgressFailingQueue(
        [{"id": "job-progress", "receipt": "claim-progress", "payload": {}}]
    )

    def execute(_: dict[str, Any]) -> dict[str, Any]:
        stopped.set()
        return {"verdict": "done"}

    worker = Worker(queue=queue, execute=execute, health_path=tmp_path / "health.json")
    worker.run(stopped)

    assert queue.results == [
        {"job_id": "job-progress", "status": "COMPLETED", "result": {"verdict": "done"}}
    ]
