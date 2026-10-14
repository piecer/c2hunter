import json
from pathlib import Path
from typing import Any, cast

import pytest
from prometheus_client import generate_latest

from c2hunter_controller._baseline_storage import BaselineStorageError
from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.ai_queueing import (
    MemoryAIAnalysisTaskQueue,
    MemoryAIAnalysisWorkerQueue,
)
from c2hunter_controller.ai_worker import AIAnalysisWorker, AIWorkerMetrics
from c2hunter_controller.historical_ai_storage import (
    HistoricalStorageError,
    HistoricalStorageOutcomeUnknown,
)
from c2hunter_controller.repositories import MemoryRepository


def candidate() -> dict[str, object]:
    return {
        "id": "candidate-1",
        "candidate_ip": "203.0.113.9",
        "score": 75,
        "evidence": [{"type": "PERIODIC_BEACON", "description": "Stable interval"}],
    }


def test_memory_task_queue_deduplicates_run_references() -> None:
    queue = MemoryAIAnalysisTaskQueue()

    queue.enqueue("run-1")
    queue.enqueue("run-1")

    assert queue.run_ids == ["run-1"]
    assert queue.depth() == 1


def test_worker_processes_reference_idempotently_and_acknowledges(tmp_path: Path) -> None:
    repository = MemoryRepository()
    repository.jobs["job-1"] = {"id": "job-1", "status": "COMPLETED"}
    repository.save_candidates("job-1", [candidate()])
    service = AIAnalysisService(repository, FakeGateway())
    run, _ = service.create_run(
        analysis_job_id="job-1",
        idempotency_key="worker-test",
        candidate_limit=5,
        created_by="analyst",
    )
    queue = MemoryAIAnalysisWorkerQueue(
        [
            {"ai_run_id": run["id"], "receipt": "receipt-1"},
            {"ai_run_id": run["id"], "receipt": "receipt-2"},
        ]
    )
    health_path = tmp_path / "ai-worker-health.json"
    worker = AIAnalysisWorker(queue, service, health_path=health_path)

    assert worker.run_once(timeout=0) is True
    assert worker.run_once(timeout=0) is True

    assert repository.get_ai_run(run["id"])["status"] == "COMPLETED"  # type: ignore[index]
    assert len(repository.list_ai_assessments(run["id"])) == 1
    assert queue.acked == ["receipt-1", "receipt-2"]
    assert '"processed_runs":2' in health_path.read_text(encoding="utf-8")


class FailedService:
    def execute(self, run_id: str) -> dict[str, str]:
        return {
            "id": run_id,
            "status": "FAILED",
            "error_code": "MODEL_OUTPUT_INVALID",
        }


def test_worker_exports_real_execution_failure_schema_and_queue_metrics() -> None:
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run-failed", "receipt": "receipt-1"}])
    metrics = AIWorkerMetrics(provider="fake", model="fake-v1")
    worker = AIAnalysisWorker(queue, FailedService(), metrics=metrics)  # type: ignore[arg-type]

    assert worker.run_once(timeout=0) is True
    exported = generate_latest(metrics.registry).decode()

    assert (
        'c2hunter_ai_inference_duration_seconds_count{model="fake-v1",'
        'provider="fake",status="FAILED"} 1.0'
    ) in exported
    assert 'c2hunter_ai_failures_total{reason="MODEL_OUTPUT_INVALID"} 1.0' in exported
    assert "c2hunter_ai_schema_invalid_total 1.0" in exported
    assert "c2hunter_ai_queue_waiting_depth 0.0" in exported
    assert "c2hunter_ai_queue_processing_depth 0.0" in exported


def assert_private_failure_then_recovery(
    error: Exception,
    expected_code: str,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    class RecoveringService:
        calls = 0

        def execute(self, run_id: str) -> dict[str, str]:
            self.calls += 1
            if self.calls == 1:
                raise error from ValueError("synthetic-private-cause")
            return {"id": run_id, "status": "COMPLETED"}

    queue = MemoryAIAnalysisWorkerQueue(
        [
            {"ai_run_id": "same-run", "receipt": "failed-delivery"},
            {"ai_run_id": "same-run", "receipt": "redelivery"},
        ]
    )
    service = RecoveringService()
    health_path = tmp_path / "health.json"
    worker = AIAnalysisWorker(queue, cast(AIAnalysisService, service), health_path=health_path)

    assert worker.run_once(timeout=0) is False
    assert service.calls == 1
    assert queue.acked == []
    assert worker.processed_runs == 0
    assert worker.last_error == expected_code
    failed_text = health_path.read_text()
    failed = json.loads(failed_text)
    assert failed["status"] == "DEGRADED"
    assert failed["last_error"] == expected_code
    assert failed["processed_runs"] == 0

    assert worker.run_once(timeout=0) is True
    assert service.calls == 2
    assert queue.acked == ["redelivery"]
    assert worker.processed_runs == 1
    assert worker.last_error is None
    recovered_text = health_path.read_text()
    recovered = json.loads(recovered_text)
    assert recovered["status"] == "RUNNING"
    assert recovered["last_error"] is None
    assert recovered["processed_runs"] == 1
    observed = (
        failed_text
        + recovered_text
        + caplog.text
        + generate_latest(worker.metrics.registry).decode()
    )
    assert "synthetic-private" not in observed


@pytest.mark.parametrize(
    "error_type", [BaselineStorageError, HistoricalStorageError, HistoricalStorageOutcomeUnknown]
)
def test_worker_preserves_safe_storage_code_without_exception_text(
    error_type: type[BaselineStorageError] | type[HistoricalStorageError],
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_stringification(self: Exception) -> str:
        raise AssertionError("exception text must not be inspected")

    monkeypatch.setattr(error_type, "__str__", forbidden_stringification)
    error = error_type()
    error.args = ("synthetic-private-arguments",)
    assert_private_failure_then_recovery(error, "BASELINE_STORAGE_UNAVAILABLE", tmp_path, caplog)


class UntrustedStorageCode(str):
    def __eq__(self, other: object) -> bool:
        raise AssertionError("untrusted code equality must not run")


@pytest.mark.parametrize(
    "error_type", [BaselineStorageError, HistoricalStorageError, HistoricalStorageOutcomeUnknown]
)
@pytest.mark.parametrize(
    "code",
    [
        pytest.param("BASELINE_BUSY", id="other-structured-code"),
        pytest.param("synthetic-private-code", id="private-code"),
        pytest.param("BASELINE_STORAGE_UNAVAILABLE:synthetic-private", id="suffix"),
        pytest.param("synthetic-private:BASELINE_STORAGE_UNAVAILABLE", id="prefix"),
        pytest.param(None, id="null"),
        pytest.param(7, id="integer"),
        pytest.param(["BASELINE_STORAGE_UNAVAILABLE"], id="list"),
        pytest.param(b"BASELINE_STORAGE_UNAVAILABLE", id="bytes"),
        pytest.param(UntrustedStorageCode("BASELINE_STORAGE_UNAVAILABLE"), id="string-subclass"),
    ],
)
def test_worker_rejects_untrusted_storage_codes(
    error_type: type[BaselineStorageError] | type[HistoricalStorageError],
    code: object,
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    error = error_type(cast(Any, code))
    error.args = ("synthetic-private-arguments",)
    assert_private_failure_then_recovery(error, "AI_WORKER_EXECUTION_FAILED", tmp_path, caplog)


class StorageCodeLookalike(ValueError):
    code = "BASELINE_STORAGE_UNAVAILABLE"


class UninspectableError(ValueError):
    @property
    def code(self) -> str:
        raise AssertionError("untyped error code must not be inspected")

    def __str__(self) -> str:
        raise AssertionError("untyped error text must not be inspected")


@pytest.mark.parametrize(
    "error_type", [ValueError, OSError, StorageCodeLookalike, UninspectableError]
)
def test_worker_does_not_classify_untyped_errors_by_message_or_code(
    error_type: type[Exception], tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    error = error_type("BASELINE_STORAGE_UNAVAILABLE synthetic-private-message")
    assert_private_failure_then_recovery(error, "AI_WORKER_EXECUTION_FAILED", tmp_path, caplog)
