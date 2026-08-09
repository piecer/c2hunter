from pathlib import Path

from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.ai_queueing import (
    MemoryAIAnalysisTaskQueue,
    MemoryAIAnalysisWorkerQueue,
)
from c2hunter_controller.ai_worker import AIAnalysisWorker
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
