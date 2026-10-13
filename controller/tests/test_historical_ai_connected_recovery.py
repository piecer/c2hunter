"""Read-only candidate review probes; real producer/repositories/ASGI/worker."""

import json

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_ai_sql as sql
from c2hunter_controller._baseline_storage import BaselineStorageError
from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_http_routes import headers
from tests.test_historical_ai_api import api
from tests.test_historical_ai_execution import RecordingGateway, admitted
from tests.test_historical_ai_storage import prepared


@pytest.mark.parametrize("adapter", ["memory", "sqlite"])
@pytest.mark.parametrize("regenerate", [False, True], ids=["control", "http-regenerate"])
def test_redelivery_coexists_with_http_regeneration(tmp_path, monkeypatch, adapter, regenerate):
    repo = (
        MemoryRepository() if adapter == "memory" else SQLiteRepository(tmp_path / "redelivery.db")
    )
    client = None
    try:
        run = admitted(repo)
        original = repo.save_ai_run
        fired = []

        def before_completion(value):
            if value["status"] == "COMPLETED" and not fired:
                fired.append(value["id"])
                raise BaselineStorageError()
            return original(value)

        monkeypatch.setattr(repo, "save_ai_run", before_completion)
        gateway = RecordingGateway()
        queue = MemoryAIAnalysisWorkerQueue(
            [
                {"ai_run_id": run["id"], "receipt": "initial"},
                {"ai_run_id": run["id"], "receipt": "redelivery"},
            ]
        )
        worker = AIAnalysisWorker(queue, ai.AIAnalysisService(repo, gateway))
        assert worker.run_once(timeout=0) is False
        assert fired == [run["id"]] and queue.acked == []
        assert repo.get_ai_run(run["id"])["status"] == "VALIDATING"
        assessment = repo.list_ai_assessments(run["id"])[0]
        assert len(repo.list_ai_artifacts(assessment["id"])) == 3
        monkeypatch.setattr(repo, "save_ai_run", original)
        status = None
        if regenerate:
            client, _ = api(repo)
            response = client.post(
                f"/api/v1/ai-assessments/{assessment['id']}/artifacts/regenerate",
                headers=headers("analyst"),
            )
            status = response.status_code
            assert status == 201, response.text
            assert response.json()["total"] == 3
        count = len(repo.list_ai_artifacts(assessment["id"]))
        second = worker.run_once(timeout=0)
        observation = {
            "adapter": adapter,
            "regenerate": regenerate,
            "fault_fired": fired,
            "regenerate_http_status": status,
            "artifacts": count,
            "second_worker_result": second,
            "run_status": repo.get_ai_run(run["id"])["status"],
            "worker_error": worker.last_error,
            "gateway_calls": len(gateway.calls),
            "acked": queue.acked,
        }
        (tmp_path / f"redelivery-{adapter}-{regenerate}.json").write_text(
            json.dumps(observation, indent=2) + "\n"
        )
        print(observation)
        assert second, (
            "Valid HTTP-generated artifacts prevent saved result redelivery from completing"
        )
        assert repo.get_ai_run(run["id"])["status"] == "COMPLETED"
        assert len(gateway.calls) == 1
        assert queue.acked == ["redelivery"]
    finally:
        if client is not None:
            client.close()
        repo.close()


@pytest.mark.parametrize("uncertain", [False, True], ids=["control", "readback-fails"])
def test_http_replay_recovers_committed_but_never_enqueued_run(tmp_path, monkeypatch, uncertain):
    db = tmp_path / "admission.db"
    repo = SQLiteRepository(db)
    request, _, _ = prepared(repo)
    client, queue = api(repo)
    path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    original = sql.confirm_run
    fired = []

    def confirm(expected, connect, *, postgres):
        def failed_observer():
            fired.append(expected["id"])
            raise OSError("injected fresh-connection outage after writer commit")

        return original(expected, failed_observer if uncertain else connect, postgres=postgres)

    monkeypatch.setattr(sql, "confirm_run", confirm)
    response = client.post(path, json=request.payload.to_mapping(), headers=headers("analyst"))
    assert response.status_code == (503 if uncertain else 201), response.text
    if uncertain:
        assert len(fired) == 1 and queue.depth() == 0
        assert repo._historical_quarantined
    client.close()
    repo.close()
    monkeypatch.setattr(sql, "confirm_run", original)
    reopened = SQLiteRepository(db)
    # Preserve the same task queue: no queue failure or queue reset is involved.
    from fastapi.testclient import TestClient

    from c2hunter_controller.app import create_app
    from tests.test_baseline_http_routes import settings

    retry = TestClient(
        create_app(
            settings().model_copy(update={"ai_analysis_enabled": True}),
            reopened,
            ai_gateway=ai.FakeGateway(),
            ai_task_queue=queue,
        )
    )
    try:
        saved = reopened.get_ai_run_by_request(
            request.analysis_job_id, request.payload.idempotency_key
        )
        assert saved is not None and saved["status"] == "QUEUED"
        replay = retry.post(path, json=request.payload.to_mapping(), headers=headers("analyst"))
        assert replay.status_code == 200, replay.text
        observation = {
            "uncertain": uncertain,
            "initial_http_status": response.status_code,
            "fault_fired": fired,
            "replay_http_status": replay.status_code,
            "run_status": replay.json()["status"],
            "durable_run_id": saved["id"],
            "queue_depth": queue.depth(),
            "queued_ids": queue.run_ids,
        }
        (tmp_path / f"admission-replay-{uncertain}.json").write_text(
            json.dumps(observation, indent=2) + "\n"
        )
        print(observation)
        assert queue.depth() == 1, (
            "HTTP returns successful QUEUED replay without ever scheduling its durable run"
        )
    finally:
        retry.close()
        reopened.close()
