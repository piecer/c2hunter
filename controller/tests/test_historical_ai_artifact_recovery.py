"""Generated descendants coexist with deterministic worker drafts, never mask corruption."""

from copy import deepcopy
from uuid import UUID, uuid5

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller._baseline_storage import BaselineStorageError
from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
from c2hunter_controller.ai_worker import AIAnalysisWorker
from tests.test_baseline_http_routes import headers
from tests.test_historical_ai_access_metadata import inject
from tests.test_historical_ai_api import api
from tests.test_historical_ai_execution import RecordingGateway, admitted, forbidden
from tests.test_historical_ai_execution import repository as _repository_fixture

repository = _repository_fixture


def interrupted(repository, monkeypatch, *, missing):
    run = admitted(repository)
    method = "save_ai_artifact" if missing else "save_ai_run"
    original = getattr(repository, method)
    writes = []
    fired = []

    def fail(value):
        if (missing and len(writes) == 1) or (not missing and value["status"] == "COMPLETED"):
            fired.append(value["id"])
            raise BaselineStorageError()
        writes.append(value["id"])
        return original(value)

    monkeypatch.setattr(repository, method, fail)
    gateway = RecordingGateway()
    queue = MemoryAIAnalysisWorkerQueue(
        [
            {"ai_run_id": run["id"], "receipt": "interrupted"},
            {"ai_run_id": run["id"], "receipt": "recovery"},
        ]
    )
    worker = AIAnalysisWorker(queue, ai.AIAnalysisService(repository, gateway))
    assert not worker.run_once(timeout=0)
    assert len(fired) == 1 and queue.acked == []
    assert repository.get_ai_run(run["id"])["status"] == "VALIDATING"
    monkeypatch.setattr(repository, method, original)
    assessment = repository.list_ai_assessments(run["id"])[0]
    assert len(repository.list_ai_artifacts(assessment["id"])) == (1 if missing else 3)
    return run, assessment, gateway, queue, worker


def regenerate(repository, assessment):
    client, _ = api(repository)
    try:
        response = client.post(
            f"/api/v1/ai-assessments/{assessment['id']}/artifacts/regenerate",
            headers=headers("analyst"),
        )
        assert response.status_code == 201, response.text
        assert response.json()["total"] == 3
        return response.json()["items"]
    finally:
        client.close()


def test_missing_deterministic_drafts_restore_without_replacing_generated_reviews(
    repository, monkeypatch
):
    run, assessment, gateway, queue, worker = interrupted(repository, monkeypatch, missing=True)
    draft = repository.list_ai_artifacts(assessment["id"])[0]
    generated = regenerate(repository, assessment)
    client, _ = api(repository)
    try:
        for artifact, action in ((draft, "approve"), (generated[0], "reject")):
            response = client.post(
                f"/api/v1/ai-artifacts/{artifact['id']}/{action}",
                json={"note": "preserve this analyst decision"},
                headers=headers("analyst"),
            )
            assert response.status_code == 200, response.text
    finally:
        client.close()
    retained = {row["id"]: row for row in repository.list_ai_artifacts(assessment["id"])}
    assert len(retained) == 4
    assert retained[draft["id"]]["approved_status"] == "APPROVED"
    assert retained[generated[0]["id"]]["approved_status"] == "REJECTED"
    for name in ("get_job", "get_candidates", "read_historical_source", "get_baseline_scope"):
        monkeypatch.setattr(repository, name, forbidden)
    assert worker.run_once(timeout=0)
    after = {row["id"]: row for row in repository.list_ai_artifacts(assessment["id"])}
    assert len(after) == 6
    assert {key: after[key] for key in retained} == retained
    deterministic = {
        str(uuid5(UUID(assessment["id"]), kind))
        for kind in ("SPLUNK_HUNT", "SPLUNK_DETECTION", "MISP_DRAFT")
    }
    assert set(after) == deterministic | {row["id"] for row in generated}
    assert len(gateway.calls) == 1
    assert queue.acked == ["recovery"]
    assert repository.get_ai_run(run["id"])["status"] == "COMPLETED"


@pytest.mark.parametrize("origin", ["worker", "regenerated"])
@pytest.mark.parametrize("fault", ["content", "owner"])
def test_corrupt_artifact_still_blocks_redelivery_without_ack(
    repository, monkeypatch, origin, fault
):
    run, assessment, gateway, queue, worker = interrupted(repository, monkeypatch, missing=False)
    drafts = repository.list_ai_artifacts(assessment["id"])
    generated = regenerate(repository, assessment)
    corrupted = deepcopy((drafts if origin == "worker" else generated)[0])
    if fault == "content":
        corrupted["content"] = {"not": "authorized content"}
    else:
        corrupted["analysis_job_id"] = "another-job"
    inject(repository, "T", corrupted)
    assert not worker.run_once(timeout=0)
    assert worker.last_error == "BASELINE_STORAGE_UNAVAILABLE"
    assert queue.acked == []
    assert len(gateway.calls) == 1
    assert repository.get_ai_run(run["id"])["status"] == "VALIDATING"
