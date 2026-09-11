"""Network AI admission/publication regressions; model transport is entirely fake."""

import json
from copy import deepcopy

import pytest
from fastapi.testclient import TestClient
from test_network_ai import create, issue, response, setup

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.local_ai_runtime import LocalAITaskQueue
from c2hunter_controller.repositories import SQLiteRepository


def test_stale_local_capability_cannot_authorize_new_remote_destination():
    repository, service, transport = setup()
    ready_calls = []
    service.gateway.ready = lambda: ready_calls.append(True) or True
    settings = Settings(environment="test", ai_analysis_enabled=True, ai_model_provider="ollama")
    queue = LocalAITaskQueue()
    client = TestClient(
        create_app(settings, repository, ai_gateway=service.gateway, ai_task_queue=queue)
    )
    assert client.get("/api/v1/ai-capabilities").json()["remote"] is False
    # Settings changed after the UI obtained its capability snapshot.
    settings.ai_model_base_url = "https://new-model.example/v1"
    ready_calls.clear()
    result = client.post(
        "/api/v1/analysis-jobs/network-job/ai-runs",
        json={"idempotency_key": "stale", "analysis_kind": "NETWORK_ANOMALY"},
    )
    assert result.status_code == 409, result.text
    assert result.json()["error"]["code"] == "AI_REMOTE_CONSENT_REQUIRED"
    assert ready_calls == []  # Even a readiness request must not precede this rejection.
    assert transport.calls == []
    assert queue.depth() == 0
    assert repository.list_ai_runs("network-job") == []


def test_api_queue_capacity_rejects_without_orphan_queued_run(tmp_path):
    path = tmp_path / "capacity.sqlite3"
    repository, service, transport = setup(SQLiteRepository(path))
    service.gateway.ready = lambda: True
    queue = LocalAITaskQueue()
    for index in range(32):
        queue.enqueue(f"occupied-{index}")
    client = TestClient(
        create_app(
            Settings(environment="test", ai_analysis_enabled=True),
            repository,
            ai_gateway=service.gateway,
            ai_task_queue=queue,
            local_ai_worker_enabled=True,
        )
    )  # Deliberately no lifespan: freeze the queue to test the admission boundary.
    result = client.post(
        "/api/v1/analysis-jobs/network-job/ai-runs",
        json={"idempotency_key": "overflow", "analysis_kind": "NETWORK_ANOMALY"},
    )
    assert result.status_code == 503, result.text
    assert result.json()["error"]["code"] == "AI_QUEUE_FULL"
    runs = SQLiteRepository(path).list_ai_runs("network-job")
    assert len(runs) == 1
    assert runs[0]["status"] == "CANCELLED"
    assert "network_interpretation" not in runs[0]
    assert runs[0]["id"] not in queue.run_ids
    assert queue.depth() == 32
    assert transport.calls == []


@pytest.mark.parametrize("language", ["ko", "en"])
def test_nonempty_cited_interpretation_preserves_unknowns_and_excludes_raw_data(language):
    repository, service, transport = setup(language=language)
    job = repository.get_job("network-job")
    job["network_anomaly"]["issues"] = [issue()]
    job["network_anomaly"]["raw_packet_hex"] = "RAW_PACKET_SENTINEL"
    job["network_anomaly"]["flows"] = [{"payload": "RAW_PACKET_SENTINEL"}]
    repository.save_job(job)
    original = deepcopy(repository.get_job("network-job"))
    transport.output = response(language, ["NP-001"])
    run, _ = create(service, language)
    final = service.execute(run["id"])
    assert final["status"] == "COMPLETED", final
    assert final["network_interpretation"] == transport.output
    wire = json.dumps(transport.calls[0][2]["body"])
    assert "RAW_PACKET_SENTINEL" not in wire
    assert "SECRET" not in wire
    assert run["network_input"]["summary"]["verdict"] == "insufficient_evidence"
    assert repository.get_job("network-job") == original
    assert repository.list_ai_assessments(run["id"]) == []


@pytest.mark.parametrize("invalid_kind", ["extra-field", "citation"])
def test_invalid_model_response_does_not_leak_raw_output_through_run_api(invalid_kind, caplog):
    repository, service, transport = setup()
    transport.output = (
        {**response(), "unexpected_payload": "MODEL_RAW_SECRET_SENTINEL"}
        if invalid_kind == "extra-field"
        else response(issue_ids=["MODEL_RAW_SECRET_SENTINEL"])
    )
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == "FAILED"
    assert final["error_code"] == "MODEL_OUTPUT_INVALID"
    assert "network_interpretation" not in final
    assert len(transport.calls) == 2
    assert "MODEL_RAW_SECRET_SENTINEL" not in json.dumps(transport.calls[1][2]["body"])
    client = TestClient(create_app(Settings(environment="test"), repository))
    public = client.get("/api/v1/ai-runs/" + run["id"])
    assert public.status_code == 200
    assert "MODEL_RAW_SECRET_SENTINEL" not in public.text
    assert public.json()["error_message"] == "Model output failed validation."
    assert "MODEL_RAW_SECRET_SENTINEL" not in json.dumps(final)
    assert "MODEL_RAW_SECRET_SENTINEL" not in caplog.text


@pytest.mark.parametrize("kind", ["NETWORK_ANOMALY", "C2"])
@pytest.mark.parametrize(
    ("exception_type", "code", "message"),
    [
        (ValueError, "MODEL_OUTPUT_INVALID", "Model output failed validation."),
        (TimeoutError, "MODEL_TIMEOUT", "Model request timed out."),
        (RuntimeError, "AI_ANALYSIS_FAILED", "AI analysis failed."),
    ],
)
def test_provider_exception_text_is_not_persisted_or_published(
    kind, exception_type, code, message, caplog
):
    from test_ai_analysis import candidate, completed_job

    from c2hunter_controller.ai_analysis import AIAnalysisService

    repository, service, _ = setup()

    class FailingGateway:
        provider = "fake"
        model = "fixture"

        # Fake provider failure includes a credential-shaped marker; no network I/O.
        def assess(self, bundle):
            raise exception_type("Bearer CREDENTIAL_ECHO_SENTINEL rejected model payload")

        def interpret_network_cancellable(self, bundle, *, should_cancel):
            return self.assess(bundle)

    service = AIAnalysisService(repository, FailingGateway())
    if kind == "C2":
        repository.save_job(completed_job())
        repository.save_candidates("job-1", [candidate()])
        run, _ = service.create_run(
            analysis_job_id="job-1",
            idempotency_key="safe-error",
            candidate_limit=5,
            created_by="operator",
        )
    else:
        run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == "FAILED"
    assert final["error_code"] == code
    client = TestClient(create_app(Settings(environment="test"), repository))
    public = client.get("/api/v1/ai-runs/" + run["id"])
    assert public.status_code == 200
    assert "CREDENTIAL_ECHO_SENTINEL" not in public.text
    assert public.json()["error_message"] == message
    assert "CREDENTIAL_ECHO_SENTINEL" not in json.dumps(repository.get_ai_run(run["id"]))
    assert "CREDENTIAL_ECHO_SENTINEL" not in caplog.text
    assert repository.list_ai_assessments(run["id"]) == []
