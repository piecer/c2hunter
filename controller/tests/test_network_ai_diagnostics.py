"""Real gateway/service/storage path with deterministic local transport, no model I/O."""

import json
from copy import deepcopy
from pathlib import Path

import pytest
from test_network_ai import create, response, setup

from c2hunter_controller.repositories import SQLiteRepository


class ScriptedTransport:
    def __init__(self, *steps):
        self.steps = iter(steps)
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append(deepcopy(kwargs))
        step = next(self.steps)
        if isinstance(step, Exception):
            raise step
        return {"message": {"content": step}, "done_reason": "stop"}


def test_json_failure_persists_safe_diagnostic_after_one_repair(tmp_path, caplog):
    path = tmp_path / "diagnostic.sqlite3"
    repository, service, _ = setup(SQLiteRepository(path))
    original = deepcopy(repository.get_job("network-job"))
    raw = "한 Bearer MODEL_SECRET_SENTINEL {not-json"
    transport = ScriptedTransport(raw, raw)
    service.gateway.http = transport
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["error_code"] == "MODEL_OUTPUT_INVALID"
    assert final["failure_diagnostic"] == {
        "stage": "MODEL_OUTPUT",
        "type": "JSON_PARSE",
        "attempt_count": 2,
        "repair_count": 1,
        "output_bytes": len(raw.encode("utf-8")),
        "provider_finish_reason": "stop",
    }
    assert len(transport.calls) == 2
    assert "JSON_PARSE" in json.dumps(transport.calls[1]["body"])
    assert "MODEL_SECRET_SENTINEL" not in json.dumps(transport.calls)
    assert "MODEL_SECRET_SENTINEL" not in json.dumps(final)
    assert "MODEL_SECRET_SENTINEL" not in caplog.text
    reopened = SQLiteRepository(path)
    assert reopened.get_ai_run(run["id"])["failure_diagnostic"] == final["failure_diagnostic"]
    assert reopened.get_job("network-job") == original
    assert "network_interpretation" not in final


@pytest.mark.parametrize("category", ["SCHEMA", "INVALID_CITATION", "LANGUAGE"])
@pytest.mark.parametrize("repair_valid", [False, True])
def test_classified_repair_uses_same_final_validator(category, repair_valid, tmp_path, caplog):
    path = tmp_path / "classified.sqlite3"
    repository, service, _ = setup(SQLiteRepository(path))
    invalid = response()
    if category == "SCHEMA":
        del invalid["summary"]
        invalid["SECRET_DYNAMIC_KEY"] = {"password": "SECRET_REJECTED_VALUE"}
    elif category == "INVALID_CITATION":
        invalid = response(issue_ids=["SECRET_REJECTED_VALUE"])
    else:
        invalid = response("en")
    raw = json.dumps(invalid)
    transport = ScriptedTransport(raw, json.dumps(response()) if repair_valid else raw)
    service.gateway.http = transport
    original = deepcopy(repository.get_job("network-job"))
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == ("COMPLETED" if repair_valid else "FAILED")
    assert len(transport.calls) == 2
    assert category in transport.calls[1]["body"]["messages"][-2]["content"]
    if not repair_valid:
        assert final["failure_diagnostic"]["type"] == category
        assert final["failure_diagnostic"]["repair_count"] == 1
    assert "SECRET_" not in json.dumps(final)
    assert "SECRET_" not in json.dumps(transport.calls)
    assert "SECRET_" not in caplog.text
    reopened = SQLiteRepository(path)
    assert reopened.get_ai_run(run["id"]) == final
    assert reopened.get_job("network-job") == original


def test_source_projection_error_is_safe_and_never_calls_model():
    from test_network_ai import issue

    from c2hunter_controller.ai_analysis import AIAnalysisError

    repository, service, transport = setup()
    job = repository.get_job("network-job")
    job["network_anomaly"]["issues"] = [issue()]
    job["network_anomaly"]["issues"][0]["suspected_cause"] = {"SECRET_KEY": "SECRET_VALUE"}
    repository.save_job(job)
    with pytest.raises(AIAnalysisError) as error:
        create(service)
    assert str(error.value) == "Network report input failed validation."
    assert not transport.calls
    assert repository.list_ai_runs("network-job") == []

    from fastapi.testclient import TestClient

    from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    service.gateway.ready = lambda: True
    queue = MemoryAIAnalysisTaskQueue()
    client = TestClient(
        create_app(
            Settings(environment="test", ai_analysis_enabled=True),
            repository,
            ai_gateway=service.gateway,
            ai_task_queue=queue,
        )
    )
    rejected = client.post(
        "/api/v1/analysis-jobs/network-job/ai-runs",
        json={"idempotency_key": "unsafe-source", "analysis_kind": "NETWORK_ANOMALY"},
    )
    assert rejected.status_code == 409
    assert rejected.json()["error"]["code"] == "AI_RUN_NOT_ALLOWED"
    assert rejected.json()["error"]["message"] == "Network report input failed validation."
    assert "SECRET_" not in rejected.text
    assert not transport.calls
    assert not queue.run_ids
    assert repository.list_ai_runs("network-job") == []


@pytest.mark.parametrize("retries", [0, 1, 3])
@pytest.mark.parametrize("repair_valid", [False, True])
def test_transport_retries_do_not_multiply_completed_generations(retries, repair_valid):
    repository, service, _ = setup()
    service.gateway.retries = retries
    raw = "not-json"
    transport = ScriptedTransport(
        *[TimeoutError("SECRET_TIMEOUT") for _ in range(retries)],
        raw,
        *[OSError("SECRET_TRANSPORT") for _ in range(retries)],
        json.dumps(response()) if repair_valid else raw,
    )
    service.gateway.http = transport
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == ("COMPLETED" if repair_valid else "FAILED")
    assert len(transport.calls) == 2 * (retries + 1)
    if not repair_valid:
        assert final["failure_diagnostic"]["attempt_count"] == 2
    assert "SECRET_" not in json.dumps(final)


@pytest.mark.parametrize("after_invalid", [False, True])
@pytest.mark.parametrize(
    "failure,code,status",
    [
        (TimeoutError, "MODEL_TIMEOUT", "FAILED"),
        (OSError, "AI_ANALYSIS_FAILED", "FAILED"),
        (InterruptedError, None, "CANCELLED"),
        (RuntimeError, "AI_ANALYSIS_FAILED", "FAILED"),
    ],
)
def test_transport_failure_never_gets_model_output_diagnostic(after_invalid, failure, code, status):
    repository, service, _ = setup()
    service.gateway.retries = 1
    transport = ScriptedTransport(
        *(["not-json"] if after_invalid else []),
        failure("SECRET_EXCEPTION"),
        failure("SECRET_EXCEPTION"),
    )
    service.gateway.http = transport
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == status
    assert final.get("error_code") == code
    assert "failure_diagnostic" not in final
    assert "network_interpretation" not in final
    expected = 1 if failure in (InterruptedError, RuntimeError) else 2
    assert len(transport.calls) == expected + int(after_invalid)
    assert "SECRET_" not in json.dumps(final)


@pytest.mark.parametrize("cancel_on_call", [0, 1, 2])
def test_cancellation_is_sticky_and_never_publishes_rejected_output(cancel_on_call):
    repository, service, _ = setup()
    run, _ = create(service)

    class CancellingTransport(ScriptedTransport):
        def request(self, *args, **kwargs):
            result = super().request(*args, **kwargs)
            if len(self.calls) == cancel_on_call:
                service.cancel(run["id"], "operator")
            return result

    transport = CancellingTransport("not-json", json.dumps(response()))
    service.gateway.http = transport
    if cancel_on_call == 0:
        service.cancel(run["id"], "operator")
    final = service.execute(run["id"])
    assert final["status"] == "CANCELLED"
    assert len(transport.calls) == cancel_on_call
    assert "failure_diagnostic" not in final
    assert "network_interpretation" not in final


@pytest.mark.parametrize("finish", [None, "stop", "length", "SECRET_FINISH", {"SECRET_KEY": 1}])
@pytest.mark.parametrize("provider", ["ollama", "openai-compatible"])
def test_only_actual_allowlisted_provider_finish_reason_is_persisted(provider, finish):
    from c2hunter_controller.ai_gateway import OpenAICompatibleGateway

    repository, service, _ = setup()

    class EnvelopeTransport(ScriptedTransport):
        def request(self, *args, **kwargs):
            super().request(*args, **kwargs)
            if provider == "ollama":
                return {"message": {"content": "{}"}, "done_reason": finish}
            return {"choices": [{"message": {"content": "{}"}, "finish_reason": finish}]}

    transport = EnvelopeTransport("{}", "{}")
    if provider == "openai-compatible":
        service.gateway = OpenAICompatibleGateway(
            base_url="http://fixture", model="fixture", http_client=transport
        )
    else:
        service.gateway.http = transport
    run, _ = create(service)
    final = service.execute(run["id"])
    diagnostic = final["failure_diagnostic"]
    assert diagnostic["type"] == "SCHEMA"
    assert diagnostic.get("provider_finish_reason") == (
        finish if finish in ("stop", "length") else None
    )
    assert "SECRET_" not in json.dumps(final)


def test_run_api_publishes_typed_optional_diagnostic_without_dropping_legacy_fields(tmp_path):
    from fastapi.testclient import TestClient

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    path = tmp_path / "public.sqlite3"
    repository, service, _ = setup(SQLiteRepository(path))
    service.gateway.http = ScriptedTransport("{}", "{}")
    run, _ = create(service)
    final = service.execute(run["id"])
    client = TestClient(create_app(Settings(environment="test"), SQLiteRepository(path)))
    single = client.get("/api/v1/ai-runs/" + run["id"]).json()
    listed = client.get("/api/v1/analysis-jobs/network-job/ai-runs").json()["items"][0]
    assert single["failure_diagnostic"] == final["failure_diagnostic"]
    fixture = (
        Path(__file__).resolve().parents[2]
        / "web/tests/fixtures/network-ai-failure-diagnostic.json"
    )
    assert fixture.read_bytes() == (
        json.dumps(single["failure_diagnostic"], indent=2) + "\n"
    ).encode("utf-8")
    assert listed == single
    assert single["network_input"] == final["network_input"]
    assert single["candidate_count"] == 0
    specification = client.get("/openapi.json").json()
    schemas = specification["components"]["schemas"]
    assert schemas["NetworkFailureDiagnostic"]["additionalProperties"] is False
    for route, method, code in [
        ("/api/v1/ai-runs/{run_id}", "get", "200"),
        ("/api/v1/analysis-jobs/{job_id}/ai-runs", "post", "201"),
        ("/api/v1/ai-runs/{run_id}/cancel", "post", "200"),
    ]:
        wire = specification["paths"][route][method]["responses"][code]["content"][
            "application/json"
        ]["schema"]
        model = schemas[wire["$ref"].rsplit("/", 1)[-1]]
        assert "failure_diagnostic" in model["properties"]
        assert "failure_diagnostic" not in model["required"]
    legacy = {**final, "id": "legacy", "idempotency_key": "legacy"}
    del legacy["failure_diagnostic"]
    repository.create_ai_run(legacy)
    legacy_client = TestClient(create_app(Settings(environment="test"), SQLiteRepository(path)))
    assert "failure_diagnostic" not in legacy_client.get("/api/v1/ai-runs/legacy").json()


@pytest.mark.parametrize(
    "mutation",
    [
        {"type": "SECRET_TYPE"},
        {"stage": "SOURCE_INPUT"},
        {"SECRET_KEY": "SECRET_VALUE"},
        {"attempt_count": True},
        {"attempt_count": 3},
        {"repair_count": 2},
        {"output_bytes": -1},
        {"output_bytes": "2"},
        {"provider_finish_reason": "SECRET_FINISH"},
        {"attempt_count": 1, "repair_count": 1},
    ],
)
def test_diagnostic_contract_rejects_unknown_values_and_inconsistent_counts(mutation):
    from pydantic import ValidationError

    from c2hunter_controller.network_ai import NetworkFailureDiagnostic

    valid = {"type": "SCHEMA", "attempt_count": 2, "repair_count": 1, "output_bytes": 2}
    with pytest.raises(ValidationError):
        NetworkFailureDiagnostic.model_validate({**valid, **mutation})


def test_malformed_json_can_be_repaired_without_echoing_rejected_text():
    repository, service, _ = setup()
    transport = ScriptedTransport("SECRET_RAW_NON_JSON", json.dumps(response()))
    service.gateway.http = transport
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == "COMPLETED"
    assert len(transport.calls) == 2
    assert "SECRET_" not in json.dumps(transport.calls)
    assert "failure_diagnostic" not in final


def test_first_valid_output_needs_no_repair_or_failure_diagnostic():
    repository, service, transport = setup()
    run, _ = create(service)
    final = service.execute(run["id"])
    assert final["status"] == "COMPLETED"
    assert len(transport.calls) == 1
    assert "failure_diagnostic" not in final
