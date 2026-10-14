"""Canned responses only: never replay saved private evidence or call a model."""

import json

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_ai_storage as custody
from c2hunter_controller.ai_gateway import OllamaGateway
from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_gateway import FakeHttpClient
from tests.test_historical_ai_execution import admitted

SENTINEL = "PRIVATE_MODEL_PROMPT_THINKING_CREDENTIAL_SENTINEL"


def diagnostics(caplog):
    return [
        record.failure_diagnostic
        for record in caplog.records
        if hasattr(record, "failure_diagnostic")
    ]


def exercise(responses, *, retries=0):
    repo = MemoryRepository()
    run = admitted(repo)
    _, bundles = custody.materialize_historical_run(run)
    http = FakeHttpClient(responses(bundles[0]) if callable(responses) else responses)
    gateway = OllamaGateway(
        base_url="http://offline.invalid", model="canned", retries=retries, http_client=http
    )
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "receipt"}])
    worker = AIAnalysisWorker(queue, ai.AIAnalysisService(repo, gateway))
    return repo, run, http, queue, worker


def test_historical_json_failure_logs_bounded_diagnostic_without_private_values(caplog):
    raw = SENTINEL + "한글"
    response = {"message": {"content": raw, "thinking": SENTINEL}, "done_reason": "length"}
    repo, run, http, queue, worker = exercise([response, response])
    assert worker.run_once(timeout=0)
    saved = repo.get_ai_run(run["id"])
    assert saved["status"] == "FAILED" and saved["error_code"] == "MODEL_OUTPUT_INVALID"
    custody.materialize_historical_run(saved)
    assert saved[custody.OWNER_KEY] == run[custody.OWNER_KEY]
    assert queue.acked == ["receipt"] and len(http.requests) == 2
    assert diagnostics(caplog) == [
        {
            "stage": "JSON_PARSE",
            "attempt_count": 2,
            "repair_count": 1,
            "transport_attempt_count": 2,
            "output_bytes": len(raw.encode()),
            "provider_finish_reason": "length",
        }
    ]
    assert run["id"] in caplog.text
    assert SENTINEL not in caplog.text
    assert SENTINEL not in json.dumps(http.requests[-1]["body"])
    assert "JSON_PARSE" in json.dumps(http.requests[-1]["body"])
    assert "failure_diagnostic" not in saved


def envelope(value, finish="stop"):
    return {"message": {"content": json.dumps(value), "thinking": SENTINEL}, "done_reason": finish}


@pytest.mark.parametrize("repaired", [False, True])
def test_success_and_repair_success_are_not_failure_logs(caplog, repaired):
    def responses(bundle):
        good = envelope(ai.FakeGateway().assess(bundle))
        return ([envelope({SENTINEL: SENTINEL})] if repaired else []) + [good]

    repo, run, http, queue, worker = exercise(responses)
    assert worker.run_once(timeout=0)
    assert repo.get_ai_run(run["id"])["status"] == "COMPLETED"
    assert len(repo.list_ai_assessments(run["id"])) == 1
    assert len(http.requests) == (2 if repaired else 1)
    assert diagnostics(caplog) == [] and queue.acked == ["receipt"]
    assert SENTINEL not in json.dumps(http.requests[-1]["body"])
    assert http.requests[0]["body"]["format"] == "json"
    assert "think" not in http.requests[0]["body"]


@pytest.mark.parametrize("stage", ["SCHEMA", "EVIDENCE_VALIDATION", "RESPONSE_ENVELOPE"])
def test_rejected_stages_keep_original_terminal_codes_and_attempt_budget(caplog, stage):
    def responses(bundle):
        value = ai.FakeGateway().assess(bundle)
        if stage == "SCHEMA":
            value["candidate"]["confidence"] = SENTINEL
        else:
            value["candidate"]["external_ip"] = "203.0.113.222"
        reply = (
            {"message": {"thinking": SENTINEL}, "done_reason": SENTINEL}
            if stage == "RESPONSE_ENVELOPE"
            else envelope(value, SENTINEL)
        )
        return [reply, reply]

    repo, run, http, queue, worker = exercise(responses)
    assert worker.run_once(timeout=0)
    saved = repo.get_ai_run(run["id"])
    assert saved["error_code"] == "MODEL_OUTPUT_INVALID"
    assert saved["error_message"] == custody.FAILURES["MODEL_OUTPUT_INVALID"]
    count = 1 if stage == "RESPONSE_ENVELOPE" else 2
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["stage"] == stage
    assert diagnostic["attempt_count"] == len(http.requests) == count
    assert diagnostic["repair_count"] == count - 1
    assert diagnostic["transport_attempt_count"] == count
    assert diagnostic["provider_finish_reason"] is None
    assert (diagnostic["output_bytes"] is None) == (stage == "RESPONSE_ENVELOPE")
    assert SENTINEL not in caplog.text
    assert SENTINEL not in json.dumps(http.requests[-1]["body"])
    assert queue.acked == ["receipt"]


@pytest.mark.parametrize(
    "fault,stage,code",
    [
        (TimeoutError(SENTINEL), "TRANSPORT", "MODEL_TIMEOUT"),
        (OSError(SENTINEL), "TRANSPORT", "AI_ANALYSIS_FAILED"),
        (InterruptedError(SENTINEL), "CANCELLED", None),
    ],
)
def test_transport_and_inflight_cancel_are_diagnostic_not_raw(caplog, fault, stage, code):
    repo, run, http, queue, worker = exercise([fault])
    assert worker.run_once(timeout=0)
    saved = repo.get_ai_run(run["id"])
    assert saved["status"] == ("CANCELLED" if code is None else "FAILED")
    if code is not None:
        assert saved["error_code"] == code
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic == {
        "stage": stage,
        "attempt_count": 1,
        "repair_count": 0,
        "transport_attempt_count": 1,
        "output_bytes": None,
        "provider_finish_reason": None,
    }
    assert len(http.requests) == 1 and queue.acked == ["receipt"]
    assert SENTINEL not in caplog.text


def test_attempts_count_real_transport_retries_not_assumed_completions(caplog):
    failure = TimeoutError(SENTINEL)
    repo, run, http, _, worker = exercise(
        [failure, failure, failure, envelope({}), failure, failure, failure, failure], retries=3
    )
    assert worker.run_once(timeout=0)
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["stage"] == "TRANSPORT"
    assert diagnostic["attempt_count"] == 2 and diagnostic["repair_count"] == 1
    assert diagnostic["transport_attempt_count"] == len(http.requests) == 8
    assert diagnostic["provider_finish_reason"] is None and diagnostic["output_bytes"] is None
    assert repo.get_ai_run(run["id"])["error_code"] == "MODEL_TIMEOUT"


def test_artifact_preparation_has_its_own_stage_and_observed_success_call(caplog, monkeypatch):
    from c2hunter_controller import historical_ai_execution as execution

    fired = []

    def fail(**kwargs):
        fired.append(True)
        raise ValueError(SENTINEL)

    repo, run, _, queue, worker = exercise(lambda b: [envelope(ai.FakeGateway().assess(b))])
    monkeypatch.setattr(execution, "build_ai_artifacts", fail)
    assert worker.run_once(timeout=0)
    (diagnostic,) = diagnostics(caplog)
    assert fired == [True] and queue.acked == ["receipt"]
    assert diagnostic["stage"] == "ARTIFACT_PREPARATION"
    assert diagnostic["attempt_count"] == 1 and diagnostic["repair_count"] == 0
    assert diagnostic["transport_attempt_count"] == 1
    assert diagnostic["output_bytes"] > 0 and diagnostic["provider_finish_reason"] == "stop"
    assert repo.get_ai_run(run["id"])["error_code"] == "MODEL_OUTPUT_INVALID"
    assert repo.list_ai_assessments(run["id"]) == []
    assert SENTINEL not in caplog.text


def test_diagnostic_sink_failure_cannot_change_terminal_or_ack(monkeypatch):
    from c2hunter_controller import c2_diagnostics

    fired = []

    def fail(*args, **kwargs):
        fired.append(True)
        raise RuntimeError(SENTINEL)

    monkeypatch.setattr(c2_diagnostics.logger, "warning", fail)
    repo, run, _, queue, worker = exercise([envelope({}), envelope({})])
    assert worker.run_once(timeout=0)
    assert fired == [True] and queue.acked == ["receipt"]
    assert repo.get_ai_run(run["id"])["error_code"] == "MODEL_OUTPUT_INVALID"


@pytest.mark.parametrize("point", ["callback", "terminal"])
def test_actual_gateway_storage_failure_escapes_without_ack(caplog, monkeypatch, point):
    from c2hunter_controller._baseline_storage import BaselineStorageError

    repo, run, http, queue, worker = exercise([envelope({}), envelope({})])
    original_get, original_save = repo.get_ai_run, repo.save_ai_run
    fired = []

    def save(value):
        if value["status"] == "FAILED":
            fired.append(True)
            raise BaselineStorageError()
        saved = original_save(value)
        if value["status"] == "ANALYZING" and point == "callback":
            monkeypatch.setattr(repo, "get_ai_run", get)
        return saved

    def get(identifier):
        fired.append(True)
        raise BaselineStorageError()

    monkeypatch.setattr(repo, "save_ai_run", save)
    assert not worker.run_once(timeout=0)
    assert fired == [True] and queue.acked == []
    assert original_get(run["id"])["status"] == "ANALYZING"
    assert len(http.requests) == (0 if point == "callback" else 2)
    assert len(diagnostics(caplog)) == (0 if point == "callback" else 1)


def test_nonhistorical_c2_also_emits_safe_diagnostic(caplog):
    from tests.test_ai_gateway import source_candidate

    repo = MemoryRepository()
    repo.jobs["job-1"] = {"id": "job-1", "status": "COMPLETED"}
    repo.save_candidates("job-1", [source_candidate()])
    http = FakeHttpClient([envelope({}), envelope({})])
    gateway = OllamaGateway(
        base_url="http://offline.invalid", model="canned", retries=0, http_client=http
    )
    service = ai.AIAnalysisService(repo, gateway)
    run, _ = service.create_run(
        analysis_job_id="job-1",
        idempotency_key="diagnostic",
        candidate_limit=1,
        created_by="analyst",
    )
    saved = service.execute(run["id"])
    assert saved["error_code"] == "MODEL_OUTPUT_INVALID"
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["stage"] == "SCHEMA" and diagnostic["attempt_count"] == 2
    assert "failure_diagnostic" not in saved


def test_valid_json_with_wrong_root_shape_is_schema_not_json_parse(caplog):
    repo, run, _, _, worker = exercise([envelope([]), envelope([])])
    assert worker.run_once(timeout=0)
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["stage"] == "SCHEMA"
    assert repo.get_ai_run(run["id"])["error_code"] == "MODEL_OUTPUT_INVALID"


@pytest.mark.parametrize("checks,count", [([True], 0), ([False, False, False, False, True], 1)])
def test_cancellation_counts_only_dispatched_calls(checks, count):
    from c2hunter_controller.ai_gateway import AIAnalysisCancelled
    from c2hunter_controller.c2_diagnostics import C2Diagnostics
    from tests.test_ai_gateway import source_candidate

    observed = C2Diagnostics()
    http = FakeHttpClient([envelope({})])
    gateway = OllamaGateway(
        base_url="http://offline.invalid", model="canned", retries=0, http_client=http
    )
    iterator = iter(checks)
    with pytest.raises(AIAnalysisCancelled):
        gateway.assess_cancellable(
            ai.build_evidence_bundle(source_candidate()),
            should_cancel=lambda: next(iterator),
            diagnostics=observed,
        )
    assert observed.stage == "CANCELLED"
    assert observed.attempt_count == observed.transport_attempt_count == len(http.requests) == count
    assert observed.repair_count == 0


@pytest.mark.parametrize(
    "value",
    [
        {"stage": SENTINEL},
        {"attempt_count": 3},
        {"attempt_count": True},
        {"repair_count": 2},
        {"transport_attempt_count": 9},
        {"output_bytes": -1},
        {"output_bytes": float("inf")},
        {"output_bytes": float("nan")},
        {"output_bytes": 2**63},
        {"provider_finish_reason": SENTINEL},
        {SENTINEL: SENTINEL},
    ],
)
def test_diagnostic_contract_rejects_unbounded_or_untrusted_fields(value):
    from pydantic import ValidationError

    from c2hunter_controller.c2_diagnostics import C2FailureDiagnostic

    with pytest.raises(ValidationError):
        C2FailureDiagnostic.model_validate({"stage": "SCHEMA", **value})


def test_unvalidated_run_identifier_is_not_logged(caplog):
    from c2hunter_controller.c2_diagnostics import C2Diagnostics

    C2Diagnostics().report(SENTINEL)
    assert diagnostics(caplog) == [] and SENTINEL not in caplog.text


def test_openai_finish_reason_is_observed_without_choices_or_content_leak(caplog):
    from c2hunter_controller.ai_gateway import OpenAICompatibleGateway

    repo, run, http, _, worker = exercise(
        [
            {
                "choices": [{"message": {"content": "{}"}, "finish_reason": "length"}],
                "private": SENTINEL,
            },
            {
                "choices": [{"message": {"content": "{}"}, "finish_reason": "length"}],
                "private": SENTINEL,
            },
        ]
    )
    worker.service.gateway = OpenAICompatibleGateway(
        base_url="http://offline.invalid", model="canned", retries=0, http_client=http
    )
    assert worker.run_once(timeout=0)
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["provider_finish_reason"] == "length"
    assert diagnostic["attempt_count"] == 2 and diagnostic["output_bytes"] == 2
    assert SENTINEL not in caplog.text
    assert repo.get_ai_run(run["id"])["error_code"] == "MODEL_OUTPUT_INVALID"


def test_cache_hit_artifact_failure_reports_zero_new_calls(caplog, monkeypatch):
    from c2hunter_controller import historical_ai_execution as execution

    repo, run, http, _, worker = exercise(lambda b: [envelope(ai.FakeGateway().assess(b))])
    _, bundles = custody.materialize_historical_run(run)
    worker.service.gateway.assess(bundles[0])

    def fail(**kwargs):
        raise ValueError(SENTINEL)

    monkeypatch.setattr(execution, "build_ai_artifacts", fail)
    assert worker.run_once(timeout=0)
    (diagnostic,) = diagnostics(caplog)
    assert len(http.requests) == 1
    assert diagnostic["stage"] == "ARTIFACT_PREPARATION"
    assert diagnostic["attempt_count"] == diagnostic["transport_attempt_count"] == 0
    assert diagnostic["repair_count"] == 0
    assert diagnostic["output_bytes"] is None and diagnostic["provider_finish_reason"] is None
    assert repo.get_ai_run(run["id"])["error_code"] == "MODEL_OUTPUT_INVALID"


def test_custom_gateway_counts_stay_unknown_and_historical_storage_stays_closed(caplog):
    class Custom(ai.FakeGateway):
        def assess(self, bundle):
            return {SENTINEL: SENTINEL}

    repo, run, _, queue, worker = exercise([])
    worker.service.gateway = Custom()
    assert worker.run_once(timeout=0) and queue.acked == ["receipt"]
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["stage"] == "SCHEMA"
    assert diagnostic["attempt_count"] is None
    assert diagnostic["repair_count"] is None
    assert diagnostic["transport_attempt_count"] is None
    assert SENTINEL not in caplog.text
    saved = repo.get_ai_run(run["id"])
    with pytest.raises(custody.HistoricalStorageError):
        repo.save_ai_run({**saved, "failure_diagnostic": diagnostic})
