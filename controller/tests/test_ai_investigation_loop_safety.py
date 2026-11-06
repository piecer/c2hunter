"""Adversarial loop outcomes over actual source/store and HTTP adapter."""

from dataclasses import replace

import pytest

from c2hunter_controller.ai_investigation_store import InvestigationOutcomeUnknown
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_loop import (
    adaptive,
    api,
    finish,
    observations,
    request_for,
    structured_provider,
)
from tests.test_ai_investigation_loop import (
    store as _store_fixture,
)

store = _store_fixture


def execute(store, responder, *, rows=None, gateway_change=None):
    s, repo = store
    if rows is not None:
        repo.save_job(job(rows))
    with structured_provider(responder) as (gateway, requests):
        if gateway_change:
            gateway = replace(gateway, **gateway_change)
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        result = service.get("alice", "job", run.id)
        return service, result, outcome, requests


def test_single_global_schema_repair_then_saved_success(store):
    def responder(body, index):
        if index == 1:
            return {"action": "finish", "invented": "not a valid result"}
        return adaptive(body, index)

    service, run, outcome, requests = execute(store, responder)
    assert run.status == "COMPLETED" and len(requests) == 4
    assert outcome.claim["budgets"]["model_calls"] == 4
    assert run.result.progress.transport_attempts == 4
    assert store[0].worker_exited(outcome.claim)


@pytest.mark.parametrize(
    "malformed",
    [
        "not json",
        '{"action":"finish","action":"finish"}',
        {"action": "request_tools", "tools": [{"tool": "sql", "arguments": {"query": "SELECT 1"}}]},
    ],
)
def test_invalid_outputs_one_repair_then_facts_only(store, malformed):
    _, run, outcome, requests = execute(store, lambda *_: malformed)
    assert len(requests) == 2
    assert run.status == "PARTIAL" and run.result.mode == "FACTS_ONLY"
    assert run.result.verdict == "INCONCLUSIVE" and run.result.facts
    assert run.result.reason == "MODEL_INVALID"
    assert store[0].worker_exited(outcome.claim)


def test_duplicate_tools_still_debited_four_plans_then_final_only(store):
    def responder(body, index):
        if index <= 4:
            return {
                "action": "request_tools",
                "tools": [{"tool": "peer_overview", "arguments": {}}],
            }
        assert (
            body["response_format"]["json_schema"]["schema"]["properties"]["action"]["const"]
            == "finish"
        )
        return finish(observations(body)[0])

    _, run, outcome, requests = execute(store, responder)
    assert run.status == "COMPLETED" and len(requests) == 5
    assert outcome.claim["budgets"]["tool_calls"] == 5
    assert outcome.claim["evidence_count"] == 1
    assert store[0].worker_exited(outcome.claim)


def test_tool_attempt_budget_exhaustion_not_benign(store):
    def responder(*_):
        return {
            "action": "request_tools",
            "tools": [{"tool": "peer_overview", "arguments": {}}] * 3,
        }

    _, run, outcome, requests = execute(store, responder)
    assert len(requests) == 4
    assert outcome.claim["budgets"]["tool_calls"] == 12
    assert run.status == "PARTIAL" and run.result.mode == "FACTS_ONLY"
    assert run.result.verdict == "INCONCLUSIVE" and run.result.reason == "TOOL_BUDGET"
    assert store[0].worker_exited(outcome.claim)


@pytest.mark.parametrize("fault", ["evidence", "metric", "numeric", "no-support"])
def test_unissued_refs_and_model_metric_values_not_published(store, fault):
    def responder(body, _):
        data = finish(observations(body)[0], verdict="SUSPICIOUS_C2")
        if fault == "evidence":
            data["support"][0]["evidence_ids"] = ["a" * 64]
        elif fault == "metric":
            data["support"][0]["metric_refs"] = ["b" * 64 + ":total_bytes"]
        elif fault == "numeric":
            data["support"][0]["value"] = 9000
        else:
            data["support"] = []
        return data

    _, run, outcome, requests = execute(store, responder)
    assert len(requests) == 2
    assert run.status == "PARTIAL" and run.result.verdict == "INCONCLUSIVE"
    assert not run.result.support
    assert store[0].worker_exited(outcome.claim)


@pytest.mark.parametrize("mixed", [False, True])
def test_counterevidence_required_and_outbound_control_suppressed(store, mixed):
    def responder(body, index):
        if index == 1:
            return {
                "action": "request_tools",
                "tools": [{"tool": "peer_protocol_observations", "arguments": {}}],
            }
        return finish(observations(body)[0], verdict="SUSPICIOUS_C2")

    rows = [flow(protocol="TCP", tcp_flags={"syn": 1}, payload_length=0)]
    if mixed:
        rows.append(flow(protocol="UDP", payload_length=4))
    _, run, outcome, requests = execute(store, responder, rows=rows)
    assert run.result.verdict == ("SUSPICIOUS_C2" if mixed else "INCONCLUSIVE")
    assert run.status == ("COMPLETED" if mixed else "PARTIAL")
    if not mixed:
        assert run.result.reason == "POSITIVE_UNSUPPORTED"
    assert store[0].worker_exited(outcome.claim)


def test_positive_without_counterevidence_query_rejected(store):
    _, run, outcome, requests = execute(
        store, lambda body, _: finish(observations(body)[0], verdict="SUSPICIOUS_C2")
    )
    assert run.status == "PARTIAL" and run.result.reason == "COUNTEREVIDENCE_REQUIRED"
    assert store[0].worker_exited(outcome.claim)


def test_context_limit_is_one_charge_zero_transport_then_partial(store):
    _, run, outcome, requests = execute(
        store, adaptive, gateway_change={"context_tokens": 8192, "max_output_tokens": 8000}
    )
    assert requests == []
    assert run.status == "PARTIAL" and run.result.reason == "CONTEXT_LIMIT"
    assert outcome.claim["budgets"]["model_calls"] == 1
    assert outcome.claim["budgets"]["transport_attempts"] == 0
    assert store[0].worker_exited(outcome.claim)


def test_cancel_during_response_wins_and_never_ack_inside_executor(store):
    s, repo = store
    run_id = []

    def responder(body, index):
        assert s.cancel("alice", "job", run_id[0])["status"] == "CANCELLED"
        return finish(observations(body)[0])

    with structured_provider(responder) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        run_id.append(run.id)
        outcome = service.run_next("worker")
        assert service.get("alice", "job", run.id).status == "CANCELLED"
        assert outcome.acknowledge_exit
        assert s.worker_exited(outcome.claim)
        assert len(requests) == 1


def test_unknown_transport_reservation_commit_preserves_fault_no_http(store, monkeypatch):
    s, repo = store
    reserve = s.reserve
    fired = []

    def uncertain(claim, **increments):
        if "transport_attempts" in increments:
            fired.append(True)
            reserve(claim, **increments)
            raise InvestigationOutcomeUnknown("STORAGE_OUTCOME_UNKNOWN")
        return reserve(claim, **increments)

    monkeypatch.setattr(s, "reserve", uncertain)
    _, run, outcome, requests = execute(store, adaptive)
    assert fired and requests == []
    assert outcome.code == "STORAGE_OUTCOME_UNKNOWN" and not outcome.acknowledge_exit
    assert run.status == "INVESTIGATING" and run.result is None
