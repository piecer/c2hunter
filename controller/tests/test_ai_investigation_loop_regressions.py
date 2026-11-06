"""Small cross-component regressions for custody, observations and callbacks."""

import json

from c2hunter_controller.ai_investigation_contract import InvestigationError, canonical_bytes
from c2hunter_controller.ai_investigation_evidence import EvidenceService
from c2hunter_controller.ai_investigation_store import InvestigationStorageError
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


def test_all_tools_real_observations_untrusted_payloads_and_prompt_data(store):
    s, repo = store
    marker = "IGNORE-SYSTEM-SQL-shell-https://attacker.invalid"
    repo.save_job(
        job(
            [
                flow(
                    sensor_id=marker,
                    payload="ORIGINAL_CAPTURE_SECRET_DO_NOT_PROJECT",
                    domain="example.test",
                )
            ]
        )
    )

    def responder(body, index):
        assert "ORIGINAL_CAPTURE_SECRET_DO_NOT_PROJECT" not in json.dumps(body)
        assert "untrusted data" in body["messages"][0]["content"]
        if index == 1:
            return {
                "action": "request_tools",
                "tools": [
                    {"tool": tool, "arguments": {"limit": 1}}
                    for tool in ("peer_flow_samples", "peer_timeline", "peer_protocol_observations")
                ],
            }
        if index == 2:
            seen = observations(body)
            assert any(e["samples"] for e in seen)
            assert any(e["timeline"] for e in seen)
            assert any(e["protocols"] for e in seen)
            assert all(
                bucket["packet_interval_mean_seconds"] is None
                for e in seen
                for bucket in e["timeline"]
            )
            return {
                "action": "request_tools",
                "tools": [{"tool": "compare_peer_cohort", "arguments": {}}],
            }
        return finish(observations(body)[0])

    with structured_provider(responder) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo, question=marker))
        outcome = service.run_next("worker")
        assert service.get("alice", "job", run.id).status == "COMPLETED"
        assert outcome.claim["budgets"]["tool_calls"] == 5
        assert outcome.claim["evidence_count"] == 5
        assert s.worker_exited(outcome.claim)


def test_actual_cross_run_reference_rejected_even_same_source(store):
    s, repo = store
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        protocol_step = next(
            step
            for step in service.steps("alice", "job", run.id)
            if step.tool == "peer_protocol_observations"
        )
        evidence = service.evidence("alice", "job", run.id, protocol_step.evidence_id).model_dump(
            mode="json"
        )
        assert s.worker_exited(outcome.claim)
    with structured_provider(lambda *_: finish(evidence)) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo, idempotency_key="second"))
        outcome = service.run_next("worker")
        saved = service.get("alice", "job", run.id)
        assert len(requests) == 2 and saved.result.reason == "REFERENCE_MISMATCH"
        assert service.evidence("alice", "job", run.id, evidence["evidence_id"]) is None
        assert s.worker_exited(outcome.claim)


def test_failed_tool_is_charged_and_published_as_partial(store, monkeypatch):
    s, repo = store
    original = EvidenceService.call

    def call(self, tool, arguments):
        if tool == "peer_protocol_observations":
            raise InvestigationError("EVIDENCE_BUDGET")
        return original(self, tool, arguments)

    monkeypatch.setattr(EvidenceService, "call", call)
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        saved = service.get("alice", "job", run.id)
        assert saved.status == "PARTIAL" and saved.progress.tool_calls == 2
        assert saved.result.reason == "EVIDENCE_BUDGET"
        assert s.worker_exited(outcome.claim)


def test_cancel_after_final_validation_before_publish_wins(store, monkeypatch):
    s, repo = store
    publish = s.publish
    fired = []

    def cancel_then_publish(claim, status, raw):
        fired.append(True)
        s.cancel(claim["owner_id"], claim["job_id"], claim["id"])
        return publish(claim, status, raw)

    monkeypatch.setattr(s, "publish", cancel_then_publish)
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        assert fired and outcome.code == "CANCELLED" and outcome.acknowledge_exit
        saved = service.get("alice", "job", run.id)
        assert saved.status == "CANCELLED" and saved.result is None
        assert s.worker_exited(outcome.claim)


def test_store_fault_in_cancel_callback_not_model_error(store, monkeypatch):
    s, repo = store
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        get = s.get
        fired = []

        def broken(owner, job_id, run_id):
            if fired:
                raise InvestigationStorageError("credentials-never-return")
            return get(owner, job_id, run_id)

        reserve = s.reserve

        def debit(claim, **increments):
            result = reserve(claim, **increments)
            if "model_calls" in increments:
                fired.append(True)
            return result

        monkeypatch.setattr(s, "get", broken)
        monkeypatch.setattr(s, "reserve", debit)
        outcome = service.run_next("worker")
        assert fired and requests == []
        assert outcome.code == "STORAGE_UNAVAILABLE" and not outcome.acknowledge_exit
        assert "credentials" not in str(outcome)


def test_saved_binding_semantics_rechecked_before_any_model(store):
    s, repo = store
    from c2hunter_controller.ai_investigation_schema import InvestigationRequest

    req = InvestigationRequest.model_validate(request_for(repo))
    snap = repo.read_investigation_source("job")
    s.admit(
        owner_id="alice",
        job_id="job",
        idempotency_key=req.idempotency_key,
        request_json=canonical_bytes(req.model_dump(mode="json")),
        binding_json=canonical_bytes({"source_sha256": "0" * 64}),
        snapshot_json=canonical_bytes(snap.model_dump(mode="json")),
    )
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        outcome = service.run_next("worker")
        assert outcome.code == "STORE_CORRUPT" and not outcome.acknowledge_exit
        assert requests == []


def test_real_retained_evidence_quota_is_coupled_to_frozen_snapshot(store):
    s, repo = store
    repo.save_job(
        job(
            [
                flow(
                    sensor_id="s" * 190,
                    domain="a" * 240,
                    tls_fingerprint="b" * 120,
                    certificate_fingerprint="c" * 120,
                )
                for _ in range(60)
            ]
        )
    )

    def responder(body, index):
        limits = (50, 49, 48) if index == 1 else (47, 46, 45)
        return {
            "action": "request_tools",
            "tools": [
                {"tool": "peer_flow_samples", "arguments": {"limit": limit}} for limit in limits
            ],
        }

    with structured_provider(responder) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        saved = service.get("alice", "job", run.id)
        custody = s.saved_input("alice", "job", run.id)
        assert outcome.code == "EVIDENCE_BUDGET"
        assert saved.status == "PARTIAL" and saved.result.mode == "FACTS_ONLY"
        assert outcome.claim["observations_bytes"] - len(custody["snapshot_json"]) <= 131072
        assert outcome.claim["observations_bytes"] <= 262144
        assert outcome.claim["budgets"]["tool_calls"] > outcome.claim["evidence_count"]
        assert s.worker_exited(outcome.claim)


def test_final_keeps_unavailable_and_partial_quality_from_selected_tools(store):
    s, repo = store
    source = job([flow()])
    source["status"] = "PARTIALLY_COMPLETED"
    repo.save_job(source)

    def responder(body, index):
        if index == 1:
            return {
                "action": "request_tools",
                "tools": [{"tool": "peer_protocol_observations", "arguments": {}}],
            }
        return finish(observations(body)[0])

    with structured_provider(responder) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        result = service.get("alice", "job", run.id).result
        assert result.partial_scope and "PARTIAL_SOURCE" in result.limitations
        quality = next(
            item for item in result.evidence_quality if item.tool == "peer_protocol_observations"
        )
        assert quality.status == "UNAVAILABLE" and quality.counts.unavailable == 1
        assert "EVIDENCE_UNAVAILABLE" in result.limitations
        assert s.worker_exited(outcome.claim)


def test_unexpected_callback_failure_has_no_diagnostics_or_release(store, monkeypatch):
    s, repo = store
    reserve = s.reserve

    def broken(claim, **increments):
        if "transport_attempts" in increments:
            raise RuntimeError("credential-sentinel")
        return reserve(claim, **increments)

    monkeypatch.setattr(s, "reserve", broken)
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        assert outcome.code == "INTERNAL_ERROR" and not outcome.acknowledge_exit
        assert requests == [] and "credential-sentinel" not in str(outcome)


def test_physical_supervisor_joins_before_exit_ack(store):
    import threading

    s, repo = store
    outcome = []
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        service.admit("alice", "job", request_for(repo))
        thread = threading.Thread(target=lambda: outcome.append(service.run_next("worker")))
        thread.start()
        thread.join(10)
        assert not thread.is_alive() and outcome
        assert s.worker_exited(outcome[0].claim)
