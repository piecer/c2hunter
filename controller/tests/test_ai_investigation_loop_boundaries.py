"""Admission boundaries and deadline/custody regression witnesses."""

import json
import time
from dataclasses import replace

import pytest

from c2hunter_controller.ai_gateway import OpenAICompatibleGateway
from c2hunter_controller.ai_investigation_contract import InvestigationError, canonical_bytes
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_loop import (
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


def configured(url="http://127.0.0.1:1"):
    return OpenAICompatibleGateway(base_url=url, model="scripted", context_tokens=65536)


def test_alias_unavailable_no_legacy_readiness_source_or_model_probe(store, monkeypatch):
    s, repo = store
    req = request_for(repo)
    service = api().InvestigationService.from_configured_gateway(
        repo, s, configured("http://host.docker.internal:11434")
    )
    assert service.capabilities().availability == "UNAVAILABLE"
    monkeypatch.setattr(
        repo,
        "read_investigation_source",
        lambda *_a, **_k: pytest.fail("unavailable source acquisition"),
    )
    with pytest.raises(InvestigationError, match="UNAVAILABLE"):
        service.admit("alice", "job", req)


@pytest.mark.parametrize("server,consent", [(False, False), (False, True), (True, False)])
def test_remote_admission_requires_both_explicit_permissions(store, monkeypatch, server, consent):
    s, repo = store
    req = request_for(repo, allow_remote=consent)
    service = api().InvestigationService.from_configured_gateway(
        repo, s, configured("https://8.8.8.8"), server_allow_remote=server
    )
    monkeypatch.setattr(
        repo, "read_investigation_source", lambda *_a, **_k: pytest.fail("remote denied hydration")
    )
    with pytest.raises(InvestigationError, match="REMOTE_NOT_ALLOWED"):
        service.admit("alice", "job", req)


def test_replay_before_capability_reread_and_remote_consent_semantic(store):
    s, repo = store
    service = api().InvestigationService.from_configured_gateway(repo, s, configured())
    req = request_for(repo)
    run, _ = service.admit("alice", "job", req)
    unavailable = api().InvestigationService(repo, s, None)
    assert unavailable.admit("alice", "job", req) == (run, False)
    with pytest.raises(ValueError, match="IDEMPOTENCY_CONFLICT"):
        unavailable.admit("alice", "job", {**req, "allow_remote": True})


def test_snapshot_exact_cap_plus_one_fails_before_queue(store):
    s, repo = store
    rows = [flow(sensor_id="s1") for _ in range(180)]
    repo.save_job(job(rows))
    snapshot = repo.read_investigation_source("job")
    gap = 131072 - len(canonical_bytes(snapshot.model_dump(mode="json")))
    assert 0 <= gap <= len(rows) * 198
    for row in rows:
        extra = min(gap, 198)
        row["sensor_id"] += "x" * extra
        gap -= extra
    assert gap == 0
    repo.save_job(job(rows))
    assert (
        len(canonical_bytes(repo.read_investigation_source("job").model_dump(mode="json")))
        == 131072
    )
    service = api().InvestigationService.from_configured_gateway(repo, s, configured())
    req = request_for(repo)
    run, _ = service.admit("alice", "job", req)
    assert run.status == "QUEUED"
    rows[-1]["sensor_id"] += "y"
    repo.save_job(job(rows))
    assert (
        len(canonical_bytes(repo.read_investigation_source("job").model_dump(mode="json")))
        == 131073
    )
    with pytest.raises(InvestigationError, match="SOURCE_LIMIT"):
        service.admit("bob", "job", request_for(repo, idempotency_key="other"))
    assert s.page("bob", "job") == []


def test_deadline_expired_at_entry_and_missing_claim_have_typed_outcome(store):
    s, repo = store
    service = api().InvestigationService.from_configured_gateway(repo, s, configured())
    run, _ = service.admit("alice", "job", request_for(repo))
    assert service.execute_claim({}, deadline_monotonic=time.monotonic() + 5).code == "STALE_CLAIM"
    claim = s.claim("worker")
    outcome = service.execute_claim(claim, deadline_monotonic=time.monotonic() - 1)
    assert outcome.code == "DEADLINE_EXCEEDED"
    saved = service.get("alice", "job", run.id)
    assert saved.status == "FAILED" and saved.result.reason == "DEADLINE_EXCEEDED"
    assert s.worker_exited(outcome.claim)


def test_late_final_step_cannot_publish_completed(store, monkeypatch):
    s, repo = store
    with structured_provider(lambda body, _: finish(observations(body)[0])) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        claim = s.claim("worker")
        deadline = time.monotonic() + 0.8
        append = s.append_step

        def late(claim, raw):
            updated = append(claim, raw)
            if json.loads(raw)["kind"] == "FINAL":
                time.sleep(max(0, deadline - time.monotonic()) + 0.02)
            return updated

        monkeypatch.setattr(s, "append_step", late)
        outcome = service.execute_claim(claim, deadline_monotonic=deadline)
        assert outcome.code == "DEADLINE_EXCEEDED"
        assert service.get("alice", "job", run.id).status != "COMPLETED"
        assert len(requests) == 1
        assert s.worker_exited(outcome.claim)


def test_stale_revision_never_rebound_from_public_state(store):
    s, repo = store
    service = api().InvestigationService.from_configured_gateway(repo, s, configured())
    run, _ = service.admit("alice", "job", request_for(repo))
    claim = s.claim("worker")
    new = s.heartbeat(claim)
    outcome = service.execute_claim(claim, deadline_monotonic=time.monotonic() + 5)
    assert outcome.code == "STALE_CLAIM" and not outcome.acknowledge_exit
    assert s.get("alice", "job", run.id)["revision"] == new["revision"]
    assert s.worker_exited(new)


def test_provider_disconnect_is_not_retried(store):
    s, repo = store
    with structured_provider(lambda *_: None) as (gateway, requests):
        # Genuine dropped loopback HTTP connection after receipt, no retry.
        service = api().InvestigationService(repo, s, replace(gateway, timeout_seconds=2))
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        saved = service.get("alice", "job", run.id)
        assert outcome.code == "TRANSPORT" and saved.status == "PARTIAL"
        assert saved.progress.model_calls == saved.progress.transport_attempts == 1
        assert s.worker_exited(outcome.claim)
        assert len(requests) == 1


def test_six_call_global_budget_and_one_final_repair(store):
    s, repo = store

    def responder(body, index):
        if index <= 4:
            return {
                "action": "request_tools",
                "tools": [{"tool": "peer_timeline", "arguments": {"limit": 1}}],
            }
        return {"action": "finish"}  # one final attempt + one global repair

    with structured_provider(responder) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        saved = service.get("alice", "job", run.id)
        assert len(requests) == saved.progress.model_calls == 6
        assert saved.status == "PARTIAL"
        assert s.worker_exited(outcome.claim)


def test_snapshot_binding_and_source_argument_cannot_be_substituted(store, monkeypatch):
    s, repo = store
    req = request_for(repo)
    repo.save_job(job([flow(total_bytes=999)]))
    different = repo.read_investigation_source("job")
    monkeypatch.setattr(repo, "read_investigation_source", lambda *_a, **_k: different)
    service = api().InvestigationService.from_configured_gateway(repo, s, configured())
    with pytest.raises(InvestigationError, match="SOURCE_CHANGED"):
        service.admit("alice", "job", req)
    assert s.page("alice", "job") == []
