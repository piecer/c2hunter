"""LR01–LR03 behavioral regressions using real stores and loopback HTTP."""

from dataclasses import replace

import pytest

from c2hunter_controller.ai_investigation import InvestigationService
from tests.test_ai_investigation_loop_review import (
    backend,
    finish,
    obs,
    provider,
    request,
    row,
    tools,
)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize("verdict", ["SUSPICIOUS_C2", "BENIGN_HYPOTHESIS"])
@pytest.mark.parametrize("mixed", [False, True])
def test_usable_protocol_positive_control(tmp_path, kind, verdict, mixed):
    rows = [row(domain="updates.example.test")]
    if mixed:
        rows.append(row())
    with (
        backend(kind, tmp_path, rows) as (repo, store),
        provider(
            lambda body, n: tools("peer_protocol_observations")
            if n == 1
            else finish(obs(body)[0], verdict)
        ) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert actual.status == "COMPLETED" and actual.result.verdict == verdict
        assert len(http) == 2
        assert store.worker_exited(outcome.claim)


@pytest.mark.parametrize(
    "tool,rows",
    [
        ("peer_protocol_observations", [row()]),
        ("compare_peer_cohort", [row(source_ip="2001:db8::1")]),
    ],
)
def test_unusable_counterevidence_remains_limitation_with_one_repair(tmp_path, tool, rows):
    with (
        backend("sqlite", tmp_path, rows) as (repo, store),
        provider(
            lambda body, n: tools(tool) if n == 1 else finish(obs(body)[0], "SUSPICIOUS_C2")
        ) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert store.worker_exited(outcome.claim)
        assert len(http) == 3 and actual.progress.model_calls == 3
        assert actual.status == "PARTIAL" and actual.result.mode == "FACTS_ONLY"
        assert actual.result.reason == "COUNTEREVIDENCE_REQUIRED"
        assert "COUNTEREVIDENCE_UNAVAILABLE" in actual.result.limitations


@pytest.mark.parametrize("verdict", ["SUSPICIOUS_C2", "BENIGN_HYPOTHESIS"])
def test_usable_cohort_positive_control(tmp_path, verdict):
    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(
            lambda body, n: tools("compare_peer_cohort")
            if n == 1
            else finish(obs(body)[0], verdict)
        ) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert actual.status == "COMPLETED" and actual.result.verdict == verdict
        assert len(http) == 2 and store.worker_exited(outcome.claim)


@pytest.mark.parametrize("model", ["model-A", "model-B"])
def test_durable_identity_across_distinct_sqlite_repository_handles(tmp_path, model):
    from contextlib import closing

    from c2hunter_controller.ai_investigation_store import InvestigationRunStore
    from c2hunter_controller.repositories import SQLiteRepository

    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, replace(gateway, model="model-A"))
        req = request(repo)
        queued, _ = service.admit("alice", "job", req)
        repo.delete_job("job")
        with closing(SQLiteRepository(tmp_path / "review.db")) as successor_repo:
            successor_store = InvestigationRunStore(successor_repo)
            successor = InvestigationService(
                successor_repo, successor_store, replace(gateway, model=model)
            )
            replay, created = successor.admit("alice", "job", req)
            assert not created and replay == queued
            outcome = successor.run_next("successor")
            actual = successor.get("alice", "job", queued.id)
            assert successor_store.worker_exited(outcome.claim)
            assert actual.execution == actual.result.execution == queued.execution
            assert actual.progress == actual.result.progress
            if model == "model-A":
                assert actual.status == "COMPLETED" and len(http) == 1
                assert http[0]["model"] == "model-A"
            else:
                assert actual.status == "FAILED" and http == []
                assert actual.result.reason == "EXECUTION_IDENTITY_CHANGED"


def test_sqlite_successor_configuration_drift_must_not_send_http(tmp_path):
    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        a = InvestigationService(repo, store, replace(gateway, model="model-A"))
        req = request(repo)
        run, _ = a.admit("alice", "job", req)
        b = InvestigationService(repo, store, replace(gateway, model="model-B"))
        outcome = b.run_next("successor")
        actual = b.get("alice", "job", run.id)
        assert store.worker_exited(outcome.claim)
        assert http == [], "model-B received the model-A admitted request"
        assert actual.status == "FAILED" and actual.result.reason == "EXECUTION_IDENTITY_CHANGED"
        assert actual.execution.model == actual.result.execution.model == "model-A"
        repo.delete_job("job")
        replay, created = InvestigationService(repo, store, None).admit("alice", "job", req)
        assert not created and replay == actual
        changed_replay, created = b.admit("alice", "job", req)
        assert not created and changed_replay == actual
        assert b.page("alice", "job") == [actual]


@pytest.mark.parametrize("drift", ["prompt", "action", "final", "policy", "gateway-policy"])
def test_static_execution_contract_drift_refuses_http(tmp_path, monkeypatch, drift):
    import c2hunter_controller.ai_investigation as loop

    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        if drift == "prompt":
            monkeypatch.setattr(loop, "SYSTEM_PROMPT", loop.SYSTEM_PROMPT + " Changed.")
        elif drift == "action":
            original = loop.ACTION.json_schema
            monkeypatch.setattr(
                loop.ACTION, "json_schema", lambda: {**original(), "description": "changed"}
            )
        elif drift == "final":
            original = loop.Finish.model_json_schema
            monkeypatch.setattr(
                loop.Finish, "model_json_schema", lambda: {**original(), "description": "changed"}
            )
        elif drift == "policy":
            monkeypatch.setattr(loop, "MAX_PLANNING_RESPONSES", 3)
        else:
            monkeypatch.setattr(loop.gateway_contract, "MAX_JSON_NODES", 8191)
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert http == [] and actual.status == "FAILED"
        assert actual.execution == actual.result.execution == run.execution
        assert outcome.code == actual.result.reason == "EXECUTION_IDENTITY_CHANGED"
        assert actual.progress.model_calls == actual.progress.transport_attempts == 0
        assert store.worker_exited(outcome.claim)


@pytest.mark.parametrize(
    "setting,value",
    [
        ("temperature", 0.5),
        ("context_tokens", 32768),
        ("max_output_tokens", 4096),
        ("timeout_seconds", 60),
        ("server_allow_remote", True),
    ],
)
def test_effective_setting_drift(tmp_path, setting, value):
    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        other = InvestigationService(repo, store, replace(gateway, **{setting: value}))
        outcome = other.run_next("worker")
        assert http == [] and outcome.code == "EXECUTION_IDENTITY_CHANGED"
        assert other.get("alice", "job", run.id).execution == run.execution
        assert store.worker_exited(outcome.claim)


def test_bound_gateway_cannot_be_retargeted_midrun(tmp_path):
    replacement = []

    def respond(body, n):
        if n == 1:
            service.gateway = replacement[0]
            return tools("peer_protocol_observations")
        return finish(obs(body)[0], "SUSPICIOUS_C2")

    with (
        backend("sqlite", tmp_path, [row(domain="update.example.test")]) as (repo, store),
        provider(respond) as (a, http_a),
        provider(lambda body, n: finish(obs(body)[0])) as (b, http_b),
    ):
        replacement.append(replace(b, model="model-B"))
        service = InvestigationService(repo, store, replace(a, model="model-A"))
        run, _ = service.admit("alice", "job", request(repo))
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert actual.status == "COMPLETED" and outcome.code is None
        assert len(http_a) == 2 and http_b == []
        assert all(body["model"] == "model-A" for body in http_a)
        assert actual.execution == actual.result.execution == run.execution
        assert store.worker_exited(outcome.claim)


def test_endpoint_drift_refuses_other_provider(tmp_path):
    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (a, http_a),
        provider(lambda body, n: finish(obs(body)[0])) as (b, http_b),
    ):
        service = InvestigationService(repo, store, a)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = InvestigationService(repo, store, b).run_next("worker")
        assert http_a == http_b == [] and outcome.code == "EXECUTION_IDENTITY_CHANGED"
        assert service.get("alice", "job", run.id).execution == run.execution
        assert store.worker_exited(outcome.claim)


def test_inflight_prompt_drift_stops_further_model_work(tmp_path, monkeypatch):
    import c2hunter_controller.ai_investigation as loop

    def respond(body, n):
        monkeypatch.setattr(loop, "SYSTEM_PROMPT", loop.SYSTEM_PROMPT + " Changed.")
        return tools("peer_protocol_observations")

    with backend("sqlite", tmp_path) as (repo, store), provider(respond) as (gateway, http):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert len(http) == 1 and outcome.code == "EXECUTION_IDENTITY_CHANGED"
        assert actual.status == "PARTIAL" and actual.result.mode == "FACTS_ONLY"
        assert actual.execution == actual.result.execution == run.execution
        assert store.worker_exited(outcome.claim)


def test_credential_rotation_is_not_identity_and_secrets_never_leave_custody(tmp_path):
    import json

    from c2hunter_controller.ai_investigation import _execution_identity

    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        a = replace(gateway, api_key="DO_NOT_EXPORT_KEY_ONE")
        b = replace(gateway, api_key="DO_NOT_EXPORT_KEY_TWO")
        assert _execution_identity(a) == _execution_identity(b)
        service = InvestigationService(repo, store, a)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = InvestigationService(repo, store, b).run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert len(http) == 1 and actual.status == "COMPLETED"
        binding = store.saved_input("alice", "job", run.id)["binding_json"]
        assert set(json.loads(binding)) == {"version", "source", "execution"}
        public = actual.model_dump_json() + binding.decode()
        for secret in [
            "DO_NOT_EXPORT",
            gateway.base_url,
            "api_key",
            "Authorization",
            "lease_token",
            "snapshot_json",
        ]:
            assert secret not in public
        assert store.worker_exited(outcome.claim)


def test_execution_identity_closed_utf8_and_settings_validation(tmp_path):
    from pydantic import ValidationError

    from c2hunter_controller.ai_investigation import _execution_identity
    from c2hunter_controller.ai_investigation_schema import ExecutionIdentity

    with provider(lambda body, n: finish(obs(body)[0])) as (gateway, _):
        identity = _execution_identity(replace(gateway, model="한" * 170 + "ab"))
        assert len(identity.model.encode()) == 512
        data = identity.model_dump(mode="json")
        for model in ["한" * 171, "x\n", "", "\ud800"]:
            with pytest.raises(ValueError):
                ExecutionIdentity.model_validate({**data, "model": model})
        with pytest.raises(ValidationError):
            ExecutionIdentity.model_validate({**data, "endpoint": gateway.base_url})
        for value in [float("nan"), float("inf"), -1, True, "0.1"]:
            with pytest.raises(ValidationError):
                ExecutionIdentity.model_validate(
                    {**data, "model_settings": {**data["model_settings"], "temperature": value}}
                )


def test_legacy_source_only_custody_is_not_fabricated(tmp_path):
    from c2hunter_controller.ai_investigation_contract import canonical_bytes
    from c2hunter_controller.ai_investigation_schema import InvestigationRequest
    from c2hunter_controller.ai_investigation_store import InvestigationStoreError

    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        req = InvestigationRequest.model_validate(request(repo))
        snapshot = repo.read_investigation_source("job")
        run, _ = store.admit(
            owner_id="alice",
            job_id="job",
            idempotency_key=req.idempotency_key,
            request_json=canonical_bytes(req.model_dump(mode="json")),
            binding_json=canonical_bytes(snapshot.binding.model_dump(mode="json")),
            snapshot_json=canonical_bytes(snapshot.model_dump(mode="json")),
        )
        service = InvestigationService(repo, store, gateway)
        with pytest.raises(InvestigationStoreError, match="STORE_CORRUPT"):
            service.get("alice", "job", run["id"])
        outcome = service.run_next("worker")
        assert outcome.code == "STORE_CORRUPT" and not outcome.acknowledge_exit and http == []
        assert store.worker_exited(outcome.claim)
