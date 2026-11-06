"""Authoritative public progress must share the status/revision state epoch."""

import pytest

from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_store import (
    BUDGETS,
    InvestigationRunStore,
    InvestigationStoreError,
)
from tests.test_ai_investigation_loop_review import backend, finish, obs, provider, request


@pytest.mark.parametrize("entrypoint", ["page", "replay", "get", "cancel"])
@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_public_snapshot_progress_never_reads_steps(tmp_path, monkeypatch, entrypoint, kind):
    with (
        backend(kind, tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        req = request(repo)
        queued, _ = service.admit("alice", "job", req)
        original = store.saved_input
        outcomes = []

        def complete_between_reads(*args):
            if not outcomes:
                outcomes.append(None)
                outcomes[0] = service.run_next("worker")
            return original(*args)

        monkeypatch.setattr(store, "saved_input", complete_between_reads)

        def forbidden_steps(*args, **kwargs):
            pytest.fail("mutable progress reconstructed from historical steps")

        monkeypatch.setattr(store, "steps", forbidden_steps)
        if entrypoint == "page":
            actual = service.page("alice", "job")[0]
        elif entrypoint == "replay":
            actual, created = service.admit("alice", "job", req)
            assert not created
        elif entrypoint == "cancel":
            actual = service.cancel("alice", "job", queued.id)
        else:
            actual = service.get("alice", "job", queued.id)
        assert actual.status == ("CANCELLED" if entrypoint == "cancel" else "QUEUED")
        assert (
            actual.progress.model_calls
            == actual.progress.tool_calls
            == actual.progress.transport_attempts
            == 0
        )
        assert actual.result is None
        if entrypoint == "cancel":
            assert outcomes == [None] and http == []
        else:
            assert actual.revision == 0 and len(http) == 1
            assert service.get("alice", "job", queued.id).status == "COMPLETED"
            assert store.worker_exited(outcomes[0].claim)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_store_progress_is_closed_detached_and_current(tmp_path, kind):
    with (
        backend(kind, tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, _),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        claim = store.claim("worker")
        claim = store.reserve(claim, model_calls=1, transport_attempts=1)
        projection = store.get("alice", "job", run.id)
        assert set(projection["progress"]) == set(BUDGETS)
        assert set(projection) == {
            "id",
            "owner_id",
            "job_id",
            "status",
            "revision",
            "created_at",
            "progress",
        }
        assert projection["revision"] == claim["revision"]
        projection["progress"]["model_calls"] = 5
        assert store.get("alice", "job", run.id)["progress"]["model_calls"] == 1
        cancelled = service.cancel("alice", "job", run.id)
        assert cancelled.progress.model_calls == cancelled.progress.transport_attempts == 1
        assert store.worker_exited(claim)


@pytest.mark.parametrize("key", list(BUDGETS))
@pytest.mark.parametrize("value", [True, "1", -1, 10**9, None])
def test_corrupt_counters_are_rejected_not_coerced(key, value):
    budgets = dict.fromkeys(BUDGETS, 0)
    budgets[key] = value
    with pytest.raises(InvestigationStoreError, match="STORE_CORRUPT"):
        InvestigationRunStore._public({"budgets": budgets})


@pytest.mark.parametrize(
    "budgets", [None, [], {}, {**dict.fromkeys(BUDGETS, 0), "lease_token": "SECRET"}]
)
def test_corrupt_budget_shape_is_closed(budgets):
    with pytest.raises(InvestigationStoreError, match="STORE_CORRUPT"):
        InvestigationRunStore._public({"budgets": budgets})
