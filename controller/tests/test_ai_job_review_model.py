"""Persistent model-boundary regressions from the independent phase-three review."""

import json

import pytest

from c2hunter_controller.ai_job_investigation_runtime_schema import parse_action
from c2hunter_controller.ai_job_investigation_store import initialize_job_investigation_store
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_job_investigation_service import request_for, scripted, service_for
from tests.test_ai_job_investigation_source import flow, job


@pytest.mark.parametrize("action", [[], {}, ["finish"], None, True, 1, "unknown"])
def test_malformed_action_has_one_repair_and_bounded_partial(monkeypatch, action):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="x.test")]))
    initialize_job_investigation_store(repo)
    raw = json.dumps({"action": action})
    with pytest.raises(ValueError):
        parse_action(raw)
    try:
        with scripted(monkeypatch, lambda *_: raw) as (gateway, calls):
            svc = service_for(repo, gateway)
            run, _ = svc.admit("alice", "job", request_for())
            outcome = svc.run_next("review")
            saved = svc.get("alice", "job", run.id)
            assert outcome.acknowledge_exit
            assert saved.status == "PARTIAL"
            assert saved.result.reason == "MODEL_INVALID"
            assert saved.coverage.investigated_peers == 0
            assert len(calls) == 2
            assert svc.store.worker_exited(outcome.claim)
    finally:
        repo.close()
