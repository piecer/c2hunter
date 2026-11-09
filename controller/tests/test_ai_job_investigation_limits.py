"""Definite bounded-storage refusal is not an ambiguous commit."""

from c2hunter_controller.ai_investigation_store import InvestigationStoreError
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted, service_for
from tests.test_ai_job_investigation_service import repository as _repository

repository = _repository


def test_definite_evidence_budget_refusal_publishes_partial(repository, monkeypatch):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        service = service_for(repository, gateway)
        queued, _ = service.admit("alice", "job", request_for())
        fired = []

        def refuse(*args, **kwargs):
            fired.append(True)
            raise InvestigationStoreError("EVIDENCE_BYTES_LIMIT")

        monkeypatch.setattr(service.store, "save_evidence", refuse)
        outcome = service.run_next("worker")
        assert fired == [True]
        assert outcome.acknowledge_exit and outcome.code == "EVIDENCE_BUDGET"
        run = service.get("alice", "job", queued.id)
        assert run.status == "PARTIAL" and run.coverage.not_investigated_peers == 1
        assert run.result.assessments == () and len(calls) == 1
