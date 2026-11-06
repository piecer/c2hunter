"""Separate integration guard: stored evidence needs semantic validation."""

import pytest

from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_contract import SourceSnapshot, canonical_bytes
from c2hunter_controller.ai_investigation_evidence import EvidenceService
from c2hunter_controller.ai_investigation_store import InvestigationStoreError
from tests.test_ai_investigation_loop_review import backend, finish, obs, provider, request


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize(
    "corruption", ["negative-counts", "foreign-id", "foreign-body-id", "valid"]
)
def test_saved_evidence_semantics_use_frozen_custody(tmp_path, kind, corruption):
    with (
        backend(kind, tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        claim = store.claim("worker")
        saved = store.saved_input("alice", "job", run.id)
        frozen = SourceSnapshot.model_validate_json(saved["snapshot_json"])
        evidence = EvidenceService(frozen, run.scope).call("peer_overview", {})
        body = evidence.model_dump(mode="json")
        requested_id = evidence.evidence_id
        if corruption == "negative-counts":
            body["counts"]["retained"] = -1
        elif corruption == "foreign-id":
            requested_id = "f" * 64
        elif corruption == "foreign-body-id":
            body["evidence_id"] = "f" * 64
        claim = store.save_evidence(claim, requested_id, canonical_bytes(body))
        repo.delete_job("job")
        try:
            if corruption == "valid":
                assert service.evidence("alice", "job", run.id, requested_id) == evidence
                assert service.evidence("bob", "job", run.id, requested_id) is None
            else:
                with pytest.raises(InvestigationStoreError, match="STORE_CORRUPT"):
                    service.evidence("alice", "job", run.id, requested_id)
            assert http == []
        finally:
            assert store.worker_exited(claim)
