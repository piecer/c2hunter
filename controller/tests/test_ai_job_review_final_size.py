"""Complete final envelopes, not just model text, must fit the fixed cap."""

import pytest

from c2hunter_controller.ai_investigation_contract import canonical_bytes
from c2hunter_controller.repositories import MemoryRepository
from tests.job_review_helpers import execute, responder, verdict
from tests.test_ai_job_investigation_source import flow, job


@pytest.mark.parametrize("width", [100, 130, 160, 180])
def test_valid_model_final_size_cannot_strand_run(monkeypatch, width):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="x.test"), flow(destination_ip="2001:db8::2", domain="y.test")]))
    raws = []

    def respond(data, index):
        if index < 3:
            return responder(data, index)
        result = verdict(data, text="界" * width)
        for a in result["assessments"]:
            a["support"] *= 2
            a["counterevidence"] *= 2
            a["uncertainty"] = ["界" * width] * 2
            a["next_checks"] = ["界" * width] * 2
        raw = canonical_bytes(result)
        raws.append(raw)
        assert len(raw) <= 16384, "fixture must remain below actual gateway text cap"
        return raw.decode()

    try:
        svc, outcome, run, calls = execute(repo, monkeypatch, respond)
        assert outcome.acknowledge_exit, "bounded valid final stranded run: " + str(outcome.code)
        assert run.status in {"COMPLETED", "PARTIAL"}
        if width > 100:
            assert run.status == "PARTIAL" and run.result.reason == "FINAL_LIMIT"
            assert len(calls) == 4  # one repair only
        assert len(canonical_bytes(run.result.model_dump(mode="json"))) <= 16384
        assert run.coverage.investigated_peers == sum(
            a.mode == "MODEL_ASSISTED" for a in run.result.assessments
        )
        assert run.coverage.not_investigated_peers + run.coverage.investigated_peers == 3
        for step in svc.steps("alice", "job", run.id):
            if step.evidence_id:
                assert svc.evidence("alice", "job", run.id, step.evidence_id) is not None
        assert svc.store.worker_exited(outcome.claim)
    finally:
        repo.close()
