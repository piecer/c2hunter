import json

from c2hunter_controller.ai_investigation_contract import canonical_bytes
from c2hunter_controller.ai_investigation_http import encoded
from c2hunter_controller.repositories import SQLiteRepository
from tests.job_review_helpers import execute
from tests.test_ai_job_investigation_source import flow, job
from tests.test_ai_job_review_semantics import save

OBSERVATIONS = {}


def test_unobserved_total_bytes_cannot_become_saved_fact_zero(tmp_path, monkeypatch):
    repo = SQLiteRepository(tmp_path / "null-zero.db")
    raw = flow(domain="x.test")
    del raw["total_bytes"]
    repo.save_job(job([raw]))

    def respond(data, index):
        if index == 1:
            return dict(
                action="select_peers",
                pool_sha256=data["pool"]["pool_sha256"],
                peer_ids=[data["pool"]["entries"][0]["peer_id"]],
            )
        return {"action": "finish", "assessments": []}

    svc, outcome, run, calls = execute(repo, monkeypatch, respond)
    assert outcome.acknowledge_exit and run.status == "PARTIAL"
    metric = next(m for m in run.result.assessments[0].facts if m.name == "total_bytes")
    assert metric.value is None and metric.observed_rows == 0 and metric.unavailable_rows == 1
    assert svc.store.worker_exited(outcome.claim)
    state = json.loads(
        repo.connection.execute(
            "SELECT data FROM objects WHERE kind=? AND id=?",
            ("ai_job_investigation_state_v1", run.id),
        ).fetchone()[0]
    )
    m = next(m for m in state["result"]["assessments"][0]["facts"] if m["name"] == "total_bytes")
    m["value"] = 0
    repo.connection.execute(
        "UPDATE objects SET data=? WHERE kind=? AND id=?",
        (canonical_bytes(state).decode(), "ai_job_investigation_state_v1", run.id),
    )
    repo.connection.commit()
    evidence_id = metric.ref.split(":")[0]
    evidence = svc.evidence("alice", "job", run.id, evidence_id)
    assert next(m for m in evidence.metrics if m.name == "total_bytes").value is None
    try:
        try:
            bad = svc.get("alice", "job", run.id)
            accepted = True
        except ValueError:
            accepted = False
        save(
            "saved-unobserved-zero",
            encoded(bad).body if accepted else canonical_bytes(state),
            accepted=accepted,
            source_metric=metric.model_dump(mode="json"),
            evidence_metric=next(m for m in evidence.metrics if m.name == "total_bytes").model_dump(
                mode="json"
            ),
        )
        assert not accepted, (
            "serializer emits value=0 although saved source/evidence prove unobserved (null)"
        )
    finally:
        repo.close()
