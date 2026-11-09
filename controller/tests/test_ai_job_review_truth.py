"""Saved truth, bounded source reuse and feasible producer sibling controls."""

import json

import pytest

from c2hunter_controller.ai_investigation_contract import canonical_bytes
from c2hunter_controller.ai_investigation_evidence import EvidenceService
from c2hunter_controller.ai_job_investigation_runtime_schema import JobRun, parse_job_evidence
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.job_review_helpers import execute, responder
from tests.test_ai_job_investigation_service import request_for
from tests.test_ai_job_investigation_source import flow, job


@pytest.mark.parametrize("entrypoint", ["get", "page", "replay"])
def test_coherent_but_invented_saved_fact_rejects_every_read(tmp_path, monkeypatch, entrypoint):
    repo = SQLiteRepository(tmp_path / "saved.db")
    repo.save_job(job([flow(domain="x.test")]))
    try:
        svc, outcome, run, _ = execute(repo, monkeypatch)
        assert svc.store.worker_exited(outcome.claim)
        row = repo.connection.execute(
            "SELECT data FROM objects WHERE kind=? AND id=?",
            ("ai_job_investigation_state_v1", run.id),
        ).fetchone()
        state = json.loads(row[0])
        state["result"]["assessments"][0]["facts"][0]["value"] += 1
        repo.connection.execute(
            "UPDATE objects SET data=? WHERE kind=? AND id=?",
            (canonical_bytes(state).decode(), "ai_job_investigation_state_v1", run.id),
        )
        repo.connection.commit()
        # Schema consistency is not source truth. The complete service must reject.
        raw = run.model_dump(mode="json")
        raw["result"] = state["result"]
        JobRun.model_validate_json(canonical_bytes(raw))
        with pytest.raises(ValueError, match="STORE_CORRUPT"):
            if entrypoint == "get":
                svc.get("alice", "job", run.id)
            elif entrypoint == "page":
                svc.page("alice", "job")
            else:
                svc.admit("alice", "job", request_for("probe"))
    finally:
        repo.close()


def test_result_read_uses_one_saved_preparation_no_live_source(monkeypatch):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="x.test"), flow(destination_ip="2001:db8::2")]))
    try:
        svc, outcome, run, _ = execute(repo, monkeypatch)
        saved_input = svc.store.saved_input
        reads = []

        def saved(*args):
            reads.append(args)
            return saved_input(*args)

        monkeypatch.setattr(svc.store, "saved_input", saved)
        monkeypatch.setattr(
            repo, "read_job_investigation_source", lambda *a, **k: pytest.fail("live source read")
        )
        assert svc.get("alice", "job", run.id) == run
        assert len(reads) == 1
        assert svc.store.worker_exited(outcome.claim)
    finally:
        repo.close()


@pytest.mark.parametrize("kind", ["source_version", "quality_count", "evidence_count"])
def test_legacy_leaf_default_compatibility(kind, monkeypatch):
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="x.test")]))
    try:
        svc, outcome, run, _ = execute(repo, monkeypatch)
        raw = run.model_dump(mode="json")
        if kind == "source_version":
            del raw["source"]["version"]
            del raw["result"]["source"]["version"]
        elif kind == "quality_count":
            del raw["result"]["assessments"][0]["evidence_quality"][0]["counts"][
                "scope_unavailable"
            ]
        else:
            eid = run.result.assessments[0].evidence_quality[0].evidence_id
            evidence = svc.evidence("alice", "job", run.id, eid)
            value = evidence.model_dump(mode="json")
            del value["counts"]["scope_unavailable"]
            assert parse_job_evidence(canonical_bytes(value)) == evidence
        assert JobRun.model_validate_json(canonical_bytes(raw)) == run
        assert svc.store.worker_exited(outcome.claim)
    finally:
        repo.close()


@pytest.mark.parametrize("axis", ["null_to_zero", "impossible_rows", "unknown_ref"])
def test_complete_evidence_service_rejects_adapter_only_inconsistency(axis):
    repo = MemoryRepository()
    raw = flow(domain="x.test")
    del raw["total_bytes"]
    repo.save_job(job([raw]))
    try:
        prep = repo.read_job_investigation_source("job")
        tools = EvidenceService(prep.snapshot, prep.scope_for_peer(prep.pool.entries[0].peer_id))
        evidence = tools.call("peer_overview", {})
        value = evidence.model_dump(mode="json")
        metric = next(m for m in value["metrics"] if m["name"] == "total_bytes")
        if axis == "null_to_zero":
            metric["value"] = 0
        elif axis == "impossible_rows":
            metric["observed_rows"] = 8192
        else:
            metric["ref"] = evidence.evidence_id + ":invented"
        with pytest.raises(ValueError):
            tools.validate_evidence(parse_job_evidence(canonical_bytes(value)))
    finally:
        repo.close()


def test_cohort_unavailable_with_observed_own_counts_is_feasible(monkeypatch):
    repo = MemoryRepository()
    # Unknown protocol prevents establishing a comparable cohort, not own row counts.
    repo.save_job(job([flow(protocol="OTHER", domain="x.test")]))

    def respond(data, index):
        if index == 1:
            return responder(data, index)
        if index == 2:
            return dict(
                action="request_tools",
                tools=[
                    dict(peer_id=p, tool="compare_peer_cohort", arguments={})
                    for p in data["selection"]["peer_ids"]
                ],
            )
        return dict(
            action="finish",
            assessments=[
                dict(
                    peer_id=p,
                    verdict="NEEDS_REVIEW",
                    support=[],
                    counterevidence=[],
                    uncertainty=["Unknown cohort"],
                    next_checks=[],
                )
                for p in data["selection"]["peer_ids"]
            ],
        )

    try:
        svc, outcome, run, _ = execute(repo, monkeypatch, respond)
        assert run.status == "COMPLETED"
        assert any(
            q.tool == "compare_peer_cohort" and q.status == "UNAVAILABLE" and q.counts.retained > 0
            for a in run.result.assessments
            for q in a.evidence_quality
        )
        assert JobRun.model_validate_json(canonical_bytes(run.model_dump(mode="json"))) == run
        assert svc.store.worker_exited(outcome.claim)
    finally:
        repo.close()
