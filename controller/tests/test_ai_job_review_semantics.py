"""Persisted facts and public feasibility regressions; no free-prose truth claim."""

import json

import pytest

from c2hunter_controller.ai_investigation_contract import canonical_bytes
from c2hunter_controller.ai_job_investigation_runtime_schema import JobRun
from c2hunter_controller.ai_job_investigation_schema import pool_digest
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.job_review_helpers import execute
from tests.test_ai_job_investigation_source import flow, job


def save(*args, **kwargs):
    pass


MUTATIONS = [
    "metric_unknown_suffix",
    "metric_unit",
    "metric_unavailable_value",
    "metric_observed_rows",
    "metric_ref_name",
    "quality_status",
    "quality_source_rows",
    "zero_source_rows",
    "progress_source_rows",
    "progress_transport",
    "fake_limitations",
    "reason_disagreement",
    "rehashed_pool_impossible_rows",
]


@pytest.fixture(scope="module")
def produced():
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="x.test"), flow(destination_ip="2001:db8::2", domain="y.test")]))
    with pytest.MonkeyPatch.context() as patch:
        svc, outcome, run, calls = execute(repo, patch)
        assert run.status == "COMPLETED" and outcome.acknowledge_exit and len(calls) == 3
        assert run.coverage.investigated_peers == 3
        save("producer-completed", canonical_bytes(run.model_dump(mode="json")), status=run.status)
        evidence = svc.evidence(
            "alice", "job", run.id, run.result.assessments[0].evidence_quality[-1].evidence_id
        )
        save("producer-evidence", canonical_bytes(evidence.model_dump(mode="json")))
        assert svc.store.worker_exited(outcome.claim)
        yield run, evidence
    repo.close()


def mutate(data, axis):
    a = data["result"]["assessments"][0]
    m = a["facts"][0]
    q = a["evidence_quality"][0]
    if axis == "metric_unknown_suffix":
        m["ref"] = m["ref"].split(":")[0] + ":invented"
    elif axis == "metric_unit":
        m["unit"] = "bytes"
    elif axis == "metric_unavailable_value":
        m.update(value=0, observed_rows=0, unavailable_rows=1)
    elif axis == "metric_observed_rows":
        m["observed_rows"] = 8192
    elif axis == "metric_ref_name":
        m["name"] = "total_bytes"
        m["unit"] = "bytes"
    elif axis == "quality_status":
        q["status"] = "UNAVAILABLE"
    elif axis == "quality_source_rows":
        q["counts"].update(inspected=8192, not_observed=8192 - q["counts"]["matched"])
    elif axis == "zero_source_rows":
        for cov in (data["coverage"], data["result"]["coverage"]):
            cov["source_rows"] = 0
    elif axis == "progress_source_rows":
        for p in (data["progress"], data["result"]["progress"]):
            p["source_records"] = 0
    elif axis == "progress_transport":
        for p in (data["progress"], data["result"]["progress"]):
            p["model_calls"] = 0
            p["planning_responses"] = 0
    elif axis == "fake_limitations":
        data["result"]["limitations"] = ["WHOLE_JOB_BENIGN"]
    elif axis == "reason_disagreement":
        data["reason"] = "MODEL_INVALID"
    elif axis == "missing_source_version":
        del data["source"]["version"]
        del data["result"]["source"]["version"]
    elif axis == "missing_quality_scope_unavailable":
        del q["counts"]["scope_unavailable"]
    elif axis == "rehashed_pool_impossible_rows":
        p = data["pool"]["entries"][0]
        p.update(
            matched_rows=8192,
            eligible_rows=8192,
            suppressed_control_rows=0,
            eligibility_unavailable_rows=0,
        )
        data["pool"]["pool_sha256"] = pool_digest(data["pool"])
        data["result"]["pool_sha256"] = data["pool"]["pool_sha256"]
    else:
        raise AssertionError(axis)
    return data


@pytest.mark.parametrize("axis", MUTATIONS)
def test_impossible_public_wire_must_reject(produced, axis):
    data = mutate(produced[0].model_dump(mode="json"), axis)
    raw = canonical_bytes(data)
    try:
        JobRun.model_validate_json(raw)
        accepted = True
    except ValueError:
        accepted = False
    save(axis, raw, accepted=accepted, expected="reject", parser="JobRun.model_validate_json")
    assert not accepted, axis + " accepted impossible/missing public wire"


@pytest.mark.parametrize(
    "axis",
    ["metric_unavailable_value", "quality_status", "quality_source_rows", "fake_limitations"],
)
def test_ordinary_saved_result_corruption_must_reject(tmp_path, monkeypatch, axis):
    repo = SQLiteRepository(tmp_path / "stored.db")
    repo.save_job(job([flow(domain="x.test")]))
    svc, outcome, run, _ = execute(repo, monkeypatch)
    assert svc.store.worker_exited(outcome.claim)
    current = repo.connection.execute(
        "SELECT data FROM objects WHERE kind=? AND id=?", ("ai_job_investigation_state_v1", run.id)
    ).fetchone()
    state = json.loads(current[0])
    bad = mutate(run.model_dump(mode="json"), axis)
    state["result"] = bad["result"]
    raw = canonical_bytes(state)
    repo.connection.execute(
        "UPDATE objects SET data=? WHERE kind=? AND id=?",
        (raw.decode(), "ai_job_investigation_state_v1", run.id),
    )
    repo.connection.commit()
    try:
        try:
            observed = svc.get("alice", "job", run.id)
            accepted = True
        except ValueError:
            accepted = False
        save(
            "stored-" + axis,
            raw,
            accepted=accepted,
            expected="STORE_CORRUPT",
            entrypoint="JobInvestigationService.get",
            published=observed.model_dump(mode="json") if accepted else None,
        )
        assert not accepted, "real saved result read accepted " + axis
    finally:
        repo.close()
