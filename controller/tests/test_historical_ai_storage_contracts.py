"""Shared Memory/SQLite custody regressions through production entry points."""

from copy import deepcopy
from datetime import timedelta

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_storage as custody
from c2hunter_controller import historical_generation as generation
from c2hunter_controller.baseline_admission import BaselineAdmission, BaselineLease
from c2hunter_controller.historical_ai_builder import (
    build_historical_target_snapshot,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.historical_ai_fixtures import START, job, review
from tests.test_historical_ai_storage import advance, prepared


@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    value = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "repo.db")
    )
    yield value
    value.close()


def test_persisted_generation_is_captured_by_actual_admission(repo):
    request, _, _ = prepared(repo)
    scope_id = request.payload.baseline_reference.scope_id
    reference_job = job(0, changed=False)
    repo.save_job(reference_job)
    source = repo.read_historical_source(
        reference_job["id"],
        purpose="APPROVAL",
        scope=repo.get_baseline_scope(scope_id).config,
        quality_review=review(),
    )
    repo.publish_baseline_source(
        scope_id,
        generation.ApprovalRequest(
            expected_revision=0,
            idempotency_key="publish-reference",
            source_job_id=reference_job["id"],
            source_binding_sha256=source.source_binding_sha256,
            normality="APPROVED_NORMAL",
            quality_review=review(),
            reason="Synthetic storage test reference",
        ),
        "fixture-admin",
        START + timedelta(days=4),
    )
    scope = repo.get_baseline_scope(scope_id)
    raw = request.to_mapping()
    raw["payload"]["baseline_reference"].update(
        expected_revision=scope.control_revision,
        generation_id=scope.active.generation_id,
    )
    raw["request_fingerprint"] = dto.request_fingerprint(
        raw["analysis_job_id"],
        raw["actor"],
        dto.FrozenAIAnalysisRunCreate.model_validate(raw["payload"]),
    )
    request = dto.HistoricalAdmissionRequest.model_validate(raw)
    original = deepcopy(repo.get_job(request.analysis_job_id))
    run, created = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    view, bundles = custody.materialize_historical_run(run)
    assert created and bundles and len(view["baseline_sources"]) == 1
    assert view["baseline_summary"]["generation_id"] == scope.active.generation_id
    assert repo.get_job(request.analysis_job_id) == original


def test_replay_conflict_lease_and_current_source_independence(repo):
    request, _, _ = prepared(repo)
    admission = BaselineAdmission()
    with BaselineLease(admission) as held:
        assert held.acquire()
        with pytest.raises(ValueError, match="BASELINE_BUSY"):
            repo.admit_historical_ai_run(
                request, build_historical_target_snapshot, admission=admission
            )
    run, _ = repo.admit_historical_ai_run(
        request, build_historical_target_snapshot, admission=admission
    )
    changed = request.to_mapping()
    changed["payload"]["language"] = "en"
    changed["request_fingerprint"] = dto.request_fingerprint(
        request.analysis_job_id,
        request.actor,
        dto.FrozenAIAnalysisRunCreate.model_validate(changed["payload"]),
    )
    with pytest.raises(ValueError, match="BASELINE_IDEMPOTENCY_CONFLICT"):
        repo.admit_historical_ai_run(
            dto.HistoricalAdmissionRequest.model_validate(changed), build_historical_target_snapshot
        )
    repo.save_job({"id": request.analysis_job_id, "status": "FAILED"})
    with BaselineLease(admission) as held:
        assert held.acquire()
        replay, created = repo.admit_historical_ai_run(
            request,
            lambda *_: pytest.fail("rebuilt replay"),
            admission=admission,
        )
    assert not created and replay == run


def test_generic_off_request_cannot_replay_historical_owner(repo):
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    off = {
        "id": "new-off-id",
        "analysis_job_id": request.analysis_job_id,
        "idempotency_key": request.payload.idempotency_key,
        "created_at": run["created_at"],
        "status": "QUEUED",
    }
    with pytest.raises(ValueError, match="BASELINE_IDEMPOTENCY_CONFLICT"):
        repo.create_ai_run(off)
    assert repo.get_ai_run(run["id"]) == run


def test_terminal_winner_and_five_candidate_lifecycle(repo):
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    for state, progress in (("PREPARING", 10), ("ANALYZING", 40)):
        run = repo.save_ai_run(advance(run, state, progress))
    for index in range(5):
        run = repo.save_ai_run(advance(run, "VALIDATING", 80))
        if index != 4:
            run = repo.save_ai_run(advance(run, "ANALYZING", 40))
    late = advance(run, "CANCELLED", 80)
    winner = repo.save_ai_run(advance(run, "COMPLETED", 100))
    assert repo.save_ai_run(late) == winner
    assert len(winner["transitions"]) <= 16
    for field in ("_historical_admission", "baseline_mode"):
        bad = deepcopy(late)
        del bad[field]
        with pytest.raises(ValueError):
            repo.save_ai_run(bad)
    assert repo.get_ai_run(run["id"]) == winner


def test_unreviewed_evaluation_admission_uses_real_parent_bridge(repo):
    from c2hunter_controller.historical_ai_builder import build_historical_target_snapshot
    from tests.historical_ai_fixtures import rule, world
    from tests.test_historical_ai_target import unreviewed_request

    inputs = world(kind="EVALUATION", sources=0, candidates=[rule()])
    request = unreviewed_request(inputs)
    repo.create_baseline_scope(inputs["scope"].config, "fixture-admin", START)
    repo.save_job(job())
    repo.save_candidates(job()["id"], [rule()])
    run, created = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    view, bundles = custody.materialize_historical_run(run)
    assert created and bundles
    assert view["baseline_summary"]["quality_assurance"] == "UNREVIEWED"
    assert "TARGET_REVIEW_REQUIRED" in view["baseline_summary"]["warnings"]
    assert run["_historical_admission"]["request_canonical_json"].find('"quality_review":null') >= 0
    assert repo.save_ai_run(advance(run, "PREPARING", 10))["status"] == "PREPARING"


def test_delete_retires_owner_and_late_save_does_not_resurrect(repo):
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    cancelled = repo.save_ai_run(advance(run, "CANCELLED", 0))
    assert repo.delete_job(request.analysis_job_id)
    assert repo.get_ai_run(run["id"]) is None
    assert (
        repo.get_ai_run_by_request(request.analysis_job_id, request.payload.idempotency_key) is None
    )
    with pytest.raises(ValueError):
        repo.save_ai_run(cancelled)
    assert repo.get_ai_run(run["id"]) is None
