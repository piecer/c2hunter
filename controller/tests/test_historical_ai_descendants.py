"""Real descendant publication fenced against current saved owner/lifecycle."""

from copy import deepcopy
from uuid import uuid4

import pytest

from c2hunter_controller import repositories
from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway
from c2hunter_controller.historical_ai_access import HistoricalAccessDenied, public_ai_access
from c2hunter_controller.historical_ai_storage import (
    HistoricalStorageError,
    materialize_historical_run,
)
from tests.test_historical_ai_access import repo as _repository_fixture
from tests.test_historical_ai_execution import admitted, corrupt_snapshot
from tests.test_historical_ai_storage import advance

repo = _repository_fixture


class StopPublication(RuntimeError):
    pass


def staged(repo, monkeypatch):
    run = admitted(repo)
    captured = []
    save = repo.save_ai_assessment

    def stop(value):
        captured.append(deepcopy(value))
        raise StopPublication()

    monkeypatch.setattr(repo, "save_ai_assessment", stop)
    with pytest.raises(StopPublication):
        AIAnalysisService(repo, FakeGateway()).execute(run["id"])
    monkeypatch.setattr(repo, "save_ai_assessment", save)
    run = repo.get_ai_run(run["id"])
    assert run["status"] == "VALIDATING"
    return run, captured[0]


def test_first_assessment_publication_carries_validated_owner_summary(repo, monkeypatch):
    run, proposal = staged(repo, monkeypatch)
    expected, _ = materialize_historical_run(run)
    stored = repo.save_ai_assessment(proposal)
    assert stored["baseline_mode"] == "historical"
    assert stored["baseline_summary"] == expected["baseline_summary"]
    assert repo.get_ai_assessment(proposal["id"]) == stored
    assert proposal.get("baseline_mode") is None


@pytest.mark.parametrize("cause", ["cancel", "delete", "bundle", "owner"])
def test_final_assessment_fence_rejects_late_or_forged_publication(repo, monkeypatch, cause):
    run, proposal = staged(repo, monkeypatch)
    if cause == "cancel":
        repo.save_ai_run(advance(run, "CANCELLED", 80))
    elif cause == "delete":
        if isinstance(repo, repositories.MemoryRepository):
            del repo.ai_runs[run["id"]]
            del repo._historical_admissions[run["id"]]
        else:
            repo.connection.execute("DELETE FROM ai_analysis_runs WHERE run_id=?", (run["id"],))
            repo.connection.commit()
    elif cause == "bundle":
        proposal["evidence_bundle"]["candidate"]["existing_c2hunter_score"] += 1
    else:
        corrupt_snapshot(repo, run)
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_assessment(proposal)
    if isinstance(repo, repositories.MemoryRepository):
        assert proposal["id"] not in repo.ai_assessments
    else:
        assert (
            repo.connection.execute(
                "SELECT 1 FROM ai_candidate_assessments WHERE assessment_id=?", (proposal["id"],)
            ).fetchone()
            is None
        )


def test_descendant_save_denial_ignores_compact_exception(repo, monkeypatch):
    _, proposal = staged(repo, monkeypatch)
    with public_ai_access(1, compact_runs=True), pytest.raises(HistoricalAccessDenied):
        repo.save_ai_assessment(proposal)


def test_same_identity_replay_cannot_change_owner_or_bundle(repo, monkeypatch):
    _, proposal = staged(repo, monkeypatch)
    saved = repo.save_ai_assessment(proposal)
    tampered = {**saved, "candidate_id": "different-candidate"}
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_assessment(tampered)
    assert repo.get_ai_assessment(saved["id"]) == saved


def drafts(repo, monkeypatch):
    from c2hunter_controller.ai_analysis import CandidateAssessment
    from c2hunter_controller.ai_artifacts import build_ai_artifacts

    run, proposal = staged(repo, monkeypatch)
    saved = repo.save_ai_assessment(proposal)
    _, bundles = materialize_historical_run(run)
    artifacts = build_ai_artifacts(
        assessment_id=saved["id"],
        ai_run_id=run["id"],
        analysis_job_id=run["analysis_job_id"],
        assessment=CandidateAssessment.model_validate(saved["assessment"]),
        bundle=bundles[0],
    )
    feedback = {
        "id": str(uuid4()),
        "assessment_id": saved["id"],
        "created_at": saved["created_at"],
        "verdict": "NEED_MORE_DATA",
        "corrected_confidence": None,
        "note": "investigate",
        "created_by": "analyst",
    }
    return run, saved, artifacts, feedback


def test_artifact_and_feedback_first_write_keep_historical_custody(repo, monkeypatch):
    run, assessment, artifacts, feedback = drafts(repo, monkeypatch)
    for kind, proposal in [("artifact", artifacts[0]), ("feedback", feedback)]:
        with public_ai_access(1, compact_runs=True), pytest.raises(HistoricalAccessDenied):
            getattr(repo, "save_ai_" + kind)(proposal)
        with public_ai_access(2):
            stored = getattr(repo, "save_ai_" + kind)(proposal)
            assert stored["baseline_mode"] == "historical"
            assert stored["baseline_summary"] == assessment["baseline_summary"]
    repo.save_ai_run(advance(run, "CANCELLED", 80))
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_artifact(artifacts[1])
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_feedback({**feedback, "id": str(uuid4())})


@pytest.mark.parametrize("fault", ["actor", "note", "verdict", "confidence", "owner"])
def test_feedback_rejects_unbounded_or_invalid_input_before_write(repo, monkeypatch, fault):
    run, _, _, feedback = drafts(repo, monkeypatch)
    if fault == "actor":
        feedback["created_by"] = "x" * 201
    if fault == "note":
        feedback["note"] = "x" * 5001
    if fault == "verdict":
        feedback["verdict"] = "anything"
    if fault == "confidence":
        feedback["corrected_confidence"] = 2
    if fault == "owner":
        corrupt_snapshot(repo, run)
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_feedback(feedback)
    if isinstance(repo, repositories.MemoryRepository):
        assert not repo.ai_feedback
    else:
        assert repo.connection.execute("SELECT count(*) FROM ai_feedback").fetchone()[0] == 0


def test_artifact_retry_never_resets_review_and_same_status_checks_owner(repo, monkeypatch):
    from c2hunter_controller.ai_artifacts import AIArtifactService

    run, _, artifacts, _ = drafts(repo, monkeypatch)
    draft = repo.save_ai_artifact(artifacts[0])
    run = repo.save_ai_run(advance(run, "COMPLETED", 100))
    service = AIArtifactService(repo)
    with public_ai_access(2):
        reviewed = service.review(
            draft["id"], status="APPROVED", reviewed_by="analyst", note="checked"
        )
    assert repo.save_ai_artifact(artifacts[0]) == reviewed
    with pytest.raises(HistoricalStorageError):
        repo.save_ai_artifact({**reviewed, "assessment_id": str(uuid4())})
    corrupt_snapshot(repo, run)
    with public_ai_access(2), pytest.raises(HistoricalStorageError):
        service.review(draft["id"], status="APPROVED", reviewed_by="analyst")
