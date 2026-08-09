from __future__ import annotations

import pytest

from c2hunter_controller.ai_feedback import (
    REVIEW_PRIORITY_VERSION,
    AIFeedbackError,
    AIFeedbackService,
    calculate_review_priority,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def assessment() -> dict[str, object]:
    return {
        "id": "assessment-1",
        "ai_run_id": "run-1",
        "created_at": "2026-08-09T00:00:00+00:00",
        "existing_c2hunter_score": 82,
        "prefilter_score": 40,
        "assessment": {
            "candidate": {
                "verdict": "SUSPICIOUS",
                "confidence": 0.72,
            }
        },
    }


def test_review_priority_formula_is_versioned_clamped_and_deterministic() -> None:
    priority = calculate_review_priority(
        existing_score=82,
        prefilter_score=40,
        ai_verdict="SUSPICIOUS",
        ai_confidence=0.72,
    )

    assert priority == 65
    assert REVIEW_PRIORITY_VERSION == "review-priority-v1"
    assert (
        calculate_review_priority(
            existing_score=200,
            prefilter_score=200,
            ai_verdict="LIKELY_C2",
            ai_confidence=1,
        )
        == 100
    )


def test_feedback_is_append_only_and_does_not_change_ai_assessment() -> None:
    repository = MemoryRepository()
    source = assessment()
    repository.save_ai_assessment(source)
    service = AIFeedbackService(repository)

    first = service.append(
        assessment_id="assessment-1",
        verdict="CONFIRM_C2",
        corrected_confidence=0.9,
        note="Confirmed from passive endpoint telemetry",
        created_by="alice",
    )
    second = service.append(
        assessment_id="assessment-1",
        verdict="NEED_MORE_DATA",
        corrected_confidence=None,
        note="Request a wider capture window",
        created_by="bob",
    )

    assert first["id"] != second["id"]
    assert [item["verdict"] for item in service.list("assessment-1")] == [
        "CONFIRM_C2",
        "NEED_MORE_DATA",
    ]
    assert repository.get_ai_assessment("assessment-1") == source


def test_feedback_rejects_unknown_assessment() -> None:
    with pytest.raises(AIFeedbackError, match="not found"):
        AIFeedbackService(MemoryRepository()).append(
            assessment_id="missing",
            verdict="CONFIRM_BENIGN",
            corrected_confidence=None,
            note="No corresponding service owner activity",
            created_by="analyst",
        )


def test_sqlite_persists_append_only_feedback(tmp_path) -> None:
    path = tmp_path / "feedback.sqlite3"
    repository = SQLiteRepository(path)
    repository.save_ai_assessment(assessment())
    AIFeedbackService(repository).append(
        assessment_id="assessment-1",
        verdict="CONFIRM_BENIGN",
        corrected_confidence=0.8,
        note="Known internal service owner confirmed the destination",
        created_by="alice",
    )
    repository.connection.close()

    reopened = SQLiteRepository(path)
    feedback = reopened.list_ai_feedback("assessment-1")

    assert len(feedback) == 1
    assert feedback[0]["verdict"] == "CONFIRM_BENIGN"
    assert feedback[0]["created_by"] == "alice"
