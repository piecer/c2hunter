from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

REVIEW_PRIORITY_VERSION = "review-priority-v1"
FeedbackVerdict = Literal[
    "CONFIRM_C2",
    "CONFIRM_BENIGN",
    "NEED_MORE_DATA",
    "REJECT_EXPLANATION",
]


class AIFeedbackError(ValueError):
    """Raised when analyst feedback violates the append-only contract."""


class FeedbackRepository(Protocol):
    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None: ...
    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]: ...
    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]: ...


def calculate_review_priority(
    *,
    existing_score: float,
    prefilter_score: float,
    ai_verdict: str | None,
    ai_confidence: float | None,
) -> int:
    existing = min(100.0, max(0.0, float(existing_score)))
    prefilter = min(100.0, max(0.0, float(prefilter_score)))
    weights = {
        "LIKELY_C2": 1.0,
        "SUSPICIOUS": 0.7,
        "INCONCLUSIVE": 0.3,
        "LIKELY_BENIGN": 0.0,
    }
    if ai_verdict not in weights or ai_confidence is None:
        return min(100, max(0, round(0.6875 * existing + 0.3125 * prefilter)))
    confidence = min(1.0, max(0.0, float(ai_confidence)))
    ai_priority = 100 * confidence * weights[ai_verdict]
    return min(100, max(0, round(0.55 * existing + 0.25 * prefilter + 0.20 * ai_priority)))


class AIFeedbackService:
    def __init__(self, repository: FeedbackRepository) -> None:
        self.repository = repository

    def append(
        self,
        *,
        assessment_id: str,
        verdict: FeedbackVerdict,
        corrected_confidence: float | None,
        note: str,
        created_by: str,
    ) -> dict[str, Any]:
        if self.repository.get_ai_assessment(assessment_id) is None:
            raise AIFeedbackError("AI assessment not found")
        feedback = {
            "id": str(uuid.uuid4()),
            "assessment_id": assessment_id,
            "verdict": verdict,
            "corrected_confidence": corrected_confidence,
            "note": note,
            "created_by": created_by,
            "created_at": datetime.now(UTC).isoformat(),
        }
        return self.repository.save_ai_feedback(feedback)

    def list(self, assessment_id: str) -> list[dict[str, Any]]:
        if self.repository.get_ai_assessment(assessment_id) is None:
            raise AIFeedbackError("AI assessment not found")
        return self.repository.list_ai_feedback(assessment_id)
