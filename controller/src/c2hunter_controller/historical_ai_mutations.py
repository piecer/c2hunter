"""Historical mutation input admission and saved-only artifact inputs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import historical_ai_storage as custody
from .historical_ai import HistoricalAIError

if TYPE_CHECKING:
    from .ai_analysis import CandidateEvidenceBundle


def validate_mutation(actor: object, note: object, *, max_note: int) -> None:
    custody._identifier(actor)
    if type(note) is not str or not 1 <= len(note) <= max_note:
        raise HistoricalAIError("VALIDATION_ERROR")


def saved_bundle(repository: Any, assessment: dict[str, Any]) -> CandidateEvidenceBundle:
    from .historical_ai_descendants import checked_assessment

    run = repository.get_ai_run(assessment["ai_run_id"])
    custody.require(run is not None)
    checked_assessment(assessment, run)
    _, bundles = custody.materialize_historical_run(run)
    selected = [b for b in bundles if b.candidate.candidate_id == assessment["candidate_id"]]
    custody.require(len(selected) == 1)
    return selected[0]
