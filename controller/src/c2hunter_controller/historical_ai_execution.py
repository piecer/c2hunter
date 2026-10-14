"""Historical execution consumes admitted bundles, never current source data."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import ValidationError

from . import historical_ai as dto
from . import historical_ai_storage as custody
from ._baseline_storage import BaselineStorageError
from .ai_analysis import (
    AIAnalysisError,
    AIAnalysisState,
    CandidateAssessment,
    CandidateEvidenceBundle,
    validate_assessment_evidence,
)
from .ai_artifacts import build_ai_artifacts
from .ai_feedback import REVIEW_PRIORITY_VERSION, calculate_review_priority
from .ai_gateway import AIAnalysisCancelled, assess_candidate
from .baseline_admission import BaselineAdmission
from .c2_diagnostics import C2Diagnostics
from .historical_ai_builder import build_historical_target_snapshot

if TYPE_CHECKING:
    from .ai_analysis import AIAnalysisService


def create_saved(
    service: AIAnalysisService,
    *,
    analysis_job_id: str,
    actor: str,
    payload: dict[str, Any],
    admission: BaselineAdmission | None,
) -> tuple[dict[str, Any], bool]:
    from pydantic import TypeAdapter

    from .historical_baseline import Identifier

    TypeAdapter(Identifier).validate_python(analysis_job_id, strict=True)
    TypeAdapter(Identifier).validate_python(actor, strict=True)
    frozen = dto.FrozenAIAnalysisRunCreate.model_validate(payload)
    if frozen.baseline_mode != "historical":
        raise dto.HistoricalAIError("BASELINE_MODE_NOT_ALLOWED")
    fingerprint = dto.request_fingerprint(analysis_job_id, actor, frozen)
    existing = service.repository.get_ai_run_by_request(analysis_job_id, frozen.idempotency_key)
    if existing is not None:
        if custody.OWNER_KEY not in existing:
            raise dto.HistoricalAIError("BASELINE_IDEMPOTENCY_CONFLICT")
        custody.materialize_historical_run(existing)
        original = custody._original_request(custody.historical_header(existing))
        if original.request_fingerprint != fingerprint:
            raise dto.HistoricalAIError("BASELINE_IDEMPOTENCY_CONFLICT")
        return existing, False
    request = dto.HistoricalAdmissionRequest(
        analysis_job_id=analysis_job_id,
        payload=frozen,
        actor=actor,
        run_id=str(uuid.uuid4()),
        admitted_at=datetime.now(UTC),
        provider=service.gateway.provider,
        model_name=service.gateway.model,
        prompt_name=str(getattr(service.gateway, "prompt_name", "candidate_system")),
        prompt_version=str(getattr(service.gateway, "prompt_version", "1.1")),
        prompt_hash=str(
            getattr(
                service.gateway,
                "prompt_hash",
                hashlib.sha256(b"C2Hunter defensive candidate assessment prompt v1.1").hexdigest(),
            )
        ),
        input_schema_version="1.0",
        output_schema_version="1.0",
        request_fingerprint=fingerprint,
    )
    return service.repository.admit_historical_ai_run(
        request, build_historical_target_snapshot, admission=admission
    )


def execute_saved(service: AIAnalysisService, run: dict[str, Any]) -> dict[str, Any]:
    # Validate semantics even on terminal replay. Literal ownership alone is not
    # authorization to execute or return a successful receipt.
    try:
        view, bundles = custody.materialize_historical_run(run)
    except dto.HistoricalAIError:
        failure = custody.safe_historical_failure(run, datetime.now(UTC))
        return service.repository.save_ai_run(failure)
    if run["status"] in custody.TERMINAL:
        return run
    if run["status"] == "QUEUED":
        run = service._transition(run, AIAnalysisState.PREPARING, "loading saved evidence bundles")
    if run["status"] in custody.TERMINAL:
        return run
    candidates = {item["id"]: item for item in view["candidate_snapshots"]}
    run_id = run["id"]
    if run["status"] == "PREPARING":
        run = service._transition(run, AIAnalysisState.ANALYZING, "calling model gateway")
    retained = service.repository.list_ai_assessments(run_id)
    custody.require(len(retained) <= len(bundles))
    retained_by_id = {row["id"]: row for row in retained}
    expected_ids = {
        str(uuid.uuid5(uuid.UUID(run_id), "assessment:" + bundle.candidate.candidate_id))
        for bundle in bundles
    }
    custody.require(len(retained_by_id) == len(retained) and retained_by_id.keys() <= expected_ids)
    for position, bundle in enumerate(bundles):
        if run["status"] in custody.TERMINAL:
            return run
        assessment_id = str(
            uuid.uuid5(uuid.UUID(run_id), "assessment:" + bundle.candidate.candidate_id)
        )
        existing = retained_by_id.get(assessment_id)
        if existing is not None:
            custody.require(
                existing["ai_run_id"] == run_id
                and existing["analysis_job_id"] == run["analysis_job_id"]
                and existing["candidate_id"] == bundle.candidate.candidate_id
                and existing["evidence_bundle"] == bundle.model_dump(mode="json", by_alias=True)
                and bundle.metadata is not None
                and existing["evidence_bundle_hash"] == bundle.metadata.canonical_sha256
            )
            assessment = CandidateAssessment.model_validate(existing["assessment"])
            validate_assessment_evidence(assessment, bundle)
            _ensure_artifacts(service, existing, assessment, bundle)
            continue
        validations = sum(step["to_status"] == "VALIDATING" for step in run["transitions"])
        custody.require(validations in {position, position + 1})
        if run["status"] == "VALIDATING" and validations == position:
            run = service._transition(run, AIAnalysisState.ANALYZING, "analyzing next candidate")
            if run["status"] in custody.TERMINAL:
                return run
        diagnostics = C2Diagnostics()
        try:
            response = assess_candidate(
                service.gateway,
                bundle,
                should_cancel=lambda: (
                    (latest := service.repository.get_ai_run(run_id)) is not None
                    and latest["status"] == "CANCELLED"
                ),
                diagnostics=diagnostics,
            )
            diagnostics.stage = "SCHEMA"
            assessment = CandidateAssessment.model_validate(response)
            diagnostics.stage = "EVIDENCE_VALIDATION"
            validate_assessment_evidence(assessment, bundle)
            diagnostics.stage = "ARTIFACT_PREPARATION"
            build_ai_artifacts(
                assessment_id=assessment_id,
                ai_run_id=run["id"],
                analysis_job_id=run["analysis_job_id"],
                assessment=assessment,
                bundle=bundle,
            )
        except (BaselineStorageError, custody.HistoricalStorageError):
            raise
        except AIAnalysisCancelled:
            diagnostics.stage = "CANCELLED"
            diagnostics.report(run_id)
            return service._transition(run, AIAnalysisState.CANCELLED, "model request cancelled")
        except TimeoutError:
            if diagnostics.stage == "GATEWAY":
                diagnostics.stage = "TRANSPORT"
            diagnostics.report(run_id)
            return _failure(service, run, "MODEL_TIMEOUT", "model timeout")
        except (AIAnalysisError, ValidationError, TypeError, ValueError):
            diagnostics.report(run_id)
            return _failure(service, run, "MODEL_OUTPUT_INVALID", "model output rejected")
        except Exception:
            diagnostics.report(run_id)
            return _failure(service, run, "AI_ANALYSIS_FAILED", "AI analysis failed")
        # Persistence errors deliberately escape execute: an uncertain write is
        # not a validated FAILED outcome and must not be acknowledged by a worker.
        if run["status"] == "ANALYZING":
            run = service._transition(run, AIAnalysisState.VALIDATING, "validating model output")
        if run["status"] in custody.TERMINAL:
            return run
        candidate = candidates[bundle.candidate.candidate_id]
        stored = service.repository.save_ai_assessment(
            {
                "id": assessment_id,
                "ai_run_id": run["id"],
                "analysis_job_id": run["analysis_job_id"],
                "candidate_id": bundle.candidate.candidate_id,
                "external_ip": bundle.candidate.external_ip,
                "existing_c2hunter_score": bundle.candidate.existing_c2hunter_score,
                "prefilter_score": bundle.candidate.prefilter_score,
                "prefilter_score_version": bundle.candidate.prefilter_score_version,
                "discovery_origin": candidate.get("discovery_origin"),
                "behavior_anomaly_score": candidate.get("behavior_anomaly_score"),
                "review_priority": calculate_review_priority(
                    existing_score=bundle.candidate.existing_c2hunter_score,
                    prefilter_score=bundle.candidate.prefilter_score,
                    ai_verdict=assessment.candidate.verdict,
                    ai_confidence=assessment.candidate.confidence,
                ),
                "review_priority_version": REVIEW_PRIORITY_VERSION,
                "assessment": assessment.model_dump(mode="json"),
                "evidence_bundle": bundle.model_dump(mode="json", by_alias=True),
                "evidence_bundle_hash": bundle.metadata.canonical_sha256
                if bundle.metadata
                else None,
                "created_at": datetime.now(UTC).isoformat(),
            }
        )
        _ensure_artifacts(service, stored, assessment, bundle)
    if not bundles and run["status"] == "ANALYZING":
        run = service._transition(run, AIAnalysisState.VALIDATING, "no candidates selected")
    return service._transition(run, AIAnalysisState.COMPLETED, "all assessments validated")


def _ensure_artifacts(
    service: AIAnalysisService,
    stored: dict[str, Any],
    assessment: CandidateAssessment,
    bundle: CandidateEvidenceBundle,
) -> None:
    # Repository reads validate every descendant's owner, content and review.
    # HTTP regeneration legitimately appends fresh-ID drafts to this collection;
    # only the deterministic worker-owned set is reconciled below.
    retained = service.repository.list_ai_artifacts(stored["id"])
    existing = {item["id"]: item for item in retained}
    custody.require(len(retained) == len(existing))
    expected = build_ai_artifacts(
        assessment_id=stored["id"],
        ai_run_id=stored["ai_run_id"],
        analysis_job_id=stored["analysis_job_id"],
        assessment=assessment,
        bundle=bundle,
    )
    for artifact in expected:
        artifact["id"] = str(uuid.uuid5(uuid.UUID(stored["id"]), artifact["artifact_type"]))
        artifact["created_at"] = stored["created_at"]
    for artifact in expected:
        old = existing.get(artifact["id"])
        if old is None:
            service.repository.save_ai_artifact(artifact)
        else:
            # Redelivery completes missing drafts, never resets analyst review.
            custody.require(
                all(old.get(k) == v for k, v in artifact.items() if k != "approved_status")
            )


def _failure(
    service: AIAnalysisService, run: dict[str, Any], code: str, reason: str
) -> dict[str, Any]:
    run = {**run, "error_code": code, "error_message": custody.FAILURES[code]}
    return service._transition(run, AIAnalysisState.FAILED, reason)
