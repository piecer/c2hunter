"""No-I/O composition of accepted source, comparison, selector and finalizer.

All identities/time/provider facts are caller values. No repository, gateway,
clock or queue capability is accepted or acquired. This is not a Python sandbox.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from typing import Any

from c2hunter_analysis import behavior_baseline as b
from c2hunter_analysis.behavior_discovery import BehaviorCandidate
from pydantic import ValidationError

from . import ai_analysis as ai
from . import ai_discovery
from . import historical_ai as dto
from . import historical_baseline as h
from . import historical_evidence as e
from . import historical_generation as g
from .historical_read import HistoricalAITargetSnapshot, HistoricalReadSnapshot
from .historical_source import (
    SourceProjection,
    UnreviewedEvaluationTarget,
    checked_evaluation_target,
    compare_evaluation_target,
    source_build_input,
    target_vetoes,
)


def _history_candidate(job_id: str, candidate: BehaviorCandidate) -> dict[str, Any]:
    return {
        "id": "ai-behavior-"
        + hashlib.sha256(f"{job_id}:{candidate.candidate_ip}".encode()).hexdigest()[:16],
        "candidate_ip": candidate.candidate_ip,
        "candidate_kind": "C2",
        "score": 0,
        "behavior_anomaly_score": candidate.anomaly_score,
        "internal_hosts": list(candidate.internal_hosts),
        "protocols": list(candidate.protocols),
        "ports": list(candidate.ports),
        "first_seen": candidate.first_seen.isoformat(),
        "last_seen": candidate.last_seen.isoformat(),
        "source": "BEHAVIOR_DISCOVERY",
        "evidence": [],
    }


def build_historical_snapshot(value: dto.HistoricalAdmissionInput) -> dto.HistoricalRunSnapshot:
    """Build one immutable QUEUED admission value; caller owns persistence/admission."""
    try:
        return _build(value)
    except dto.HistoricalAIError:
        raise
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        allowed = {
            "BASELINE_SOURCE_INVALID",
            "BASELINE_SOURCE_LIMIT",
            "BASELINE_PROFILE_LIMIT",
            "BASELINE_SCOPE_MISMATCH",
            "BASELINE_GENERATION_MISMATCH",
            "BASELINE_GENERATION_LIMIT",
            "BASELINE_CANDIDATE_LIMIT",
            "BASELINE_RUN_SNAPSHOT_LIMIT",
            "BASELINE_SOURCE_STATE",
        }
        code = getattr(exc, "code", str(exc))
        raise dto.HistoricalAIError(code if code in allowed else "BASELINE_SOURCE_INVALID") from exc


def _build(value: dto.HistoricalAdmissionInput) -> dto.HistoricalRunSnapshot:
    if type(value) is not dto.HistoricalAdmissionInput:
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    dto.check_closed_model(value)
    if type(value.candidates) is not tuple or type(value.target) is not SourceProjection:
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    if len(value.candidates) > ai_discovery.MAX_SELECTION_CANDIDATES:
        raise dto.HistoricalAIError("BASELINE_CANDIDATE_LIMIT")
    if type(value.target.original) is not h.OriginalJobProjection:
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    if len(value.target.original.flow_records) > 8192 or len(value.target.strict_flows) > 8192:
        raise dto.HistoricalAIError("BASELINE_SOURCE_LIMIT")
    # Existing upstream readers admit complete stored bytes. Here meter the
    # already-projected originals again, without thawing or copying candidates.
    budget = h._OriginalBudget(4 * 1024 * 1024, frozen=True)
    for projected in value.candidates:
        if type(projected) is not h.CandidateProjection:
            raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
        try:
            budget.visit(projected.fields)
        except ValueError as exc:
            if str(exc) == "BASELINE_SOURCE_LIMIT":
                raise dto.HistoricalAIError("BASELINE_CANDIDATE_LIMIT") from exc
            raise
    request = dto.checked_request(value.request)
    scope = g.ScopeView.model_validate(value.scope)
    snapshot = g._checked(
        HistoricalReadSnapshot,
        HistoricalReadSnapshot(
            source=value.target,
            candidates=value.candidates,
            source_binding_sha256=value.target_source_binding_sha256,
        ),
    )
    if tuple(c.position for c in snapshot.candidates) != tuple(
        sorted(c.position for c in snapshot.candidates)
    ):
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    value = dto.HistoricalAdmissionInput(
        request=request,
        target=snapshot.source,
        candidates=snapshot.candidates,
        scope=scope,
        generation=value.generation,
        target_source_binding_sha256=snapshot.source_binding_sha256,
    )
    return _compose(
        value.request,
        value.target,
        value.candidates,
        value.scope,
        value.generation,
        value.target_source_binding_sha256,
    )


def build_historical_target_snapshot(
    request: dto.HistoricalAdmissionRequest,
    target: HistoricalAITargetSnapshot,
    scope: g.ScopeView,
    generation: g.GenerationDocument | None,
) -> dto.HistoricalRunSnapshot:
    """AI consumer entry; reviewed source/publication contracts remain closed."""
    if type(target) is not HistoricalAITargetSnapshot:
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    request = dto.checked_request(request)
    if type(target.source) is SourceProjection:
        return build_historical_snapshot(
            dto.HistoricalAdmissionInput(
                request=request,
                target=target.source,
                candidates=target.candidates,
                scope=scope,
                generation=generation,
                target_source_binding_sha256=target.source_binding_sha256,
            )
        )
    if type(target.candidates) is not tuple:
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    if len(target.candidates) > ai_discovery.MAX_SELECTION_CANDIDATES:
        raise dto.HistoricalAIError("BASELINE_CANDIDATE_LIMIT")
    budget = h._OriginalBudget(4 * 1024 * 1024, frozen=True)
    candidates = []
    for candidate in target.candidates:
        if type(candidate) is not h.CandidateProjection:
            raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
        g._snapshot_preflight(candidate, h.CandidateProjection)
        budget.visit(candidate.fields)
        candidates.append(h.CandidateProjection.model_validate(g._unmodel(candidate)))
    if tuple(c.position for c in candidates) != tuple(sorted(c.position for c in candidates)):
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    if not isinstance(target.source, UnreviewedEvaluationTarget):
        raise dto.HistoricalAIError("BASELINE_SOURCE_INVALID")
    checked = checked_evaluation_target(target.source)
    scope = g.ScopeView.model_validate(scope)
    if generation is not None:
        generation = g.GenerationDocument.model_validate(generation)
    ref = request.payload.baseline_reference
    if ref is None or ref.quality_review is not None or checked.structural.scope != scope.config:
        raise dto.HistoricalAIError("BASELINE_SCOPE_MISMATCH")
    return _compose(
        request, checked, tuple(candidates), scope, generation, target.source_binding_sha256
    )


def _compose(
    request: dto.HistoricalAdmissionRequest,
    target_value: SourceProjection | UnreviewedEvaluationTarget,
    candidates: tuple[h.CandidateProjection, ...],
    scope: g.ScopeView,
    generation: g.GenerationDocument | None,
    source_binding_sha256: str,
) -> dto.HistoricalRunSnapshot:
    target = (
        target_value.structural.source
        if isinstance(target_value, UnreviewedEvaluationTarget)
        else target_value.source_binding()
    )
    reference_request = request.payload.baseline_reference
    if reference_request is None:
        raise dto.HistoricalAIError("BASELINE_MODE_NOT_ALLOWED")
    if reference_request.expected_revision != scope.control_revision:
        raise dto.HistoricalAIError("BASELINE_REVISION_CONFLICT")
    if reference_request.scope_id != scope.config.scope_id:
        raise dto.HistoricalAIError("BASELINE_SCOPE_MISMATCH")
    active_id = scope.active.generation_id if scope.active else None
    if reference_request.generation_id != active_id:
        raise dto.HistoricalAIError("BASELINE_GENERATION_MISMATCH")
    if (generation is None) != (scope.active is None):
        raise dto.HistoricalAIError("BASELINE_GENERATION_MISMATCH")
    if generation is not None and (
        g.generation_view(generation) != scope.active
        or generation.publication_revision > scope.control_revision
        or generation.published_at > request.admitted_at
        or any(source.approved_at > request.admitted_at for source in generation.sources)
    ):
        raise dto.HistoricalAIError("BASELINE_GENERATION_MISMATCH")
    if generation is not None:
        dto.validate_receipt_quality(generation.sources)
    if target.original.id != request.analysis_job_id:
        raise dto.HistoricalAIError("BASELINE_SOURCE_CHANGED")
    binding = h.source_binding_sha256(target, purpose="COMPARISON", candidates=candidates)
    if (
        binding != source_binding_sha256
        or binding != reference_request.target_source_binding_sha256
    ):
        raise dto.HistoricalAIError("BASELINE_SOURCE_CHANGED")
    reference = g.generation_reference(generation, scope=scope.config) if generation else None
    if isinstance(target_value, UnreviewedEvaluationTarget):
        comparison = compare_evaluation_target(target_value, reference=reference)
    else:
        build = source_build_input(
            target_value,
            scope=scope.config,
            quality_review=reference_request.quality_review,
            source_receipt_id=None,
        )
        comparison = b.compare_behavior_windows(
            target=b.build_behavior_windows(build),
            reference=reference,
            scope=build.scope,
            target_observation=b.ObservationIdentity(
                target.root_identity,
                target.original.dataset_id,
                target_value.feature_observation_sha256,
            ),
            target_event_start=target.event_start,
            target_event_end=target.event_end,
            target_vetoes=target_vetoes(
                target_value, quality_review=reference_request.quality_review
            ),
        )
    mapped = b.baseline_comparison_to_mapping(comparison)
    comparisons = tuple(
        e.ProfileComparison.model_validate_json(h.canonical_json(row))
        for row in mapped["comparisons"]
    )
    history_keys = {
        row["candidate"]["candidate_ip"]: row["comparison_key"] for row in mapped["candidates"]
    }
    historical = {item.candidate.candidate_ip: item for item in comparison.candidates}
    original = h.thaw_original_job(target.original)
    existing = [h._mapping(h.thaw_original_json(c.fields)) for c in candidates]
    try:
        legacy, local, local_result = ai._shadow_preselection(original, existing)
    except ai.AIAnalysisError as exc:
        if str(exc) in {
            "generated peer pool exceeds its admission limit",
            "behavior discovery candidate pool exceeds its admission limit",
        }:
            raise dto.HistoricalAIError("BASELINE_CANDIDATE_LIMIT") from exc
        raise
    merged = {item["candidate_ip"]: item for item in local}
    for peer_ip, item in historical.items():
        if peer_ip in merged:
            merged[peer_ip]["behavior_anomaly_score"] = max(
                merged[peer_ip]["behavior_anomaly_score"], item.candidate.anomaly_score
            )
        else:
            merged[peer_ip] = _history_candidate(request.analysis_job_id, item.candidate)
    if len(legacy) + len(merged) > ai_discovery.MAX_SELECTION_CANDIDATES:
        raise dto.HistoricalAIError("BASELINE_CANDIDATE_LIMIT")
    selected, inventory, summary = ai_discovery.select_shadow_candidates(
        legacy, list(merged.values()), limit=request.payload.candidate_limit
    )
    summary["warnings"] = [w for w in summary["warnings"] if w != "NO_HISTORICAL_BASELINE"]
    summary["warnings"].extend(
        local_result.warnings if local_result else ("NO_USABLE_FLOW_RECORDS",)
    )
    if not merged:
        summary["warnings"].append("NO_DISCOVERY_EVIDENCE")
    summary["warnings"].extend(["CAPTURE_COMPLETENESS_UNVERIFIED", "PRIMARY_STREAM_ONLY"])
    limitations = set(e.ASSERTION_REASONS) | set(comparison.limitations)
    if reference_request.quality_review:
        limitations.add("HUMAN_ASSERTED_CLOCK_BOUND")
        if reference_request.quality_review.sensor_alias_asserted:
            limitations.add("EVALUATION_SENSOR_ALIAS")
    facts = e.ReferenceFacts.model_validate_json(
        h.canonical_json(
            {
                "schema_version": "historical-baseline-v1",
                "scope_id": scope.config.scope_id,
                "scope_kind": scope.config.kind,
                "scope_config_sha256": scope.config_sha256,
                "scope_revision": scope.control_revision,
                "scope_state": scope.state,
                "frozen_at_admission": scope.frozen,
                "generation_id": active_id,
                "generation_sha256": scope.active.content_sha256 if scope.active else None,
                "target_source_binding_sha256": binding,
                "target_event_start": h._utc(target.event_start).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "target_event_end": h._utc(target.event_end).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "admitted_at": request.to_mapping()["admitted_at"],
                "comparison_semantics": "RETROSPECTIVE_APPROVED_REFERENCE",
                "identity_assurance": "ADMIN_ASSERTED",
                "quality_assurance": "ANALYST_ASSERTED"
                if reference_request.quality_review
                else "UNREVIEWED",
                "producer_completeness": "UNKNOWN",
                "limitations": sorted(limitations),
            }
        )
    )
    sources = generation.sources if generation else ()
    refs = dto.compact_sources(sources)
    bundles = []
    candidate_snapshots = []
    attached = set()
    for candidate in selected:
        peer = historical.get(candidate["candidate_ip"])
        key = (
            e.ProfileKey.model_validate_json(
                h.canonical_json(history_keys[candidate["candidate_ip"]])
            )
            if peer
            else None
        )
        try:
            reference_value = e.reference_for_selected_peer(
                external_ip=candidate["candidate_ip"],
                candidate_kind=candidate.get("candidate_kind", "C2"),
                facts=facts,
                comparisons=comparisons,
                historical_comparison_key=key,
                source_references=refs,
            )
        except ValidationError as exc:
            # The shared closed reference raises this one model-level budget
            # failure after validating its provenance. Do not remap member or
            # shape errors, nor trim mandatory support to fit the reference.
            errors = exc.errors(include_input=False)
            if exc.title in {"UsableReference", "UnusableReference"} and len(errors) == 1:
                error = errors[0]
                cause = error.get("ctx", {}).get("error")
                if (
                    error["type"] == "value_error"
                    and error["loc"] == ()
                    and type(cause) is ValueError
                    and cause.args == ("historical reference exceeds 8KiB",)
                ):
                    raise dto.HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT") from exc
            raise
        if reference_value.comparison:
            attached.add(reference_value.comparison.key)
        factors = []
        if peer and reference_value.historical_factor_types:
            by_type = {"BEHAVIOR_" + factor.name: factor for factor in peer.candidate.factors}
            for index, factor_type in enumerate(e.FACTOR_TYPES):
                if factor_type not in reference_value.historical_factor_types:
                    continue
                factor = by_type[factor_type]
                factors.append(
                    ai.EvidenceItem(
                        id=e.FACTOR_IDS[index],
                        type=factor_type,
                        summary=factor.explanation,
                        contribution=factor.points,
                        metrics={
                            **factor.metrics,
                            "current": factor.metrics["observed_value"],
                            "reference": (
                                f"/historical_reference/comparison/features/{e.FAMILIES[index]}"
                            ),
                        },
                    )
                )
        bundle = ai.build_unfinalized_evidence_bundle(candidate, job=original)
        bundle.data_quality.payload_fields_excluded = h.projected_payload_fields_excluded(
            target.original.flow_records
        )
        finalized = e.finalize_historical_bundle(
            bundle,
            reference=reference_value,
            factors=tuple(factors),
            source_references=refs,
            local_warnings=tuple(summary["warnings"]),
        )
        if finalized.metadata is None:
            raise dto.HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")
        bundles.append(
            e.AdmittedBundle(
                candidate_id=candidate["id"],
                canonical_json=ai.canonical_bundle_json(finalized),
                metadata=e.FrozenBundleMetadata.model_validate(finalized.metadata.model_dump()),
            )
        )
        saved_candidate = ai._candidate_snapshot(candidate)
        saved_candidate["evidence"] = dto.final_evidence(finalized)
        candidate_snapshots.append(h._frozen_object(saved_candidate))
    counts: Counter[str] = Counter(row.status for row in comparisons)
    summary_value = facts.model_dump(mode="json")
    summary_value["warnings"] = summary_value.pop("limitations")
    baseline_summary = dto.BaselineSummary(
        **summary_value,
        mode="historical",
        profile_counts=dto.ProfileCounts(
            **{name: counts[name] for name in dto.ProfileCounts.model_fields}
        ),
        historical_candidate_count=len(historical),
        unprofiled_count=comparison.unprofiled_count,
    )
    seed = request.to_mapping()
    return dto.HistoricalRunSnapshot(
        id=request.run_id,
        analysis_job_id=request.analysis_job_id,
        dataset_id=target.original.dataset_id,
        idempotency_key=request.payload.idempotency_key,
        status="QUEUED",
        progress_percent=0,
        candidate_limit=request.payload.candidate_limit,
        candidate_ids=tuple(c["id"] for c in selected),
        candidate_snapshots=tuple(candidate_snapshots),
        **{
            name: seed[name]
            for name in (
                "provider",
                "model_name",
                "prompt_name",
                "prompt_version",
                "prompt_hash",
                "input_schema_version",
                "output_schema_version",
            )
        },
        created_by=request.actor,
        created_at=request.admitted_at,
        updated_at=request.admitted_at,
        transitions=(
            dto.QueuedTransition(
                to_status="QUEUED", occurred_at=request.admitted_at, reason="requested"
            ),
        ),
        analysis_kind="C2",
        language=request.payload.language,
        discovery_mode="shadow",
        baseline_mode="historical",
        selection_inventory=tuple(dto.FrozenSelectionItem(**item) for item in inventory),
        selection_summary=dto.FrozenSelectionSummary(**summary),
        baseline_summary=baseline_summary,
        baseline_comparisons=tuple(
            dto.SavedProfileComparison(**row.model_dump(), selected=row.key in attached)
            for row in comparisons
        ),
        baseline_sources=sources,
        admitted_bundles=tuple(bundles),
        baseline_request=request.payload,
        baseline_request_fingerprint=request.request_fingerprint,
    )
