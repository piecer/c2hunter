"""Closed historical model facts and no-I/O saved evidence helpers.

The comparison wire DTOs mirror the frozen analysis interface; they do not
implement comparison or fetch current scope/source state.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from math import isclose, isfinite
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self
from unicodedata import category
from uuid import UUID

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

if TYPE_CHECKING:
    from .ai_analysis import CandidateEvidenceBundle, EvidenceItem


def _uuid(value: str) -> str:
    if str(UUID(value)) != value:
        raise ValueError("noncanonical UUID")
    return value


def _utc(value: str) -> str:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ") != value:
        raise ValueError("noncanonical UTC timestamp")
    return value


UUIDText = Annotated[str, AfterValidator(_uuid)]
UTCText = Annotated[str, AfterValidator(_utc)]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
ReasonCode = Literal[
    "PRODUCER_COMPLETENESS_UNKNOWN",
    "ADMIN_ASSERTED_IDENTITY",
    "HUMAN_ASSERTED_CLOCK_BOUND",
    "EVALUATION_SENSOR_ALIAS",
    "TARGET_REVIEW_REQUIRED",
    "TARGET_PARTIAL_CAPTURE",
    "SOURCE_PARTIAL_CAPTURE",
    "SOURCE_CLOCK_UNCERTAIN",
    "HOST_ATTRIBUTION_UNKNOWN",
    "SCOPE_IDENTITY_MISMATCH",
    "ROOT_PROVENANCE_UNAVAILABLE",
    "PACKET_TIMING_UNAVAILABLE",
    "MIXED_REPRESENTATION",
    "DIRECTION_BALANCE_UNAVAILABLE",
    "DERIVED_FROM_CIDR",
    "INSUFFICIENT_STREAM_SAMPLES",
    "INSUFFICIENT_REFERENCE_WINDOWS",
    "INSUFFICIENT_REFERENCE_SPAN",
    "STALE_REFERENCE",
    "NO_MATCHING_PROFILE",
    "NO_ACTIVE_REFERENCE",
    "FUTURE_OR_OVERLAPPING_WINDOWS_EXCLUDED",
    "TARGET_SOURCE_EXCLUDED",
    "TRUSTED_PEERS_EXCLUDED",
    "COMMON_SERVICES_EXCLUDED",
    "SUPPRESSED_CONTROL_OR_RETRY_ROWS",
    "NONFINITE_FEATURE_UNAVAILABLE",
    "PEER_PRIMARY_STREAM_ONLY",
    "RETROSPECTIVE_NOT_AS_WAS",
    "HISTORY_MATCH_IS_NOT_BENIGN",
    "SERVICE_PORT_UNAVAILABLE",
]


def _ordered(values: tuple[str, ...]) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError("expected sorted unique values")
    return values


Reasons = Annotated[tuple[ReasonCode, ...], Field(max_length=30), AfterValidator(_ordered)]
ASSERTION_REASONS = frozenset(
    {
        "ADMIN_ASSERTED_IDENTITY",
        "PRODUCER_COMPLETENESS_UNKNOWN",
        "RETROSPECTIVE_NOT_AS_WAS",
        "HISTORY_MATCH_IS_NOT_BENIGN",
        "PEER_PRIMARY_STREAM_ONLY",
    }
)


GLOBAL_TARGET_VETOES = frozenset(
    {"TARGET_REVIEW_REQUIRED", "TARGET_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN"}
)


class ClosedFacts(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True, allow_inf_nan=False)


class ReferenceFacts(ClosedFacts):
    schema_version: Literal["historical-baseline-v1"]
    scope_id: UUIDText
    scope_kind: Literal["OPERATIONAL", "EVALUATION"]
    scope_config_sha256: Digest
    scope_revision: int = Field(ge=0)
    scope_state: Literal["EMPTY", "HAS_REFERENCE", "REVOKED", "RETIRED"]
    frozen_at_admission: bool
    generation_id: UUIDText | None
    generation_sha256: Digest | None
    target_source_binding_sha256: Digest
    target_event_start: UTCText
    target_event_end: UTCText
    admitted_at: UTCText
    comparison_semantics: Literal["RETROSPECTIVE_APPROVED_REFERENCE"]
    identity_assurance: Literal["ADMIN_ASSERTED"]
    quality_assurance: Literal["ANALYST_ASSERTED", "UNREVIEWED"]
    producer_completeness: Literal["UNKNOWN"]
    limitations: Reasons

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if (self.generation_id is None) != (self.generation_sha256 is None):
            raise ValueError("generation pair mismatch")
        if (self.scope_state == "HAS_REFERENCE") != (self.generation_id is not None):
            raise ValueError("scope head mismatch")
        if self.target_event_start >= self.target_event_end:
            raise ValueError("invalid target interval")
        if not ASSERTION_REASONS.issubset(self.limitations):
            raise ValueError("missing assertion limitations")
        reviewed = self.quality_assurance == "ANALYST_ASSERTED"
        if reviewed != ("HUMAN_ASSERTED_CLOCK_BOUND" in self.limitations):
            raise ValueError("clock assertion mismatch")
        return self


def _text(value: str) -> str:
    if any(category(c) == "Cc" for c in value):
        raise ValueError("control character")
    return value


Text = Annotated[str, Field(min_length=1, max_length=200), AfterValidator(_text)]


def _ip(value: str) -> str:
    if str(ip_address(value)) != value:
        raise ValueError("noncanonical IP")
    return value


Status = Literal["READY", "INSUFFICIENT", "STALE", "MISSING", "INCOMPATIBLE"]
WindowIDs = Annotated[tuple[UUIDText, ...], Field(max_length=16), AfterValidator(_ordered)]
Number = Annotated[float, Field(ge=0, allow_inf_nan=False)]
HistoricalFactorType = Literal[
    "BEHAVIOR_HISTORICAL_RECURRENCE_CHANGE",
    "BEHAVIOR_HISTORICAL_RECORD_SIZE_DISPERSION_CHANGE",
    "BEHAVIOR_HISTORICAL_DIRECTION_BALANCE_CHANGE",
]
FAMILIES = ("recurrence", "size_dispersion", "outbound_share")
FACTOR_TYPES: tuple[HistoricalFactorType, ...] = (
    "BEHAVIOR_HISTORICAL_RECURRENCE_CHANGE",
    "BEHAVIOR_HISTORICAL_RECORD_SIZE_DISPERSION_CHANGE",
    "BEHAVIOR_HISTORICAL_DIRECTION_BALANCE_CHANGE",
)


class ProfileKey(ClosedFacts):
    scope_config_sha256: Digest
    sensor_key: Text
    internal_host_ip: Annotated[str, AfterValidator(_ip)]
    host_epoch: Annotated[Text, Field(max_length=64)]
    peer_ip: Annotated[str, AfterValidator(_ip)]
    protocol: Annotated[str, Field(min_length=1, max_length=256), AfterValidator(_text)]
    service_port: int = Field(ge=0, le=65535)
    observation_kind: Literal["PACKET", "AGGREGATE"]
    feature_version: Literal["behavior-window-v1"]

    @model_validator(mode="after")
    def uppercase_protocol(self) -> Self:
        if self.protocol != self.protocol.upper():
            raise ValueError("noncanonical protocol")
        return self


class FeatureComparison(ClosedFacts):
    status: Status
    current: Number | None
    reference_median: Number | None
    reference_scale: Number | None
    robust_z: Number | None
    eligible_window_ids: WindowIDs
    excluded_future_count: int = Field(ge=0, le=16)
    drifting: bool

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if len(self.eligible_window_ids) + self.excluded_future_count > 16:
            raise ValueError("family receipt limit")
        if self.status == "READY":
            if (
                self.current is None
                or self.reference_median is None
                or self.reference_scale is None
                or self.robust_z is None
                or self.reference_scale < 0.05
                or len(self.eligible_window_ids) < 3
            ):
                raise ValueError("missing READY statistics/support")
            z = abs(self.current - self.reference_median) / self.reference_scale
            if not isclose(self.robust_z, z, rel_tol=1e-9, abs_tol=1e-9):
                raise ValueError("inconsistent robust z")
            if self.drifting != (self.robust_z >= 3):
                raise ValueError("inconsistent drift")
        elif (
            self.reference_median is not None
            or self.reference_scale is not None
            or self.robust_z is not None
            or self.drifting
        ):
            raise ValueError("unavailable statistics must be null")
        if self.status in {"MISSING", "INCOMPATIBLE"} and self.eligible_window_ids:
            raise ValueError("unsupported family has support")
        if self.status in {"STALE", "INSUFFICIENT"} and (
            self.current is None or not self.eligible_window_ids
        ):
            raise ValueError("retained support requires measured current and sources")
        return self


def _require_incompatible(features: tuple[FeatureComparison, ...]) -> None:
    # Feature validation already guarantees null reference statistics, empty
    # support and no drift for INCOMPATIBLE. Never erase measured currents.
    if any(feature.status != "INCOMPATIBLE" for feature in features):
        raise ValueError("target veto requires every family INCOMPATIBLE")


class Features(ClosedFacts):
    recurrence: FeatureComparison
    size_dispersion: FeatureComparison
    outbound_share: FeatureComparison

    @model_validator(mode="after")
    def share_range(self) -> Self:
        if any(
            value is not None and value > 1
            for value in (self.outbound_share.current, self.outbound_share.reference_median)
        ):
            raise ValueError("outbound share outside unit interval")
        return self

    def ordered(self) -> tuple[FeatureComparison, ...]:
        return (self.recurrence, self.size_dispersion, self.outbound_share)


class ProfileComparison(ClosedFacts):
    key: ProfileKey
    status: Status
    limitations: Reasons
    source_window_ids: WindowIDs
    features: Features
    historical_anomaly_score: Number

    @model_validator(mode="after")
    def consistent(self) -> Self:
        # These reasons are stream-local; a facts-level union may describe a
        # different excluded stream and must not veto this selected profile.
        if self.key.service_port in {53, 123} or set(self.limitations) & {
            "TRUSTED_PEERS_EXCLUDED",
            "COMMON_SERVICES_EXCLUDED",
            "SERVICE_PORT_UNAVAILABLE",
        }:
            raise ValueError("excluded stream cannot have a comparison")
        features = self.features.ordered()
        if (
            self.key.observation_kind == "AGGREGATE"
            or "PACKET_TIMING_UNAVAILABLE" in self.limitations
        ) and self.features.recurrence.current is not None:
            raise ValueError("unavailable timing must remain unmeasured")
        if (
            "DIRECTION_BALANCE_UNAVAILABLE" in self.limitations
            and self.features.outbound_share.current is not None
        ):
            raise ValueError("unavailable direction must remain unmeasured")
        if GLOBAL_TARGET_VETOES.intersection(self.limitations) or (
            "INSUFFICIENT_STREAM_SAMPLES" in self.limitations
        ):
            _require_incompatible(features)
        union = tuple(sorted({wid for f in features for wid in f.eligible_window_ids}))
        if self.source_window_ids != union:
            raise ValueError("profile support mismatch")
        statuses = [f.status for f in features]
        status = (
            "READY"
            if statuses.count("READY") >= 2
            else "STALE"
            if "STALE" in statuses
            else "INSUFFICIENT"
            if "READY" in statuses or "INSUFFICIENT" in statuses
            else "MISSING"
            if "MISSING" in statuses
            else "INCOMPATIBLE"
        )
        if self.status != status:
            raise ValueError("profile status mismatch")
        drifting = [f for f in features if f.drifting]
        score = sum(round(min(30, 10 + (f.robust_z or 0)), 3) for f in drifting)
        if self.historical_anomaly_score != (score if len(drifting) >= 2 else 0):
            raise ValueError("two-family score mismatch")
        return self


class CompactSourceReference(ClosedFacts):
    source_receipt_id: UUIDText
    source_job_id: Text
    event_start: UTCText
    event_end: UTCText
    approved_at: UTCText
    source_binding_sha256: Digest

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.event_start >= self.event_end:
            raise ValueError("invalid source interval")
        return self


SourceReferences = Annotated[tuple[CompactSourceReference, ...], Field(max_length=16)]


def _reference_integrity(reference: UsableReference | UnusableReference) -> None:
    comparison = reference.comparison
    ids = tuple(s.source_receipt_id for s in reference.source_references)
    if ids != (comparison.source_window_ids if comparison else ()):
        raise ValueError("compact sources differ from family support union")
    if reference.facts.generation_id is None and ids:
        raise ValueError("null head has sources")
    if comparison:
        if GLOBAL_TARGET_VETOES.intersection(reference.facts.limitations):
            _require_incompatible(comparison.features.ordered())
        if comparison.key.scope_config_sha256 != reference.facts.scope_config_sha256:
            raise ValueError("comparison scope mismatch")
        if not set(comparison.limitations).issubset(reference.facts.limitations):
            raise ValueError("comparison limitations omitted")
    if any(s.event_end >= reference.facts.target_event_start for s in reference.source_references):
        raise ValueError("noncausal source support")
    if comparison:
        _validate_support_times(
            comparison.features.ordered(),
            reference.source_references,
            reference.facts.target_event_start,
        )
    if len(_canonical(reference.model_dump(mode="json")).encode()) > 8192:
        raise ValueError("historical reference exceeds 8KiB")


def _validate_support_times(
    features: tuple[FeatureComparison, ...],
    sources: tuple[CompactSourceReference, ...],
    target_start: str,
) -> None:
    # Only saved event bounds can establish temporal feasibility. Each family
    # owns its support; the union's freshness/span cannot justify another family.
    bounds = {
        source.source_receipt_id: (
            datetime.fromisoformat(source.event_start),
            datetime.fromisoformat(source.event_end),
        )
        for source in sources
    }
    cutoff = datetime.fromisoformat(target_start)
    for feature in features:
        # No inference about unavailable measurements or nonfinite arithmetic:
        # MISSING/INCOMPATIBLE have empty support, already enforced by the DTO.
        if feature.status not in {"READY", "STALE", "INSUFFICIENT"}:
            continue
        support = [bounds[wid] for wid in feature.eligible_window_ids]
        newest = max(end for _, end in support)
        if cutoff - newest > timedelta(days=7):
            expected = "STALE"
        elif len(support) < 3 or newest - min(start for start, _ in support) < timedelta(days=1):
            expected = "INSUFFICIENT"
        else:
            expected = "READY"
        if feature.status != expected:
            raise ValueError("family status contradicts saved receipt times")


def _canonical(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False
    )


class UsableReference(ClosedFacts):
    availability: Literal["USABLE"]
    facts: ReferenceFacts
    comparison: ProfileComparison
    source_references: SourceReferences
    historical_factor_types: Annotated[
        tuple[HistoricalFactorType, ...], Field(max_length=3), AfterValidator(_ordered)
    ]

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.comparison.status != "READY":
            raise ValueError("USABLE requires READY")
        if self.facts.quality_assurance != "ANALYST_ASSERTED":
            raise ValueError("READY requires supplied target review")
        expected = tuple(
            sorted(
                t
                for t, f in zip(FACTOR_TYPES, self.comparison.features.ordered(), strict=True)
                if f.drifting
            )
        )
        if self.historical_factor_types != (expected if len(expected) >= 2 else ()):
            raise ValueError("historical factors mismatch")
        _reference_integrity(self)
        return self


class UnusableReference(ClosedFacts):
    availability: Literal["UNUSABLE"]
    facts: ReferenceFacts
    cause: Literal["NO_PROFILE", "COMMUNICATION_STATUS", "COMPARISON_UNAVAILABLE"]
    comparison: ProfileComparison | None
    source_references: SourceReferences
    historical_factor_types: tuple[()]

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.cause == "COMPARISON_UNAVAILABLE":
            if self.comparison is None or self.comparison.status == "READY":
                raise ValueError("unavailable requires non-READY comparison")
        elif self.comparison is not None or self.source_references:
            raise ValueError("no-profile/operational evidence cannot have history")
        _reference_integrity(self)
        return self


HistoricalReference = Annotated[
    UsableReference | UnusableReference, Field(discriminator="availability")
]

COVERAGE_ID = "E-C2H-HIST-COVERAGE"
COVERAGE_DESCRIPTION = (
    "Historical reference use and availability are stated in historical_reference. "
    "Identity and window quality are human assertions; producer completeness is UNKNOWN. "
    "This is a retrospective approved reference, not an as-was backtest. "
    "Historical agreement is not a benign verdict; anomaly rank is not C2 probability. "
    "Current-job coverage limitations still apply."
)
FACTOR_IDS = ("E-C2H-HIST-RECURRENCE", "E-C2H-HIST-SIZE", "E-C2H-HIST-DIRECTION")


class HistoricalEvidenceError(ValueError):
    """Static typed error for the caller's admission/worker error mapping."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _validate_attachment(
    bundle: CandidateEvidenceBundle,
    reference: HistoricalReference,
    factors: tuple[EvidenceItem, ...],
    source_references: tuple[CompactSourceReference, ...],
) -> None:
    if len(source_references) > 16:
        raise ValueError("source manifest limit")
    if reference.facts.generation_id is None and source_references:
        raise ValueError("null head has a nonempty saved manifest")
    manifest = {s.source_receipt_id: s for s in source_references}
    if len(manifest) != len(source_references):
        raise ValueError("duplicate source receipt")
    if any(manifest.get(s.source_receipt_id) != s for s in reference.source_references):
        raise ValueError("saved source receipt mismatch")
    operational = bundle.candidate.candidate_kind == "COMMUNICATION_STATUS"
    if operational != (
        isinstance(reference, UnusableReference) and reference.cause == "COMMUNICATION_STATUS"
    ):
        raise ValueError("operational historical claims")
    comparison = reference.comparison
    if comparison and comparison.key.peer_ip != bundle.candidate.external_ip:
        raise ValueError("comparison peer mismatch")
    expected = [i for i, t in enumerate(FACTOR_TYPES) if t in reference.historical_factor_types]
    if len(factors) != len(expected):
        raise ValueError("positive factor omitted")
    for factor, index in zip(factors, expected, strict=True):
        if len(factor.metrics) > 128 or len(factor.description) > 2048:
            raise ValueError("protected factor input limit")
        if comparison is None:
            raise ValueError("factor without comparison")
        feature = comparison.features.ordered()[index]
        if (
            factor.evidence_id != FACTOR_IDS[index]
            or factor.evidence_type != FACTOR_TYPES[index]
            or factor.contribution != round(min(30, 10 + (feature.robust_z or 0)), 3)
            or not factor.description
        ):
            raise ValueError("factor identity/points mismatch")
        for key, value in factor.metrics.items():
            if (
                not isinstance(key, str)
                or len(key) > 100
                or type(value) not in (str, int, float, bool, type(None))
                or isinstance(value, float)
                and not isfinite(value)
                or isinstance(value, str)
                and len(value) > 512
            ):
                raise ValueError("nonprimitive factor metrics")
        for key in ("current", "reference_median", "reference_scale", "robust_z"):
            if type(factor.metrics.get(key)) not in (int, float) or factor.metrics.get(
                key
            ) != getattr(feature, key):
                raise ValueError("factor statistics mismatch")
        if (
            factor.metrics.get("reference")
            != f"/historical_reference/comparison/features/{FAMILIES[index]}"
        ):
            raise ValueError("factor reference mismatch")
    if (
        comparison
        and sum(f.contribution or 0 for f in factors) != comparison.historical_anomaly_score
    ):
        raise ValueError("factor score mismatch")


def finalize_historical_bundle(
    bundle: CandidateEvidenceBundle,
    *,
    reference: HistoricalReference,
    factors: tuple[EvidenceItem, ...],
    source_references: tuple[CompactSourceReference, ...],
    local_warnings: tuple[str, ...],
) -> CandidateEvidenceBundle:
    """Attach protected facts to pre-finalized local evidence, without I/O.

    source_references is the compact projection of the saved validated receipts,
    not current source rows. Factors come from the exact positive comparison.
    """
    from .ai_analysis import BundleMetadata, CandidateEvidenceBundle, EvidenceItem

    if bundle.metadata is not None or bundle.historical_reference is not None:
        raise ValueError("expected pre-finalized local bundle")
    _admit_local(bundle, local_warnings)
    _validate_attachment(bundle, reference, factors, source_references)
    coverage = EvidenceItem(
        id=COVERAGE_ID,
        type="BEHAVIOR_COVERAGE",
        summary=COVERAGE_DESCRIPTION,
        contribution=0,
        metrics={
            "reference": "/historical_reference",
            "local_warnings": [w for w in local_warnings if w != "NO_HISTORICAL_BASELINE"],
        },
    )
    optional = [e for e in bundle.evidence if e.evidence_type != "BEHAVIOR_COVERAGE"]
    if any(
        e.evidence_type in FACTOR_TYPES or e.evidence_id.startswith("E-C2H-HIST-") for e in optional
    ):
        raise ValueError("historical factors must use protected input")
    raw = bundle.model_dump(mode="json", by_alias=True, exclude={"metadata"})
    raw["historical_reference"] = reference.model_dump(mode="json")
    raw["evidence"] = [
        e.model_dump(mode="json", by_alias=True) for e in (coverage, *factors, *optional)
    ]
    canonical, reduced = _reduce(raw, mandatory_count=1 + len(factors))
    encoded = canonical.encode()
    result = CandidateEvidenceBundle.model_validate_json(canonical)
    if _canonical(result.model_dump(mode="json", by_alias=True, exclude={"metadata"})) != canonical:
        raise ValueError("pre-finalized values were not canonical model values")
    result.metadata = BundleMetadata(
        canonical_sha256=hashlib.sha256(encoded).hexdigest(),
        byte_size=len(encoded),
        estimated_tokens=(len(encoded) + 2) // 3,
        reduced=reduced,
        storage_backend="JSONB_INLINE",
    )
    return result


def _admit_local(bundle: CandidateEvidenceBundle, warnings: tuple[str, ...]) -> None:
    """Bound collections/strings before copying or constructing the removal sequence."""
    if len(bundle.evidence) > 50 or len(warnings) > 30 or any(len(w) > 1000 for w in warnings):
        raise ValueError("local evidence/warning limit")
    context = bundle.protocol_context
    for values in (context.domains, context.tls_fingerprints, context.certificate_fingerprints):
        if len(values) > 100 or any(len(v) > 512 for v in values):
            raise ValueError("protocol string limit")
    if len(context.tcp_flags) > 128 or any(len(k) > 256 for k in context.tcp_flags):
        raise ValueError("protocol flag limit")
    nodes = 0
    string_bytes = 0

    def visit(value: object, depth: int = 0) -> None:
        nonlocal nodes, string_bytes
        nodes += 1
        if depth > 16 or nodes > 262144:
            raise ValueError("local structural limit")
        if isinstance(value, BaseModel):
            for name in type(value).model_fields:
                visit(getattr(value, name), depth + 1)
        elif isinstance(value, dict):
            if len(value) > 128:
                raise ValueError("local collection limit")
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("invalid JSON key")
                visit(key, depth + 1)
                visit(item, depth + 1)
        elif isinstance(value, list | tuple):
            if len(value) > 128:
                raise ValueError("local collection limit")
            for item in value:
                visit(item, depth + 1)
        elif isinstance(value, str):
            if len(value) > 65536:
                raise HistoricalEvidenceError("BASELINE_RUN_SNAPSHOT_LIMIT")
            string_bytes += len(value.encode())
            if string_bytes > 1048576:
                raise HistoricalEvidenceError("BASELINE_RUN_SNAPSHOT_LIMIT")
        elif type(value) not in (bool, int, float, type(None)):
            raise ValueError("non-JSON value")
        elif isinstance(value, float) and not isfinite(value):
            raise ValueError("nonfinite local metric")

    visit(bundle)


def _fits(text: str) -> bool:
    size = len(text.encode())
    return size <= 65536 and (size + 2) // 3 <= 8192


def _reduce(raw: dict[str, Any], *, mandatory_count: int) -> tuple[str, bool]:
    # Fixed semantic sequence: evidence tails, domains, TLS, certificates, flags.
    # Every probe derives from original values, never from a previous probe.
    optional = len(raw["evidence"]) - mandatory_count
    fields = ("domains", "tls_fingerprints", "certificate_fingerprints")
    context = raw["protocol_context"]
    flags = sorted(context["tcp_flags"])
    total = optional + sum(len(context[f]) for f in fields) + len(flags)
    count_trim = max(0, len(raw["evidence"]) - 50)

    def probe(prefix: int) -> str:
        drop = min(prefix, optional)
        value = {**raw, "evidence": raw["evidence"][: len(raw["evidence"]) - drop]}
        remaining = prefix - drop
        protocol = dict(context)
        for field in fields:
            drop = min(remaining, len(context[field]))
            protocol[field] = context[field][: len(context[field]) - drop]
            remaining -= drop
        protocol["tcp_flags"] = {
            key: context["tcp_flags"][key] for key in flags[: len(flags) - remaining]
        }
        value["protocol_context"] = protocol
        return _canonical(value)

    if _fits(probe(count_trim)):
        chosen = count_trim
    else:
        if not _fits(probe(total)):
            raise HistoricalEvidenceError("BASELINE_RUN_SNAPSHOT_LIMIT")
        lo, hi = count_trim + 1, total
        while lo < hi:
            mid = (lo + hi) // 2
            if _fits(probe(mid)):
                hi = mid
            else:
                lo = mid + 1
        chosen = lo
    return probe(chosen), chosen > 0


def reference_for_selected_peer(
    *,
    external_ip: str,
    candidate_kind: Literal["C2", "COMMUNICATION_STATUS"],
    facts: ReferenceFacts,
    comparisons: tuple[ProfileComparison, ...],
    historical_comparison_key: ProfileKey | None,
    source_references: tuple[CompactSourceReference, ...],
) -> HistoricalReference:
    """Resolve after real selection; never rely on selector-preserved extra keys.

    The positive key is the immutable HistoricalPeerCandidate.comparison_key,
    independent of any local/history max-score winner. This does not select peers.
    """
    if len(comparisons) > 128 or len(source_references) > 16:
        raise ValueError("comparison/manifest limit")
    keys = [_canonical(c.key.model_dump(mode="json")) for c in comparisons]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate comparison")
    if candidate_kind == "COMMUNICATION_STATUS":
        return UnusableReference(
            availability="UNUSABLE",
            facts=facts,
            cause="COMMUNICATION_STATUS",
            comparison=None,
            source_references=(),
            historical_factor_types=(),
        )
    rows = sorted(
        (c for c in comparisons if c.key.peer_ip == external_ip),
        key=lambda c: (c.status != "READY", _canonical(c.key.model_dump(mode="json"))),
    )
    selected = rows[0] if rows else None
    if historical_comparison_key is not None:
        selected = next((c for c in rows if c.key == historical_comparison_key), None)
        if selected is None or selected.historical_anomaly_score <= 0:
            raise ValueError("missing positive comparison provenance")
    elif selected and selected.historical_anomaly_score:
        raise ValueError("positive comparison requires HistoricalPeerCandidate key")
    if selected is None:
        return UnusableReference(
            availability="UNUSABLE",
            facts=facts,
            cause="NO_PROFILE",
            comparison=None,
            source_references=(),
            historical_factor_types=(),
        )
    facts = ReferenceFacts.model_validate(
        {
            **facts.model_dump(),
            "limitations": tuple(sorted(set(facts.limitations) | set(selected.limitations))),
        }
    )
    manifest = {s.source_receipt_id: s for s in source_references}
    if len(manifest) != len(source_references) or not set(selected.source_window_ids).issubset(
        manifest
    ):
        raise ValueError("missing/duplicate source receipt")
    refs = tuple(manifest[wid] for wid in selected.source_window_ids)
    if selected.status != "READY":
        return UnusableReference(
            availability="UNUSABLE",
            facts=facts,
            cause="COMPARISON_UNAVAILABLE",
            comparison=selected,
            source_references=refs,
            historical_factor_types=(),
        )
    types = (
        tuple(
            sorted(
                t
                for t, f in zip(FACTOR_TYPES, selected.features.ordered(), strict=True)
                if f.drifting
            )
        )
        if selected.historical_anomaly_score
        else ()
    )
    return UsableReference(
        availability="USABLE",
        facts=facts,
        comparison=selected,
        source_references=refs,
        historical_factor_types=types,
    )


class FrozenBundleMetadata(ClosedFacts):
    canonical_sha256: Digest
    byte_size: int = Field(ge=0)
    estimated_tokens: int = Field(ge=0, le=8192)
    reduced: bool
    storage_backend: Literal["JSONB_INLINE", "MINIO_OBJECT"]


class AdmittedBundle(ClosedFacts):
    candidate_id: Text
    canonical_json: str = Field(max_length=65536)
    metadata: FrozenBundleMetadata


def decode_admitted_bundle(
    saved: object,
    *,
    expected_candidate_id: str,
    facts: ReferenceFacts,
    comparisons: tuple[ProfileComparison, ...],
    source_references: tuple[CompactSourceReference, ...],
    local_warnings: tuple[str, ...],
) -> CandidateEvidenceBundle:
    """Decode only saved bytes and validated saved receipt projections; no capabilities.

    The caller validates the owning run and full SourceReceipt DTOs and passes
    their exact compact projections. This is not a repository/run decoder.
    """
    from .ai_analysis import BundleMetadata, CandidateEvidenceBundle, canonical_bundle_json

    try:
        envelope = AdmittedBundle.model_validate(saved)
        text = envelope.canonical_json
        if not _fits(text):
            raise ValueError("saved size limit")
        encoded = text.encode()
        metadata = envelope.metadata
        if (
            envelope.candidate_id != expected_candidate_id
            or metadata.canonical_sha256 != hashlib.sha256(encoded).hexdigest()
            or metadata.byte_size != len(encoded)
            or metadata.estimated_tokens != (len(encoded) + 2) // 3
            or metadata.storage_backend != "JSONB_INLINE"
        ):
            raise ValueError("saved envelope mismatch")
        # Re-encoding rejects duplicate keys, alternate JSON spellings and nonfinite
        # values even in legacy free-form metrics, before they can reach a gateway.
        if _canonical(json.loads(text)) != text:
            raise ValueError("noncanonical JSON")
        bundle = CandidateEvidenceBundle.model_validate_json(text)
        if (
            canonical_bundle_json(bundle) != text
            or bundle.candidate.candidate_id != expected_candidate_id
        ):
            raise ValueError("noncanonical/mismatched saved bundle")
        _admit_local(bundle, local_warnings)
        reference = bundle.historical_reference
        if reference is None or reference.facts != facts:
            raise ValueError("saved reference facts mismatch")
        if len(comparisons) > 128 or (
            reference.comparison is not None and reference.comparison not in comparisons
        ):
            raise ValueError("saved comparison mismatch")
        factors = tuple(e for e in bundle.evidence if e.evidence_type in FACTOR_TYPES)
        _validate_attachment(bundle, reference, factors, source_references)
        coverage = bundle.evidence[0]
        if (
            coverage.evidence_id != COVERAGE_ID
            or coverage.evidence_type != "BEHAVIOR_COVERAGE"
            or coverage.description != COVERAGE_DESCRIPTION
            or coverage.contribution != 0
            or coverage.metrics
            != {
                "reference": "/historical_reference",
                "local_warnings": [w for w in local_warnings if w != "NO_HISTORICAL_BASELINE"],
            }
            or tuple(bundle.evidence[1 : 1 + len(factors)]) != factors
            or len({e.evidence_id for e in bundle.evidence}) != len(bundle.evidence)
        ):
            raise ValueError("saved protected evidence mismatch")
        for item in bundle.evidence[1 + len(factors) :]:
            if item.evidence_type == "BEHAVIOR_COVERAGE" or item.evidence_id.startswith(
                "E-C2H-HIST-"
            ):
                raise ValueError("unprotected historical evidence")
        bundle.metadata = BundleMetadata.model_validate(metadata.model_dump())
        return bundle
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        raise HistoricalEvidenceError("HISTORICAL_SNAPSHOT_INVALID") from exc
