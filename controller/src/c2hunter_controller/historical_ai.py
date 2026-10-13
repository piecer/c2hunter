"""Internal immutable historical AI values; no route or storage registration.

The owning decoder accepts an independently captured request seed. It never reads
jobs, scope heads, queues or clocks, and never falls back to legacy reconstruction.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from datetime import datetime
from typing import TYPE_CHECKING, Annotated, Any, Literal, Self, get_args, get_origin

from pydantic import ConfigDict, Field, PlainSerializer, PlainValidator, model_validator

from . import historical_baseline as h
from . import historical_evidence as e
from . import historical_generation as g
from .historical_source import SourceProjection

if TYPE_CHECKING:
    from .ai_analysis import CandidateEvidenceBundle


class HistoricalAIError(ValueError):
    """Static domain outcome; transport mapping belongs to the future caller."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class Value(e.ClosedFacts):
    model_config = ConfigDict(revalidate_instances="always")

    @model_validator(mode="before")
    @classmethod
    def arrays(cls, value: Any) -> Any:
        if type(value) is dict:
            value = dict(value)
            for name, item in value.items():
                field = cls.model_fields.get(name)
                if field and get_origin(field.annotation) is Literal:
                    from typing import get_args

                    if not any(
                        type(item) is type(v) and item == v for v in get_args(field.annotation)
                    ):
                        raise ValueError("invalid literal")
                if field and get_origin(field.annotation) is tuple and type(item) is list:
                    value[name] = tuple(item)
        return value

    def to_mapping(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def _quality_review(value: Any) -> h.QualityReview:
    try:
        g._preflight(value, h.QualityReview)
        return h.QualityReview.model_validate(g._unmodel(value))
    except (ValueError, TypeError) as exc:
        raise HistoricalAIError("BASELINE_SOURCE_INVALID") from exc


def _source_projection(value: Any) -> SourceProjection:
    # Reuse the existing read-only source shape/count/byte admission, then
    # re-enter its real validators (including immutable StrictFlow copies).
    # _unmodel preserves original FrozenObject kinds/order and numeric leaves.
    try:
        g._snapshot_preflight(value, SourceProjection)
        return SourceProjection.model_validate(g._unmodel(value))
    except (ValueError, TypeError) as exc:
        code = getattr(exc, "code", str(exc))
        raise HistoricalAIError(
            code
            if code in {"BASELINE_SOURCE_LIMIT", "BASELINE_PROFILE_LIMIT"}
            else "BASELINE_SOURCE_INVALID"
        ) from exc


class BaselineReferenceRequest(Value):
    scope_id: h.UUIDString
    expected_revision: h.Nonnegative
    generation_id: h.UUIDString | None
    target_source_binding_sha256: h.Digest
    quality_review: (
        Annotated[
            h.QualityReview,
            PlainValidator(_quality_review),
            PlainSerializer(lambda v, info: v.model_dump(mode=info.mode)),
        ]
        | None
    )


class FrozenAIAnalysisRunCreate(Value):
    idempotency_key: h.Identifier
    candidate_limit: Annotated[int, Field(ge=1, le=5)] = 5
    analysis_kind: Literal["C2", "NETWORK_ANOMALY", "DDOS_ATTACK"] = "C2"
    language: Literal["ko", "en"] = "ko"
    allow_remote: bool = False
    discovery_mode: Literal["legacy", "shadow"] = "legacy"
    baseline_mode: Literal["off", "historical"] = "off"
    baseline_reference: BaselineReferenceRequest | None = None

    @model_validator(mode="after")
    def modes(self) -> Self:
        if self.baseline_mode == "historical":
            if (self.analysis_kind, self.discovery_mode) != ("C2", "shadow"):
                raise HistoricalAIError("BASELINE_MODE_NOT_ALLOWED")
            if self.baseline_reference is None:
                raise HistoricalAIError("BASELINE_SOURCE_INVALID")
        elif self.baseline_reference is not None:
            raise HistoricalAIError("BASELINE_MODE_NOT_ALLOWED")
        return self


def request_fingerprint(job_id: str, actor: str, payload: FrozenAIAnalysisRunCreate) -> str:
    return hashlib.sha256(
        h.canonical_json(
            {
                "analysis_job_id": job_id,
                "actor": actor,
                "payload": payload.to_mapping(),
            }
        ).encode()
    ).hexdigest()


class HistoricalAdmissionRequest(Value):
    analysis_job_id: h.Identifier
    payload: FrozenAIAnalysisRunCreate
    actor: h.Identifier
    run_id: h.UUIDString
    admitted_at: h.UTCDateTime
    provider: h.Identifier
    model_name: h.Identifier
    prompt_name: h.Identifier
    prompt_version: h.Identifier
    prompt_hash: h.Digest
    input_schema_version: Literal["1.0"]
    output_schema_version: Literal["1.0"]
    request_fingerprint: h.Digest

    @model_validator(mode="after")
    def identity(self) -> Self:
        if self.payload.baseline_mode != "historical":
            raise HistoricalAIError("BASELINE_MODE_NOT_ALLOWED")
        if self.request_fingerprint != request_fingerprint(
            self.analysis_job_id, self.actor, self.payload
        ):
            raise HistoricalAIError("BASELINE_SOURCE_INVALID")
        return self


class HistoricalAdmissionInput(Value):
    request: HistoricalAdmissionRequest
    target: Annotated[
        SourceProjection,
        PlainValidator(_source_projection),
        PlainSerializer(lambda v, info: v.model_dump(mode=info.mode)),
    ]
    candidates: Annotated[tuple[h.CandidateProjection, ...], Field(max_length=2048)]
    scope: Annotated[
        g.ScopeView,
        PlainValidator(g.ScopeView.model_validate),
        PlainSerializer(lambda v, info: v.model_dump(mode=info.mode)),
    ]
    generation: (
        Annotated[
            g.GenerationDocument,
            PlainValidator(g.GenerationDocument.model_validate),
            PlainSerializer(lambda v, info: v.model_dump(mode=info.mode)),
        ]
        | None
    )
    target_source_binding_sha256: h.Digest

    @model_validator(mode="before")
    @classmethod
    def candidate_count(cls, value: Any) -> Any:
        # Runs before Value.arrays copies lists and before member validators.
        if type(value) is dict and "candidates" in value:
            candidates = value["candidates"]
            if type(candidates) not in (tuple, list):
                raise HistoricalAIError("BASELINE_SOURCE_INVALID")
            if len(candidates) > 2048:
                raise HistoricalAIError("BASELINE_CANDIDATE_LIMIT")
        return value


class FrozenSelectionItem(Value):
    candidate_id: h.Identifier
    external_ip: Annotated[str, Field(max_length=45)]
    origin: Literal["RULE", "PREFILTER", "BEHAVIOR", "RULE_AND_BEHAVIOR"]
    existing_score: Annotated[float, Field(ge=0, le=100)]
    anomaly_score: Annotated[float, Field(ge=0)] | None
    selected: bool
    reason: Literal["DISCOVERY_RESERVED", "RANKED", "BUDGET_LIMIT"]


class FrozenSelectionSummary(Value):
    version: Literal["behavior-selection-v1"]
    candidate_pool_count: Annotated[int, Field(ge=0, le=2048)]
    selected_count: Annotated[int, Field(ge=0, le=5)]
    omitted_count: Annotated[int, Field(ge=0, le=2048)]
    discovery_candidate_count: Annotated[int, Field(ge=0, le=2048)]
    discovery_selected_count: Annotated[int, Field(ge=0, le=5)]
    rule_free_selected_count: Annotated[int, Field(ge=0, le=5)]
    reserved_discovery_slots: Annotated[int, Field(ge=0, le=2)]
    warnings: Annotated[tuple[Annotated[str, Field(max_length=1000)], ...], Field(max_length=30)]


class ProfileCounts(Value):
    READY: h.Nonnegative
    INSUFFICIENT: h.Nonnegative
    STALE: h.Nonnegative
    MISSING: h.Nonnegative
    INCOMPATIBLE: h.Nonnegative


class BaselineSummary(Value):
    mode: Literal["historical"]
    schema_version: Literal["historical-baseline-v1"]
    scope_id: h.UUIDString
    scope_kind: Literal["OPERATIONAL", "EVALUATION"]
    scope_config_sha256: h.Digest
    scope_revision: h.Nonnegative
    scope_state: Literal["EMPTY", "HAS_REFERENCE", "REVOKED", "RETIRED"]
    frozen_at_admission: bool
    generation_id: h.UUIDString | None
    generation_sha256: h.Digest | None
    target_event_start: e.UTCText
    target_event_end: e.UTCText
    target_source_binding_sha256: h.Digest
    admitted_at: e.UTCText
    comparison_semantics: Literal["RETROSPECTIVE_APPROVED_REFERENCE"]
    identity_assurance: Literal["ADMIN_ASSERTED"]
    quality_assurance: Literal["ANALYST_ASSERTED", "UNREVIEWED"]
    producer_completeness: Literal["UNKNOWN"]
    profile_counts: ProfileCounts
    unprofiled_count: Annotated[int, Field(ge=0, le=128)]
    historical_candidate_count: Annotated[int, Field(ge=0, le=128)]
    warnings: e.Reasons

    def facts(self) -> e.ReferenceFacts:
        raw = self.to_mapping()
        for key in ("mode", "profile_counts", "unprofiled_count", "historical_candidate_count"):
            raw.pop(key)
        raw["limitations"] = raw.pop("warnings")
        return e.ReferenceFacts.model_validate_json(h.canonical_json(raw))


class SavedProfileComparison(e.ProfileComparison):
    selected: bool

    def comparison(self) -> e.ProfileComparison:
        return e.ProfileComparison.model_validate(self.model_dump(exclude={"selected"}))


class QueuedTransition(Value):
    to_status: Literal["QUEUED"]
    occurred_at: h.UTCDateTime
    reason: Literal["requested"]


def _saved_comparison(value: Any) -> SavedProfileComparison:
    return SavedProfileComparison.model_validate_json(
        json.dumps(value, ensure_ascii=False, allow_nan=False, default=_model_json)
    )


def _saved_bundle(value: Any) -> e.AdmittedBundle:
    return e.AdmittedBundle.model_validate_json(
        json.dumps(value, ensure_ascii=False, allow_nan=False, default=_model_json)
    )


class HistoricalRunSnapshot(Value):
    id: h.UUIDString
    analysis_job_id: h.Identifier
    dataset_id: h.Identifier
    idempotency_key: h.Identifier
    status: Literal["QUEUED"]
    progress_percent: Literal[0]
    candidate_limit: Annotated[int, Field(ge=1, le=5)]
    candidate_ids: Annotated[tuple[h.Identifier, ...], Field(max_length=5)]
    candidate_snapshots: Annotated[tuple[h.OriginalFrozenObject, ...], Field(max_length=5)]
    provider: h.Identifier
    model_name: h.Identifier
    prompt_name: h.Identifier
    prompt_version: h.Identifier
    prompt_hash: h.Digest
    input_schema_version: Literal["1.0"]
    output_schema_version: Literal["1.0"]
    created_by: h.Identifier
    created_at: h.UTCDateTime
    updated_at: h.UTCDateTime
    transitions: Annotated[tuple[QueuedTransition, ...], Field(min_length=1, max_length=1)]
    analysis_kind: Literal["C2"]
    language: Literal["ko", "en"]
    discovery_mode: Literal["shadow"]
    baseline_mode: Literal["historical"]
    selection_inventory: Annotated[tuple[FrozenSelectionItem, ...], Field(max_length=2048)]
    selection_summary: FrozenSelectionSummary
    baseline_summary: BaselineSummary
    baseline_comparisons: Annotated[
        tuple[
            Annotated[
                SavedProfileComparison,
                PlainValidator(_saved_comparison),
                PlainSerializer(lambda v: v.model_dump(mode="json")),
            ],
            ...,
        ],
        Field(max_length=128),
    ]
    baseline_sources: Annotated[
        tuple[
            Annotated[
                g.SourceReceipt,
                PlainValidator(g.SourceReceipt.model_validate),
                PlainSerializer(lambda v: v.model_dump(mode="json")),
            ],
            ...,
        ],
        Field(max_length=16),
    ]
    admitted_bundles: Annotated[
        tuple[
            Annotated[
                e.AdmittedBundle,
                PlainValidator(_saved_bundle),
                PlainSerializer(lambda v: v.model_dump(mode="json")),
            ],
            ...,
        ],
        Field(max_length=5),
    ]
    baseline_request: FrozenAIAnalysisRunCreate
    baseline_request_fingerprint: h.Digest

    @model_validator(mode="before")
    @classmethod
    def sizes(cls, value: Any) -> Any:
        if type(value) is dict:
            validate_snapshot_sizes(value)
        return value


PRIVATE_ADDITIONS = (
    "baseline_summary",
    "baseline_comparisons",
    "baseline_sources",
    "admitted_bundles",
    "baseline_request",
    "baseline_request_fingerprint",
)


def _model_json(value: Any) -> Any:
    if isinstance(value, e.ClosedFacts | h.FrozenDTO):
        check_closed_model(value)
        return vars(value)
    if isinstance(value, datetime):
        return h._utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    raise TypeError("not a historical value")


def check_closed_model(value: Any) -> None:
    if (
        not isinstance(value, e.ClosedFacts | h.FrozenDTO)
        or value.__pydantic_extra__
        or (set(vars(value)) != set(type(value).model_fields))
    ):
        raise HistoricalAIError("BASELINE_SOURCE_INVALID")


def _request_preflight(value: HistoricalAdmissionRequest) -> None:
    """Bound the closed request before encoding, copying or semantic validation.

    These ClosedFacts records are not generation FrozenDTOs. Walk their actual
    fields without model_dump (which can discard unknown copied fields), then
    reuse generation's bounded scalar admission and the real request validators.
    """
    budget = _CanonicalBudget(16384)
    leaves: list[tuple[Any, Any]] = []

    def visit(item: Any, annotation: Any) -> None:
        kind = annotation
        while get_origin(kind) is Annotated:
            kind = get_args(kind)[0]
        choices = get_args(kind)
        if type(None) in choices:
            if item is None:
                budget.visit(None)
            else:
                visit(item, next(choice for choice in choices if choice is not type(None)))
            return
        if isinstance(kind, type) and issubclass(kind, e.ClosedFacts | h.FrozenDTO):
            fields = kind.model_fields
            if type(item) is kind:
                if item.__pydantic_extra__ or len(vars(item)) != len(fields):
                    raise HistoricalAIError("BASELINE_SOURCE_INVALID")
                item = vars(item)
            if (
                type(item) is not dict
                or len(item) > len(fields)
                or any(type(name) is not str or name not in fields for name in item)
            ):
                raise HistoricalAIError("BASELINE_SOURCE_INVALID")
            # Unlike canonical snapshots, checked_request keeps JSONEncoder's
            # default comma/colon separators, each including a trailing space.
            budget.add(2 + 2 * max(0, len(item) - 1) + 2 * len(item))
            for name, child in item.items():
                budget.visit(name)
                visit(child, fields[name].rebuild_annotation())
            return
        # No request field is an array or free-form object. Reject those before
        # walking any members; even a model_copy value is not already admitted.
        if type(item) not in (str, int, bool, datetime, type(None)):
            raise HistoricalAIError("BASELINE_SOURCE_INVALID")
        budget.visit(item)
        leaves.append((item, annotation))

    try:
        visit(value, HistoricalAdmissionRequest)
    except HistoricalAIError as exc:
        if exc.code == "BASELINE_RUN_SNAPSHOT_LIMIT":
            raise HistoricalAIError("BASELINE_SOURCE_LIMIT") from exc
        raise
    # Byte overflow keeps the old 16KiB taxonomy. Bounded but malformed field
    # lengths/types remain invalid, rather than becoming a new limit category.
    for item, annotation in leaves:
        try:
            g._preflight(item, annotation)
        except (ValueError, TypeError) as exc:
            raise HistoricalAIError("BASELINE_SOURCE_INVALID") from exc


def checked_request(value: HistoricalAdmissionRequest) -> HistoricalAdmissionRequest:
    if type(value) is not HistoricalAdmissionRequest:
        raise HistoricalAIError("BASELINE_SOURCE_INVALID")
    _request_preflight(value)
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, default=_model_json)
    parts = []
    size = 0
    for part in encoder.iterencode(value):
        size += len(part.encode())
        if size > 16384:
            raise HistoricalAIError("BASELINE_SOURCE_LIMIT")
        parts.append(part)
    return HistoricalAdmissionRequest.model_validate_json("".join(parts))


class _CanonicalBudget:
    """Meter canonical UTF-8 without making an encoded scalar or container copy.

    Container/node/depth ceilings match the saved original-JSON reader. Sort
    order changes no byte count; object/array kinds and scalar spellings do.
    """

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.size = 0
        self.nodes = 0
        self.active: set[int] = set()

    def add(self, amount: int) -> None:
        self.size += amount
        if self.size > self.limit:
            raise HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")

    def visit(self, value: Any, depth: int = 0) -> None:
        self.nodes += 1
        if depth > 16 or self.nodes > 262144:
            raise HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")
        if isinstance(value, e.ClosedFacts | h.FrozenDTO):
            check_closed_model(value)
            value = vars(value)
        elif type(value) is datetime:
            value = _model_json(value)
        if type(value) is str:
            # Every character contributes at least one byte, plus two quotes.
            if len(value) + 2 > self.limit - self.size:
                raise HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")
            self.add(2)
            for char in value:
                point = ord(char)
                if 0xD800 <= point <= 0xDFFF:
                    raise HistoricalAIError("BASELINE_SOURCE_INVALID")
                self.add(
                    2
                    if point in (34, 92, 8, 12, 10, 13, 9)
                    else 6
                    if point < 32
                    else 1
                    if point < 128
                    else 2
                    if point < 2048
                    else 3
                    if point < 65536
                    else 4
                )
        elif value is None:
            self.add(4)
        elif type(value) is bool:
            self.add(4 if value else 5)
        elif type(value) is int:
            # All admitted historical integers have this existing domain bound.
            if not -(2**63) <= value < 2**63:
                raise HistoricalAIError("BASELINE_SOURCE_INVALID")
            self.add(len(str(value)))
        elif type(value) is float:
            if not math.isfinite(value):
                raise HistoricalAIError("BASELINE_SOURCE_INVALID")
            self.add(len(repr(value)))
        elif type(value) in (dict, tuple, list, h.FrozenObject):
            if id(value) in self.active:
                raise HistoricalAIError("BASELINE_SOURCE_INVALID")
            is_object = type(value) in (dict, h.FrozenObject)
            entries = value.entries if type(value) is h.FrozenObject else value
            count = len(entries)
            if self.nodes + count * (2 if is_object else 1) > 262144:
                raise HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")
            self.add(2 + max(0, count - 1) + (count if is_object else 0))
            self.active.add(id(value))
            try:
                if is_object:
                    for key, child in entries.items() if type(entries) is dict else entries:
                        if type(key) is not str:
                            raise HistoricalAIError("BASELINE_SOURCE_INVALID")
                        self.visit(key, depth + 1)
                        self.visit(child, depth + 1)
                else:
                    for child in entries:
                        self.visit(child, depth + 1)
            finally:
                self.active.remove(id(value))
        else:
            raise HistoricalAIError("BASELINE_SOURCE_INVALID")


def validate_snapshot_sizes(value: dict[str, Any]) -> None:
    """Admit raw shape and exact bytes before serialization or hydration."""
    if type(value) is not dict:
        raise HistoricalAIError("BASELINE_SOURCE_INVALID")
    for name, limit in (
        ("baseline_comparisons", 128),
        ("baseline_sources", 16),
        ("admitted_bundles", 5),
        ("candidate_ids", 5),
        ("candidate_snapshots", 5),
        ("selection_inventory", 2048),
    ):
        if name in value and (type(value[name]) not in (tuple, list) or len(value[name]) > limit):
            raise HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")
    comparisons = value.get("baseline_comparisons", ())
    private = {name: value[name] for name in PRIVATE_ADDITIONS if name in value}
    # No encoder sees any scalar until all applicable cumulative gates pass.
    _CanonicalBudget(256 * 1024).visit(comparisons)
    _CanonicalBudget(1024 * 1024).visit(private)
    _CanonicalBudget(4 * 1024 * 1024).visit(value)
    encoder = json.JSONEncoder(
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=_model_json,
    )

    def bound(item: Any, budget: int) -> None:
        size = 0
        for part in encoder.iterencode(item):
            size += len(part.encode())
            if size > budget:
                raise HistoricalAIError("BASELINE_RUN_SNAPSHOT_LIMIT")

    bound(comparisons, 256 * 1024)
    bound(private, 1024 * 1024)


def compact_sources(sources: tuple[g.SourceReceipt, ...]) -> tuple[e.CompactSourceReference, ...]:
    return tuple(
        e.CompactSourceReference.model_validate_json(
            h.canonical_json(
                {key: source.to_mapping()[key] for key in e.CompactSourceReference.model_fields}
            )
        )
        for source in sources
    )


def decode_historical_snapshot(
    saved: str, *, request: HistoricalAdmissionRequest, expected_snapshot_sha256: str
) -> tuple[CandidateEvidenceBundle, ...]:
    """Decode an immutable admission envelope, not a mutable lifecycle record.

    The caller captures the canonical snapshot digest at admission and supplies
    it from its trusted owning envelope, independently of these saved bytes.
    A digest freshly recomputed from the supplied body cannot establish custody.
    The future persistence/worker adapter owns that envelope; this module adds
    neither a DTO self-hash nor a new storage field or mutable lifecycle policy.
    """
    try:
        _require(type(saved) is str and len(saved) <= 4 * 1024 * 1024)
        _require(type(expected_snapshot_sha256) is str and len(expected_snapshot_sha256) == 64)
        encoded = saved.encode()
        _require(len(encoded) <= 4 * 1024 * 1024)
        _require(hashlib.sha256(encoded).hexdigest() == expected_snapshot_sha256)
        request = checked_request(request)
        raw = h.thaw_original_json(h.decode_original_json(saved, max_bytes=4 * 1024 * 1024))
        if type(raw) is not dict:
            raise HistoricalAIError("HISTORICAL_SNAPSHOT_INVALID")
        validate_snapshot_sizes(raw)
        snapshot = HistoricalRunSnapshot.model_validate(raw)
        _require(h.canonical_json(snapshot.to_mapping()) == saved)
        _owner(snapshot, request)
        _selection(snapshot)
        comparisons = tuple(row.comparison() for row in snapshot.baseline_comparisons)
        facts = snapshot.baseline_summary.facts()
        _history(snapshot, facts, comparisons)
        refs = compact_sources(snapshot.baseline_sources)
        decoded = []
        attached = set()
        for identifier, bundle, frozen in zip(
            snapshot.candidate_ids,
            snapshot.admitted_bundles,
            snapshot.candidate_snapshots,
            strict=True,
        ):
            candidate = h._mapping(h.thaw_original_json(frozen))
            positive = sorted(
                (
                    c
                    for c in comparisons
                    if c.key.peer_ip == candidate["candidate_ip"] and c.historical_anomaly_score > 0
                ),
                key=lambda c: (-c.historical_anomaly_score, h.canonical_json(c.key.model_dump())),
            )
            expected = e.reference_for_selected_peer(
                external_ip=candidate["candidate_ip"],
                candidate_kind=candidate.get("candidate_kind", "C2"),
                facts=facts,
                comparisons=comparisons,
                historical_comparison_key=positive[0].key if positive else None,
                source_references=refs,
            )
            result = e.decode_admitted_bundle(
                bundle,
                expected_candidate_id=identifier,
                facts=expected.facts,
                comparisons=comparisons,
                source_references=refs,
                local_warnings=snapshot.selection_summary.warnings,
            )
            if result.historical_reference != expected:
                raise ValueError("selected provenance mismatch")
            _candidate_bundle(candidate, result)
            if expected.comparison:
                attached.add(expected.comparison.key)
            decoded.append(result)
        if any(row.selected != (row.key in attached) for row in snapshot.baseline_comparisons):
            raise ValueError("selected comparison mismatch")
        return tuple(decoded)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
        raise HistoricalAIError("HISTORICAL_SNAPSHOT_INVALID") from exc


def _require(condition: bool) -> None:
    if not condition:
        raise HistoricalAIError("HISTORICAL_SNAPSHOT_INVALID")


def _owner(snapshot: HistoricalRunSnapshot, request: HistoricalAdmissionRequest) -> None:
    _require(snapshot.id == request.run_id and snapshot.analysis_job_id == request.analysis_job_id)
    _require(snapshot.baseline_request == request.payload)
    _require(snapshot.baseline_request_fingerprint == request.request_fingerprint)
    _require(snapshot.created_by == request.actor)
    _require(snapshot.created_at == snapshot.updated_at == request.admitted_at)
    _require(snapshot.transitions[0].occurred_at == request.admitted_at)
    for field in (
        "provider",
        "model_name",
        "prompt_name",
        "prompt_version",
        "prompt_hash",
        "input_schema_version",
        "output_schema_version",
    ):
        _require(getattr(snapshot, field) == getattr(request, field))
    for field in (
        "idempotency_key",
        "candidate_limit",
        "language",
        "analysis_kind",
        "discovery_mode",
        "baseline_mode",
    ):
        _require(getattr(snapshot, field) == getattr(request.payload, field))
    reference = request.payload.baseline_reference
    _require(reference is not None)
    if reference is None:
        return
    summary = snapshot.baseline_summary
    _require(
        (
            summary.scope_id,
            summary.scope_revision,
            summary.generation_id,
            summary.target_source_binding_sha256,
        )
        == (
            reference.scope_id,
            reference.expected_revision,
            reference.generation_id,
            reference.target_source_binding_sha256,
        )
    )
    _require(summary.admitted_at == request.to_mapping()["admitted_at"])
    _require(
        summary.quality_assurance
        == ("ANALYST_ASSERTED" if reference.quality_review else "UNREVIEWED")
    )
    _require(
        ("EVALUATION_SENSOR_ALIAS" in summary.warnings)
        == bool(reference.quality_review and reference.quality_review.sensor_alias_asserted)
    )


def _selection(snapshot: HistoricalRunSnapshot) -> None:
    inventory, summary = snapshot.selection_inventory, snapshot.selection_summary
    ids = snapshot.candidate_ids
    _require(
        len(ids)
        == len(set(ids))
        == len(snapshot.candidate_snapshots)
        == len(snapshot.admitted_bundles)
    )
    _require(len(ids) <= snapshot.candidate_limit)
    _require(tuple(item.candidate_id for item in snapshot.admitted_bundles) == ids)
    _require(len({item.candidate_id for item in inventory}) == len(inventory))
    _require(len({item.external_ip for item in inventory}) == len(inventory))
    _require(tuple(item.candidate_id for item in inventory if item.selected) == ids)
    _require(
        tuple(item.selected for item in inventory)
        == tuple(i < len(ids) for i in range(len(inventory)))
    )
    _require(summary.candidate_pool_count == len(inventory))
    _require(
        summary.selected_count == len(ids) and summary.omitted_count == len(inventory) - len(ids)
    )
    discovery = {"BEHAVIOR", "RULE_AND_BEHAVIOR"}
    _require(summary.discovery_candidate_count == sum(i.origin in discovery for i in inventory))
    _require(
        summary.discovery_selected_count
        == sum(i.origin in discovery and i.selected for i in inventory)
    )
    _require(
        summary.rule_free_selected_count
        == sum(i.origin == "BEHAVIOR" and i.selected for i in inventory)
    )
    reserved = sum(i.reason == "DISCOVERY_RESERVED" for i in inventory)
    _require(
        summary.reserved_discovery_slots
        == reserved
        == min(2, snapshot.candidate_limit, sum(i.origin == "BEHAVIOR" for i in inventory))
    )
    for index, item in enumerate(inventory):
        _require(
            item.reason
            == (
                "DISCOVERY_RESERVED"
                if index < reserved
                else "RANKED"
                if item.selected
                else "BUDGET_LIMIT"
            )
        )
        if item.reason == "DISCOVERY_RESERVED":
            _require(item.origin == "BEHAVIOR")
    _require("NO_HISTORICAL_BASELINE" not in summary.warnings)
    for identifier, frozen, item in zip(
        ids, snapshot.candidate_snapshots, inventory[: len(ids)], strict=True
    ):
        candidate = h._mapping(h.thaw_original_json(frozen))
        _require(set(candidate) <= h.CANDIDATE_FIELDS - {"excluded"})
        _require(candidate["id"] == identifier)
        _require(candidate["candidate_ip"] == item.external_ip)
        _require(candidate["score"] == item.existing_score)
        _require(candidate.get("behavior_anomaly_score") == item.anomaly_score)
        _require(candidate.get("discovery_origin") == item.origin)


def validate_receipt_quality(sources: tuple[g.SourceReceipt, ...]) -> None:
    # Approval refuses known partial captures and clock uncertainty before
    # producing APPROVED_NORMAL (historical_generation.produce_generation).
    # These source negatives contradict that saved approval even if unused.
    for source in sources:
        if {"SOURCE_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN"}.intersection(source.limitations):
            raise HistoricalAIError("BASELINE_SOURCE_INVALID")


def _history(
    snapshot: HistoricalRunSnapshot,
    facts: e.ReferenceFacts,
    comparisons: tuple[e.ProfileComparison, ...],
) -> None:
    counts: Counter[str] = Counter(row.status for row in comparisons)
    _require(
        snapshot.baseline_summary.profile_counts.to_mapping()
        == {name: counts[name] for name in ProfileCounts.model_fields}
    )
    _require(len(comparisons) + snapshot.baseline_summary.unprofiled_count <= 128)
    keys = [h.canonical_json(c.key.model_dump(mode="json")) for c in comparisons]
    _require(keys == sorted(set(keys)))
    positives = {c.key.peer_ip for c in comparisons if c.historical_anomaly_score > 0}
    _require(snapshot.baseline_summary.historical_candidate_count == len(positives))
    sources = snapshot.baseline_sources
    _require(bool(sources) == (facts.generation_id is not None))
    _require(len({s.source_receipt_id for s in sources}) == len(sources))
    _require(len({s.root_identity for s in sources}) == len(sources))
    _require(len({s.feature_observation_sha256 for s in sources}) == len(sources))
    _require(sources == tuple(sorted(sources, key=lambda s: (s.event_end, s.source_receipt_id))))
    _require(len({s.sensor_key for s in sources}) <= 1)
    if facts.scope_kind == "OPERATIONAL":
        _require(len({s.actual_sensor_id for s in sources}) <= 1)
    for index, source in enumerate(sources):
        _require(source.quality_review.sensor_alias_asserted == (facts.scope_kind == "EVALUATION"))
        if facts.scope_kind == "OPERATIONAL":
            _require(source.origin == "SENSOR_CAPTURE")
        if index:
            _require(source.event_start > sources[index - 1].event_end)
        _require(source.approved_at <= snapshot.created_at)
    validate_receipt_quality(sources)
    full_manifest = {s.source_receipt_id: s for s in sources}
    cutoff = h._utc(facts.target_event_start)
    possible_future_count = sum(s.event_end >= cutoff for s in sources)
    manifest = {s.source_receipt_id: s for s in compact_sources(sources)}
    for row in comparisons:
        _require(row.key.scope_config_sha256 == facts.scope_config_sha256)
        _require(not sources or row.key.sensor_key == sources[0].sensor_key)
        _require(set(row.limitations) <= set(facts.limitations))
        _require(set(row.source_window_ids) <= set(manifest))
        for identifier in row.source_window_ids:
            source = full_manifest[identifier]
            _require(source.dataset_id != snapshot.dataset_id)
            _require(snapshot.analysis_job_id not in source.ancestry_job_ids)
        for feature in row.features.ordered():
            # Full receipts establish only an upper bound: individual profile
            # or family measurements need not exist in every future source.
            _require(feature.excluded_future_count <= possible_future_count)
            _require(
                len(feature.eligible_window_ids) + feature.excluded_future_count <= len(sources)
            )
        # This also validates non-selected rows against full saved support times.
        row_facts = e.ReferenceFacts.model_validate(
            {
                **facts.model_dump(),
                "limitations": tuple(sorted(set(facts.limitations) | set(row.limitations))),
            }
        )
        refs = tuple(manifest[i] for i in row.source_window_ids)
        e.reference_for_selected_peer(
            external_ip=row.key.peer_ip,
            candidate_kind="C2",
            facts=row_facts,
            comparisons=(row,),
            historical_comparison_key=row.key if row.historical_anomaly_score else None,
            source_references=refs,
        )


def _candidate_bundle(candidate: dict[str, Any], bundle: CandidateEvidenceBundle) -> None:
    from .ai_analysis import build_unfinalized_evidence_bundle

    # Validate saved identity using the unchanged formatting helper, not a job or
    # a model-input reconstruction. Return only the decoded canonical bytes.
    identity = build_unfinalized_evidence_bundle(candidate).candidate
    _require(identity == bundle.candidate)
    _require(candidate["evidence"] == final_evidence(bundle))


def final_evidence(bundle: CandidateEvidenceBundle) -> list[dict[str, Any]]:
    """Snapshot allowlist with finalized, not pre-reduction, selected evidence."""
    return [
        {
            "type": item.evidence_type,
            "description": item.description,
            "contribution": item.contribution,
            "metrics": item.metrics,
        }
        for item in bundle.evidence
    ]
