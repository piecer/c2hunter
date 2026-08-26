from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Literal, NamedTuple, Protocol, cast

from c2hunter_analysis.pcap_postings import PostingQueryLimits, select_posting_candidates

from .api_errors import ApiError
from .config import Settings
from .jobs import JobState
from .pcap import compile_packet_predicate
from .pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexIdentity,
    StructuralIndexIdentityLookup,
    StructuralIndexLookup,
    StructuralIndexParentIdentity,
    StructuralIndexSnapshot,
    structural_index_identity,
)
from .pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexIdentity,
    PostingIndexIdentityLookup,
    PostingIndexLookup,
    posting_index_identity,
    validate_posting_index,
)

PostingSourceKind = Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]
_HARD_MAX_MANIFEST_SOURCES = 1_024


@dataclass(frozen=True, order=True)
class PostingPacketCandidate:
    source_order: int
    source_kind: PostingSourceKind
    source_id: str
    parent_structural_build_id: str
    packet_index: int


@dataclass(frozen=True)
class AnalysisPostingCandidateSet:
    """Bounded safe superset; callers must apply the compiled predicate to referenced packets."""

    source_generation: str
    candidates: tuple[PostingPacketCandidate, ...]


class _PostingSelectionSourceProof(NamedTuple):
    source: CaptureSourceVersion
    parent: StructuralIndexSnapshot
    parent_identity: StructuralIndexIdentity
    posting_identity: PostingIndexIdentity


class _PostingSelectionPlan(NamedTuple):
    candidates: AnalysisPostingCandidateSet
    source_proofs: tuple[_PostingSelectionSourceProof, ...]


class PostingSelectionRepository(Protocol):
    def get_job_summary(self, job_id: str) -> dict[str, Any] | None: ...

    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None: ...

    def snapshot_pcap_export_source(
        self,
        job_id: str,
        canonical_request: dict[str, Any],
        effective_limits: dict[str, int],
    ) -> dict[str, Any] | None: ...

    def get_capture_source_version(self, source_id: str, /) -> CaptureSourceVersion | None: ...

    def get_live_capture_source_version(self, source_id: str, /) -> CaptureSourceVersion | None: ...

    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup: ...

    def get_structural_index_identity(
        self, source_version: CaptureSourceVersion
    ) -> StructuralIndexIdentityLookup: ...

    def get_posting_index(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        limits: PostingQueryLimits | None = None,
    ) -> PostingIndexLookup: ...

    def get_posting_index_identity(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexParentIdentity,
    ) -> PostingIndexIdentityLookup: ...


def _source_matches_manifest(
    source: CaptureSourceVersion,
    descriptor: Mapping[str, Any],
    source_kind: PostingSourceKind,
) -> bool:
    return bool(
        source.source_kind == source_kind
        and source.source_id == descriptor.get("id")
        and source.source_version_id == descriptor.get("version_id")
        and source.source_size_bytes == descriptor.get("size_bytes")
        and source.source_sha256 == descriptor.get("sha256")
    )


def _ready_parent(
    repository: PostingSelectionRepository, source: CaptureSourceVersion
) -> StructuralIndexSnapshot | None:
    compact = repository.get_structural_index_identity(source)
    if compact.availability is not IndexAvailability.READY or compact.identity is None:
        return None
    lookup = repository.get_structural_index(compact.identity.binding)
    if (
        lookup.availability is not IndexAvailability.READY
        or lookup.snapshot is None
        or structural_index_identity(lookup.snapshot) != compact.identity
    ):
        return None
    return lookup.snapshot


def _query_limits(settings: Settings) -> PostingQueryLimits:
    return PostingQueryLimits(
        max_operations=settings.pcap_posting_index_query_max_operations,
        max_result_ordinals=settings.pcap_posting_index_query_max_result_ordinals,
        max_decoded_memberships=settings.pcap_posting_index_query_max_decoded_memberships,
        max_directory_chunks=settings.pcap_posting_index_query_max_directory_chunks,
        max_dictionary_terms=settings.pcap_posting_index_query_max_dictionary_terms,
    )


def _allocated_query_limits(
    settings: Settings, source_count: int
) -> tuple[PostingQueryLimits, ...] | None:
    global_limits = _query_limits(settings)
    fields = (
        "max_operations",
        "max_result_ordinals",
        "max_decoded_memberships",
        "max_directory_chunks",
        "max_dictionary_terms",
    )
    if source_count <= 0 or any(getattr(global_limits, field) < source_count for field in fields):
        return None
    allocations: list[PostingQueryLimits] = []
    source_order = 0
    while source_order < source_count:
        values: dict[str, int] = {}
        for field in fields:
            quotient, remainder = divmod(getattr(global_limits, field), source_count)
            values[field] = quotient + (1 if source_order < remainder else 0)
        allocations.append(PostingQueryLimits(**values))
        source_order += 1
    return tuple(allocations)


def _source_identity(source: CaptureSourceVersion) -> tuple[object, ...]:
    return (
        source.source_kind,
        source.source_id,
        source.object_key,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
    )


def _select_analysis_posting_plan_from_snapshot(
    repository: PostingSelectionRepository,
    settings: Settings,
    *,
    requested_job: Mapping[str, Any],
    source_snapshot: Mapping[str, Any],
    canonical_request: Mapping[str, Any],
    candidate_id: str | None,
    max_sources: int = _HARD_MAX_MANIFEST_SOURCES,
) -> _PostingSelectionPlan | None:
    """Select an internal proof-bound plan from one authorized immutable snapshot."""
    del candidate_id  # Ownership and normalization belong to the compatibility facade/executor.
    job = requested_job
    normalized = dict(canonical_request)
    snapshot = source_snapshot
    manifest = snapshot.get("source_manifest")
    snapshot_kind = snapshot.get("source_kind")
    if (
        not isinstance(manifest, list)
        or not manifest
        or snapshot_kind not in {"canonical_capture", "segment_manifest"}
        or (snapshot_kind == "canonical_capture" and len(manifest) != 1)
    ):
        return None
    scan_packet_limit = settings.pcap_export_scan_max_packets
    effective_source_limit = min(max_sources, _HARD_MAX_MANIFEST_SOURCES)
    if (
        effective_source_limit <= 0
        or len(manifest) > effective_source_limit
        or scan_packet_limit is None
        or len(manifest) > scan_packet_limit
    ):
        return None

    source_kind: PostingSourceKind = (
        "PCAP_UPLOAD" if snapshot.get("source_kind") == "canonical_capture" else "LIVE_SEGMENT"
    )
    predicate = compile_packet_predicate(
        normalized,
        internal_networks=[str(item) for item in job.get("internal_networks", [])],
    )
    allocated_limits = _allocated_query_limits(settings, len(manifest))
    if allocated_limits is None:
        return None
    global_result_limit = settings.pcap_posting_index_query_max_result_ordinals
    selected: list[PostingPacketCandidate] = []
    observed: list[
        tuple[
            tuple[object, ...],
            StructuralIndexSnapshot,
            StructuralIndexIdentity,
            PostingIndexIdentity,
        ]
    ] = []
    for source_order, descriptor_value in enumerate(manifest):
        limits = allocated_limits[source_order]
        if not isinstance(descriptor_value, Mapping):
            return None
        descriptor = descriptor_value
        if descriptor.get("order") != source_order:
            return None
        source_id = descriptor.get("id")
        if not isinstance(source_id, str) or not source_id:
            return None
        source = (
            repository.get_capture_source_version(source_id)
            if source_kind == "PCAP_UPLOAD"
            else repository.get_live_capture_source_version(source_id)
        )
        if source is None or not _source_matches_manifest(source, descriptor, source_kind):
            return None
        parent = _ready_parent(repository, source)
        if parent is None:
            return None
        posting_lookup = repository.get_posting_index(source, parent, limits)
        posting = posting_lookup.snapshot
        if (
            posting_lookup.availability is not PostingIndexAvailability.READY
            or posting is None
            or not validate_posting_index(posting, source_version=source, parent=parent)
        ):
            return None
        ordinals = select_posting_candidates(
            posting.generation,
            predicate,
            sensor_id=str(descriptor.get("sensor_id", "")),
            limits=limits,
        )
        if ordinals is None:
            return None
        selected.extend(
            PostingPacketCandidate(
                source_order,
                source_kind,
                source_id,
                parent.build_id,
                packet_index,
            )
            for packet_index in ordinals
        )
        if len(selected) > global_result_limit:
            return None
        observed.append(
            (
                _source_identity(source),
                parent,
                structural_index_identity(parent),
                posting_index_identity(posting),
            )
        )

    final_sources: list[CaptureSourceVersion] = []
    # Re-read canonical ownership after all bounded queries so replacements or
    # deletion observed during selection invalidate the whole candidate view.
    for source_order, identities in enumerate(observed):
        descriptor = cast(Mapping[str, Any], manifest[source_order])
        source_identity, _parent, parent_identity, posting_identity = identities
        source_id = cast(str, source_identity[1])
        current_source = (
            repository.get_capture_source_version(source_id)
            if source_kind == "PCAP_UPLOAD"
            else repository.get_live_capture_source_version(source_id)
        )
        if (
            current_source is None
            or _source_identity(current_source) != source_identity
            or not _source_matches_manifest(current_source, descriptor, source_kind)
        ):
            return None
        current_parent = repository.get_structural_index_identity(current_source)
        if (
            current_parent.availability is not IndexAvailability.READY
            or current_parent.identity != parent_identity
        ):
            return None
        current_posting = repository.get_posting_index_identity(current_source, parent_identity)
        if (
            current_posting.availability is not PostingIndexAvailability.READY
            or current_posting.identity != posting_identity
        ):
            return None
        final_sources.append(current_source)

    unique = tuple(sorted(set(selected), key=lambda item: (item.source_order, item.packet_index)))
    proofs = tuple(
        _PostingSelectionSourceProof(source, identities[1], identities[2], identities[3])
        for source, identities in zip(final_sources, observed, strict=True)
    )
    return _PostingSelectionPlan(
        AnalysisPostingCandidateSet(str(snapshot.get("source_generation", "")), unique),
        proofs,
    )


def select_analysis_posting_candidates_from_snapshot(
    repository: PostingSelectionRepository,
    settings: Settings,
    *,
    requested_job: Mapping[str, Any],
    source_snapshot: Mapping[str, Any],
    canonical_request: Mapping[str, Any],
    candidate_id: str | None,
    max_sources: int = _HARD_MAX_MANIFEST_SOURCES,
) -> AnalysisPostingCandidateSet | None:
    """Return the unchanged Stage 11 facade from one admitted source snapshot."""
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=requested_job,
        source_snapshot=source_snapshot,
        canonical_request=canonical_request,
        candidate_id=candidate_id,
        max_sources=max_sources,
    )
    return None if plan is None else plan.candidates


def select_analysis_posting_candidates(
    repository: PostingSelectionRepository,
    settings: Settings,
    *,
    job_id: str,
    canonical_request: Mapping[str, Any],
    candidate_id: str | None = None,
    max_sources: int = _HARD_MAX_MANIFEST_SOURCES,
) -> AnalysisPostingCandidateSet | None:
    """Compatibility facade preserving authorization, ownership, and snapshot provenance."""
    job = repository.get_job_summary(job_id)
    if job is None:
        raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
    if job.get("mode") == "LIVE" and job.get("status") != JobState.COMPLETED:
        raise ApiError(
            409,
            "PCAP_SOURCE_NOT_FINAL",
            "LIVE analysis must be completed before PCAP export",
        )
    normalized = dict(canonical_request)
    if candidate_id is not None:
        found_candidate = repository.get_candidate(candidate_id)
        if found_candidate is None or found_candidate[0] != job_id:
            raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
        normalized["candidate_ip"] = found_candidate[1]["candidate_ip"]
    effective_limits = {
        "scan_max_bytes": cast(int, settings.pcap_export_scan_max_bytes),
        "scan_max_packets": cast(int, settings.pcap_export_scan_max_packets),
    }
    try:
        snapshot = repository.snapshot_pcap_export_source(job_id, normalized, effective_limits)
    except ValueError as exc:
        if str(exc) in {"source_provenance_cycle", "source_provenance_missing"}:
            raise ApiError(
                409,
                "PCAP_SOURCE_PROVENANCE_INVALID",
                "PCAP source provenance is invalid",
            ) from exc
        return None
    if snapshot is None:
        raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
    return select_analysis_posting_candidates_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=snapshot,
        canonical_request=normalized,
        candidate_id=candidate_id,
        max_sources=max_sources,
    )
