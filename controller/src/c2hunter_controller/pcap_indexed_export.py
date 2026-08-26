from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Literal, Protocol

from c2hunter_analysis.pcap import PcapParseError
from c2hunter_analysis.pcap_export import (
    CaptureInterface,
    PacketLocator,
    export_packet_from_structural_locator,
)
from c2hunter_analysis.pcap_index import StructuralPacketEntry

from .config import Settings
from .pcap import CompiledPacketPredicate
from .pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    StructuralIndexIdentity,
    StructuralIndexParentIdentity,
    StructuralIndexSnapshot,
    structural_index_identity,
    validate_structural_index,
)
from .pcap_posting_index import PostingIndexAvailability, PostingIndexIdentity
from .pcap_posting_selection import (
    PostingSelectionRepository,
    _PostingSelectionPlan,
    _select_analysis_posting_plan_from_snapshot,
)

_MAX_I64 = (1 << 63) - 1


class IndexedFallbackReason(StrEnum):
    UNSUPPORTED_SOURCE = "unsupported_source"
    UNSUPPORTED_SCAN_SEMANTICS = "unsupported_scan_semantics"
    INDEX_UNAVAILABLE = "index_unavailable"
    INDEX_CORRUPT = "index_corrupt"
    RESOURCE_LIMIT = "resource_limit"
    RANGE_MISSING = "range_missing"
    RANGE_SHORT = "range_short"
    RANGE_UNAVAILABLE = "range_unavailable"
    VERSION_DRIFT = "version_drift"
    OWNERSHIP_CHANGED = "ownership_changed"


class IndexedFallback(RuntimeError):
    """Typed reason that atomically abandons an entire provisional indexed batch."""

    def __init__(self, reason: IndexedFallbackReason) -> None:
        super().__init__(reason.value)
        self.reason = reason


class IndexedRangeFallback(IndexedFallback):
    """Compatibility name for pure locator/planner fallbacks."""

    def __init__(self, reason: str | IndexedFallbackReason) -> None:
        super().__init__(IndexedFallbackReason(reason))


class IndexedLocatorError(IndexedRangeFallback):
    def __init__(self, message: str = "index_corrupt") -> None:
        super().__init__(message)


class CaptureRangeError(RuntimeError):
    pass


class CaptureRangeMissing(CaptureRangeError):
    pass


class CaptureRangeUnavailable(CaptureRangeError):
    pass


class CaptureRangeVersionDrift(CaptureRangeError):
    pass


class CaptureRangeShortRead(CaptureRangeError):
    pass


@dataclass(frozen=True)
class CaptureByteRange:
    offset: int
    length: int

    def __post_init__(self) -> None:
        if type(self.offset) is not int or self.offset < 0 or self.offset > _MAX_I64:
            raise ValueError("capture range offset must be a non-negative signed 64-bit integer")
        if type(self.length) is not int or self.length <= 0 or self.length > _MAX_I64:
            raise ValueError("capture range length must be a positive signed 64-bit integer")
        if self.offset > _MAX_I64 - self.length:
            raise ValueError("capture range end exceeds signed 64-bit bounds")

    def validate_for_source(self, source: CaptureSourceVersion) -> None:
        if self.offset + self.length > source.source_size_bytes:
            raise ValueError("capture range exceeds source size")


@dataclass(frozen=True)
class SelectedPacketLocator:
    source_kind: Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]
    source_id: str
    object_key: str
    source_version_id: str
    source_size_bytes: int
    source_sha256: str
    parent_structural_build_id: str
    source_order: int
    packet_index: int
    record_offset: int
    data_offset: int
    captured_length: int
    original_length: int
    framed_length: int
    raw_timestamp_ticks: int
    interface: CaptureInterface

    @property
    def locator(self) -> PacketLocator:
        return PacketLocator(
            self.source_id,
            self.source_order,
            self.packet_index,
            self.record_offset,
            self.data_offset,
            self.captured_length,
            self.framed_length,
        )


@dataclass(frozen=True)
class LocatedPacketSelection:
    locators: tuple[SelectedPacketLocator, ...]
    admitted_packet_count: int
    scanned_bytes: int
    byte_limited: bool
    packet_limited: bool


def _validate_snapshot_binding(
    source: CaptureSourceVersion,
    snapshot: StructuralIndexSnapshot,
    expected_parent_build_id: str,
) -> None:
    binding = snapshot.binding
    if (
        not expected_parent_build_id
        or snapshot.build_id != expected_parent_build_id
        or binding.source_kind != source.source_kind
        or binding.source_id != source.source_id
        or binding.source_version_id != source.source_version_id
        or binding.source_size_bytes != source.source_size_bytes
        or binding.source_sha256 != source.source_sha256
        or not validate_structural_index(snapshot)
    ):
        raise IndexedLocatorError()


def _classic_prefix(
    packets: tuple[StructuralPacketEntry, ...],
    source_size: int,
    byte_budget: int,
    packet_limit: int,
) -> tuple[int, int, bool, bool]:
    if byte_budget < 0 or packet_limit < 0:
        raise IndexedLocatorError()
    if byte_budget < 24:
        return 0, 0, True, False
    admitted = 0
    scanned = 24
    source_exceeds_limit = source_size > byte_budget
    while admitted < len(packets):
        if source_exceeds_limit and byte_budget - scanned < 16:
            return admitted, scanned, True, False
        if admitted >= packet_limit:
            return admitted, scanned, False, True
        packet = packets[admitted]
        end = packet.record_offset + packet.framed_length
        if source_exceeds_limit and end > byte_budget:
            return admitted, scanned, True, False
        admitted += 1
        scanned = end
    if byte_budget >= source_size:
        scanned = source_size
    return admitted, scanned, scanned < source_size, False


def locate_selected_packets(
    source: CaptureSourceVersion,
    snapshot: StructuralIndexSnapshot,
    *,
    expected_parent_build_id: str,
    selected_ordinals: tuple[int, ...],
    source_order: int,
    remaining_byte_budget: int,
    remaining_packet_limit: int,
) -> LocatedPacketSelection:
    """Map posting ordinals to exact, scan-prefix-fenced structural locators."""
    _validate_snapshot_binding(source, snapshot, expected_parent_build_id)
    if source_order < 0 or remaining_byte_budget < 0 or remaining_packet_limit < 0:
        raise IndexedLocatorError()
    if any(type(value) is not int for value in selected_ordinals) or any(
        current <= previous
        for previous, current in zip(selected_ordinals, selected_ordinals[1:], strict=False)
    ):
        raise IndexedLocatorError()
    if selected_ordinals and (
        selected_ordinals[0] < 0 or selected_ordinals[-1] >= len(snapshot.packets)
    ):
        raise IndexedLocatorError()
    if snapshot.binding.capture_format == "PCAPNG":
        if remaining_byte_budget < source.source_size_bytes:
            raise IndexedRangeFallback("unsupported_scan_semantics")
        admitted = min(len(snapshot.packets), remaining_packet_limit)
        packet_limited = admitted < len(snapshot.packets)
        scanned = (
            snapshot.packets[admitted].record_offset if packet_limited else source.source_size_bytes
        )
        byte_limited = False
    elif snapshot.binding.capture_format == "PCAP":
        admitted, scanned, byte_limited, packet_limited = _classic_prefix(
            snapshot.packets,
            source.source_size_bytes,
            remaining_byte_budget,
            remaining_packet_limit,
        )
    else:  # defensive against runtime-constructed invalid dataclasses
        raise IndexedRangeFallback("unsupported_scan_semantics")
    interface_map = {item.interface_ordinal: item for item in snapshot.interfaces}
    located: list[SelectedPacketLocator] = []
    for ordinal in selected_ordinals:
        if ordinal >= admitted:
            continue
        packet = snapshot.packets[ordinal]
        if packet.packet_index != ordinal:
            raise IndexedLocatorError()
        structural_interface = interface_map.get(packet.interface_ordinal)
        if (
            structural_interface is None
            or structural_interface.section_index != packet.section_index
            or structural_interface.interface_id != packet.interface_id
        ):
            raise IndexedLocatorError()
        interface = CaptureInterface(
            structural_interface.section_index,
            structural_interface.interface_id,
            structural_interface.interface_ordinal,
            structural_interface.link_type,
            structural_interface.snaplen,
            structural_interface.timestamp_resolution_numerator,
            structural_interface.timestamp_resolution_denominator,
            structural_interface.timestamp_offset_seconds,
        )
        located.append(
            SelectedPacketLocator(
                source.source_kind,
                source.source_id,
                source.object_key,
                source.source_version_id,
                source.source_size_bytes,
                source.source_sha256,
                snapshot.build_id,
                source_order,
                ordinal,
                packet.record_offset,
                packet.data_offset,
                packet.captured_length,
                packet.original_length,
                packet.framed_length,
                packet.raw_timestamp_ticks,
                interface,
            )
        )
    return LocatedPacketSelection(tuple(located), admitted, scanned, byte_limited, packet_limited)


@dataclass(frozen=True)
class PacketRangeSlice:
    packet_index: int
    data_offset: int
    captured_length: int


@dataclass(frozen=True)
class CoalescedRange:
    source_kind: Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]
    source_id: str
    object_key: str
    source_version_id: str
    parent_structural_build_id: str
    offset: int
    length: int
    packet_slices: tuple[PacketRangeSlice, ...]

    @property
    def byte_range(self) -> CaptureByteRange:
        return CaptureByteRange(self.offset, self.length)


@dataclass(frozen=True)
class RangePlan:
    ranges: tuple[CoalescedRange, ...]
    selected_payload_bytes: int
    fetched_bytes: int

    @property
    def amplification(self) -> float:
        return self.fetched_bytes / max(1, self.selected_payload_bytes)


@dataclass(frozen=True)
class RangePlanLimits:
    max_gap_bytes: int
    max_range_bytes: int
    max_ranges: int
    max_total_fetched_bytes: int
    max_amplification_numerator: int
    max_amplification_denominator: int
    max_source_fraction_numerator: int
    max_source_fraction_denominator: int

    def __post_init__(self) -> None:
        values = (
            self.max_gap_bytes,
            self.max_range_bytes,
            self.max_ranges,
            self.max_total_fetched_bytes,
            self.max_amplification_numerator,
            self.max_amplification_denominator,
            self.max_source_fraction_numerator,
            self.max_source_fraction_denominator,
        )
        if (
            any(type(value) is not int or value > _MAX_I64 for value in values)
            or self.max_gap_bytes < 0
            or self.max_range_bytes <= 0
            or self.max_ranges <= 0
            or self.max_total_fetched_bytes <= 0
            or self.max_amplification_numerator <= 0
            or self.max_amplification_denominator <= 0
            or self.max_amplification_numerator < self.max_amplification_denominator
            or self.max_source_fraction_numerator <= 0
            or self.max_source_fraction_denominator <= 0
            or self.max_source_fraction_numerator > self.max_source_fraction_denominator
        ):
            raise ValueError("invalid indexed range planning limits")


@dataclass(frozen=True)
class SourceRangePlanLimits:
    """Physical ceilings that apply independently to each capture source."""

    max_gap_bytes: int
    max_range_bytes: int
    max_source_fraction_numerator: int
    max_source_fraction_denominator: int

    def __post_init__(self) -> None:
        values = (
            self.max_gap_bytes,
            self.max_range_bytes,
            self.max_source_fraction_numerator,
            self.max_source_fraction_denominator,
        )
        if (
            any(type(value) is not int or value > _MAX_I64 for value in values)
            or self.max_gap_bytes < 0
            or self.max_range_bytes <= 0
            or self.max_source_fraction_numerator <= 0
            or self.max_source_fraction_denominator <= 0
            or self.max_source_fraction_numerator > self.max_source_fraction_denominator
        ):
            raise ValueError("invalid per-source indexed range planning limits")


def _source_range_limits(limits: RangePlanLimits) -> SourceRangePlanLimits:
    return SourceRangePlanLimits(
        limits.max_gap_bytes,
        limits.max_range_bytes,
        limits.max_source_fraction_numerator,
        limits.max_source_fraction_denominator,
    )


def _same_identity(left: SelectedPacketLocator, right: SelectedPacketLocator) -> bool:
    return (
        left.source_kind,
        left.source_id,
        left.object_key,
        left.source_version_id,
        left.parent_structural_build_id,
    ) == (
        right.source_kind,
        right.source_id,
        right.object_key,
        right.source_version_id,
        right.parent_structural_build_id,
    )


def plan_source_packet_ranges(
    locators: tuple[SelectedPacketLocator, ...], *, limits: SourceRangePlanLimits
) -> RangePlan:
    """Pure physical planner retaining only ceilings independent per source."""
    ordered = tuple(
        sorted(
            locators,
            key=lambda locator: (
                locator.source_order,
                locator.data_offset,
                locator.packet_index,
            ),
        )
    )
    packet_identities = {
        (locator.source_kind, locator.source_id, locator.source_version_id, locator.packet_index)
        for locator in ordered
    }
    if len(packet_identities) != len(ordered):
        raise IndexedLocatorError()
    source_identities: dict[tuple[str, str, str], tuple[str, int, str, str, int]] = {}
    orders: dict[int, tuple[str, str, str]] = {}
    selected_bytes = sum(item.captured_length for item in ordered)
    ranges: list[CoalescedRange] = []
    previous: SelectedPacketLocator | None = None
    for item in ordered:
        identity_key = (item.source_kind, item.source_id, item.source_version_id)
        identity = (
            item.object_key,
            item.source_size_bytes,
            item.source_sha256,
            item.parent_structural_build_id,
            item.source_order,
        )
        if source_identities.setdefault(identity_key, identity) != identity:
            raise IndexedLocatorError()
        if orders.setdefault(item.source_order, identity_key) != identity_key:
            raise IndexedLocatorError()
        if (
            type(item.data_offset) is not int
            or type(item.captured_length) is not int
            or item.data_offset < 0
            or item.data_offset > _MAX_I64
            or item.captured_length < 0
            or item.captured_length > _MAX_I64
            or item.data_offset + item.captured_length > item.source_size_bytes
        ):
            raise IndexedLocatorError()
        packet_slice = PacketRangeSlice(item.packet_index, item.data_offset, item.captured_length)
        if item.captured_length == 0:
            previous = item
            continue
        if item.captured_length > limits.max_range_bytes:
            raise IndexedRangeFallback("resource_limit")
        can_join = False
        if ranges and previous is not None and _same_identity(previous, item):
            current = ranges[-1]
            current_end = current.offset + current.length
            gap = item.data_offset - current_end
            span = item.data_offset + item.captured_length - current.offset
            can_join = (
                item.packet_index == previous.packet_index + 1
                and gap >= 0
                and gap <= limits.max_gap_bytes
                and span <= limits.max_range_bytes
                and current.source_id == item.source_id
                and current.source_version_id == item.source_version_id
            )
        if can_join:
            current = ranges[-1]
            ranges[-1] = CoalescedRange(
                current.source_kind,
                current.source_id,
                current.object_key,
                current.source_version_id,
                current.parent_structural_build_id,
                current.offset,
                item.data_offset + item.captured_length - current.offset,
                current.packet_slices + (packet_slice,),
            )
        else:
            ranges.append(
                CoalescedRange(
                    item.source_kind,
                    item.source_id,
                    item.object_key,
                    item.source_version_id,
                    item.parent_structural_build_id,
                    item.data_offset,
                    item.captured_length,
                    (packet_slice,),
                )
            )
        previous = item
    fetched = sum(item.length for item in ranges)
    fetched_by_source: dict[tuple[str, str, str], int] = {}
    source_sizes: dict[tuple[str, str, str], int] = {}
    for item in ordered:
        key = (item.source_kind, item.source_id, item.source_version_id)
        source_sizes[key] = item.source_size_bytes
    for byte_range in ranges:
        key = (byte_range.source_kind, byte_range.source_id, byte_range.source_version_id)
        fetched_by_source[key] = fetched_by_source.get(key, 0) + byte_range.length
    if any(
        count >= source_sizes[key]
        or count * limits.max_source_fraction_denominator
        > source_sizes[key] * limits.max_source_fraction_numerator
        for key, count in fetched_by_source.items()
    ):
        raise IndexedRangeFallback("resource_limit")
    return RangePlan(tuple(ranges), selected_bytes, fetched)


def _validate_request_range_totals(
    *, range_count: int, fetched_bytes: int, selected_payload_bytes: int, limits: RangePlanLimits
) -> None:
    if range_count > limits.max_ranges or fetched_bytes > limits.max_total_fetched_bytes:
        raise IndexedRangeFallback("resource_limit")
    if selected_payload_bytes == 0:
        if fetched_bytes != 0:
            raise IndexedRangeFallback("resource_limit")
        return
    if (
        fetched_bytes * limits.max_amplification_denominator
        > selected_payload_bytes * limits.max_amplification_numerator
    ):
        raise IndexedRangeFallback("resource_limit")


def plan_packet_ranges(
    locators: tuple[SelectedPacketLocator, ...], *, limits: RangePlanLimits
) -> RangePlan:
    """Pure planner enforcing both per-source and whole-plan resource ceilings."""
    plan = plan_source_packet_ranges(locators, limits=_source_range_limits(limits))
    _validate_request_range_totals(
        range_count=len(plan.ranges),
        fetched_bytes=plan.fetched_bytes,
        selected_payload_bytes=plan.selected_payload_bytes,
        limits=limits,
    )
    return plan


class IndexedExportRepository(PostingSelectionRepository, Protocol):
    def get_capture_source_version(self, source_id: str, /) -> CaptureSourceVersion | None: ...

    def get_live_capture_source_version(self, source_id: str, /) -> CaptureSourceVersion | None: ...

    def get_posting_index_identity(
        self, source_version: CaptureSourceVersion, parent: StructuralIndexParentIdentity
    ) -> Any: ...

    def read_capture_range(
        self, source: CaptureSourceVersion, byte_range: CaptureByteRange
    ) -> bytes: ...


class IndexedMatchFactory(Protocol):
    """Internal executor seam for one admitted, authorization-normalized snapshot."""

    def __call__(
        self,
        *,
        repository: object,
        settings: Settings,
        requested_job: Mapping[str, Any],
        source_snapshot: Mapping[str, Any],
        canonical_request: Mapping[str, Any],
        candidate_id: str | None,
        predicate: CompiledPacketPredicate,
        internal_networks: Sequence[str],
        scan_max_bytes: int,
        scan_max_packets: int,
        checkpoint: Callable[..., None],
        check_cancelled: Callable[[], None] | None = None,
        check_deadline: Callable[[], None] | None = None,
    ) -> IndexedMatchBatch: ...


@dataclass(frozen=True)
class IndexedSourceIdentityProof:
    source: CaptureSourceVersion
    parent_identity: StructuralIndexIdentity
    posting_identity: PostingIndexIdentity


@dataclass(frozen=True)
class IndexedMatchBatch:
    """Complete provisional indexed result; safe to write only after final fences."""

    records: tuple[Any, ...]
    source_capture_count: int
    scanned_source_capture_count: int
    source_total_bytes: int
    scanned_source_bytes: int
    scanned_packet_count: int
    source_manifest: tuple[tuple[str, str], ...]
    truncation_reasons: tuple[str, ...]
    range_count: int
    selected_payload_bytes: int
    fetched_bytes: int
    identity_proof: tuple[IndexedSourceIdentityProof, ...]
    requested_range_count: int = 0


def _source_identity(source: CaptureSourceVersion) -> tuple[object, ...]:
    return (
        source.source_kind,
        source.source_id,
        source.object_key,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
    )


def _current_source(
    repository: IndexedExportRepository, source_kind: str, source_id: str
) -> CaptureSourceVersion | None:
    if source_kind == "PCAP_UPLOAD":
        return repository.get_capture_source_version(source_id)
    if source_kind == "LIVE_SEGMENT":
        return repository.get_live_capture_source_version(source_id)
    return None


def _run_checks(check_cancelled: Callable[[], None], check_deadline: Callable[[], None]) -> None:
    check_cancelled()
    if check_deadline is not check_cancelled:
        check_deadline()


def _fallback_for_range_error(exc: CaptureRangeError) -> IndexedFallback:
    if isinstance(exc, CaptureRangeMissing):
        return IndexedFallback(IndexedFallbackReason.RANGE_MISSING)
    if isinstance(exc, CaptureRangeShortRead):
        return IndexedFallback(IndexedFallbackReason.RANGE_SHORT)
    if isinstance(exc, CaptureRangeVersionDrift):
        return IndexedFallback(IndexedFallbackReason.VERSION_DRIFT)
    return IndexedFallback(IndexedFallbackReason.RANGE_UNAVAILABLE)


def _validate_exact_range_plan(
    plan: RangePlan, locators: tuple[SelectedPacketLocator, ...]
) -> None:
    expected = {
        locator.packet_index: (locator.data_offset, locator.captured_length)
        for locator in locators
        if locator.captured_length > 0
    }
    observed: dict[int, tuple[int, int]] = {}
    intervals: dict[tuple[str, str, str], list[tuple[int, int]]] = {}
    for byte_range in plan.ranges:
        range_end = byte_range.offset + byte_range.length
        identity = (
            byte_range.source_kind,
            byte_range.source_id,
            byte_range.source_version_id,
        )
        for packet_slice in byte_range.packet_slices:
            slice_end = packet_slice.data_offset + packet_slice.captured_length
            if (
                packet_slice.packet_index in observed
                or packet_slice.captured_length <= 0
                or packet_slice.data_offset < byte_range.offset
                or slice_end > range_end
            ):
                raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)
            observed[packet_slice.packet_index] = (
                packet_slice.data_offset,
                packet_slice.captured_length,
            )
            intervals.setdefault(identity, []).append((packet_slice.data_offset, slice_end))
    if observed != expected:
        raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)
    for source_intervals in intervals.values():
        ordered = sorted(source_intervals)
        pairs = zip(ordered, ordered[1:], strict=False)
        if any(current_start < previous_end for (_, previous_end), (current_start, _) in pairs):
            raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)


@dataclass(frozen=True)
class _PlannedIndexedSource:
    source: CaptureSourceVersion
    parent: StructuralIndexSnapshot
    located: LocatedPacketSelection
    range_plan: RangePlan
    sensor_id: str
    scanned_packets_before: int
    identity_proof: IndexedSourceIdentityProof


def _fence_indexed_source_proofs(
    repository: IndexedExportRepository,
    proofs: Sequence[IndexedSourceIdentityProof],
    *,
    check_cancelled: Callable[[], None],
    check_deadline: Callable[[], None],
) -> None:
    for proof in proofs:
        source = _current_source(repository, proof.source.source_kind, proof.source.source_id)
        if source is None or _source_identity(source) != _source_identity(proof.source):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
        parent = repository.get_structural_index_identity(source)
        if (
            parent.availability is not IndexAvailability.READY
            or parent.identity != proof.parent_identity
        ):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
        posting = repository.get_posting_index_identity(source, proof.parent_identity)
        if (
            posting.availability is not PostingIndexAvailability.READY
            or posting.identity != proof.posting_identity
        ):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
        _run_checks(check_cancelled, check_deadline)


def collect_indexed_matches(
    repository: IndexedExportRepository,
    *,
    source_snapshot: Mapping[str, Any],
    selection_plan: _PostingSelectionPlan,
    predicate: CompiledPacketPredicate,
    internal_networks: Sequence[str],
    scan_max_bytes: int,
    scan_max_packets: int,
    range_limits: RangePlanLimits,
    checkpoint: Callable[..., None] | None = None,
    check_cancelled: Callable[[], None] | None = None,
    check_deadline: Callable[[], None] | None = None,
) -> IndexedMatchBatch:
    """Collect an all-or-nothing sparse-read batch without writer or publication I/O."""
    checkpoint = checkpoint or (lambda **_progress: None)
    check_cancelled = check_cancelled or (lambda: None)
    check_deadline = check_deadline or (lambda: None)
    _run_checks(check_cancelled, check_deadline)
    manifest_value = source_snapshot.get("source_manifest")
    if (
        not isinstance(manifest_value, list)
        or not manifest_value
        or str(source_snapshot.get("source_generation", ""))
        != selection_plan.candidates.source_generation
        or len(selection_plan.source_proofs) != len(manifest_value)
        or scan_max_bytes < 0
        or scan_max_packets < 0
    ):
        raise IndexedFallback(IndexedFallbackReason.UNSUPPORTED_SOURCE)
    manifest = manifest_value
    snapshot_kind = source_snapshot.get("source_kind")
    expected_source_kind = (
        "PCAP_UPLOAD"
        if snapshot_kind == "canonical_capture"
        else "LIVE_SEGMENT"
        if snapshot_kind == "segment_manifest"
        else None
    )
    if expected_source_kind is None or (
        expected_source_kind == "PCAP_UPLOAD" and len(manifest) != 1
    ):
        raise IndexedFallback(IndexedFallbackReason.UNSUPPORTED_SOURCE)
    for source_order, (descriptor_value, proof) in enumerate(
        zip(manifest, selection_plan.source_proofs, strict=True)
    ):
        if (
            not isinstance(descriptor_value, Mapping)
            or descriptor_value.get("order") != source_order
            or not isinstance(descriptor_value.get("id"), str)
            or not descriptor_value.get("id")
        ):
            raise IndexedFallback(IndexedFallbackReason.UNSUPPORTED_SOURCE)
        if (
            proof.source.source_kind != expected_source_kind
            or proof.source.source_id != descriptor_value.get("id")
            or proof.source.source_version_id != descriptor_value.get("version_id")
            or proof.source.source_size_bytes != descriptor_value.get("size_bytes")
            or proof.source.source_sha256 != descriptor_value.get("sha256")
        ):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
    selected_by_source: dict[int, list[int]] = {}
    for candidate in selection_plan.candidates.candidates:
        if candidate.source_order < 0 or candidate.source_order >= len(manifest):
            raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)
        descriptor = manifest[candidate.source_order]
        proof = selection_plan.source_proofs[candidate.source_order]
        if (
            not isinstance(descriptor, Mapping)
            or candidate.source_id != descriptor.get("id")
            or candidate.source_kind != expected_source_kind
            or candidate.source_kind != proof.source.source_kind
            or candidate.source_id != proof.source.source_id
            or candidate.parent_structural_build_id != proof.parent_identity.build_id
        ):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
        selected_by_source.setdefault(candidate.source_order, []).append(candidate.packet_index)
    if any(ordinals != sorted(set(ordinals)) for ordinals in selected_by_source.values()):
        raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)

    from .pcap_stream import MatchedPacketRecord

    records: list[Any] = []
    planned_sources: list[_PlannedIndexedSource] = []
    final_proofs: list[IndexedSourceIdentityProof] = []
    source_manifest: list[tuple[str, str]] = []
    truncation: list[str] = []
    scanned_bytes = 0
    scanned_packets = 0
    scanned_sources = 0
    total_source_bytes = sum(
        proof.source.source_size_bytes for proof in selection_plan.source_proofs
    )
    range_count = 0
    selected_payload_bytes = 0
    fetched_bytes = 0

    for source_order, descriptor_value in enumerate(manifest):
        _run_checks(check_cancelled, check_deadline)
        if (
            not isinstance(descriptor_value, Mapping)
            or descriptor_value.get("order") != source_order
        ):
            raise IndexedFallback(IndexedFallbackReason.UNSUPPORTED_SOURCE)
        descriptor = descriptor_value
        proof = selection_plan.source_proofs[source_order]
        source_id = descriptor.get("id")
        if not isinstance(source_id, str) or not source_id:
            raise IndexedFallback(IndexedFallbackReason.UNSUPPORTED_SOURCE)
        source = _current_source(repository, proof.source.source_kind, source_id)
        if (
            source is None
            or _source_identity(source) != _source_identity(proof.source)
            or source.source_version_id != descriptor.get("version_id")
            or source.source_size_bytes != descriptor.get("size_bytes")
            or source.source_sha256 != descriptor.get("sha256")
        ):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
        compact_parent = repository.get_structural_index_identity(source)
        if compact_parent.availability is IndexAvailability.MISSING:
            raise IndexedFallback(IndexedFallbackReason.INDEX_UNAVAILABLE)
        if (
            compact_parent.availability is not IndexAvailability.READY
            or compact_parent.identity != proof.parent_identity
        ):
            raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)
        parent = proof.parent
        if structural_index_identity(
            parent
        ) != proof.parent_identity or not validate_structural_index(parent):
            raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)
        posting = repository.get_posting_index_identity(source, proof.parent_identity)
        if (
            posting.availability is not PostingIndexAvailability.READY
            or posting.identity != proof.posting_identity
        ):
            raise IndexedFallback(IndexedFallbackReason.OWNERSHIP_CHANGED)
        _run_checks(check_cancelled, check_deadline)

        remaining_bytes = scan_max_bytes - scanned_bytes
        remaining_packets = scan_max_packets - scanned_packets
        if remaining_packets < 1:
            truncation.append("SOURCE_PACKET_LIMIT")
            break
        if remaining_bytes < 1:
            truncation.append("SOURCE_BYTE_LIMIT")
            break
        ordinals = tuple(selected_by_source.get(source_order, ()))
        located = locate_selected_packets(
            source,
            parent,
            expected_parent_build_id=parent.build_id,
            selected_ordinals=ordinals,
            source_order=source_order,
            remaining_byte_budget=remaining_bytes,
            remaining_packet_limit=remaining_packets,
        )
        plan = plan_source_packet_ranges(
            located.locators, limits=_source_range_limits(range_limits)
        )
        _validate_exact_range_plan(plan, located.locators)
        next_range_count = range_count + len(plan.ranges)
        next_selected_payload_bytes = selected_payload_bytes + plan.selected_payload_bytes
        next_fetched_bytes = fetched_bytes + plan.fetched_bytes
        if (
            next_range_count > range_limits.max_ranges
            or next_fetched_bytes > range_limits.max_total_fetched_bytes
        ):
            raise IndexedRangeFallback("resource_limit")
        identity_proof = IndexedSourceIdentityProof(
            source, proof.parent_identity, proof.posting_identity
        )
        planned_sources.append(
            _PlannedIndexedSource(
                source,
                parent,
                located,
                plan,
                str(descriptor.get("sensor_id", "")),
                scanned_packets,
                identity_proof,
            )
        )
        scanned_bytes += located.scanned_bytes
        scanned_packets += located.admitted_packet_count
        if located.admitted_packet_count:
            scanned_sources += 1
        source_manifest.append((source.source_id, source.source_sha256))
        range_count = next_range_count
        selected_payload_bytes = next_selected_payload_bytes
        fetched_bytes = next_fetched_bytes
        if located.byte_limited:
            truncation.append("SOURCE_BYTE_LIMIT")
        if located.packet_limited:
            truncation.append("SOURCE_PACKET_LIMIT")
        final_proofs.append(identity_proof)
        if located.byte_limited or located.packet_limited:
            break

    # Amplification is a weighted request-wide ratio. Checking source prefixes would
    # cause avoidable fallback when later selected payload makes the exact total safe.
    _validate_request_range_totals(
        range_count=range_count,
        fetched_bytes=fetched_bytes,
        selected_payload_bytes=selected_payload_bytes,
        limits=range_limits,
    )

    # Recheck the complete admitted plan before the first range read. This catches
    # metadata races triggered while later manifest sources were being planned.
    _run_checks(check_cancelled, check_deadline)
    _fence_indexed_source_proofs(
        repository,
        final_proofs,
        check_cancelled=check_cancelled,
        check_deadline=check_deadline,
    )

    # Fetch and decode only after every per-source plan and global total is admitted.
    for planned in planned_sources:
        _fence_indexed_source_proofs(
            repository,
            (planned.identity_proof,),
            check_cancelled=check_cancelled,
            check_deadline=check_deadline,
        )
        source = planned.source
        located = planned.located
        plan = planned.range_plan
        raw_packets: dict[int, bytes] = {
            locator.packet_index: b""
            for locator in located.locators
            if locator.captured_length == 0
        }
        for byte_range in plan.ranges:
            _run_checks(check_cancelled, check_deadline)
            checkpoint(
                phase="SOURCE_FETCH",
                scanned_packet_count=planned.scanned_packets_before,
                requested_range_bytes=byte_range.length,
            )
            try:
                content = repository.read_capture_range(source, byte_range.byte_range)
            except CaptureRangeError as exc:
                raise _fallback_for_range_error(exc) from exc
            if type(content) is not bytes or len(content) != byte_range.length:
                raise IndexedFallback(IndexedFallbackReason.RANGE_SHORT)
            _run_checks(check_cancelled, check_deadline)
            for packet_slice in byte_range.packet_slices:
                start = packet_slice.data_offset - byte_range.offset
                end = start + packet_slice.captured_length
                packet_bytes = content[start:end]
                if start < 0 or len(packet_bytes) != packet_slice.captured_length:
                    raise IndexedFallback(IndexedFallbackReason.RANGE_SHORT)
                raw_packets[packet_slice.packet_index] = packet_bytes
        for locator in located.locators:
            if locator.packet_index % 256 == 0:
                _run_checks(check_cancelled, check_deadline)
            selected_packet_bytes = raw_packets.get(locator.packet_index)
            if selected_packet_bytes is None:
                raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT)
            try:
                packet = export_packet_from_structural_locator(
                    selected_packet_bytes,
                    locator=locator.locator,
                    interface=locator.interface,
                    original_length=locator.original_length,
                    raw_timestamp_ticks=locator.raw_timestamp_ticks,
                    internal_networks=internal_networks,
                )
            except PcapParseError as exc:
                raise IndexedFallback(IndexedFallbackReason.INDEX_CORRUPT) from exc
            if packet.supported and predicate.matches(packet, sensor_id=planned.sensor_id):
                records.append(
                    MatchedPacketRecord.from_export_packet(packet, sensor_id=planned.sensor_id)
                )

    # Exact post-fence for every admitted source. Cancellation/deadline remain outside fallback.
    _run_checks(check_cancelled, check_deadline)
    _fence_indexed_source_proofs(
        repository,
        final_proofs,
        check_cancelled=check_cancelled,
        check_deadline=check_deadline,
    )

    return IndexedMatchBatch(
        tuple(records),
        len(manifest),
        scanned_sources,
        total_source_bytes,
        scanned_bytes,
        scanned_packets,
        tuple(source_manifest),
        tuple(dict.fromkeys(truncation)),
        range_count,
        selected_payload_bytes,
        fetched_bytes,
        tuple(final_proofs),
        sum(len(planned.located.locators) for planned in planned_sources),
    )


def create_indexed_match_factory(
    repository: IndexedExportRepository,
    *,
    range_limits: RangePlanLimits,
    max_sources: int,
) -> IndexedMatchFactory:
    """Bind the private posting-plan and sparse collector to one repository.

    The returned executor dependency consumes the already admitted source snapshot and
    already authorization-normalized request. It never discovers or snapshots sources.
    """
    bound_repository = repository

    def indexed_match_factory(
        *,
        repository: object,
        settings: Settings,
        requested_job: Mapping[str, Any],
        source_snapshot: Mapping[str, Any],
        canonical_request: Mapping[str, Any],
        candidate_id: str | None,
        predicate: CompiledPacketPredicate,
        internal_networks: Sequence[str],
        scan_max_bytes: int,
        scan_max_packets: int,
        checkpoint: Callable[..., None],
        check_cancelled: Callable[[], None] | None = None,
        check_deadline: Callable[[], None] | None = None,
    ) -> IndexedMatchBatch:
        del candidate_id
        if repository is not bound_repository:
            raise RuntimeError("indexed match factory repository mismatch")
        cancelled_guard = check_cancelled or (lambda: None)
        deadline_guard = check_deadline or (lambda: None)
        _run_checks(cancelled_guard, deadline_guard)
        selection_plan = _select_analysis_posting_plan_from_snapshot(
            bound_repository,
            settings,
            requested_job=requested_job,
            source_snapshot=source_snapshot,
            canonical_request=canonical_request,
            candidate_id=None,
            max_sources=max_sources,
        )
        _run_checks(cancelled_guard, deadline_guard)
        if selection_plan is None:
            raise IndexedFallback(IndexedFallbackReason.INDEX_UNAVAILABLE)
        return collect_indexed_matches(
            bound_repository,
            source_snapshot=source_snapshot,
            selection_plan=selection_plan,
            predicate=predicate,
            internal_networks=internal_networks,
            scan_max_bytes=scan_max_bytes,
            scan_max_packets=scan_max_packets,
            range_limits=range_limits,
            checkpoint=checkpoint,
            check_cancelled=cancelled_guard,
            check_deadline=deadline_guard,
        )

    return indexed_match_factory


def create_indexed_match_factory_from_settings(
    repository: IndexedExportRepository, settings: Settings
) -> IndexedMatchFactory:
    """Construct the bounded Stage 12 executor from validated settings."""
    return create_indexed_match_factory(
        repository,
        range_limits=RangePlanLimits(
            max_gap_bytes=settings.pcap_indexed_export_max_gap_bytes,
            max_range_bytes=settings.pcap_indexed_export_max_range_bytes,
            max_ranges=settings.pcap_indexed_export_max_ranges,
            max_total_fetched_bytes=settings.pcap_indexed_export_max_total_fetched_bytes,
            max_amplification_numerator=(settings.pcap_indexed_export_max_amplification_numerator),
            max_amplification_denominator=(
                settings.pcap_indexed_export_max_amplification_denominator
            ),
            max_source_fraction_numerator=(
                settings.pcap_indexed_export_max_source_fraction_numerator
            ),
            max_source_fraction_denominator=(
                settings.pcap_indexed_export_max_source_fraction_denominator
            ),
        ),
        max_sources=settings.pcap_indexed_export_max_sources,
    )
