"""Bounded, pure historical comparisons against explicitly approved observations.

Source and target use the same all-stream builder. The controller supplies immutable
scope/observation bindings and receipt IDs; this module neither approves normality
nor computes source identity from decoded Flow defaults. Original JSON presence,
source quality assertions, receipt authority and generation digests remain upstream.
No implicit clock, storage, controller import, local-cohort score or I/O is used.

Use the closed mapping projections rather than dataclasses.asdict: historical
candidate metrics are read-only mappings inside the existing BehaviorCandidate DTO.
Projections return fresh JSON primitives, preserve nulls, and normalize UTC text.
A READY comparison is usable history, not a benign verdict. A single drifting
family remains descriptive only: two READY drifting families are required for
both a positive historical score and a HistoricalPeerCandidate.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass, fields, is_dataclass, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from ipaddress import ip_address, ip_network
from math import isfinite
from statistics import median
from types import MappingProxyType, UnionType
from typing import Any, Literal, cast, get_args, get_origin, get_type_hints
from uuid import UUID

from .ai_candidates import PrefilterFactor
from .behavior_discovery import BehaviorCandidate
from .domain import AnalysisContext, Flow
from .tcp_sessions import syn_retry_duplicate_flow_ids
from .traffic_suppression import outbound_control_flood_flow_ids

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
ComparisonStatus = Literal["READY", "INSUFFICIENT", "STALE", "MISSING", "INCOMPATIBLE"]
FeatureVersion = Literal["behavior-window-v1"]
ObservationKind = Literal["PACKET", "AGGREGATE"]
ErrorCode = Literal[
    "BASELINE_SOURCE_INVALID",
    "BASELINE_SOURCE_LIMIT",
    "BASELINE_PROFILE_LIMIT",
    "BASELINE_SCOPE_MISMATCH",
]


class BaselineInputError(ValueError):
    def __init__(self, code: ErrorCode = "BASELINE_SOURCE_INVALID") -> None:
        self.code = code
        super().__init__(
            "Invalid baseline input."
            if code == "BASELINE_SOURCE_INVALID"
            else "Baseline input exceeds bounds."
            if code.endswith("LIMIT")
            else "Baseline scope does not match."
        )


@dataclass(frozen=True)
class HostEpoch:
    ip: str
    epoch: str


@dataclass(frozen=True)
class BaselineScopeIdentity:
    scope_config_sha256: str
    kind: Literal["OPERATIONAL", "EVALUATION"]
    sensor_key: str
    stored_sensor_id: str | None
    internal_networks: tuple[str, ...]
    window_seconds: int
    hosts: tuple[HostEpoch, ...]
    feature_version: FeatureVersion


@dataclass(frozen=True)
class ObservationIdentity:
    root_identity: str
    dataset_id: str
    feature_observation_sha256: str


@dataclass(frozen=True)
class ProfileKey:
    scope_config_sha256: str
    sensor_key: str
    internal_host_ip: str
    host_epoch: str
    peer_ip: str
    protocol: str
    service_port: int
    observation_kind: ObservationKind
    feature_version: FeatureVersion


@dataclass(frozen=True)
class StreamKey:
    internal_host_ip: str
    host_epoch: str
    peer_ip: str
    protocol: str
    service_port: int | None


@dataclass(frozen=True)
class BaselineBuildInput:
    scope: BaselineScopeIdentity
    actual_sensor_id: str
    sensor_alias_asserted: bool
    event_start: datetime
    event_end: datetime
    flows: tuple[Flow, ...]
    trusted_peers: tuple[str, ...]
    source_receipt_id: str | None


@dataclass(frozen=True)
class BehaviorWindow:
    key: ProfileKey
    source_receipt_id: str | None
    event_start: datetime
    event_end: datetime
    outbound_record_count: int
    recurrence: float | None
    size_dispersion: float | None
    outbound_share: float | None
    limitations: tuple[ReasonCode, ...]


@dataclass(frozen=True)
class ProfileBuildRecord:
    stream: StreamKey
    key: ProfileKey | None
    window: BehaviorWindow | None
    eligible_for_reference: bool
    reasons: tuple[ReasonCode, ...]


@dataclass(frozen=True)
class BaselineBuildResult:
    profiles: tuple[ProfileBuildRecord, ...]
    raw_profile_count: int
    eligible_profile_count: int
    excluded_profile_count: int
    excluded_row_count: int
    limitations: tuple[ReasonCode, ...]


@dataclass(frozen=True)
class ReferenceWindow:
    window: BehaviorWindow
    observation: ObservationIdentity


@dataclass(frozen=True)
class BaselineReference:
    windows: tuple[ReferenceWindow, ...]


@dataclass(frozen=True)
class FeatureComparison:
    status: ComparisonStatus
    current: float | None
    reference_median: float | None
    reference_scale: float | None
    robust_z: float | None
    eligible_window_ids: tuple[str, ...]
    excluded_future_count: int
    drifting: bool


@dataclass(frozen=True)
class ProfileComparison:
    key: ProfileKey
    status: ComparisonStatus
    limitations: tuple[ReasonCode, ...]
    source_window_ids: tuple[str, ...]
    recurrence: FeatureComparison
    size_dispersion: FeatureComparison
    outbound_share: FeatureComparison
    historical_anomaly_score: float


@dataclass(frozen=True)
class HistoricalPeerCandidate:
    comparison_key: ProfileKey
    candidate: BehaviorCandidate


@dataclass(frozen=True)
class BaselineComparisonResult:
    comparisons: tuple[ProfileComparison, ...]
    candidates: tuple[HistoricalPeerCandidate, ...]
    unprofiled_count: int
    limitations: tuple[ReasonCode, ...]


BASE_LIMITATIONS: tuple[ReasonCode, ...] = (
    "HISTORY_MATCH_IS_NOT_BENIGN",
    "RETROSPECTIVE_NOT_AS_WAS",
)
GLOBAL_TARGET_VETOES: frozenset[ReasonCode] = frozenset(
    ("TARGET_REVIEW_REQUIRED", "TARGET_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN")
)
FEATURES = ("recurrence", "size_dispersion", "outbound_share")
FACTOR_NAMES = (
    "HISTORICAL_RECURRENCE_CHANGE",
    "HISTORICAL_RECORD_SIZE_DISPERSION_CHANGE",
    "HISTORICAL_DIRECTION_BALANCE_CHANGE",
)


def _key_bytes(key: ProfileKey | StreamKey) -> bytes:
    return json.dumps(
        asdict(key), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _dispersion(values: list[float]) -> float:
    center = median(values)
    return median(abs(value - center) for value in values) / max(center, 1e-9)


def _require(condition: bool, code: ErrorCode = "BASELINE_SOURCE_INVALID") -> None:
    if not condition:
        raise BaselineInputError(code)


def _text(value: object, maximum: int = 200) -> None:
    if type(value) is not str:
        raise BaselineInputError()
    _require(
        1 <= len(value) <= maximum
        and not any(
            ord(c) < 32 or 127 <= ord(c) <= 159 or 0xD800 <= ord(c) <= 0xDFFF for c in value
        )
    )


def _integer(value: object, maximum: int = 2**53, minimum: int = 0) -> None:
    _require(type(value) is int and minimum <= value <= maximum)


def _number(value: object, maximum: float = 2**53) -> None:
    if type(value) is int:
        _integer(value, min(2**53, int(maximum)) if isfinite(maximum) else 2**53)
    else:
        if type(value) is not float:
            raise BaselineInputError()
        _require(0 <= value <= maximum and isfinite(value))


def _tuple(value: object, maximum: int, minimum: int = 0) -> None:
    if type(value) is not tuple:
        raise BaselineInputError()
    _require(len(value) <= maximum, "BASELINE_SOURCE_LIMIT")
    _require(len(value) >= minimum)


def _ip(value: str) -> None:
    _text(value, 45)
    try:
        _require(str(ip_address(value)) == value)
    except ValueError:
        raise BaselineInputError() from None


def _digest(value: str) -> None:
    _text(value, 64)
    _require(re.fullmatch("[0-9a-f]{64}", value) is not None)


def _receipt(value: str | None, *, required: bool = False) -> None:
    if value is None:
        _require(not required)
        return
    _text(value, 36)
    try:
        _require(str(UUID(value)) == value)
    except ValueError:
        raise BaselineInputError() from None


def _utc(value: datetime) -> datetime:
    _require(type(value) is datetime)
    try:
        _require(value.utcoffset() is not None)
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        raise BaselineInputError() from None


def _envelope(start: datetime, end: datetime, seconds: int | None = None) -> None:
    start, end = _utc(start), _utc(end)
    _require(end > start)
    if seconds is not None:
        _require(end - start == timedelta(seconds=seconds), "BASELINE_SCOPE_MISMATCH")
    else:
        _require(timedelta(seconds=60) <= end - start <= timedelta(seconds=21600))
        _require((end - start) % timedelta(seconds=1) == timedelta(0))


def _scope(scope: BaselineScopeIdentity) -> None:
    _require(type(scope) is BaselineScopeIdentity)
    _tuple(scope.hosts, 128)
    _require(bool(scope.hosts), "BASELINE_SCOPE_MISMATCH")
    _tuple(scope.internal_networks, 128, 1)
    _digest(scope.scope_config_sha256)
    _text(scope.sensor_key)
    _require(scope.kind in ("OPERATIONAL", "EVALUATION"))
    _require(scope.feature_version == "behavior-window-v1")
    _integer(scope.window_seconds, 21600, 60)
    if scope.kind == "OPERATIONAL":
        _text(scope.stored_sensor_id)
    else:
        _require(scope.stored_sensor_id is None)
    networks = []
    for network in scope.internal_networks:
        _text(network, 49)
        try:
            parsed = ip_network(network)
            _require(str(parsed) == network)
        except ValueError:
            raise BaselineInputError() from None
        networks.append(parsed)
    _require(len(set(scope.internal_networks)) == len(scope.internal_networks))
    for host in scope.hosts:
        _require(type(host) is HostEpoch)
        _ip(host.ip)
        try:
            _text(host.epoch, 64)
        except BaselineInputError:
            raise BaselineInputError("BASELINE_SCOPE_MISMATCH") from None
        _require(any(ip_address(host.ip) in n for n in networks), "BASELINE_SCOPE_MISMATCH")
    _require(len({h.ip for h in scope.hosts}) == len(scope.hosts))


@dataclass(frozen=True, slots=True)
class _StructuralBuildInput:
    """Calculation facts only, never a reviewed/publication capability."""

    scope: BaselineScopeIdentity
    actual_sensor_id: str
    event_start: datetime
    event_end: datetime
    flows: tuple[Flow, ...]
    trusted_peers: tuple[str, ...]


def _flow_caps(request: BaselineBuildInput | _StructuralBuildInput) -> None:
    _tuple(request.flows, 8192)
    _tuple(request.trusted_peers, 128)
    _require(type(request.scope) is BaselineScopeIdentity)
    _tuple(request.scope.hosts, 128)
    _tuple(request.scope.internal_networks, 128)
    total_syn = 0
    for row in request.flows:
        _require(type(row) is Flow)
        if row.tcp_syn_only_observations is not None:
            _tuple(row.tcp_syn_only_observations, 256)
            total_syn += len(row.tcp_syn_only_observations)
            _require(total_syn <= 256, "BASELINE_SOURCE_LIMIT")
        if row.tcp_flags is not None:
            _require(isinstance(row.tcp_flags, Mapping))
            _require(len(row.tcp_flags) <= 16, "BASELINE_SOURCE_LIMIT")


def _build_input(request: BaselineBuildInput) -> BaselineBuildInput:
    _require(type(request) is BaselineBuildInput)
    _flow_caps(request)
    _scope(request.scope)
    _envelope(request.event_start, request.event_end, request.scope.window_seconds)
    _receipt(request.source_receipt_id)
    _text(request.actual_sensor_id)
    _require(type(request.sensor_alias_asserted) is bool)
    if request.scope.kind == "OPERATIONAL":
        _require(
            not request.sensor_alias_asserted
            and request.actual_sensor_id == request.scope.stored_sensor_id,
            "BASELINE_SCOPE_MISMATCH",
        )
    else:
        _require(
            request.sensor_alias_asserted or request.actual_sensor_id == request.scope.sensor_key,
            "BASELINE_SCOPE_MISMATCH",
        )
    return _validated_rows(request)


def _structural_input(request: _StructuralBuildInput) -> _StructuralBuildInput:
    _require(type(request) is _StructuralBuildInput)
    _flow_caps(request)
    for row in request.flows:
        _tuple(row.packet_sizes, 128)
    _scope(request.scope)
    _envelope(request.event_start, request.event_end, request.scope.window_seconds)
    _text(request.actual_sensor_id)
    if request.scope.kind == "OPERATIONAL":
        _require(
            request.actual_sensor_id == request.scope.stored_sensor_id,
            "BASELINE_SCOPE_MISMATCH",
        )
    return _validated_rows(request)


def _validated_rows[T: (BaselineBuildInput, _StructuralBuildInput)](request: T) -> T:
    for peer in request.trusted_peers:
        _ip(peer)
    _require(len(set(request.trusted_peers)) == len(request.trusted_peers))
    rows = tuple(_flow(row, request) for row in request.flows)
    return replace(
        request,
        flows=rows,
        event_start=_utc(request.event_start),
        event_end=_utc(request.event_end),
    )


def _flow(row: Flow, request: BaselineBuildInput | _StructuralBuildInput) -> Flow:
    _text(row.sensor_id)
    _require(row.sensor_id == request.actual_sensor_id, "BASELINE_SCOPE_MISMATCH")
    _ip(row.source_ip)
    _ip(row.destination_ip)
    for port in (row.source_port, row.destination_port):
        if port is not None:
            _integer(port, 65535)
    _text(row.protocol, 256)
    protocol = row.protocol.upper()
    _text(protocol, 256)
    _text(row.direction, 256)
    _require(row.direction.upper() in ("UNKNOWN", "OUTBOUND", "INBOUND"))
    _integer(row.packet_count, minimum=1)
    _integer(row.total_bytes)
    _number(row.duration_seconds, 31_536_000)
    micros = Decimal(str(row.duration_seconds)) * 1_000_000
    _require(micros == micros.to_integral_value())
    timestamp = _utc(row.timestamp)
    _require(request.event_start <= timestamp <= request.event_end)
    _require(micros <= (request.event_end - timestamp) // timedelta(microseconds=1))
    for flag in (
        row.bidirectional,
        row.tcp_flags_observed,
        row.tcp_syn_only_observations_truncated,
    ):
        _require(type(flag) is bool)
    for value in (
        row.tcp_syn_count,
        row.tcp_ack_count,
        row.tcp_rst_count,
        row.tcp_syn_only_count,
        row.tcp_syn_ack_count,
        row.tcp_ack_only_count,
    ):
        _integer(value)
    for key, flag_count in (row.tcp_flags or {}).items():
        _text(key, 256)
        _number(flag_count)
    for pair in row.tcp_syn_only_observations or ():
        _require(type(pair) is tuple and len(pair) == 2)
        offset, sequence = pair
        _integer(offset, 31_536_000_000_000)
        _integer(sequence, 2**32 - 1)
        _require(offset <= (request.event_end - timestamp) // timedelta(microseconds=1))
    if row.payload_length is not None:
        _integer(row.payload_length)
    for text in (
        row.payload_hash,
        row.last_payload_hash,
        row.payload_prefix_hash,
        row.payload_simhash,
    ):
        if text is not None:
            _text(text, 256)
    return replace(row, timestamp=timestamp, protocol=protocol, direction=row.direction.upper())


def _flow_order(row: Flow) -> tuple[Any, ...]:
    # Shared retry selection is timestamp-stable; canonicalize every consumed tie field first.
    return (
        row.timestamp,
        row.sensor_id,
        row.source_ip,
        row.destination_ip,
        -1 if row.source_port is None else row.source_port,
        -1 if row.destination_port is None else row.destination_port,
        row.protocol,
        row.direction,
        row.packet_count,
        row.total_bytes,
        row.duration_seconds,
        row.tcp_syn_only_observations or (),
        row.tcp_syn_only_observations_truncated,
        row.tcp_flags_observed,
        row.tcp_syn_count,
        row.tcp_ack_count,
        row.tcp_rst_count,
        row.tcp_syn_only_count,
        row.tcp_syn_ack_count,
        row.tcp_ack_only_count,
        tuple(sorted((row.tcp_flags or {}).items())),
        row.bidirectional,
        bool(
            row.payload_hash
            or row.last_payload_hash
            or row.payload_prefix_hash
            or row.payload_simhash
            or (row.payload_length or 0) > 0
        ),
    )


@dataclass(frozen=True)
class _PreparedStream:
    stream: StreamKey
    key: ProfileKey | None
    rows: tuple[Flow, ...]
    outbound_rows: tuple[Flow, ...]
    reasons: tuple[ReasonCode, ...]


@dataclass(frozen=True)
class _PreparedBuild:
    request: _StructuralBuildInput
    streams: tuple[_PreparedStream, ...]
    excluded_rows: int


def build_behavior_windows(request: BaselineBuildInput) -> BaselineBuildResult:
    return _calculate_behavior_windows(_prepare_behavior_windows(request), request)


def build_behavior_windows_with_retained_keys(
    request: BaselineBuildInput, *, retained_keys: tuple[ProfileKey, ...]
) -> BaselineBuildResult:
    """Admit the retained publication union before calculating any features.

    The caller supplies keys only after prospective receipt retention. No callbacks,
    authority assertions, feature placeholders or prepared input escape this helper.
    The normal builder keeps its original public signature and strict input policy.
    """
    _tuple(retained_keys, 128)
    for key in retained_keys:
        _key(key)
        _require(vars(key).keys() == {field.name for field in fields(ProfileKey)})
    prepared = _prepare_behavior_windows(request)
    for key in retained_keys:
        _scoped_key(key, prepared.request.scope)
    keys = set(retained_keys)
    for stream in prepared.streams:
        # _flow admits integer bytes in [0, 2**53], positive packet counts,
        # and <=8192 rows. Size dispersion therefore always exists for >=8
        # retained outbound rows: both medians are finite in [0, 2**53],
        # denominator >=1e-9, result <=2**53/1e-9 (finite, including all-zero).
        # This is exactly _eligible's nonnull-feature condition, not a guess
        # based on raw groups, packet timing or direction-share availability.
        if stream.key is not None and len(stream.outbound_rows) >= 8:
            keys.add(stream.key)
            _require(len(keys) <= 128, "BASELINE_PROFILE_LIMIT")
    return _calculate_behavior_windows(prepared, request)


def _prepare_behavior_windows(request: BaselineBuildInput) -> _PreparedBuild:
    request = _build_input(request)
    return _prepare_structural_windows(
        _StructuralBuildInput(
            request.scope,
            request.actual_sensor_id,
            request.event_start,
            request.event_end,
            request.flows,
            request.trusted_peers,
        )
    )


def _prepare_structural_windows(request: _StructuralBuildInput) -> _PreparedBuild:
    """Group admitted rows once; reviewed and structural entries share this path."""
    scope = request.scope
    hosts = {host.ip: host.epoch for host in scope.hosts}
    groups: dict[StreamKey, list[Flow]] = {}
    networks = tuple(ip_network(n) for n in scope.internal_networks)
    excluded_rows = 0
    for row in request.flows:
        outbound = any(ip_address(row.source_ip) in n for n in networks)
        inbound = any(ip_address(row.destination_ip) in n for n in networks)
        if outbound == inbound:
            excluded_rows += 1
            continue
        host = row.source_ip if outbound else row.destination_ip
        peer = row.destination_ip if outbound else row.source_ip
        port = row.destination_port if outbound else row.source_port
        _require(host in hosts, "BASELINE_SCOPE_MISMATCH")
        _require(
            row.direction == "UNKNOWN" or row.direction == ("OUTBOUND" if outbound else "INBOUND")
        )
        stream = StreamKey(host, hosts[host], peer, row.protocol.upper(), port)
        groups.setdefault(stream, []).append(row)
        if len(groups) > 128:
            raise BaselineInputError("BASELINE_PROFILE_LIMIT")
    scoped_rows = sorted((r for rows in groups.values() for r in rows), key=_flow_order)
    context = AnalysisContext(
        "",
        request.event_start,
        request.event_end,
        scoped_rows,
        (request.actual_sensor_id,),
        scope.internal_networks,
    )
    suppressed = syn_retry_duplicate_flow_ids(context)
    peers: dict[str, list[Flow]] = {}
    for stream, rows in groups.items():
        peers.setdefault(stream.peer_ip, []).extend(rows)
    _require(len(peers) <= 256, "BASELINE_SOURCE_LIMIT")
    for rows in peers.values():
        suppressed.update(outbound_control_flood_flow_ids(context, rows))
    streams = []
    for stream, raw_rows in sorted(groups.items(), key=lambda item: _key_bytes(item[0])):
        rows = [r for r in raw_rows if id(r) not in suppressed]
        outbound_rows = [row for row in rows if row.source_ip == stream.internal_host_ip]
        reasons: set[ReasonCode] = set()
        if len(rows) != len(raw_rows):
            reasons.add("SUPPRESSED_CONTROL_OR_RETRY_ROWS")
        if stream.peer_ip in request.trusted_peers:
            reasons.add("TRUSTED_PEERS_EXCLUDED")
        if stream.service_port in {53, 123}:
            reasons.add("COMMON_SERVICES_EXCLUDED")
        if stream.service_port is None:
            reasons.add("SERVICE_PORT_UNAVAILABLE")
        if not outbound_rows:
            reasons.add("INSUFFICIENT_STREAM_SAMPLES")
        if not _window_allowed(stream, tuple(reasons)) or not outbound_rows:
            streams.append(_PreparedStream(stream, None, (), (), tuple(sorted(reasons))))
            continue
        if any(row.direction == "UNKNOWN" for row in rows):
            reasons.add("DERIVED_FROM_CIDR")
        packet = [row.packet_count == 1 and row.duration_seconds == 0 for row in outbound_rows]
        kind: ObservationKind = "PACKET" if all(packet) else "AGGREGATE"
        if any(packet) and not all(packet):
            reasons.add("MIXED_REPRESENTATION")
        if stream.service_port is None:
            raise BaselineInputError()
        key = ProfileKey(
            scope.scope_config_sha256,
            scope.sensor_key,
            stream.internal_host_ip,
            stream.host_epoch,
            stream.peer_ip,
            stream.protocol,
            stream.service_port,
            kind,
            scope.feature_version,
        )
        streams.append(
            _PreparedStream(stream, key, tuple(rows), tuple(outbound_rows), tuple(sorted(reasons)))
        )
    return _PreparedBuild(request, tuple(streams), excluded_rows)


@dataclass(frozen=True, slots=True)
class _CalculatedStream:
    stream: StreamKey
    key: ProfileKey | None
    outbound_record_count: int
    recurrence: float | None
    size_dispersion: float | None
    outbound_share: float | None
    eligible: bool
    reasons: tuple[ReasonCode, ...]


def _calculate_structural_windows(prepared: _PreparedBuild) -> tuple[_CalculatedStream, ...]:
    profiles = []
    for item in prepared.streams:
        stream, key = item.stream, item.key
        if key is None:
            profiles.append(
                _CalculatedStream(stream, None, 0, None, None, None, False, item.reasons)
            )
            continue
        rows, outbound_rows = item.rows, item.outbound_rows
        reasons = set(item.reasons)
        kind = key.observation_kind
        recurrence = size = share = None
        times = sorted({row.timestamp for row in outbound_rows})
        if len(outbound_rows) < 8:
            reasons.add("INSUFFICIENT_STREAM_SAMPLES")
        else:
            if kind == "PACKET" and len(times) >= 8:
                recurrence = _dispersion(
                    [
                        (right - left).total_seconds()
                        for left, right in zip(times, times[1:], strict=False)
                    ]
                )
            else:
                reasons.add("PACKET_TIMING_UNAVAILABLE")
            size = _dispersion([row.total_bytes / row.packet_count for row in outbound_rows])
            total = sum(row.total_bytes for row in rows)
            if total and not any(row.bidirectional for row in rows):
                share = sum(row.total_bytes for row in outbound_rows) / total
            else:
                reasons.add("DIRECTION_BALANCE_UNAVAILABLE")
        limits = tuple(sorted(reasons))
        eligible = _eligible_values(stream, limits, len(outbound_rows), (recurrence, size, share))
        profiles.append(
            _CalculatedStream(
                stream, key, len(outbound_rows), recurrence, size, share, eligible, limits
            )
        )
    return tuple(profiles)


def _structural_counts(
    request: _StructuralBuildInput,
) -> tuple[int, int, int, tuple[ReasonCode, ...]]:
    profiles = _calculate_structural_windows(
        _prepare_structural_windows(_structural_input(request))
    )
    eligible = sum(item.eligible for item in profiles)
    return (
        len(profiles),
        eligible,
        len(profiles) - eligible,
        tuple(sorted({reason for item in profiles for reason in item.reasons})),
    )


def _calculate_behavior_windows(
    prepared: _PreparedBuild, reviewed: BaselineBuildInput
) -> BaselineBuildResult:
    profiles = []
    for item in _calculate_structural_windows(prepared):
        if item.key is None:
            profiles.append(ProfileBuildRecord(item.stream, None, None, False, item.reasons))
            continue
        reasons = set(item.reasons)
        if reviewed.scope.kind == "EVALUATION" and reviewed.sensor_alias_asserted:
            reasons.add("EVALUATION_SENSOR_ALIAS")
        window = BehaviorWindow(
            item.key,
            reviewed.source_receipt_id,
            prepared.request.event_start,
            prepared.request.event_end,
            item.outbound_record_count,
            item.recurrence,
            item.size_dispersion,
            item.outbound_share,
            tuple(sorted(reasons)),
        )
        profiles.append(
            ProfileBuildRecord(item.stream, item.key, window, item.eligible, window.limitations)
        )
    eligible_count = sum(p.eligible_for_reference for p in profiles)
    return BaselineBuildResult(
        tuple(profiles),
        len(profiles),
        eligible_count,
        len(profiles) - eligible_count,
        prepared.excluded_rows,
        tuple(sorted({r for p in profiles for r in p.reasons})),
    )


def _reasons(reasons: tuple[ReasonCode, ...]) -> None:
    _tuple(reasons, len(get_args(ReasonCode)))
    for reason in reasons:
        _text(reason, 64)
        _require(reason in get_args(ReasonCode))
    _require(tuple(sorted(set(reasons))) == reasons)


def _stream(stream: StreamKey) -> None:
    _require(type(stream) is StreamKey)
    _ip(stream.internal_host_ip)
    _ip(stream.peer_ip)
    _text(stream.host_epoch, 64)
    _text(stream.protocol, 256)
    _require(stream.protocol == stream.protocol.upper())
    if stream.service_port is not None:
        _integer(stream.service_port, 65535)


def _key(key: ProfileKey) -> None:
    _require(type(key) is ProfileKey)
    _digest(key.scope_config_sha256)
    _text(key.sensor_key)
    _stream(_key_stream(key))
    _integer(key.service_port, 65535)
    _require(key.observation_kind in ("PACKET", "AGGREGATE"))
    _require(key.feature_version == "behavior-window-v1")


def _key_stream(key: ProfileKey) -> StreamKey:
    return StreamKey(
        key.internal_host_ip, key.host_epoch, key.peer_ip, key.protocol, key.service_port
    )


def _host_binding(stream: StreamKey, hosts: dict[str, str]) -> None:
    _require(
        hosts.setdefault(stream.internal_host_ip, stream.host_epoch) == stream.host_epoch,
        "BASELINE_SCOPE_MISMATCH",
    )


def _scoped_stream(stream: StreamKey, scope: BaselineScopeIdentity) -> None:
    _require(
        any(h.ip == stream.internal_host_ip and h.epoch == stream.host_epoch for h in scope.hosts),
        "BASELINE_SCOPE_MISMATCH",
    )
    _require(
        not any(ip_address(stream.peer_ip) in ip_network(n) for n in scope.internal_networks),
        "BASELINE_SCOPE_MISMATCH",
    )


def _scoped_key(key: ProfileKey, scope: BaselineScopeIdentity) -> None:
    _require(
        (key.scope_config_sha256, key.sensor_key, key.feature_version)
        == (scope.scope_config_sha256, scope.sensor_key, scope.feature_version),
        "BASELINE_SCOPE_MISMATCH",
    )
    _scoped_stream(_key_stream(key), scope)


def _window_allowed(stream: StreamKey, reasons: tuple[ReasonCode, ...]) -> bool:
    # These exclusions are stream-local, not vetoes on a result's reason union.
    return stream.service_port not in (None, 53, 123) and not set(reasons) & {
        "TRUSTED_PEERS_EXCLUDED",
        "COMMON_SERVICES_EXCLUDED",
        "SERVICE_PORT_UNAVAILABLE",
    }


def _window(window: BehaviorWindow, *, publication: bool = False) -> None:
    _require(type(window) is BehaviorWindow)
    _key(window.key)
    _receipt(window.source_receipt_id, required=publication)
    _envelope(window.event_start, window.event_end)
    _integer(window.outbound_record_count, 8192, 1)
    _reasons(window.limitations)
    _require(_window_allowed(_key_stream(window.key), window.limitations))
    for value in (window.recurrence, window.size_dispersion, window.outbound_share):
        if value is not None:
            _number(value, float("inf"))
    if window.outbound_share is not None:
        _require(window.outbound_share <= 1)
    if "PACKET_TIMING_UNAVAILABLE" in window.limitations:
        _require(window.recurrence is None)
    if "DIRECTION_BALANCE_UNAVAILABLE" in window.limitations:
        _require(window.outbound_share is None)
    if "MIXED_REPRESENTATION" in window.limitations:
        _require(window.key.observation_kind == "AGGREGATE")
    if window.key.observation_kind == "AGGREGATE":
        _require(window.recurrence is None)
    if "INSUFFICIENT_STREAM_SAMPLES" in window.limitations:
        _require(window.outbound_record_count < 8)
    if window.outbound_record_count < 8:
        _require(all(getattr(window, name) is None for name in FEATURES))
    if publication:
        _require(_eligible(window))


def _eligible(window: BehaviorWindow) -> bool:
    return _eligible_values(
        _key_stream(window.key),
        window.limitations,
        window.outbound_record_count,
        tuple(getattr(window, name) for name in FEATURES),
    )


def _eligible_values(
    stream: StreamKey,
    reasons: tuple[ReasonCode, ...],
    count: int,
    features: tuple[float | None, ...],
) -> bool:
    return (
        _window_allowed(stream, reasons)
        and count >= 8
        and any(value is not None for value in features)
    )


def _build_result(result: BaselineBuildResult) -> None:
    _require(type(result) is BaselineBuildResult)
    _tuple(result.profiles, 128)
    for value in (
        result.raw_profile_count,
        result.eligible_profile_count,
        result.excluded_profile_count,
    ):
        _integer(value, 128)
    _integer(result.excluded_row_count, 8192)
    _reasons(result.limitations)
    streams = set()
    bindings = set()
    hosts: dict[str, str] = {}
    records = 0
    for record in result.profiles:
        _require(type(record) is ProfileBuildRecord)
        _stream(record.stream)
        _host_binding(record.stream, hosts)
        _require(record.stream not in streams)
        streams.add(record.stream)
        _require(type(record.eligible_for_reference) is bool)
        _reasons(record.reasons)
        _require(set(record.reasons) <= set(result.limitations))
        if record.window is None:
            _require(record.key is None and not record.eligible_for_reference)
            _require(
                bool(
                    set(record.reasons)
                    & {
                        "TRUSTED_PEERS_EXCLUDED",
                        "COMMON_SERVICES_EXCLUDED",
                        "SERVICE_PORT_UNAVAILABLE",
                        "INSUFFICIENT_STREAM_SAMPLES",
                    }
                )
            )
        else:
            _window(record.window)
            if record.key is None:
                raise BaselineInputError()
            _key(record.key)
            _require(record.key == record.window.key)
            _require(record.stream == _key_stream(record.window.key))
            _require(record.eligible_for_reference == _eligible(record.window))
            _require(record.reasons == record.window.limitations)
            w = record.window
            bindings.add(
                (
                    w.source_receipt_id,
                    w.event_start,
                    w.event_end,
                    w.key.scope_config_sha256,
                    w.key.sensor_key,
                    w.key.feature_version,
                )
            )
            records += w.outbound_record_count
    _require(len(bindings) <= 1)
    _require(records + result.excluded_row_count <= 8192)
    _require(result.raw_profile_count == len(result.profiles))
    _require(
        result.eligible_profile_count == sum(p.eligible_for_reference for p in result.profiles)
    )
    _require(
        result.excluded_profile_count == result.raw_profile_count - result.eligible_profile_count
    )


def _observation(observation: ObservationIdentity) -> None:
    _require(type(observation) is ObservationIdentity)
    _text(observation.root_identity, 420)
    _text(observation.dataset_id)
    _digest(observation.feature_observation_sha256)


def _reference(reference: BaselineReference, scope: BaselineScopeIdentity | None = None) -> None:
    _require(type(reference) is BaselineReference)
    _tuple(reference.windows, 2048)
    receipts: dict[str, tuple[datetime, datetime, ObservationIdentity]] = {}
    keys: set[ProfileKey] = set()
    pairs: set[tuple[ProfileKey, str]] = set()
    identities = set()
    hosts: dict[str, str] = {}
    for ref in reference.windows:
        _require(type(ref) is ReferenceWindow)
        _window(ref.window, publication=True)
        _observation(ref.observation)
        w = ref.window
        _host_binding(_key_stream(w.key), hosts)
        if scope is not None:
            _scoped_key(w.key, scope)
            _envelope(w.event_start, w.event_end, scope.window_seconds)
        receipt = w.source_receipt_id
        if receipt is None:
            raise BaselineInputError()
        binding = (w.event_start, w.event_end, ref.observation)
        _require(receipt not in receipts or receipts[receipt] == binding)
        receipts[receipt] = binding
        keys.add(w.key)
        _require((w.key, receipt) not in pairs)
        pairs.add((w.key, receipt))
        identities.add(
            (
                w.key.scope_config_sha256,
                w.key.sensor_key,
                w.key.feature_version,
                w.event_end - w.event_start,
            )
        )
        _require(len(receipts) <= 16, "BASELINE_SOURCE_LIMIT")
        _require(len(keys) <= 128, "BASELINE_PROFILE_LIMIT")
        _require(len(identities) <= 1, "BASELINE_SCOPE_MISMATCH")


def compare_behavior_windows(
    *,
    target: BaselineBuildResult,
    reference: BaselineReference | None,
    scope: BaselineScopeIdentity,
    target_observation: ObservationIdentity,
    target_event_start: datetime,
    target_event_end: datetime,
    target_vetoes: tuple[ReasonCode, ...],
) -> BaselineComparisonResult:
    _scope(scope)
    _observation(target_observation)
    _envelope(target_event_start, target_event_end, scope.window_seconds)
    _reasons(target_vetoes)
    _require(set(target_vetoes) <= GLOBAL_TARGET_VETOES)
    _build_result(target)
    vetoes = set(target_vetoes) | (set(target.limitations) & GLOBAL_TARGET_VETOES)
    for record in target.profiles:
        _scoped_stream(record.stream, scope)
        if record.window is not None:
            w = record.window
            _scoped_key(w.key, scope)
            _require(w.source_receipt_id is None)
            _require((w.event_start, w.event_end) == (target_event_start, target_event_end))
    if reference is not None:
        _reference(reference, scope)
    comparisons = []
    candidates = []
    unprofiled = 0
    for record in target.profiles:
        window = record.window
        if window is None:
            unprofiled += 1
            continue
        support = [r for r in reference.windows if r.window.key == window.key] if reference else []
        reasons: set[ReasonCode] = (
            set(window.limitations)
            | vetoes
            | {"RETROSPECTIVE_NOT_AS_WAS", "HISTORY_MATCH_IS_NOT_BENIGN"}
        )
        whole: ComparisonStatus | None = None
        if vetoes or window.outbound_record_count < 8:
            whole = "INCOMPATIBLE"
            if window.outbound_record_count < 8:
                reasons.add("INSUFFICIENT_STREAM_SAMPLES")
        elif not support:
            whole = "MISSING"
            reasons.add("NO_ACTIVE_REFERENCE" if reference is None else "NO_MATCHING_PROFILE")
        families = []
        for name in FEATURES:
            current = getattr(window, name)
            if whole:
                family = _unavailable(whole, current)
            elif current is None:
                family = _unavailable("INCOMPATIBLE", None)
            else:
                family = _compare_feature(
                    current, name, support, target_observation, target_event_start, reasons
                )
            families.append(family)
        status = whole or _profile_status(families)
        ids = tuple(sorted({identity for f in families for identity in f.eligible_window_ids}))
        factors = _factors(families)
        score = sum(f.points for f in factors) if len(factors) >= 2 else 0.0
        limitations = tuple(sorted(reasons))
        comparison = ProfileComparison(
            window.key, status, limitations, ids, families[0], families[1], families[2], score
        )
        comparisons.append(comparison)
        key = window.key
        if len(factors) >= 2:
            candidate = BehaviorCandidate(
                key.peer_ip,
                score,
                (key.internal_host_ip,),
                (key.protocol,),
                (key.service_port,),
                window.event_start,
                window.event_end,
                tuple(factors),
                limitations,
            )
            candidates.append(HistoricalPeerCandidate(key, candidate))
    winners: dict[str, HistoricalPeerCandidate] = {}
    for item in sorted(candidates, key=_candidate_order):
        winners.setdefault(item.candidate.candidate_ip, item)
    return BaselineComparisonResult(
        tuple(sorted(comparisons, key=lambda c: _key_bytes(c.key))),
        tuple(winners.values()),
        unprofiled,
        tuple(
            sorted(
                set(target.limitations)
                | set(target_vetoes)
                | set(BASE_LIMITATIONS)
                | {r for c in comparisons for r in c.limitations}
            )
        ),
    )


def compare_unreviewed_evaluation_target(
    request: _StructuralBuildInput,
    *,
    reference: BaselineReference | None,
    target_observation: ObservationIdentity,
    target_vetoes: tuple[ReasonCode, ...],
) -> BaselineComparisonResult:
    """Return comparisons only; null-receipt target windows never escape."""
    request = _structural_input(request)
    _require(request.scope.kind == "EVALUATION", "BASELINE_SCOPE_MISMATCH")
    prepared = _prepare_structural_windows(request)
    profiles = []
    for item in _calculate_structural_windows(prepared):
        if item.key is None:
            profiles.append(ProfileBuildRecord(item.stream, None, None, False, item.reasons))
            continue
        window = BehaviorWindow(
            item.key,
            None,
            request.event_start,
            request.event_end,
            item.outbound_record_count,
            item.recurrence,
            item.size_dispersion,
            item.outbound_share,
            item.reasons,
        )
        profiles.append(
            ProfileBuildRecord(item.stream, item.key, window, item.eligible, item.reasons)
        )
    eligible = sum(item.eligible_for_reference for item in profiles)
    target = BaselineBuildResult(
        tuple(profiles),
        len(profiles),
        eligible,
        len(profiles) - eligible,
        prepared.excluded_rows,
        tuple(sorted({reason for item in profiles for reason in item.reasons})),
    )
    return compare_behavior_windows(
        target=target,
        reference=reference,
        scope=request.scope,
        target_observation=target_observation,
        target_event_start=request.event_start,
        target_event_end=request.event_end,
        target_vetoes=tuple(sorted(set(target_vetoes) | {"TARGET_REVIEW_REQUIRED"})),
    )


def _candidate_order(item: HistoricalPeerCandidate) -> tuple[float, str, bytes]:
    return (
        -item.candidate.anomaly_score,
        item.candidate.candidate_ip,
        _key_bytes(item.comparison_key),
    )


def _unavailable(
    status: ComparisonStatus, current: float | None, ids: tuple[str, ...] = (), future: int = 0
) -> FeatureComparison:
    return FeatureComparison(status, current, None, None, None, ids, future, False)


def _profile_status(families: list[FeatureComparison]) -> ComparisonStatus:
    states = [f.status for f in families]
    if states.count("READY") >= 2:
        return "READY"
    if "STALE" in states:
        return "STALE"
    if "READY" in states or "INSUFFICIENT" in states:
        return "INSUFFICIENT"
    if "MISSING" in states:
        return "MISSING"
    return "INCOMPATIBLE"


def _compare_feature(
    current: float,
    name: str,
    support: list[ReferenceWindow],
    observation: ObservationIdentity,
    cutoff: datetime,
    reasons: set[ReasonCode],
) -> FeatureComparison:
    eligible = []
    future = 0
    for ref in support:
        w = ref.window
        if w.outbound_record_count < 8 or getattr(w, name) is None:
            continue
        if w.event_end >= cutoff:
            future += 1
            reasons.add("FUTURE_OR_OVERLAPPING_WINDOWS_EXCLUDED")
            continue
        if (
            ref.observation.root_identity == observation.root_identity
            or ref.observation.dataset_id == observation.dataset_id
            or ref.observation.feature_observation_sha256 == observation.feature_observation_sha256
        ):
            reasons.add("TARGET_SOURCE_EXCLUDED")
            continue
        eligible.append(w)
    ids = tuple(sorted(w.source_receipt_id for w in eligible if w.source_receipt_id))
    if not eligible:
        return _unavailable("MISSING", current, ids, future)
    newest = max(w.event_end for w in eligible)
    if cutoff - newest > timedelta(days=7):
        reasons.add("STALE_REFERENCE")
        return _unavailable("STALE", current, ids, future)
    short = newest - min(w.event_start for w in eligible) < timedelta(days=1)
    if len(eligible) < 3 or short:
        if len(eligible) < 3:
            reasons.add("INSUFFICIENT_REFERENCE_WINDOWS")
        if short:
            reasons.add("INSUFFICIENT_REFERENCE_SPAN")
        return _unavailable("INSUFFICIENT", current, ids, future)
    values = [getattr(w, name) for w in eligible]
    center = median(values)
    scale = max(0.05, 1.4826 * median(abs(v - center) for v in values))
    z = abs(current - center) / scale
    if not all(isfinite(value) for value in (center, scale, z)):
        reasons.add("NONFINITE_FEATURE_UNAVAILABLE")
        return _unavailable("INCOMPATIBLE", current, (), future)
    return FeatureComparison("READY", current, center, scale, z, ids, future, z >= 3)


def _window_ids(ids: tuple[str, ...]) -> None:
    _tuple(ids, 16)
    for identity in ids:
        _receipt(identity, required=True)
    _require(tuple(sorted(set(ids))) == ids)


def _feature_comparison(feature: FeatureComparison, name: str) -> None:
    _require(type(feature) is FeatureComparison)
    _require(type(feature.status) is str and feature.status in get_args(ComparisonStatus))
    _window_ids(feature.eligible_window_ids)
    _integer(feature.excluded_future_count, 16)
    _require(len(feature.eligible_window_ids) + feature.excluded_future_count <= 16)
    _require(type(feature.drifting) is bool)
    if feature.current is not None:
        _number(feature.current, 1 if name == "outbound_share" else float("inf"))
    if feature.status == "READY":
        _require(len(feature.eligible_window_ids) >= 3)
        _number(feature.current, float("inf"))
        _number(feature.reference_median, 1 if name == "outbound_share" else float("inf"))
        _number(feature.reference_scale, float("inf"))
        _number(feature.robust_z, float("inf"))
        if (
            feature.current is None
            or feature.reference_median is None
            or feature.reference_scale is None
            or feature.robust_z is None
        ):
            raise BaselineInputError()
        _require(feature.reference_scale >= 0.05)
        _require(
            feature.robust_z
            == abs(feature.current - feature.reference_median) / feature.reference_scale
        )
        _require(feature.drifting == (feature.robust_z >= 3))
    else:
        _require(
            feature.reference_median is None
            and feature.reference_scale is None
            and feature.robust_z is None
            and not feature.drifting
        )
        if feature.status in ("MISSING", "INCOMPATIBLE"):
            _require(not feature.eligible_window_ids)
        else:
            _require(bool(feature.eligible_window_ids) and feature.current is not None)


def _comparison_result(result: BaselineComparisonResult) -> None:
    _require(type(result) is BaselineComparisonResult)
    _tuple(result.comparisons, 128)
    _tuple(result.candidates, 128)
    _integer(result.unprofiled_count, 128)
    _require(len(result.comparisons) + result.unprofiled_count <= 128)
    _reasons(result.limitations)
    comparisons: dict[ProfileKey, ProfileComparison] = {}
    positive: dict[str, list[ProfileComparison]] = {}
    identities = set()
    hosts: dict[str, str] = {}
    receipts: set[str] = set()
    for row in result.comparisons:
        _require(type(row) is ProfileComparison)
        _key(row.key)
        identities.add((row.key.scope_config_sha256, row.key.sensor_key, row.key.feature_version))
        _require(len(identities) <= 1, "BASELINE_SCOPE_MISMATCH")
        _host_binding(_key_stream(row.key), hosts)
        _require(row.key not in comparisons)
        comparisons[row.key] = row
        _reasons(row.limitations)
        _require(_window_allowed(_key_stream(row.key), row.limitations))
        _require(set(row.limitations) <= set(result.limitations))
        _window_ids(row.source_window_ids)
        families = [getattr(row, name) for name in FEATURES]
        for name, feature in zip(FEATURES, families, strict=True):
            _feature_comparison(feature, name)
        if set(result.limitations) & GLOBAL_TARGET_VETOES or (
            "INSUFFICIENT_STREAM_SAMPLES" in row.limitations
        ):
            # Family validation also requires null statistics, no support and no drift.
            _require(all(f.status == "INCOMPATIBLE" for f in families))
        if (
            row.key.observation_kind == "AGGREGATE"
            or "PACKET_TIMING_UNAVAILABLE" in row.limitations
        ):
            _require(row.recurrence.current is None)
        if "DIRECTION_BALANCE_UNAVAILABLE" in row.limitations:
            _require(row.outbound_share.current is None)
        _require(type(row.status) is str and row.status == _profile_status(families))
        _require(
            row.source_window_ids
            == tuple(sorted({i for f in families for i in f.eligible_window_ids}))
        )
        receipts.update(row.source_window_ids)
        _require(len(receipts) <= 16, "BASELINE_SOURCE_LIMIT")
        factors = _factors(families)
        score = sum(f.points for f in factors) if len(factors) >= 2 else 0.0
        _number(row.historical_anomaly_score, 90)
        _require(row.historical_anomaly_score == score)
        if score:
            positive.setdefault(row.key.peer_ip, []).append(row)
    winners = {
        peer: min(rows, key=lambda r: (-r.historical_anomaly_score, _key_bytes(r.key)))
        for peer, rows in positive.items()
    }
    seen: set[str] = set()
    for item in result.candidates:
        _require(type(item) is HistoricalPeerCandidate)
        _key(item.comparison_key)
        candidate = item.candidate
        _require(type(candidate) is BehaviorCandidate)
        _ip(candidate.candidate_ip)
        peer = candidate.candidate_ip
        _require(peer in winners and peer not in seen)
        seen.add(peer)
        row = winners[peer]
        _require(item.comparison_key == row.key)
        _number(candidate.anomaly_score, 90)
        _require(candidate.anomaly_score == row.historical_anomaly_score)
        for collection in (candidate.internal_hosts, candidate.protocols, candidate.ports):
            _tuple(collection, 1, 1)
        _integer(candidate.ports[0], 65535)
        _require(
            candidate.internal_hosts == (row.key.internal_host_ip,)
            and candidate.protocols == (row.key.protocol,)
            and candidate.ports == (row.key.service_port,)
        )
        _envelope(candidate.first_seen, candidate.last_seen)
        _reasons(cast(tuple[ReasonCode, ...], candidate.limitations))
        _require(candidate.limitations == row.limitations)
        _tuple(candidate.factors, 3, 2)
        for factor in candidate.factors:
            _require(type(factor) is PrefilterFactor)
            _text(factor.name, 64)
            _text(factor.explanation, 420)
            _number(factor.points, 30)
            _require(isinstance(factor.metrics, Mapping))
            _require(len(factor.metrics) <= 16, "BASELINE_SOURCE_LIMIT")
            for key, value in factor.metrics.items():
                _text(key, 64)
                if type(value) is str:
                    _text(value)
                else:
                    _number(value, float("inf"))
        _require(candidate.factors == tuple(_factors([getattr(row, name) for name in FEATURES])))
    _require(seen == set(winners))


def _encode(value: Any) -> Any:
    if isinstance(value, datetime):
        return _utc(value).isoformat(timespec="microseconds").replace("+00:00", "Z")
    if is_dataclass(value):
        result = {field.name: _encode(getattr(value, field.name)) for field in fields(value)}
        if isinstance(value, ProfileComparison):
            result["features"] = {name: result.pop(name) for name in FEATURES}
        return result
    if isinstance(value, tuple):
        return [_encode(item) for item in value]
    if isinstance(value, Mapping):
        return {key: _encode(item) for key, item in value.items()}
    return value


_ARRAY_LIMITS = {
    "windows": 2048,
    "factors": 3,
    "source_window_ids": 16,
    "eligible_window_ids": 16,
    "limitations": len(get_args(ReasonCode)),
    "reasons": len(get_args(ReasonCode)),
}


def _decode(value: Any, kind: Any, field_name: str = "") -> Any:
    # The schema bounds traversal before member construction; no generic walk of unknown data.
    origin, args = get_origin(kind), get_args(kind)
    if origin is UnionType:
        for alternative in args:
            try:
                return _decode(value, alternative, field_name)
            except BaselineInputError as error:
                if error.code != "BASELINE_SOURCE_INVALID":
                    raise
        raise BaselineInputError()
    if kind is type(None):
        _require(value is None)
        return None
    if origin is Literal:
        _require(type(value) is str and value in args)
        return value
    if origin is tuple:
        _require(type(value) is list)
        _require(len(value) <= _ARRAY_LIMITS.get(field_name, 128), "BASELINE_SOURCE_LIMIT")
        return tuple(_decode(item, args[0]) for item in value)
    if origin is dict:
        _require(type(value) is dict)
        _require(len(value) <= 16, "BASELINE_SOURCE_LIMIT")
        return {_decode(key, args[0]): _decode(item, args[1]) for key, item in value.items()}
    if kind is datetime:
        _text(value, 27)
        _require(
            re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z", value)
            is not None
        )
        try:
            return _utc(datetime.fromisoformat(value))
        except ValueError:
            raise BaselineInputError() from None
    if is_dataclass(kind):
        _require(type(value) is dict)
        names = {field.name for field in fields(kind)}
        wire_names = (names - set(FEATURES)) | {"features"} if kind is ProfileComparison else names
        _require(value.keys() == wire_names)
        data = dict(value)
        if kind is ProfileComparison:
            features = data.pop("features")
            _require(type(features) is dict and features.keys() == set(FEATURES))
            data.update(features)
        types = get_type_hints(kind)
        decoded = cast(Any, kind)(
            **{
                field.name: _decode(data[field.name], types[field.name], field.name)
                for field in fields(kind)
            }
        )
        if kind is PrefilterFactor:
            return replace(decoded, metrics=MappingProxyType(decoded.metrics))
        return decoded
    if kind is bool:
        _require(type(value) is bool)
    elif kind is int:
        _integer(value)
    elif kind is float:
        _number(value, float("inf"))
        return float(value)
    elif kind is str:
        _text(value, 420)
    else:
        raise BaselineInputError()
    return value


def baseline_build_to_mapping(result: BaselineBuildResult) -> dict[str, Any]:
    _build_result(result)
    ordered = replace(
        result, profiles=tuple(sorted(result.profiles, key=lambda p: _key_bytes(p.stream)))
    )
    return cast(dict[str, Any], _encode(ordered))


def baseline_build_from_mapping(value: object) -> BaselineBuildResult:
    result = cast(BaselineBuildResult, _decode(value, BaselineBuildResult))
    _build_result(result)
    return result


def baseline_comparison_to_mapping(result: BaselineComparisonResult) -> dict[str, Any]:
    _comparison_result(result)
    ordered = replace(
        result,
        comparisons=tuple(sorted(result.comparisons, key=lambda c: _key_bytes(c.key))),
        candidates=tuple(sorted(result.candidates, key=_candidate_order)),
    )
    return cast(dict[str, Any], _encode(ordered))


def baseline_comparison_from_mapping(value: object) -> BaselineComparisonResult:
    result = cast(BaselineComparisonResult, _decode(value, BaselineComparisonResult))
    _comparison_result(result)
    return result


def behavior_window_to_mapping(window: BehaviorWindow) -> dict[str, Any]:
    """Source publication projection; target null receipts are only legal inside a build."""
    _window(window, publication=True)
    return cast(dict[str, Any], _encode(window))


def behavior_window_from_mapping(value: object) -> BehaviorWindow:
    window = cast(BehaviorWindow, _decode(value, BehaviorWindow))
    _window(window, publication=True)
    return window


def baseline_reference_to_mapping(reference: BaselineReference) -> dict[str, Any]:
    _reference(reference)
    ordered = replace(
        reference,
        windows=tuple(
            sorted(
                reference.windows,
                key=lambda r: (_key_bytes(r.window.key), r.window.source_receipt_id or ""),
            )
        ),
    )
    return cast(dict[str, Any], _encode(ordered))


def baseline_reference_from_mapping(value: object) -> BaselineReference:
    reference = cast(BaselineReference, _decode(value, BaselineReference))
    _reference(reference)
    return reference


def _factors(families: list[FeatureComparison]) -> list[PrefilterFactor]:
    factors = []
    for family, name in zip(families, FACTOR_NAMES, strict=True):
        if family.status != "READY" or not family.drifting:
            continue
        if (
            family.current is None
            or family.reference_median is None
            or family.reference_scale is None
            or family.robust_z is None
        ):
            raise BaselineInputError()
        factors.append(
            PrefilterFactor(
                name,
                round(min(30.0, 10.0 + family.robust_z), 3),
                "Change relative to explicitly approved historical windows; not a threat verdict.",
                {
                    "observed_value": family.current,
                    "reference_median": family.reference_median,
                    "reference_scale": family.reference_scale,
                    "robust_z": family.robust_z,
                    "reference_windows": len(family.eligible_window_ids),
                },
            )
        )
    return [
        replace(f, metrics=cast(dict[str, int | float | str], MappingProxyType(f.metrics)))
        for f in factors
    ]
