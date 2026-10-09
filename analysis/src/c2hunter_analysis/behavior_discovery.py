"""Rule-independent, same-job service-cohort discovery; not a threat verdict.

Each peer contributes one primary (host, sensor, protocol, service-port) stream,
chosen by retained record count and then lexical identity. Cohorts share protocol,
service port and packet/aggregate representation; peers are equally weighted.
Eight outbound records per stream and eight peers per observed feature are required.
The families are normalized MAD of outbound inter-arrivals, normalized MAD of
outbound record means (bytes/packets), and directional byte share. Two families
must exceed a robust z of 3 against the same-job median, with scale
max(0.05, 1.4826 * MAD). Dispersion is tested downward, byte share two-sided.
Each family contributes min(30, 10+z); uncertain reported clocks subtract 10.
These are bounded prioritization points, not probabilities or trained ML accuracy.

Timing requires ALL primary outbound rows to have packet_count=1 and duration=0,
with eight distinct timestamps. Aggregate flush times and packet_sizes (which
may merely contain min/max) are never interpreted as packet sequences. Aggregate
record means and unidirectional byte totals can still support size/direction
comparisons. Bidirectional rows cannot establish directional totals. No historical
baseline, threat intelligence, port suspicion, or existing detector score is used.
Trusted peers and primary DNS/NTP services are conservatively excluded; uniform
heartbeat populations do not become candidates merely by being periodic.

Admission is fail-closed, not prefix sampling: at most 8192 input rows, 256 peers,
256 total SYN observations and 128 items per context collection. Input/context/SYN
budget rejection does not enumerate peers (both counts are zero, warning says so).
Peer-budget rejection counts all valid scoped peers as excluded. These fixed caps
also bound calls into shared suppression helpers; new cohort work has no pairwise
comparison loop. Invalid rows are skipped with an explicit warning, never repaired.
Only needed fields are inspected (bounded identifier/flag lengths); payload blobs
and packet-size arrays are not traversed. At most four factors per candidate.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network
from math import isfinite
from statistics import median

from .ai_candidates import PrefilterFactor
from .domain import AnalysisContext, Flow
from .tcp_sessions import syn_retry_duplicate_flow_ids
from .traffic_suppression import outbound_control_flood_flow_ids

MIN_RECORDS = 8
MIN_COHORT_PEERS = 8
ROBUST_Z_THRESHOLD = 3.0
DISPERSION_FLOOR = 0.05
MAX_INPUT_FLOWS = 8192
MAX_PEERS = 256
MAX_SYN_OBSERVATIONS = 256
MAX_CONTEXT_ITEMS = 128
MAX_FIELD_CHARS = 256
MAX_TCP_FLAGS = 16


@dataclass(frozen=True)
class BehaviorCandidate:
    candidate_ip: str
    anomaly_score: float
    internal_hosts: tuple[str, ...]
    protocols: tuple[str, ...]
    ports: tuple[int, ...]
    first_seen: datetime
    last_seen: datetime
    factors: tuple[PrefilterFactor, ...]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class BehaviorDiscoveryResult:
    """Counts describe valid scoped external peers, not malformed/out-of-scope rows.

    Examined means a primary stream had enough outbound samples (even if its
    cohort was too sparse). Excluded means an enumerated peer could not be
    profiled, or admission/suppression rejected it. Benign examined peers are not
    counted as excluded. Warnings distinguish unenumerated early rejection.
    """

    candidates: tuple[BehaviorCandidate, ...]
    examined_peer_count: int
    excluded_peer_count: int
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class _Profile:
    peer: str
    rows: tuple[Flow, ...]
    host: str
    protocol: str
    port: int
    recurrence: float | None
    size_dispersion: float
    outbound_share: float | None
    packet_level: bool
    hosts: tuple[str, ...]
    protocols: tuple[str, ...]
    ports: tuple[int, ...]
    first_seen: datetime
    last_seen: datetime


def _dispersion(values: list[float]) -> float:
    center = median(values)
    return median(abs(value - center) for value in values) / max(center, 1e-9)


def _finite_nonnegative(value: object) -> bool:
    return (
        isinstance(value, int | float)
        and not isinstance(value, bool)
        and 0 <= value <= 2**53
        and isfinite(value)
    )


def _valid_row(flow: Flow) -> bool:
    if (
        any(
            not isinstance(value, str) or len(value) > MAX_FIELD_CHARS
            for value in (
                flow.source_ip,
                flow.destination_ip,
                flow.sensor_id,
                flow.protocol,
                flow.direction,
            )
        )
        or len(flow.tcp_flags or {}) > MAX_TCP_FLAGS
    ):
        return False
    if any(not isinstance(key, str) or len(key) > MAX_FIELD_CHARS for key in flow.tcp_flags or {}):
        return False
    if any(
        port is not None and (type(port) is not int or not 0 <= port <= 65535)
        for port in (flow.source_port, flow.destination_port)
    ):
        return False
    if not all(
        _finite_nonnegative(value)
        for value in (
            flow.packet_count,
            flow.total_bytes,
            flow.duration_seconds,
            flow.tcp_syn_count,
            flow.tcp_ack_count,
            flow.tcp_rst_count,
            flow.tcp_syn_only_count,
            flow.tcp_syn_ack_count,
            flow.tcp_ack_only_count,
            *(flow.tcp_flags or {}).values(),
        )
    ):
        return False
    if (
        not isinstance(flow.packet_count, int)
        or flow.packet_count < 1
        or not isinstance(flow.total_bytes, int)
        or flow.duration_seconds > 31_536_000
    ):
        return False
    try:
        if flow.timestamp.utcoffset() is None:
            return False
        flow.timestamp + timedelta(seconds=flow.duration_seconds)
        for offset, sequence in flow.tcp_syn_only_observations or ():
            if (
                type(offset) is not int
                or not 0 <= offset <= 31_536_000_000_000
                or type(sequence) is not int
                or not 0 <= sequence < 2**32
            ):
                return False
            flow.timestamp + timedelta(microseconds=offset)
        ip_address(flow.source_ip)
        ip_address(flow.destination_ip)
    except (AttributeError, OverflowError, TypeError, ValueError):
        return False
    return True


def _flow_order(flow: Flow) -> tuple[object, ...]:
    """Canonicalize ties before the shared retry helper's stable timestamp sort."""
    return (
        flow.timestamp,
        flow.sensor_id,
        flow.source_ip,
        flow.destination_ip,
        flow.source_port if flow.source_port is not None else -1,
        flow.destination_port if flow.destination_port is not None else -1,
        flow.protocol,
        flow.direction,
        flow.packet_count,
        flow.total_bytes,
        flow.duration_seconds,
        flow.tcp_syn_only_observations or (),
        flow.tcp_syn_only_observations_truncated,
        flow.tcp_flags_observed,
        flow.tcp_syn_count,
        flow.tcp_ack_count,
        flow.tcp_rst_count,
        flow.tcp_syn_only_count,
        flow.tcp_syn_ack_count,
        flow.tcp_ack_only_count,
        tuple(sorted((flow.tcp_flags or {}).items())),
        bool(
            flow.payload_hash
            or flow.last_payload_hash
            or flow.payload_prefix_hash
            or flow.payload_simhash
            or (flow.payload_length or 0) > 0
        ),
        flow.bidirectional,
    )


def discover_behavior_candidates(
    context: AnalysisContext, *, trusted_peers: set[str] | None = None
) -> BehaviorDiscoveryResult:
    """Return relative behavior candidates without changing rule scores."""
    if context.start.utcoffset() is None or context.end.utcoffset() is None:
        return BehaviorDiscoveryResult((), 0, 0, ("INVALID_ANALYSIS_WINDOW",))
    if len(context.flows) > MAX_INPUT_FLOWS:
        return BehaviorDiscoveryResult(
            (), 0, 0, (f"INPUT_FLOW_BUDGET_EXCEEDED:{MAX_INPUT_FLOWS};PEER_COUNTS_NOT_ENUMERATED",)
        )
    if any(
        len(items) > MAX_CONTEXT_ITEMS
        for items in (
            context.selected_sensors,
            context.internal_cidrs,
            context.clock_offsets_ms,
            context.parameters,
        )
    ):
        return BehaviorDiscoveryResult(
            (), 0, 0, (f"CONTEXT_BUDGET_EXCEEDED:{MAX_CONTEXT_ITEMS};PEER_COUNTS_NOT_ENUMERATED",)
        )
    try:
        for cidr in context.internal_cidrs:
            if len(cidr) > MAX_FIELD_CHARS:
                raise ValueError("overlong CIDR")
            ip_network(cidr, strict=False)
    except (TypeError, ValueError):
        return BehaviorDiscoveryResult((), 0, 0, ("INVALID_INTERNAL_CIDRS",))
    if (
        sum(len(flow.tcp_syn_only_observations or ()) for flow in context.flows)
        > MAX_SYN_OBSERVATIONS
    ):
        return BehaviorDiscoveryResult(
            (),
            0,
            0,
            (f"SYN_OBSERVATION_BUDGET_EXCEEDED:{MAX_SYN_OBSERVATIONS};PEER_COUNTS_NOT_ENUMERATED",),
        )
    warnings: set[str] = set()
    valid = []
    for flow in context.flows:
        if _valid_row(flow):
            valid.append(flow)
        else:
            warnings.add("INVALID_FLOW_ROWS_SKIPPED")
    context = replace(context, flows=sorted(valid, key=_flow_order))
    grouped: dict[str, dict[tuple[str, str, str, int], list[Flow]]] = defaultdict(
        lambda: defaultdict(list)
    )
    for flow in context.scoped_flows():
        if flow.direction.upper() == "OUTBOUND":
            peer, host, port = flow.destination_ip, flow.source_ip, flow.destination_port
        elif flow.direction.upper() == "INBOUND":
            peer, host, port = flow.source_ip, flow.destination_ip, flow.source_port
        else:
            source_internal = context.is_internal(flow.source_ip)
            destination_internal = context.is_internal(flow.destination_ip)
            if source_internal == destination_internal:
                continue
            if source_internal:
                peer, host, port = flow.destination_ip, flow.source_ip, flow.destination_port
            else:
                peer, host, port = flow.source_ip, flow.destination_ip, flow.source_port
        if port is None:
            continue
        key = (host, flow.sensor_id, flow.protocol.upper(), port)
        grouped[peer][key].append(flow)
    if len(grouped) > MAX_PEERS:
        return BehaviorDiscoveryResult(
            (), 0, len(grouped), tuple(sorted(warnings | {f"PEER_BUDGET_EXCEEDED:{MAX_PEERS}"}))
        )
    profiles: list[_Profile] = []
    try:
        retry_duplicates = syn_retry_duplicate_flow_ids(context)
    except (OverflowError, TypeError, ValueError):
        return BehaviorDiscoveryResult(
            (), 0, len(grouped), tuple(sorted(warnings | {"SUPPRESSION_UNAVAILABLE"}))
        )
    for peer, streams in sorted(grouped.items()):
        suppressed = outbound_control_flood_flow_ids(
            context, (flow for rows in streams.values() for flow in rows)
        )
        retained = {
            key: [
                flow
                for flow in rows
                if id(flow) not in suppressed and id(flow) not in retry_duplicates
            ]
            for key, rows in streams.items()
        }
        if any(len(retained[key]) < len(streams[key]) for key in streams):
            warnings.add("SUPPRESSED_CONTROL_OR_RETRY_ROWS")
        streams = {key: rows for key, rows in retained.items() if rows}
        if not streams:
            continue
        if trusted_peers and peer in trusted_peers:
            warnings.add("TRUSTED_PEERS_EXCLUDED")
            continue
        key = min(streams, key=lambda key: (-len(streams[key]), key))
        if key[3] in {53, 123}:
            warnings.add("COMMON_SERVICES_EXCLUDED")
            continue
        rows = tuple(sorted(streams[key], key=lambda flow: flow.timestamp))
        outbound = [flow for flow in rows if flow.source_ip == key[0]]
        if len(outbound) < MIN_RECORDS:
            warnings.add("INSUFFICIENT_STREAM_SAMPLES")
            continue
        packet_level = all(
            flow.packet_count == 1 and flow.duration_seconds == 0 for flow in outbound
        )
        times = sorted({flow.timestamp.timestamp() for flow in outbound}) if packet_level else []
        intervals = [right - left for left, right in zip(times, times[1:], strict=False)]
        if not packet_level:
            warnings.add("AGGREGATED_FLOW_TIMING_UNAVAILABLE")
        total_bytes = sum(flow.total_bytes for flow in rows)
        outbound_share = (
            sum(flow.total_bytes for flow in outbound) / total_bytes
            if total_bytes and not any(flow.bidirectional for flow in rows)
            else None
        )
        profiles.append(
            _Profile(
                peer,
                rows,
                key[0],
                key[2],
                key[3],
                _dispersion(intervals) if len(intervals) >= MIN_RECORDS - 1 else None,
                _dispersion([flow.total_bytes / flow.packet_count for flow in outbound]),
                outbound_share,
                packet_level,
                tuple(sorted({key[0] for key in streams})),
                tuple(sorted({key[2] for key in streams})),
                tuple(sorted({key[3] for key in streams})),
                min(flow.timestamp for rows in streams.values() for flow in rows),
                max(
                    flow.timestamp + timedelta(seconds=flow.duration_seconds)
                    for rows in streams.values()
                    for flow in rows
                ),
            )
        )
    cohorts: dict[tuple[str, int, bool], list[_Profile]] = defaultdict(list)
    for profile in profiles:
        cohorts[profile.protocol, profile.port, profile.packet_level].append(profile)
    candidates: list[BehaviorCandidate] = []
    for cohort in cohorts.values():
        if len(cohort) < MIN_COHORT_PEERS:
            warnings.add("INSUFFICIENT_SERVICE_COHORT")
            continue
        baselines = []
        for attribute in ("recurrence", "size_dispersion", "outbound_share"):
            values = [
                value for profile in cohort if (value := getattr(profile, attribute)) is not None
            ]
            if len(values) < MIN_COHORT_PEERS:
                continue
            center = median(values)
            scale = max(DISPERSION_FLOOR, 1.4826 * median(abs(v - center) for v in values))
            baselines.append((attribute, center, scale, len(values)))
        for profile in cohort:
            factors = []
            for attribute, center, scale, cohort_peers in baselines:
                observed = getattr(profile, attribute)
                if observed is None:
                    continue
                z = (
                    abs(center - observed) if attribute == "outbound_share" else center - observed
                ) / scale
                if z < ROBUST_Z_THRESHOLD:
                    continue
                factors.append(
                    PrefilterFactor(
                        name={
                            "recurrence": "RELATIVE_RECURRENCE",
                            "size_dispersion": "RELATIVE_RECORD_SIZE_STABILITY",
                            "outbound_share": "RELATIVE_DIRECTION_BALANCE",
                        }[attribute],
                        points=round(min(30.0, 10.0 + z), 3),
                        explanation=(
                            "Directional byte share differs from same-job service peers."
                            if attribute == "outbound_share"
                            else "Lower normalized dispersion than same-job service peers."
                        ),
                        metrics={
                            "observed_value": observed,
                            "cohort_median": center,
                            "robust_z": z,
                            "cohort_peers": cohort_peers,
                            "record_count": len(profile.rows),
                            "host": profile.host,
                            "sensor": profile.rows[0].sensor_id,
                            "protocol": profile.protocol,
                            "service_port": profile.port,
                        },
                    )
                )
            if len(factors) < 2:
                continue
            clock = context.clock_offsets_ms.get(profile.rows[0].sensor_id, 0.0)
            uncertain_clock = not _finite_nonnegative(abs(clock)) or abs(clock) > 2000
            if uncertain_clock:
                warnings.add("CAPTURE_CLOCK_UNCERTAINTY")
                factors.append(
                    PrefilterFactor(
                        name="CAPTURE_CLOCK_UNCERTAINTY",
                        points=-10.0,
                        explanation=(
                            "Reported sensor clock quality reduces confidence, not threat evidence."
                        ),
                        metrics={"clock_quality": "uncertain"},
                    )
                )
            candidates.append(
                BehaviorCandidate(
                    candidate_ip=profile.peer,
                    anomaly_score=sum(factor.points for factor in factors),
                    internal_hosts=profile.hosts,
                    protocols=profile.protocols,
                    ports=profile.ports,
                    first_seen=profile.first_seen,
                    last_seen=profile.last_seen,
                    factors=tuple(factors),
                    limitations=(
                        "JOB_LOCAL_NO_HISTORICAL_BASELINE",
                        "CAPTURE_COMPLETENESS_UNVERIFIED",
                        "RECORD_MEANS_NOT_PACKET_SIZE_DISTRIBUTION",
                        "PRIMARY_STREAM_ONLY",
                        *(("CAPTURE_CLOCK_UNCERTAINTY",) if uncertain_clock else ()),
                        *(
                            ("AGGREGATED_FLOW_TIMING_UNAVAILABLE",)
                            if not profile.packet_level
                            else ()
                        ),
                    ),
                )
            )
    return BehaviorDiscoveryResult(
        tuple(sorted(candidates, key=lambda item: (-item.anomaly_score, item.candidate_ip))),
        len(profiles),
        len(grouped) - len(profiles),
        tuple(sorted(warnings)),
    )
