"""Bounded, deterministic DDoS traffic classification.

The module reports observations and defensive hypotheses.  It never attributes an
actor, claims service impact, or executes a mitigation.  Packet-level and
aggregated-flow rate measurements remain explicitly distinct.
"""

from __future__ import annotations

import hashlib
import heapq
import math
import statistics
from bisect import bisect_right
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Network, IPv6Network, collapse_addresses, ip_address, ip_network
from typing import Any, cast

REPORT_VERSION = "ddos-attack-report-v2"
CATALOG_VERSION = "ddos-taxonomy-v2"
REFLECTION_PORTS = frozenset({17, 19, 53, 123, 389, 1900, 11211})
MAX_TARGETS = 4096
MAX_BUCKETS_PER_TARGET = 3600
MAX_FINDINGS = 100
MAX_INTERNAL_NETWORKS = 256
MAX_SCANNED_RECORDS = 2_000_000
MIN_TARGET_RECORDS = 100
MAX_REPORT_INTEGER = 2**53 - 1

_PARAMETER_BOUNDS: dict[str, tuple[float, float, bool]] = {
    "ddos_bucket_seconds": (1, 60, True),
    "ddos_min_duration_seconds": (1, 3600, True),
    "ddos_min_source_count": (2, 100_000, True),
    "ddos_min_packet_count": (1, 2**63 - 1, True),
    "ddos_min_packets_per_second": (1, 10_000_000, False),
    "ddos_min_bits_per_second": (1, 10**13, False),
    "ddos_baseline_min_buckets": (5, 3600, True),
    "ddos_baseline_ratio": (1, 1000, False),
    "ddos_mad_z_threshold": (2, 100, False),
    "ddos_protocol_share_threshold": (0.5, 1, False),
    "ddos_tcp_flag_share_threshold": (0.5, 1, False),
    "ddos_response_ratio_max": (0, 1, False),
    "ddos_reflection_port_share_threshold": (0.5, 1, False),
    "ddos_reflection_min_average_packet_bytes": (1, 65535, True),
    "ddos_overlap_window_seconds": (1, 300, True),
}

_DEFAULTS: dict[str, int | float] = {
    "ddos_bucket_seconds": 1,
    "ddos_min_duration_seconds": 3,
    "ddos_min_source_count": 20,
    "ddos_min_packet_count": 1000,
    "ddos_min_packets_per_second": 100,
    "ddos_min_bits_per_second": 1_000_000,
    "ddos_baseline_min_buckets": 20,
    "ddos_baseline_ratio": 5.0,
    "ddos_mad_z_threshold": 6.0,
    "ddos_protocol_share_threshold": 0.80,
    "ddos_tcp_flag_share_threshold": 0.80,
    "ddos_response_ratio_max": 0.20,
    "ddos_reflection_port_share_threshold": 0.60,
    "ddos_reflection_min_average_packet_bytes": 256,
    "ddos_overlap_window_seconds": 10,
}

_PRIORITY = {
    "MULTI_VECTOR": 0,
    "POSSIBLE_REFLECTION_AMPLIFICATION": 1,
    "TCP_SYN_FLOOD": 2,
    "UDP_FLOOD": 3,
    "ICMP_ECHO_FLOOD": 4,
    "ICMP_FLOOD": 5,
    "TCP_ACK_FLOOD": 6,
    "TCP_RST_FLOOD": 7,
}

_COMMON_RECOMMENDATIONS = (
    "PRESERVE_CAPTURE_AND_LOGS",
    "VERIFY_SERVICE_IMPACT",
    "CONTACT_UPSTREAM_PROVIDER",
    "MONITOR_RECOVERY_AND_FALSE_POSITIVES",
)
_TYPE_RECOMMENDATIONS = {
    "TCP_SYN_FLOOD": (
        "ENABLE_SYN_PROXY_OR_COOKIES",
        "APPLY_EDGE_SYN_RATE_LIMIT",
        "CHECK_SYN_BACKLOG_AND_CONNTRACK",
    ),
    "UDP_FLOOD": (
        "ENGAGE_SCRUBBING_OR_FLOWSPEC",
        "FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES",
    ),
    "POSSIBLE_REFLECTION_AMPLIFICATION": (
        "ENGAGE_SCRUBBING_OR_FLOWSPEC",
        "FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES",
        "VALIDATE_REFLECTION_SOURCE_PORTS",
    ),
    "ICMP_ECHO_FLOOD": ("RATE_LIMIT_NONESSENTIAL_ICMP", "PRESERVE_PMTUD_AND_REQUIRED_ICMP"),
    "ICMP_FLOOD": ("RATE_LIMIT_NONESSENTIAL_ICMP", "PRESERVE_PMTUD_AND_REQUIRED_ICMP"),
    "TCP_ACK_FLOOD": (
        "APPLY_STATEFUL_TCP_VALIDATION",
        "RATE_LIMIT_INVALID_TCP_FLAGS",
        "CHECK_MIDDLEBOX_RESET_SOURCES",
    ),
    "TCP_RST_FLOOD": (
        "APPLY_STATEFUL_TCP_VALIDATION",
        "RATE_LIMIT_INVALID_TCP_FLAGS",
        "CHECK_MIDDLEBOX_RESET_SOURCES",
    ),
    "MULTI_VECTOR": ("ENGAGE_SCRUBBING_OR_FLOWSPEC",),
}
_OUTBOUND_RECOMMENDATIONS = (
    "ISOLATE_INTERNAL_SOURCES",
    "APPLY_EGRESS_RATE_LIMIT",
    "ENFORCE_EGRESS_ANTISPOOFING",
)


@dataclass(frozen=True)
class Observation:
    sensor: str
    timestamp: datetime
    source: str
    target: str
    target_port: int | None
    source_port: int | None
    protocol: str
    role: str
    direction_source: str
    packets: int
    size_bytes: int
    duration: float
    precision: str
    syn_only: int = 0
    syn_ack: int = 0
    ack_only: int = 0
    rst: int = 0
    fin: int = 0
    payload_packets: int = 0
    payload_visible: bool = True
    response_visible: bool = False
    icmp_type: int | None = None
    packet_sizes: tuple[int, ...] = ()
    payload_prefix_hash: str | None = None
    hop_limit_min: int | None = None
    hop_limit_max: int | None = None
    hop_limit_mode: int | None = None
    hop_limit_distinct_count: int = 0
    ip_id_observed_count: int = 0
    ip_id_distinct_count: int = 0
    ip_id_values_truncated: bool = False
    ip_id_monotonic_transitions: int = 0
    ip_id_transition_count: int = 0


@dataclass
class Target:
    role: str
    ip: str
    port: int | None
    protocol: str
    record_count: int = 0
    packet_count: int = 0
    byte_count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    interval_end: datetime | None = None
    sources: set[str] = field(default_factory=set)
    sensors: set[str] = field(default_factory=set)
    direction_sources: set[str] = field(default_factory=set)
    precisions: set[str] = field(default_factory=set)
    syn_only: int = 0
    syn_ack: int = 0
    ack_only: int = 0
    rst: int = 0
    fin: int = 0
    payload_packets: int = 0
    payload_visible: bool = True
    response_visible: bool = False
    source_ports: Counter[int] = field(default_factory=Counter)
    source_port_records: Counter[int] = field(default_factory=Counter)
    icmp_types: Counter[int] = field(default_factory=Counter)
    packet_sizes: Counter[int] = field(default_factory=Counter)
    packet_size_observed_records: int = 0
    payload_prefix_hashes: Counter[str] = field(default_factory=Counter)
    hop_limit_min: int | None = None
    hop_limit_max: int | None = None
    identity_anomaly_records: int = 0
    identity_observed_records: int = 0
    ip_id_observed_count: int = 0
    ip_id_distinct_count: int = 0
    ip_id_monotonic_transitions: int = 0
    ip_id_transition_count: int = 0
    identity_values_truncated: bool = False
    buckets: dict[int, tuple[int, int]] = field(default_factory=dict)
    bucket_record_counts: dict[int, int] = field(default_factory=dict)
    bucket_heap: list[int] = field(default_factory=list)
    bucket_limited: bool = False


class InvalidRecord(ValueError):
    pass


def _target_rank(key: tuple[str, str, int | None, str]) -> tuple[int, int, int, int, int]:
    role, address, port, protocol = key
    parsed = ip_address(address)
    return (
        0 if role == "VICTIM_SIDE_INBOUND" else 1,
        parsed.version,
        int(parsed),
        -1 if port is None else port,
        {"ICMP": 0, "ICMPV6": 1, "TCP": 2, "UDP": 3}[protocol],
    )


def _target_heap_entry(
    key: tuple[str, str, int | None, str],
) -> tuple[int, int, int, int, int, tuple[str, str, int | None, str]]:
    rank = _target_rank(key)
    return (-rank[0], -rank[1], -rank[2], -rank[3], -rank[4], key)


def _response_rank(key: tuple[str, int | None]) -> tuple[int, int, int]:
    parsed = ip_address(key[0])
    return parsed.version, int(parsed), -1 if key[1] is None else key[1]


def _response_heap_entry(
    key: tuple[str, int | None],
) -> tuple[int, int, int, tuple[str, int | None]]:
    rank = _response_rank(key)
    return -rank[0], -rank[1], -rank[2], key


def _observation_rank(item: Observation) -> tuple[object, ...]:
    return (
        item.timestamp,
        item.sensor,
        item.role,
        item.target,
        -1 if item.target_port is None else item.target_port,
        item.protocol,
        item.source,
        -1 if item.source_port is None else item.source_port,
        item.packets,
        item.size_bytes,
        item.duration,
        item.precision,
        item.direction_source,
        item.syn_only,
        item.syn_ack,
        item.ack_only,
        item.rst,
        item.fin,
        item.payload_packets,
        item.payload_visible,
        item.response_visible,
        -1 if item.icmp_type is None else item.icmp_type,
    )


def _number(parameters: Mapping[str, object], name: str) -> float:
    value = parameters.get(name, _DEFAULTS[name])
    if isinstance(value, bool) or not isinstance(value, int | float) or not math.isfinite(value):
        raise ValueError(f"{name} must be a finite number")
    return float(value)


def _validated_policy(parameters: Mapping[str, object] | None) -> dict[str, object]:
    policy = dict(parameters or {})
    for name, (minimum, maximum, integer_only) in _PARAMETER_BOUNDS.items():
        raw_value = policy.get(name, _DEFAULTS[name])
        if integer_only:
            valid = (
                not isinstance(raw_value, bool)
                and isinstance(raw_value, int)
                and minimum <= raw_value <= maximum
            )
        else:
            value = _number(policy, name)
            valid = minimum <= value <= maximum
        if not valid:
            minimum_text = int(minimum) if float(minimum).is_integer() else minimum
            maximum_text = int(maximum) if float(maximum).is_integer() else maximum
            raise ValueError(f"{name} must be between {minimum_text} and {maximum_text}")
    return policy


def _when(value: object) -> datetime:
    if isinstance(value, str):
        if len(value) > 64:
            raise InvalidRecord("timestamp too long")
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise InvalidRecord("invalid timestamp") from error
    if not isinstance(value, datetime):
        raise InvalidRecord("invalid timestamp")
    try:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    except (OverflowError, ValueError) as error:
        raise InvalidRecord("invalid timestamp") from error


def _address(value: object) -> str:
    if not isinstance(value, str) or len(value) > 45 or "%" in value:
        raise InvalidRecord("invalid address")
    try:
        return str(ip_address(value))
    except ValueError as error:
        raise InvalidRecord("invalid address") from error


def _counter(record: Mapping[str, object], name: str, default: int = 0) -> int:
    value = record.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 2**63:
        raise InvalidRecord(f"invalid {name}")
    return value


def _port(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise InvalidRecord("invalid port")
    return value


NetworkIndex = dict[int, tuple[tuple[int, ...], tuple[int, ...]]]


def _compile_networks(networks: Sequence[object]) -> NetworkIndex:
    if len(networks) > MAX_INTERNAL_NETWORKS:
        raise ValueError("too many internal networks")
    parsed: list[IPv4Network | IPv6Network] = []
    try:
        for network in networks:
            text = str(network)
            if len(text) > 64:
                raise ValueError("internal network is too long")
            parsed.append(ip_network(text, strict=False))
    except ValueError as error:
        raise ValueError("invalid internal network") from error
    result: NetworkIndex = {}
    groups: tuple[list[IPv4Network], list[IPv6Network]] = (
        [item for item in parsed if isinstance(item, IPv4Network)],
        [item for item in parsed if isinstance(item, IPv6Network)],
    )
    collapsed_groups: tuple[list[IPv4Network], list[IPv6Network]] = (
        list(collapse_addresses(groups[0])),
        list(collapse_addresses(groups[1])),
    )
    result[4] = (
        tuple(int(item.network_address) for item in collapsed_groups[0]),
        tuple(int(item.broadcast_address) for item in collapsed_groups[0]),
    )
    result[6] = (
        tuple(int(item.network_address) for item in collapsed_groups[1]),
        tuple(int(item.broadcast_address) for item in collapsed_groups[1]),
    )
    return result


def _internal(value: str, networks: NetworkIndex) -> bool:
    address = ip_address(value)
    starts, ends = networks[address.version]
    index = bisect_right(starts, int(address)) - 1
    return index >= 0 and int(address) <= ends[index]


def _normalize(record: Mapping[str, object], networks: NetworkIndex) -> Observation:
    source = _address(record.get("source_ip"))
    destination = _address(record.get("destination_ip"))
    source_port = _port(record.get("source_port"))
    destination_port = _port(record.get("destination_port"))
    protocol_value = record.get("protocol")
    direction_value = record.get("direction")
    sensor = record.get("sensor_id")
    if not isinstance(protocol_value, str) or protocol_value.upper() not in {
        "TCP",
        "UDP",
        "ICMP",
        "ICMPV6",
    }:
        raise InvalidRecord("unsupported protocol")
    if (
        not isinstance(direction_value, str)
        or not isinstance(sensor, str)
        or not sensor
        or len(sensor) > 128
    ):
        raise InvalidRecord("invalid direction or sensor")
    protocol = protocol_value.upper()
    direction = direction_value.upper()
    source_internal = _internal(source, networks)
    destination_internal = _internal(destination, networks)
    if direction == "INBOUND" and destination_internal:
        role, target, target_port, direction_source = (
            "VICTIM_SIDE_INBOUND",
            destination,
            destination_port,
            "OBSERVED",
        )
    elif direction == "OUTBOUND" and source_internal:
        role, target, target_port, direction_source = (
            "PARTICIPANT_SIDE_OUTBOUND",
            destination,
            destination_port,
            "OBSERVED",
        )
    elif direction in {"UNKNOWN", "BIDIRECTIONAL"} and source_internal != destination_internal:
        if source_internal:
            role, target, target_port = "PARTICIPANT_SIDE_OUTBOUND", destination, destination_port
        else:
            role, target, target_port = "VICTIM_SIDE_INBOUND", destination, destination_port
        direction_source = "INTERNAL_CIDR"
    else:
        raise InvalidRecord("ambiguous direction")

    packets = _counter(record, "packet_count", 1)
    size_bytes = _counter(record, "total_bytes")
    duration_value = record.get("duration_seconds", 0)
    if (
        isinstance(duration_value, bool)
        or not isinstance(duration_value, int | float)
        or not math.isfinite(duration_value)
        or duration_value < 0
    ):
        raise InvalidRecord("invalid duration")
    precision = (
        "PACKET"
        if record.get("packet_evidence_complete") is True and packets == 1
        else "AGGREGATED_FLOW"
    )
    flags = record.get("tcp_flags")
    flags_map = flags if isinstance(flags, Mapping) else {}

    def flag_count(field: str, flag: str) -> int:
        if field in record:
            return _counter(record, field)
        value = flags_map.get(flag, 0)
        return packets if value in (1, True) else 0

    icmp_type = record.get("icmp_type")
    if icmp_type is not None and (
        isinstance(icmp_type, bool) or not isinstance(icmp_type, int) or not 0 <= icmp_type <= 255
    ):
        raise InvalidRecord("invalid ICMP type")
    payload_count_value = record.get("transport_payload_packet_count")
    if payload_count_value is not None:
        payload_packets = _counter(record, "transport_payload_packet_count")
        if payload_packets > packets:
            raise InvalidRecord("transport payload packet count exceeds packet_count")
        payload_visible = True
    else:
        payload_value = record.get("transport_payload_length")
        payload_visible = payload_value is not None
        payload_length = (
            0 if payload_value is None else _counter(record, "transport_payload_length")
        )
        payload_packets = packets if payload_length > 0 else 0
    timestamp = _when(record.get("timestamp"))
    try:
        timestamp + timedelta(seconds=float(duration_value))
    except (OverflowError, ValueError) as error:
        raise InvalidRecord("invalid observation interval") from error
    syn_only = flag_count("tcp_syn_only_count", "syn") if protocol == "TCP" else 0
    syn_ack = flag_count("tcp_syn_ack_count", "syn_ack") if protocol == "TCP" else 0
    ack_only = flag_count("tcp_ack_only_count", "ack") if protocol == "TCP" else 0
    rst = flag_count("tcp_rst_count", "rst") if protocol == "TCP" else 0
    fin = flag_count("tcp_fin_count", "fin") if protocol == "TCP" else 0
    if any(value > packets for value in (syn_only, syn_ack, ack_only, rst, fin)):
        raise InvalidRecord("TCP counter exceeds packet_count")
    if syn_only + syn_ack + ack_only + rst > packets:
        raise InvalidRecord("mutually exclusive TCP counters exceed packet_count")
    packet_sizes_value = record.get("packet_sizes", ())
    if not isinstance(packet_sizes_value, list | tuple) or len(packet_sizes_value) > 32:
        raise InvalidRecord("invalid packet sizes")
    packet_sizes: list[int] = []
    for value in packet_sizes_value:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
            raise InvalidRecord("invalid packet size")
        packet_sizes.append(value)
    payload_prefix_value = record.get("payload_prefix_hash")
    if payload_prefix_value is not None and (
        not isinstance(payload_prefix_value, str)
        or len(payload_prefix_value) != 64
        or any(character not in "0123456789abcdef" for character in payload_prefix_value)
    ):
        raise InvalidRecord("invalid payload prefix hash")

    def bounded_counter(name: str, maximum: int) -> int:
        value = _counter(record, name)
        if value > maximum:
            raise InvalidRecord(f"invalid {name}")
        return value

    hop_limit_min: int | None
    hop_limit_max: int | None
    hop_limit_mode: int | None
    hop_values = tuple(
        record.get(name) for name in ("hop_limit_min", "hop_limit_max", "hop_limit_mode")
    )
    if any(value is not None for value in hop_values):
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255
            for value in hop_values
        ):
            raise InvalidRecord("invalid hop limit statistics")
        hop_limit_min, hop_limit_max, hop_limit_mode = (
            cast(int, hop_values[0]),
            cast(int, hop_values[1]),
            cast(int, hop_values[2]),
        )
        if not hop_limit_min <= hop_limit_mode <= hop_limit_max:
            raise InvalidRecord("inconsistent hop limit statistics")
    else:
        hop_limit_min = hop_limit_max = hop_limit_mode = None
    hop_limit_distinct_count = bounded_counter("hop_limit_distinct_count", 256)
    if (hop_limit_min is None) != (hop_limit_distinct_count == 0):
        raise InvalidRecord("incomplete hop limit statistics")
    ip_id_observed_count = _counter(record, "ip_id_observed_count")
    ip_id_distinct_count = bounded_counter("ip_id_distinct_count", 64)
    ip_id_monotonic_transitions = _counter(record, "ip_id_monotonic_transitions")
    ip_id_transition_count = _counter(record, "ip_id_transition_count")
    if (
        ip_id_distinct_count > ip_id_observed_count
        or ip_id_monotonic_transitions > ip_id_transition_count
        or ip_id_transition_count > max(0, ip_id_observed_count - 1)
    ):
        raise InvalidRecord("inconsistent IP ID statistics")
    return Observation(
        sensor=str(sensor),
        timestamp=timestamp,
        source=source,
        target=target,
        target_port=target_port,
        source_port=source_port,
        protocol=protocol,
        role=role,
        direction_source=direction_source,
        packets=packets,
        size_bytes=size_bytes,
        duration=float(duration_value),
        precision=precision,
        syn_only=syn_only,
        syn_ack=syn_ack,
        ack_only=ack_only,
        rst=rst,
        fin=fin,
        payload_packets=payload_packets,
        payload_visible=payload_visible,
        response_visible=direction == "BIDIRECTIONAL" and record.get("tcp_flags_observed") is True,
        icmp_type=icmp_type,
        packet_sizes=tuple(packet_sizes),
        payload_prefix_hash=payload_prefix_value,
        hop_limit_min=hop_limit_min,
        hop_limit_max=hop_limit_max,
        hop_limit_mode=hop_limit_mode,
        hop_limit_distinct_count=hop_limit_distinct_count,
        ip_id_observed_count=ip_id_observed_count,
        ip_id_distinct_count=ip_id_distinct_count,
        ip_id_values_truncated=record.get("ip_id_values_truncated") is True,
        ip_id_monotonic_transitions=ip_id_monotonic_transitions,
        ip_id_transition_count=ip_id_transition_count,
    )


def _add_observation(target: Target, row: Observation, bucket_seconds: int) -> int:
    target.record_count += 1
    target.packet_count += row.packets
    target.byte_count += row.size_bytes
    target.first_seen = (
        min(target.first_seen, row.timestamp) if target.first_seen else row.timestamp
    )
    row_end = row.timestamp + timedelta(seconds=row.duration)
    target.last_seen = max(target.last_seen, row_end) if target.last_seen else row_end
    target.interval_end = max(target.interval_end, row_end) if target.interval_end else row_end
    target.sources.add(row.source)
    target.sensors.add(row.sensor)
    target.direction_sources.add(row.direction_source)
    target.precisions.add(row.precision)
    target.syn_only += row.syn_only
    target.syn_ack += row.syn_ack
    target.ack_only += row.ack_only
    target.rst += row.rst
    target.fin += row.fin
    target.payload_packets += row.payload_packets
    target.payload_visible = target.payload_visible and row.payload_visible
    target.response_visible = target.response_visible or row.response_visible
    if row.source_port is not None:
        target.source_ports[row.source_port] += row.packets
        target.source_port_records[row.source_port] += 1
    if row.icmp_type is not None:
        target.icmp_types[row.icmp_type] += row.packets
    for packet_size in row.packet_sizes:
        if packet_size in target.packet_sizes or len(target.packet_sizes) < 64:
            target.packet_sizes[packet_size] += 1
    if row.packet_sizes:
        target.packet_size_observed_records += 1
    if row.payload_prefix_hash is not None and (
        row.payload_prefix_hash in target.payload_prefix_hashes
        or len(target.payload_prefix_hashes) < 64
    ):
        target.payload_prefix_hashes[row.payload_prefix_hash] += 1
    if row.hop_limit_min is not None and row.hop_limit_max is not None:
        target.identity_observed_records += 1
        target.hop_limit_min = (
            min(target.hop_limit_min, row.hop_limit_min)
            if target.hop_limit_min is not None
            else row.hop_limit_min
        )
        target.hop_limit_max = (
            max(target.hop_limit_max, row.hop_limit_max)
            if target.hop_limit_max is not None
            else row.hop_limit_max
        )
    if row.ip_id_observed_count:
        target.identity_observed_records += int(row.hop_limit_min is None)
        target.ip_id_observed_count += row.ip_id_observed_count
        target.ip_id_distinct_count += row.ip_id_distinct_count
        target.ip_id_monotonic_transitions += row.ip_id_monotonic_transitions
        target.ip_id_transition_count += row.ip_id_transition_count
        target.identity_values_truncated = (
            target.identity_values_truncated or row.ip_id_values_truncated
        )
    low_monotonicity = (
        row.ip_id_transition_count >= 4
        and row.ip_id_monotonic_transitions / row.ip_id_transition_count < 0.10
        and row.ip_id_distinct_count >= 4
    )
    if row.hop_limit_distinct_count >= 4 or low_monotonicity:
        target.identity_anomaly_records += 1
    if row.precision != "PACKET":
        return 0
    bucket = int(row.timestamp.timestamp() // bucket_seconds)
    omitted_records = 0
    if bucket not in target.buckets and len(target.buckets) >= MAX_BUCKETS_PER_TARGET:
        target.bucket_limited = True
        largest = -target.bucket_heap[0]
        if bucket >= largest:
            return 1
        target.buckets.pop(largest)
        omitted_records = target.bucket_record_counts.pop(largest)
        heapq.heapreplace(target.bucket_heap, -bucket)
    elif bucket not in target.buckets:
        heapq.heappush(target.bucket_heap, -bucket)
    packets, size = target.buckets.get(bucket, (0, 0))
    target.buckets[bucket] = packets + row.packets, size + row.size_bytes
    target.bucket_record_counts[bucket] = target.bucket_record_counts.get(bucket, 0) + 1
    return omitted_records


def _precision(target: Target) -> str:
    return next(iter(target.precisions)) if len(target.precisions) == 1 else "MIXED"


def _rates(target: Target, parameters: Mapping[str, object]) -> dict[str, Any]:
    if target.first_seen is None or target.interval_end is None:
        raise ValueError("target has no observations")
    span = max(1.0, (target.interval_end - target.first_seen).total_seconds())
    bucket_seconds = _number(parameters, "ddos_bucket_seconds")
    packet_buckets = [value for value in target.buckets.values()]
    peak_pps = max((value[0] / bucket_seconds for value in packet_buckets), default=None)
    peak_bps = max((value[1] * 8 / bucket_seconds for value in packet_buckets), default=None)
    precision = _precision(target)
    average_pps = target.packet_count / span
    average_bps = target.byte_count * 8 / span
    bucket_pps = sorted(value[0] / bucket_seconds for value in packet_buckets)
    baseline_pps: float | None = None
    baseline_ratio: float | None = None
    robust_z: float | None = None
    minimum = int(_number(parameters, "ddos_baseline_min_buckets"))
    if len(bucket_pps) >= minimum + 1:
        baseline_values = bucket_pps[:minimum]
        baseline_pps = statistics.median(baseline_values)
        peak = max(bucket_pps)
        baseline_ratio = peak / baseline_pps if baseline_pps > 0 else None
        mad = statistics.median(abs(value - baseline_pps) for value in baseline_values)
        if mad > 0:
            robust_z = (peak - baseline_pps) / (1.4826 * mad)
    return {
        "packet_count": target.packet_count,
        "byte_count": target.byte_count,
        "duration_seconds": round(span, 6),
        "average_packets_per_second": round(average_pps, 6),
        "average_bits_per_second": round(average_bps, 6),
        "peak_packets_per_second": round(peak_pps, 6) if peak_pps is not None else None,
        "peak_bits_per_second": round(peak_bps, 6) if peak_bps is not None else None,
        "peak_is_lower_bound": precision == "MIXED" or target.bucket_limited,
        "measurement_precision": precision,
        "baseline_packets_per_second": baseline_pps,
        "baseline_ratio": baseline_ratio,
        "robust_z_score": robust_z,
    }


def _shape(
    target: Target, rates: Mapping[str, Any], parameters: Mapping[str, object]
) -> tuple[str, dict[str, object], list[str]] | None:
    packets = int(rates["packet_count"])
    protocol = target.protocol
    uncertainty: list[str] = []
    metrics: dict[str, object] = {}
    if protocol == "TCP":
        syn_only_ratio = target.syn_only / packets if packets else 0.0
        ack_only_ratio = target.ack_only / packets if packets else 0.0
        rst_ratio = target.rst / packets if packets else 0.0
        fin_ratio = target.fin / packets if packets else 0.0
        payload_ratio = target.payload_packets / packets if packets else 0.0
        response_ratio = (
            target.syn_ack / max(1, target.syn_only + target.syn_ack)
            if target.response_visible
            else None
        )
        ratios: dict[str, object] = {
            "syn_only_ratio": syn_only_ratio,
            "ack_only_ratio": ack_only_ratio,
            "rst_ratio": rst_ratio,
            "fin_ratio": fin_ratio,
            "payload_packet_ratio": payload_ratio,
            "response_ratio": response_ratio,
        }
        metrics.update(ratios)
        threshold = _number(parameters, "ddos_tcp_flag_share_threshold")
        if syn_only_ratio >= threshold:
            if response_ratio is None:
                uncertainty.append("TCP_RESPONSE_VISIBILITY_UNKNOWN")
            elif response_ratio > _number(parameters, "ddos_response_ratio_max"):
                uncertainty.append("SUBSTANTIAL_TCP_RESPONSES_OBSERVED")
            return "TCP_SYN_FLOOD", metrics, uncertainty
        if ack_only_ratio >= threshold and fin_ratio <= 1 - threshold:
            if target.payload_visible and payload_ratio > 1 - threshold:
                return None
            ack_uncertainty = ["ACK_TRAFFIC_MAY_BE_LEGITIMATE"]
            if not target.payload_visible:
                ack_uncertainty.append("TCP_PAYLOAD_VISIBILITY_UNKNOWN")
            return "TCP_ACK_FLOOD", metrics, ack_uncertainty
        if rst_ratio >= threshold:
            return "TCP_RST_FLOOD", metrics, ["RESETS_MAY_BE_DEFENSIVE_RESPONSES"]
        return None
    if protocol == "UDP":
        reflection_ports = Counter(
            {port: count for port, count in target.source_ports.items() if port in REFLECTION_PORTS}
        )
        dominant_count = max(reflection_ports.values(), default=0)
        dominant_port = min(
            (port for port, count in reflection_ports.items() if count == dominant_count),
            default=None,
        )
        reflection_share = sum(reflection_ports.values()) / packets if packets else 0.0
        average_size = target.byte_count / max(1, packets)
        metrics.update(
            {
                "dominant_reflection_source_port": dominant_port,
                "reflection_source_port_ratio": reflection_share,
                "average_packet_bytes": round(average_size, 6),
                "amplification_ratio": None,
            }
        )
        if (
            target.role == "VICTIM_SIDE_INBOUND"
            and dominant_port in REFLECTION_PORTS
            and reflection_share >= _number(parameters, "ddos_reflection_port_share_threshold")
            and average_size >= _number(parameters, "ddos_reflection_min_average_packet_bytes")
        ):
            return (
                "POSSIBLE_REFLECTION_AMPLIFICATION",
                metrics,
                ["AMPLIFICATION_RATIO_UNOBSERVED", "SOURCE_SPOOFING_UNCONFIRMED"],
            )
        return "UDP_FLOOD", metrics, uncertainty
    if protocol in {"ICMP", "ICMPV6"}:
        observed = sum(target.icmp_types.values())
        echo_type = 8 if protocol == "ICMP" else 128
        echo = target.icmp_types.get(echo_type, 0)
        metrics["icmp_type_observed_packets"] = observed
        metrics["icmp_echo_request_ratio"] = echo / packets if packets else None
        if observed < packets:
            uncertainty.append("ICMP_TYPE_UNAVAILABLE")
        if packets and echo / packets >= _number(parameters, "ddos_protocol_share_threshold"):
            return "ICMP_ECHO_FLOOD", metrics, uncertainty
        return "ICMP_FLOOD", metrics, uncertainty
    return None


def _objective(attack_type: str, rates: Mapping[str, Any]) -> str:
    if attack_type == "TCP_SYN_FLOOD":
        return "CONNECTION_STATE_EXHAUSTION"
    if attack_type in {"TCP_ACK_FLOOD", "TCP_RST_FLOOD"}:
        return "PACKET_PROCESSING_EXHAUSTION"
    if attack_type == "POSSIBLE_REFLECTION_AMPLIFICATION":
        return "REFLECTED_BANDWIDTH_EXHAUSTION"
    if attack_type == "MULTI_VECTOR":
        return "MULTI_RESOURCE_EXHAUSTION"
    average_bytes = int(rates["byte_count"]) / max(1, int(rates["packet_count"]))
    return "PACKET_PROCESSING_EXHAUSTION" if average_bytes < 128 else "BANDWIDTH_EXHAUSTION"


def _recommendation_codes(attack_type: str, role: str) -> list[str]:
    codes: list[str] = list(_TYPE_RECOMMENDATIONS[attack_type])
    if role == "PARTICIPANT_SIDE_OUTBOUND":
        codes.extend(_OUTBOUND_RECOMMENDATIONS)
    codes.extend(_COMMON_RECOMMENDATIONS)
    return list(dict.fromkeys(codes))[:8]


def _stable_id(prefix: str, *parts: object) -> str:
    canonical = "|".join(str(part) for part in parts)
    return prefix + hashlib.sha256(canonical.encode()).hexdigest()[:16]


def _classification(attack_type: str, target: Target) -> dict[str, str]:
    identity_anomaly_ratio = target.identity_anomaly_records / max(
        1, target.identity_observed_records
    )
    spoofing_suspected = bool(target.identity_observed_records and identity_anomaly_ratio >= 0.20)
    if attack_type == "POSSIBLE_REFLECTION_AMPLIFICATION":
        return {
            "delivery_mechanism": "REFLECTION_AMPLIFICATION",
            "source_population": "REFLECTOR_SET",
            "source_authenticity": (
                "SPOOFING_SUSPECTED" if spoofing_suspected else "SPOOFING_UNCONFIRMED"
            ),
            "confidence": "medium",
        }
    if target.role == "PARTICIPANT_SIDE_OUTBOUND":
        return {
            "delivery_mechanism": "DIRECT_DISTRIBUTED",
            "source_population": "BOTNET_LIKE_COORDINATION",
            "source_authenticity": (
                "SPOOFING_SUSPECTED" if spoofing_suspected else "SOURCE_CONSISTENT"
            ),
            "confidence": "medium",
        }
    if spoofing_suspected:
        return {
            "delivery_mechanism": "DIRECT_DISTRIBUTED",
            "source_population": "DISTRIBUTED_UNATTRIBUTED",
            "source_authenticity": "SPOOFING_SUSPECTED",
            "confidence": "medium",
        }
    return {
        "delivery_mechanism": "DIRECT_DISTRIBUTED",
        "source_population": "DISTRIBUTED_UNATTRIBUTED",
        "source_authenticity": "SPOOFING_UNCONFIRMED",
        "confidence": "low",
    }


def _common_patterns(target: Target, attack_type: str) -> list[dict[str, object]]:
    patterns: list[dict[str, object]] = []

    def add(pattern_type: str, support_count: int, values: list[str]) -> None:
        patterns.append(
            {
                "id": _stable_id("ddos-pattern-", target.role, target.ip, pattern_type, *values),
                "type": pattern_type,
                "support_count": support_count,
                "support_ratio": min(1.0, support_count / max(1, target.record_count)),
                "values": values[:16],
            }
        )

    add("DESTINATION_CONVERGENCE", target.record_count, [target.ip, str(target.port)])
    if attack_type == "POSSIBLE_REFLECTION_AMPLIFICATION":
        ports = [
            str(port)
            for port, _ in sorted(target.source_ports.items(), key=lambda item: (-item[1], item[0]))
            if port in REFLECTION_PORTS
        ][:8]
        if ports:
            add(
                "REFLECTION_SERVICE_CONVERGENCE",
                sum(target.source_port_records[int(p)] for p in ports),
                ports,
            )
    if target.packet_sizes:
        values = [
            str(size)
            for size, _ in sorted(
                target.packet_sizes.items(), key=lambda item: (-item[1], item[0])
            )[:8]
        ]
        add("PACKET_SIZE_CLUSTER", target.packet_size_observed_records, values)
    if target.payload_prefix_hashes:
        values = [
            value
            for value, _ in sorted(
                target.payload_prefix_hashes.items(), key=lambda item: (-item[1], item[0])
            )[:8]
        ]
        add("PAYLOAD_PREFIX_CLUSTER", sum(target.payload_prefix_hashes.values()), values)
    if attack_type.startswith("TCP_"):
        add(attack_type.removesuffix("_FLOOD") + "_FLAG_DOMINANCE", target.record_count, [])
    if target.identity_anomaly_records:
        if target.hop_limit_min is not None and target.hop_limit_max is not None:
            add(
                "HOP_LIMIT_DIVERSITY",
                target.identity_anomaly_records,
                [str(target.hop_limit_min), str(target.hop_limit_max)],
            )
        if target.ip_id_transition_count:
            add(
                "IP_ID_INCONSISTENCY",
                target.identity_anomaly_records,
                [
                    str(target.ip_id_distinct_count),
                    str(target.ip_id_monotonic_transitions),
                    str(target.ip_id_transition_count),
                ],
            )
    return patterns[:8]


def _signature_candidates(
    target: Target,
    attack_type: str,
    classification: Mapping[str, str],
) -> list[dict[str, object]]:
    kind = (
        "REFLECTION_PROFILE"
        if attack_type == "POSSIBLE_REFLECTION_AMPLIFICATION"
        else "TRAFFIC_SHAPE"
    )
    source_ports = (
        sorted(port for port in target.source_ports if port in REFLECTION_PORTS)[:16]
        if kind == "REFLECTION_PROFILE"
        else []
    )
    packet_sizes = sorted(target.packet_sizes)
    signature: dict[str, object] = {
        "id": _stable_id("ddos-sig-", target.role, target.ip, target.port, attack_type, kind),
        "kind": kind,
        "protocol": target.protocol,
        "source_ports": source_ports,
        "destination_ports": [] if target.port is None else [target.port],
        "packet_size_range": ([packet_sizes[0], packet_sizes[-1]] if packet_sizes else None),
        "payload_prefix_hashes": [
            value
            for value, _ in sorted(
                target.payload_prefix_hashes.items(), key=lambda item: (-item[1], item[0])
            )[:8]
        ],
        "tcp_flag_profile": attack_type if attack_type.startswith("TCP_") else None,
        "confidence": classification["confidence"],
        "false_positive_codes": [
            "SOURCE_ADDRESSES_MAY_BE_SPOOFED"
            if classification["source_authenticity"] == "SPOOFING_SUSPECTED"
            else "DISTRIBUTED_TRAFFIC_MAY_HAVE_LEGITIMATE_CAUSES"
        ],
        "requires_human_approval": True,
    }
    signatures: list[dict[str, object]] = [signature]
    if target.identity_anomaly_records:
        signatures.append(
            {
                **signature,
                "id": _stable_id(
                    "ddos-sig-", target.role, target.ip, target.port, "SPOOFING_HEURISTIC"
                ),
                "kind": "SPOOFING_HEURISTIC",
                "source_ports": [],
                "payload_prefix_hashes": [],
                "tcp_flag_profile": None,
                "confidence": "medium",
                "false_positive_codes": ["MULTIPATH_OR_NAT_MAY_CHANGE_NETWORK_IDENTITY_FEATURES"],
            }
        )
    return signatures[:4]


def _finding(target: Target, parameters: Mapping[str, object]) -> dict[str, Any] | None:
    rates = _rates(target, parameters)
    shape = _shape(target, rates, parameters)
    if shape is None:
        return None
    attack_type, shape_metrics, uncertainty = shape
    packets = int(rates["packet_count"])
    duration = float(rates["duration_seconds"])
    pps = max(
        float(rates["average_packets_per_second"]),
        float(rates["peak_packets_per_second"] or 0),
    )
    bps = max(float(rates["average_bits_per_second"]), float(rates["peak_bits_per_second"] or 0))
    volume = (
        packets >= _number(parameters, "ddos_min_packet_count")
        and duration >= _number(parameters, "ddos_min_duration_seconds")
        and (
            pps >= _number(parameters, "ddos_min_packets_per_second")
            or bps >= _number(parameters, "ddos_min_bits_per_second")
        )
    )
    sources = len(target.sources)
    distributed = sources >= _number(parameters, "ddos_min_source_count")
    if not volume or not distributed:
        return None
    baseline_ratio, robust_z = rates["baseline_ratio"], rates["robust_z_score"]
    relative = (
        baseline_ratio is not None
        and float(baseline_ratio) >= _number(parameters, "ddos_baseline_ratio")
    ) or (robust_z is not None and float(robust_z) >= _number(parameters, "ddos_mad_z_threshold"))
    likelihood = (
        "LIKELY" if relative and attack_type != "POSSIBLE_REFLECTION_AMPLIFICATION" else "POSSIBLE"
    )
    if {
        "TCP_RESPONSE_VISIBILITY_UNKNOWN",
        "TCP_PAYLOAD_VISIBILITY_UNKNOWN",
        "SUBSTANTIAL_TCP_RESPONSES_OBSERVED",
    } & set(uncertainty):
        likelihood = "POSSIBLE"
    sample_limited = target.record_count < MIN_TARGET_RECORDS or duration < 10
    if sample_limited:
        likelihood = "POSSIBLE"
    if baseline_ratio is None and robust_z is None:
        uncertainty.append("BASELINE_UNAVAILABLE")
    if target.bucket_limited:
        uncertainty.append("BUCKET_LIMIT_REACHED")
    if target.first_seen is None or target.last_seen is None:
        return None
    first, last = target.first_seen, target.last_seen
    identity = f"{target.role}|{target.ip}|{target.port}|{target.protocol}|{attack_type}"
    metrics = {
        **rates,
        **shape_metrics,
        "distinct_sources": sources,
        "distinct_sensors": len(target.sensors),
        "record_count": target.record_count,
        "direction_source": (
            "OBSERVED" if target.direction_sources == {"OBSERVED"} else "INTERNAL_CIDR"
        ),
        "hop_limit_min": target.hop_limit_min,
        "hop_limit_max": target.hop_limit_max,
        "network_identity_observed_records": target.identity_observed_records,
        "network_identity_anomaly_records": target.identity_anomaly_records,
        "ip_id_observed_count": target.ip_id_observed_count,
        "ip_id_distinct_count": target.ip_id_distinct_count,
        "ip_id_monotonic_ratio": (
            target.ip_id_monotonic_transitions / target.ip_id_transition_count
            if target.ip_id_transition_count
            else None
        ),
        "network_identity_values_truncated": target.identity_values_truncated,
    }
    recommendations = _recommendation_codes(attack_type, target.role)
    classification = _classification(attack_type, target)
    if classification["source_population"] == "BOTNET_LIKE_COORDINATION":
        uncertainty.append("BOTNET_ATTRIBUTION_UNCONFIRMED")
    if classification["source_authenticity"] == "SPOOFING_SUSPECTED":
        uncertainty.append("SOURCE_SPOOFING_NOT_CONFIRMED")
    return {
        "id": "ddos-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
        "attack_type": attack_type,
        "attack_role": target.role,
        "target": {"ip": target.ip, "port": target.port},
        "protocol": target.protocol,
        "objective": _objective(attack_type, rates),
        "likelihood": likelihood,
        "severity": "HIGH" if likelihood == "LIKELY" else "MEDIUM",
        "confidence": "low" if sample_limited else "high" if likelihood == "LIKELY" else "medium",
        "first_seen": first.isoformat(),
        "last_seen": last.isoformat(),
        "metrics": metrics,
        "evidence_codes": [
            "VOLUME_GATE_MET",
            "DISTRIBUTED_SOURCE_GATE_MET",
            f"{attack_type}_SHAPE",
        ],
        "uncertainty_codes": list(dict.fromkeys(uncertainty))[:8],
        "recommendation_codes": recommendations,
        "classification": classification,
        "common_patterns": _common_patterns(target, attack_type),
        "signature_candidates": _signature_candidates(target, attack_type, classification),
    }


def _multi_vector(
    findings: list[dict[str, Any]], parameters: Mapping[str, object]
) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for item in findings:
        grouped[(item["attack_role"], item["target"]["ip"])].append(item)
    result: list[dict[str, Any]] = []
    overlap = _number(parameters, "ddos_overlap_window_seconds")
    for (role, target_ip), items in grouped.items():
        intervals = {
            item["id"]: (
                datetime.fromisoformat(item["first_seen"]),
                datetime.fromisoformat(item["last_seen"]),
            )
            for item in items
        }

        def gap(
            left: dict[str, Any],
            right: dict[str, Any],
            current_intervals: dict[str, tuple[datetime, datetime]] = intervals,
        ) -> float:
            left_start, left_end = current_intervals[left["id"]]
            right_start, right_end = current_intervals[right["id"]]
            difference = max(left_start, right_start) - min(left_end, right_end)
            return max(0.0, difference.total_seconds())

        selected: list[dict[str, Any]] | None = None
        selected_key: tuple[int, int, str, tuple[str, ...]] | None = None
        for anchor in items:
            subset = sorted(
                (item for item in items if gap(anchor, item) <= overlap),
                key=lambda item: item["id"],
            )
            if len({item["attack_type"] for item in subset}) >= 2:
                subset_key: tuple[int, int, str, tuple[str, ...]] = (
                    -len({item["attack_type"] for item in subset}),
                    -len(subset),
                    min(item["first_seen"] for item in subset),
                    tuple(item["id"] for item in subset),
                )
                if selected_key is None or subset_key < selected_key:
                    selected, selected_key = subset, subset_key
        if selected is None:
            continue
        types = {item["attack_type"] for item in selected}
        starts = [intervals[item["id"]][0] for item in selected]
        ends = [intervals[item["id"]][1] for item in selected]
        identity = f"{role}|{target_ip}|MULTI_VECTOR|{'|'.join(sorted(types))}"
        recommendations = _recommendation_codes("MULTI_VECTOR", role)
        all_likely = all(item["likelihood"] == "LIKELY" for item in selected)
        dimensions = {
            name: {item["classification"][name] for item in selected}
            for name in ("delivery_mechanism", "source_population", "source_authenticity")
        }
        multi_classification = {
            name: next(iter(values)) if len(values) == 1 else "MIXED"
            for name, values in dimensions.items()
        }
        multi_classification["confidence"] = (
            "low"
            if any(item["classification"]["confidence"] == "low" for item in selected)
            else "medium"
        )
        multi_uncertainty = ["SHARED_TARGET_DOES_NOT_PROVE_SHARED_ACTOR"]
        if multi_classification["source_population"] == "BOTNET_LIKE_COORDINATION":
            multi_uncertainty.append("BOTNET_ATTRIBUTION_UNCONFIRMED")
        if any(
            item["classification"]["source_authenticity"] == "SPOOFING_SUSPECTED"
            for item in selected
        ):
            multi_uncertainty.append("SOURCE_SPOOFING_NOT_CONFIRMED")
        common_patterns = list(
            {
                pattern["id"]: pattern for item in selected for pattern in item["common_patterns"]
            }.values()
        )[:8]
        signature_candidates = list(
            {
                signature["id"]: signature
                for item in selected
                for signature in item["signature_candidates"]
            }.values()
        )[:4]
        result.append(
            {
                "id": "ddos-" + hashlib.sha256(identity.encode()).hexdigest()[:16],
                "attack_type": "MULTI_VECTOR",
                "attack_role": role,
                "target": {"ip": target_ip, "port": None},
                "protocol": "MULTIPLE",
                "objective": "MULTI_RESOURCE_EXHAUSTION",
                "likelihood": "LIKELY" if all_likely else "POSSIBLE",
                "severity": "CRITICAL" if all_likely else "HIGH",
                "confidence": (
                    "high"
                    if all_likely
                    else "low"
                    if any(item["confidence"] == "low" for item in selected)
                    else "medium"
                ),
                "first_seen": min(starts).isoformat(),
                "last_seen": max(ends).isoformat(),
                "metrics": {
                    "component_types": sorted(types),
                    "component_finding_count": len(selected),
                },
                "evidence_codes": ["OVERLAPPING_ATTACK_VECTORS"],
                "uncertainty_codes": multi_uncertainty,
                "recommendation_codes": recommendations,
                "classification": multi_classification,
                "common_patterns": common_patterns,
                "signature_candidates": signature_candidates,
            }
        )
    return result


def _recommendations(codes: Iterable[str]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for priority, code in enumerate(dict.fromkeys(codes), 1):
        result.append(
            {
                "code": code,
                "priority": priority,
                "scope": (
                    "UPSTREAM"
                    if code in {"CONTACT_UPSTREAM_PROVIDER", "ENGAGE_SCRUBBING_OR_FLOWSPEC"}
                    else "LOCAL"
                ),
                "rationale_code": f"{code}_RATIONALE",
                "caveat_code": f"{code}_CAVEAT",
                "requires_human_approval": True,
            }
        )
    return result


def analyze_ddos_attack(
    records: Iterable[Mapping[str, object]],
    *,
    internal_cidrs: Sequence[object] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
    parameters: Mapping[str, object] | None = None,
    coverage_context: Mapping[str, object] | None = None,
) -> dict[str, Any]:
    """Classify bounded DDoS-shaped traffic and publish a deterministic report."""
    policy = _validated_policy(parameters)
    compiled_networks = _compile_networks(internal_cidrs)
    bucket_seconds = int(_number(policy, "ddos_bucket_seconds"))
    targets: dict[tuple[str, str, int | None, str], Target] = {}
    target_heap: list[tuple[int, int, int, int, int, tuple[str, str, int | None, str]]] = []
    reverse_syn_ack: dict[tuple[str, int | None], int] = {}
    response_heap: list[tuple[int, int, int, tuple[str, int | None]]] = []
    warnings: set[str] = set()
    context = dict(coverage_context or {})
    allowed_context = {
        "parser_skipped_packet_count",
        "sensor_dropped_packet_count",
        "sensor_clock_skew_detected",
        "sensor_capture_quality_unavailable",
        "capture_partial",
    }
    if not set(context) <= allowed_context:
        raise ValueError("unknown DDoS coverage context field")
    for field_name, warning in (
        ("parser_skipped_packet_count", "PARSER_SKIPPED_PACKETS"),
        ("sensor_dropped_packet_count", "SENSOR_DROPS_REPORTED"),
    ):
        value = context.get(field_name, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value >= 2**63:
            raise ValueError(f"invalid DDoS coverage field: {field_name}")
        if value > 0:
            warnings.add(warning)
    for field_name, warning in (
        ("sensor_clock_skew_detected", "SENSOR_CLOCK_SKEW"),
        ("sensor_capture_quality_unavailable", "SENSOR_CAPTURE_QUALITY_UNAVAILABLE"),
        ("capture_partial", "PARTIAL_CAPTURE"),
    ):
        value = context.get(field_name, False)
        if not isinstance(value, bool):
            raise ValueError(f"invalid DDoS coverage field: {field_name}")
        if value:
            warnings.add(warning)
    scanned = skipped = evaluated = incomplete = packet_total = byte_total = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    coverage_warnings = set(warnings)
    input_overflow = False
    numeric_overflow = False
    for entry in records:
        scanned += 1
        if scanned > MAX_SCANNED_RECORDS:
            input_overflow = True
            break
        try:
            row = _normalize(entry, compiled_networks)
        except InvalidRecord as error:
            skipped += 1
            warnings.add(
                "AMBIGUOUS_DIRECTION" if "ambiguous" in str(error) else "INCOMPLETE_RECORDS"
            )
            continue
        if numeric_overflow:
            continue
        if (
            packet_total + row.packets > MAX_REPORT_INTEGER
            or byte_total + row.size_bytes > MAX_REPORT_INTEGER
        ):
            numeric_overflow = True
            continue
        evaluated += 1
        packet_total += row.packets
        byte_total += row.size_bytes
        first_seen = min(first_seen, row.timestamp) if first_seen else row.timestamp
        row_end = row.timestamp + timedelta(seconds=row.duration)
        last_seen = max(last_seen, row_end) if last_seen else row_end
        if row.protocol == "TCP" and row.role == "PARTICIPANT_SIDE_OUTBOUND" and row.syn_ack > 0:
            candidate_response_key = (row.source, row.source_port)
            response_key: tuple[str, int | None] | None = candidate_response_key
            response_heap_inserted = False
            if response_key not in reverse_syn_ack and len(reverse_syn_ack) >= MAX_TARGETS:
                largest_response = response_heap[0][3]
                response_rank = _response_rank(candidate_response_key)
                largest_rank = _response_rank(largest_response)
                if response_rank < largest_rank:
                    reverse_syn_ack.pop(largest_response)
                    heapq.heapreplace(response_heap, _response_heap_entry(candidate_response_key))
                    response_heap_inserted = True
                else:
                    response_key = None
                if "TARGET_LIMIT_REACHED" not in warnings:
                    incomplete += 1
                warnings.add("TARGET_LIMIT_REACHED")
            if response_key is not None:
                if (
                    not response_heap_inserted
                    and response_key not in reverse_syn_ack
                    and len(reverse_syn_ack) < MAX_TARGETS
                ):
                    heapq.heappush(response_heap, _response_heap_entry(response_key))
                reverse_syn_ack[response_key] = reverse_syn_ack.get(response_key, 0) + row.syn_ack
        key = row.role, row.target, row.target_port, row.protocol
        target = targets.get(key)
        if target is None:
            if len(targets) >= MAX_TARGETS:
                if "TARGET_LIMIT_REACHED" not in warnings:
                    incomplete += 1
                warnings.add("TARGET_LIMIT_REACHED")
                largest = target_heap[0][5]
                if _target_rank(key) >= _target_rank(largest):
                    continue
                targets.pop(largest)
                heapq.heapreplace(target_heap, _target_heap_entry(key))
            else:
                heapq.heappush(target_heap, _target_heap_entry(key))
            target = targets[key] = Target(*key)
        omitted_records = _add_observation(target, row, bucket_seconds)
        if omitted_records:
            incomplete += omitted_records
            warnings.add("BUCKET_LIMIT_REACHED")

    if input_overflow or numeric_overflow:
        targets.clear()
        reverse_syn_ack.clear()
        target_heap.clear()
        response_heap.clear()
        skipped = evaluated = packet_total = byte_total = 0
        incomplete = 1
        first_seen = last_seen = None
        warnings = coverage_warnings | {
            "INPUT_RECORD_LIMIT_REACHED" if input_overflow else "INCOMPLETE_RECORDS"
        }

    for target in targets.values():
        response_key = (target.ip, target.port)
        if target.role == "VICTIM_SIDE_INBOUND" and response_key in reverse_syn_ack:
            target.response_visible = True
            target.syn_ack += reverse_syn_ack[response_key]
    findings = [item for target in targets.values() if (item := _finding(target, policy))]
    if not findings:
        for target in targets.values():
            if len(target.sources) < _number(
                policy, "ddos_min_source_count"
            ) and target.packet_count >= _number(policy, "ddos_min_packet_count"):
                warnings.add("DOS_LIKE_TRAFFIC")
    findings.extend(_multi_vector(findings, policy))
    total_findings = len(findings)
    findings.sort(
        key=lambda item: (
            _PRIORITY[item["attack_type"]],
            0 if item["likelihood"] == "LIKELY" else 1,
            item["target"]["ip"],
            -1 if item["target"]["port"] is None else item["target"]["port"],
            item["id"],
        )
    )
    if len(findings) > MAX_FINDINGS:
        findings = findings[:MAX_FINDINGS]
        warnings.add("FINDING_LIMIT_REACHED")
    for item in findings:
        if "BASELINE_UNAVAILABLE" in item["uncertainty_codes"]:
            warnings.add("BASELINE_UNAVAILABLE")
    short_sample = not targets or any(
        target.record_count < MIN_TARGET_RECORDS
        or (
            target.first_seen is not None
            and target.last_seen is not None
            and (target.last_seen - target.first_seen).total_seconds() < 10
        )
        for target in targets.values()
    )
    if short_sample:
        warnings.add("SAMPLE_WINDOW_SHORT")
    if any(len(target.sensors) > 1 for target in targets.values()):
        warnings.add("DUPLICATE_CAPTURE_NOT_EXCLUDED")
    lower_bound_warnings = {
        "INPUT_RECORD_LIMIT_REACHED",
        "TARGET_LIMIT_REACHED",
        "BUCKET_LIMIT_REACHED",
        "FINDING_LIMIT_REACHED",
        "PARSER_SKIPPED_PACKETS",
        "SENSOR_DROPS_REPORTED",
        "PARTIAL_CAPTURE",
    }
    coverage_qualifiers = lower_bound_warnings | {
        "SENSOR_CLOCK_SKEW",
        "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
        "DUPLICATE_CAPTURE_NOT_EXCLUDED",
    }
    counts_are_lower_bounds = bool(lower_bound_warnings & warnings) or skipped > 0 or incomplete > 0
    coverage_complete = (
        evaluated > 0 and skipped == 0 and incomplete == 0 and not coverage_qualifiers & warnings
    )
    evidence_limited = not coverage_complete
    if evidence_limited:
        for finding in findings:
            if finding["likelihood"] == "LIKELY":
                finding["likelihood"] = "POSSIBLE"
                finding["severity"] = (
                    "HIGH" if finding["attack_type"] == "MULTI_VECTOR" else "MEDIUM"
                )
            finding["confidence"] = "low"
    if any(item["likelihood"] == "LIKELY" for item in findings):
        verdict, confidence = "attack_likely", "high"
    elif findings:
        verdict = "suspicious_traffic"
        confidence = (
            "low"
            if evidence_limited or all(item["confidence"] == "low" for item in findings)
            else "medium"
        )
    elif (
        coverage_complete
        and "SAMPLE_WINDOW_SHORT" not in warnings
        and "DOS_LIKE_TRAFFIC" not in warnings
    ):
        verdict, confidence = "no_clear_attack", "low"
    else:
        verdict, confidence = "insufficient_evidence", "unknown"
    primary = findings[0] if findings else None
    codes = [code for item in findings for code in item["recommendation_codes"]]
    return {
        "version": REPORT_VERSION,
        "catalog_version": CATALOG_VERSION,
        "verdict": verdict,
        "confidence": confidence,
        "primary_finding_id": primary["id"] if primary else None,
        "summary": {
            "scanned_records": scanned,
            "evaluated_records": evaluated,
            "skipped_records": skipped,
            "incomplete_records": incomplete,
            "target_count": len(targets),
            "finding_count": total_findings,
            "displayed_finding_count": len(findings),
            "packet_count": packet_total,
            "byte_count": byte_total,
            "first_seen": first_seen.isoformat() if first_seen else None,
            "last_seen": last_seen.isoformat() if last_seen else None,
            "coverage_complete": coverage_complete,
            "counts_are_lower_bounds": counts_are_lower_bounds,
            "truncated": total_findings > len(findings) or counts_are_lower_bounds,
            "primary_attack_type": primary["attack_type"] if primary else None,
            "primary_objective": primary["objective"] if primary else None,
        },
        "findings": findings,
        "recommendations": _recommendations(codes),
        "warnings": sorted(warnings),
        "limitations": [
            "NO_FINDING_DOES_NOT_PROVE_HEALTH",
            "OBSERVED_SOURCES_ARE_NOT_CONFIRMED_ATTACKERS",
            "TRAFFIC_SHAPE_DOES_NOT_PROVE_SERVICE_IMPACT",
            "APPLICATION_LAYER_FLOODS_NOT_CLASSIFIED",
        ],
        "omitted_finding_count": total_findings - len(findings),
    }
