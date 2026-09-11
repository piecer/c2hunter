"""Pattern-first capture observations; legacy measurement API remains separate.

The identification pass retains correlation facts, not packets or flow reports.
Only ranked suspect groups receive evidence prose and representative details.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from heapq import heappop, heappush
from ipaddress import ip_address
from typing import Literal, TypedDict

Record = Mapping[str, object]
MAX_TRACKED_FLOWS = 8192
MAX_FLOW_CORRELATIONS = 4096
MAX_TOTAL_CORRELATIONS = 131072
MAX_PENDING_QUOTES = 8192
MAX_FLOW_OBSERVATIONS = 16
EndpointKey = tuple[str, int | None]
FlowKey = tuple[str, int | None, str, EndpointKey, EndpointKey]
Verdict = Literal["anomaly_observed", "no_clear_anomaly", "insufficient_evidence"]
Pattern = Literal[
    "syn_retransmissions",
    "matched_resets",
    "data_retransmissions",
    "duplicate_acks",
    "icmp_errors",
    "udp_duplicate_candidates",
]


class Endpoint(TypedDict):
    ip: str
    port: int | None


class Scope(TypedDict):
    sensor_id: str
    interface_id: int | None
    protocol: str
    peer: Endpoint


class Example(TypedDict):
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    event_count: int
    facts: dict[str, int]


class Issue(TypedDict):
    id: str
    pattern: Pattern
    title: str
    severity: Literal["observation"]
    scope: Scope
    event_count: int
    affected_flow_count: int
    affected_host_count: int
    first_seen: str
    last_seen: str
    examples: list[Example]
    omitted_examples: int
    evidence: list[str]
    uncertainty: list[str]
    next_checks: list[str]


class Summary(TypedDict):
    verdict: Verdict
    narrative: str
    scanned_records: int
    skipped_records: int
    evaluated_records: int
    incomplete_records: int
    tracking_limited_records: int
    counts_are_lower_bounds: bool
    flow_count: int
    suspect_flow_count: int
    detailed_flow_count: int
    issue_count: int
    displayed_issue_count: int
    omitted_issue_count: int
    coverage_complete: bool
    truncated: bool


class Report(TypedDict):
    version: Literal["network-pattern-report-v1"]
    summary: Summary
    issues: list[Issue]
    flows: list[object]
    warnings: list[str]
    limitations: list[str]


@dataclass(slots=True)
class Observation:
    count: int
    first: float
    last: float
    facts: tuple[int | None, ...]


DataKey = tuple[int, int, str]


@dataclass(slots=True)
class TCPDirection:
    seen: set[DataKey] = field(default_factory=set)
    outstanding: set[DataKey] = field(default_factory=set)
    starts: list[tuple[int, DataKey]] = field(default_factory=list)
    ends: list[tuple[int, DataKey]] = field(default_factory=list)
    last_ack: tuple[int, int, int] | None = None

    def acknowledge(self, ack: int) -> bool:
        while self.ends and self.ends[0][0] <= ack:
            _, identity = heappop(self.ends)
            self.outstanding.discard(identity)
        while self.starts and self.starts[0][1] not in self.outstanding:
            heappop(self.starts)
        return bool(self.starts and -self.starts[0][0] >= ack)


@dataclass(slots=True)
class Budget:
    correlations: int = 0


class TrackingLimit(Exception):
    pass


@dataclass(slots=True)
class Flow:
    budget: Budget
    limited: bool = False
    directions: set[int] = field(default_factory=set)
    tcp: tuple[TCPDirection, TCPDirection] = field(
        default_factory=lambda: (TCPDirection(), TCPDirection())
    )
    udp: set[tuple[int, int, str]] = field(default_factory=set)
    syn: dict[tuple[int, int], float] = field(default_factory=dict)
    last_time: float | None = None
    clock_invalid: bool = False
    observations: dict[tuple[Pattern, EndpointKey], Observation] = field(default_factory=dict)

    def clear_correlations(self) -> None:
        self.clear_tcp()
        self.budget.correlations -= len(self.udp)
        self.udp.clear()

    def clear_tcp(self) -> None:
        self.budget.correlations -= sum(len(d.seen) for d in self.tcp)
        self.syn.clear()
        self.tcp = TCPDirection(), TCPDirection()

    def reserve(self) -> None:
        size = len(self.udp) + sum(len(d.seen) for d in self.tcp)
        if size >= MAX_FLOW_CORRELATIONS or self.budget.correlations >= MAX_TOTAL_CORRELATIONS:
            raise TrackingLimit
        self.budget.correlations += 1

    def observe(self, pattern: Pattern, peer: EndpointKey, time: float, record: Record) -> None:
        key = pattern, peer
        previous = self.observations.get(key)
        if previous is None:
            facts = tuple(
                value if type(value := record.get(name)) is int and 0 <= value < ceiling else None
                for name, ceiling in zip(_FACT_FIELDS, _FACT_CEILINGS, strict=True)
            )
            self.observations[key] = Observation(1, time, time, facts)
        else:
            previous.count += 1
            previous.first = min(previous.first, time)
            previous.last = max(previous.last, time)


_FACT_FIELDS = (
    "tcp_sequence",
    "tcp_acknowledgment",
    "tcp_window",
    "transport_payload_length",
    "icmp_type",
    "icmp_code",
)
_FACT_CEILINGS = (2**32, 2**32, 65536, 65536, 256, 256)

GroupKey = tuple[str, int | None, str, Pattern, EndpointKey]


@dataclass(slots=True)
class Group:
    count: int = 0
    flows: int = 0
    hosts: set[str] = field(default_factory=set)
    first: float = float("inf")
    last: float = float("-inf")
    examples: list[tuple[FlowKey, Observation]] = field(default_factory=list)


_TITLES: dict[Pattern, str] = {
    "syn_retransmissions": "Repeated TCP SYN attempts",
    "matched_resets": "TCP resets matched to SYN attempts",
    "data_retransmissions": "Exact TCP data repeats",
    "duplicate_acks": "Duplicate TCP ACKs with outstanding data",
    "icmp_errors": "Observed ICMP errors",
    "udp_duplicate_candidates": "UDP duplicate candidates",
}


# Pattern-specific interpretation is deliberately separate from packet correlation.
_DIAGNOSTICS: dict[Pattern, tuple[str, str, str]] = {
    "syn_retransmissions": (
        "The same directional SYN sequence was observed again before a matching response.",
        "Repeated attempts do not distinguish a missing response from duplicate capture.",
        "Inspect handshake response visibility, listener state and firewall logs.",
    ),
    "matched_resets": (
        "A reverse RST+ACK acknowledgment matched an observed SYN sequence plus one.",
        "A matched reset suggests refusal of this attempt, not proof of a host outage.",
        "Check listener availability, service policy and reset-origin logs.",
    ),
    "data_retransmissions": (
        "TCP sequence, payload length and payload hash repeated in the same direction.",
        "Exact repeats do not prove path loss; capture duplication remains possible.",
        "Compare sequence/ACK progress with peer captures and retransmission counters.",
    ),
    "duplicate_acks": (
        "Repeated pure ACK sequence/acknowledgment/window signatures accompanied outstanding data.",
        "Reordering and duplicated capture can also produce duplicate ACK observations.",
        "Inspect missing sequence ranges, reordering and subsequent ACK progress.",
    ),
    "udp_duplicate_candidates": (
        "Directional UDP payload hash and length repeated within a capture-local flow epoch.",
        "Application retries or intentional repeats are not UDP transport retransmissions.",
        "Inspect application request identifiers and expected retry/heartbeat behavior.",
    ),
    "icmp_errors": (
        "ICMP errors were observed; valid quoted endpoints scope the affected peer when present.",
        "An ICMP report is not proof of permanent unreachability or a common root cause.",
        "Inspect original ICMP type/code, quoted headers and reporting-device policy.",
    ),
}


def _details(
    flows: dict[FlowKey, Flow], max_issues: int, max_examples: int
) -> tuple[list[Issue], int, int]:
    # Stage two visits only numeric candidate observations. Prose and endpoint
    # DTOs are materialized only for retained groups and suspect examples.
    from heapq import nsmallest

    groups: dict[GroupKey, Group] = {}
    for fkey, flow in flows.items():
        for (pattern, peer), observation in flow.observations.items():
            group_key = fkey[0], fkey[1], fkey[2], pattern, peer
            group = groups.get(group_key)
            if group is None:
                group = groups[group_key] = Group()
            group.count += observation.count
            group.flows += 1
            group.hosts.update((fkey[3][0], fkey[4][0]))
            group.first = min(group.first, observation.first)
            group.last = max(group.last, observation.last)
            if len(group.examples) < max_examples:
                group.examples.append((fkey, observation))
    selected = nsmallest(max_issues, groups, key=lambda k: (-groups[k].count, repr(k)))
    issues: list[Issue] = []
    detailed: set[FlowKey] = set()
    for index, key in enumerate(selected):
        group = groups[key]
        examples: list[Example] = []
        for flow_key, observation in group.examples:
            detailed.add(flow_key)
            examples.append(
                {
                    "endpoint_a": {"ip": flow_key[3][0], "port": flow_key[3][1]},
                    "endpoint_b": {"ip": flow_key[4][0], "port": flow_key[4][1]},
                    "event_count": observation.count,
                    "facts": {
                        name: value
                        for name, value in zip(_FACT_FIELDS, observation.facts, strict=True)
                        if value is not None
                    },
                }
            )
        issues.append(
            {
                "id": f"pattern-{index + 1}",
                "pattern": key[3],
                "title": _TITLES[key[3]],
                "severity": "observation",
                "scope": {
                    "sensor_id": key[0],
                    "interface_id": key[1],
                    "protocol": key[2],
                    "peer": {"ip": key[4][0], "port": key[4][1]},
                },
                "event_count": group.count,
                "affected_flow_count": group.flows,
                "affected_host_count": len(group.hosts),
                "first_seen": datetime.fromtimestamp(group.first, UTC).isoformat(),
                "last_seen": datetime.fromtimestamp(group.last, UTC).isoformat(),
                "examples": examples,
                "omitted_examples": group.flows - len(examples),
                "evidence": [
                    f"{group.count} {key[3]} observations across {group.flows} flows.",
                    _DIAGNOSTICS[key[3]][0],
                ],
                "uncertainty": [
                    _DIAGNOSTICS[key[3]][1],
                    "Shared peer and pattern do not establish a shared root cause.",
                ],
                "next_checks": [
                    _DIAGNOSTICS[key[3]][2],
                    "Check capture completeness and duplicate capture.",
                ],
            }
        )
    return issues, len(groups), len(detailed)


def _scan_tcp(record: Record, flow: Flow, direction: int, key: FlowKey, time: float) -> None:
    flags = record.get("tcp_flags")
    seq, ack = record.get("tcp_sequence"), record.get("tcp_acknowledgment")
    if not isinstance(flags, Mapping) or type(seq) is not int or type(ack) is not int:
        return
    source, dest = (key[3], key[4]) if direction == 0 else (key[4], key[3])
    if flags.get("syn") and not flags.get("ack") and not flags.get("rst"):
        identity = direction, seq
        if identity in flow.syn:
            flow.observe("syn_retransmissions", dest, time, record)
        else:
            flow.clear_tcp()
            flow.syn[identity] = time
    if flags.get("ack") and (flags.get("syn") or flags.get("rst")):
        match = flow.syn.pop((1 - direction, (ack - 1) % 2**32), None)
        if match is not None and flags.get("rst"):
            flow.observe("matched_resets", source, time, record)
    own, reverse = flow.tcp[direction], flow.tcp[1 - direction]
    length, window, digest = (
        record.get("transport_payload_length"),
        record.get("tcp_window"),
        record.get("payload_hash"),
    )
    control = any(flags.get(f) for f in ("syn", "fin", "rst", "urg"))
    if type(length) is int and type(window) is int:
        if flags.get("ack") and not control:
            outstanding = reverse.acknowledge(ack)
            signature = seq, ack, window
            if length == 0 and window > 0 and outstanding and own.last_ack == signature:
                flow.observe("duplicate_acks", source, time, record)
            own.last_ack = signature if length == 0 else None
        else:
            own.last_ack = None
        if length > 0 and not control and isinstance(digest, str) and digest:
            data_key = seq, length, digest
            if data_key in own.seen:
                flow.observe("data_retransmissions", dest, time, record)
            else:
                flow.reserve()
                own.seen.add(data_key)
                own.outstanding.add(data_key)
                heappush(own.starts, (-seq, data_key))
                heappush(own.ends, (seq + length, data_key))
    if flags.get("rst") or flags.get("fin"):
        flow.clear_tcp()


def _endpoint(ip: object, port: object) -> EndpointKey:
    if not isinstance(ip, str) or len(ip) > 45 or "%" in ip:
        raise ValueError("invalid IP")
    ip_address(ip)
    if port is not None and (type(port) is not int or not 0 <= port <= 65535):
        raise ValueError("invalid port")
    return ip, port


def _identity(record: Record) -> tuple[FlowKey, int, float]:
    sensor, interface, protocol = (
        record.get("sensor_id"),
        record.get("capture_interface_id"),
        record.get("protocol"),
    )
    if not isinstance(sensor, str) or not 1 <= len(sensor) <= 256:
        raise ValueError("invalid sensor")
    if not isinstance(protocol, str) or not 1 <= len(protocol) <= 32:
        raise ValueError("invalid protocol")
    if interface is not None and (type(interface) is not int or not 0 <= interface < 2**32):
        raise ValueError("invalid interface")
    source = _endpoint(record.get("source_ip"), record.get("source_port"))
    dest = _endpoint(record.get("destination_ip"), record.get("destination_port"))
    a, b = sorted((source, dest), key=lambda e: (e[0], -1 if e[1] is None else e[1]))
    timestamp = record.get("timestamp")
    if isinstance(timestamp, str):
        if len(timestamp) > 64:
            raise ValueError("invalid timestamp length")
        timestamp = datetime.fromisoformat(timestamp)
    if not isinstance(timestamp, datetime):
        raise ValueError("invalid timestamp")
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    seconds = timestamp.timestamp()
    if not -62135596800 <= seconds <= 253402300799:
        raise ValueError("timestamp outside publication range")
    for name, default in (("packet_count", 1), ("total_bytes", 0)):
        value = record.get(name, default)
        if type(value) is not int or not 0 <= value < 2**63:
            raise ValueError("invalid counter")
    return (sensor, interface, protocol.upper(), a, b), int(source != a), seconds


def _complete(record: Record, protocol: str) -> bool:
    if record.get("packet_evidence_complete") is not True or record.get("packet_count", 1) != 1:
        return False
    if protocol in {"TCP", "UDP"}:
        length = record.get("transport_payload_length")
        if type(length) is not int or not 0 <= length <= 65535:
            return False
        digest = record.get("payload_hash")
        if digest is not None and (not isinstance(digest, str) or len(digest) > 256):
            return False
        if length > 0 and (not isinstance(digest, str) or not 1 <= len(digest) <= 256):
            return False
    if protocol == "TCP":
        flags = record.get("tcp_flags")
        if not isinstance(flags, Mapping) or any(
            type(flags.get(name)) not in (int, bool) or flags.get(name) not in (0, 1)
            for name in ("syn", "ack", "fin", "rst", "urg")
        ):
            return False
        for name, ceiling in (
            ("tcp_sequence", 2**32),
            ("tcp_acknowledgment", 2**32),
            ("tcp_window", 65536),
        ):
            value = record.get(name)
            if type(value) is not int or not 0 <= value < ceiling:
                return False
    if protocol in {"ICMP", "ICMPV6"}:
        for name in ("icmp_type", "icmp_code"):
            value = record.get(name)
            if type(value) is not int or not 0 <= value <= 255:
                return False
    return protocol in {"TCP", "UDP", "ICMP", "ICMPV6"}


def analyze_network_report(
    records: Iterable[Record], *, max_issues: int = 20, max_examples: int = 3
) -> Report:
    """Consume every record once; explicitly report incomplete bounded tracking."""
    if type(max_issues) is not int or not 1 <= max_issues <= 100:
        raise ValueError("max_issues must be between 1 and 100")
    if type(max_examples) is not int or not 1 <= max_examples <= 10:
        raise ValueError("max_examples must be between 1 and 10")
    flows: dict[FlowKey, Flow] = {}
    quoted: dict[tuple[FlowKey, FlowKey], Flow] = {}
    budget = Budget()
    scanned = skipped = incomplete = evaluated = 0
    limited = 0
    warnings: set[str] = set()
    for record in records:
        scanned += 1
        try:
            key, direction, time = _identity(record)
        except (KeyError, TypeError, ValueError, OverflowError, AttributeError):
            skipped += 1
            warnings.add("INCOMPLETE_RECORDS")
            continue
        flow = flows.get(key)
        if flow is None:
            if len(flows) >= MAX_TRACKED_FLOWS:
                incomplete += 1
                limited += 1
                warnings.add("FLOW_TRACKING_LIMIT_REACHED")
                continue
            flow = flows[key] = Flow(budget)
        if flow.limited:
            incomplete += 1
            limited += 1
            continue
        flow.directions.add(direction)
        if not _complete(record, key[2]):
            incomplete += 1
            warnings.add("INCOMPLETE_PACKET_EVIDENCE")
            flow.clear_correlations()
            continue
        if flow.last_time is not None and time < flow.last_time:
            flow.clock_invalid = True
        if flow.clock_invalid:
            incomplete += 1
            warnings.add("NON_MONOTONIC_TIMESTAMPS")
            flow.clear_correlations()
            continue
        if flow.last_time is not None and time - flow.last_time > 60:
            flow.clear_correlations()
        flow.last_time = time
        evaluated += 1
        if key[2] == "TCP":
            try:
                _scan_tcp(record, flow, direction, key, time)
            except TrackingLimit:
                flow.limited = True
        elif key[2] == "UDP":
            length, digest = record.get("transport_payload_length"), record.get("payload_hash")
            if type(length) is int and isinstance(digest, str) and digest:
                identity = direction, length, digest
                if identity in flow.udp:
                    flow.observe(
                        "udp_duplicate_candidates",
                        key[4] if direction == 0 else key[3],
                        time,
                        record,
                    )
                else:
                    try:
                        flow.reserve()
                        flow.udp.add(identity)
                    except TrackingLimit:
                        flow.limited = True
        elif key[2] in {"ICMP", "ICMPV6"} and record.get("icmp_error"):
            quote = record.get("icmp_quoted_flow")
            target, peer = flow, key[3] if direction == 0 else key[4]
            if isinstance(quote, Mapping):
                try:
                    qa = _endpoint(quote.get("source_ip"), quote.get("source_port"))
                    qb = _endpoint(quote.get("destination_ip"), quote.get("destination_port"))
                    a, b = sorted((qa, qb), key=lambda e: (e[0], -1 if e[1] is None else e[1]))
                    protocol = quote.get("protocol")
                    if (
                        isinstance(protocol, str)
                        and len(protocol) <= 6
                        and protocol.upper() in {"TCP", "UDP", "ICMP", "ICMPV6"}
                    ):
                        quoted_key = (key[0], key[1], protocol.upper(), a, b), key
                        pending_flow = quoted.get(quoted_key)
                        if pending_flow is None:
                            if len(quoted) >= MAX_PENDING_QUOTES:
                                evaluated -= 1
                                incomplete += 1
                                limited += 1
                                warnings.add("ICMP_QUOTE_LIMIT_REACHED")
                                continue
                            pending_flow = quoted[quoted_key] = Flow(budget)
                        target = pending_flow
                        peer = qb
                    else:
                        raise ValueError("invalid quoted protocol")
                except (TypeError, ValueError):
                    warnings.add("INCOMPLETE_ICMP_QUOTE")
            target.observe("icmp_errors", peer, time, record)
        if flow.limited:
            flow.clear_correlations()
            evaluated -= 1
            incomplete += 1
            limited += 1
            warnings.add("CORRELATION_LIMIT_REACHED")
    # Resolve quotes after identification so report scope never depends on whether
    # the quoted transport flow preceded the ICMP record. Each error counted once.
    for (target_key, origin_key), pending in quoted.items():
        target = flows.get(target_key, flows[origin_key])
        for observation_key, observation in pending.observations.items():
            previous = target.observations.get(observation_key)
            if previous is None:
                if len(target.observations) >= MAX_FLOW_OBSERVATIONS:
                    evaluated -= observation.count
                    incomplete += observation.count
                    limited += observation.count
                    warnings.add("OBSERVATION_LIMIT_REACHED")
                    continue
                target.observations[observation_key] = observation
            else:
                previous.count += observation.count
                previous.first = min(previous.first, observation.first)
                previous.last = max(previous.last, observation.last)
    if any(len(f.directions) < 2 for f in flows.values()):
        warnings.add("ONE_DIRECTION_OBSERVED")
    complete = bool(evaluated) and not warnings
    issues, total, detailed = _details(flows, max_issues, max_examples)
    verdict: Verdict = (
        "anomaly_observed" if total else "no_clear_anomaly" if complete else "insufficient_evidence"
    )
    narrative = (
        "Supported observable patterns identified; inspect grouped evidence."
        if total
        else "No supported anomaly pattern observed."
        if complete
        else "Evidence is insufficient to exclude anomaly patterns."
    )
    if not complete and total:
        narrative += " Coverage is incomplete; additional patterns may be unobservable."
    return {
        "version": "network-pattern-report-v1",
        "summary": {
            "verdict": verdict,
            "narrative": narrative,
            "scanned_records": scanned,
            "skipped_records": skipped,
            "evaluated_records": evaluated,
            "incomplete_records": incomplete,
            "tracking_limited_records": limited,
            "counts_are_lower_bounds": bool(limited),
            "flow_count": len(flows),
            "suspect_flow_count": sum(bool(f.observations) for f in flows.values()),
            "detailed_flow_count": detailed,
            "issue_count": total,
            "displayed_issue_count": len(issues),
            "omitted_issue_count": total - len(issues),
            "coverage_complete": complete,
            "truncated": total > len(issues) or bool(limited),
        },
        "issues": issues,
        "flows": [],
        "warnings": sorted(warnings),
        "limitations": [
            "Single-vantage observations do not prove loss, asymmetric routing or root cause.",
            "Duplicate capture can mimic TCP retransmissions and UDP duplicate candidates.",
            "RTT and interarrival dispersion are not classified without a configured baseline.",
        ],
    }
