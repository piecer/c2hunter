from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field

from .domain import AnalysisContext, Flow

TCPConnectionKey = tuple[str, str, str, int | None, int | None]
FlowRow = tuple[str, Flow]


def _candidate_host(context: AnalysisContext, flow: Flow) -> tuple[str, str] | None:
    direction = flow.direction.upper()
    if direction == "OUTBOUND":
        return flow.destination_ip, flow.source_ip
    if direction == "INBOUND":
        return flow.source_ip, flow.destination_ip
    if context.is_internal(flow.source_ip) and not context.is_internal(flow.destination_ip):
        return flow.destination_ip, flow.source_ip
    if context.is_internal(flow.destination_ip) and not context.is_internal(flow.source_ip):
        return flow.source_ip, flow.destination_ip
    return None


def _raw_groups(context: AnalysisContext) -> dict[str, list[FlowRow]]:
    grouped: dict[str, list[FlowRow]] = defaultdict(list)
    for flow in context.scoped_flows():
        role = _candidate_host(context, flow)
        if role is not None:
            grouped[role[0]].append((role[1], flow))
    return grouped


def _normalized_direction(context: AnalysisContext, flow: Flow) -> str:
    direction = flow.direction.upper()
    if direction in {"OUTBOUND", "INBOUND"}:
        return direction
    source_internal = context.is_internal(flow.source_ip)
    destination_internal = context.is_internal(flow.destination_ip)
    if source_internal and not destination_internal:
        return "OUTBOUND"
    if destination_internal and not source_internal:
        return "INBOUND"
    return "UNKNOWN"


def _connection_key(context: AnalysisContext, flow: Flow) -> TCPConnectionKey | None:
    if flow.protocol.upper() != "TCP":
        return None
    role = _candidate_host(context, flow)
    if role is None:
        return None
    candidate, host = role
    direction = _normalized_direction(context, flow)
    if direction == "OUTBOUND":
        internal_port, service_port = flow.source_port, flow.destination_port
    elif direction == "INBOUND":
        internal_port, service_port = flow.destination_port, flow.source_port
    else:
        return None
    return flow.sensor_id, candidate, host, internal_port, service_port


@dataclass
class TCPConnectionProfile:
    rows: list[FlowRow] = field(default_factory=list)
    metadata_available: bool = False
    outbound_syn_only: int = 0
    inbound_syn_only: int = 0
    outbound_syn_ack: int = 0
    inbound_syn_ack: int = 0
    outbound_ack_only: int = 0
    inbound_ack_only: int = 0
    outbound_rst: int = 0
    inbound_rst: int = 0
    outbound_payload: bool = False
    inbound_payload: bool = False
    bidirectional: bool = False
    total_packets: int = 0

    def add(self, context: AnalysisContext, row: FlowRow) -> None:
        self.rows.append(row)
        flow = row[1]
        self.metadata_available = self.metadata_available or flow.tcp_flags_observed
        self.bidirectional = self.bidirectional or flow.bidirectional
        self.total_packets += max(0, flow.packet_count)
        direction = _normalized_direction(context, flow)
        has_payload = bool(flow.payload_hash or (flow.payload_length or 0) > 0)
        if direction == "OUTBOUND":
            self.outbound_syn_only += max(0, flow.tcp_syn_only_count)
            self.outbound_syn_ack += max(0, flow.tcp_syn_ack_count)
            self.outbound_ack_only += max(0, flow.tcp_ack_only_count)
            self.outbound_rst += max(0, flow.tcp_rst_count)
            self.outbound_payload = self.outbound_payload or has_payload
        elif direction == "INBOUND":
            self.inbound_syn_only += max(0, flow.tcp_syn_only_count)
            self.inbound_syn_ack += max(0, flow.tcp_syn_ack_count)
            self.inbound_ack_only += max(0, flow.tcp_ack_only_count)
            self.inbound_rst += max(0, flow.tcp_rst_count)
            self.inbound_payload = self.inbound_payload or has_payload

    @property
    def internally_initiated(self) -> bool:
        return self.outbound_syn_only > 0

    @property
    def established(self) -> bool:
        outbound_handshake = (
            self.outbound_syn_only > 0 and self.inbound_syn_ack > 0 and self.outbound_ack_only > 0
        )
        inbound_handshake = (
            self.inbound_syn_only > 0 and self.outbound_syn_ack > 0 and self.inbound_ack_only > 0
        )
        midstream_ack_exchange = self.outbound_ack_only > 0 and self.inbound_ack_only > 0
        payload_with_reply = self.bidirectional and (
            (self.outbound_payload and self.inbound_ack_only > 0)
            or (self.inbound_payload and self.outbound_ack_only > 0)
            or (self.outbound_payload and self.inbound_payload)
        )
        return (
            outbound_handshake or inbound_handshake or midstream_ack_exchange or payload_with_reply
        )

    @property
    def qualified(self) -> bool:
        return self.internally_initiated or self.established

    @property
    def outbound_syn_unanswered(self) -> bool:
        """An outbound SYN is present but neither the peer's SYN-ACK nor an
        outbound ACK ever completed the handshake.

        This is the signature of a connect() that never reached the remote
        endpoint (drop, firewall, or scan retry). It is deliberately distinct
        from ``scan_like``: a fully half-open handshake (SYN followed by a
        SYN-ACK) is still a live conversation, not an unanswered probe.
        """
        return (
            self.metadata_available
            and self.internally_initiated
            and self.inbound_syn_ack == 0
            and self.outbound_ack_only == 0
        )

    @property
    def scan_like(self) -> bool:
        return (
            self.metadata_available
            and self.inbound_syn_only > 0
            and not self.internally_initiated
            and not self.established
        )

    def external_connect_probe(self, maximum_packets: int) -> bool:
        return (
            self.metadata_available
            and self.inbound_syn_only > 0
            and not self.internally_initiated
            and self.total_packets <= maximum_packets
            and not self.outbound_payload
            and not self.inbound_payload
        )


def tcp_profiles(
    context: AnalysisContext,
) -> tuple[dict[str, list[FlowRow]], dict[str, dict[TCPConnectionKey, TCPConnectionProfile]]]:
    raw = _raw_groups(context)
    result: dict[str, dict[TCPConnectionKey, TCPConnectionProfile]] = {}
    for candidate, rows in raw.items():
        connections: dict[TCPConnectionKey, TCPConnectionProfile] = {}
        for row in rows:
            key = _connection_key(context, row[1])
            if key is None:
                continue
            connections.setdefault(key, TCPConnectionProfile()).add(context, row)
        result[candidate] = connections
    return raw, result


def scan_suppressed_keys(
    context: AnalysisContext,
    connections: Mapping[TCPConnectionKey, TCPConnectionProfile],
) -> set[TCPConnectionKey]:
    if not bool(context.parameters.get("tcp_scan_suppression_enabled", True)):
        return set()
    minimum_targets = max(2, int(context.parameters.get("tcp_scan_min_targets", 8)))
    maximum_packets = max(1, int(context.parameters.get("tcp_scan_probe_max_packets", 4)))
    minimum_ratio = max(
        0.0,
        min(1.0, float(context.parameters.get("tcp_scan_probe_ratio", 0.8))),
    )
    observed = {key: profile for key, profile in connections.items() if profile.metadata_available}
    probes = {
        key for key, profile in observed.items() if profile.external_connect_probe(maximum_packets)
    }
    targets = {key[2] for key in probes}
    if (
        len(targets) < minimum_targets
        or not observed
        or len(probes) / len(observed) < minimum_ratio
    ):
        return set()
    return probes


def qualified_candidate_groups(context: AnalysisContext) -> dict[str, list[FlowRow]]:
    raw, profiles = tcp_profiles(context)
    if not bool(context.parameters.get("tcp_session_gating_enabled", True)):
        return raw
    allow_legacy = bool(context.parameters.get("tcp_allow_legacy_without_flags", True))
    require_established = bool(context.parameters.get("tcp_require_established_outbound", False))
    grouped: dict[str, list[FlowRow]] = {}
    for candidate, rows in raw.items():
        connections = profiles.get(candidate, {})
        suppressed = scan_suppressed_keys(context, connections)
        selected: list[FlowRow] = []
        for row in rows:
            flow = row[1]
            if flow.protocol.upper() != "TCP":
                selected.append(row)
                continue
            key = _connection_key(context, flow)
            profile = connections.get(key) if key is not None else None
            if key in suppressed:
                continue
            if (
                require_established
                and profile is not None
                and profile.metadata_available
                and profile.outbound_syn_unanswered
            ):
                # Outbound SYN without a SYN-ACK or ACK: the connection never
                # completed, so this row contributes no session evidence.
                continue
            if profile is None:
                if allow_legacy and not flow.tcp_flags_observed:
                    selected.append(row)
            elif profile.metadata_available:
                if profile.qualified:
                    selected.append(row)
            elif allow_legacy:
                selected.append(row)
        if selected:
            grouped[candidate] = selected
    return grouped


def qualified_tcp_flow_ids(context: AnalysisContext) -> set[int]:
    if not bool(context.parameters.get("tcp_session_gating_enabled", True)):
        return {id(flow) for flow in context.scoped_flows() if flow.protocol.upper() == "TCP"}
    raw, profiles = tcp_profiles(context)
    allow_legacy = bool(context.parameters.get("tcp_allow_legacy_without_flags", True))
    require_established = bool(context.parameters.get("tcp_require_established_outbound", False))
    qualified: set[int] = set()
    for candidate, rows in raw.items():
        connections = profiles.get(candidate, {})
        suppressed = scan_suppressed_keys(context, connections)
        for row in rows:
            flow = row[1]
            if flow.protocol.upper() != "TCP":
                continue
            key = _connection_key(context, flow)
            if key in suppressed:
                continue
            profile = connections.get(key) if key is not None else None
            if (
                require_established
                and profile is not None
                and profile.metadata_available
                and profile.outbound_syn_unanswered
            ):
                continue
            if profile is None:
                if allow_legacy and not flow.tcp_flags_observed:
                    qualified.add(id(flow))
            elif (profile.metadata_available and profile.qualified) or (
                not profile.metadata_available and allow_legacy
            ):
                qualified.add(id(flow))
    return qualified
