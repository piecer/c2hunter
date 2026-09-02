from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import timedelta

from .domain import AnalysisContext, Flow

MINIMUM_CONTROL_FLOOD_PACKETS = 32
MINIMUM_CONTROL_FLOOD_RATE = 5


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


def _tcp_flag_count(flow: Flow, name: str) -> int:
    values: list[int] = []
    for key, value in (flow.tcp_flags or {}).items():
        if str(key).strip().lower() != name:
            continue
        try:
            values.append(max(0, int(value)))
        except (OverflowError, TypeError, ValueError):
            continue
    if values:
        return max(values)
    return max(
        0,
        {
            "syn": flow.tcp_syn_count,
            "ack": flow.tcp_ack_count,
            "rst": flow.tcp_rst_count,
        }.get(name, 0),
    )


def _payload_observed(flow: Flow) -> bool:
    return bool(
        flow.payload_hash
        or flow.last_payload_hash
        or flow.payload_prefix_hash
        or flow.payload_simhash
        or (flow.payload_length or 0) > 0
    )


def _control_packets(flow: Flow) -> int:
    packets = max(0, flow.packet_count)
    return min(
        packets,
        _tcp_flag_count(flow, "syn") + _tcp_flag_count(flow, "fin") + _tcp_flag_count(flow, "rst"),
    )


def outbound_control_flood_flow_ids(context: AnalysisContext, flows: Iterable[Flow]) -> set[int]:
    """Return only payload-free outbound TCP control rows from a proven flood.

    Classification is peer-local, but disposition is row-local: mixed UDP,
    inbound, acknowledged, and payload-bearing flows remain available to C2
    detectors. A rate is considered proven only by multiple timestamps or an
    explicit positive aggregate duration.
    """

    rows = list(flows)
    outbound_packets = 0
    inbound_packets = 0
    control_packets = 0
    acknowledged_packets = 0
    control_rows: list[Flow] = []
    first_observed = None
    last_observed = None
    rate_observations = 0
    explicit_duration = False
    invalid_duration = False
    for flow in rows:
        if flow.protocol.upper() != "TCP":
            continue
        packets = max(0, flow.packet_count)
        direction = _normalized_direction(context, flow)
        if direction == "INBOUND":
            inbound_packets += packets
            continue
        if direction != "OUTBOUND":
            continue
        outbound_packets += packets
        control = _control_packets(flow)
        control_packets += control
        acknowledged_packets += min(packets, _tcp_flag_count(flow, "ack"))
        if control <= 0:
            continue
        control_rows.append(flow)
        rate_observations += 1
        duration = flow.duration_seconds
        if not math.isfinite(duration) or not 0 <= duration <= 31_536_000:
            invalid_duration = True
            duration = 0
        started = flow.timestamp
        ended = started + timedelta(seconds=duration)
        explicit_duration = explicit_duration or duration > 0
        first_observed = started if first_observed is None else min(first_observed, started)
        last_observed = ended if last_observed is None else max(last_observed, ended)
    if outbound_packets <= 0 or not control_rows or invalid_duration:
        return set()
    if not explicit_duration and rate_observations < 2:
        return set()
    span = (last_observed - first_observed) if first_observed and last_observed else timedelta(0)
    span_microseconds = span // timedelta(microseconds=1)
    rate_met = span_microseconds == 0 or (
        control_packets * 1_000_000 >= MINIMUM_CONTROL_FLOOD_RATE * span_microseconds
    )
    flood = (
        control_packets >= MINIMUM_CONTROL_FLOOD_PACKETS
        and control_packets / outbound_packets >= 0.8
        and acknowledged_packets / outbound_packets <= 0.2
        and inbound_packets / outbound_packets <= 0.2
        and rate_met
    )
    if not flood:
        return set()
    return {
        id(flow)
        for flow in control_rows
        if not _payload_observed(flow)
        and _tcp_flag_count(flow, "ack") / max(1, flow.packet_count) <= 0.2
    }


def is_outbound_control_flood(context: AnalysisContext, flows: Iterable[Flow]) -> bool:
    return bool(outbound_control_flood_flow_ids(context, flows))
