"""Capture-local network observations, independent of C2 suspicion scoring.

Consumes existing parser packet records before aggregation. See NETWORK_ANOMALY.md.
Never infer packet loss, route bypass or host RTT from capture visibility alone.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from datetime import datetime
from ipaddress import ip_address
from statistics import pstdev
from typing import Any

_COUNTERS = (
    "syn_retransmissions",
    "data_retransmissions",
    "duplicate_acks",
    "matched_resets",
    "udp_duplicate_candidates",
    "icmp_errors",
)
_DIRECTIONS = ("a_to_b", "b_to_a")


def _stats(values: list[float]) -> dict[str, Any]:
    return {
        "count": len(values),
        "min": min(values) if values else None,
        "max": max(values) if values else None,
        "mean": round(sum(values) / len(values), 6) if values else None,
    }


def _tcp_data(
    record: Mapping[str, Any],
    state: dict[str, Any],
    metrics: dict[str, Any],
    direction: int,
    time: float,
) -> None:
    flags = record.get("tcp_flags") or {}
    seq, ack = record["tcp_sequence"], record["tcp_acknowledgment"]
    length = record.get("transport_payload_length")
    if not isinstance(length, int):
        state["warnings"].add("INCOMPLETE_PACKET_EVIDENCE")
        return
    own, reverse = state["data"][direction], state["data"][1 - direction]
    control = any(flags.get(f) for f in ("syn", "fin", "rst", "urg"))
    if flags.get("ack") and not control:
        signature = (seq, ack, record.get("tcp_window"))
        outstanding = any(not v["acked"] and k[0] >= ack for k, v in reverse.items())
        if (
            length == 0
            and isinstance(signature[2], int)
            and signature[2] > 0
            and outstanding
            and state["last_ack"][direction] == signature
        ):
            metrics["duplicate_acks"] += 1
        state["last_ack"][direction] = signature if length == 0 else None
        covered = [(k, v) for k, v in reverse.items() if not v["acked"] and k[0] + k[1] <= ack]
        if len(covered) == 1:
            k, v = covered[0]
            if k[0] + k[1] == ack and not v["ambiguous"] and time > v["time"]:
                state["rtt"].append(round((time - v["time"]) * 1000, 6))
        for _, value in covered:
            value["acked"] = True
    else:
        state["last_ack"][direction] = None
    if length > 0 and not control and record.get("payload_hash"):
        identity = (seq, length, record["payload_hash"])
        if identity in own:
            metrics["data_retransmissions"] += 1
            own[identity]["ambiguous"] = True
        else:
            overlapping = [v for k, v in own.items() if seq < k[0] + k[1] and seq + length > k[0]]
            for value in overlapping:
                value["ambiguous"] = True
            own[identity] = {
                "time": time,
                "acked": False,
                "ambiguous": bool(overlapping) or seq + length >= 2**32,
            }


def analyze_network_anomalies(
    records: Iterable[Mapping[str, Any]],
    *,
    max_packets: int = 100_000,
    max_flows: int = 1000,
) -> dict[str, Any]:
    """Return bounded, JSON-safe per-bidirectional-flow observations.

    Limits may be lowered by the caller but cannot exceed the parser's two-million
    packet ceiling or 1000 output flows. Ordering follows capture order.
    """
    if type(max_packets) is not int or not 1 <= max_packets <= 2_000_000:
        raise ValueError("max_packets must be between 1 and 2000000")
    if type(max_flows) is not int or not 1 <= max_flows <= 1000:
        raise ValueError("max_flows must be between 1 and 1000")
    groups: dict[tuple[Any, ...], dict[str, Any]] = {}
    states: dict[tuple[Any, ...], dict[str, Any]] = {}
    warnings: set[str] = set()
    quoted_errors: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
    scanned = skipped = 0
    for record in records:
        if scanned >= max_packets:
            warnings.add("PACKET_LIMIT_REACHED")
            break
        scanned += 1
        try:
            if not isinstance(record, Mapping):
                raise ValueError("record must be a mapping")
            sensor = str(record["sensor_id"])
            source = (str(record["source_ip"]), record.get("source_port"))
            destination = (str(record["destination_ip"]), record.get("destination_port"))
            protocol = str(record["protocol"]).upper()
            if not sensor or len(sensor) > 256 or len(protocol) > 32:
                raise ValueError("invalid identifier")
            for endpoint in (source, destination):
                ip_address(endpoint[0])
                if endpoint[1] is not None and (
                    type(endpoint[1]) is not int or not 0 <= endpoint[1] <= 65535
                ):
                    raise ValueError("invalid port")
            packet_count, byte_count = record.get("packet_count", 1), record.get("total_bytes", 0)
            if any(
                type(v) is not int or not 0 <= v <= 2**63 - 1 for v in (packet_count, byte_count)
            ):
                raise ValueError("invalid counters")
            timestamp = record["timestamp"]
            if not isinstance(timestamp, datetime):
                timestamp = datetime.fromisoformat(timestamp)
            time = timestamp.timestamp()
            a, b = sorted((source, destination), key=lambda e: (e[0], e[1] or 0))
            interface = record.get("capture_interface_id")
            if interface is not None and (
                type(interface) is not int or not 0 <= interface <= 2**32 - 1
            ):
                raise ValueError("invalid interface")
            key = (sensor, interface, protocol, a, b)
            hash(key)
        except (KeyError, TypeError, ValueError, OverflowError):
            skipped += 1
            warnings.add("INCOMPLETE_RECORDS")
            continue
        if key not in groups:
            if len(groups) >= max_flows:
                skipped += 1
                warnings.add("FLOW_LIMIT_REACHED")
                continue
            groups[key] = {
                "sensor_id": sensor,
                "interface_id": interface,
                "protocol": protocol,
                "endpoint_a": {"ip": a[0], "port": a[1]},
                "endpoint_b": {"ip": b[0], "port": b[1]},
                "observed_directions": {d: {"packets": 0, "bytes": 0} for d in _DIRECTIONS},
                "metrics": {**dict.fromkeys(_COUNTERS, 0), "icmp_error_details": []},
                "warnings": [],
            }
            states[key] = {
                "syn": {},
                "rtt": [],
                "warnings": set(),
                "data": [{}, {}],
                "last_ack": [None, None],
                "udp": set(),
                "last_time": [None, None],
                "intervals": [[], []],
                "ttl": [[], []],
            }
        flow, state = groups[key], states[key]
        direction = 0 if source == a else 1
        counts = flow["observed_directions"][_DIRECTIONS[direction]]
        counts["packets"] += packet_count
        counts["bytes"] += byte_count
        if record.get("packet_evidence_complete") is not True or packet_count != 1:
            state["warnings"].add("INCOMPLETE_PACKET_EVIDENCE")
            state["last_time"][direction] = None
            state["data"] = [{}, {}]
            state["syn"].clear()
            state["udp"].clear()
            state["last_ack"] = [None, None]
            continue
        if any(t is not None and time < t for t in state["last_time"]):
            state["warnings"].add("NON_MONOTONIC_TIMESTAMPS")
        if "NON_MONOTONIC_TIMESTAMPS" in state["warnings"]:
            continue
        previous = state["last_time"][direction]
        latest = max((t for t in state["last_time"] if t is not None), default=time)
        if time - latest > 60:
            state["data"] = [{}, {}]
            state["syn"].clear()
            state["udp"].clear()
            state["last_ack"] = [None, None]
        if previous is not None and time >= previous:
            state["intervals"][direction].append(round((time - previous) * 1000, 6))
        state["last_time"][direction] = time
        ttl = record.get("ip_ttl")
        if isinstance(ttl, int) and 0 <= ttl <= 255:
            state["ttl"][direction].append(ttl)
        if (len(state["syn"]) + len(state["udp"]) + sum(len(d) for d in state["data"])) >= 256:
            state["warnings"].add("FLOW_STATE_LIMIT_REACHED")
        if "FLOW_STATE_LIMIT_REACHED" in state["warnings"]:
            continue
        if protocol == "TCP":
            flags = record.get("tcp_flags") or {}
            seq, ack = record.get("tcp_sequence"), record.get("tcp_acknowledgment")
            window, length = record.get("tcp_window"), record.get("transport_payload_length")
            if (
                not isinstance(flags, Mapping)
                or type(seq) is not int
                or not 0 <= seq < 2**32
                or type(ack) is not int
                or not 0 <= ack < 2**32
                or type(window) is not int
                or not 0 <= window <= 65535
                or type(length) is not int
                or not 0 <= length <= 65535
            ):
                state["warnings"].add("INCOMPLETE_PACKET_EVIDENCE")
                state["data"] = [{}, {}]
                state["syn"].clear()
                state["last_ack"] = [None, None]
                continue
            syns = state["syn"]
            if flags.get("syn") and not flags.get("ack") and (direction, seq) not in syns:
                state["data"] = [{}, {}]
                state["last_ack"] = [None, None]
                syns.clear()
            if flags.get("syn") and not flags.get("ack") and not flags.get("rst"):
                identity = (direction, seq)
                if identity in syns:
                    flow["metrics"]["syn_retransmissions"] += 1
                    syns[identity][1] = True
                else:
                    syns[identity] = [time, False]
            if flags.get("ack") and (flags.get("syn") or flags.get("rst")):
                match = syns.pop((1 - direction, (ack - 1) % (2**32)), None)
                if match is not None:
                    if flags.get("rst"):
                        flow["metrics"]["matched_resets"] += 1
                    elif not match[1] and time > match[0]:
                        state["rtt"].append(round((time - match[0]) * 1000, 6))
            _tcp_data(record, state, flow["metrics"], direction, time)
            if flags.get("rst") or flags.get("fin"):
                state["data"] = [{}, {}]
                state["syn"].clear()
                state["last_ack"] = [None, None]
        elif protocol == "UDP" and record.get("payload_hash"):
            udp_identity = (
                direction,
                record.get("transport_payload_length"),
                record["payload_hash"],
            )
            if udp_identity in state["udp"]:
                flow["metrics"]["udp_duplicate_candidates"] += 1
            state["udp"].add(udp_identity)
        elif protocol in {"ICMP", "ICMPV6"} and record.get("icmp_error"):
            detail = {
                "type": record.get("icmp_type"),
                "code": record.get("icmp_code"),
                "reporter_ip": source[0],
                "quoted_flow": record.get("icmp_quoted_flow"),
            }
            flow["metrics"]["icmp_errors"] += 1
            if len(flow["metrics"]["icmp_error_details"]) < 16:
                flow["metrics"]["icmp_error_details"].append(detail)
            quote = record.get("icmp_quoted_flow")
            if quote and len(quoted_errors) < max_packets:
                qa, qb = sorted(
                    (
                        (quote["source_ip"], quote["source_port"]),
                        (quote["destination_ip"], quote["destination_port"]),
                    )
                )
                quoted_errors.append(((sensor, interface, quote["protocol"], qa, qb), detail))
    for target, detail in quoted_errors:
        if target in groups:
            metrics = groups[target]["metrics"]
            metrics["icmp_errors"] += 1
            if len(metrics["icmp_error_details"]) < 16:
                metrics["icmp_error_details"].append(detail)
    for key, flow in groups.items():
        state = states[key]
        flow["metrics"]["observed_rtt_ms"] = _stats(state["rtt"])
        flow["metrics"]["interarrival_variation_ms"] = {
            d: {
                **_stats(state["intervals"][i]),
                "stddev": round(pstdev(state["intervals"][i]), 6)
                if len(state["intervals"][i]) >= 2
                else None,
            }
            for i, d in enumerate(_DIRECTIONS)
        }
        flow["metrics"]["ttl_observed"] = {
            d: {
                "min": min(state["ttl"][i]) if state["ttl"][i] else None,
                "max": max(state["ttl"][i]) if state["ttl"][i] else None,
            }
            for i, d in enumerate(_DIRECTIONS)
        }
        if any(v["packets"] == 0 for v in flow["observed_directions"].values()):
            state["warnings"].add("ONE_DIRECTION_OBSERVED")
        flow["warnings"] = sorted(state["warnings"])
    return {
        "version": "network-anomaly-v1",
        "summary": {
            "scanned_records": scanned,
            "skipped_records": skipped,
            "flow_count": len(groups),
            "truncated": bool(warnings & {"PACKET_LIMIT_REACHED", "FLOW_LIMIT_REACHED"}),
        },
        "flows": list(groups.values()),
        "warnings": sorted(warnings),
        "limitations": [
            "Single-vantage observations do not prove loss or asymmetric routing.",
            "Duplicate capture can mimic retransmissions.",
            "Observed RTT includes peer response delay; not host end-to-end RTT.",
            "Interarrival variation is not one-way jitter.",
            "UDP duplicates are candidates, not transport retransmissions.",
        ],
    }
