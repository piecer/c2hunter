from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from statistics import median

from .domain import AnalysisContext, Flow

PREFILTER_VERSION = "ai-prefilter-v1"
_COMMON_SERVICE_PORTS = {53, 123}


@dataclass(frozen=True)
class PrefilterFactor:
    name: str
    points: float
    explanation: str
    metrics: dict[str, int | float | str]


@dataclass(frozen=True)
class PrefilterCandidate:
    candidate_ip: str
    prefilter_score: int
    score_version: str
    factors: tuple[PrefilterFactor, ...]
    internal_hosts: tuple[str, ...]
    protocols: tuple[str, ...]
    ports: tuple[int, ...]
    first_seen: datetime
    last_seen: datetime


def _peer_and_host(context: AnalysisContext, flow: Flow) -> tuple[str, str, int | None] | None:
    direction = flow.direction.upper()
    if direction == "OUTBOUND":
        return flow.destination_ip, flow.source_ip, flow.destination_port
    if direction == "INBOUND":
        return flow.source_ip, flow.destination_ip, flow.source_port
    source_internal = context.is_internal(flow.source_ip)
    destination_internal = context.is_internal(flow.destination_ip)
    if source_internal == destination_internal:
        return None
    if source_internal:
        return flow.destination_ip, flow.source_ip, flow.destination_port
    return flow.source_ip, flow.destination_ip, flow.source_port


def _interval_factor(peer_flows: list[tuple[Flow, str, int | None]]) -> PrefilterFactor | None:
    timestamps_by_host: dict[str, list[float]] = defaultdict(list)
    for flow, host, _port in peer_flows:
        timestamps_by_host[host].append(flow.timestamp.timestamp())
    best_samples = 0
    best_deviation = 1.0
    best_period = 0.0
    for timestamps in timestamps_by_host.values():
        ordered = sorted(set(timestamps))
        intervals = [right - left for left, right in zip(ordered, ordered[1:], strict=False)]
        if len(intervals) < 3:
            continue
        period = median(intervals)
        if period <= 0:
            continue
        deviation = median(abs(value - period) for value in intervals) / period
        if deviation <= 0.2 and (len(intervals) > best_samples or deviation < best_deviation):
            best_samples = len(intervals)
            best_deviation = deviation
            best_period = period
    if best_samples < 3:
        return None
    points = round(35 * (1 - min(1.0, best_deviation)), 2)
    return PrefilterFactor(
        name="SINGLE_HOST_BEACON",
        points=points,
        explanation="One internal host contacted the peer at stable repeated intervals.",
        metrics={
            "interval_samples": best_samples,
            "median_period_seconds": round(best_period, 3),
            "normalized_mad": round(best_deviation, 4),
        },
    )


def _payload_factor(peer_flows: list[tuple[Flow, str, int | None]]) -> PrefilterFactor | None:
    signatures: list[str] = []
    for flow, _host, _port in peer_flows:
        signature = flow.payload_simhash or flow.payload_hash or flow.payload_prefix_hash
        if signature:
            signatures.append(signature)
    if len(signatures) < 3:
        return None
    signature, count = Counter(signatures).most_common(1)[0]
    ratio = count / len(signatures)
    if count < 3 or ratio < 0.6:
        return None
    return PrefilterFactor(
        name="PAYLOAD_CLUSTER",
        points=round(20 * ratio, 2),
        explanation="Repeated irreversible payload features form a dominant cluster.",
        metrics={
            "sample_count": len(signatures),
            "dominant_count": count,
            "dominant_ratio": round(ratio, 4),
            "feature_prefix": signature[:12],
        },
    )


def _synchronization_factor(
    peer_flows: list[tuple[Flow, str, int | None]],
) -> PrefilterFactor | None:
    hosts_by_bucket: dict[int, set[str]] = defaultdict(set)
    for flow, host, _port in peer_flows:
        hosts_by_bucket[int(flow.timestamp.timestamp() // 2)].add(host)
    synchronized_hosts = max((len(hosts) for hosts in hosts_by_bucket.values()), default=0)
    if synchronized_hosts < 3:
        return None
    return PrefilterFactor(
        name="SYNCHRONIZED_CLUSTER",
        points=min(20.0, 5.0 * synchronized_hosts),
        explanation="Multiple internal hosts contacted the peer inside the same two-second window.",
        metrics={"synchronized_hosts": synchronized_hosts, "window_seconds": 2},
    )


def _robust_anomaly_factor(
    flow_count: int, byte_count: int, peer_profiles: list[tuple[int, int]]
) -> PrefilterFactor | None:
    flow_values = [profile[0] for profile in peer_profiles]
    byte_values = [profile[1] for profile in peer_profiles]
    flow_median = float(median(flow_values))
    byte_median = float(median(byte_values))
    flow_mad = float(median(abs(value - flow_median) for value in flow_values))
    byte_mad = float(median(abs(value - byte_median) for value in byte_values))
    flow_z = (flow_count - flow_median) / max(1.0, 1.4826 * flow_mad)
    byte_z = (byte_count - byte_median) / max(1.0, 1.4826 * byte_mad)
    robust_z = max(flow_z, byte_z)
    if robust_z < 3:
        return None
    return PrefilterFactor(
        name="ROBUST_ANOMALY",
        points=min(20.0, 5.0 + robust_z),
        explanation="Peer activity is an outlier against the job-level external-peer population.",
        metrics={
            "robust_z": round(robust_z, 3),
            "flow_count": flow_count,
            "median_flow_count": round(flow_median, 3),
            "total_bytes": byte_count,
            "median_total_bytes": round(byte_median, 3),
        },
    )


def generate_high_recall_candidates(
    context: AnalysisContext,
    *,
    trusted_peers: set[str] | None = None,
    limit: int | None = None,
) -> list[PrefilterCandidate]:
    """Rank every scoped external peer without changing deterministic detector results."""
    if limit is not None and limit < 1:
        raise ValueError("limit must be positive")
    trusted = trusted_peers or set()
    grouped: dict[str, list[tuple[Flow, str, int | None]]] = defaultdict(list)
    for flow in context.scoped_flows():
        endpoint = _peer_and_host(context, flow)
        if endpoint is None:
            continue
        peer, host, port = endpoint
        grouped[peer].append((flow, host, port))
    profiles = [
        (len(peer_flows), sum(max(0, flow.total_bytes) for flow, _host, _port in peer_flows))
        for peer_flows in grouped.values()
    ]
    candidates: list[PrefilterCandidate] = []
    for peer, peer_flows in grouped.items():
        ordered = sorted(peer_flows, key=lambda item: (item[0].timestamp, item[1], item[2] or -1))
        total_packets = sum(max(0, flow.packet_count) for flow, _host, _port in ordered)
        total_bytes = sum(max(0, flow.total_bytes) for flow, _host, _port in ordered)
        factors = [
            PrefilterFactor(
                name="PEER_BASELINE",
                points=min(10.0, 2.0 + 2.0 * math.log2(len(ordered) + 1)),
                explanation="The external peer is present in the completed analysis flow universe.",
                metrics={
                    "flow_count": len(ordered),
                    "packet_count": total_packets,
                    "total_bytes": total_bytes,
                },
            )
        ]
        for factor in (
            _interval_factor(ordered),
            _payload_factor(ordered),
            _synchronization_factor(ordered),
            _robust_anomaly_factor(len(ordered), total_bytes, profiles),
        ):
            if factor is not None:
                factors.append(factor)
        ports = sorted({port for _flow, _host, port in ordered if port is not None})
        if ports and set(ports) <= _COMMON_SERVICE_PORTS:
            factors.append(
                PrefilterFactor(
                    name="COMMON_SERVICE_PENALTY",
                    points=-15,
                    explanation="Traffic uses only common DNS/NTP service ports.",
                    metrics={"ports": ",".join(str(port) for port in ports)},
                )
            )
        if total_bytes >= 50 * 1024 * 1024 or total_packets >= 100_000:
            factors.append(
                PrefilterFactor(
                    name="HIGH_VOLUME_PENALTY",
                    points=-20,
                    explanation=(
                        "High-volume traffic is down-ranked to reduce "
                        "bulk-transfer false positives."
                    ),
                    metrics={"packet_count": total_packets, "total_bytes": total_bytes},
                )
            )
        if peer in trusted:
            factors.append(
                PrefilterFactor(
                    name="TRUSTED_PEER_PENALTY",
                    points=-100,
                    explanation="The peer is present in the explicitly supplied trusted-peer set.",
                    metrics={"trusted": 1},
                )
            )
        score = max(0, min(100, round(sum(factor.points for factor in factors))))
        candidates.append(
            PrefilterCandidate(
                candidate_ip=peer,
                prefilter_score=score,
                score_version=PREFILTER_VERSION,
                factors=tuple(factors),
                internal_hosts=tuple(sorted({host for _flow, host, _port in ordered})),
                protocols=tuple(sorted({flow.protocol for flow, _host, _port in ordered})),
                ports=tuple(ports),
                first_seen=ordered[0][0].timestamp,
                last_seen=ordered[-1][0].timestamp,
            )
        )
    ranked = sorted(candidates, key=lambda item: (-item.prefilter_score, item.candidate_ip))
    return ranked[:limit] if limit is not None else ranked
