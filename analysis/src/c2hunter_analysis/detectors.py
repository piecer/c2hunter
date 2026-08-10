from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta

from .domain import AnalysisContext, Detector, Evidence, Flow
from .payload_features import simhash_hamming_distance
from .tcp_sessions import (
    qualified_candidate_groups,
    qualified_tcp_flow_ids,
    scan_suppressed_keys,
    tcp_profiles,
)


def _candidate_host(context: AnalysisContext, flow: Flow) -> tuple[str, str] | None:
    direction = flow.direction.upper()
    if direction == "OUTBOUND":
        return flow.destination_ip, flow.source_ip
    if direction == "INBOUND":
        return flow.source_ip, flow.destination_ip

    # BIDIRECTIONAL/UNKNOWN has no authoritative packet-side role. Fall back to
    # configured CIDRs only for those ambiguous records.
    if context.is_internal(flow.source_ip) and not context.is_internal(flow.destination_ip):
        return flow.destination_ip, flow.source_ip
    if context.is_internal(flow.destination_ip) and not context.is_internal(flow.source_ip):
        return flow.source_ip, flow.destination_ip
    return None


def _groups(context: AnalysisContext) -> dict[str, list[tuple[str, Flow]]]:
    return qualified_candidate_groups(context)


def _service_port(context: AnalysisContext, flow: Flow) -> int | None:
    direction = flow.direction.upper()
    if direction == "OUTBOUND":
        return flow.destination_port
    if direction == "INBOUND":
        return flow.source_port

    if context.is_internal(flow.source_ip) and not context.is_internal(flow.destination_ip):
        return flow.destination_port
    if context.is_internal(flow.destination_ip) and not context.is_internal(flow.source_ip):
        return flow.source_port
    return None


def _base_evidence(
    candidate: str,
    kind: str,
    detector: str,
    contribution: float,
    rows: list[tuple[str, Flow]],
    metrics: Mapping[str, object],
    description: str,
    *,
    confidence: float = 1.0,
    warnings: tuple[str, ...] = (),
) -> Evidence:
    timestamps = [flow.timestamp for _, flow in rows]
    return Evidence(
        candidate,
        kind,
        detector,
        "1.0.0",
        contribution,
        contribution,
        description,
        tuple(sorted({host for host, _ in rows})),
        tuple(sorted({flow.sensor_id for _, flow in rows})),
        min(timestamps),
        max(timestamps),
        dict(metrics),
        confidence,
        warnings,
    )


@dataclass(frozen=True)
class CommonDestinationDetector:
    name: str = "common_destination"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("minimum_distinct_clients", 3))
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            hosts = {host for host, _ in rows}
            if len(hosts) < minimum:
                continue
            ports = Counter(_service_port(context, flow) for _, flow in rows)
            hashes = Counter(flow.payload_hash for _, flow in rows if flow.payload_hash)
            duration = (
                max(flow.timestamp for _, flow in rows) - min(flow.timestamp for _, flow in rows)
            ).total_seconds()
            legacy_dns_ntp_servers = {
                str(value) for value in context.parameters.get("public_dns_ntp_servers", ())
            }
            trusted_dns_servers = legacy_dns_ntp_servers | {
                str(value) for value in context.parameters.get("trusted_dns_servers", ())
            }
            trusted_ntp_servers = legacy_dns_ntp_servers | {
                str(value) for value in context.parameters.get("trusted_ntp_servers", ())
            }
            service_ports = {port for port in ports if port is not None}
            public_dns_ntp = (
                (candidate in trusted_dns_servers and service_ports == {53})
                or (candidate in trusted_ntp_servers and service_ports == {123})
            ) and all(flow.protocol.upper() == "UDP" for _, flow in rows)
            domains = {flow.domain.lower().rstrip(".") for _, flow in rows if flow.domain}
            cdn_suffixes = {
                str(value).lower().lstrip(".").rstrip(".")
                for value in context.parameters.get("cdn_domain_suffixes", ())
            }
            trusted_cdn_suffix = next(
                (
                    suffix
                    for suffix in sorted(cdn_suffixes)
                    if domains and all(domain.endswith(suffix) for domain in domains)
                ),
                None,
            )
            infrastructure_ips = {
                str(value) for value in context.parameters.get("trusted_infrastructure_ips", ())
            }
            cdn_cloud = trusted_cdn_suffix is not None or candidate in infrastructure_ips
            metrics = {
                "distinct_hosts": len(hosts),
                "connections": len(rows),
                "distinct_sensors": len({flow.sensor_id for _, flow in rows}),
                "duration_seconds": duration,
                "connections_per_host": len(rows) / len(hosts),
                "dominant_port_ratio": max(ports.values()) / len(rows),
                "fingerprint_ratio": max(hashes.values()) / len(rows) if hashes else 0.0,
                "sample_count": len(rows),
                "public_dns_ntp": public_dns_ntp,
                "service_ports": tuple(sorted(service_ports)),
                "cdn_cloud": cdn_cloud,
                "distinct_domains": len(domains),
            }
            if trusted_cdn_suffix is not None:
                metrics["trusted_cdn_suffix"] = trusted_cdn_suffix
            contribution = min(20.0, 10 + 10 * min(1.0, len(hosts) / minimum))
            result.append(
                _base_evidence(
                    candidate,
                    "COMMON_DESTINATION",
                    self.name,
                    contribution,
                    rows,
                    metrics,
                    "다수 내부 호스트가 같은 외부 목적지와 통신",
                )
            )
        return result


@dataclass(frozen=True)
class NonWellKnownPortDetector:
    """Add a bounded hunting signal when the external service port is non-standard.

    The detector always derives the service-side port from the internal/external role.
    It therefore does not accidentally score an internal client's ephemeral source port.
    """

    name: str = "non_well_known_port"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        maximum = max(
            0,
            min(65535, int(context.parameters.get("well_known_port_max", 1023))),
        )
        minimum_ratio = max(
            0.0,
            min(1.0, float(context.parameters.get("non_well_known_port_min_ratio", 0.75))),
        )
        minimum_observations = max(
            1,
            int(context.parameters.get("non_well_known_port_min_observations", 2)),
        )
        excluded = {
            int(value)
            for value in context.parameters.get("non_well_known_port_exclusions", ())
            if isinstance(value, int | str) and str(value).isdigit() and 0 <= int(value) <= 65535
        }
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            inspected: list[tuple[str, Flow, int]] = []
            for host, flow in rows:
                port = _service_port(context, flow)
                if port is not None:
                    inspected.append((host, flow, port))
            suspicious = [
                (host, flow, port)
                for host, flow, port in inspected
                if port > maximum and port not in excluded
            ]
            if len(suspicious) < minimum_observations or not inspected:
                continue
            ratio = len(suspicious) / len(inspected)
            if ratio < minimum_ratio:
                continue
            counts = Counter(port for _, _, port in suspicious)
            dominant_port, dominant_count = counts.most_common(1)[0]
            selected = [(host, flow) for host, flow, _ in suspicious]
            contribution = min(25.0, 15.0 + 10.0 * ratio)
            result.append(
                _base_evidence(
                    candidate,
                    "NON_WELL_KNOWN_PORT",
                    self.name,
                    contribution,
                    selected,
                    {
                        "well_known_port_max": maximum,
                        "non_well_known_ratio": round(ratio, 4),
                        "observed_flow_count": len(inspected),
                        "sample_count": len(suspicious),
                        "service_ports": tuple(sorted(counts)),
                        "dominant_port": dominant_port,
                        "dominant_port_ratio": dominant_count / len(suspicious),
                    },
                    "외부 endpoint가 well-known 범위 밖의 service port를 반복 사용",
                    confidence=0.6,
                    warnings=("port_heuristic_only",),
                )
            )
        return result


@dataclass(frozen=True)
class PeriodicBeaconDetector:
    name: str = "periodic_beacon"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("periodicity_min_samples", 5))
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            by_host: dict[str, list[Flow]] = defaultdict(list)
            for host, flow in rows:
                by_host[host].append(flow)
            regular: list[tuple[str, float, float, int]] = []
            for host, flows in by_host.items():
                times = sorted(flow.timestamp.timestamp() for flow in flows)
                if len(times) < minimum:
                    continue
                intervals = [right - left for left, right in zip(times, times[1:], strict=False)]
                mean = statistics.fmean(intervals)
                cv = statistics.pstdev(intervals) / mean if mean else math.inf
                if 0 < mean and cv <= float(context.parameters.get("maximum_beacon_cv", 0.30)):
                    regular.append((host, mean, cv, len(times)))
            if not regular:
                continue
            # Keep short beacon periods meaningful; only coarse-bin periods where a
            # five-second bucket cannot collapse the estimate to zero.
            median_period = statistics.median(item[1] for item in regular)
            period = round(median_period / 5) * 5 if median_period >= 5 else median_period
            cv = statistics.fmean(item[2] for item in regular)
            matching = [item for item in regular if abs(item[1] - period) / period <= 0.30]
            selected = [
                (host, flow) for host, flow in rows if host in {item[0] for item in matching}
            ]
            sizes = [size for _, flow in selected for size in flow.packet_sizes] or [
                flow.total_bytes for _, flow in selected
            ]
            size_cv = (
                statistics.pstdev(sizes) / statistics.fmean(sizes)
                if sizes and statistics.fmean(sizes)
                else 0.0
            )
            metrics = {
                "sample_count": sum(item[3] for item in matching),
                "period_seconds": round(period, 6),
                "coefficient_of_variation": cv,
                "jitter_ratio": cv,
                "autocorrelation": max(0.0, 1.0 - cv),
                "size_similarity": max(0.0, 1.0 - size_cv),
                "matching_hosts": len(matching),
                "distinct_sensors": len({flow.sensor_id for _, flow in selected}),
            }
            result.append(
                _base_evidence(
                    candidate,
                    "PERIODIC_BEACON",
                    self.name,
                    15,
                    selected,
                    metrics,
                    "허용 jitter 범위 내 주기 통신",
                )
            )
        return result


@dataclass(frozen=True)
class SingleHostCompositeBeaconDetector:
    name: str = "single_host_composite_beacon"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("periodicity_min_samples", 5))
        maximum_cv = float(context.parameters.get("maximum_beacon_cv", 0.30))
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            if len({host for host, _ in rows}) != 1 or len(rows) < minimum:
                continue
            ordered = sorted(rows, key=lambda item: item[1].timestamp)
            intervals = [
                (right[1].timestamp - left[1].timestamp).total_seconds()
                for left, right in zip(ordered, ordered[1:], strict=False)
            ]
            mean_interval = statistics.fmean(intervals)
            interval_cv = (
                statistics.pstdev(intervals) / mean_interval if mean_interval else math.inf
            )
            if mean_interval <= 0 or interval_cv > maximum_cv:
                continue
            hashes = Counter(flow.payload_hash for _, flow in rows if flow.payload_hash)
            payload_stability = max(hashes.values()) / len(rows) if hashes else 0.0
            sizes = [size for _, flow in rows for size in flow.packet_sizes] or [
                flow.total_bytes for _, flow in rows
            ]
            average_size = statistics.fmean(sizes) if sizes else 0.0
            size_cv = statistics.pstdev(sizes) / average_size if average_size else math.inf
            average_packets = statistics.fmean(flow.packet_count for _, flow in rows)
            if (payload_stability < 0.60 and size_cv > 0.20) or average_packets > 10:
                continue
            metrics = {
                "sample_count": len(rows),
                "period_seconds": round(mean_interval, 6),
                "coefficient_of_variation": interval_cv,
                "payload_stability": payload_stability,
                "size_coefficient_of_variation": size_cv,
                "average_packets": average_packets,
                "distinct_sensors": len({flow.sensor_id for _, flow in rows}),
            }
            result.append(
                _base_evidence(
                    candidate,
                    "SINGLE_HOST_BEACON",
                    self.name,
                    35,
                    rows,
                    metrics,
                    "단일 내부 호스트의 저용량 주기 통신과 안정된 Payload/크기 패턴",
                    confidence=0.7,
                )
            )
        return result


@dataclass(frozen=True)
class AnalystPayloadSignatureDetector:
    name: str = "analyst_payload_signature"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        raw_signatures = context.parameters.get("payload_signatures", ())
        if not isinstance(raw_signatures, list | tuple):
            return []
        signatures = [
            item for item in raw_signatures if isinstance(item, Mapping) and item.get("enabled")
        ]
        matched: dict[
            tuple[str, str], list[tuple[str, Flow, str, dict[str, object], Mapping[str, object]]]
        ] = defaultdict(list)
        for flow in context.scoped_flows():
            role = _candidate_host(context, flow)
            if role is None:
                continue
            candidate, host = role
            for signature in signatures:
                comparison = self._match(context, flow, signature)
                if comparison is None:
                    continue
                mode, metrics = comparison
                signature_id = str(signature.get("id", ""))
                if not signature_id:
                    continue
                matched[(candidate, signature_id)].append((host, flow, mode, metrics, signature))

        result: list[Evidence] = []
        for (candidate, _signature_id), values in matched.items():
            exact = [value for value in values if value[2] == "EXACT"]
            selected = exact or values
            mode = "EXACT" if exact else "STRUCTURAL"
            rows = [(host, flow) for host, flow, *_rest in selected]
            signature = selected[0][4]
            comparisons = [value[3] for value in selected]
            raw_version = signature.get("version", 1)
            if not isinstance(raw_version, int | float | str):
                raw_version = 1
            sig_metrics: dict[str, object] = {
                "signature_id": str(signature["id"]),
                "signature_name": str(signature.get("name", signature["id"])),
                "signature_version": int(raw_version),  # type: ignore
                "match_mode": mode,
                "matched_flow_count": len(selected),
                "sample_count": len(selected),
                "action": "alert" if mode == "EXACT" else "monitor",
                "comparisons": comparisons[:20],
                "analyst_confirmed": mode == "EXACT",
            }
            result.append(
                _base_evidence(
                    candidate,
                    "ANALYST_PAYLOAD_SIGNATURE",
                    self.name,
                    80 if mode == "EXACT" else 60,
                    rows,
                    sig_metrics,
                    (
                        "분석가가 승인한 Payload signature와 정확히 일치"
                        if mode == "EXACT"
                        else "분석가가 승인한 Payload signature의 구조 특징과 일치"
                    ),
                    confidence=1.0 if mode == "EXACT" else 0.7,
                    warnings=() if mode == "EXACT" else ("structural_match_review",),
                )
            )
        return result

    @staticmethod
    def _match(
        context: AnalysisContext, flow: Flow, signature: Mapping[str, object]
    ) -> tuple[str, dict[str, object]] | None:
        protocol = str(signature.get("protocol", "")).upper()
        if protocol and flow.protocol.upper() != protocol:
            return None
        direction = str(signature.get("direction", "")).upper()
        if direction and flow.direction.upper() != direction:
            return None
        raw_service_port = signature.get("service_port")
        if raw_service_port is not None and _service_port(context, flow) != int(  # type: ignore
            raw_service_port
        ):
            return None

        signature_hash = str(signature.get("payload_hash") or "")
        flow_hashes = {value for value in (flow.payload_hash, flow.last_payload_hash) if value}
        if signature_hash and signature_hash in flow_hashes:
            return (
                "EXACT",
                {
                    "matched_payload_hash": signature_hash,
                    "matched_payload_position": (
                        "FIRST" if flow.payload_hash == signature_hash else "LAST"
                    ),
                    "flow_payload_hashes": tuple(sorted(flow_hashes)),
                    "service_port": _service_port(context, flow),
                },
            )

        feature_version = signature.get("payload_feature_version")
        if feature_version and flow.payload_feature_version != str(feature_version):
            return None
        prefix_match = bool(
            signature.get("payload_prefix_hash")
            and flow.payload_prefix_hash == str(signature["payload_prefix_hash"])
        )
        simhash_distance: int | None = None
        if signature.get("payload_simhash") and flow.payload_simhash:
            try:
                simhash_distance = simhash_hamming_distance(
                    str(signature["payload_simhash"]), flow.payload_simhash
                )
            except ValueError:
                return None
        max_distance = int(signature.get("simhash_max_distance", 8))  # type: ignore
        strong_content = prefix_match or (
            simhash_distance is not None and simhash_distance <= max_distance
        )
        if not strong_content:
            return None

        raw_length = signature.get("payload_length")
        raw_entropy = signature.get("payload_entropy")
        if (
            raw_length is None
            or flow.payload_length is None
            or raw_entropy is None
            or flow.payload_entropy is None
        ):
            return None
        source_length = int(raw_length)  # type: ignore
        length_difference = abs(flow.payload_length - source_length)
        length_tolerance = max(
            16,
            round(source_length * float(signature.get("length_tolerance_ratio", 0.15))),  # type: ignore
        )
        entropy_difference = abs(flow.payload_entropy - float(raw_entropy))  # type: ignore
        entropy_tolerance = float(signature.get("entropy_tolerance", 0.75))  # type: ignore
        if length_difference > length_tolerance or entropy_difference > entropy_tolerance:
            return None
        comparable = (
            3
            + int(simhash_distance is not None)
            + int(
                flow.payload_printable_ratio is not None
                and signature.get("payload_printable_ratio") is not None
            )
        )
        if comparable < 3:
            return None
        return (
            "STRUCTURAL",
            {
                "prefix_match": prefix_match,
                "simhash_distance": simhash_distance,
                "simhash_max_distance": max_distance,
                "length_difference": length_difference,
                "length_tolerance": length_tolerance,
                "entropy_difference": round(entropy_difference, 4),
                "entropy_tolerance": entropy_tolerance,
                "comparable_features": comparable,
                "service_port": _service_port(context, flow),
            },
        )


@dataclass(frozen=True)
class SynchronizedCommunicationDetector:
    name: str = "synchronized_communication"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        window = float(context.parameters.get("synchronization_window_seconds", 2.0))
        minimum = int(context.parameters.get("minimum_distinct_clients", 3))
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            buckets: dict[int, list[tuple[str, Flow]]] = defaultdict(list)
            for row in rows:
                corrected = row[1].timestamp - timedelta(
                    milliseconds=context.clock_offsets_ms.get(row[1].sensor_id, 0)
                )
                buckets[int(corrected.timestamp() // window)].append(row)
            repeated = [
                items for items in buckets.values() if len({host for host, _ in items}) >= minimum
            ]
            if len(repeated) < 2:
                continue
            chosen = [row for items in repeated for row in items]
            max_hosts = max(len({host for host, _ in items}) for items in repeated)
            spread = max(
                (
                    max(f.timestamp for _, f in items) - min(f.timestamp for _, f in items)
                ).total_seconds()
                for items in repeated
            )
            metrics = {
                "window_seconds": window,
                "synchronized_hosts": max_hosts,
                "event_count": len(chosen),
                "repetition_count": len(repeated),
                "distinct_sensors": len({f.sensor_id for _, f in chosen}),
                "observed_spread": spread,
                "sample_count": len(chosen),
            }
            skewed = any(
                abs(context.clock_offsets_ms.get(f.sensor_id, 0)) > 2000 for _, f in chosen
            )
            result.append(
                _base_evidence(
                    candidate,
                    "SYNCHRONIZED_COMMUNICATION",
                    self.name,
                    15,
                    chosen,
                    metrics,
                    "다중 호스트 동기 통신 반복",
                    confidence=0.7 if skewed else 1.0,
                    warnings=("clock_skew",) if skewed else (),
                )
            )
        return result


@dataclass(frozen=True)
class CommandAttackDetector:
    name: str = "command_attack_correlation"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("minimum_distinct_clients", 3))
        all_flows = context.scoped_flows()
        qualified_tcp = qualified_tcp_flow_ids(context)
        inbound: dict[str, list[tuple[str, Flow]]] = defaultdict(list)
        for flow in all_flows:
            if flow.direction.upper() == "INBOUND":
                if flow.protocol.upper() == "TCP" and id(flow) not in qualified_tcp:
                    continue
                inbound[flow.source_ip].append((flow.destination_ip, flow))
        result: list[Evidence] = []
        for candidate, commands in inbound.items():
            hosts = {host for host, _ in commands}
            if len(hosts) < minimum:
                continue
            seed = min(flow.timestamp for _, flow in commands)
            attacks = [
                flow
                for flow in all_flows
                if flow.direction == "OUTBOUND"
                and flow.source_ip in hosts
                and flow.destination_ip != candidate
                and 1 <= (flow.timestamp - seed).total_seconds() <= 30
            ]
            if not attacks:
                continue
            targets = Counter(
                (flow.destination_ip, flow.destination_port, flow.protocol) for flow in attacks
            )
            target, count = targets.most_common(1)[0]
            attack_packets = sum(
                flow.packet_count
                for flow in attacks
                if (flow.destination_ip, flow.destination_port, flow.protocol) == target
            )
            baseline = [
                flow
                for flow in all_flows
                if flow.direction == "OUTBOUND"
                and flow.source_ip in hosts
                and flow.destination_ip == target[0]
                and seed - timedelta(seconds=30) <= flow.timestamp < seed
            ]
            baseline_packets = sum(flow.packet_count for flow in baseline)
            ratio = attack_packets / max(1, baseline_packets)
            affected = len({flow.source_ip for flow in attacks if flow.destination_ip == target[0]})
            if affected < minimum or ratio < 3:
                continue
            metrics = {
                "command_size": sum(flow.total_bytes for _, flow in commands),
                "affected_hosts": affected,
                "increase_ratio": ratio,
                "attack_target": target[0],
                "target_port": target[1],
                "target_protocol": target[2],
                "sample_count": len(commands) + len(attacks),
            }
            result.append(
                _base_evidence(
                    candidate,
                    "COMMAND_ATTACK_CORRELATION",
                    self.name,
                    25,
                    commands,
                    metrics,
                    "작은 inbound 명령 직후 공통 target 공격 증가",
                )
            )
        return result


@dataclass(frozen=True)
class PersistenceRarityDetector:
    name: str = "persistence_rarity"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("minimum_distinct_clients", 3))
        result: list[Evidence] = []
        groups = _groups(context)
        candidate_count = len(groups)
        for candidate, rows in groups.items():
            duration = (
                max(f.timestamp for _, f in rows) - min(f.timestamp for _, f in rows)
            ).total_seconds()
            hosts = {host for host, _ in rows}
            avg_packets = statistics.fmean(f.packet_count for _, f in rows)
            if len(hosts) < minimum or duration < 300 or avg_packets > 10:
                continue
            metrics = {
                "duration_seconds": duration,
                "average_packets": avg_packets,
                "destination_stability": 1.0,
                "rarity": 1 / max(1, candidate_count),
                "sample_count": len(rows),
            }
            result.append(
                _base_evidence(
                    candidate,
                    "LOW_VOLUME_PERSISTENCE_RARITY",
                    self.name,
                    5,
                    rows,
                    metrics,
                    "저용량 연결이 장기간 안정적으로 지속",
                )
            )
        return result


@dataclass(frozen=True)
class ProtocolSimilarityDetector:
    name: str = "protocol_similarity"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("minimum_distinct_clients", 3))
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            hosts = {host for host, _ in rows}
            if len(hosts) < minimum:
                continue
            features = Counter(
                (
                    f.protocol,
                    _service_port(context, f),
                    f.payload_hash,
                    f.tls_fingerprint,
                    f.certificate_fingerprint,
                    f.domain,
                    f.packet_sizes,
                )
                for _, f in rows
            )
            ratio = max(features.values()) / len(rows)
            domains = {f.domain for _, f in rows if f.domain}
            if ratio < 0.6 or len(domains) > max(3, len(hosts)):
                continue
            metrics = {
                "dominant_feature_ratio": ratio,
                "domain_diversity": len(domains),
                "sample_count": len(rows),
                "payload_hash": features.most_common(1)[0][0][2],
            }
            result.append(
                _base_evidence(
                    candidate,
                    "PROTOCOL_PAYLOAD_SIMILARITY",
                    self.name,
                    10 * ratio,
                    rows,
                    metrics,
                    "여러 호스트의 protocol/payload 통계가 유사",
                )
            )
        return result


_C2_ANOMALY_DIRECTIONS: dict[str, str] = {
    "interval_cv": "LOW",
    "size_cv": "LOW",
    "payload_stability": "HIGH",
    "port_stability": "HIGH",
    "fingerprint_stability": "HIGH",
    "domain_diversity_ratio": "LOW",
}


def _candidate_feature_vector(
    context: AnalysisContext, rows: list[tuple[str, Flow]]
) -> dict[str, float | None]:
    """Build auditable C2-oriented features without external ML dependencies.

    Missing telemetry remains ``None`` and is excluded from the population
    baseline. This prevents absent payload/TLS/domain metadata from being treated
    as a meaningful zero value.
    """
    by_host: dict[str, list[Flow]] = defaultdict(list)
    for host, flow in rows:
        by_host[host].append(flow)

    interval_cvs: list[float] = []
    for flows in by_host.values():
        if len(flows) < 4:
            continue
        times = sorted(flow.timestamp.timestamp() for flow in flows)
        intervals = [right - left for left, right in zip(times, times[1:], strict=False)]
        mean = statistics.fmean(intervals)
        if mean > 0:
            interval_cvs.append(statistics.pstdev(intervals) / mean)

    sizes = [size for _, flow in rows for size in flow.packet_sizes if size > 0] or [
        flow.total_bytes for _, flow in rows if flow.total_bytes > 0
    ]
    mean_size = statistics.fmean(sizes) if sizes else 0.0

    payload_hashes = [flow.payload_hash for _, flow in rows if flow.payload_hash]
    ports = [port for _, flow in rows if (port := _service_port(context, flow)) is not None]
    fingerprints = [
        (flow.tls_fingerprint, flow.certificate_fingerprint)
        for _, flow in rows
        if flow.tls_fingerprint or flow.certificate_fingerprint
    ]
    domains = [flow.domain.lower().rstrip(".") for _, flow in rows if flow.domain]

    return {
        "interval_cv": statistics.fmean(interval_cvs) if interval_cvs else None,
        "size_cv": statistics.pstdev(sizes) / mean_size if sizes and mean_size else None,
        "payload_stability": (
            max(Counter(payload_hashes).values()) / len(payload_hashes) if payload_hashes else None
        ),
        "port_stability": max(Counter(ports).values()) / len(ports) if ports else None,
        "fingerprint_stability": (
            max(Counter(fingerprints).values()) / len(fingerprints) if fingerprints else None
        ),
        "domain_diversity_ratio": len(set(domains)) / len(domains) if domains else None,
    }


def _robust_center_scale(values: list[float]) -> tuple[float, float]:
    """Return median and robust scale, falling back to population stdev.

    Median/MAD keeps one extreme candidate from defining its own baseline. The
    standard-deviation fallback still permits useful scoring when most candidates
    share exactly the same value and one candidate differs.
    """
    center = statistics.median(values)
    mad = statistics.median(abs(value - center) for value in values)
    if mad > 1e-9:
        return center, 1.4826 * mad
    stdev = statistics.pstdev(values)
    return center, stdev


@dataclass(frozen=True)
class PopulationAnomalyDetector:
    """Optional population-relative C2 hunting signal.

    The detector is disabled by default. It only counts deviations in a
    C2-consistent direction: lower interval/size variation, higher payload/port/
    fingerprint stability, and lower domain diversity. Generic outliers in the
    opposite direction do not receive positive evidence.
    """

    name: str = "ml_population_anomaly"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        if not bool(context.parameters.get("ml_anomaly_enabled", False)):
            return []

        minimum_population = max(8, int(context.parameters.get("ml_anomaly_min_population", 30)))
        minimum_samples = max(3, int(context.parameters.get("ml_anomaly_min_candidate_samples", 5)))
        z_threshold = max(2.0, float(context.parameters.get("ml_anomaly_z_threshold", 3.5)))
        feature_z_floor = max(0.0, float(context.parameters.get("ml_anomaly_feature_z_floor", 1.0)))
        minimum_directional_features = max(
            1,
            min(
                len(_C2_ANOMALY_DIRECTIONS),
                int(context.parameters.get("ml_anomaly_min_directional_features", 2)),
            ),
        )
        contribution_cap = max(
            0.0,
            min(5.0, float(context.parameters.get("ml_anomaly_contribution_cap", 5.0))),
        )

        groups = {
            candidate: rows
            for candidate, rows in _groups(context).items()
            if len(rows) >= minimum_samples
        }
        if len(groups) < minimum_population:
            return []

        vectors = {
            candidate: _candidate_feature_vector(context, rows)
            for candidate, rows in groups.items()
        }
        minimum_feature_population = max(8, minimum_population // 2)
        baselines: dict[str, tuple[float, float, int]] = {}
        for feature in _C2_ANOMALY_DIRECTIONS:
            values = [
                value
                for vector in vectors.values()
                if (value := vector.get(feature)) is not None and math.isfinite(value)
            ]
            if len(values) < minimum_feature_population:
                continue
            center, scale = _robust_center_scale(values)
            if scale > 1e-9:
                baselines[feature] = (center, scale, len(values))

        if len(baselines) < minimum_directional_features:
            return []

        result: list[Evidence] = []
        for candidate, rows in groups.items():
            vector = vectors[candidate]
            raw_z_scores: dict[str, float] = {}
            directional_z_scores: dict[str, float] = {}
            contributors: list[tuple[str, float]] = []
            for feature, direction in _C2_ANOMALY_DIRECTIONS.items():
                value = vector.get(feature)
                baseline = baselines.get(feature)
                if value is None or baseline is None:
                    continue
                center, scale, _population = baseline
                raw_z = (value - center) / scale
                directional_z = -raw_z if direction == "LOW" else raw_z
                raw_z_scores[feature] = raw_z
                directional_z_scores[feature] = max(0.0, directional_z)
                if directional_z >= feature_z_floor:
                    contributors.append((feature, directional_z))

            if len(contributors) < minimum_directional_features:
                continue
            anomaly_score = math.sqrt(sum(z_score * z_score for _, z_score in contributors))
            if anomaly_score < z_threshold:
                continue

            top_features = sorted(contributors, key=lambda item: item[1], reverse=True)[:3]
            contribution = min(
                contribution_cap,
                max(0.0, 1.0 + 2.0 * (anomaly_score - z_threshold)),
            )
            metrics = {
                "anomaly_score": round(anomaly_score, 4),
                "z_threshold": z_threshold,
                "feature_z_floor": feature_z_floor,
                "population_size": len(groups),
                "minimum_feature_population": minimum_feature_population,
                "available_feature_count": len(raw_z_scores),
                "directional_feature_count": len(contributors),
                "feature_vector": {
                    key: round(value, 4) if value is not None else None
                    for key, value in vector.items()
                },
                "raw_z_scores": {key: round(value, 4) for key, value in raw_z_scores.items()},
                "directional_z_scores": {
                    key: round(value, 4) for key, value in directional_z_scores.items()
                },
                "baseline_population": {
                    key: population for key, (_center, _scale, population) in baselines.items()
                },
                "top_contributing_features": [
                    {"feature": name, "directional_z_score": round(z_score, 4)}
                    for name, z_score in top_features
                ],
                "sample_count": len(rows),
            }
            result.append(
                _base_evidence(
                    candidate,
                    "ML_POPULATION_ANOMALY",
                    self.name,
                    contribution,
                    rows,
                    metrics,
                    "동일 분석의 외부 후보군 대비 C2형 feature 조합이 이례적",
                    confidence=min(0.7, 0.45 + 0.05 * len(contributors)),
                    warnings=(
                        "unsupervised_no_ground_truth",
                        "population_relative_signal",
                    ),
                )
            )
        return result


@dataclass(frozen=True)
class MultiSensorDetector:
    name: str = "multi_sensor_context"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        minimum = int(context.parameters.get("minimum_distinct_clients", 3))
        result: list[Evidence] = []
        for candidate, rows in _groups(context).items():
            sensor_hosts: dict[str, set[str]] = defaultdict(set)
            for host, flow in rows:
                sensor_hosts[flow.sensor_id].add(host)
            sensors = [sensor for sensor, hosts in sensor_hosts.items() if len(hosts) >= minimum]
            # Independent reproduction does not require the same client IPs at every site.
            independent_hosts = min((len(sensor_hosts[sensor]) for sensor in sensors), default=0)
            if len(sensors) < 2 or independent_hosts < minimum:
                continue
            metrics = {
                "distinct_sensors": len(sensors),
                "independent_hosts": independent_hosts,
                "observation_count": len(rows),
                "timestamp_tolerance_seconds": 2,
                "sample_count": len(rows),
            }
            result.append(
                _base_evidence(
                    candidate,
                    "MULTI_SENSOR_CONTEXT",
                    self.name,
                    10,
                    rows,
                    metrics,
                    "복수 센서에서 독립 호스트 패턴 재현",
                )
            )
        return result


@dataclass(frozen=True)
class TCPSessionQualityDetector:
    """Add connection-state context only to candidates supported by another detector."""

    name: str = "tcp_session_quality"
    version: str = "1.0.0"

    def analyze(self, context: AnalysisContext) -> list[Evidence]:
        if not bool(context.parameters.get("tcp_session_gating_enabled", True)):
            return []
        initiated_points = max(
            0.0,
            min(15.0, float(context.parameters.get("tcp_outbound_initiated_contribution", 5))),
        )
        established_points = max(
            0.0,
            min(15.0, float(context.parameters.get("tcp_established_contribution", 10))),
        )
        _raw, profiles = tcp_profiles(context)
        result: list[Evidence] = []
        for candidate, connections in profiles.items():
            suppressed = scan_suppressed_keys(context, connections)
            qualified = [
                profile
                for key, profile in connections.items()
                if key not in suppressed and profile.metadata_available and profile.qualified
            ]
            if not qualified:
                continue
            initiated = sum(profile.internally_initiated for profile in qualified)
            established = sum(profile.established for profile in qualified)
            contribution = min(
                15.0,
                (initiated_points if initiated else 0.0)
                + (established_points if established else 0.0),
            )
            if contribution <= 0:
                continue
            rows = [row for profile in qualified for row in profile.rows]
            result.append(
                _base_evidence(
                    candidate,
                    "TCP_SESSION_QUALITY",
                    self.name,
                    contribution,
                    rows,
                    {
                        "outbound_initiated_connections": initiated,
                        "established_connections": established,
                        "qualified_tcp_connections": len(qualified),
                        "scan_suppressed_connections": sum(
                            profile.scan_like or key in suppressed
                            for key, profile in connections.items()
                        ),
                        "sample_count": len(rows),
                    },
                    "내부 SYN 시작 또는 양방향 ACK/Payload로 TCP 세션 신뢰도 확인",
                )
            )
        return result


DEFAULT_DETECTORS: tuple[Detector, ...] = (
    CommonDestinationDetector(),
    NonWellKnownPortDetector(),
    PeriodicBeaconDetector(),
    SingleHostCompositeBeaconDetector(),
    AnalystPayloadSignatureDetector(),
    SynchronizedCommunicationDetector(),
    CommandAttackDetector(),
    PersistenceRarityDetector(),
    ProtocolSimilarityDetector(),
    MultiSensorDetector(),
    PopulationAnomalyDetector(),
    TCPSessionQualityDetector(),
)


def run_detectors(
    context: AnalysisContext, detectors: Iterable[Detector] = DEFAULT_DETECTORS
) -> list[Evidence]:
    primary: list[Evidence] = []
    tcp_enrichment: list[Evidence] = []
    anomaly: list[Evidence] = []
    for detector in detectors:
        produced = detector.analyze(context)
        if detector.name == "ml_population_anomaly":
            anomaly.extend(produced)
        elif detector.name == "tcp_session_quality":
            tcp_enrichment.extend(produced)
        else:
            primary.extend(produced)

    supported_candidates = {evidence.candidate_ip for evidence in primary}
    tcp_enrichment = [
        evidence for evidence in tcp_enrichment if evidence.candidate_ip in supported_candidates
    ]

    # Safe default: population anomaly enriches candidates supported by another
    # detector. Standalone anomaly-only hunting must be enabled explicitly.
    if anomaly and not bool(context.parameters.get("ml_anomaly_allow_standalone", False)):
        anomaly = [
            evidence for evidence in anomaly if evidence.candidate_ip in supported_candidates
        ]
    return primary + tcp_enrichment + anomaly
