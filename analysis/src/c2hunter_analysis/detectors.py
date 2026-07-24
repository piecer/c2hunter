from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta

from .domain import AnalysisContext, Detector, Evidence, Flow
from .payload_features import simhash_hamming_distance


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
    grouped: dict[str, list[tuple[str, Flow]]] = defaultdict(list)
    for flow in context.scoped_flows():
        role = _candidate_host(context, flow)
        if role:
            grouped[role[0]].append((role[1], flow))
    return grouped


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
            public_dns_ntp_servers = {
                str(value) for value in context.parameters.get("public_dns_ntp_servers", ())
            }
            service_ports = {port for port in ports if port is not None}
            public_dns_ntp = (
                candidate in public_dns_ntp_servers
                and len(service_ports) == 1
                and service_ports <= {53, 123}
                and all(flow.protocol.upper() == "UDP" for _, flow in rows)
            )
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
            if isinstance(value, int | str)
            and str(value).isdigit()
            and 0 <= int(value) <= 65535
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
            metrics: dict[str, object] = {
                "signature_id": str(signature["id"]),
                "signature_name": str(signature.get("name", signature["id"])),
                "signature_version": int(signature.get("version", 1)),
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
                    metrics,
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
        if raw_service_port is not None and _service_port(context, flow) != int(raw_service_port):
            return None

        signature_hash = str(signature.get("payload_hash") or "")
        flow_hashes = {
            value
            for value in (flow.payload_hash, flow.last_payload_hash)
            if value
        }
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
        max_distance = int(signature.get("simhash_max_distance", 8))
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
        source_length = int(raw_length)
        length_difference = abs(flow.payload_length - source_length)
        length_tolerance = max(
            16,
            round(source_length * float(signature.get("length_tolerance_ratio", 0.15))),
        )
        entropy_difference = abs(flow.payload_entropy - float(raw_entropy))
        entropy_tolerance = float(signature.get("entropy_tolerance", 0.75))
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
        inbound: dict[str, list[tuple[str, Flow]]] = defaultdict(list)
        for flow in all_flows:
            if flow.direction.upper() == "INBOUND":
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
        for candidate, rows in _groups(context).items():
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
                "rarity": 1 / max(1, len(_groups(context))),
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
)


def run_detectors(
    context: AnalysisContext, detectors: Iterable[Detector] = DEFAULT_DETECTORS
) -> list[Evidence]:
    return [evidence for detector in detectors for evidence in detector.analyze(context)]
