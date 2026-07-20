from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import timedelta

from .domain import AnalysisContext, Detector, Evidence, Flow


def _candidate_host(context: AnalysisContext, flow: Flow) -> tuple[str, str] | None:
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
            ports = Counter(
                flow.destination_port if context.is_internal(flow.source_ip) else flow.source_port
                for _, flow in rows
            )
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
            if (
                flow.direction == "INBOUND"
                and context.is_internal(flow.destination_ip)
                and not context.is_internal(flow.source_ip)
            ):
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
                    f.destination_port if context.is_internal(f.source_ip) else f.source_port,
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
    PeriodicBeaconDetector(),
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
