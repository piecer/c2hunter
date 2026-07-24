from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any, Protocol


@dataclass(frozen=True)
class Flow:
    sensor_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int | None
    destination_port: int | None
    protocol: str
    direction: str
    packet_count: int = 1
    total_bytes: int = 0
    payload_hash: str | None = None
    payload_prefix_hash: str | None = None
    payload_length: int | None = None
    payload_entropy: float | None = None
    payload_printable_ratio: float | None = None
    payload_simhash: str | None = None
    payload_feature_version: str | None = None
    tls_fingerprint: str | None = None
    certificate_fingerprint: str | None = None
    domain: str | None = None
    packet_sizes: tuple[int, ...] = ()
    attack_target_ip: str | None = None
    duration_seconds: float = 0.0
    last_payload_hash: str | None = None


@dataclass(frozen=True)
class PacketObservation:
    sensor_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    ip_id: int
    tcp_sequence: int
    payload_length: int
    payload_hash: str
    direction: str = "UNKNOWN"


@dataclass(frozen=True)
class LogicalPacket:
    fingerprint: str
    observations: tuple[PacketObservation, ...]
    logical_count: int = 1


@dataclass(frozen=True)
class SensorOperationalState:
    sensor_id: str
    status: str
    clock_offset_ms: float = 0.0
    observed_packets: int | None = None
    loss_reason: str | None = None


@dataclass(frozen=True)
class OperationalMetadata:
    """Sidecar facts for capture properties that are not representable in a PCAP."""

    completed_sensors: tuple[str, ...]
    failed_sensors: tuple[str, ...]
    sensors: Mapping[str, SensorOperationalState]

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> OperationalMetadata:
        completed = cls._string_tuple(value.get("completed_sensors", ()))
        failed = cls._string_tuple(value.get("failed_sensors", ()))
        raw_sensors = value.get("sensors", {})
        if not isinstance(raw_sensors, Mapping):
            raise ValueError("operations.sensors must be a mapping")
        sensors: dict[str, SensorOperationalState] = {}
        for raw_sensor_id, raw_details in raw_sensors.items():
            if not isinstance(raw_sensor_id, str) or not isinstance(raw_details, Mapping):
                raise ValueError("each sensor operation must be a named mapping")
            status = raw_details.get("status")
            if not isinstance(status, str):
                raise ValueError(f"operations sensor {raw_sensor_id} requires status")
            raw_offset = raw_details.get("clock_offset_ms", 0)
            if not isinstance(raw_offset, int | float):
                raise ValueError(f"operations sensor {raw_sensor_id} has invalid clock offset")
            raw_observed = raw_details.get("observed_packets")
            if raw_observed is not None and not isinstance(raw_observed, int):
                raise ValueError(f"operations sensor {raw_sensor_id} has invalid packet count")
            raw_reason = raw_details.get("loss_reason")
            if raw_reason is not None and not isinstance(raw_reason, str):
                raise ValueError(f"operations sensor {raw_sensor_id} has invalid loss reason")
            sensors[raw_sensor_id] = SensorOperationalState(
                raw_sensor_id,
                status,
                float(raw_offset),
                raw_observed,
                raw_reason,
            )
        unknown = (set(completed) | set(failed)) - set(sensors)
        if unknown:
            raise ValueError(f"operations missing sensor details: {sorted(unknown)}")
        return cls(completed, failed, sensors)

    @staticmethod
    def _string_tuple(value: object) -> tuple[str, ...]:
        if not isinstance(value, list | tuple) or not all(isinstance(item, str) for item in value):
            raise ValueError("sensor lists must contain strings")
        return tuple(value)

    def sensor_status(self, sensor_id: str) -> str:
        return self.sensors[sensor_id].status

    @property
    def clock_offsets_ms(self) -> dict[str, float]:
        return {sensor_id: state.clock_offset_ms for sensor_id, state in self.sensors.items()}

    @property
    def completion_status(self) -> str:
        return "PARTIALLY_COMPLETED" if self.failed_sensors else "COMPLETED"

    @property
    def confidence(self) -> float:
        return 0.7 if "CLOCK_SKEW" in self.warnings else 1.0

    @property
    def warnings(self) -> tuple[str, ...]:
        return (
            ("CLOCK_SKEW",)
            if any(abs(state.clock_offset_ms) > 2000 for state in self.sensors.values())
            else ()
        )

    @property
    def loss_report(self) -> dict[str, str]:
        return {
            sensor_id: self.sensors[sensor_id].loss_reason or "sensor data unavailable"
            for sensor_id in self.failed_sensors
        }

    @property
    def loss_reported(self) -> bool:
        return bool(self.loss_report)


@dataclass(frozen=True)
class AllowlistEntry:
    type: str
    value: str
    description: str
    expires_at: datetime | None = None
    enabled: bool = True

    def matches(self, candidate_ip: str, evidence: Sequence[Evidence], now: datetime) -> bool:
        if not self.enabled or (self.expires_at is not None and self.expires_at <= now):
            return False
        kind = self.type.upper()
        if kind == "IP":
            return ip_address(candidate_ip) == ip_address(self.value)
        if kind == "CIDR":
            return ip_address(candidate_ip) in ip_network(self.value, strict=False)
        metrics = [item.metrics for item in evidence]
        if kind == "DOMAIN_SUFFIX":
            suffix = self.value.lower().lstrip(".")
            return any(
                str(m.get("domain", "")).lower().rstrip(".").endswith(suffix) for m in metrics
            )
        key = {
            "TLS_FINGERPRINT": "tls_fingerprint",
            "CERT_FINGERPRINT": "certificate_fingerprint",
        }.get(kind)
        return key is not None and any(m.get(key) == self.value for m in metrics)


@dataclass(frozen=True)
class Evidence:
    candidate_ip: str
    type: str
    detector: str
    version: str
    raw_score: float
    contribution: float
    description: str
    hosts: tuple[str, ...] = ()
    sensors: tuple[str, ...] = ()
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScoreAdjustment:
    kind: str
    points: int
    explanation: str


@dataclass(frozen=True)
class Candidate:
    candidate_ip: str
    score: int
    severity: str
    evidence: tuple[Evidence, ...]
    adjustments: tuple[ScoreAdjustment, ...]
    hosts: tuple[str, ...]
    sensors: tuple[str, ...]
    first_seen: datetime | None
    last_seen: datetime | None


@dataclass(frozen=True)
class AnalysisContext:
    dataset_id: str
    start: datetime
    end: datetime
    flows: Sequence[Flow]
    selected_sensors: tuple[str, ...] = ()
    internal_cidrs: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
    clock_offsets_ms: dict[str, float] = field(default_factory=dict)
    parameters: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.end <= self.start:
            raise ValueError("end must be after start")

    def is_internal(self, value: str) -> bool:
        address = ip_address(value)
        return any(address in ip_network(cidr, strict=False) for cidr in self.internal_cidrs)

    def scoped_flows(self) -> list[Flow]:
        sensors = set(self.selected_sensors)
        return [
            flow
            for flow in self.flows
            if self.start <= flow.timestamp <= self.end
            and (not sensors or flow.sensor_id in sensors)
        ]

    def candidate_traffic_profiles(self) -> dict[str, dict[str, int]]:
        """Aggregate all scoped traffic per external endpoint for score adjustments."""
        profiles: dict[str, dict[str, int]] = {}
        for flow in self.scoped_flows():
            direction = flow.direction.upper()
            if direction == "OUTBOUND":
                candidate_ip = flow.destination_ip
            elif direction == "INBOUND":
                candidate_ip = flow.source_ip
            else:
                source_internal = self.is_internal(flow.source_ip)
                destination_internal = self.is_internal(flow.destination_ip)
                if source_internal == destination_internal:
                    continue
                candidate_ip = flow.destination_ip if source_internal else flow.source_ip
            profile = profiles.setdefault(
                candidate_ip,
                {
                    "flow_count": 0,
                    "total_packets": 0,
                    "total_bytes": 0,
                },
            )
            profile["flow_count"] += 1
            profile["total_packets"] += max(0, int(flow.packet_count))
            profile["total_bytes"] += max(0, int(flow.total_bytes))
        return profiles


class Detector(Protocol):
    @property
    def name(self) -> str: ...

    @property
    def version(self) -> str: ...

    def analyze(self, context: AnalysisContext) -> list[Evidence]: ...
