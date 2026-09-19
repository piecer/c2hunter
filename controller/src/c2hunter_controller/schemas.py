from __future__ import annotations

import hashlib
import math
import re
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Any, Literal

from c2hunter_analysis.scoring import DEFAULT_DETECTOR_WEIGHTS, MAX_DETECTOR_WEIGHT
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .network_ai import NetworkFailureDiagnostic


class Direction(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BIDIRECTIONAL = "BIDIRECTIONAL"
    UNKNOWN = "UNKNOWN"


class CaptureDirection(StrEnum):
    INBOUND = "INBOUND"
    OUTBOUND = "OUTBOUND"
    BIDIRECTIONAL = "BIDIRECTIONAL"


class SensorStatus(StrEnum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    DEGRADED = "DEGRADED"
    CAPTURING = "CAPTURING"
    ERROR = "ERROR"


class CaptureSource(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str = Field(min_length=1, max_length=15)
    direction: CaptureDirection
    bpf_filter: str = Field(default="", max_length=2000)
    enabled: bool = True
    store_pcap: bool = False
    validation_status: str | None = Field(default=None, pattern=r"^VALID$")

    @field_validator("interface")
    @classmethod
    def safe_linux_interface(cls, value: str) -> str:
        # Linux IFNAMSIZ is 16 including NUL. Exclude whitespace, slashes and shell metacharacters.
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", value):
            raise ValueError("interface must be a safe Linux interface name (1-15 characters)")
        return value


class SensorConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    capture_sources: list[CaptureSource] = Field(min_length=1, max_length=128)
    internal_networks: list[str] = Field(min_length=1, max_length=1024)

    @model_validator(mode="after")
    def normalize_and_validate(self) -> SensorConfiguration:
        names = [source.interface for source in self.capture_sources]
        if len(names) != len(set(names)):
            raise ValueError("capture source interfaces must be unique")
        if not any(source.enabled for source in self.capture_sources):
            raise ValueError("at least one capture source must be enabled")
        self.internal_networks = [
            str(ip_network(network, strict=False)) for network in self.internal_networks
        ]
        if len(self.internal_networks) != len(set(self.internal_networks)):
            raise ValueError("internal_networks must be unique")
        return self


class EnrollmentCreate(SensorConfiguration):
    name: str = Field(min_length=1, max_length=200)
    expires_in_seconds: int = Field(gt=0, le=604800)


class DiscoveredInterface(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=15)
    mac_address: str | None = Field(default=None, min_length=11, max_length=32)

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        return CaptureSource.safe_linux_interface(value)


class EnrollmentClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hostname: str = Field(min_length=1, max_length=255)
    agent_version: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=128)
    kernel_version: str = Field(min_length=1, max_length=128)
    capabilities: list[str] = Field(default_factory=list, max_length=128)
    discovered_interfaces: list[DiscoveredInterface] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def unique_interfaces(self) -> EnrollmentClaim:
        names = [interface.name for interface in self.discovered_interfaces]
        if len(names) != len(set(names)):
            raise ValueError("discovered interface names must be unique")
        return self


class SensorConfigurationUpdate(SensorConfiguration):
    config_version: int = Field(ge=1)


class EnrollmentCreateResponse(BaseModel):
    enrollment_id: str
    enrollment_token: str
    install_command: str
    expires_at: datetime


class ValidatedCaptureSource(BaseModel):
    interface: str
    direction: CaptureDirection
    bpf_filter: str
    enabled: bool
    store_pcap: bool = False
    validation_status: str = Field(pattern=r"^VALID$")


class ActiveCaptureJob(BaseModel):
    job_id: str
    start_time: datetime
    end_time: datetime
    store_pcap: bool
    max_packets: int | None = Field(default=None, ge=0)
    max_bytes: int | None = Field(default=None, ge=0)
    bpf_filter: str | None = Field(default=None)


class EnrollmentClaimResponse(BaseModel):
    sensor_id: str
    agent_token: str
    config_version: int
    capture_sources: list[ValidatedCaptureSource]
    capture_jobs: list[ActiveCaptureJob] = Field(default_factory=list)
    internal_networks: list[str]
    heartbeat_interval_seconds: int
    config_poll_interval_seconds: int


class SensorConfigurationResponse(BaseModel):
    config_version: int
    capture_sources: list[ValidatedCaptureSource]
    capture_jobs: list[ActiveCaptureJob] = Field(default_factory=list)
    internal_networks: list[str]


_SENSOR_PCAP_METADATA_EXAMPLE: dict[str, Any] = {
    "id": "8f9756c2c95f35b536155ba0acdd926d3bdca13a2bd433f6b9f0d18f120366f3",
    "sensor_id": "sensor-1",
    "sensor_name": "edge sensor",
    "analysis_job_id": "live-analysis-1",
    "filename": "eth0-000001.pcap",
    "size_bytes": 24,
    "sha256": "d92c6a81b2ff9e7893465d5e141eb80a0f37e74f33446f727ec14919dd1d1d88",
    "uploaded_at": "2026-08-25T00:00:00Z",
}


class SensorPcapMetadata(BaseModel):
    model_config = ConfigDict(
        extra="forbid", json_schema_extra={"examples": [_SENSOR_PCAP_METADATA_EXAMPLE]}
    )

    id: str
    sensor_id: str
    sensor_name: str
    analysis_job_id: str | None = None
    filename: str
    size_bytes: int
    sha256: str
    uploaded_at: datetime


class SensorPcapUploadResponse(SensorPcapMetadata):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={
            "examples": [
                {
                    **_SENSOR_PCAP_METADATA_EXAMPLE,
                    "segment_id": _SENSOR_PCAP_METADATA_EXAMPLE["id"],
                }
            ]
        },
    )

    segment_id: str


class SensorPcapListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[SensorPcapMetadata]
    total: int
    page: int
    page_size: int


class SensorInterface(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    mac_address: str | None = Field(default=None, min_length=11, max_length=32)
    direction: Direction


class SensorRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sensor_id: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    name: str = Field(min_length=1, max_length=200)
    hostname: str = Field(min_length=1, max_length=255)
    agent_version: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=128)
    kernel_version: str = Field(min_length=1, max_length=128)
    interfaces: list[SensorInterface] = Field(min_length=1, max_length=128)
    capabilities: list[str]
    current_time: datetime
    available_disk_bytes: int = Field(ge=0)
    received_packets: int = Field(ge=0)
    dropped_packets: int = Field(ge=0)


class HeartbeatInterface(BaseModel):
    model_config = ConfigDict(extra="forbid")
    interface: str = Field(min_length=1, max_length=128)
    direction: Direction
    status: SensorStatus
    received_packets: int = Field(ge=0)
    dropped_packets: int = Field(ge=0)
    last_error: str | None = Field(default=None, max_length=2000)


class CaptureCompletion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,200}$")
    stop_reason: str = Field(pattern=r"^(MAX_PACKETS|MAX_BYTES)$")


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reported_at: datetime
    status: SensorStatus
    cpu_percent: float = Field(ge=0, le=100)
    memory_percent: float = Field(ge=0, le=100)
    disk_percent: float = Field(ge=0, le=100)
    active_job_ids: list[str]
    received_packets: int = Field(ge=0)
    dropped_packets: int = Field(ge=0)
    pending_bytes: int = Field(ge=0)
    pcap_dropped_packets: int = Field(default=0, ge=0)
    completed_capture_jobs: list[CaptureCompletion] = Field(default_factory=list, max_length=128)
    last_error: str | None = Field(default=None, max_length=2000)
    interfaces: list[HeartbeatInterface] = Field(default_factory=list)
    discovered_interfaces: list[DiscoveredInterface] | None = Field(
        default=None, min_length=1, max_length=128
    )

    @model_validator(mode="after")
    def unique_discovered_interfaces(self) -> Heartbeat:
        if self.discovered_interfaces is None:
            return self
        names = [interface.name for interface in self.discovered_interfaces]
        if len(names) != len(set(names)):
            raise ValueError("discovered interface names must be unique")
        return self


class SensorGroupCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=1000)
    sensor_ids: list[str] = Field(min_length=1)

    @field_validator("sensor_ids")
    @classmethod
    def unique_sensors(cls, value: list[str]) -> list[str]:
        if len(value) != len(set(value)):
            raise ValueError("sensor_ids must be unique")
        return value


class CaptureParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    duration_seconds: int | None = Field(default=None, gt=0, le=86400)
    max_packets: int | None = Field(default=None, gt=0)
    max_bytes: int | None = Field(default=None, gt=0)
    directions: list[Direction] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    bpf_filter: str = Field(default="", max_length=2000)
    store_pcap: bool = False


class AnalysisParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module: Literal["c2", "network_anomaly", "ddos_attack"] = "c2"
    profile: str = Field(default="ddos_botnet", min_length=1, max_length=100)
    minimum_distinct_clients: int = Field(default=3, ge=2, le=100000)
    minimum_candidate_score: int = Field(default=0, ge=0, le=100)
    command_correlation_window_seconds: int = Field(default=10, ge=1, le=30)
    periodicity_min_samples: int = Field(default=5, ge=3, le=100000)
    well_known_port_max: int = Field(default=1023, ge=0, le=65535)
    non_well_known_port_min_ratio: float = Field(default=0.75, ge=0, le=1)
    non_well_known_port_min_observations: int = Field(default=2, ge=1, le=100000)
    non_well_known_port_exclusions: list[int] = Field(default_factory=list)
    high_volume_bytes_threshold: int = Field(default=50 * 1024 * 1024, ge=0)
    high_volume_packet_threshold: int = Field(default=100000, ge=0)
    high_volume_penalty: int = Field(default=30, ge=0, le=100)
    high_volume_tcp_session_bytes_threshold: int = Field(default=50 * 1024 * 1024, ge=0)
    high_volume_tcp_session_packet_threshold: int = Field(default=100000, ge=0)
    high_volume_tcp_session_score_cap: int = Field(default=20, ge=0, le=100)
    tcp_session_gating_enabled: bool = True
    tcp_allow_legacy_without_flags: bool = True
    tcp_outbound_initiated_contribution: int = Field(default=5, ge=0, le=15)
    tcp_established_contribution: int = Field(default=10, ge=0, le=15)
    tcp_scan_suppression_enabled: bool = True
    tcp_scan_min_targets: int = Field(default=8, ge=2, le=100000)
    tcp_scan_probe_max_packets: int = Field(default=4, ge=1, le=100)
    tcp_scan_probe_ratio: float = Field(default=0.8, ge=0, le=1)
    tcp_syn_retry_detection_enabled: bool = True
    tcp_syn_retry_min_intervals: int = Field(default=3, ge=3, le=15)
    tcp_syn_retry_min_interval_ms: int = Field(default=500, ge=1, le=300_000)
    tcp_syn_retry_max_interval_ms: int = Field(default=120_000, ge=1, le=300_000)
    tcp_syn_retry_max_interval_multiple: int = Field(default=8, ge=1, le=32)
    tcp_syn_retry_absolute_tolerance_ms: int = Field(default=250, ge=0, le=10_000)
    tcp_syn_retry_tolerance_ratio: float = Field(default=0.20, ge=0, le=0.5)
    # This optional policy excludes outbound sessions for which completion was
    # not observed. Missing replies can also mean capture loss or asymmetry, so
    # the default remains fail-open.
    tcp_require_established_outbound: bool = False
    detector_weights: dict[str, float] = Field(
        default_factory=lambda: dict(DEFAULT_DETECTOR_WEIGHTS)
    )
    ml_anomaly_enabled: bool = False
    ml_anomaly_allow_standalone: bool = False
    ml_anomaly_min_population: int = Field(default=30, ge=8, le=100000)
    ml_anomaly_min_candidate_samples: int = Field(default=5, ge=3, le=100000)
    ml_anomaly_z_threshold: float = Field(default=3.5, ge=2.0, le=20.0)
    ml_anomaly_feature_z_floor: float = Field(default=1.0, ge=0.0, le=10.0)
    ml_anomaly_min_directional_features: int = Field(default=2, ge=1, le=6)
    ml_anomaly_contribution_cap: float = Field(default=5.0, ge=0.0, le=5.0)
    ddos_bucket_seconds: int = Field(default=1, ge=1, le=60, strict=True)
    ddos_min_duration_seconds: int = Field(default=3, ge=1, le=3600, strict=True)
    ddos_min_source_count: int = Field(default=20, ge=2, le=100000, strict=True)
    ddos_min_packet_count: int = Field(default=1000, ge=1, le=2**63 - 1, strict=True)
    ddos_min_packets_per_second: int = Field(default=100, ge=1, le=10_000_000, strict=True)
    ddos_min_bits_per_second: int = Field(default=1_000_000, ge=1, le=10**13, strict=True)
    ddos_baseline_min_buckets: int = Field(default=20, ge=5, le=3600, strict=True)
    ddos_baseline_ratio: float = Field(
        default=5.0, ge=1.0, le=1000.0, allow_inf_nan=False, strict=True
    )
    ddos_mad_z_threshold: float = Field(
        default=6.0, ge=2.0, le=100.0, allow_inf_nan=False, strict=True
    )
    ddos_protocol_share_threshold: float = Field(
        default=0.80, ge=0.5, le=1.0, allow_inf_nan=False, strict=True
    )
    ddos_tcp_flag_share_threshold: float = Field(
        default=0.80, ge=0.5, le=1.0, allow_inf_nan=False, strict=True
    )
    ddos_response_ratio_max: float = Field(
        default=0.20, ge=0.0, le=1.0, allow_inf_nan=False, strict=True
    )
    ddos_reflection_port_share_threshold: float = Field(
        default=0.60, ge=0.5, le=1.0, allow_inf_nan=False, strict=True
    )
    ddos_reflection_min_average_packet_bytes: int = Field(default=256, ge=1, le=65535, strict=True)
    ddos_overlap_window_seconds: int = Field(default=10, ge=1, le=300, strict=True)

    @field_validator("detector_weights", mode="before")
    @classmethod
    def normalize_detector_weights(cls, value: object) -> dict[str, float]:
        if not isinstance(value, dict):
            raise ValueError("detector_weights must be an object")
        unknown = set(value) - set(DEFAULT_DETECTOR_WEIGHTS)
        if unknown:
            raise ValueError(f"unknown detector weights: {sorted(unknown)}")
        normalized = dict(DEFAULT_DETECTOR_WEIGHTS)
        for name, raw_weight in value.items():
            if isinstance(raw_weight, bool) or not isinstance(raw_weight, int | float):
                raise ValueError(f"detector weight {name} must be numeric")
            weight = float(raw_weight)
            if not math.isfinite(weight) or not 0 <= weight <= MAX_DETECTOR_WEIGHT:
                raise ValueError(
                    f"detector weight {name} must be between 0 and {MAX_DETECTOR_WEIGHT:g}"
                )
            normalized[str(name)] = weight
        return normalized

    @model_validator(mode="after")
    def ordered_syn_retry_interval_bounds(self) -> AnalysisParameters:
        if self.tcp_syn_retry_max_interval_ms < self.tcp_syn_retry_min_interval_ms:
            raise ValueError("TCP SYN retry maximum interval must not be below minimum interval")
        return self


DDoSAttackType = Literal[
    "TCP_SYN_FLOOD",
    "TCP_ACK_FLOOD",
    "TCP_RST_FLOOD",
    "UDP_FLOOD",
    "ICMP_ECHO_FLOOD",
    "ICMP_FLOOD",
    "POSSIBLE_REFLECTION_AMPLIFICATION",
    "MULTI_VECTOR",
]
DDoSObjective = Literal[
    "CONNECTION_STATE_EXHAUSTION",
    "BANDWIDTH_EXHAUSTION",
    "PACKET_PROCESSING_EXHAUSTION",
    "REFLECTED_BANDWIDTH_EXHAUSTION",
    "MULTI_RESOURCE_EXHAUSTION",
]
_DDOS_RECOMMENDATION_CODES = frozenset(
    {
        "PRESERVE_CAPTURE_AND_LOGS",
        "VERIFY_SERVICE_IMPACT",
        "CONTACT_UPSTREAM_PROVIDER",
        "MONITOR_RECOVERY_AND_FALSE_POSITIVES",
        "ENABLE_SYN_PROXY_OR_COOKIES",
        "APPLY_EDGE_SYN_RATE_LIMIT",
        "CHECK_SYN_BACKLOG_AND_CONNTRACK",
        "ENGAGE_SCRUBBING_OR_FLOWSPEC",
        "FILTER_OR_RATE_LIMIT_UNUSED_UDP_SERVICES",
        "VALIDATE_REFLECTION_SOURCE_PORTS",
        "RATE_LIMIT_NONESSENTIAL_ICMP",
        "PRESERVE_PMTUD_AND_REQUIRED_ICMP",
        "APPLY_STATEFUL_TCP_VALIDATION",
        "RATE_LIMIT_INVALID_TCP_FLAGS",
        "CHECK_MIDDLEBOX_RESET_SOURCES",
        "ISOLATE_INTERNAL_SOURCES",
        "APPLY_EGRESS_RATE_LIMIT",
        "ENFORCE_EGRESS_ANTISPOOFING",
    }
)
_DDOS_COMMON_RECOMMENDATIONS = (
    "PRESERVE_CAPTURE_AND_LOGS",
    "VERIFY_SERVICE_IMPACT",
    "CONTACT_UPSTREAM_PROVIDER",
    "MONITOR_RECOVERY_AND_FALSE_POSITIVES",
)
_DDOS_TYPE_RECOMMENDATIONS: dict[str, tuple[str, ...]] = {
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
_DDOS_OUTBOUND_RECOMMENDATIONS = (
    "ISOLATE_INTERNAL_SOURCES",
    "APPLY_EGRESS_RATE_LIMIT",
    "ENFORCE_EGRESS_ANTISPOOFING",
)
_DDOS_WARNING_CODES = frozenset(
    {
        "INPUT_RECORD_LIMIT_REACHED",
        "BASELINE_UNAVAILABLE",
        "SAMPLE_WINDOW_SHORT",
        "DOS_LIKE_TRAFFIC",
        "AMBIGUOUS_DIRECTION",
        "INCOMPLETE_RECORDS",
        "TARGET_LIMIT_REACHED",
        "BUCKET_LIMIT_REACHED",
        "FINDING_LIMIT_REACHED",
        "DUPLICATE_CAPTURE_NOT_EXCLUDED",
        "PARSER_SKIPPED_PACKETS",
        "SENSOR_DROPS_REPORTED",
        "SENSOR_CLOCK_SKEW",
        "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
        "PARTIAL_CAPTURE",
    }
)
_DDOS_LIMITATION_CODES = frozenset(
    {
        "NO_FINDING_DOES_NOT_PROVE_HEALTH",
        "OBSERVED_SOURCES_ARE_NOT_CONFIRMED_ATTACKERS",
        "TRAFFIC_SHAPE_DOES_NOT_PROVE_SERVICE_IMPACT",
        "APPLICATION_LAYER_FLOODS_NOT_CLASSIFIED",
    }
)
_DDOS_UNCERTAINTY_CODES = frozenset(
    {
        "BASELINE_UNAVAILABLE",
        "TCP_RESPONSE_VISIBILITY_UNKNOWN",
        "TCP_PAYLOAD_VISIBILITY_UNKNOWN",
        "SUBSTANTIAL_TCP_RESPONSES_OBSERVED",
        "ACK_TRAFFIC_MAY_BE_LEGITIMATE",
        "RESETS_MAY_BE_DEFENSIVE_RESPONSES",
        "AMPLIFICATION_RATIO_UNOBSERVED",
        "SOURCE_SPOOFING_UNCONFIRMED",
        "ICMP_TYPE_UNAVAILABLE",
        "SHARED_TARGET_DOES_NOT_PROVE_SHARED_ACTOR",
        "BUCKET_LIMIT_REACHED",
    }
)


class DDoSTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(min_length=1, max_length=45)
    port: int | None = Field(ge=0, le=65535)

    @field_validator("ip")
    @classmethod
    def valid_ip(cls, value: str) -> str:
        return str(ip_address(value))


class DDoSMetrics(BaseModel):
    model_config = ConfigDict(extra="forbid")

    packet_count: int | None = Field(default=None, ge=0, le=2**63 - 1)
    byte_count: int | None = Field(default=None, ge=0, le=2**63 - 1)
    record_count: int | None = Field(default=None, ge=0, le=2_000_000)
    duration_seconds: float | None = Field(
        default=None, ge=0, le=315_537_897_600, allow_inf_nan=False
    )
    average_packets_per_second: float | None = Field(
        default=None, ge=0, le=2**53 - 1, allow_inf_nan=False
    )
    average_bits_per_second: float | None = Field(
        default=None, ge=0, le=10**18, allow_inf_nan=False
    )
    peak_packets_per_second: float | None = Field(
        default=None, ge=0, le=2**53 - 1, allow_inf_nan=False
    )
    peak_bits_per_second: float | None = Field(default=None, ge=0, le=10**18, allow_inf_nan=False)
    peak_is_lower_bound: bool | None = None
    measurement_precision: Literal["PACKET", "AGGREGATED_FLOW", "MIXED"] | None = None
    baseline_packets_per_second: float | None = Field(
        default=None, ge=0, le=2**53 - 1, allow_inf_nan=False
    )
    baseline_ratio: float | None = Field(default=None, ge=0, le=10**18, allow_inf_nan=False)
    robust_z_score: float | None = Field(default=None, ge=0, le=10**18, allow_inf_nan=False)
    distinct_sources: int | None = Field(default=None, ge=0, le=2_000_000)
    distinct_sensors: int | None = Field(default=None, ge=0, le=2_000_000)
    direction_source: Literal["OBSERVED", "INTERNAL_CIDR"] | None = None
    syn_only_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    ack_only_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    rst_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    fin_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    payload_packet_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    response_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    dominant_reflection_source_port: int | None = Field(default=None, ge=0, le=65535)
    reflection_source_port_ratio: float | None = Field(
        default=None, ge=0, le=1, allow_inf_nan=False
    )
    average_packet_bytes: float | None = Field(
        default=None, ge=0, le=2**53 - 1, allow_inf_nan=False
    )
    amplification_ratio: None = None
    icmp_type_observed_packets: int | None = Field(default=None, ge=0, le=2**63 - 1)
    icmp_echo_request_ratio: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    component_types: list[DDoSAttackType] | None = Field(default=None, max_length=8)
    component_finding_count: int | None = Field(default=None, ge=2, le=4096)


class DDoSFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^ddos-[0-9a-f]{16}$")
    attack_type: DDoSAttackType
    attack_role: Literal["VICTIM_SIDE_INBOUND", "PARTICIPANT_SIDE_OUTBOUND"]
    target: DDoSTarget
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPV6", "MULTIPLE"]
    objective: DDoSObjective
    likelihood: Literal["LIKELY", "POSSIBLE"]
    severity: Literal["MEDIUM", "HIGH", "CRITICAL"]
    confidence: Literal["high", "medium", "low"]
    first_seen: datetime
    last_seen: datetime
    metrics: DDoSMetrics
    evidence_codes: list[str] = Field(max_length=8)
    uncertainty_codes: list[str] = Field(max_length=8)
    recommendation_codes: list[str] = Field(max_length=8)

    @model_validator(mode="after")
    def ordered_time(self) -> DDoSFinding:
        if self.last_seen < self.first_seen:
            raise ValueError("DDoS finding last_seen must not precede first_seen")
        if not set(self.recommendation_codes) <= _DDOS_RECOMMENDATION_CODES:
            raise ValueError("DDoS finding contains an unknown recommendation code")
        if not set(self.uncertainty_codes) <= _DDOS_UNCERTAINTY_CODES:
            raise ValueError("DDoS finding contains an unknown uncertainty code")
        allowed_evidence = {
            "VOLUME_GATE_MET",
            "DISTRIBUTED_SOURCE_GATE_MET",
            "OVERLAPPING_ATTACK_VECTORS",
            f"{self.attack_type}_SHAPE",
        }
        if not set(self.evidence_codes) <= allowed_evidence:
            raise ValueError("DDoS finding contains an unknown evidence code")
        if self.attack_type == "MULTI_VECTOR":
            required_metrics = {"component_types", "component_finding_count"}
            required_evidence = {"OVERLAPPING_ATTACK_VECTORS"}
            expected_protocols = {"MULTIPLE"}
            component_types = self.metrics.component_types or []
            if (
                len(component_types) < 2
                or len(component_types) != len(set(component_types))
                or "MULTI_VECTOR" in component_types
                or (self.metrics.component_finding_count or 0) < len(component_types)
            ):
                raise ValueError("DDoS multi-vector components are inconsistent")
        else:
            required_metrics = {
                "packet_count",
                "byte_count",
                "record_count",
                "duration_seconds",
                "average_packets_per_second",
                "average_bits_per_second",
                "peak_packets_per_second",
                "peak_bits_per_second",
                "peak_is_lower_bound",
                "measurement_precision",
                "baseline_packets_per_second",
                "baseline_ratio",
                "robust_z_score",
                "distinct_sources",
                "distinct_sensors",
                "direction_source",
            }
            required_evidence = {
                "VOLUME_GATE_MET",
                "DISTRIBUTED_SOURCE_GATE_MET",
                f"{self.attack_type}_SHAPE",
            }
            if self.attack_type.startswith("TCP_"):
                required_metrics |= {
                    "syn_only_ratio",
                    "ack_only_ratio",
                    "rst_ratio",
                    "fin_ratio",
                    "payload_packet_ratio",
                    "response_ratio",
                }
                expected_protocols = {"TCP"}
            elif self.attack_type in {"UDP_FLOOD", "POSSIBLE_REFLECTION_AMPLIFICATION"}:
                required_metrics |= {
                    "dominant_reflection_source_port",
                    "reflection_source_port_ratio",
                    "average_packet_bytes",
                    "amplification_ratio",
                }
                expected_protocols = {"UDP"}
            else:
                required_metrics |= {"icmp_type_observed_packets", "icmp_echo_request_ratio"}
                expected_protocols = {"ICMP", "ICMPV6"}
        if self.metrics.model_fields_set != required_metrics:
            raise ValueError("DDoS finding measured facts do not match its attack type")
        if set(self.evidence_codes) != required_evidence:
            raise ValueError("DDoS finding evidence gates are inconsistent")
        if self.protocol not in expected_protocols:
            raise ValueError("DDoS finding protocol is inconsistent with attack type")
        uncertainty = set(self.uncertainty_codes)
        required_uncertainty = {
            "TCP_ACK_FLOOD": {"ACK_TRAFFIC_MAY_BE_LEGITIMATE"},
            "TCP_RST_FLOOD": {"RESETS_MAY_BE_DEFENSIVE_RESPONSES"},
            "POSSIBLE_REFLECTION_AMPLIFICATION": {
                "AMPLIFICATION_RATIO_UNOBSERVED",
                "SOURCE_SPOOFING_UNCONFIRMED",
            },
            "MULTI_VECTOR": {"SHARED_TARGET_DOES_NOT_PROVE_SHARED_ACTOR"},
        }.get(self.attack_type, set())
        if not required_uncertainty <= uncertainty:
            raise ValueError("DDoS finding is missing mandatory family uncertainty")
        if self.attack_type == "MULTI_VECTOR" and uncertainty != required_uncertainty:
            raise ValueError("DDoS multi-vector uncertainty is inconsistent")
        if self.attack_type != "MULTI_VECTOR":
            required_values = (
                self.metrics.packet_count,
                self.metrics.byte_count,
                self.metrics.record_count,
                self.metrics.duration_seconds,
                self.metrics.average_packets_per_second,
                self.metrics.average_bits_per_second,
                self.metrics.peak_is_lower_bound,
                self.metrics.measurement_precision,
                self.metrics.distinct_sources,
                self.metrics.distinct_sensors,
                self.metrics.direction_source,
            )
            if any(value is None for value in required_values):
                raise ValueError("DDoS finding is missing required measured facts")
            baseline_unavailable = (
                self.metrics.baseline_ratio is None and self.metrics.robust_z_score is None
            )
            if ("BASELINE_UNAVAILABLE" in uncertainty) != baseline_unavailable:
                raise ValueError("DDoS baseline uncertainty is inconsistent")
            if self.likelihood == "LIKELY" and (
                baseline_unavailable
                or {
                    "TCP_RESPONSE_VISIBILITY_UNKNOWN",
                    "TCP_PAYLOAD_VISIBILITY_UNKNOWN",
                    "SUBSTANTIAL_TCP_RESPONSES_OBSERVED",
                }
                & uncertainty
            ):
                raise ValueError("likely DDoS finding has limiting uncertainty")
        if self.attack_type.startswith("TCP_") and any(
            value is None
            for value in (
                self.metrics.syn_only_ratio,
                self.metrics.ack_only_ratio,
                self.metrics.rst_ratio,
                self.metrics.fin_ratio,
                self.metrics.payload_packet_ratio,
            )
        ):
            raise ValueError("DDoS TCP finding is missing required ratios")
        if self.attack_type == "TCP_SYN_FLOOD" and (
            (self.metrics.response_ratio is None)
            != ("TCP_RESPONSE_VISIBILITY_UNKNOWN" in self.uncertainty_codes)
        ):
            raise ValueError("DDoS TCP response uncertainty is inconsistent")
        if self.attack_type in {"UDP_FLOOD", "POSSIBLE_REFLECTION_AMPLIFICATION"} and any(
            value is None
            for value in (
                self.metrics.reflection_source_port_ratio,
                self.metrics.average_packet_bytes,
            )
        ):
            raise ValueError("DDoS UDP finding is missing required metrics")
        if self.attack_type in {"ICMP_ECHO_FLOOD", "ICMP_FLOOD"}:
            if (
                self.metrics.icmp_type_observed_packets is None
                or self.metrics.icmp_echo_request_ratio is None
            ):
                raise ValueError("DDoS ICMP finding is missing required metrics")
            partial_types = self.metrics.icmp_type_observed_packets < (
                self.metrics.packet_count or 0
            )
            if ("ICMP_TYPE_UNAVAILABLE" in self.uncertainty_codes) != partial_types:
                raise ValueError("DDoS ICMP type uncertainty is inconsistent")
        identity = (
            f"{self.attack_role}|{self.target.ip}|MULTI_VECTOR|"
            + "|".join(sorted(self.metrics.component_types or []))
            if self.attack_type == "MULTI_VECTOR"
            else (
                f"{self.attack_role}|{self.target.ip}|{self.target.port}|"
                f"{self.protocol}|{self.attack_type}"
            )
        )
        expected_id = "ddos-" + hashlib.sha256(identity.encode()).hexdigest()[:16]
        if self.id != expected_id:
            raise ValueError("DDoS finding ID is inconsistent")
        if self.attack_type == "POSSIBLE_REFLECTION_AMPLIFICATION" and (
            self.attack_role != "VICTIM_SIDE_INBOUND" or self.likelihood != "POSSIBLE"
        ):
            raise ValueError("DDoS reflection semantics are inconsistent")
        expected_severity = (
            "CRITICAL"
            if self.attack_type == "MULTI_VECTOR" and self.likelihood == "LIKELY"
            else "HIGH"
            if self.attack_type == "MULTI_VECTOR" or self.likelihood == "LIKELY"
            else "MEDIUM"
        )
        if self.severity != expected_severity:
            raise ValueError("DDoS finding severity is inconsistent")
        if (
            self.attack_type == "MULTI_VECTOR"
            and self.likelihood == "POSSIBLE"
            and (self.confidence == "high")
        ):
            raise ValueError("DDoS multi-vector confidence is inconsistent")
        if "DISTRIBUTED_SOURCE_GATE_MET" in self.evidence_codes and (
            self.metrics.distinct_sources is None or self.metrics.distinct_sources < 1
        ):
            raise ValueError("DDoS distributed-source evidence is inconsistent")
        if self.attack_type == "TCP_SYN_FLOOD":
            expected_objective = "CONNECTION_STATE_EXHAUSTION"
        elif self.attack_type in {"TCP_ACK_FLOOD", "TCP_RST_FLOOD"}:
            expected_objective = "PACKET_PROCESSING_EXHAUSTION"
        elif self.attack_type == "POSSIBLE_REFLECTION_AMPLIFICATION":
            expected_objective = "REFLECTED_BANDWIDTH_EXHAUSTION"
        elif self.attack_type == "MULTI_VECTOR":
            expected_objective = "MULTI_RESOURCE_EXHAUSTION"
        else:
            average_bytes = (self.metrics.byte_count or 0) / max(1, self.metrics.packet_count or 0)
            expected_objective = (
                "PACKET_PROCESSING_EXHAUSTION" if average_bytes < 128 else "BANDWIDTH_EXHAUSTION"
            )
        if self.objective != expected_objective:
            raise ValueError("DDoS finding objective is inconsistent")
        expected_recommendations = list(_DDOS_TYPE_RECOMMENDATIONS[self.attack_type])
        if self.attack_role == "PARTICIPANT_SIDE_OUTBOUND":
            expected_recommendations.extend(_DDOS_OUTBOUND_RECOMMENDATIONS)
        expected_recommendations.extend(_DDOS_COMMON_RECOMMENDATIONS)
        if self.recommendation_codes != list(dict.fromkeys(expected_recommendations))[:8]:
            raise ValueError("DDoS finding recommendations are inconsistent")
        for codes in (self.evidence_codes, self.uncertainty_codes, self.recommendation_codes):
            if len(codes) != len(set(codes)):
                raise ValueError("DDoS finding code arrays must not contain duplicates")
        return self


class DDoSRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(min_length=1, max_length=100)
    priority: int = Field(ge=1, le=100)
    scope: Literal["UPSTREAM", "LOCAL"]
    rationale_code: str = Field(min_length=1, max_length=128)
    caveat_code: str = Field(min_length=1, max_length=128)
    requires_human_approval: Literal[True]

    @model_validator(mode="after")
    def known_code(self) -> DDoSRecommendation:
        if self.code not in _DDOS_RECOMMENDATION_CODES:
            raise ValueError("unknown DDoS recommendation code")
        if self.rationale_code != f"{self.code}_RATIONALE":
            raise ValueError("DDoS recommendation rationale does not match its code")
        if self.caveat_code != f"{self.code}_CAVEAT":
            raise ValueError("DDoS recommendation caveat does not match its code")
        expected_scope = (
            "UPSTREAM"
            if self.code in {"CONTACT_UPSTREAM_PROVIDER", "ENGAGE_SCRUBBING_OR_FLOWSPEC"}
            else "LOCAL"
        )
        if self.scope != expected_scope:
            raise ValueError("DDoS recommendation scope does not match its code")
        return self


class DDoSSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scanned_records: int = Field(ge=0, le=2_000_001)
    evaluated_records: int = Field(ge=0, le=2_000_000)
    skipped_records: int = Field(ge=0, le=2_000_000)
    incomplete_records: int = Field(ge=0, le=2_000_000)
    target_count: int = Field(ge=0, le=4096)
    finding_count: int = Field(ge=0, le=6144)
    displayed_finding_count: int = Field(ge=0, le=100)
    packet_count: int = Field(ge=0, le=2**53 - 1)
    byte_count: int = Field(ge=0, le=2**53 - 1)
    first_seen: datetime | None
    last_seen: datetime | None
    coverage_complete: bool
    counts_are_lower_bounds: bool
    truncated: bool
    primary_attack_type: DDoSAttackType | None
    primary_objective: DDoSObjective | None


class DDoSAttackReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: Literal["ddos-attack-report-v1"]
    catalog_version: Literal["ddos-taxonomy-v1"]
    verdict: Literal[
        "attack_likely", "suspicious_traffic", "no_clear_attack", "insufficient_evidence"
    ]
    confidence: Literal["high", "medium", "low", "unknown"]
    primary_finding_id: str | None
    summary: DDoSSummary
    findings: list[DDoSFinding] = Field(max_length=100)
    recommendations: list[DDoSRecommendation] = Field(max_length=100)
    warnings: list[str] = Field(max_length=16)
    limitations: list[str] = Field(max_length=8)
    omitted_finding_count: int = Field(ge=0, le=6144)

    @model_validator(mode="before")
    @classmethod
    def strict_wire_scalars(cls, value: object) -> object:
        if not isinstance(value, dict):
            return value
        summary = value.get("summary")
        integer_summary = {
            "scanned_records",
            "evaluated_records",
            "skipped_records",
            "incomplete_records",
            "target_count",
            "finding_count",
            "displayed_finding_count",
            "packet_count",
            "byte_count",
        }
        if isinstance(summary, dict):
            if any(type(summary.get(name)) is not int for name in integer_summary):
                raise ValueError("DDoS summary counters must be JSON integers")
            if any(
                type(summary.get(name)) is not bool
                for name in {"coverage_complete", "counts_are_lower_bounds", "truncated"}
            ):
                raise ValueError("DDoS summary flags must be JSON booleans")
        if type(value.get("omitted_finding_count")) is not int:
            raise ValueError("DDoS omitted finding count must be a JSON integer")
        integer_metrics = {
            "packet_count",
            "byte_count",
            "record_count",
            "distinct_sources",
            "distinct_sensors",
            "dominant_reflection_source_port",
            "icmp_type_observed_packets",
            "component_finding_count",
        }
        numeric_metrics = integer_metrics | {
            "duration_seconds",
            "average_packets_per_second",
            "average_bits_per_second",
            "peak_packets_per_second",
            "peak_bits_per_second",
            "baseline_packets_per_second",
            "baseline_ratio",
            "robust_z_score",
            "syn_only_ratio",
            "ack_only_ratio",
            "rst_ratio",
            "fin_ratio",
            "payload_packet_ratio",
            "response_ratio",
            "reflection_source_port_ratio",
            "average_packet_bytes",
            "amplification_ratio",
            "icmp_echo_request_ratio",
        }
        findings = value.get("findings")
        if isinstance(findings, list):
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                target = finding.get("target")
                if isinstance(target, dict) and target.get("port") is not None:
                    if type(target.get("port")) is not int:
                        raise ValueError("DDoS target port must be a JSON integer")
                metrics = finding.get("metrics")
                if isinstance(metrics, dict):
                    if any(
                        name in metrics
                        and metrics[name] is not None
                        and type(metrics[name]) is not int
                        for name in integer_metrics
                    ):
                        raise ValueError("DDoS count metrics must be JSON integers")
                    if any(
                        name in metrics
                        and metrics[name] is not None
                        and type(metrics[name]) not in {int, float}
                        for name in numeric_metrics
                    ):
                        raise ValueError("DDoS numeric metrics must be JSON numbers")
        recommendations = value.get("recommendations")
        if isinstance(recommendations, list) and any(
            isinstance(item, dict) and type(item.get("priority")) is not int
            for item in recommendations
        ):
            raise ValueError("DDoS recommendation priorities must be JSON integers")
        return value

    @model_validator(mode="after")
    def internally_consistent(self) -> DDoSAttackReport:
        if (
            self.summary.evaluated_records + self.summary.skipped_records
            > self.summary.scanned_records
        ):
            raise ValueError("DDoS scanned record count is inconsistent")
        if self.summary.finding_count != len(self.findings) + self.omitted_finding_count:
            raise ValueError("DDoS finding counters are inconsistent")
        if self.summary.displayed_finding_count != len(self.findings):
            raise ValueError("DDoS displayed finding count is inconsistent")
        lower_bound_codes = {
            "INPUT_RECORD_LIMIT_REACHED",
            "TARGET_LIMIT_REACHED",
            "BUCKET_LIMIT_REACHED",
            "FINDING_LIMIT_REACHED",
            "PARSER_SKIPPED_PACKETS",
            "SENSOR_DROPS_REPORTED",
            "PARTIAL_CAPTURE",
        }
        coverage_codes = lower_bound_codes | {
            "SENSOR_CLOCK_SKEW",
            "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
            "DUPLICATE_CAPTURE_NOT_EXCLUDED",
        }
        expected_lower_bound = bool(lower_bound_codes & set(self.warnings)) or (
            self.summary.skipped_records > 0 or self.summary.incomplete_records > 0
        )
        if self.summary.counts_are_lower_bounds != expected_lower_bound:
            raise ValueError("DDoS lower-bound coverage flag is inconsistent")
        expected_coverage = (
            self.summary.evaluated_records > 0
            and self.summary.skipped_records == 0
            and self.summary.incomplete_records == 0
            and not coverage_codes & set(self.warnings)
        )
        if self.summary.coverage_complete != expected_coverage:
            raise ValueError("DDoS complete coverage flag is inconsistent")
        if self.summary.truncated != (
            self.omitted_finding_count > 0 or self.summary.counts_are_lower_bounds
        ):
            raise ValueError("DDoS truncation flag is inconsistent")
        ids = {item.id for item in self.findings}
        if len(ids) != len(self.findings):
            raise ValueError("DDoS finding IDs must be unique")
        if self.primary_finding_id is not None and self.primary_finding_id not in ids:
            raise ValueError("DDoS primary finding is not retained")
        if bool(self.findings) != bool(self.primary_finding_id):
            raise ValueError("DDoS primary finding presence is inconsistent")
        primary = next((item for item in self.findings if item.id == self.primary_finding_id), None)
        if (primary.attack_type if primary else None) != self.summary.primary_attack_type or (
            primary.objective if primary else None
        ) != self.summary.primary_objective:
            raise ValueError("DDoS primary summary is inconsistent")
        base_findings = [item for item in self.findings if item.attack_type != "MULTI_VECTOR"]
        base_targets = {
            (item.attack_role, item.target.ip, item.target.port, item.protocol)
            for item in base_findings
        }
        if len(base_targets) > self.summary.target_count:
            raise ValueError("DDoS finding targets exceed the report summary")
        if (
            sum(item.metrics.packet_count or 0 for item in base_findings)
            > self.summary.packet_count
        ):
            raise ValueError("DDoS finding packet totals exceed the report summary")
        if sum(item.metrics.byte_count or 0 for item in base_findings) > self.summary.byte_count:
            raise ValueError("DDoS finding byte totals exceed the report summary")
        if self.findings and (
            self.summary.first_seen is None
            or self.summary.last_seen is None
            or any(
                item.first_seen < self.summary.first_seen or item.last_seen > self.summary.last_seen
                for item in self.findings
            )
        ):
            raise ValueError("DDoS finding times exceed the report summary")
        has_likely = any(item.likelihood == "LIKELY" for item in self.findings)
        evidence_limited = not self.summary.coverage_complete
        if has_likely and evidence_limited:
            raise ValueError("likely DDoS findings require complete sufficient evidence")
        if self.findings:
            expected_verdict = "attack_likely" if has_likely else "suspicious_traffic"
        elif (
            self.summary.coverage_complete
            and "SAMPLE_WINDOW_SHORT" not in self.warnings
            and "DOS_LIKE_TRAFFIC" not in self.warnings
        ):
            expected_verdict = "no_clear_attack"
        else:
            expected_verdict = "insufficient_evidence"
        if self.verdict != expected_verdict:
            raise ValueError("DDoS report verdict is inconsistent")
        for finding in self.findings:
            sample_limited = finding.attack_type != "MULTI_VECTOR" and (
                (finding.metrics.record_count or 0) < 100
                or (finding.metrics.duration_seconds or 0) < 10
            )
            if finding.likelihood == "LIKELY" and sample_limited:
                raise ValueError("likely DDoS finding has insufficient target-local evidence")
            if evidence_limited or sample_limited:
                expected = "low"
            elif finding.likelihood == "LIKELY":
                expected = "high"
            elif finding.attack_type == "MULTI_VECTOR":
                expected = finding.confidence
            else:
                expected = "medium"
            if finding.confidence != expected or (
                finding.attack_type == "MULTI_VECTOR" and expected not in {"low", "medium", "high"}
            ):
                raise ValueError("DDoS finding confidence is inconsistent")
        expected_confidence = {
            "attack_likely": "high",
            "no_clear_attack": "low",
            "insufficient_evidence": "unknown",
        }.get(self.verdict)
        if self.verdict == "suspicious_traffic":
            expected_confidence = (
                "low"
                if not self.summary.coverage_complete
                or all(finding.confidence == "low" for finding in self.findings)
                else "medium"
            )
        if self.confidence != expected_confidence:
            raise ValueError("DDoS report confidence is inconsistent")
        expected_codes = {
            code for finding in self.findings for code in finding.recommendation_codes
        }
        actual_codes = [item.code for item in self.recommendations]
        if expected_codes != set(actual_codes) or len(actual_codes) != len(set(actual_codes)):
            raise ValueError("DDoS recommendation relationships are inconsistent")
        if [item.priority for item in self.recommendations] != list(
            range(1, len(self.recommendations) + 1)
        ):
            raise ValueError("DDoS recommendation priorities must be contiguous")
        if not set(self.warnings) <= _DDOS_WARNING_CODES:
            raise ValueError("DDoS report contains an unknown warning code")
        if len(self.warnings) != len(set(self.warnings)):
            raise ValueError("DDoS report warnings must not contain duplicates")
        if set(self.limitations) != _DDOS_LIMITATION_CODES or len(self.limitations) != len(
            _DDOS_LIMITATION_CODES
        ):
            raise ValueError("DDoS report must preserve all mandatory limitations")
        self._finite(self.model_dump(mode="python"))
        return self

    @classmethod
    def _finite(cls, value: object) -> None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("DDoS report contains a non-finite number")
        if isinstance(value, dict):
            for child in value.values():
                cls._finite(child)
        elif isinstance(value, list | tuple):
            for child in value:
                cls._finite(child)


class TCPSYNOnlyObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    offset_us: int = Field(ge=0, le=31_536_000_000_000)
    sequence: int = Field(ge=0, le=2**32 - 1)


class ICMPQuotedFlow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_ip: str = Field(min_length=1, max_length=45)
    destination_ip: str = Field(min_length=1, max_length=45)
    source_port: int = Field(ge=0, le=65535, strict=True)
    destination_port: int = Field(ge=0, le=65535, strict=True)
    protocol: Literal["TCP", "UDP"]


class FlowRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sensor_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str
    direction: Direction
    packet_count: int = Field(default=1, ge=1)
    total_bytes: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0, ge=0, le=31_536_000, allow_inf_nan=False)
    tcp_flags: dict[str, int | float] | None = Field(default=None)

    @field_validator("tcp_flags", mode="before")
    @classmethod
    def validate_tcp_flags(cls, value: object) -> dict[str, int | float] | None:
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError("tcp_flags must be an object or null")
        normalized: dict[str, int | float] = {}
        for key, val in value.items():
            name = str(key).strip().lower()
            if not name or len(name) > 64:
                raise ValueError("TCP flag name must contain 1 to 64 characters")
            if name in normalized:
                raise ValueError(f"duplicate TCP flag: {name}")
            if not isinstance(val, int | float) or isinstance(val, bool):
                raise ValueError(f"tcp_flags[{key}] must be numeric")
            count: int | float = val
            if isinstance(val, float):
                if not math.isfinite(val):
                    raise ValueError(f"tcp_flags[{key}] must be finite")
                if val < 0:
                    raise ValueError(f"tcp_flags[{key}] must be non-negative")
                if val > 2**64 - 1:
                    raise ValueError(f"tcp_flags[{key}] exceeds uint64")
                if name not in {"rst_ratio", "syn_ack_ratio"}:
                    if not val.is_integer():
                        raise ValueError(f"tcp_flags[{key}] must be an integer count")
                    count = int(val)

            if count < 0:
                raise ValueError(f"tcp_flags[{key}] must be non-negative")
            if count > 2**64 - 1:
                raise ValueError(f"tcp_flags[{key}] exceeds uint64")
            normalized[name] = count
        return normalized

    payload_hash: str | None = None
    last_payload_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    payload_prefix_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    payload_sample_hex: str | None = Field(
        default=None, max_length=512, pattern=r"^(?:[0-9a-fA-F]{2})+$"
    )
    payload_length: int | None = Field(default=None, ge=0)
    payload_entropy: float | None = Field(default=None, ge=0, le=8)
    payload_printable_ratio: float | None = Field(default=None, ge=0, le=1)
    payload_simhash: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    payload_feature_version: str | None = Field(default=None, pattern=r"^[0-9]{1,8}$")
    tls_fingerprint: str | None = None
    certificate_fingerprint: str | None = None
    domain: str | None = None
    packet_sizes: tuple[int, ...] = ()
    tcp_flags_observed: bool = False
    tcp_syn_count: int = Field(default=0, ge=0)
    tcp_ack_count: int = Field(default=0, ge=0)
    tcp_rst_count: int = Field(default=0, ge=0)
    tcp_syn_only_count: int = Field(default=0, ge=0)
    tcp_syn_ack_count: int = Field(default=0, ge=0)
    tcp_ack_only_count: int = Field(default=0, ge=0)
    tcp_syn_only_observations: list[TCPSYNOnlyObservation] | None = Field(
        default=None, max_length=16
    )
    tcp_syn_only_observations_truncated: bool = False
    bidirectional: bool = False
    tcp_sequence: int | None = Field(default=None, ge=0, le=2**32 - 1)
    tcp_acknowledgment: int | None = Field(default=None, ge=0, le=2**32 - 1)
    tcp_window: int | None = Field(default=None, ge=0, le=65535)
    transport_payload_length: int | None = Field(default=None, ge=0)
    transport_payload_packet_count: int | None = Field(default=None, ge=0, strict=True)
    ip_ttl: int | None = Field(default=None, ge=0, le=255)
    capture_interface_id: int | None = Field(default=None, ge=0)
    packet_evidence_complete: bool = False
    icmp_type: int | None = Field(default=None, ge=0, le=255, strict=True)
    icmp_code: int | None = Field(default=None, ge=0, le=255, strict=True)
    icmp_error: bool = Field(default=False, strict=True)
    icmp_quoted_flow: ICMPQuotedFlow | None = None

    raw_packet_hex: str | None = Field(default=None, pattern=r"^(?:[0-9a-fA-F]{2})+$")

    @model_validator(mode="after")
    def valid_tcp_flag_metadata(self) -> FlowRecord:
        counters = (
            self.tcp_syn_count,
            self.tcp_ack_count,
            self.tcp_rst_count,
            self.tcp_syn_only_count,
            self.tcp_syn_ack_count,
            self.tcp_ack_only_count,
        )
        if not self.tcp_flags_observed and any(counters):
            raise ValueError("TCP flag counters require tcp_flags_observed")
        if self.tcp_flags_observed and self.protocol.upper() != "TCP":
            raise ValueError("tcp_flags_observed is valid only for TCP records")
        if any(counter > self.packet_count for counter in counters):
            raise ValueError("TCP flag counter exceeds packet_count")
        if (
            self.transport_payload_packet_count is not None
            and self.transport_payload_packet_count > self.packet_count
        ):
            raise ValueError("transport payload packet count exceeds packet_count")
        if self.tcp_syn_only_count + self.tcp_syn_ack_count > self.tcp_syn_count:
            raise ValueError("TCP SYN combination counters exceed tcp_syn_count")
        if self.tcp_syn_ack_count + self.tcp_ack_only_count > self.tcp_ack_count:
            raise ValueError("TCP ACK combination counters exceed tcp_ack_count")
        if (
            self.tcp_syn_only_count
            + self.tcp_syn_ack_count
            + self.tcp_ack_only_count
            + self.tcp_rst_count
            > self.packet_count
        ):
            raise ValueError("mutually exclusive TCP shape counters exceed packet_count")
        if self.tcp_syn_only_observations is not None:
            if not self.tcp_flags_observed or self.protocol.upper() != "TCP":
                raise ValueError("TCP SYN observations require observed TCP metadata")
            offsets = [observation.offset_us for observation in self.tcp_syn_only_observations]
            if offsets != sorted(set(offsets)):
                raise ValueError("TCP SYN observation offsets must be unique and increasing")
            if offsets and offsets[-1] > round(self.duration_seconds * 1_000_000):
                raise ValueError("TCP SYN observation offset exceeds flow duration")
            if (
                not self.tcp_syn_only_observations_truncated
                and len(self.tcp_syn_only_observations) != self.tcp_syn_only_count
            ):
                raise ValueError("complete TCP SYN observations must match SYN-only count")
        elif self.tcp_syn_only_observations_truncated:
            raise ValueError("truncated TCP SYN observations require an observation array")
        return self


class FlowBatchCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    batch_id: str = Field(pattern=r"^[A-Za-z0-9_.:-]{1,200}$")
    records: list[FlowRecord] = Field(min_length=1, max_length=100000)

    @model_validator(mode="after")
    def sensor_ids_match(self) -> FlowBatchCreate:
        if len({record.sensor_id for record in self.records}) != 1:
            raise ValueError("all records in a batch must belong to one sensor")
        return self


class AnalysisJobCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=200)
    idempotency_key: str = Field(min_length=1, max_length=200)
    sensor_ids: list[str] = Field(min_length=1)
    sensor_group_id: str | None = None
    mode: str = Field(pattern=r"^(LIVE|HISTORICAL|REANALYSIS|PCAP_UPLOAD)$")
    start_time: datetime
    end_time: datetime
    capture: CaptureParameters
    analysis: AnalysisParameters
    internal_networks: list[str] = Field(min_length=1, max_length=256)
    flow_records: list[FlowRecord] = Field(default_factory=list)

    @field_validator("internal_networks")
    @classmethod
    def bounded_internal_networks(cls, values: list[str]) -> list[str]:
        if any(len(value) > 64 for value in values):
            raise ValueError("internal network is too long")
        normalized = [str(ip_network(value, strict=False)) for value in values]
        if len(normalized) != len(set(normalized)):
            raise ValueError("internal networks must be unique")
        return normalized

    @model_validator(mode="after")
    def valid_range(self) -> AnalysisJobCreate:
        if self.end_time <= self.start_time:
            raise ValueError("end_time must be after start_time")
        if len(self.sensor_ids) != len(set(self.sensor_ids)):
            raise ValueError("sensor_ids must be unique")
        return self


class AnalysisJobUpdate(BaseModel):
    """Mutable analyst metadata; captured data and detector parameters stay immutable."""

    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=5000)

    @field_validator("name")
    @classmethod
    def nonblank_name(cls, value: str | None) -> str | None:
        if value is None:
            raise ValueError("name must not be null")
        normalized = value.strip()
        if not normalized:
            raise ValueError("name must not be blank")
        return normalized

    @model_validator(mode="after")
    def contains_change(self) -> AnalysisJobUpdate:
        if not self.model_fields_set:
            raise ValueError("at least one mutable field is required")
        return self


class DevLoginRequest(BaseModel):
    """Input for the opt-in development-only token helper."""

    model_config = ConfigDict(extra="forbid")
    username: str = Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")


class CancelRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str = Field(default="operator requested", min_length=1, max_length=1000)


class ReanalysisRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idempotency_key: str = Field(min_length=1, max_length=200)
    minimum_candidate_score: int | None = Field(default=None, ge=0, le=100)
    minimum_distinct_clients: int | None = Field(default=None, ge=2)
    detector_weights: dict[str, float] | None = None
    ddos_min_source_count: int | None = Field(default=None, ge=2, le=100000, strict=True)
    ddos_min_packet_count: int | None = Field(default=None, ge=1, le=2**63 - 1, strict=True)
    ddos_min_packets_per_second: int | None = Field(default=None, ge=1, le=10_000_000, strict=True)
    ddos_min_bits_per_second: int | None = Field(default=None, ge=1, le=10**13, strict=True)
    ddos_bucket_seconds: int | None = Field(default=None, ge=1, le=60, strict=True)
    ddos_min_duration_seconds: int | None = Field(default=None, ge=1, le=3600, strict=True)
    ddos_baseline_min_buckets: int | None = Field(default=None, ge=5, le=3600, strict=True)
    ddos_baseline_ratio: float | None = Field(
        default=None, ge=1, le=1000, allow_inf_nan=False, strict=True
    )
    ddos_mad_z_threshold: float | None = Field(
        default=None, ge=2, le=100, allow_inf_nan=False, strict=True
    )
    ddos_protocol_share_threshold: float | None = Field(
        default=None, ge=0.5, le=1, allow_inf_nan=False, strict=True
    )
    ddos_tcp_flag_share_threshold: float | None = Field(
        default=None, ge=0.5, le=1, allow_inf_nan=False, strict=True
    )
    ddos_response_ratio_max: float | None = Field(
        default=None, ge=0, le=1, allow_inf_nan=False, strict=True
    )
    ddos_reflection_port_share_threshold: float | None = Field(
        default=None, ge=0.5, le=1, allow_inf_nan=False, strict=True
    )
    ddos_reflection_min_average_packet_bytes: int | None = Field(
        default=None, ge=1, le=65535, strict=True
    )
    ddos_overlap_window_seconds: int | None = Field(default=None, ge=1, le=300, strict=True)

    @field_validator("detector_weights", mode="before")
    @classmethod
    def validate_detector_weights(cls, value: object) -> dict[str, float] | None:
        if value is None:
            return None
        return AnalysisParameters.normalize_detector_weights(value)


class DetectorWeightPresetCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    detector_weights: dict[str, float]
    set_as_default: bool = False

    @field_validator("detector_weights", mode="before")
    @classmethod
    def validate_detector_weights(cls, value: object) -> dict[str, float]:
        return AnalysisParameters.normalize_detector_weights(value)


class DetectorWeightPresetUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    detector_weights: dict[str, float] | None = None
    set_as_default: bool | None = None

    @field_validator("detector_weights", mode="before")
    @classmethod
    def validate_detector_weights(cls, value: object) -> dict[str, float] | None:
        if value is None:
            return None
        return AnalysisParameters.normalize_detector_weights(value)

    @model_validator(mode="after")
    def rejects_null_resource_fields(self) -> DetectorWeightPresetUpdate:
        resource_fields = {"name", "description", "detector_weights"}
        if not self.model_fields_set or (
            not self.model_fields_set & resource_fields and self.set_as_default is not True
        ):
            raise ValueError("at least one preset change is required")
        if any(getattr(self, field) is None for field in self.model_fields_set & resource_fields):
            raise ValueError("preset resource fields must not be null")
        return self


class FlowLabelCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    flow_id: str = Field(pattern=r"^[0-9a-f]{24}$")
    verdict: str = Field(pattern=r"^(C2|BENIGN)$")
    confidence: str = Field(pattern=r"^(CONFIRMED|HIGH|MEDIUM)$")
    note: str = Field(min_length=1, max_length=5000)
    create_signature: bool = False
    signature_name: str | None = Field(default=None, min_length=1, max_length=200)
    signature_description: str = Field(default="", max_length=2000)

    @model_validator(mode="after")
    def signature_requires_c2_verdict(self) -> FlowLabelCreate:
        if self.create_signature and self.verdict != "C2":
            raise ValueError("only a C2 label can create a payload signature")
        return self


class PayloadSignatureUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    length_tolerance_ratio: float | None = Field(default=None, ge=0, le=1)
    entropy_tolerance: float | None = Field(default=None, ge=0, le=4)
    simhash_max_distance: int | None = Field(default=None, ge=0, le=32)

    @model_validator(mode="after")
    def contains_update(self) -> PayloadSignatureUpdate:
        if not self.model_fields_set:
            raise ValueError("at least one signature field is required")
        if any(getattr(self, field) is None for field in self.model_fields_set):
            raise ValueError("signature fields must not be null")
        return self


class AllowlistCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(
        pattern=r"^(IP|CIDR|DOMAIN_SUFFIX|TLS_FINGERPRINT|CERT_FINGERPRINT|TRUSTED_DNS|TRUSTED_NTP)$"
    )
    value: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=1000)
    expires_at: datetime | None = None
    enabled: bool = True

    @field_validator("expires_at", mode="before")
    @classmethod
    def expiration_is_iso_string(cls, value: object) -> object:
        if value is not None and not isinstance(value, str):
            raise ValueError("expires_at must be an ISO 8601 string")
        if isinstance(value, str) and "T" not in value.upper():
            raise ValueError("expires_at must be an ISO 8601 datetime string")
        return value

    @model_validator(mode="after")
    def normalize(self) -> AllowlistCreate:
        if self.type in {"IP", "TRUSTED_DNS", "TRUSTED_NTP"}:
            self.value = str(ip_address(self.value))
        elif self.type == "CIDR":
            self.value = str(ip_network(self.value, strict=False))
        elif self.type == "DOMAIN_SUFFIX":
            self.value = self.value.lower().strip().lstrip(".").rstrip(".")
        else:
            self.value = self.value.lower().strip()
        if self.expires_at is not None:
            if self.expires_at.utcoffset() is None:
                raise ValueError("expires_at must include a timezone offset or Z")
            self.expires_at = self.expires_at.astimezone(UTC)
            if self.expires_at <= datetime.now(UTC):
                raise ValueError("expires_at must be in the future")
        return self


class PcapFlowFilter(BaseModel):
    model_config = ConfigDict(extra="forbid")

    candidate_ip: str | None = None
    protocol: str | None = Field(default=None, max_length=32)
    port: int | None = Field(default=None, ge=0, le=65535)
    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    direction: Direction | None = None
    has_payload: bool | None = None

    @model_validator(mode="after")
    def normalize_and_require_condition(self) -> PcapFlowFilter:
        if self.candidate_ip:
            self.candidate_ip = str(ip_network(self.candidate_ip, strict=False))
        if self.protocol:
            self.protocol = self.protocol.strip().upper() or None
        if all(value is None for value in self.model_dump().values()):
            raise ValueError("flow filter must contain an active condition")
        return self


class PcapExportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str
    candidate_id: str | None = None
    internal_host_ip: str | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    direction: Direction | None = None
    sensor_id: str | None = None
    include_filters: list[PcapFlowFilter] = Field(default_factory=list, max_length=20)
    exclude_filters: list[PcapFlowFilter] = Field(default_factory=list, max_length=20)
    idempotency_key: str | None = Field(default=None, min_length=1, max_length=128)

    @model_validator(mode="after")
    def valid_range(self) -> PcapExportCreate:
        if self.start_time and self.end_time and self.end_time < self.start_time:
            raise ValueError("end_time must not precede start_time")
        if self.internal_host_ip:
            self.internal_host_ip = str(ip_address(self.internal_host_ip))
        return self


class PcapExportSource(BaseModel):
    id: str
    sha256: str


class PcapExportProgress(BaseModel):
    phase: Literal[
        "QUEUED",
        "SNAPSHOT_VALIDATION",
        "SOURCE_FETCH",
        "SOURCE_SCAN",
        "FILTER",
        "SERIALIZE",
        "PUBLISH",
        "TERMINAL",
    ]
    percent: int = Field(ge=0, le=100)
    scanned_source_bytes: int = Field(ge=0)
    scanned_packet_count: int = Field(ge=0)
    matched_packet_count: int = Field(ge=0)
    exported_packet_count: int = Field(ge=0)


class PcapExportJobResponse(BaseModel):
    """Truthful state-conditional lifecycle response for sync and async exports."""

    model_config = ConfigDict(
        json_schema_extra={
            "allOf": [
                {
                    "if": {"properties": {"status": {"const": "COMPLETED"}}},
                    "then": {
                        "required": [
                            "download_url",
                            "matched_packet_count",
                            "exported_packet_count",
                            "omitted_packet_count",
                            "truncated",
                            "truncation_reasons",
                            "size_bytes",
                            "sha256",
                            "capture_format",
                            "filename",
                            "filter",
                            "source_capture_count",
                            "scanned_source_capture_count",
                            "omitted_source_capture_count",
                            "source_total_bytes",
                            "scanned_source_bytes",
                            "scanned_packet_count",
                            "output_byte_limit",
                            "source_scan_byte_limit",
                            "source_scan_packet_limit",
                            "source_manifest",
                        ]
                    },
                }
            ]
        }
    )

    id: str
    job_id: str
    candidate_id: str | None
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]
    execution_mode: Literal["SYNC", "ASYNC"]
    progress: PcapExportProgress
    cancellation_requested: bool
    attempt: int = Field(ge=0)
    max_attempts: int = Field(ge=1)
    queued_at: datetime | None = None
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    next_attempt_at: datetime | None = None
    status_url: str
    download_url: str | None = None
    error_code: str | None = None
    error: str | None = None
    matched_packet_count: int | None = None
    exported_packet_count: int | None = None
    omitted_packet_count: int | None = None
    truncated: bool | None = None
    truncation_reasons: list[str] | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    capture_format: Literal["PCAP", "PCAPNG"] | None = None
    filename: str | None = None
    filter: dict[str, Any] | None = None
    source_capture_count: int | None = None
    scanned_source_capture_count: int | None = None
    omitted_source_capture_count: int | None = None
    source_total_bytes: int | None = None

    scanned_source_bytes: int | None = None
    scanned_packet_count: int | None = None
    output_byte_limit: int | None = None
    source_scan_byte_limit: int | None = None
    source_scan_packet_limit: int | None = None
    source_manifest: list[PcapExportSource] | None = None

    @model_validator(mode="after")
    def artifact_state_is_truthful(self) -> PcapExportJobResponse:
        terminal_fields = (
            self.download_url,
            self.matched_packet_count,
            self.exported_packet_count,
            self.omitted_packet_count,
            self.truncated,
            self.truncation_reasons,
            self.size_bytes,
            self.sha256,
            self.capture_format,
            self.filename,
            self.filter,
            self.source_capture_count,
            self.scanned_source_capture_count,
            self.omitted_source_capture_count,
            self.source_total_bytes,
            self.scanned_source_bytes,
            self.scanned_packet_count,
            self.output_byte_limit,
            self.source_scan_byte_limit,
            self.source_scan_packet_limit,
            self.source_manifest,
        )
        if self.status in {"QUEUED", "RUNNING", "CANCELLED"} and any(
            value is not None for value in terminal_fields
        ):
            raise ValueError("active or cancelled exports cannot expose artifact metadata")
        if self.status == "COMPLETED" and any(value is None for value in terminal_fields):
            raise ValueError("completed exports require every terminal field")
        return self


class PcapExportCancel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    reason: str | None = Field(default=None, min_length=1, max_length=500)


class PcapExportResponse(BaseModel):
    id: str
    job_id: str
    source_job_id: str
    candidate_id: str | None
    status: Literal["COMPLETED", "FAILED"]
    matched_packet_count: int
    exported_packet_count: int
    omitted_packet_count: int
    truncated: bool
    truncation_reasons: list[str]
    size_bytes: int
    sha256: str
    capture_format: Literal["PCAP", "PCAPNG"]
    filename: str
    filter: dict[str, Any]
    source_capture_count: int
    scanned_source_capture_count: int
    omitted_source_capture_count: int
    source_total_bytes: int
    scanned_source_bytes: int
    scanned_packet_count: int
    output_byte_limit: int
    source_scan_byte_limit: int
    source_scan_packet_limit: int
    source_manifest: list[PcapExportSource]
    created_at: datetime
    error_code: str | None
    error: str | None


class CandidateUpdate(BaseModel):
    """후보 수정을 위한 스키마. 분석 결과의 메타데이터 수정."""

    model_config = ConfigDict(extra="forbid")
    score_adjustment: int | None = Field(default=None, ge=-100, le=100)
    exclude_reason: str | None = Field(
        default=None, min_length=1, max_length=500, description="후비 후보에서 제외된 이유"
    )

    @field_validator("score_adjustment")
    @classmethod
    def non_null_if_set(cls, v: int | None) -> int | None:
        return v


class CandidateVerdictCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: str = Field(pattern=r"^(CONFIRMED_C2|FALSE_POSITIVE|UNDER_REVIEW)$")
    confidence: str = Field(pattern=r"^(CONFIRMED|HIGH|MEDIUM|LOW)$")
    note: str = Field(min_length=1, max_length=5000)


class CandidateActionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(pattern=r"^(IN_PROGRESS|COMPLETED)$")
    note: str = Field(min_length=1, max_length=5000)


class MispExportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9-]+$",
    )
    comment: str = Field(default="C2Hunter confirmed C2 candidate", min_length=1, max_length=1000)


class IntegrationSettingsUpdate(BaseModel):
    """WebUI에서 관리하는 비밀이 아닌 외부 연동 운영 정책."""

    model_config = ConfigDict(extra="forbid")

    expected_version: int = Field(ge=0)
    virustotal_enabled: bool
    abuseipdb_enabled: bool
    misp_enabled: bool
    misp_url: str = Field(default="", max_length=2048)
    misp_verify_tls: bool = True
    threat_intel_timeout_seconds: float = Field(gt=0, le=30)
    threat_intel_request_delay_seconds: float | None = Field(default=None, ge=0, le=60)
    abuseipdb_max_age_days: int = Field(ge=1, le=365)
    abuseipdb_positive_threshold: int = Field(ge=0, le=100)
    candidate_auto_enrichment_enabled: bool
    candidate_auto_enrichment_limit: int = Field(ge=0, le=200)
    candidate_auto_enrichment_workers: int = Field(ge=1, le=16)
    candidate_auto_enrichment_queue_capacity: int = Field(ge=1, le=2000)
    management_event_id: str = Field(default="", max_length=100, pattern=r"^(?:|[A-Za-z0-9-]+)$")
    management_auto_register: bool = False
    immediate_action_event_id: str = Field(
        default="", max_length=100, pattern=r"^(?:|[A-Za-z0-9-]+)$"
    )
    immediate_action_auto_register: bool = False
    immediate_action_min_positive_providers: int = Field(default=2, ge=2, le=3)

    @model_validator(mode="after")
    def validate_misp_automation(self) -> IntegrationSettingsUpdate:
        if (
            self.management_event_id
            and self.immediate_action_event_id
            and self.management_event_id == self.immediate_action_event_id
        ):
            raise ValueError("management and immediate-action MISP events must differ")
        if self.management_auto_register and not self.management_event_id:
            raise ValueError(
                "management_event_id is required when automatic registration is enabled"
            )
        if self.immediate_action_auto_register and not self.immediate_action_event_id:
            raise ValueError(
                "immediate_action_event_id is required when automatic registration is enabled"
            )
        return self


class CandidateBulkOperationCreate(BaseModel):
    """목록에서 선택한 Candidate에 적용할 제한된 일괄 판정 명령."""

    model_config = ConfigDict(extra="forbid")

    candidate_ids: list[str] = Field(min_length=1, max_length=200)
    command: str = Field(pattern=r"^(UNDER_REVIEW|CONFIRMED_C2|FALSE_POSITIVE)$")
    confidence: str = Field(default="MEDIUM", pattern=r"^(CONFIRMED|HIGH|MEDIUM|LOW)$")
    note: str = Field(min_length=1, max_length=5000)

    @field_validator("candidate_ids")
    @classmethod
    def unique_candidate_ids(cls, value: list[str]) -> list[str]:
        if any(not candidate_id or len(candidate_id) > 200 for candidate_id in value):
            raise ValueError("candidate IDs must be between 1 and 200 characters")
        if len(set(value)) != len(value):
            raise ValueError("candidate IDs must be unique")
        return value


class CandidateResponse(BaseModel):
    """후보 단일 조회 응답 스키마."""

    id: str
    job_id: str
    candidate_ip: str
    score: int
    evidence: list[dict[str, Any]] = Field(default_factory=list)
    adjustments: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime | None = None


class CandidateListResponse(BaseModel):
    """후보 목록 조회 응답 스키마."""

    items: list[CandidateResponse] = Field(default_factory=list)
    total: int
    page: int
    page_size: int


class AIAnalysisRunResponse(BaseModel):
    # Existing runs have an extensible metadata envelope. Preserve those fields;
    # only the new diagnostic is a closed, strict public contract.
    model_config = ConfigDict(extra="allow")

    id: str
    status: str
    failure_diagnostic: NetworkFailureDiagnostic | None = None


class AIAnalysisRunListResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    items: list[AIAnalysisRunResponse]


class AIAnalysisRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=200)
    candidate_limit: int = Field(default=5, ge=1, le=5)
    analysis_kind: Literal["C2", "NETWORK_ANOMALY", "DDOS_ATTACK"] = "C2"
    language: Literal["ko", "en"] = "ko"
    allow_remote: bool = Field(default=False, strict=True)


class AIAnalysisRunCancel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=1000)


class AIArtifactReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    note: str = Field(min_length=1, max_length=2000)


class AIFeedbackCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    verdict: Literal[
        "CONFIRM_C2",
        "CONFIRM_BENIGN",
        "NEED_MORE_DATA",
        "REJECT_EXPLANATION",
    ]
    corrected_confidence: float | None = Field(default=None, ge=0, le=1)
    note: str = Field(min_length=1, max_length=5000)
