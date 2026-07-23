from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from ipaddress import ip_address, ip_network

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


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
    validation_status: str = Field(pattern=r"^VALID$")


class EnrollmentClaimResponse(BaseModel):
    sensor_id: str
    agent_token: str
    config_version: int
    capture_sources: list[ValidatedCaptureSource]
    internal_networks: list[str]
    heartbeat_interval_seconds: int
    config_poll_interval_seconds: int


class SensorConfigurationResponse(BaseModel):
    config_version: int
    capture_sources: list[ValidatedCaptureSource]
    internal_networks: list[str]


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
    interfaces: list[SensorInterface] = Field(min_length=1)
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
    last_error: str | None = Field(default=None, max_length=2000)
    interfaces: list[HeartbeatInterface] = Field(default_factory=list)


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
    profile: str = Field(default="ddos_botnet", min_length=1, max_length=100)
    minimum_distinct_clients: int = Field(default=3, ge=2, le=100000)
    minimum_candidate_score: int = Field(default=0, ge=0, le=100)
    command_correlation_window_seconds: int = Field(default=10, ge=1, le=30)
    periodicity_min_samples: int = Field(default=5, ge=3, le=100000)


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
    payload_hash: str | None = None
    payload_prefix_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    payload_length: int | None = Field(default=None, ge=0)
    payload_entropy: float | None = Field(default=None, ge=0, le=8)
    payload_printable_ratio: float | None = Field(default=None, ge=0, le=1)
    payload_simhash: str | None = Field(default=None, pattern=r"^[0-9a-f]{16}$")
    payload_feature_version: str | None = Field(default=None, pattern=r"^[0-9]{1,8}$")
    tls_fingerprint: str | None = None
    certificate_fingerprint: str | None = None
    domain: str | None = None
    packet_sizes: tuple[int, ...] = ()
    raw_packet_hex: str | None = Field(default=None, pattern=r"^(?:[0-9a-fA-F]{2})+$")


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
    internal_networks: list[str] = Field(min_length=1)
    flow_records: list[FlowRecord] = Field(default_factory=list)

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
    idempotency_key: str = Field(min_length=1, max_length=200)
    minimum_candidate_score: int | None = Field(default=None, ge=0, le=100)
    minimum_distinct_clients: int | None = Field(default=None, ge=2)


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
    type: str = Field(pattern=r"^(IP|CIDR|DOMAIN_SUFFIX|TLS_FINGERPRINT|CERT_FINGERPRINT)$")
    value: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=1000)
    expires_at: datetime | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def normalize(self) -> AllowlistCreate:
        if self.type == "IP":
            self.value = str(ip_address(self.value))
        elif self.type == "CIDR":
            self.value = str(ip_network(self.value, strict=False))
        elif self.type == "DOMAIN_SUFFIX":
            self.value = self.value.lower().strip().lstrip(".").rstrip(".")
        else:
            self.value = self.value.lower().strip()
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

    @model_validator(mode="after")
    def valid_range(self) -> PcapExportCreate:
        if self.start_time and self.end_time and self.end_time < self.start_time:
            raise ValueError("end_time must not precede start_time")
        if self.internal_host_ip:
            self.internal_host_ip = str(ip_address(self.internal_host_ip))
        return self
