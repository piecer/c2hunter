"""Versioned source/evidence contracts; no run or approval authority."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

VERSION: Literal["ip-evidence-v1"] = "ip-evidence-v1"
ToolName = Literal[
    "peer_overview",
    "peer_flow_samples",
    "peer_timeline",
    "peer_protocol_observations",
    "compare_peer_cohort",
]
MetricName = Literal[
    "matched_rows",
    "total_bytes",
    "packet_count",
    "sensor_count",
    "c2_eligible_rows",
    "suppressed_control_rows",
    "eligibility_unavailable_rows",
    "inbound_rows",
    "outbound_rows",
    "internal_rows",
    "unknown_rows",
    "inbound_bytes",
    "outbound_bytes",
    "internal_bytes",
    "unknown_bytes",
]
MetricUnit = Literal["rows", "bytes", "packets", "sensors"]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[
    str, Field(min_length=1, max_length=200, pattern=r"^[^\x00-\x1f\x7f-\x9f]+$")
]
Counter = Annotated[int, Field(ge=0, le=2**40 - 1)]


class InvestigationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def literal_ip(value: str) -> str:
    if type(value) is not str or not 1 <= len(value) <= 45 or "%" in value:
        raise ValueError("single literal IP required")
    return str(ip_address(value))


def normalize_timestamp(value: str) -> str:
    if type(value) is not str or not 20 <= len(value) <= 40:
        raise ValueError("bounded aware timestamp required")
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError("aware timestamp required")
    return parsed.astimezone(UTC).isoformat(timespec="microseconds")


class Frozen(BaseModel):
    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always", allow_inf_nan=False
    )


class SourceBinding(Frozen):
    version: Literal["ip-evidence-v1"] = VERSION
    job_id: Identifier
    dataset_id: Identifier
    metadata_sha256: Digest
    rows_sha256: Digest
    projection_sha256: Digest
    source_sha256: Digest


class TCPFlag(Frozen):
    name: Literal["syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"]
    count: Counter


class Observation(Frozen):
    ordinal: Annotated[int, Field(ge=0, lt=8192)]
    row_sha256: Digest
    sensor_id: Identifier
    timestamp: str
    source_ip: str
    destination_ip: str
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPV6", "OTHER"]
    direction: Literal["INBOUND", "OUTBOUND", "INTERNAL", "UNKNOWN"]
    packet_count: Annotated[int, Field(ge=1, le=2**40 - 1)] | None = None
    total_bytes: Counter | None = None
    duration_seconds: Annotated[float, Field(ge=0, le=1e9)] | None = None
    source_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    destination_port: Annotated[int, Field(ge=0, le=65535)] | None = None
    domain: Annotated[str, Field(max_length=253, pattern=r"^[a-zA-Z0-9_.-]+$")] | None = None
    tls_fingerprint: Annotated[str, Field(max_length=128, pattern=r"^[a-zA-Z0-9:_-]+$")] | None = (
        None
    )
    certificate_fingerprint: (
        Annotated[str, Field(max_length=128, pattern=r"^[a-zA-Z0-9:_-]+$")] | None
    ) = None
    payload_length: Counter | None = None
    payload_length_source: Literal["payload_length", "complete_transport_packet"] | None = None
    tcp_flags: tuple[TCPFlag, ...] | None = None
    present_fields: tuple[str, ...]
    # Fields present in the committed source but outside the evidence vocabulary
    # or bounded text policy. Their original values remain in row_sha256.
    unavailable_fields: Annotated[
        tuple[
            Literal[
                "protocol", "direction", "domain", "tls_fingerprint", "certificate_fingerprint"
            ],
            ...,
        ],
        Field(max_length=5),
    ] = ()

    @property
    def c2_eligibility(self) -> Literal["ELIGIBLE", "UNAVAILABLE", "SUPPRESSED_OUTBOUND_CONTROL"]:
        if self.protocol != "TCP" or self.direction != "OUTBOUND":
            return "ELIGIBLE"
        if self.tcp_flags is None or self.payload_length is None:
            return "UNAVAILABLE"
        flags: dict[str, int] = {flag.name: flag.count for flag in self.tcp_flags}
        if (
            any(flags.get(name, 0) for name in ("syn", "fin", "rst"))
            and not flags.get("ack", 0)
            and self.payload_length == 0
        ):
            return "SUPPRESSED_OUTBOUND_CONTROL"
        return "ELIGIBLE"

    _ip = field_validator("source_ip", "destination_ip")(literal_ip)
    _timestamp = field_validator("timestamp")(normalize_timestamp)


class SourceSnapshot(Frozen):
    binding: SourceBinding
    status: Literal["COMPLETED", "PARTIALLY_COMPLETED"]
    rows: tuple[Observation, ...]

    @field_validator("rows", mode="after")
    @classmethod
    def _row_limit(cls, value: tuple[Observation, ...]) -> tuple[Observation, ...]:
        # Let the strict JSON tuple decoder handle nested arrays first. A before
        # validator converts its input to Python, losing JSON tuple semantics.
        if len(value) > 8192:
            raise ValueError("SOURCE_LIMIT")
        return value

    @model_validator(mode="after")
    def _binding(self) -> Self:
        original = self.binding.model_dump(exclude={"source_sha256"})
        if (
            digest(original) != self.binding.source_sha256
            or digest([r.row_sha256 for r in self.rows]) != self.binding.rows_sha256
            or digest([self.status, [r.model_dump() for r in self.rows]])
            != self.binding.projection_sha256
            or any(r.ordinal != index for index, r in enumerate(self.rows))
        ):
            raise ValueError("SOURCE_INVALID")
        return self


class InvestigationScope(Frozen):
    target_ip: str
    sensor_id: Identifier | None = None
    endpoint_side: Literal["either", "source", "destination"] = "either"
    traffic_direction: Literal["INBOUND", "OUTBOUND", "INTERNAL", "UNKNOWN"] | None = None
    start_time: str | None = None
    end_time: str | None = None

    _ip = field_validator("target_ip")(literal_ip)

    @field_validator("start_time", "end_time")
    @classmethod
    def _time(cls, value: str | None) -> str | None:
        return None if value is None else normalize_timestamp(value)

    @model_validator(mode="after")
    def _range(self) -> Self:
        if self.start_time is not None and self.end_time is not None:
            if self.start_time > self.end_time:
                raise ValueError("invalid time range")
        return self


class Counts(Frozen):
    inspected: int
    matched: int
    retained: int
    omitted: int
    not_observed: int
    unavailable: int = 0
    # Selection eligibility unknown; neither a match nor a definite nonmatch.
    scope_unavailable: Annotated[int, Field(ge=0, le=8192)] = 0


class Metric(Frozen):
    ref: str
    name: MetricName
    unit: MetricUnit
    value: int | None
    observed_rows: int
    unavailable_rows: int


class RowReference(Frozen):
    source_sha256: Digest
    ordinal: Annotated[int, Field(ge=0, lt=8192)]
    row_sha256: Digest


class Sample(Frozen):
    ref: RowReference
    row: Observation
    selection: Literal["SOURCE_ORDER"] = "SOURCE_ORDER"
    c2_eligibility: Literal["ELIGIBLE", "UNAVAILABLE", "SUPPRESSED_OUTBOUND_CONTROL"]


class TimelineBucket(Frozen):
    sensor_id: Identifier
    start_time: str
    end_time: str
    rows: int
    packet_rows: int
    aggregate_rows: int
    unavailable_rows: int
    packet_interval_mean_seconds: None = None


class ProtocolObservation(Frozen):
    ref: RowReference
    domain: str | None
    tls_fingerprint: str | None
    certificate_fingerprint: str | None
    payload_length: int | None
    payload_length_source: Literal["payload_length", "complete_transport_packet"] | None = None
    tcp_flags: tuple[TCPFlag, ...] | None
    c2_eligibility: Literal["ELIGIBLE", "UNAVAILABLE", "SUPPRESSED_OUTBOUND_CONTROL"]


class CohortPeer(Frozen):
    sensor_id: Identifier
    ip: str
    rows: int
    total_bytes: int | None
    observed_byte_rows: int
    comparison: Literal["SAME_SOURCE_PROTOCOL_OVERLAP"] = "SAME_SOURCE_PROTOCOL_OVERLAP"


class Evidence(Frozen):
    version: Literal["ip-evidence-v1"] = VERSION
    evidence_id: Digest
    source: SourceBinding
    scope: InvestigationScope
    tool: ToolName
    args_sha256: Digest
    limit: int | None = None
    status: Literal["OBSERVED", "NOT_OBSERVED", "UNAVAILABLE", "NOT_FOUND_IN_INSPECTED_SCOPE"]
    counts: Counts
    metrics: tuple[Metric, ...]
    samples: tuple[Sample, ...] = ()
    timeline: tuple[TimelineBucket, ...] = ()
    protocols: tuple[ProtocolObservation, ...] = ()
    cohort: tuple[CohortPeer, ...] = ()
    cohort_total: int = 0
    cohort_omitted: int = 0
    # Input rows excluded from comparison, not additional observed peers.
    cohort_unavailable_rows: Annotated[int, Field(ge=0, le=8192)] = 0
    limitations: tuple[str, ...]
