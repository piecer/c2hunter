"""Closed v4 signature wire contract, independent of legacy v1/v2/v3 parsing."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Count = Annotated[int, Field(strict=True, ge=0, le=2**53 - 1)]
Port = Annotated[int, Field(strict=True, ge=0, le=65535)]
Hash = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LengthCondition(Closed):
    field: Literal["CAPTURED_FRAME_BYTES", "IP_BYTES", "TRANSPORT_PAYLOAD_BYTES"]
    minimum: Annotated[int, Field(strict=True, ge=0, le=65535)]
    maximum: Annotated[int, Field(strict=True, ge=0, le=65535)]

    @model_validator(mode="after")
    def ordered(self) -> LengthCondition:
        if self.minimum > self.maximum:
            raise ValueError("length interval is reversed")
        return self


class Predicate(Closed):
    target_ip: str = Field(max_length=45)
    direction: Literal["INBOUND", "OUTBOUND"]
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPV6"]
    source_ports: list[Port] | None = Field(min_length=1, max_length=16)
    destination_ports: list[Port] | None = Field(min_length=1, max_length=16)
    tcp_flags: dict[str, int] | None
    length: LengthCondition | None
    protocol_fields: dict[str, Any]

    @field_validator("target_ip")
    @classmethod
    def address(cls, value: str) -> str:
        if str(ip_address(value)) != value:
            raise ValueError("canonical target required")
        return value

    @model_validator(mode="after")
    def supported(self) -> Predicate:
        if self.protocol_fields and (
            self.protocol not in {"ICMP", "ICMPV6"}
            or set(self.protocol_fields) != {"icmp_type"}
            or type(self.protocol_fields["icmp_type"]) is not int
            or not 0 <= self.protocol_fields["icmp_type"] <= 255
        ):
            raise ValueError("unsupported protocol condition")
        for ports in (self.source_ports, self.destination_ports):
            if ports is not None and ports != sorted(set(ports)):
                raise ValueError("ports must be unique and ordered")
        if self.tcp_flags is not None and (
            self.protocol != "TCP"
            or not self.tcp_flags
            or not set(self.tcp_flags) <= {"syn", "ack", "rst", "fin"}
            or any(type(v) is not int or v not in (0, 1) for v in self.tcp_flags.values())
        ):
            raise ValueError("unsupported flag condition")
        return self


class MatchResult(Closed):
    matched_records: Count
    eligible_records: Count
    unknown_records: Count
    matched_packets: Count
    eligible_packets: Count
    unknown_packets: Count
    record_match_rate: float | None = Field(ge=0, le=1, allow_inf_nan=False)
    packet_match_rate: float | None = Field(ge=0, le=1, allow_inf_nan=False)
    sampled_records: Count
    omitted_records: Count
    sample_bytes: Count
    record_limit: Literal[512]
    byte_limit: Literal[262144]
    evidence_refs: list[Annotated[str, Field(pattern=r"^(0|[1-9][0-9]{0,2}):[0-9a-f]{64}$")]] = (
        Field(max_length=8)
    )
    evidence_digest: Hash

    @model_validator(mode="after")
    def counters(self) -> MatchResult:
        if (
            self.sampled_records != self.eligible_records + self.unknown_records
            or self.sampled_records > self.record_limit
            or not 2 <= self.sample_bytes <= self.byte_limit
        ):
            raise ValueError("signature sample counters disagree")
        for unit in ("records", "packets"):
            matched = getattr(self, f"matched_{unit}")
            eligible = getattr(self, f"eligible_{unit}")
            rate = getattr(self, f"{unit[:-1]}_match_rate")
            if matched > eligible or rate != (matched / eligible if eligible else None):
                raise ValueError("signature match denominator disagrees")
        if (
            self.eligible_packets < self.eligible_records
            or self.unknown_packets < self.unknown_records
            or self.matched_packets < self.matched_records
            or (self.matched_records == 0) != (self.matched_packets == 0)
            or (self.eligible_records == 0) != (self.eligible_packets == 0)
            or (self.unknown_records == 0) != (self.unknown_packets == 0)
        ):
            raise ValueError("record support cannot invent packet support")
        unmatched_records = self.eligible_records - self.matched_records
        unmatched_packets = self.eligible_packets - self.matched_packets
        if unmatched_packets < unmatched_records or (unmatched_records == 0) != (
            unmatched_packets == 0
        ):
            raise ValueError("nonmatching record/packet support disagrees")
        indices = [int(ref.split(":")[0]) for ref in self.evidence_refs]
        if (
            len(indices) != min(8, self.matched_records)
            or len(set(indices)) != len(indices)
            or any(index >= self.sampled_records for index in indices)
        ):
            raise ValueError("signature evidence references disagree")
        return self


class Reference(Closed):
    coverage_limited: Literal[True]

    @field_validator("coverage_limited", mode="before")
    @classmethod
    def coverage_boolean(cls, value: object) -> object:
        if value is not True:
            raise ValueError("coverage must be the JSON boolean true")
        return value

    job_id: str = Field(min_length=1, max_length=200)
    dataset_id: str = Field(min_length=1, max_length=200)
    content_digest: Hash
    record_count: Annotated[int, Field(strict=True, ge=1, le=512)]
    selected_by: str = Field(min_length=1, max_length=128)
    selected_at: str = Field(min_length=1, max_length=64)


class NormalResult(Closed):
    status: Literal["UNMEASURED", "MEASURED"]
    result: MatchResult | None
    reference: Reference | None

    @model_validator(mode="after")
    def measured(self) -> NormalResult:
        if self.status == "UNMEASURED":
            if self.result is not None or self.reference is not None:
                raise ValueError("unmeasured false positives must not contain measurements")
        elif self.result is None or self.reference is None:
            raise ValueError("measured reference missing")
        elif (
            self.result.sampled_records != self.reference.record_count
            or self.result.evidence_digest != self.reference.content_digest
            or self.result.omitted_records != 0
        ):
            raise ValueError("reference result binding disagrees")
        return self


class SignatureEvaluation(Closed):
    predicate: Predicate
    attack: MatchResult
    normal: NormalResult
    confidence_basis: Literal["RETAINED_EVIDENCE_NOT_ATTACK_PROBABILITY"]
    approval_conditions: list[str]
    exclusions: list[str]
    invalidation: list[str]
    supported_export_targets: list[str]
    automatic_enforcement: Literal[False]

    @field_validator("automatic_enforcement", mode="before")
    @classmethod
    def enforcement_boolean(cls, value: object) -> object:
        if value is not False:
            raise ValueError("automatic enforcement must be the JSON boolean false")
        return value

    @model_validator(mode="after")
    def policy(self) -> SignatureEvaluation:
        for field, expected in {
            "approval_conditions": [
                "VERIFY_TARGET_OWNERSHIP",
                "REVIEW_NORMAL_TRAFFIC",
                "HUMAN_APPROVAL",
            ],
            "exclusions": ["LEGITIMATE_SHARED_SERVICES", "INCOMPLETE_OBSERVATIONS"],
            "invalidation": ["DATASET_OR_TOPOLOGY_CHANGE", "REVALIDATE_BEFORE_EACH_USE"],
            "supported_export_targets": ["STRUCTURED_JSON"],
        }.items():
            if getattr(self, field) != expected:
                raise ValueError("signature review policy mismatch")
        return self


class SignatureReportContext:
    """Shared v4 association checks before API publication or lossy AI projection."""

    def __init__(self, evaluated_records: int, packet_count: int, reference: Any) -> None:
        if any(
            type(value) is not int or not 0 <= value <= 2**53 - 1
            for value in (evaluated_records, packet_count)
        ):
            raise ValueError("invalid DDoS report sample totals")
        self.evaluated_records = evaluated_records
        self.packet_count = packet_count
        self.reference = Reference.model_validate(reference) if reference is not None else None
        self.sample: tuple[int, int, int, str, int] | None = None

    def accept(
        self,
        evaluation: SignatureEvaluation,
        *,
        target_ip: str,
        target_port: int | None,
        role: str,
        attack_type: str,
        protocol: str,
    ) -> None:
        if evaluation.normal.reference != self.reference:
            raise ValueError("DDoS signature/report reference mismatch")
        attack = evaluation.attack
        packets = attack.eligible_packets + attack.unknown_packets
        if (
            attack.sampled_records + attack.omitted_records != self.evaluated_records
            or packets > self.packet_count
            or self.packet_count - packets < attack.omitted_records
            or (not attack.omitted_records and packets != self.packet_count)
        ):
            raise ValueError("DDoS signature sample disagrees with report")
        identity = (
            attack.sampled_records,
            attack.omitted_records,
            attack.sample_bytes,
            attack.evidence_digest,
            packets,
        )
        if self.sample is not None and identity != self.sample:
            raise ValueError("DDoS global signature sample mismatch")
        self.sample = identity
        predicate = evaluation.predicate
        direction = "INBOUND" if role == "VICTIM_SIDE_INBOUND" else "OUTBOUND"
        if predicate.target_ip != target_ip or predicate.direction != direction:
            raise ValueError("DDoS signature target mismatch")
        # MULTI_VECTOR carries component predicates. Spoofing candidates intentionally
        # omit flag/source-port conditions but keep the same protocol/destination port.
        if attack_type != "MULTI_VECTOR" and (
            predicate.protocol != protocol
            or predicate.destination_ports != ([target_port] if target_port is not None else None)
        ):
            raise ValueError("DDoS signature protocol/port mismatch")
