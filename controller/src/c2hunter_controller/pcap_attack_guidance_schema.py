"""Closed offline review contract. Not an extension of ddos-attack-report-v1..v4.

JSON Schema describes shapes; model validators additionally enforce measured
relationships, exact UTC windows, family policy and owner/report binding.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Annotated, Any, Literal, Self, get_args

from c2hunter_analysis.pcap_attack_guidance import MAX_BYTES, canonical_bytes, stamp
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

Family = Literal[
    "SYN_CONCENTRATION", "PAYLOAD_FREE_ACK_BURST", "RST_BURST", "UDP_BURST", "ICMP_BURST"
]
Reason = Literal["SYN_SHARE_HIGH", "ABSOLUTE_VOLUME", "RELATIVE_RATE_INCREASE"]
Uncertainty = Literal[
    "INTENT_AND_IMPACT_UNCONFIRMED",
    "REVERSE_VISIBILITY_UNKNOWN",
    "WITHIN_CAPTURE_BASELINE_UNAVAILABLE",
    "WITHIN_CAPTURE_NOT_KNOWN_NORMAL",
    "LOW_SOURCE_DIVERSITY",
    "SHORT_OBSERVATION",
]
Alternative = Literal[
    "LEGITIMATE_CONNECTION_SURGE",
    "EXPECTED_SERVICE_BURST",
    "MIDDLEBOX_OR_SERVER_RESETS",
    "ASYMMETRIC_TCP_CAPTURE",
]
NextCheck = Literal[
    "CHECK_BIDIRECTIONAL_CAPTURE",
    "CHECK_SYN_BACKLOG",
    "CHECK_TCP_STATE",
    "CHECK_SERVICE_REQUEST_RESPONSE",
    "CHECK_ICMP_OPERATIONS",
]
Coverage = Literal[
    "INPUT_LIMIT",
    "PARSER_GAPS",
    "SENSOR_DROPS",
    "CLOCK_SKEW",
    "CAPTURE_PARTIAL",
    "CAPTURE_QUALITY_UNKNOWN",
    "DUPLICATE_CAPTURE_POSSIBLE",
    "DDOS_COVERAGE_LIMITED",
    "INELIGIBLE_RECORDS",
    "RECORDS_REJECTED",
    "WINDOW_STATE_LIMIT",
    "RESPONSE_STATE_LIMIT",
]
Limitation = Literal[
    "REVIEW_NOT_ATTACK_CLASSIFICATION",
    "NO_CANDIDATE_NOT_CLEAN",
    "L7_NOT_ASSESSED",
    "OBSERVED_SOURCES_NOT_ACTORS",
]
REGISTRY = {
    "family": get_args(Family),
    "reason": get_args(Reason),
    "uncertainty": get_args(Uncertainty),
    "alternative": get_args(Alternative),
    "next_check": get_args(NextCheck),
    "coverage": get_args(Coverage),
    "limitation": get_args(Limitation),
}


def integer_value(value: Any) -> int:
    if type(value) not in (int, float) or not math.isfinite(value) or int(value) != value:
        raise ValueError("expected finite integer-valued primitive number")
    if not 0 <= value <= 2**53 - 1:
        raise ValueError("integer outside safe nonnegative range")
    return int(value)


Count = Annotated[int, BeforeValidator(integer_value), Field(ge=0, le=2**53 - 1)]
Timestamp = Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")]


def instant(value: str) -> datetime:
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value):
        raise ValueError("noncanonical UTC timestamp")
    return datetime.fromisoformat(value)


def address(value: str) -> str:
    if "%" in value or str(ip_address(value)) != value:
        raise ValueError("noncanonical IP address")
    return value


class Closed(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, revalidate_instances="always")


class GuidanceTarget(Closed):
    ip: Annotated[str, Field(min_length=2, max_length=39)]
    port: Annotated[Count, Field(le=65535)] | None
    protocol: Literal["TCP", "UDP", "ICMP", "ICMPV6"]

    _address = field_validator("ip")(address)


class GuidanceCandidate(Closed):
    family: Family
    role: Literal["VICTIM_SIDE_INBOUND", "PARTICIPANT_SIDE_OUTBOUND"]
    target: GuidanceTarget
    window_start: Timestamp
    window_end: Timestamp
    first_seen: Timestamp
    last_seen: Timestamp
    packet_count: Annotated[Count, Field(ge=32)]
    byte_count: Count
    source_count: Annotated[Count, Field(ge=1, le=32)]
    source_count_is_lower_bound: bool
    source_examples: Annotated[list[str], Field(min_length=1, max_length=8)]
    syn_only_count: Count
    ack_only_count: Count
    rst_count: Count
    payload_packet_count: Count
    payload_visibility_complete: bool
    baseline_window_count: Annotated[Count, Field(le=511)]
    baseline_packet_count: Count
    reason_codes: Annotated[list[Reason], Field(min_length=1, max_length=1)]
    uncertainty_codes: Annotated[list[Uncertainty], Field(min_length=3, max_length=6)]
    alternative_codes: Annotated[list[Alternative], Field(min_length=1, max_length=1)]
    next_check_codes: Annotated[list[NextCheck], Field(min_length=2, max_length=2)]

    @model_validator(mode="after")
    def measured_relationships(self) -> Self:
        start, end, first, last = map(
            instant, (self.window_start, self.window_end, self.first_seen, self.last_seen)
        )
        if (
            end - start != timedelta(seconds=5)
            or start.microsecond
            or start.second % 5
            or not start <= first <= last < end
        ):
            raise ValueError("invalid fixed window or observed interval")
        if (
            len(self.source_examples) != min(8, self.source_count)
            or self.source_examples != sorted(set(self.source_examples))
            or self.source_count > self.packet_count
            or (self.source_count_is_lower_bound and self.source_count != 32)
        ):
            raise ValueError("invalid bounded source evidence")
        for value in self.source_examples:
            address(value)
        if (
            self.syn_only_count + self.ack_only_count + self.rst_count > self.packet_count
            or self.payload_packet_count > self.packet_count
        ):
            raise ValueError("counter exceeds observed packets")
        if self.baseline_window_count == 0:
            if self.baseline_packet_count != 0:
                raise ValueError("invented baseline")
        elif (
            self.baseline_window_count < 3
            or self.baseline_packet_count < self.baseline_window_count
        ):
            raise ValueError("ineligible within-capture baseline")
        protocol = self.target.protocol
        if (
            self.family in {"SYN_CONCENTRATION", "PAYLOAD_FREE_ACK_BURST", "RST_BURST"}
            and protocol != "TCP"
        ):
            raise ValueError("TCP family on non-TCP target")
        alternative, check = "EXPECTED_SERVICE_BURST", "CHECK_SERVICE_REQUEST_RESPONSE"
        if self.family == "SYN_CONCENTRATION":
            if self.syn_only_count * 5 < self.packet_count * 4 or self.reason_codes != [
                "SYN_SHARE_HIGH"
            ]:
                raise ValueError("SYN family lacks concentration")
            alternative, check = "LEGITIMATE_CONNECTION_SURGE", "CHECK_SYN_BACKLOG"
        else:
            if self.reason_codes == ["ABSOLUTE_VOLUME"]:
                if self.packet_count < 1000:
                    raise ValueError("volume floor not met")
            elif self.reason_codes == ["RELATIVE_RATE_INCREASE"]:
                if (
                    self.baseline_window_count < 3
                    or self.packet_count * self.baseline_window_count
                    < 5 * self.baseline_packet_count
                ):
                    raise ValueError("relative floor not met")
            else:
                raise ValueError("burst lacks rate evidence")
            if self.family == "PAYLOAD_FREE_ACK_BURST":
                if (
                    self.ack_only_count * 5 < self.packet_count * 4
                    or self.payload_packet_count
                    or not self.payload_visibility_complete
                ):
                    raise ValueError("ACK family lacks payload absence")
                alternative, check = "ASYMMETRIC_TCP_CAPTURE", "CHECK_TCP_STATE"
            elif self.family == "RST_BURST":
                if self.rst_count * 5 < self.packet_count * 4:
                    raise ValueError("RST family lacks concentration")
                alternative, check = "MIDDLEBOX_OR_SERVER_RESETS", "CHECK_TCP_STATE"
            elif self.family == "UDP_BURST" and protocol != "UDP":
                raise ValueError("UDP family mismatch")
            elif self.family == "ICMP_BURST":
                if protocol not in {"ICMP", "ICMPV6"}:
                    raise ValueError("ICMP family mismatch")
                check = "CHECK_ICMP_OPERATIONS"
        if protocol != "TCP" and (self.syn_only_count or self.ack_only_count or self.rst_count):
            raise ValueError("non-TCP flag evidence")
        uncertainty = [
            "INTENT_AND_IMPACT_UNCONFIRMED",
            "REVERSE_VISIBILITY_UNKNOWN",
            "WITHIN_CAPTURE_NOT_KNOWN_NORMAL"
            if self.baseline_window_count
            else "WITHIN_CAPTURE_BASELINE_UNAVAILABLE",
        ]
        if self.source_count < 20:
            uncertainty.append("LOW_SOURCE_DIVERSITY")
        if last - first < timedelta(seconds=3):
            uncertainty.append("SHORT_OBSERVATION")
        if (
            self.uncertainty_codes != sorted(uncertainty)
            or self.alternative_codes != [alternative]
            or self.next_check_codes != ["CHECK_BIDIRECTIONAL_CAPTURE", check]
        ):
            raise ValueError("family guidance codes disagree with evidence")
        return self


class GuidanceSummary(Closed):
    scanned_records: Count
    evaluated_records: Count
    rejected_record_count: Count
    packet_count: Count
    byte_count: Count
    eligible_packet_count: Count
    excluded_record_count: Count
    retained_target_count: Annotated[Count, Field(le=256)]
    retained_window_count: Annotated[Count, Field(le=8192)]
    omitted_observation_count: Count
    response_state_count: Annotated[
        Count,
        Field(
            le=8192, description="Retained bounded SYN/SYN-ACK matching observations, not tuples."
        ),
    ]
    response_omitted_count: Annotated[
        Count,
        Field(description="SYN/SYN-ACK observations discarded at the global matching event cap."),
    ]
    suppressed_handshake_window_count: Annotated[
        Count,
        Field(
            description="SYN candidate windows suppressed by temporal reverse-tuple "
            "reply abundance; not proof of completed TCP handshakes or successful sessions."
        ),
    ]
    qualifying_window_count: Count
    candidate_count: Annotated[Count, Field(le=32)]
    omitted_candidate_count: Annotated[Count, Field(le=256)]
    coverage_complete: bool
    first_seen: Timestamp | None
    last_seen: Timestamp | None


class PcapAttackGuidance(Closed):
    version: Literal["pcap-attack-guidance-v1"]
    job_id: Annotated[str, Field(min_length=1, max_length=128)]
    dataset_id: Annotated[str, Field(min_length=1, max_length=128)]
    status: Literal["REVIEW_CANDIDATES", "NO_CANDIDATE", "INSUFFICIENT_OBSERVATION"]
    summary: GuidanceSummary
    candidates: Annotated[list[GuidanceCandidate], Field(max_length=32)]
    coverage_codes: Annotated[list[Coverage], Field(max_length=12)]
    limitations: Annotated[list[Limitation], Field(min_length=4, max_length=4)]

    @model_validator(mode="after")
    def conservation(self) -> Self:
        s = self.summary
        if (
            s.eligible_packet_count + s.excluded_record_count != s.evaluated_records
            or s.evaluated_records + s.rejected_record_count > s.scanned_records
            or s.eligible_packet_count > s.packet_count
            or s.retained_target_count > s.retained_window_count
            or s.retained_window_count > s.eligible_packet_count
            or s.omitted_observation_count > s.eligible_packet_count
            or s.response_omitted_count > s.eligible_packet_count
            or s.response_state_count > s.eligible_packet_count
            or s.response_state_count + s.response_omitted_count > s.eligible_packet_count
            or s.qualifying_window_count + s.suppressed_handshake_window_count
            > s.retained_window_count
            or s.candidate_count + s.omitted_candidate_count > s.retained_target_count
            or s.candidate_count + s.omitted_candidate_count > s.qualifying_window_count
            or s.candidate_count != len(self.candidates)
        ):
            raise ValueError("inconsistent guidance counters")
        if (
            self.coverage_codes != sorted(set(self.coverage_codes))
            or s.coverage_complete != (not self.coverage_codes)
            or self.limitations != list(get_args(Limitation))
        ):
            raise ValueError("inconsistent coverage or limitations")
        for count, code in (
            (s.excluded_record_count, "INELIGIBLE_RECORDS"),
            (s.rejected_record_count, "RECORDS_REJECTED"),
            (s.omitted_observation_count, "WINDOW_STATE_LIMIT"),
            (s.response_omitted_count, "RESPONSE_STATE_LIMIT"),
        ):
            if bool(count) != (code in self.coverage_codes):
                raise ValueError("coverage code disagrees with counter")
        expected_status = (
            "REVIEW_CANDIDATES"
            if self.candidates
            else ("NO_CANDIDATE" if s.eligible_packet_count >= 32 else "INSUFFICIENT_OBSERVATION")
        )
        if self.status != expected_status:
            raise ValueError("status disagrees with measured candidates")
        if bool(s.evaluated_records) != (s.first_seen is not None and s.last_seen is not None):
            raise ValueError("observation bounds unavailable")
        if not s.evaluated_records and (s.first_seen is not None or s.last_seen is not None):
            raise ValueError("unobserved timestamp")
        if s.first_seen is not None and s.last_seen is not None:
            if instant(s.first_seen) > instant(s.last_seen):
                raise ValueError("reversed report bounds")
        identities = set()
        for candidate in self.candidates:
            key = (
                candidate.role,
                candidate.target.ip,
                candidate.target.port,
                candidate.target.protocol,
            )
            if key in identities:
                raise ValueError("multiple candidates for target")
            identities.add(key)
            if (
                s.first_seen is None
                or s.last_seen is None
                or not instant(s.first_seen)
                <= instant(candidate.first_seen)
                <= instant(candidate.last_seen)
                <= instant(s.last_seen)
            ):
                raise ValueError("candidate outside observed report bounds")
            if candidate.baseline_window_count + 1 > s.retained_window_count:
                raise ValueError("baseline exceeds retained windows")
            # A partial first window is occupied evidence too. Floor the actual
            # first instant, not the candidate's observed interval, using exact
            # datetime arithmetic (including pre-epoch and microseconds).
            first = instant(s.first_seen)
            first_window = first.replace(second=first.second // 5 * 5, microsecond=0)
            prior_slots = (instant(candidate.window_start) - first_window) // timedelta(seconds=5)
            if candidate.baseline_window_count > prior_slots:
                raise ValueError("baseline exceeds possible prior time slots")
            if candidate.baseline_packet_count + candidate.packet_count > s.eligible_packet_count:
                raise ValueError("baseline exceeds observed population")
        # Candidate identities are unique, so their target windows and packet
        # populations (including prior baselines) are disjoint. These are
        # necessary feasibility checks, not proof of worker fact authenticity.
        if (
            sum(c.baseline_window_count + 1 for c in self.candidates) > s.retained_window_count
            or sum(c.baseline_packet_count + c.packet_count for c in self.candidates)
            > s.eligible_packet_count - s.omitted_observation_count
            or sum(c.byte_count for c in self.candidates) > s.byte_count
        ):
            raise ValueError("published evidence exceeds observations")
        if len(canonical_bytes(self.model_dump(mode="json"))) > MAX_BYTES:
            raise ValueError("guidance exceeds byte budget")
        return self


class GuidanceError(ValueError):
    """A present guide failed its closed result contract."""


def validate_job_guidance(job: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return _validate_job_guidance(job)
    except (ValueError, TypeError, OverflowError) as error:
        raise GuidanceError("invalid PCAP attack guidance") from error


def _validate_job_guidance(job: dict[str, Any]) -> dict[str, Any] | None:
    """Absence is unavailable; malformed-present never downgrades to absence."""
    if "pcap_attack_guidance" not in job:
        return None
    if (
        job.get("source_type") != "PCAP_UPLOAD"
        or job.get("analysis", {}).get("module") != "ddos_attack"
    ):
        raise ValueError("guidance is offline PCAP DDoS only")
    guide = PcapAttackGuidance.model_validate(job["pcap_attack_guidance"])
    if guide.job_id != job.get("id") or guide.dataset_id != job.get("dataset_id"):
        raise ValueError("foreign guidance owner")
    for field, observed in (
        ("packet_count", guide.summary.packet_count),
        ("flow_count", guide.summary.scanned_records),
    ):
        if field in job and observed > integer_value(job[field]):
            raise ValueError("guidance exceeds enclosing job observations")
    report = job.get("ddos_attack")
    if not isinstance(report, dict) or not isinstance(report.get("summary"), dict):
        raise ValueError("guidance lacks bound DDoS report")
    summary = report["summary"]
    for field in ("scanned_records", "evaluated_records", "packet_count", "byte_count"):
        if getattr(guide.summary, field) != summary.get(field):
            raise ValueError("guidance disagrees with report counts")
    if guide.summary.rejected_record_count != summary.get("skipped_records"):
        raise ValueError("guidance disagrees with rejected records")
    for field in ("first_seen", "last_seen"):
        value = summary.get(field)
        expected = stamp(datetime.fromisoformat(value)) if isinstance(value, str) else None
        if getattr(guide.summary, field) != expected:
            raise ValueError("guidance disagrees with report bounds")
    if ("DDOS_COVERAGE_LIMITED" in guide.coverage_codes) != (not summary.get("coverage_complete")):
        raise ValueError("guidance disagrees with report coverage")
    return guide.model_dump(mode="json")


def project_job_guidance(job: dict[str, Any], *, compact: bool = False) -> dict[str, Any]:
    """Validate before projection; lists carry a derived compact status, never the guide."""
    guide = validate_job_guidance(job)
    projected = dict(job)
    if guide is not None:
        projected["pcap_attack_guidance"] = guide
    if guide is not None or (
        job.get("source_type") == "PCAP_UPLOAD"
        and job.get("analysis", {}).get("module") == "ddos_attack"
    ):
        projected["pcap_attack_guidance_summary"] = guidance_summary(job)
    else:
        projected.pop("pcap_attack_guidance_summary", None)
    if compact:
        projected.pop("pcap_attack_guidance", None)
    return projected


def guidance_summary(job: dict[str, Any]) -> dict[str, Any]:
    guide = validate_job_guidance(job)
    if guide is None:
        return {"status": "UNAVAILABLE"}
    return {
        "status": guide["status"],
        "candidate_count": guide["summary"]["candidate_count"],
        "omitted_candidate_count": guide["summary"]["omitted_candidate_count"],
        "coverage_complete": guide["summary"]["coverage_complete"],
    }
