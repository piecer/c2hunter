"""Passive predicate evaluation. Counts describe retained evidence, never enforcement."""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_right
from collections.abc import Mapping
from datetime import datetime
from ipaddress import ip_address
from typing import Any

MAX_RECORDS = 512
MAX_RECORD_BYTES = 2048
MAX_SAMPLE_BYTES = 256 * 1024
MAX_EVALUATION_BYTES = 8192
MAX_PUBLICATION_BYTES = 1024 * 1024
FLAG_CONDITIONS = {
    "TCP_SYN_FLOOD": {"syn": 1, "ack": 0},
    "TCP_ACK_FLOOD": {"syn": 0, "ack": 1, "rst": 0},
    "TCP_RST_FLOOD": {"rst": 1},
    "TCP_FIN_FLOOD": {"fin": 1},
}
FIELDS = (
    "sensor_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "direction",
    "packet_count",
    "total_bytes",
    "tcp_flags",
    "tcp_flags_observed",
    "packet_evidence_complete",
    "transport_payload_length",
    "icmp_type",
)


def encoded(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(encoded(value)).hexdigest()


def project(record: Mapping[str, object], packet_count: int | None = None) -> dict[str, Any]:
    """Fixed-field, bounded scalar projection; never copies raw payload or sidecars."""
    result: dict[str, Any] = {}
    for key in FIELDS:
        value = (
            packet_count if key == "packet_count" and packet_count is not None else record.get(key)
        )
        if key in {"source_ip", "destination_ip"} and type(value) is str and len(value) <= 45:
            try:
                value = str(ip_address(value))
            except ValueError:
                value = None
        if key in {"protocol", "direction"} and type(value) is str and len(value) <= 16:
            value = value.upper()
        if key == "timestamp" and isinstance(value, datetime):
            value = value.isoformat()
        if key == "tcp_flags" and type(value) is dict:
            value = {k: value.get(k) for k in ("syn", "ack", "rst", "fin")}
            if any(type(v) is not int or v not in (0, 1) for v in value.values()):
                value = None
        elif value is not None and not (
            type(value) is bool
            or type(value) is int
            and 0 <= value <= 2**53 - 1
            or type(value) is str
            and len(value) <= 128
        ):
            value = None
        result[key] = value
    if len(encoded(result)) > MAX_RECORD_BYTES:
        raise ValueError("signature record byte limit")
    return result


class EvidenceSample:
    def __init__(self) -> None:
        self.records: list[dict[str, Any]] = []
        self.omitted = 0
        self.bytes = 2
        self._keys: list[bytes] = []
        self._seen = 0

    def add(self, record: Mapping[str, object], *, packet_count: int | None = None) -> None:
        self._seen += 1
        row = project(record, packet_count)
        key = encoded(row)
        position = bisect_right(self._keys, key)
        if position < MAX_RECORDS:
            self._keys.insert(position, key)
            self.records.insert(position, row)
            self.bytes += len(key) + (len(self.records) > 1)
            while len(self.records) > MAX_RECORDS or self.bytes > MAX_SAMPLE_BYTES:
                self.bytes -= len(self._keys.pop()) + (len(self.records) > 1)
                self.records.pop()
        self.omitted = self._seen - len(self.records)


def match(predicate: dict[str, Any], row: dict[str, Any]) -> bool | None:
    """Three-valued conjunction; an absent observation is not a wildcard."""
    unknown = False
    for field, expected in (
        ("destination_ip", predicate["target_ip"]),
        ("direction", predicate["direction"]),
        ("protocol", predicate["protocol"]),
    ):
        actual = row.get(field)
        if (
            type(actual) is not str
            or field == "direction"
            and actual not in {"INBOUND", "OUTBOUND"}
            or field == "protocol"
            and actual not in {"TCP", "UDP", "ICMP", "ICMPV6"}
        ):
            unknown = True
        elif actual != expected:
            return False
    for field, options in (
        ("source_port", predicate["source_ports"]),
        ("destination_port", predicate["destination_ports"]),
    ):
        if options is None:
            continue  # Explicit unconstrained port, never missing condition.
        if type(row.get(field)) is not int or not 0 <= row[field] <= 65535:
            unknown = True
        elif row[field] not in options:
            return False
    flags = predicate["tcp_flags"]
    if flags is not None:
        observed = row.get("tcp_flags")
        if (
            row.get("packet_count") != 1
            or row.get("packet_evidence_complete") is not True
            or row.get("tcp_flags_observed") is not True
            or type(observed) is not dict
        ):
            unknown = True
        else:
            for key, expected in flags.items():
                if observed.get(key) is None:
                    unknown = True
                elif observed[key] != expected:
                    return False
    # Frame, IP and transport payload lengths are distinct measurements. This
    # record contract has no observed IP-length scalar; never substitute frame size.
    length = predicate["length"]
    if length is not None:
        length_field = {
            "CAPTURED_FRAME_BYTES": "total_bytes",
            "TRANSPORT_PAYLOAD_BYTES": "transport_payload_length",
        }.get(length["field"])
        measured = row.get(length_field) if length_field else None
        if (
            row.get("packet_count") != 1
            or row.get("packet_evidence_complete") is not True
            or type(measured) is not int
        ):
            unknown = True
        elif not length["minimum"] <= measured <= length["maximum"]:
            return False
    for field, expected in predicate["protocol_fields"].items():
        measured = (
            row.get(field)
            if field == "icmp_type" and row.get("protocol") in {"ICMP", "ICMPV6"}
            else None
        )
        if (
            row.get("packet_count") != 1
            or row.get("packet_evidence_complete") is not True
            or type(measured) is not int
        ):
            unknown = True
        elif measured != expected:
            return False
    return None if unknown else True


def evaluate(predicate: dict[str, Any], sample: EvidenceSample) -> dict[str, Any]:
    counts = {
        f"{state}_{unit}": 0
        for state in ("matched", "eligible", "unknown")
        for unit in ("records", "packets")
    }
    refs: list[str] = []
    for index, row in enumerate(sample.records):
        verdict = match(predicate, row)
        packets = row["packet_count"]
        if type(packets) is not int or packets < 1:
            raise ValueError("invalid signature packet count")
        state = "unknown" if verdict is None else "eligible"
        counts[f"{state}_records"] += 1
        counts[f"{state}_packets"] += packets
        if verdict:
            counts["matched_records"] += 1
            counts["matched_packets"] += packets
            if len(refs) < 8:
                refs.append(f"{index}:{digest(row)}")
    return {
        **counts,
        "record_match_rate": counts["matched_records"] / counts["eligible_records"]
        if counts["eligible_records"]
        else None,
        "packet_match_rate": counts["matched_packets"] / counts["eligible_packets"]
        if counts["eligible_packets"]
        else None,
        "sampled_records": len(sample.records),
        "omitted_records": sample.omitted,
        "sample_bytes": sample.bytes,
        "record_limit": MAX_RECORDS,
        "byte_limit": MAX_SAMPLE_BYTES,
        "evidence_refs": refs,
        "evidence_digest": digest(sample.records),
    }


def load_reference(job: Mapping[str, Any]) -> dict[str, Any] | None:
    present = "ddos_reference_snapshot" in job
    binding = job.get("ddos_reference_binding")
    if not present and binding is None:
        return None
    snapshot = job.get("ddos_reference_snapshot")
    if not isinstance(snapshot, dict):
        raise ValueError("invalid DDoS reference snapshot")
    reference_sample(snapshot)
    if snapshot["reference"]["dataset_id"] == job.get("dataset_id"):
        raise ValueError("DDoS reference must be a separate dataset")
    if type(binding) is not str or len(binding) != 64 or digest(snapshot) != binding:
        raise ValueError("DDoS reference request binding mismatch")
    return snapshot


def reference_sample(snapshot: Any) -> tuple[EvidenceSample, dict[str, Any]]:
    if (
        type(snapshot) is not dict
        or set(snapshot) != {"version", "reference", "records"}
        or snapshot["version"] != "ddos-normal-reference-v1"
    ):
        raise ValueError("invalid DDoS reference snapshot")
    rows, reference = snapshot["records"], snapshot["reference"]
    if type(rows) is not list or not 1 <= len(rows) <= MAX_RECORDS:
        raise ValueError("invalid DDoS reference record count")
    if type(reference) is not dict or set(reference) != {
        "job_id",
        "dataset_id",
        "content_digest",
        "record_count",
        "selected_by",
        "selected_at",
        "coverage_limited",
    }:
        raise ValueError("invalid DDoS reference provenance")
    for key, limit in (
        ("job_id", 200),
        ("dataset_id", 200),
        ("selected_by", 128),
        ("selected_at", 64),
        ("content_digest", 64),
    ):
        if type(reference[key]) is not str or not 1 <= len(reference[key]) <= limit:
            raise ValueError("invalid DDoS reference identity")
    if reference["coverage_limited"] is not True:
        raise ValueError("reference population coverage is not established")
    sample = EvidenceSample()
    for row in rows:
        if type(row) is not dict or set(row) != set(FIELDS) or project(row) != row:
            raise ValueError("invalid DDoS reference record")
        if (
            type(row["packet_count"]) is not int
            or not 1 <= row["packet_count"] <= (2**53 - 1) // MAX_RECORDS
        ):
            raise ValueError("invalid DDoS reference packet count")
        sample.add(row)
    if (
        sample.omitted
        or reference["record_count"] != len(rows)
        or reference["content_digest"] != digest(rows)
    ):
        raise ValueError("DDoS reference content identity mismatch")
    return sample, reference


def attach_evaluations(
    findings: list[dict[str, Any]], sample: EvidenceSample, normal_snapshot: Any = None
) -> None:
    normal = reference_sample(normal_snapshot) if normal_snapshot is not None else None
    publication_bytes = 0
    for finding in findings:
        # Multi-vector entries retain their component predicates, not a MULTIPLE wildcard.
        for candidate in finding["signature_candidates"]:
            profile_flags = FLAG_CONDITIONS.get(candidate["tcp_flag_profile"])
            flags = dict(profile_flags) if profile_flags is not None else None
            predicate = {
                "target_ip": finding["target"]["ip"],
                "direction": "INBOUND"
                if finding["attack_role"] == "VICTIM_SIDE_INBOUND"
                else "OUTBOUND",
                "protocol": candidate["protocol"],
                "source_ports": candidate["source_ports"] or None,
                "destination_ports": candidate["destination_ports"] or None,
                "tcp_flags": flags,
                "length": None,
                "protocol_fields": {},
            }
            candidate["packet_size_range"] = None
            candidate["payload_prefix_hashes"] = []
            candidate["confidence"] = "low"
            normal_result: dict[str, Any] = {
                "status": "UNMEASURED",
                "result": None,
                "reference": None,
            }
            if normal is not None:
                normal_result = {
                    "status": "MEASURED",
                    "result": evaluate(predicate, normal[0]),
                    "reference": dict(normal[1]),
                }
            candidate["evaluation"] = {
                "predicate": predicate,
                "attack": evaluate(predicate, sample),
                "normal": normal_result,
                "confidence_basis": "RETAINED_EVIDENCE_NOT_ATTACK_PROBABILITY",
                "approval_conditions": [
                    "VERIFY_TARGET_OWNERSHIP",
                    "REVIEW_NORMAL_TRAFFIC",
                    "HUMAN_APPROVAL",
                ],
                "exclusions": ["LEGITIMATE_SHARED_SERVICES", "INCOMPLETE_OBSERVATIONS"],
                "invalidation": ["DATASET_OR_TOPOLOGY_CHANGE", "REVALIDATE_BEFORE_EACH_USE"],
                "supported_export_targets": ["STRUCTURED_JSON"],
                "automatic_enforcement": False,
            }
            candidate["id"] = "ddos-sig-" + digest(predicate)[:16]
            if len(encoded(candidate["evaluation"])) > MAX_EVALUATION_BYTES:
                raise ValueError("signature evaluation byte limit")
        publication_bytes += len(encoded(finding["signature_candidates"]))
        if publication_bytes > MAX_PUBLICATION_BYTES:
            raise ValueError("signature publication byte limit")
