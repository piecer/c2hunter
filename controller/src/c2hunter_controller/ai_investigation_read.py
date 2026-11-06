"""Bounded read-only acquisition, separate from historical approval semantics.

Reuse only metered low-level storage readers. Caller holds its repository fence
and SQL snapshot through projection. No generic job hydration or candidate read.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from functools import wraps
from typing import Any, Literal

from . import historical_read as bounded
from .ai_investigation_contract import (
    VERSION,
    InvestigationError,
    Observation,
    SourceBinding,
    SourceSnapshot,
    TCPFlag,
    digest,
)


def validate_arguments(job_id: str, expected: str | None) -> None:
    if (
        type(job_id) is not str
        or not 1 <= len(job_id) <= 200
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in job_id)
        or (
            expected is not None
            and (type(expected) is not str or re.fullmatch(r"[0-9a-f]{64}", expected) is None)
        )
    ):
        raise InvestigationError("INVALID_SOURCE_ARGUMENTS")
    try:
        job_id.encode("utf-8")
    except UnicodeError:
        raise InvestigationError("INVALID_SOURCE_ARGUMENTS") from None


def _state(metadata: dict[str, Any], job_id: str) -> None:
    dataset_id = metadata.get("dataset_id")
    if (
        type(dataset_id) is not str
        or not 1 <= len(dataset_id) <= 200
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in dataset_id)
    ):
        raise InvestigationError("SOURCE_INVALID")
    if metadata.get("id") != job_id:
        raise InvestigationError("SOURCE_INVALID")
    if metadata.get("status") not in ("COMPLETED", "PARTIALLY_COMPLETED"):
        raise InvestigationError("SOURCE_STATE")
    analysis = metadata.get("analysis")
    if type(analysis) is not dict or analysis.get("module") not in (
        "c2",
        "network_anomaly",
        "ddos_attack",
    ):
        raise InvestigationError("SOURCE_UNAVAILABLE")


def _project(metadata: dict[str, Any], rows: list[dict[str, Any]]) -> SourceSnapshot:
    observations = []
    for ordinal, raw in enumerate(rows):
        fields = set(Observation.model_fields) - {
            "ordinal",
            "row_sha256",
            "present_fields",
            "unavailable_fields",
            "payload_length_source",
        }
        if "tcp_flags_observed" in raw and type(raw["tcp_flags_observed"]) is not bool:
            raise InvestigationError("SOURCE_INVALID")
        selected = {key: raw[key] for key in fields if key in raw}
        unavailable = []
        protocol = selected.get("protocol")
        if type(protocol) is str:
            if protocol.upper() in ("TCP", "UDP", "ICMP", "ICMPV6", "OTHER"):
                selected["protocol"] = protocol.upper()
            elif re.fullmatch(r"IP_(?:0|[1-9][0-9]{0,2})", protocol) and int(protocol[3:]) <= 255:
                selected["protocol"] = "OTHER"
                unavailable.append("protocol")
        # BIDIRECTIONAL describes traffic in both directions, not internal peers.
        # UNKNOWN is the closed evidence direction's explicit unavailable bucket.
        if selected.get("direction") == "BIDIRECTIONAL":
            selected["direction"] = "UNKNOWN"
            unavailable.append("direction")
        for key, maximum, pattern in (
            ("domain", 253, r"[a-zA-Z0-9_.-]+"),
            ("tls_fingerprint", 128, r"[a-zA-Z0-9:_-]+"),
            ("certificate_fingerprint", 128, r"[a-zA-Z0-9:_-]+"),
        ):
            value = selected.get(key)
            if value is not None:
                if type(value) is not str:
                    raise InvestigationError("SOURCE_INVALID")
                if len(value) > maximum or re.fullmatch(pattern, value) is None:
                    selected[key] = None
                    unavailable.append(key)
        selected["unavailable_fields"] = tuple(sorted(unavailable))
        if selected.get("tcp_flags") is not None:
            flags = selected["tcp_flags"]
            if type(flags) is not dict:
                raise InvestigationError("SOURCE_INVALID")
            # FlowRecord also carries ratios, connection_count, ns and extension
            # counters. They remain in the raw commitment, never packet flags.
            # The raw object is already bounded by the source row byte gate.
            known: set[Literal["syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"]] = {
                "syn",
                "ack",
                "fin",
                "rst",
                "psh",
                "urg",
                "ece",
                "cwr",
            }
            for name, value in flags.items():
                if (
                    type(name) is not str
                    or not 1 <= len(name) <= 64
                    or type(value) not in (int, float)
                    or not 0 <= value <= 2**64 - 1
                    or (name not in {"rst_ratio", "syn_ack_ratio"} and type(value) is not int)
                ):
                    raise InvestigationError("SOURCE_INVALID")
            selected["tcp_flags"] = (
                None
                if raw.get("tcp_flags_observed") is False
                else tuple(
                    TCPFlag(name=k, count=flags[k]) for k in sorted(known.intersection(flags))
                )
                or None
            )
        # Payload-feature extraction intentionally omits empty payloads. A
        # complete single TCP/UDP packet has a separate authoritative length;
        # neither an incomplete capture nor an aggregate proves observed zero.
        transport_length = raw.get("transport_payload_length")
        if transport_length is not None and (
            type(transport_length) is not int or not 0 <= transport_length < 2**40
        ):
            raise InvestigationError("SOURCE_INVALID")
        if "packet_evidence_complete" in raw and type(raw["packet_evidence_complete"]) is not bool:
            raise InvestigationError("SOURCE_INVALID")
        selected["payload_length_source"] = (
            "payload_length" if selected.get("payload_length") is not None else None
        )
        if (
            selected.get("payload_length") is None
            and transport_length is not None
            and raw.get("packet_evidence_complete") is True
            and raw.get("packet_count") == 1
            and raw.get("duration_seconds") == 0
            and selected.get("protocol") in ("TCP", "UDP")
        ):
            selected["payload_length"] = transport_length
            selected["payload_length_source"] = "complete_transport_packet"
        observations.append(
            Observation(
                ordinal=ordinal,
                row_sha256=digest(raw),
                present_fields=tuple(sorted(fields.intersection(raw))),
                **selected,
            )
        )
    binding = dict(
        version=VERSION,
        job_id=metadata["id"],
        dataset_id=metadata["dataset_id"],
        metadata_sha256=digest(metadata),
        rows_sha256=digest([row.row_sha256 for row in observations]),
        projection_sha256=digest([metadata["status"], [r.model_dump() for r in observations]]),
    )
    return SourceSnapshot(
        binding=SourceBinding(**binding, source_sha256=digest(binding)),
        status=metadata["status"],
        rows=tuple(observations),
    )


def _safe[**P, T](operation: Callable[P, T]) -> Callable[P, T]:
    @wraps(operation)
    def run(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return operation(*args, **kwargs)
        except InvestigationError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
            code = "SOURCE_LIMIT" if str(exc) == "BASELINE_SOURCE_LIMIT" else "SOURCE_INVALID"
            raise InvestigationError(code) from None

    return run


def _checked(snapshot: SourceSnapshot, expected: str | None) -> SourceSnapshot:
    if expected is not None and snapshot.binding.source_sha256 != expected:
        raise InvestigationError("SOURCE_CHANGED")
    return snapshot


@_safe
def memory_snapshot(
    jobs: Mapping[str, dict[str, Any]],
    job_id: str,
    expected: str | None = None,
) -> SourceSnapshot:
    if job_id not in jobs:
        raise InvestigationError("SOURCE_NOT_FOUND")
    raw = jobs[job_id]
    metadata = bounded._metadata(raw)
    _state(metadata, job_id)
    if "flow_records" not in raw:
        raise InvestigationError("SOURCE_UNAVAILABLE")
    rows = bounded._admit_rows(raw["flow_records"])
    return _checked(_project(metadata, rows), expected)


@_safe
def sqlite_snapshot(
    connection: Any,
    job_id: str,
    expected: str | None = None,
) -> SourceSnapshot:
    metadata = bounded._sqlite_metadata(connection, job_id)
    if metadata is None:
        raise InvestigationError("SOURCE_NOT_FOUND")
    _state(metadata, job_id)
    if (
        connection.execute("SELECT 1 FROM job_flow_records WHERE job_id=?", (job_id,)).fetchone()
        is None
    ):
        raise InvestigationError("SOURCE_UNAVAILABLE")
    return _checked(_project(metadata, bounded._sqlite_flows(connection, job_id)), expected)


@_safe
def postgres_snapshot(cursor: Any, job_id: str, expected: str | None = None) -> SourceSnapshot:
    """Requires the caller's REPEATABLE READ READ ONLY transaction."""
    metadata = bounded._pg_metadata(cursor, job_id)
    if metadata is None:
        raise InvestigationError("SOURCE_NOT_FOUND")
    _state(metadata, job_id)
    cursor.execute("SELECT 1 FROM job_flow_records WHERE job_id=%s", (job_id,))
    legacy = cursor.fetchone() is not None
    cursor.execute("SELECT 1 FROM job_flow_record_chunks WHERE job_id=%s LIMIT 1", (job_id,))
    chunks = cursor.fetchone() is not None
    if not legacy and not chunks:
        raise InvestigationError("SOURCE_UNAVAILABLE")
    return _checked(_project(metadata, bounded._pg_flows(cursor, job_id)), expected)
