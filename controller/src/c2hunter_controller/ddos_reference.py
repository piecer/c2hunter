"""Bounded immutable normal-reference acquisition; uses existing global job RBAC.

SQL preflight caps raw transfer before JSON hydration. No historical C2 approval
is reused. Normality is an operator assertion, not an analyzer conclusion.
"""

from __future__ import annotations

import json
from typing import Any

from c2hunter_analysis.ddos_signatures import MAX_RECORDS, EvidenceSample, digest

MAX_SOURCE_BYTES = 1024 * 1024


class ReferenceError(ValueError):
    pass


# Known facts are dataset properties, regardless of the analyzer that ran.
# Absence is unknown, not evidence of zero loss; all references remain coverage-limited.
LOSS_PATHS = (
    ("source", "skipped_packet_count"),
    ("capture_quality", "dropped_packet_count"),
    ("capture_limit", "discarded_packets"),
    ("ddos_coverage_context", "parser_skipped_packet_count"),
    ("ddos_coverage_context", "sensor_dropped_packet_count"),
)
PARTIAL_PATHS = (("capture_incomplete",), ("ddos_coverage_context", "capture_partial"))


def _fact(metadata: dict[str, Any], path: tuple[str, ...]) -> Any:
    value: Any = metadata
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def known_incomplete(metadata: dict[str, Any]) -> bool:
    return bool(
        metadata.get("known_incomplete")
        or any(_fact(metadata, path) for path in LOSS_PATHS + PARTIAL_PATHS)
        or metadata.get("error_code") == "LIVE_CAPTURE_RESTART_INCOMPLETE"
    )


def eligible(metadata: Any, job_id: str, dataset_id: str) -> None:
    if metadata is None:
        raise ReferenceError("DDOS_REFERENCE_NOT_FOUND")
    if metadata.get("id") != job_id or metadata.get("dataset_id") != dataset_id:
        raise ReferenceError("DDOS_REFERENCE_IDENTITY_MISMATCH")
    if metadata.get("status") != "COMPLETED":
        raise ReferenceError("DDOS_REFERENCE_NOT_FINAL")
    if known_incomplete(metadata):
        raise ReferenceError("DDOS_REFERENCE_INCOMPLETE")


def projected(records: Any) -> dict[str, Any]:
    if type(records) is not list or not 1 <= len(records) <= MAX_RECORDS:
        raise ReferenceError("DDOS_REFERENCE_RECORD_LIMIT")
    sample = EvidenceSample()
    for row in records:
        if (
            type(row) is not dict
            or type(row.get("packet_count")) is not int
            or not 1 <= row["packet_count"] <= (2**53 - 1) // MAX_RECORDS
        ):
            raise ReferenceError("DDOS_REFERENCE_INVALID_RECORD")
        sample.add(row)
    if sample.omitted:
        raise ReferenceError("DDOS_REFERENCE_BYTE_LIMIT")
    return {"records": sample.records, "content_digest": digest(sample.records)}


def sqlite_read(connection: Any, job_id: str, dataset_id: str) -> dict[str, Any]:
    # Fixed scalar projection avoids transferring report/snapshot bodies at preflight.
    row = connection.execute(
        "SELECT json_object('id',id,'dataset_id',json_extract(data,'$.dataset_id'),"
        "'status',json_extract(data,'$.status'),'known_incomplete',"
        "((json_extract(data,'$.source.skipped_packet_count') IS NOT NULL AND "
        "json_extract(data,'$.source.skipped_packet_count') != 0) OR "
        "(json_extract(data,'$.capture_quality.dropped_packet_count') IS NOT NULL AND "
        "json_extract(data,'$.capture_quality.dropped_packet_count') != 0) OR "
        "(json_extract(data,'$.capture_limit.discarded_packets') IS NOT NULL AND "
        "json_extract(data,'$.capture_limit.discarded_packets') != 0) OR "
        "(json_extract(data,'$.ddos_coverage_context.parser_skipped_packet_count') IS NOT "
        "NULL AND json_extract(data,'$.ddos_coverage_context.parser_skipped_packet_count') "
        "!= 0) OR (json_extract(data,'$.ddos_coverage_context.sensor_dropped_packet_count') "
        "IS NOT NULL AND "
        "json_extract(data,'$.ddos_coverage_context.sensor_dropped_packet_count') != 0) OR "
        "(json_extract(data,'$.capture_incomplete') IS NOT NULL AND "
        "json_extract(data,'$.capture_incomplete') != 0) OR "
        "(json_extract(data,'$.ddos_coverage_context.capture_partial') IS NOT NULL AND "
        "json_extract(data,'$.ddos_coverage_context.capture_partial') != 0) OR "
        "coalesce(json_extract(data,'$.error_code')='LIVE_CAPTURE_RESTART_INCOMPLETE',false))"
        ") FROM objects WHERE kind='job' AND id=?",
        (job_id,),
    ).fetchone()
    eligible(json.loads(row[0]) if row else None, job_id, dataset_id)
    row = connection.execute(
        "SELECT length(CAST(data AS BLOB)),json_array_length(data) "
        "FROM job_flow_records WHERE job_id=?",
        (job_id,),
    ).fetchone()
    if row is None or not 1 <= row[1] <= MAX_RECORDS:
        raise ReferenceError("DDOS_REFERENCE_RECORD_LIMIT")
    if row[0] > MAX_SOURCE_BYTES:
        raise ReferenceError("DDOS_REFERENCE_BYTE_LIMIT")
    row = connection.execute(
        "SELECT data FROM job_flow_records WHERE job_id=?", (job_id,)
    ).fetchone()
    result = projected(json.loads(row[0]))
    result["coverage_limited"] = True
    return result


def postgres_read(cursor: Any, job_id: str, dataset_id: str) -> dict[str, Any]:
    # Repeatable-read owned transaction is established by the repository caller.
    cursor.execute(
        "SELECT jsonb_build_object('id',id,'dataset_id',data->'dataset_id',"
        "'status',data->'status','known_incomplete',"
        "((data #> '{source,skipped_packet_count}' IS NOT NULL AND data #> "
        "'{source,skipped_packet_count}' NOT IN ('null'::jsonb, 'false'::jsonb, "
        "'0'::jsonb)) OR (data #> '{capture_quality,dropped_packet_count}' IS NOT NULL AND "
        "data #> '{capture_quality,dropped_packet_count}' NOT IN ('null'::jsonb, "
        "'false'::jsonb, '0'::jsonb)) OR (data #> '{capture_limit,discarded_packets}' IS "
        "NOT NULL AND data #> '{capture_limit,discarded_packets}' NOT IN ('null'::jsonb, "
        "'false'::jsonb, '0'::jsonb)) OR (data #> "
        "'{ddos_coverage_context,parser_skipped_packet_count}' IS NOT NULL AND data #> "
        "'{ddos_coverage_context,parser_skipped_packet_count}' NOT IN ('null'::jsonb, "
        "'false'::jsonb, '0'::jsonb)) OR (data #> "
        "'{ddos_coverage_context,sensor_dropped_packet_count}' IS NOT NULL AND data #> "
        "'{ddos_coverage_context,sensor_dropped_packet_count}' NOT IN ('null'::jsonb, "
        "'false'::jsonb, '0'::jsonb)) OR (data #> '{capture_incomplete}' IS NOT NULL AND "
        "data #> '{capture_incomplete}' NOT IN ('null'::jsonb, 'false'::jsonb, '0'::jsonb)) "
        "OR (data #> '{ddos_coverage_context,capture_partial}' IS NOT NULL AND data #> "
        "'{ddos_coverage_context,capture_partial}' NOT IN ('null'::jsonb, 'false'::jsonb, "
        "'0'::jsonb)) OR "
        "coalesce(data->>'error_code'='LIVE_CAPTURE_RESTART_INCOMPLETE',false))"
        ") FROM controller_objects WHERE kind='job' AND id=%s",
        (job_id,),
    )
    row = cursor.fetchone()
    metadata = row[0] if row else None
    eligible(json.loads(metadata) if isinstance(metadata, str) else metadata, job_id, dataset_id)
    cursor.execute(
        "SELECT count(*),coalesce(sum(octet_length(data::text)),0),"
        "coalesce(sum(jsonb_array_length(data)),0) FROM job_flow_record_chunks WHERE job_id=%s",
        (job_id,),
    )
    chunks, size, count = cursor.fetchone()
    if not chunks:
        cursor.execute(
            "SELECT octet_length(data::text),jsonb_array_length(data) "
            "FROM job_flow_records WHERE job_id=%s",
            (job_id,),
        )
        row = cursor.fetchone()
        size, count = row if row else (0, 0)
    if not 1 <= count <= MAX_RECORDS or chunks > MAX_RECORDS:
        raise ReferenceError("DDOS_REFERENCE_RECORD_LIMIT")
    if size > MAX_SOURCE_BYTES:
        raise ReferenceError("DDOS_REFERENCE_BYTE_LIMIT")
    if chunks:
        cursor.execute(
            "SELECT data FROM job_flow_record_chunks WHERE job_id=%s ORDER BY chunk_no", (job_id,)
        )
        rows = cursor.fetchall()
    else:
        cursor.execute("SELECT data FROM job_flow_records WHERE job_id=%s", (job_id,))
        rows = [cursor.fetchone()]
    records = []
    for row in rows:
        records.extend(json.loads(row[0]) if isinstance(row[0], str) else row[0])
    result = projected(records)
    result["coverage_limited"] = True
    return result
