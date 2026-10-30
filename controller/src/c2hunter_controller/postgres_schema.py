"""Read-only PostgreSQL compatibility gate (indexes are not schema versions).

The v1 catalog digest covers application tables, columns and constraints, not
physical OIDs, schema names or secondary indexes. The fixture records the exact
fresh-install layout behind the digest. Historical owner guards are verified by
their existing semantic validator, including trigger/function definitions.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from . import historical_ai_sql
from ._baseline_storage import BaselineStorageError

VERSION = 1
# Bound to tests/fixtures/postgres_schema_v1.json; update only with a migration.
LAYOUT_SHA256 = "b1089969bcea23e54a8697c5995f22cff22d3707b618d8e8542a806e9dadaff8"
TABLES = (
    "ai_analysis_runs",
    "ai_candidate_assessments",
    "ai_feedback",
    "ai_generated_artifacts",
    "audit_events",
    "baseline_catalog",
    "baseline_generations",
    "baseline_operations",
    "baseline_scopes",
    "candidate_records",
    "controller_objects",
    "controller_schema_version",
    "job_candidates",
    "job_flow_record_chunks",
    "job_flow_records",
    "job_idempotency",
    "job_payload_signatures",
    "pcap_capture_source_versions",
    "pcap_export_jobs",
    "pcap_offset_index_generations",
    "pcap_offset_index_interfaces",
    "pcap_offset_index_jobs",
    "pcap_offset_index_owners",
    "pcap_offset_index_packets",
    "pcap_posting_index_chunks",
    "pcap_posting_index_generations",
    "pcap_posting_index_intents",
    "pcap_posting_index_jobs",
    "pcap_posting_index_owners",
)


class SchemaNotReady(BaselineStorageError):
    """Compatibility refusal retains the public storage-unavailable contract."""


def layout(cursor: Any) -> list[Any]:
    cursor.execute(
        "SELECT c.relname,c.relkind,c.relrowsecurity,c.relforcerowsecurity,"
        "(SELECT jsonb_agg(jsonb_build_array(a.attname,"
        "pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,"
        "a.attidentity,a.attgenerated,"
        "(SELECT pg_catalog.pg_get_expr(d.adbin,d.adrelid) FROM pg_catalog.pg_attrdef d "
        "WHERE d.adrelid=a.attrelid AND d.adnum=a.attnum)) ORDER BY a.attname) "
        "FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid "
        "AND a.attnum>0 AND NOT a.attisdropped),"
        "(SELECT jsonb_agg(jsonb_build_array(con.contype,con.convalidated,"
        "con.condeferrable,con.condeferred,pg_catalog.pg_get_constraintdef(con.oid)) "
        "ORDER BY con.contype,pg_catalog.pg_get_constraintdef(con.oid)) "
        "FROM pg_catalog.pg_constraint con WHERE con.conrelid=c.oid) "
        "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n "
        "ON n.oid=c.relnamespace WHERE n.nspname=current_schema() "
        "AND c.relname=ANY(%s) ORDER BY c.relname",
        (list(TABLES),),
    )
    return list(cursor.fetchall())


def verify_layout(cursor: Any) -> None:
    encoded = json.dumps(layout(cursor), separators=(",", ":"), ensure_ascii=True).encode()
    if hashlib.sha256(encoded).hexdigest() != LAYOUT_SHA256:
        raise SchemaNotReady()
    historical_ai_sql.postgres_schema(cursor)


def require_ready(cursor: Any) -> None:
    # Missing/malformed marker columns can fail before value validation. Map
    # schema faults, not connection failures, into the stable compatibility error.
    import psycopg

    try:
        cursor.execute("SELECT version FROM controller_schema_version LIMIT 2")
        if cursor.fetchall() != [(VERSION,)]:
            raise SchemaNotReady()
        verify_layout(cursor)
    except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn) as exc:
        raise SchemaNotReady() from exc
