"""JOB acquisition uses existing metered readers under the repository's source fence."""

from collections.abc import Mapping
from typing import Any

from . import historical_read as bounded
from .ai_investigation_contract import InvestigationError, canonical_bytes
from .ai_investigation_read import _checked, _project, _safe
from .ai_investigation_read import _state as _ip_state
from .ai_job_investigation_behavior import discover
from .ai_job_investigation_pool import build_pool
from .ai_job_investigation_schema import PREPARATION_BYTES, JobPreparation


def _state(metadata: dict[str, Any], job_id: str) -> None:
    _ip_state(metadata, job_id)
    if metadata["analysis"]["module"] != "c2":
        raise InvestigationError("SOURCE_UNAVAILABLE")


def _prepare(
    metadata: dict[str, Any], rows: list[dict[str, Any]], expected: str | None
) -> JobPreparation:
    snapshot = _checked(_project(metadata, rows), expected)
    if len(canonical_bytes(snapshot.model_dump())) > PREPARATION_BYTES:
        raise InvestigationError("SOURCE_LIMIT")
    scores, coverage = discover(metadata, rows)
    pool = build_pool(snapshot, scores, coverage)
    if (
        len(canonical_bytes({"snapshot": snapshot.model_dump(), "pool": pool.model_dump()}))
        > PREPARATION_BYTES
    ):
        raise InvestigationError("SOURCE_LIMIT")
    return JobPreparation(snapshot=snapshot, pool=pool)


@_safe
def memory_preparation(
    jobs: Mapping[str, dict[str, Any]], job_id: str, expected: str | None = None
) -> JobPreparation:
    if job_id not in jobs:
        raise InvestigationError("SOURCE_NOT_FOUND")
    raw = jobs[job_id]
    metadata = bounded._metadata(raw)
    _state(metadata, job_id)
    if "flow_records" not in raw:
        raise InvestigationError("SOURCE_UNAVAILABLE")
    return _prepare(metadata, bounded._admit_rows(raw["flow_records"]), expected)


@_safe
def sqlite_preparation(connection: Any, job_id: str, expected: str | None = None) -> JobPreparation:
    metadata = bounded._sqlite_metadata(connection, job_id)
    if metadata is None:
        raise InvestigationError("SOURCE_NOT_FOUND")
    _state(metadata, job_id)
    if (
        connection.execute("SELECT 1 FROM job_flow_records WHERE job_id=?", (job_id,)).fetchone()
        is None
    ):
        raise InvestigationError("SOURCE_UNAVAILABLE")
    return _prepare(metadata, bounded._sqlite_flows(connection, job_id), expected)


@_safe
def postgres_preparation(cursor: Any, job_id: str, expected: str | None = None) -> JobPreparation:
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
    return _prepare(metadata, bounded._pg_flows(cursor, job_id), expected)
