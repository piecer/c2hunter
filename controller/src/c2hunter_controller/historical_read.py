"""Bounded persisted-source acquisition. No generic repository loaders.

The public repository owns its fence throughout admission and projection. This
module has no approval authority. PostgreSQL JSONB cannot attest original wire
key uniqueness. Stored byte bounds are not database-engine RSS/CPU bounds.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import wraps
from typing import Any, Literal, cast

from . import historical_baseline as h
from . import historical_source as source

Purpose = Literal["APPROVAL", "COMPARISON"]
METADATA_BYTES = 256 * 1024
FLOW_BYTES = 8 * 1024 * 1024
ROW_BYTES = 64 * 1024
CANDIDATE_BYTES = 4 * 1024 * 1024
FLOW_COUNT = 8192
CANDIDATE_COUNT = 2048
BATCH = 128
READ_CODES = source.SOURCE_ERROR_CODES | {
    "BASELINE_SOURCE_NOT_FOUND",
    "BASELINE_SOURCE_CHANGED",
    "BASELINE_CANDIDATE_LIMIT",
    "BASELINE_STORAGE_UNAVAILABLE",
    "BASELINE_BUSY",
}


class HistoricalReadError(ValueError):
    """Closed static error; never exposes stored inputs or driver diagnostics."""

    def __init__(self, code: str = "BASELINE_SOURCE_INVALID") -> None:
        self.code = code if code in READ_CODES else "BASELINE_SOURCE_INVALID"
        super().__init__(self.code)


@dataclass(frozen=True)
class _Acquired:
    metadata: list[dict[str, Any]]
    flows: list[dict[str, Any]]
    candidates: list[tuple[int, dict[str, Any]]]


class HistoricalReadSnapshot(h.FrozenDTO):
    source: source.SourceProjection
    candidates: tuple[h.CandidateProjection, ...]
    source_binding_sha256: h.Digest


@dataclass(frozen=True, slots=True)
class HistoricalAITargetSnapshot:
    """AI-only acquisition; never admitted as an approved source snapshot."""

    source: source.SourceProjection | source.UnreviewedEvaluationTarget
    candidates: tuple[h.CandidateProjection, ...]
    source_binding_sha256: str


def _safe[**P, T](operation: Callable[P, T]) -> Callable[P, T]:
    @wraps(operation)
    def run(*args: P.args, **kwargs: P.kwargs) -> T:
        try:
            return operation(*args, **kwargs)
        except HistoricalReadError:
            raise
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError) as exc:
            code = exc.args[0] if exc.args and type(exc.args[0]) is str else ""
            raise HistoricalReadError(code) from None

    return run


def validate_arguments(
    job_id: str, purpose: Purpose, scope: h.ScopeConfig, quality_review: h.QualityReview | None
) -> None:
    if (
        type(job_id) is not str
        or not 1 <= len(job_id) <= 200
        or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in job_id)
        or type(purpose) is not str
        or purpose not in ("APPROVAL", "COMPARISON")
        or type(scope) is not h.ScopeConfig
        or (quality_review is not None and type(quality_review) is not h.QualityReview)
    ):
        raise HistoricalReadError()
    try:
        job_id.encode("utf-8")
    except UnicodeError:
        raise HistoricalReadError() from None


def _finish(
    metadata: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    candidates: list[tuple[int, dict[str, Any]]],
    purpose: Purpose,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalReadSnapshot:
    raw = dict(metadata[0], flow_records=flows)
    _state(raw, purpose)
    projected = source.project_source(
        raw, ancestors=tuple(metadata[1:]), scope=scope, quality_review=quality_review
    )
    selected = tuple(h.project_candidate(row, position=position) for position, row in candidates)
    return HistoricalReadSnapshot(
        source=projected,
        candidates=selected,
        source_binding_sha256=h.source_binding_sha256(
            projected.source_binding(), purpose=purpose, candidates=selected
        ),
    )


def _finish_ai_target(
    acquired: _Acquired, scope: h.ScopeConfig, quality_review: h.QualityReview | None
) -> HistoricalAITargetSnapshot:
    if scope.kind != "EVALUATION" or quality_review is not None:
        value = _finish(
            acquired.metadata,
            acquired.flows,
            acquired.candidates,
            "COMPARISON",
            scope,
            quality_review,
        )
        return HistoricalAITargetSnapshot(
            value.source, value.candidates, value.source_binding_sha256
        )
    from ._baseline_storage import _preview_binding, _preview_candidates

    binding = _preview_binding(acquired)
    target = source.unreviewed_evaluation_target(binding, scope=scope)
    candidates = _preview_candidates(acquired)
    return HistoricalAITargetSnapshot(
        target,
        candidates,
        h.source_binding_sha256(binding, purpose="COMPARISON", candidates=candidates),
    )


def _state(raw: dict[str, Any], purpose: Purpose) -> None:
    analysis = raw.get("analysis")
    if type(analysis) is not dict or analysis.get("module") != "c2":
        raise HistoricalReadError()
    if raw.get("status") not in (
        ("COMPLETED",) if purpose == "APPROVAL" else ("COMPLETED", "PARTIALLY_COMPLETED")
    ):
        raise HistoricalReadError("BASELINE_SOURCE_STATE")


def _metadata(raw: dict[str, Any]) -> dict[str, Any]:
    # Meter the original values before even a shallow metadata projection.
    budget = h._OriginalBudget(METADATA_BYTES)
    budget.object_items(
        ((k, v) for k, v in raw.items() if k not in {"flow_records", "payload_signatures"}), 0
    )
    return {k: v for k, v in raw.items() if k not in {"flow_records", "payload_signatures"}}


def _chain(job_id: str, get: Callable[[str], dict[str, Any] | None]) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    current: Any = job_id
    while current is not None:
        if (
            type(current) is not str
            or not 1 <= len(current) <= 200
            or current in seen
            or len(nodes) == 16
        ):
            raise HistoricalReadError("BASELINE_SOURCE_LINEAGE_INVALID")
        seen.add(current)
        node = get(current)
        if node is None:
            raise HistoricalReadError(
                "BASELINE_SOURCE_NOT_FOUND" if not nodes else "BASELINE_SOURCE_LINEAGE_INVALID"
            )
        if node.get("id") != current or "parent_job_id" not in node:
            raise HistoricalReadError("BASELINE_SOURCE_LINEAGE_INVALID")
        nodes.append(node)
        current = node["parent_job_id"]
    return nodes


def _admit_rows(rows: object, *, candidates: bool = False) -> list[dict[str, Any]]:
    limit = CANDIDATE_COUNT if candidates else FLOW_COUNT
    code = "BASELINE_CANDIDATE_LIMIT" if candidates else "BASELINE_SOURCE_LIMIT"
    if type(rows) is not list:
        raise HistoricalReadError()
    if len(rows) > limit:
        raise HistoricalReadError(code)
    budget = h._OriginalBudget(CANDIDATE_BYTES if candidates else FLOW_BYTES)
    if not candidates:
        budget.add(2 + max(0, len(rows) - 1))
    budget.node(0)
    try:
        for row in rows:
            if type(row) is not dict:
                raise HistoricalReadError()
            h._validate_original(row, max_bytes=ROW_BYTES)
            budget.visit(row, 1)
    except ValueError as exc:
        if str(exc) == "BASELINE_SOURCE_LIMIT":
            raise HistoricalReadError(code) from None
        raise
    return cast("list[dict[str, Any]]", rows)


@_safe
def _memory_acquire(
    jobs: Mapping[str, dict[str, Any]],
    candidate_sets: Mapping[str, list[dict[str, Any]]],
    job_id: str,
    purpose: Purpose,
    *,
    structural: bool = False,
) -> _Acquired:
    """Caller owns the complete fence and transaction; never changes custody."""
    metadata = _chain(job_id, lambda key: _metadata(jobs[key]) if key in jobs else None)
    _state(metadata[0], "COMPARISON" if structural else purpose)
    flows = _admit_rows(jobs[job_id].get("flow_records"))
    candidates = (
        _admit_rows(candidate_sets.get(job_id, []), candidates=True)
        if purpose == "COMPARISON"
        else []
    )
    return _Acquired(metadata, flows, list(enumerate(candidates)))


@_safe
def memory_snapshot(
    jobs: Mapping[str, dict[str, Any]],
    candidate_sets: Mapping[str, list[dict[str, Any]]],
    job_id: str,
    purpose: Purpose,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalReadSnapshot:
    """Caller holds MemoryRepository's public lock; borrowed values never escape."""
    acquired = _memory_acquire(jobs, candidate_sets, job_id, purpose)
    return _finish(
        acquired.metadata, acquired.flows, acquired.candidates, purpose, scope, quality_review
    )


@_safe
def memory_ai_target(
    jobs: Mapping[str, dict[str, Any]],
    candidate_sets: Mapping[str, list[dict[str, Any]]],
    job_id: str,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalAITargetSnapshot:
    """Caller holds the admission lock through read, build and persistence."""
    validate_arguments(job_id, "COMPARISON", scope, quality_review)
    return _finish_ai_target(
        _memory_acquire(jobs, candidate_sets, job_id, "COMPARISON"), scope, quality_review
    )


class _RowAdmission:
    """Charge decoded SQL rows before retention; at most one overflow row parses."""

    def __init__(self, *, candidates: bool = False) -> None:
        self.candidates = candidates
        self.count = 0
        self.limit = CANDIDATE_COUNT if candidates else FLOW_COUNT
        self.code = "BASELINE_CANDIDATE_LIMIT" if candidates else "BASELINE_SOURCE_LIMIT"
        self.budget = h._OriginalBudget(CANDIDATE_BYTES if candidates else FLOW_BYTES)
        self.budget.node(0)
        if not candidates:
            self.budget.add(2)

    def admit(self, row: dict[str, Any]) -> None:
        if self.count >= self.limit:
            raise HistoricalReadError(self.code)
        try:
            h._validate_original(row, max_bytes=ROW_BYTES)
            if not self.candidates and self.count:
                self.budget.add(1)
            self.budget.visit(row, 1)
        except ValueError as exc:
            if str(exc) == "BASELINE_SOURCE_LIMIT":
                raise HistoricalReadError(self.code) from None
            raise
        self.count += 1


def _decode_flow_rows(cursor: Any) -> list[dict[str, Any]]:
    admission = _RowAdmission()
    rows = []
    for row in _batches(cursor):
        value = _decode(row[0], max_bytes=ROW_BYTES)
        admission.admit(value)
        rows.append(value)
    return rows


def _decode(raw: str, *, max_bytes: int = METADATA_BYTES) -> dict[str, Any]:
    if type(raw) is not str:
        raise HistoricalReadError()
    value = h.thaw_original_json(h.decode_original_json(raw, max_bytes=max_bytes))
    if type(value) is not dict:
        raise HistoricalReadError()
    return value


def _batches(cursor: Any) -> Any:
    while batch := cursor.fetchmany(BATCH):
        yield from batch


def _sqlite_metadata(connection: Any, job_id: str) -> dict[str, Any] | None:
    size = connection.execute(
        "SELECT length(CAST(data AS BLOB)),typeof(data) FROM objects WHERE kind='job' AND id=?",
        (job_id,),
    ).fetchone()
    if size is None:
        return None
    if size[1] != "text":
        raise HistoricalReadError()
    if size[0] > METADATA_BYTES:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    raw = connection.execute(
        "SELECT data FROM objects WHERE kind='job' AND id=?", (job_id,)
    ).fetchone()
    value = _decode(raw[0])
    # Initializers migrate these. A residual embedded legacy array is explicitly
    # unsupported, even if small: never select an arbitrary competing source.
    if "flow_records" in value or "payload_signatures" in value:
        raise HistoricalReadError()
    return value


def _sqlite_flows(connection: Any, job_id: str) -> list[dict[str, Any]]:
    size = connection.execute(
        "SELECT length(CAST(data AS BLOB)),typeof(data) FROM job_flow_records WHERE job_id=?",
        (job_id,),
    ).fetchone()
    if size is None:
        raise HistoricalReadError()
    if size[1] != "text":
        raise HistoricalReadError()
    if size[0] > FLOW_BYTES:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    valid = connection.execute(
        "SELECT json_valid(data) FROM job_flow_records WHERE job_id=?", (job_id,)
    ).fetchone()[0]
    if not valid:
        raise HistoricalReadError()
    shape = connection.execute(
        "SELECT json_type(data),json_array_length(data) FROM job_flow_records WHERE job_id=?",
        (job_id,),
    ).fetchone()
    if shape[0] != "array":
        raise HistoricalReadError()
    if shape[1] > FLOW_COUNT:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    row_gate = connection.execute(
        "SELECT COALESCE(max(length(CAST(j.value AS BLOB))),0), "
        "COALESCE(sum(j.type != 'object'),0) "
        "FROM job_flow_records f, json_each(f.data) j WHERE f.job_id=?",
        (job_id,),
    ).fetchone()
    if row_gate[0] > ROW_BYTES:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    if row_gate[1]:
        raise HistoricalReadError()
    cursor = connection.execute(
        "SELECT j.value FROM job_flow_records f, json_each(f.data) j "
        "WHERE f.job_id=? ORDER BY j.key",
        (job_id,),
    )
    return _decode_flow_rows(cursor)


def _sqlite_candidates(connection: Any, job_id: str) -> list[tuple[int, dict[str, Any]]]:
    # Residual pre-migration candidate arrays cannot silently become an empty set.
    if connection.execute("SELECT 1 FROM candidates WHERE job_id=?", (job_id,)).fetchone():
        raise HistoricalReadError()
    count, total, largest, invalid = connection.execute(
        "SELECT count(*),COALESCE(sum(length(CAST(data AS BLOB))),0),"
        "COALESCE(max(length(CAST(data AS BLOB))),0),"
        "COALESCE(sum(typeof(data)!='text'),0) FROM candidate_records WHERE job_id=?",
        (job_id,),
    ).fetchone()
    if invalid:
        raise HistoricalReadError()
    if count > CANDIDATE_COUNT or total > CANDIDATE_BYTES or largest > ROW_BYTES:
        raise HistoricalReadError("BASELINE_CANDIDATE_LIMIT")
    cursor = connection.execute(
        "SELECT position,candidate_id,data FROM candidate_records WHERE job_id=? "
        "ORDER BY position,candidate_id",
        (job_id,),
    )
    rows = []
    admission = _RowAdmission(candidates=True)
    for position, candidate_id, raw in _batches(cursor):
        value = _decode(raw, max_bytes=ROW_BYTES)
        if value.get("id") != candidate_id:
            raise HistoricalReadError()
        admission.admit(value)
        rows.append((position, value))
    return rows


@_safe
def _sqlite_acquire(
    connection: Any,
    job_id: str,
    purpose: Purpose,
    *,
    structural: bool = False,
) -> _Acquired:
    """Caller owns the complete fence and transaction; never changes custody."""
    metadata = _chain(job_id, lambda key: _sqlite_metadata(connection, key))
    _state(metadata[0], "COMPARISON" if structural else purpose)
    flows = _sqlite_flows(connection, job_id)
    candidates = _sqlite_candidates(connection, job_id) if purpose == "COMPARISON" else []
    return _Acquired(metadata, flows, candidates)


@_safe
def sqlite_snapshot(
    connection: Any,
    job_id: str,
    purpose: Purpose,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalReadSnapshot:
    """Private held-read helper; public adapter owns the connection transaction."""
    acquired = _sqlite_acquire(connection, job_id, purpose)
    return _finish(
        acquired.metadata, acquired.flows, acquired.candidates, purpose, scope, quality_review
    )


@_safe
def sqlite_ai_target(
    connection: Any,
    job_id: str,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalAITargetSnapshot:
    """Use the caller's held SQLite transaction; never commit or reopen it."""
    validate_arguments(job_id, "COMPARISON", scope, quality_review)
    return _finish_ai_target(
        _sqlite_acquire(connection, job_id, "COMPARISON"), scope, quality_review
    )


def _pg_metadata(cursor: Any, job_id: str) -> dict[str, Any] | None:
    cursor.execute(
        "SELECT octet_length(data::text) FROM controller_objects WHERE kind='job' AND id=%s",
        (job_id,),
    )
    size = cursor.fetchone()
    if size is None:
        return None
    if size[0] > METADATA_BYTES:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    # The predicate repeats admission on the materializing statement: discovery
    # is not fenced yet and a writer could replace metadata between statements.
    cursor.execute(
        "SELECT data::text FROM controller_objects WHERE kind='job' AND id=%s "
        "AND octet_length(data::text)<=%s",
        (job_id, METADATA_BYTES),
    )
    row = cursor.fetchone()
    if row is None:
        raise HistoricalReadError("BASELINE_SOURCE_CHANGED")
    value = _decode(row[0])
    if "flow_records" in value or "payload_signatures" in value:
        raise HistoricalReadError()
    return value


def _pg_flows(cursor: Any, job_id: str) -> list[dict[str, Any]]:
    cursor.execute(
        "SELECT chunk_no FROM job_flow_record_chunks WHERE job_id=%s ORDER BY chunk_no LIMIT 65",
        (job_id,),
    )
    chunks = list(_batches(cursor))
    if len(chunks) > 64:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    cursor.execute("SELECT 1 FROM job_flow_records WHERE job_id=%s", (job_id,))
    legacy = cursor.fetchone() is not None
    if legacy and chunks:
        raise HistoricalReadError()
    if not legacy and not chunks:
        raise HistoricalReadError()
    table = "job_flow_records" if legacy else "job_flow_record_chunks"
    # The only dynamic SQL tokens are these two code-owned table/order choices.
    cursor.execute(
        f"SELECT COALESCE(sum(octet_length(data::text)),0) FROM {table} WHERE job_id=%s",  # noqa: S608
        (job_id,),
    )
    if cursor.fetchone()[0] > FLOW_BYTES:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    cursor.execute(
        f"SELECT count(*) FROM {table} WHERE job_id=%s AND jsonb_typeof(data)!='array'",  # noqa: S608
        (job_id,),
    )
    if cursor.fetchone()[0]:
        raise HistoricalReadError()
    cursor.execute(
        f"SELECT COALESCE(sum(jsonb_array_length(data)),0) FROM {table} WHERE job_id=%s",  # noqa: S608
        (job_id,),
    )
    if cursor.fetchone()[0] > FLOW_COUNT:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    cursor.execute(
        "SELECT COALESCE(max(octet_length(j.value::text)),0), "  # noqa: S608 -- code-owned table
        "count(*) FILTER (WHERE jsonb_typeof(j.value)!='object') "
        f"FROM {table} f CROSS JOIN LATERAL jsonb_array_elements(f.data) j(value) "  # noqa: S608
        "WHERE f.job_id=%s",
        (job_id,),
    )
    largest, invalid = cursor.fetchone()
    if largest > ROW_BYTES:
        raise HistoricalReadError("BASELINE_SOURCE_LIMIT")
    if invalid:
        raise HistoricalReadError()
    order = "j.position" if legacy else "f.chunk_no,j.position"
    with cursor.connection.cursor(name="h4_flows") as payload:
        payload.execute(
            f"SELECT j.value::text FROM {table} f "  # noqa: S608
            "CROSS JOIN LATERAL jsonb_array_elements(f.data) WITH ORDINALITY j(value,position) "
            f"WHERE f.job_id=%s ORDER BY {order}",
            (job_id,),
        )
        return _decode_flow_rows(payload)


def _pg_candidates(cursor: Any, job_id: str) -> list[tuple[int, dict[str, Any]]]:
    cursor.execute("SELECT 1 FROM job_candidates WHERE job_id=%s", (job_id,))
    if cursor.fetchone():
        raise HistoricalReadError()
    cursor.execute(
        "SELECT count(*),COALESCE(sum(octet_length(data::text)),0),"
        "COALESCE(max(octet_length(data::text)),0) FROM candidate_records WHERE job_id=%s",
        (job_id,),
    )
    count, total, largest = cursor.fetchone()
    if count > CANDIDATE_COUNT or total > CANDIDATE_BYTES or largest > ROW_BYTES:
        raise HistoricalReadError("BASELINE_CANDIDATE_LIMIT")
    with cursor.connection.cursor(name="h4_candidates") as payload:
        payload.execute(
            "SELECT position,candidate_id,data::text FROM candidate_records WHERE job_id=%s "
            "ORDER BY position,candidate_id",
            (job_id,),
        )
        rows = []
        admission = _RowAdmission(candidates=True)
        for position, candidate_id, raw in _batches(payload):
            value = _decode(raw, max_bytes=ROW_BYTES)
            if value.get("id") != candidate_id:
                raise HistoricalReadError()
            admission.admit(value)
            rows.append((position, value))
    return rows


@_safe
def _postgres_acquire(
    cursor: Any,
    job_id: str,
    purpose: Purpose,
    *,
    structural: bool = False,
) -> _Acquired:
    """Caller owns the complete fence and transaction; never changes custody."""
    discovered = _chain(job_id, lambda key: _pg_metadata(cursor, key))
    # Job rows precede candidate reads. Never chase a changed edge after locks.
    for key in sorted(node["id"] for node in discovered):
        cursor.execute(
            "SELECT id FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE", (key,)
        )
        if cursor.fetchone() is None:
            raise HistoricalReadError("BASELINE_SOURCE_CHANGED")
    metadata = []
    for old in discovered:
        current = _pg_metadata(cursor, old["id"])
        if current != old:
            raise HistoricalReadError("BASELINE_SOURCE_CHANGED")
        metadata.append(current)
    _state(metadata[0], "COMPARISON" if structural else purpose)
    flows = _pg_flows(cursor, job_id)
    candidates = _pg_candidates(cursor, job_id) if purpose == "COMPARISON" else []
    return _Acquired(metadata, flows, candidates)


@_safe
def postgres_snapshot(
    cursor: Any,
    job_id: str,
    purpose: Purpose,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalReadSnapshot:
    acquired = _postgres_acquire(cursor, job_id, purpose)
    return _finish(
        acquired.metadata, acquired.flows, acquired.candidates, purpose, scope, quality_review
    )


@_safe
def postgres_ai_target(
    cursor: Any,
    job_id: str,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> HistoricalAITargetSnapshot:
    """Use the caller's admission cursor and its existing lock order."""
    validate_arguments(job_id, "COMPARISON", scope, quality_review)
    return _finish_ai_target(_postgres_acquire(cursor, job_id, "COMPARISON"), scope, quality_review)
