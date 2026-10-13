"""Private baseline catalog storage and structural-preview operations.

Facades hold their repository lock. SQL operations own exactly their public
transaction; acquisition primitives never own one. No live-source foreign keys,
publication authority, background work or callback capabilities are introduced.
"""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from ipaddress import ip_network
from typing import Any, get_args

from c2hunter_analysis.behavior_baseline import BaselineInputError, ReasonCode
from pydantic import TypeAdapter, ValidationError

from . import historical_baseline as h
from . import historical_generation as g
from . import historical_read as r
from . import historical_source as s
from .baseline_admission import BaselineLease


class BaselineStorageError(ValueError):
    def __init__(self, code: str = "BASELINE_STORAGE_UNAVAILABLE") -> None:
        self.code = code
        super().__init__(code)


def _require(ok: bool, code: str = "BASELINE_STORAGE_UNAVAILABLE") -> None:
    if not ok:
        raise BaselineStorageError(code)


def scope_id(value: str) -> str:
    return TypeAdapter(h.UUIDString).validate_python(value, strict=True)


def page_arguments(offset: int, limit: int) -> None:
    _require(type(offset) is int and 0 <= offset <= 16, "BASELINE_SOURCE_INVALID")
    _require(type(limit) is int and 1 <= limit <= 20, "BASELINE_SOURCE_INVALID")


def preview_arguments(identifier: str, job_id: str, revision: int, purpose: r.Purpose) -> None:
    scope_id(identifier)
    _require(type(revision) is int and 0 <= revision <= 2**63 - 1, "BASELINE_SOURCE_INVALID")
    _require(type(job_id) is str and 1 <= len(job_id) <= 200, "BASELINE_SOURCE_INVALID")
    TypeAdapter(h.Identifier).validate_python(job_id, strict=True)
    job_id.encode("utf-8")
    _require(
        type(purpose) is str and purpose in ("APPROVAL", "COMPARISON"), "BASELINE_SOURCE_INVALID"
    )


def new_scope(config: h.ScopeConfig, actor: str, now: datetime) -> g.ScopeView:
    config = g._checked(h.ScopeConfig, config)
    return g.ScopeView(
        config=config,
        config_sha256=h.scope_config_sha256(config),
        control_revision=0,
        frozen=False,
        state="EMPTY",
        accepted_event_end=None,
        active=None,
        previous=None,
        created_by=actor,
        created_at=now,
    )


def _page(items: tuple[g.ScopeView, ...], total: int, offset: int, limit: int) -> g.ScopePage:
    end = offset + len(items)
    return g.ScopePage(
        items=items,
        total=total,
        offset=offset,
        limit=limit,
        next_offset=end if end < total else None,
    )


def _revision(view: g.ScopeView | None, expected: int) -> g.ScopeView:
    if view is None:
        raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
    _require(view.control_revision == expected, "BASELINE_REVISION_CONFLICT")
    return view


@s._safe
def _preview_binding(acquired: r._Acquired) -> h.SourceBindingProjection:
    # Use the reviewed source policy at the raw projection boundary, including
    # typed limits and Pydantic-wrapped causes, before the public read boundary.
    raw = dict(acquired.metadata[0], flow_records=acquired.flows)
    s._original_syn_cap(raw, projected=False)
    # These raw context arrays otherwise reach Pydantic's generic length error,
    # which carries no domain cause. Admit with the existing source array policy.
    for field in ("sensor_ids", "internal_networks"):
        h._array(raw.get(field))
    original = h.project_original_job(raw)
    lineage = tuple(
        h.project_lineage_node(node) for node in (*acquired.metadata[1:], acquired.metadata[0])
    )
    roots = [node for node in lineage if node.parent_job_id is None]
    if len(roots) != 1:
        raise r.HistoricalReadError("BASELINE_SOURCE_LINEAGE_INVALID")
    root = roots[0]
    digest = (
        root.source.value.sha256.value
        if isinstance(root.source, h.Present) and isinstance(root.source.value.sha256, h.Present)
        else None
    )
    return h.SourceBindingProjection(
        original=original,
        lineage=lineage,
        root_job_id=root.id,
        root_identity="pcap:" + digest if digest else h.canonical_json([root.id, root.dataset_id]),
        root_content_sha256=digest,
        origin="PCAP_UPLOAD" if digest else "SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        actual_sensor_id=original.sensor_ids[0],
        event_start=h._utc(original.start_time),
        event_end=h._utc(original.end_time),
        internal_networks=tuple(
            sorted(str(ip_network(network, strict=False)) for network in original.internal_networks)
        ),
        quality=h.aggregate_lineage_quality(lineage, selected_job_id=original.id),
    )


@s._safe
def _preview_candidates(acquired: r._Acquired) -> tuple[h.CandidateProjection, ...]:
    return tuple(
        h.project_candidate(row, position=position) for position, row in acquired.candidates
    )


@r._safe
def finish_preview(acquired: r._Acquired, view: g.ScopeView, purpose: r.Purpose) -> g.SourcePreview:
    binding = _preview_binding(acquired)
    original = binding.original
    request = s.structural_preview_input(binding, scope=view.config)
    counts = s.calculate_structural_preview(request)
    candidates = _preview_candidates(acquired)
    source_hash = h.source_binding_sha256(binding, purpose=purpose, candidates=candidates)
    observation, feature = s._hashes(
        binding, request.strict_flows, request.trusted_peers, view.config.sensor_key
    )
    quality = binding.quality
    reasons: set[ReasonCode] = set(counts.reasons)
    reasons.update({"ADMIN_ASSERTED_IDENTITY", "PRODUCER_COMPLETENESS_UNKNOWN"})
    if not counts.profile_count:
        reasons.add("INSUFFICIENT_STREAM_SAMPLES")
    if quality.known_partial:
        reasons.add("SOURCE_PARTIAL_CAPTURE" if purpose == "APPROVAL" else "TARGET_PARTIAL_CAPTURE")
    if quality.clock_uncertain:
        reasons.add("SOURCE_CLOCK_UNCERTAIN")
    offsets = [
        v for bound in quality.sensor_offset_bounds for v in (bound.minimum_ms, bound.maximum_ms)
    ]
    offset = min(offsets, key=lambda value: (-abs(value), value)) if offsets else None
    return g.SourcePreview(
        scope_id=view.config.scope_id,
        scope_revision=view.control_revision,
        scope_config_sha256=view.config_sha256,
        source_job_id=original.id,
        root_job_id=binding.root_job_id,
        dataset_id=original.dataset_id,
        source_binding_sha256=source_hash,
        observation_sha256=observation,
        feature_observation_sha256=feature,
        origin=binding.origin,
        origin_assurance=binding.origin_assurance,
        actual_sensor_id=binding.actual_sensor_id,
        event_start=binding.event_start,
        event_end=binding.event_end,
        flow_count=len(acquired.flows),
        profile_count=counts.profile_count,
        eligible_profile_count=counts.eligible_profile_count,
        excluded_profile_count=counts.excluded_profile_count,
        admissible=counts.eligible_profile_count > 0
        and not quality.known_partial
        and not quality.clock_uncertain,
        reasons=tuple(sorted(reasons)),
        required_review="EXPLICIT_NORMAL_AND_QUALITY_ASSERTION",
        producer_completeness="UNKNOWN",
        known_partial=quality.known_partial,
        stored_clock_offset_ms=offset,
    )


def _document(
    config: h.ScopeConfig, identifier: str, envelope: tuple[Any, ...], revision: int
) -> g.GenerationView:
    _require(type(envelope) is tuple and len(envelope) == 4)
    publication, raw, digest, size = envelope
    _require(type(publication) is int and 1 <= publication <= revision)
    _require(type(raw) is str and 1 <= len(raw) <= 2097152)
    _require(type(size) is int and 1 <= size <= 2097152)
    _require(
        type(digest) is str and len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
    )
    document = g.decode_generation(raw, content_sha256=digest, byte_size=size, scope=config)
    _require(document.generation_id == identifier and document.publication_revision == publication)
    return g.generation_view(document)


def _memory_catalog(scopes: dict[str, g.ScopeView]) -> None:
    _require(type(scopes) is dict and len(scopes) <= 16)
    try:
        for key in scopes:
            scope_id(key)
    except (ValueError, TypeError):
        raise BaselineStorageError() from None


def memory_get(
    scopes: dict[str, g.ScopeView],
    identifier: str,
    generations: dict[tuple[str, str], tuple[Any, ...]],
) -> g.ScopeView | None:
    scope_id(identifier)
    _memory_catalog(scopes)
    if identifier not in scopes:
        return None
    value = scopes[identifier]
    _require(type(value) is g.ScopeView)
    try:
        value = g.ScopeView.model_validate(value)
        _require(value.config.scope_id == identifier)
        _require(type(generations) is dict and len(generations) <= 32)
        for key in generations:
            _require(type(key) is tuple and len(key) == 2)
            scope_id(key[0])
            scope_id(key[1])
        retained = {
            key[1]: envelope for key, envelope in generations.items() if key[0] == identifier
        }
        pointers = {
            view.generation_id for view in (value.active, value.previous) if view is not None
        }
        _require(len(retained) <= 2 and set(retained) == pointers)
        for view in (value.active, value.previous):
            if view is not None:
                _require(
                    _document(
                        value.config,
                        view.generation_id,
                        retained[view.generation_id],
                        value.control_revision,
                    )
                    == view
                )
        if value.previous is not None and value.active is not None:
            _require(
                retained[value.previous.generation_id][0] < retained[value.active.generation_id][0]
            )
        return value
    except ValueError:
        raise BaselineStorageError() from None


def memory_create(
    scopes: dict[str, g.ScopeView],
    proposed: g.ScopeView,
    generations: dict[tuple[str, str], tuple[Any, ...]],
) -> tuple[dict[str, g.ScopeView], g.ScopeView, bool]:
    current = memory_get(scopes, proposed.config.scope_id, generations)
    if current is not None:
        _require(
            current.config == proposed.config and current.created_by == proposed.created_by,
            "BASELINE_SCOPE_EXISTS",
        )
        return scopes, current, False
    _require(len(scopes) < 16, "BASELINE_SCOPE_LIMIT")
    return {**scopes, proposed.config.scope_id: proposed}, proposed, True


def memory_page(
    scopes: dict[str, g.ScopeView],
    offset: int,
    limit: int,
    generations: dict[tuple[str, str], tuple[Any, ...]],
) -> g.ScopePage:
    page_arguments(offset, limit)
    _memory_catalog(scopes)
    items = []
    for key in sorted(scopes)[offset : offset + limit]:
        value = memory_get(scopes, key, generations)
        if value is None:
            raise BaselineStorageError()
        items.append(value)
    return _page(tuple(items), len(scopes), offset, limit)


def schema(*, postgres: bool) -> str:
    config_bytes = "octet_length(config_json)" if postgres else "length(CAST(config_json AS BLOB))"
    doc_bytes = "octet_length(document_json)" if postgres else "length(CAST(document_json AS BLOB))"
    config_type = "" if postgres else "AND typeof(config_json)='text'"
    doc_type = "" if postgres else "AND typeof(document_json)='text'"
    receipt_bytes = (
        "octet_length(receipt_json)" if postgres else "length(CAST(receipt_json AS BLOB))"
    )
    receipt_type = "" if postgres else "AND typeof(receipt_json)='text'"
    return f"""
    CREATE TABLE IF NOT EXISTS baseline_catalog(id INTEGER PRIMARY KEY CHECK(id=1));
    INSERT INTO baseline_catalog(id) VALUES(1) ON CONFLICT(id) DO NOTHING;
    CREATE TABLE IF NOT EXISTS baseline_scopes(
      scope_id TEXT PRIMARY KEY, config_json TEXT NOT NULL,
      config_byte_size INTEGER NOT NULL CHECK(config_byte_size BETWEEN 1 AND 65536),
      config_content_sha256 TEXT NOT NULL, config_sha256 TEXT NOT NULL,
      created_by TEXT NOT NULL, created_at TEXT NOT NULL,
      control_revision BIGINT NOT NULL CHECK(control_revision>=0),
      frozen INTEGER NOT NULL CHECK(frozen IN (0,1)),
      state TEXT NOT NULL CHECK(state IN ('EMPTY','HAS_REFERENCE','REVOKED','RETIRED')),
      accepted_event_end TEXT, active_generation_id TEXT, previous_generation_id TEXT,
      CHECK({config_bytes} BETWEEN 1 AND 65536 {config_type})
    );
    CREATE TABLE IF NOT EXISTS baseline_generations(
      scope_id TEXT NOT NULL REFERENCES baseline_scopes(scope_id), generation_id TEXT NOT NULL,
      publication_revision BIGINT NOT NULL CHECK(publication_revision>=1),
      document_json TEXT NOT NULL, content_sha256 TEXT NOT NULL,
      byte_size INTEGER NOT NULL CHECK(byte_size BETWEEN 1 AND 2097152),
      PRIMARY KEY(scope_id,generation_id), UNIQUE(scope_id,publication_revision),
      CHECK({doc_bytes} BETWEEN 1 AND 2097152 {doc_type})
    );
    CREATE TABLE IF NOT EXISTS baseline_operations(
      scope_id TEXT NOT NULL REFERENCES baseline_scopes(scope_id),
      revision BIGINT NOT NULL CHECK(revision>=1),
      idempotency_key TEXT NOT NULL, request_sha256 TEXT NOT NULL,
      operation_id TEXT NOT NULL UNIQUE, receipt_json TEXT NOT NULL,
      receipt_sha256 TEXT NOT NULL,
      receipt_byte_size INTEGER NOT NULL CHECK(receipt_byte_size BETWEEN 1 AND 4096),
      PRIMARY KEY(scope_id,revision), UNIQUE(scope_id,idempotency_key),
      CHECK({receipt_bytes} BETWEEN 1 AND 4096 {receipt_type})
    );
    """


@contextmanager
def transaction(
    connection: Any, *, postgres: bool, write: bool = False, snapshot: bool = True
) -> Iterator[Any]:
    if postgres:
        import psycopg
        from psycopg.pq import TransactionStatus

        _require(
            connection.info.transaction_status == TransactionStatus.IDLE
            and not connection.autocommit,
            "BASELINE_BUSY",
        )
        try:
            with connection.transaction(), connection.cursor() as cursor:
                if snapshot:
                    cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")
                cursor.execute("SET LOCAL lock_timeout='5s'")
                yield cursor
        except psycopg.errors.LockNotAvailable:
            raise BaselineStorageError("BASELINE_BUSY") from None
        except psycopg.Error:
            raise BaselineStorageError() from None
    else:
        _require(
            not connection.in_transaction and connection.autocommit is not True, "BASELINE_BUSY"
        )
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                yield connection
                if write:
                    connection.commit()
            finally:
                connection.rollback()
        except sqlite3.Error as exc:
            code = getattr(exc, "sqlite_errorcode", 0) & 0xFF
            raise BaselineStorageError(
                "BASELINE_BUSY"
                if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
                else "BASELINE_STORAGE_UNAVAILABLE"
            ) from None


class _SQL:
    """Cursor-local baseline table operations, with no lifecycle side effects."""

    def __init__(self, cursor: Any, postgres: bool) -> None:
        self.cursor = cursor
        self.postgres = postgres

    def execute(self, statement: str, values: tuple[Any, ...] = ()) -> Any:
        result = self.cursor.execute(
            statement.replace("?", "%s") if self.postgres else statement, values
        )
        return self.cursor if self.postgres else result

    def count(self) -> int:
        count, longest = self.execute(
            "SELECT count(*),COALESCE(max(length(scope_id)),0) FROM baseline_scopes"
        ).fetchone()
        _require(type(count) is int and 0 <= count <= 16 and longest <= 36)
        return count

    def _scalar_gate(self, identifier: str) -> None:
        # Only code-owned columns/limits enter SQL; values remain parameters.
        bounds = {
            "config_content_sha256": 64,
            "config_sha256": 64,
            "created_by": 800,
            "created_at": 64,
            "state": 13,
            "accepted_event_end": 64,
            "active_generation_id": 36,
            "previous_generation_id": 36,
        }
        clauses = []
        for column, maximum in bounds.items():
            length = (
                f"octet_length({column})" if self.postgres else f"length(CAST({column} AS BLOB))"
            )
            kind = "TRUE" if self.postgres else f"typeof({column})='text'"
            clauses.append(f"({column} IS NULL OR ({length}<={maximum} AND {kind}))")
        if not self.postgres:
            clauses.extend(
                f"typeof({column})='integer'"
                for column in ("config_byte_size", "control_revision", "frozen")
            )
        statement = (
            "SELECT CASE WHEN "  # noqa: S608 -- fixed internal column/limit clauses
            + " AND ".join(clauses)
            + " THEN 1 ELSE 0 END FROM baseline_scopes WHERE scope_id=?"
        )
        admitted = self.execute(statement, (identifier,)).fetchone()
        _require(admitted is not None and admitted[0] == 1)

    def get(self, identifier: str, *, lock: bool = False) -> g.ScopeView | None:
        self.count()
        if lock and self.postgres:
            self.execute(
                "SELECT scope_id FROM baseline_scopes WHERE scope_id=? FOR UPDATE", (identifier,)
            )
        length = (
            "octet_length(config_json)" if self.postgres else "length(CAST(config_json AS BLOB))"
        )
        kind = "'text'" if self.postgres else "typeof(config_json)"
        sizes = self.execute(
            f"SELECT {length},{kind} FROM baseline_scopes WHERE scope_id=?",  # noqa: S608 -- fixed byte/type expressions
            (identifier,),
        ).fetchone()
        if sizes is None:
            return None
        _require(sizes[1] == "text" and 1 <= sizes[0] <= 65536)
        self._scalar_gate(identifier)
        count, largest_id, largest_hash = self.execute(
            "SELECT count(*),COALESCE(max(length(generation_id)),0),"
            "COALESCE(max(length(content_sha256)),0) FROM baseline_generations WHERE scope_id=?",
            (identifier,),
        ).fetchone()
        _require(count <= 2 and largest_id <= 36 and largest_hash <= 64)
        row = self.execute(
            "SELECT "
            "config_json,config_byte_size,config_content_sha256,config_sha256,created_by,created_at,control_revision,frozen,state,accepted_event_end,active_generation_id,previous_generation_id"
            " FROM baseline_scopes WHERE scope_id=?",
            (identifier,),
        ).fetchone()
        _require(row is not None)
        (
            raw,
            size,
            digest,
            identity,
            actor,
            created,
            revision,
            frozen,
            state,
            watermark,
            active,
            previous,
        ) = row
        try:
            _require(type(raw) is str and type(size) is int and len(raw.encode("utf-8")) == size)
            _require(hashlib.sha256(raw.encode("utf-8")).hexdigest() == digest)
            config = h.ScopeConfig.from_mapping(r._decode(raw, max_bytes=65536))
            _require(config.scope_id == identifier and h.canonical_json(config.to_mapping()) == raw)
            _require(type(frozen) is int and frozen in (0, 1))
            pointers = {pointer for pointer in (active, previous) if pointer is not None}
            _require(count == len(pointers))
            doc_length = (
                "octet_length(document_json)"
                if self.postgres
                else "length(CAST(document_json AS BLOB))"
            )
            doc_kind = "'text'" if self.postgres else "typeof(document_json)"
            sizes = self.execute(
                f"SELECT generation_id,{doc_length},{doc_kind} FROM "  # noqa: S608 -- fixed byte/type expressions
                f"baseline_generations WHERE scope_id=? LIMIT 2",
                (identifier,),
            ).fetchall()
            _require({entry[0] for entry in sizes} == pointers)
            _require(all(entry[2] == "text" and 1 <= entry[1] <= 2097152 for entry in sizes))
            documents = self.execute(
                "SELECT "
                "generation_id,publication_revision,document_json,content_sha256,byte_size"
                " FROM baseline_generations WHERE scope_id=? LIMIT 2",
                (identifier,),
            ).fetchall()
            views = {
                entry[0]: _document(config, entry[0], tuple(entry[1:]), revision)
                for entry in documents
            }
            publications = {entry[0]: entry[1] for entry in documents}
            if previous is not None:
                _require(active is not None and publications[previous] < publications[active])
            return g.ScopeView(
                config=config,
                config_sha256=identity,
                control_revision=revision,
                frozen=bool(frozen),
                state=state,
                accepted_event_end=watermark,
                active=views.get(active),
                previous=views.get(previous),
                created_by=actor,
                created_at=created,
            )
        except (ValueError, TypeError, UnicodeError):
            raise BaselineStorageError() from None

    def insert(self, view: g.ScopeView) -> None:
        raw = h.canonical_json(view.config.to_mapping())
        self.execute(
            "INSERT INTO "
            "baseline_scopes(scope_id,config_json,config_byte_size,config_content_sha256,config_sha256,created_by,created_at,control_revision,frozen,state,accepted_event_end,active_generation_id,previous_generation_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                view.config.scope_id,
                raw,
                len(raw.encode("utf-8")),
                hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                view.config_sha256,
                view.created_by,
                view.to_mapping()["created_at"],
                0,
                0,
                "EMPTY",
                None,
                None,
                None,
            ),
        )


def sql_get(connection: Any, identifier: str, *, postgres: bool) -> g.ScopeView | None:
    scope_id(identifier)
    with transaction(connection, postgres=postgres) as cursor:
        return _SQL(cursor, postgres).get(identifier)


def sql_create(
    connection: Any, proposed: g.ScopeView, *, postgres: bool
) -> tuple[g.ScopeView, bool]:
    identifier = proposed.config.scope_id
    with transaction(connection, postgres=postgres, write=True, snapshot=False) as cursor:
        db = _SQL(cursor, postgres)
        rows = db.execute(
            "SELECT id FROM baseline_catalog FOR UPDATE"
            if postgres
            else "SELECT id FROM baseline_catalog"
        ).fetchall()
        _require(rows == [(1,)])
        current = db.get(identifier)
        if current is not None:
            _require(
                current.config == proposed.config and current.created_by == proposed.created_by,
                "BASELINE_SCOPE_EXISTS",
            )
            return current, False
        _require(db.count() < 16, "BASELINE_SCOPE_LIMIT")
        db.insert(proposed)
        _require(db.get(identifier) == proposed)
    readback = sql_get(connection, identifier, postgres=postgres)
    _require(readback == proposed)
    if readback is None:
        raise BaselineStorageError()
    return readback, True


def sql_page(connection: Any, offset: int, limit: int, *, postgres: bool) -> g.ScopePage:
    page_arguments(offset, limit)
    with transaction(connection, postgres=postgres) as cursor:
        db = _SQL(cursor, postgres)
        total = db.count()
        rows = db.execute(
            "SELECT scope_id FROM baseline_scopes ORDER BY scope_id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        items = []
        for (identifier,) in rows:
            view = db.get(identifier)
            if view is None:
                raise BaselineStorageError()
            items.append(view)
        return _page(tuple(items), total, offset, limit)


def sql_preview(
    connection: Any,
    identifier: str,
    job_id: str,
    revision: int,
    purpose: r.Purpose,
    *,
    postgres: bool,
) -> g.SourcePreview:
    preview_arguments(identifier, job_id, revision, purpose)
    _revision(sql_get(connection, identifier, postgres=postgres), revision)
    with transaction(connection, postgres=postgres, snapshot=False) as cursor:
        acquired = (
            r._postgres_acquire(cursor, job_id, purpose, structural=True)
            if postgres
            else r._sqlite_acquire(cursor, job_id, purpose, structural=True)
        )
        view = _revision(_SQL(cursor, postgres).get(identifier, lock=True), revision)
        return finish_preview(acquired, view, purpose)


_APPROVAL_CODES = frozenset(
    {
        "BASELINE_SCOPE_NOT_FOUND",
        "BASELINE_SOURCE_NOT_FOUND",
        "BASELINE_REVISION_CONFLICT",
        "BASELINE_IDEMPOTENCY_CONFLICT",
        "BASELINE_FROZEN",
        "BASELINE_SOURCE_CHANGED",
        "BASELINE_SOURCE_STATE",
        "BASELINE_SOURCE_LINEAGE_INVALID",
        "BASELINE_SOURCE_QUALITY",
        "BASELINE_SCOPE_MISMATCH",
        "BASELINE_SOURCE_DUPLICATE",
        "BASELINE_EVENT_ORDER",
        "BASELINE_SOURCE_LIMIT",
        "BASELINE_PROFILE_LIMIT",
        "BASELINE_GENERATION_LIMIT",
        "BASELINE_CONTROL_LIMIT",
        "BASELINE_SOURCE_INVALID",
        "BASELINE_BUSY",
        "BASELINE_STORAGE_UNAVAILABLE",
        "BASELINE_GENERATION_MISMATCH",
    }
)


def _construction_code(error: Any) -> str | None:
    if isinstance(error, r.HistoricalReadError | s.SourceInputError | BaselineInputError):
        code = error.code
    elif type(error) is ValueError and len(error.args) == 1 and type(error.args[0]) is str:
        code = error.args[0]
    else:
        return None
    if code not in _APPROVAL_CODES:
        return None
    return "BASELINE_STORAGE_UNAVAILABLE" if code == "BASELINE_GENERATION_MISMATCH" else code


@contextmanager
def approval_errors() -> Iterator[None]:
    # External typed admission occurs first; persisted decoders own corruption.
    try:
        yield
    except BaselineStorageError:
        raise
    except ValidationError as error:
        causes = [
            _construction_code(item.get("ctx", {}).get("error"))
            for item in error.errors(include_input=False, include_url=False)
        ]
        if causes and causes[0] is not None and all(code == causes[0] for code in causes):
            raise BaselineStorageError(causes[0]) from None
        raise
    except (r.HistoricalReadError, s.SourceInputError, BaselineInputError, ValueError) as error:
        code = _construction_code(error)
        if code is not None:
            raise BaselineStorageError(code) from None
        raise


def approval_arguments(
    identifier: str, request: g.ApprovalRequest, actor: str, now: datetime
) -> tuple[g.ApprovalRequest, str, datetime, str]:
    scope_id(identifier)
    request = g._checked(g.ApprovalRequest, request)
    actor = TypeAdapter(h.Identifier).validate_python(actor, strict=True)
    if type(now) is not datetime:
        raise ValueError("expected aware datetime")
    now = TypeAdapter(h.UTCDateTime).validate_python(now, strict=True)
    raw = h.canonical_json(request.to_mapping())
    if len(raw.encode("utf-8")) > 16384:
        raise ValueError("approval request too large")
    digest = hashlib.sha256(
        h.canonical_json(
            {
                "action": "APPROVE",
                "scope_id": identifier,
                "actor": actor,
                "request": request.to_mapping(),
            }
        ).encode("utf-8")
    ).hexdigest()
    return request, actor, now, digest


def source_page_arguments(identifier: str, generation_id: str, offset: int, limit: int) -> None:
    scope_id(identifier)
    scope_id(generation_id)
    if type(offset) is not int or not 0 <= offset <= 16:
        raise ValueError("invalid source page offset")
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError("invalid source page limit")


def _sources(document: g.GenerationDocument, offset: int, limit: int) -> g.SourcePage:
    items = document.sources[offset : offset + limit]
    end = offset + len(items)
    return g.SourcePage(
        items=items,
        total=len(document.sources),
        offset=offset,
        limit=limit,
        next_offset=end if end < len(document.sources) else None,
    )


def _stored_document(
    view: g.ScopeView, identifier: str, envelope: tuple[Any, ...]
) -> g.GenerationDocument:
    try:
        _document(view.config, identifier, envelope, view.control_revision)
        return g.decode_generation(
            envelope[1], content_sha256=envelope[2], byte_size=envelope[3], scope=view.config
        )
    except (ValueError, UnicodeError):
        raise BaselineStorageError() from None


def memory_sources(
    scopes: dict, generations: dict, identifier: str, generation_id: str, offset: int, limit: int
) -> g.SourcePage:
    view = memory_get(scopes, identifier, generations)
    _require(view is not None, "BASELINE_SCOPE_NOT_FOUND")
    if view is None:
        raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
    _require(
        generation_id in {v.generation_id for v in (view.active, view.previous) if v},
        "BASELINE_GENERATION_RETIRED",
    )
    return _sources(
        _stored_document(view, generation_id, generations[(identifier, generation_id)]),
        offset,
        limit,
    )


def _operation_envelope(row: tuple[Any, ...], identifier: str) -> g.OperationReceipt:
    _require(type(row) is tuple and len(row) == 8)
    scope, revision, key, request_hash, operation_id, raw, receipt_hash, size = row
    try:
        _require(scope == identifier)
        _require(type(revision) is int and 1 <= revision <= 2**63 - 1)
        TypeAdapter(h.Identifier).validate_python(key, strict=True)
        scope_id(operation_id)
        for value in (request_hash, receipt_hash):
            TypeAdapter(h.Digest).validate_python(value, strict=True)
        _require(type(raw) is str and 1 <= len(raw) <= 4096)
        _require(type(size) is int and 1 <= size <= 4096)
        data = raw.encode("utf-8")
        _require(len(data) == size and hashlib.sha256(data).hexdigest() == receipt_hash)
        value = r._decode(raw, max_bytes=4096)
        _require(type(value) is dict and len(value) <= 8)
        _require(all(type(name) is str for name in value))
        action = value.get("action")
        # Preserve the approval JSON decoder boundary after actual byte admission.
        # Missing/unknown discriminators still fail its closed required shape;
        # only the five exact control actions select the other closed decoder.
        receipt: g.OperationReceipt = (
            g.ControlReceipt.model_validate_json(raw)
            if type(action) is str and action in get_args(g.ControlAction)
            else g.ApprovalReceipt.model_validate_json(raw)
        )
        _require(h.canonical_json(receipt.to_mapping()) == raw)
        _require(receipt.revision == revision and receipt.operation_id == operation_id)
    except (ValueError, UnicodeError):
        raise BaselineStorageError() from None
    return receipt


def _operation(
    row: tuple[Any, ...], identifier: str, request: g.ApprovalRequest, actor: str, digest: str
) -> g.ApprovalReceipt:
    receipt = _operation_envelope(row, identifier)
    _require(row[2] == request.idempotency_key)
    _require(row[3] == digest, "BASELINE_IDEMPOTENCY_CONFLICT")
    if type(receipt) is not g.ApprovalReceipt:
        raise BaselineStorageError()
    _require(
        receipt.actor == actor
        and receipt.source_job_id == request.source_job_id
        and receipt.source_binding_sha256 == request.source_binding_sha256
        and receipt.revision == request.expected_revision + 1
    )
    return receipt


def _operation_row(
    identifier: str,
    request: g.ApprovalRequest | g.ControlRequest,
    digest: str,
    receipt: g.OperationReceipt,
) -> tuple[Any, ...]:
    raw = h.canonical_json(receipt.to_mapping())
    data = raw.encode("utf-8")
    _require(len(data) <= 4096, "BASELINE_CONTROL_LIMIT")
    return (
        identifier,
        receipt.revision,
        request.idempotency_key,
        digest,
        receipt.operation_id,
        raw,
        hashlib.sha256(data).hexdigest(),
        len(data),
    )


@s._safe
def _approval_binding(acquired: r._Acquired) -> h.SourceBindingProjection:
    binding = _preview_binding(acquired)
    s._source_state(binding)
    s._preflight(binding)
    return binding


def _stage_publication(
    view: g.ScopeView,
    current: g.GenerationDocument | None,
    binding: h.SourceBindingProjection,
    request: g.ApprovalRequest,
    actor: str,
    now: datetime,
    digest: str,
) -> tuple[g.PublicationResult, tuple[Any, ...], tuple[Any, ...]]:
    from uuid import uuid4

    _revision(view, request.expected_revision)
    _require(not view.frozen, "BASELINE_FROZEN")
    _require(view.control_revision < 2**63 - 1, "BASELINE_CONTROL_LIMIT")
    binding_hash = h.source_binding_sha256(binding, purpose="APPROVAL", candidates=())
    _require(
        request.source_binding_sha256 == binding_hash
        and request.source_job_id == binding.original.id,
        "BASELINE_SOURCE_CHANGED",
    )
    source = s.source_from_binding(
        binding, scope=view.config, quality_review=request.quality_review
    )
    document = g.produce_generation(
        snapshot=r.HistoricalReadSnapshot(
            source=source, candidates=(), source_binding_sha256=binding_hash
        ),
        scope=view,
        current_generation=current,
        accepted_event_end=view.accepted_event_end,
        request=request,
        operation_id=str(uuid4()),
        generation_id=str(uuid4()),
        actor=actor,
        now=now,
    )
    raw = g.generation_json(document)
    active = g.generation_view(document)
    receipt = g.approval_receipt(document, operation_id=document.sources[-1].source_receipt_id)
    scope = g.ScopeView(
        config=view.config,
        config_sha256=view.config_sha256,
        control_revision=view.control_revision + 1,
        frozen=False,
        state="HAS_REFERENCE",
        accepted_event_end=source.event_end,
        active=active,
        previous=view.active,
        created_by=view.created_by,
        created_at=view.created_at,
    )
    return (
        g.PublicationResult(scope=scope, receipt=receipt, created=True),
        (document.publication_revision, raw, active.content_sha256, active.byte_size),
        _operation_row(view.config.scope_id, request, digest, receipt),
    )


def memory_publish(
    scopes: dict,
    generations: dict,
    operations: dict,
    jobs: dict,
    candidates: dict,
    identifier: str,
    request: g.ApprovalRequest,
    actor: str,
    now: datetime,
    digest: str,
    *,
    admission: BaselineLease | None = None,
) -> tuple[dict, dict, dict, g.PublicationResult]:
    # The facade retains lease ownership through its final map assignments.
    _require(type(operations) is dict and len(operations) <= 1024)
    try:
        for key, row in operations.items():
            _require(type(key) is tuple and len(key) == 2)
            scope_id(key[0])
            TypeAdapter(h.Identifier).validate_python(key[1], strict=True)
            _require(type(row) is tuple and len(row) == 8)
            _require(row[0] == key[0] and row[2] == key[1])
            _require(type(row[1]) is int and 1 <= row[1] <= 2**63 - 1)
            scope_id(row[4])
    except (ValueError, UnicodeError):
        raise BaselineStorageError() from None
    retained = {key: row for key, row in operations.items() if key[0] == identifier}
    _require(len(retained) <= 64)
    row = retained.get((identifier, request.idempotency_key))
    if row is not None:
        receipt = _operation(row, identifier, request, actor, digest)
        view = memory_get(scopes, identifier, generations)
        if view is None:
            raise BaselineStorageError()
        _require(receipt.revision <= view.control_revision)
        return (
            scopes,
            generations,
            operations,
            g.PublicationResult(scope=view, receipt=receipt, created=False),
        )
    _require(identifier in scopes, "BASELINE_SCOPE_NOT_FOUND")
    if admission is not None:
        _require(admission.acquire(), "BASELINE_BUSY")
    binding = _approval_binding(
        r._memory_acquire(jobs, candidates, request.source_job_id, "APPROVAL")
    )
    view = memory_get(scopes, identifier, generations)
    if view is None:
        raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
    current = (
        _stored_document(
            view, view.active.generation_id, generations[(identifier, view.active.generation_id)]
        )
        if view.active
        else None
    )
    result, envelope, operation = _stage_publication(
        view, current, binding, request, actor, now, digest
    )
    _require(all(row[4] != result.receipt.operation_id for row in operations.values()))
    next_scopes = {**scopes, identifier: result.scope}
    next_generations = dict(generations)
    if view.previous:
        del next_generations[(identifier, view.previous.generation_id)]
    next_generations[(identifier, result.receipt.generation_id)] = envelope
    next_operations = {**operations, (identifier, request.idempotency_key): operation}
    ordered = sorted((*retained.values(), operation), key=lambda row: row[1])
    for old in ordered[:-64]:
        del next_operations[(identifier, old[2])]
    _require(memory_get(next_scopes, identifier, next_generations) == result.scope)
    _require(_operation(operation, identifier, request, actor, digest) == result.receipt)
    return next_scopes, next_generations, next_operations, result


class _PublicationConnection:
    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self.failed = False


def publication_connection(repository: Any, *, postgres: bool) -> _PublicationConnection:
    # Quarantine belongs to this facade, not a global connection registry. A
    # failed close must not turn the next call into a caller-transaction BUSY or
    # let PostgresRepository.connection silently allocate a replacement.
    state = getattr(repository, "_baseline_publication_connection", None)
    if state is not None:
        _require(not state.failed)
    if postgres and repository._connection is not None:
        _require(not repository._connection.closed)
    connection = repository.connection
    if state is None or state.connection is not connection:
        state = _PublicationConnection(connection)
        repository._baseline_publication_connection = state
    return state


class _publication_transaction:
    """Private owner for the two new methods; never repairs caller transactions."""

    def __init__(self, connection: Any, *, postgres: bool, write: bool = False) -> None:
        self.state = (
            connection
            if isinstance(connection, _PublicationConnection)
            else _PublicationConnection(connection)
        )
        _require(not self.state.failed)
        self.connection = self.state.connection
        self.postgres = postgres
        self.write = write
        self.failed = False
        self.cursor: Any = None

    def __enter__(self) -> Any:
        con = self.connection
        if self.postgres:
            from psycopg.pq import TransactionStatus

            _require(
                con.info.transaction_status == TransactionStatus.IDLE and not con.autocommit,
                "BASELINE_BUSY",
            )
        else:
            _require(not con.in_transaction and con.autocommit is not True, "BASELINE_BUSY")
        try:
            if self.postgres:
                self.cursor = con.cursor()
                self.cursor.execute("BEGIN")
                self.cursor.execute(
                    "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
                    if self.write
                    else "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"
                )
                self.cursor.execute("SET LOCAL lock_timeout='5s'")
            else:
                con.execute("BEGIN IMMEDIATE" if self.write else "BEGIN")
        except BaseException as error:
            self._cleanup()
            self._raise_driver(error)
            raise
        return self.cursor if self.postgres else con

    def _cleanup(self) -> None:
        try:
            self.connection.rollback()
            if self.cursor is not None:
                self.cursor.close()
        except BaseException:
            self._discard()

    def _discard(self) -> None:
        if self.failed:
            return
        self.failed = self.state.failed = True
        try:
            self.connection.close()
        except BaseException:  # noqa: S110 -- disposal cannot replace the primary exception
            pass  # Preserve the primary, even if disposal itself fails.

    def _definite_commit_refusal(self, error: BaseException) -> bool:
        if not self.postgres:
            return isinstance(error, sqlite3.IntegrityError) or (
                isinstance(error, sqlite3.OperationalError)
                and getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_BUSY
            )
        import psycopg

        return isinstance(error, psycopg.Error) and bool(
            error.sqlstate and (error.sqlstate[:2] in {"23", "40"} or error.sqlstate == "P0001")
        )

    def _raise_driver(self, error: BaseException) -> None:
        if self.postgres:
            import psycopg

            if isinstance(error, psycopg.Error):
                raise BaselineStorageError(
                    "BASELINE_BUSY"
                    if isinstance(error, psycopg.errors.LockNotAvailable)
                    else "BASELINE_STORAGE_UNAVAILABLE"
                ) from None
        if isinstance(error, sqlite3.Error):
            code = getattr(error, "sqlite_errorcode", 0) & 0xFF
            raise BaselineStorageError(
                "BASELINE_BUSY"
                if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED)
                else "BASELINE_STORAGE_UNAVAILABLE"
            ) from None

    def __exit__(self, kind: Any, error: Any, traceback: Any) -> None:
        if error is not None:
            self._cleanup()
            self._raise_driver(error)
            return
        committed = False
        try:
            if self.write:
                self.connection.commit()
                committed = True
            else:
                self.connection.rollback()
            if self.cursor is not None:
                self.cursor.close()
        except BaseException as primary:
            if self.write and not committed and self._definite_commit_refusal(primary):
                self._cleanup()
            else:
                # Failed rollback, unknown COMMIT outcome, or postcommit cursor
                # teardown: dispose once; never manufacture prestate or retry.
                self._discard()
            self._raise_driver(primary)
            raise


class _PublicationUnique(BaselineStorageError):
    """Only actual INSERT uniqueness permits the one-shot retained recovery."""


class _PublicationSQL(_SQL):
    def insert_publication(self, statement: str, values: tuple[Any, ...]) -> None:
        if self.postgres:
            from psycopg.errors import UniqueViolation

            try:
                self.execute(statement, values)
            except UniqueViolation:
                raise _PublicationUnique() from None
        else:
            try:
                self.execute(statement, values)
            except sqlite3.IntegrityError as error:
                if error.sqlite_errorcode in (
                    sqlite3.SQLITE_CONSTRAINT_UNIQUE,
                    sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY,
                ):
                    raise _PublicationUnique() from None
                raise

    def exists(self, identifier: str, *, lock: bool = False) -> bool:
        self.count()
        suffix = " FOR UPDATE" if lock and self.postgres else ""
        return (
            self.execute(
                "SELECT scope_id FROM baseline_scopes WHERE scope_id=?" + suffix,  # noqa: S608 -- fixed lock suffix
                (identifier,),
            ).fetchone()
            is not None
        )

    def operation(
        self, identifier: str, request: g.ApprovalRequest, actor: str, digest: str
    ) -> g.ApprovalReceipt | None:
        row = self.operation_data(identifier, request.idempotency_key)
        return None if row is None else _operation(row, identifier, request, actor, digest)

    def operation_data(self, identifier: str, key: str) -> tuple[Any, ...] | None:
        count = self.execute(
            "SELECT count(*) FROM baseline_operations WHERE scope_id=?", (identifier,)
        ).fetchone()[0]
        _require(type(count) is int and 0 <= count <= 64)
        statement = (
            "SELECT CASE WHEN "  # noqa: S608 -- code-owned scalar gates
            + self.operation_gate()
            + " THEN 1 ELSE 0 END FROM baseline_operations WHERE scope_id=? AND idempotency_key=?"
        )
        gate = self.execute(statement, (identifier, key)).fetchone()
        if gate is None:
            return None
        _require(gate[0] == 1)
        row = self.execute(
            "SELECT scope_id,revision,idempotency_key,request_sha256,"
            "operation_id,receipt_json,receipt_sha256,receipt_byte_size FROM "
            "baseline_operations WHERE scope_id=? AND idempotency_key=?",
            (identifier, key),
        ).fetchone()
        _require(row is not None)
        return tuple(row)

    def operation_gate(self) -> str:
        clauses = []
        for column, maximum in (
            ("scope_id", 36),
            ("idempotency_key", 800),
            ("request_sha256", 64),
            ("operation_id", 36),
            ("receipt_json", 4096),
            ("receipt_sha256", 64),
        ):
            length = (
                f"octet_length({column})" if self.postgres else f"length(CAST({column} AS BLOB))"
            )
            kind = "TRUE" if self.postgres else f"typeof({column})='text'"
            clauses.append(f"({kind} AND {length} BETWEEN 1 AND {maximum})")
        if not self.postgres:
            clauses.extend(("typeof(revision)='integer'", "typeof(receipt_byte_size)='integer'"))
        clauses.extend(("revision>=1", "receipt_byte_size BETWEEN 1 AND 4096"))
        return " AND ".join(clauses)

    def replay(
        self, identifier: str, request: g.ApprovalRequest, actor: str, digest: str
    ) -> g.PublicationResult | None:
        receipt = self.operation(identifier, request, actor, digest)
        if receipt is None:
            return None
        view = self.get(identifier)
        if view is None:
            raise BaselineStorageError()
        _require(receipt.revision <= view.control_revision)
        return g.PublicationResult(scope=view, receipt=receipt, created=False)

    def document(self, view: g.ScopeView, generation_id: str) -> g.GenerationDocument:
        # Caller has admitted and decoded both retained pointers in this snapshot.
        _require(generation_id in {v.generation_id for v in (view.active, view.previous) if v})
        row = self.execute(
            "SELECT publication_revision,document_json,content_sha256,"
            "byte_size FROM baseline_generations WHERE scope_id=? AND "
            "generation_id=?",
            (view.config.scope_id, generation_id),
        ).fetchone()
        _require(row is not None)
        return _stored_document(view, generation_id, tuple(row))

    def publish(
        self,
        before: g.ScopeView,
        result: g.PublicationResult,
        envelope: tuple[Any, ...],
        operation: tuple[Any, ...],
    ) -> None:
        identifier = before.config.scope_id
        if before.previous:
            self.execute(
                "DELETE FROM baseline_generations WHERE scope_id=? AND generation_id=?",
                (identifier, before.previous.generation_id),
            )
        self.insert_publication(
            "INSERT INTO baseline_generations(scope_id,generation_id,"
            "publication_revision,document_json,content_sha256,byte_size) "
            "VALUES(?,?,?,?,?,?)",
            (identifier, result.receipt.generation_id, *envelope),
        )
        row = self.execute(
            "UPDATE baseline_scopes SET control_revision=?,frozen=0,"
            "state='HAS_REFERENCE',accepted_event_end=?,active_generation_id=?,"
            "previous_generation_id=? WHERE scope_id=? AND control_revision=?",
            (
                result.scope.control_revision,
                result.scope.to_mapping()["accepted_event_end"],
                result.receipt.generation_id,
                before.active.generation_id if before.active else None,
                identifier,
                before.control_revision,
            ),
        )
        _require(row.rowcount == 1, "BASELINE_REVISION_CONFLICT")
        self.retain_operation(identifier, operation)

    def retain_operation(self, identifier: str, operation: tuple[Any, ...]) -> None:
        self.insert_publication(
            "INSERT INTO baseline_operations(scope_id,revision,idempotency_key,"
            "request_sha256,operation_id,receipt_json,receipt_sha256,"
            "receipt_byte_size) VALUES(?,?,?,?,?,?,?,?)",
            operation,
        )
        cutoff = self.execute(
            "SELECT revision FROM baseline_operations WHERE scope_id=? ORDER "
            "BY revision DESC LIMIT 1 OFFSET 63",
            (identifier,),
        ).fetchone()
        if cutoff is not None:
            self.execute(
                "DELETE FROM baseline_operations WHERE scope_id=? AND revision<?",
                (identifier, cutoff[0]),
            )

    def control_replay(
        self, identifier: str, request: g.ControlRequest, actor: str, digest: str
    ) -> g.ControlResult | None:
        row = self.operation_data(identifier, request.idempotency_key)
        if row is None:
            return None
        receipt = _control_operation(row, identifier, request, actor, digest)
        view = self.get(identifier)
        if view is None:
            raise BaselineStorageError()
        _require(receipt.revision <= view.control_revision)
        return g.ControlResult(scope=view, receipt=receipt)

    def control(
        self, before: g.ScopeView, result: g.ControlResult, operation: tuple[Any, ...]
    ) -> None:
        identifier = before.config.scope_id
        remaining = {
            item.generation_id for item in (result.scope.active, result.scope.previous) if item
        }
        for item in (before.active, before.previous):
            if item and item.generation_id not in remaining:
                deleted = self.execute(
                    "DELETE FROM baseline_generations WHERE scope_id=? AND generation_id=?",
                    (identifier, item.generation_id),
                )
                _require(deleted.rowcount == 1)
        view = result.scope
        row = self.execute(
            "UPDATE baseline_scopes SET control_revision=?,frozen=?,state=?,"
            "active_generation_id=?,previous_generation_id=? "
            "WHERE scope_id=? AND control_revision=?",
            (
                view.control_revision,
                int(view.frozen),
                view.state,
                view.active.generation_id if view.active else None,
                view.previous.generation_id if view.previous else None,
                identifier,
                before.control_revision,
            ),
        )
        if row.rowcount != 1:
            raise _ControlCAS("BASELINE_REVISION_CONFLICT")
        self.retain_operation(identifier, operation)

    def events(self, identifier: str, offset: int, limit: int) -> g.ControlPage:
        view = self.get(identifier)
        if view is None:
            raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
        total, earliest = self.execute(
            "SELECT count(*),min(revision) FROM baseline_operations WHERE scope_id=?",
            (identifier,),
        ).fetchone()
        _event_metadata(total, earliest, view.control_revision)
        gates = self.execute(
            "SELECT CASE WHEN "  # noqa: S608 -- fixed scalar clauses
            + self.operation_gate()
            + " THEN 1 ELSE 0 END FROM baseline_operations WHERE scope_id=? "
            "ORDER BY revision DESC LIMIT ? OFFSET ?",
            (identifier, limit, offset),
        ).fetchall()
        _require(all(row[0] == 1 for row in gates))
        rows = self.execute(
            "SELECT scope_id,revision,idempotency_key,request_sha256,operation_id,"
            "receipt_json,receipt_sha256,receipt_byte_size FROM baseline_operations "
            "WHERE scope_id=? ORDER BY revision DESC LIMIT ? OFFSET ?",
            (identifier, limit, offset),
        ).fetchall()
        return _events(view, tuple(tuple(row) for row in rows), total, earliest, offset, limit)


def sql_sources(
    connection: Any, identifier: str, generation_id: str, offset: int, limit: int, *, postgres: bool
) -> g.SourcePage:
    with _publication_transaction(connection, postgres=postgres) as cursor:
        db = _PublicationSQL(cursor, postgres)
        view = db.get(identifier)
        if view is None:
            raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
        _require(
            generation_id in {v.generation_id for v in (view.active, view.previous) if v},
            "BASELINE_GENERATION_RETIRED",
        )
        return _sources(db.document(view, generation_id), offset, limit)


def sql_publish(
    connection: Any,
    identifier: str,
    request: g.ApprovalRequest,
    actor: str,
    now: datetime,
    digest: str,
    *,
    postgres: bool,
    admission: BaselineLease | None = None,
) -> g.PublicationResult:
    with _publication_transaction(connection, postgres=postgres) as cursor:
        db = _PublicationSQL(cursor, postgres)
        replay = db.replay(identifier, request, actor, digest)
        if replay is not None:
            return replay
        _require(db.exists(identifier), "BASELINE_SCOPE_NOT_FOUND")
    if admission is not None:
        _require(admission.acquire(), "BASELINE_BUSY")
    owner = _publication_transaction(connection, postgres=postgres, write=True)
    try:
        with owner as cursor:
            db = _PublicationSQL(cursor, postgres)
            acquired = (
                r._postgres_acquire(cursor, request.source_job_id, "APPROVAL")
                if postgres
                else r._sqlite_acquire(cursor, request.source_job_id, "APPROVAL")
            )
            binding = _approval_binding(acquired)
            db.exists(identifier, lock=True)
            replay = db.replay(identifier, request, actor, digest)
            if replay is not None:
                return replay
            view = db.get(identifier)
            if view is None:
                raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
            current = db.document(view, view.active.generation_id) if view.active else None
            result, envelope, operation = _stage_publication(
                view, current, binding, request, actor, now, digest
            )
            db.publish(view, result, envelope, operation)
    except (BaselineStorageError, r.HistoricalReadError, s.SourceInputError) as error:
        eligible = isinstance(error, _PublicationUnique) or error.code in {
            "BASELINE_SOURCE_NOT_FOUND",
            "BASELINE_SOURCE_CHANGED",
            "BASELINE_SOURCE_LINEAGE_INVALID",
            "BASELINE_REVISION_CONFLICT",
            "BASELINE_FROZEN",
        }
        if not eligible or owner.failed:
            raise
        with _publication_transaction(connection, postgres=postgres) as cursor:
            replay = _PublicationSQL(cursor, postgres).replay(identifier, request, actor, digest)
            if replay is not None:
                return replay
        raise
    with _publication_transaction(connection, postgres=postgres) as cursor:
        db = _PublicationSQL(cursor, postgres)
        try:
            replay = db.replay(identifier, request, actor, digest)
        except BaselineStorageError as error:
            # This is validation of our committed staged operation, not a retry
            # deciding whether a retained key belongs to a different request.
            if error.code == "BASELINE_IDEMPOTENCY_CONFLICT":
                raise BaselineStorageError() from None
            raise
        _require(replay is not None)
        if replay is None:
            raise BaselineStorageError()
        document = db.document(replay.scope, result.receipt.generation_id)
        _require(g.generation_json(document) == envelope[1])
        _require(
            g.approval_receipt(document, operation_id=result.receipt.operation_id)
            == result.receipt
            == replay.receipt
        )
        return g.PublicationResult(scope=replay.scope, receipt=result.receipt, created=True)


def control_arguments(
    identifier: str, request: g.ControlRequest, actor: str, now: datetime
) -> tuple[g.ControlRequest, str, datetime, str]:
    scope_id(identifier)
    request = g._checked(g.ControlRequest, request)
    actor = TypeAdapter(h.Identifier).validate_python(actor, strict=True)
    if type(now) is not datetime:
        raise ValueError("expected aware datetime")
    now = TypeAdapter(h.UTCDateTime).validate_python(now, strict=True)
    raw = h.canonical_json(request.to_mapping())
    if len(raw.encode("utf-8")) > 16384:
        raise ValueError("control request too large")
    digest = hashlib.sha256(
        h.canonical_json(
            {
                "action": request.action,
                "scope_id": identifier,
                "actor": actor,
                "request": request.to_mapping(),
            }
        ).encode("utf-8")
    ).hexdigest()
    return request, actor, now, digest


def control_page_arguments(identifier: str, offset: int, limit: int) -> None:
    scope_id(identifier)
    if type(offset) is not int or not 0 <= offset <= 64:
        raise ValueError("invalid control page offset")
    if type(limit) is not int or not 1 <= limit <= 20:
        raise ValueError("invalid control page limit")


def _control_operation(
    row: tuple[Any, ...], identifier: str, request: g.ControlRequest, actor: str, digest: str
) -> g.ControlReceipt:
    receipt = _operation_envelope(row, identifier)
    _require(row[2] == request.idempotency_key)
    _require(row[3] == digest, "BASELINE_IDEMPOTENCY_CONFLICT")
    if type(receipt) is not g.ControlReceipt:
        raise BaselineStorageError()
    _require(
        receipt.action == request.action
        and receipt.actor == actor
        and receipt.revision == request.expected_revision + 1
        and receipt.generation_id == request.generation_id
    )
    return receipt


def _stage_control(
    view: g.ScopeView, request: g.ControlRequest, actor: str, now: datetime, digest: str
) -> tuple[g.ControlResult, tuple[Any, ...]]:
    from uuid import uuid4

    _revision(view, request.expected_revision)
    _require(view.control_revision < 2**63 - 1, "BASELINE_CONTROL_LIMIT")
    active, previous, state = view.active, view.previous, view.state
    if request.action == "ROLLBACK":
        _require(previous is not None, "BASELINE_ROLLBACK_UNAVAILABLE")
        if previous is None:
            raise BaselineStorageError("BASELINE_ROLLBACK_UNAVAILABLE")
        _require(previous.generation_id == request.generation_id, "BASELINE_GENERATION_MISMATCH")
        active, previous = previous, None
    elif request.action in ("REVOKE", "RETIRE"):
        active = previous = None
        state = "REVOKED" if request.action == "REVOKE" else "RETIRED"
    scope = g.ScopeView(
        config=view.config,
        config_sha256=view.config_sha256,
        control_revision=view.control_revision + 1,
        frozen=request.action != "UNFREEZE",
        state=state,
        accepted_event_end=view.accepted_event_end,
        active=active,
        previous=previous,
        created_by=view.created_by,
        created_at=view.created_at,
    )
    receipt = g.ControlReceipt(
        operation_id=str(uuid4()),
        action=request.action,
        revision=scope.control_revision,
        actor=actor,
        occurred_at=now,
        generation_id=request.generation_id,
    )
    operation = _operation_row(view.config.scope_id, request, digest, receipt)
    return g.ControlResult(scope=scope, receipt=receipt), operation


def _memory_operations(operations: dict, identifier: str) -> dict:
    _require(type(operations) is dict and len(operations) <= 1024)
    try:
        for key, row in operations.items():
            _require(type(key) is tuple and len(key) == 2)
            scope_id(key[0])
            TypeAdapter(h.Identifier).validate_python(key[1], strict=True)
            _require(type(row) is tuple and len(row) == 8)
            _require(row[0] == key[0] and row[2] == key[1])
            _require(type(row[1]) is int and 1 <= row[1] <= 2**63 - 1)
            scope_id(row[4])
    except (ValueError, UnicodeError):
        raise BaselineStorageError() from None
    retained = {key: row for key, row in operations.items() if key[0] == identifier}
    _require(len(retained) <= 64)
    _require(len({row[1] for row in retained.values()}) == len(retained))
    return retained


def memory_control(
    scopes: dict,
    generations: dict,
    operations: dict,
    identifier: str,
    request: g.ControlRequest,
    actor: str,
    now: datetime,
    digest: str,
) -> tuple[dict, dict, dict, g.ControlResult]:
    retained = _memory_operations(operations, identifier)
    row = retained.get((identifier, request.idempotency_key))
    receipt = _control_operation(row, identifier, request, actor, digest) if row else None
    view = memory_get(scopes, identifier, generations)
    if view is None:
        raise BaselineStorageError(
            "BASELINE_STORAGE_UNAVAILABLE" if receipt else "BASELINE_SCOPE_NOT_FOUND"
        )
    if receipt:
        _require(receipt.revision <= view.control_revision)
        return scopes, generations, operations, g.ControlResult(scope=view, receipt=receipt)
    result, operation = _stage_control(view, request, actor, now, digest)
    _require(all(row[4] != result.receipt.operation_id for row in operations.values()))
    next_scopes = {**scopes, identifier: result.scope}
    next_generations = dict(generations)
    remaining = {
        item.generation_id for item in (result.scope.active, result.scope.previous) if item
    }
    for item in (view.active, view.previous):
        if item and item.generation_id not in remaining:
            del next_generations[(identifier, item.generation_id)]
    next_operations = {**operations, (identifier, request.idempotency_key): operation}
    ordered = sorted((*retained.values(), operation), key=lambda row: row[1])
    for old in ordered[:-64]:
        del next_operations[(identifier, old[2])]
    _require(memory_get(next_scopes, identifier, next_generations) == result.scope)
    _require(_control_operation(operation, identifier, request, actor, digest) == result.receipt)
    return next_scopes, next_generations, next_operations, result


def _event_metadata(total: int, earliest: int | None, revision: int) -> None:
    _require(type(total) is int and 0 <= total <= 64)
    _require(
        earliest is None if total == 0 else type(earliest) is int and 1 <= earliest <= revision
    )


def _events(
    view: g.ScopeView,
    rows: tuple[tuple[Any, ...], ...],
    total: int,
    earliest: int | None,
    offset: int,
    limit: int,
) -> g.ControlPage:
    _event_metadata(total, earliest, view.control_revision)
    items = tuple(_operation_envelope(row, view.config.scope_id) for row in rows)
    _require(all(item.revision <= view.control_revision for item in items))
    end = offset + len(items)
    try:
        return g.ControlPage(
            items=items,
            total=total,
            offset=offset,
            limit=limit,
            next_offset=end if end < total else None,
            earliest_retained_revision=earliest,
        )
    except ValueError:
        raise BaselineStorageError() from None


def memory_events(
    scopes: dict, generations: dict, operations: dict, identifier: str, offset: int, limit: int
) -> g.ControlPage:
    view = memory_get(scopes, identifier, generations)
    if view is None:
        raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
    retained = _memory_operations(operations, identifier)
    ordered = sorted(retained.values(), key=lambda row: row[1], reverse=True)
    earliest = ordered[-1][1] if ordered else None
    return _events(
        view, tuple(ordered[offset : offset + limit]), len(ordered), earliest, offset, limit
    )


class _ControlCAS(BaselineStorageError):
    """Only actual mutation CAS loss admits one recovery read."""


def sql_control(
    connection: Any,
    identifier: str,
    request: g.ControlRequest,
    actor: str,
    now: datetime,
    digest: str,
    *,
    postgres: bool,
) -> g.ControlResult:
    with _publication_transaction(connection, postgres=postgres) as cursor:
        db = _PublicationSQL(cursor, postgres)
        replay = db.control_replay(identifier, request, actor, digest)
        if replay is not None:
            return replay
        _require(db.exists(identifier), "BASELINE_SCOPE_NOT_FOUND")
    owner = _publication_transaction(connection, postgres=postgres, write=True)
    try:
        with owner as cursor:
            db = _PublicationSQL(cursor, postgres)
            db.exists(identifier, lock=True)
            replay = db.control_replay(identifier, request, actor, digest)
            if replay is not None:
                return replay
            view = db.get(identifier)
            if view is None:
                raise BaselineStorageError("BASELINE_SCOPE_NOT_FOUND")
            result, operation = _stage_control(view, request, actor, now, digest)
            db.control(view, result, operation)
    except (_PublicationUnique, _ControlCAS):
        if owner.failed:
            raise
        with _publication_transaction(connection, postgres=postgres) as cursor:
            replay = _PublicationSQL(cursor, postgres).control_replay(
                identifier, request, actor, digest
            )
            if replay is not None:
                return replay
        raise
    with _publication_transaction(connection, postgres=postgres) as cursor:
        db = _PublicationSQL(cursor, postgres)
        try:
            replay = db.control_replay(identifier, request, actor, digest)
        except BaselineStorageError as error:
            if error.code == "BASELINE_IDEMPOTENCY_CONFLICT":
                raise BaselineStorageError() from None
            raise
        if replay is None:
            raise BaselineStorageError()
        _require(replay.receipt == result.receipt)
        current, staged = replay.scope, result.scope
        if current.control_revision == staged.control_revision:
            _require(current == staged)
        else:
            _require(current.control_revision > staged.control_revision)
            _require(
                current.config == staged.config and current.config_sha256 == staged.config_sha256
            )
            _require(
                current.created_by == staged.created_by and current.created_at == staged.created_at
            )
            if staged.accepted_event_end is not None:
                _require(
                    current.accepted_event_end is not None
                    and current.accepted_event_end >= staged.accepted_event_end
                )
        return replay


def sql_events(
    connection: Any, identifier: str, offset: int, limit: int, *, postgres: bool
) -> g.ControlPage:
    with _publication_transaction(connection, postgres=postgres) as cursor:
        return _PublicationSQL(cursor, postgres).events(identifier, offset, limit)
