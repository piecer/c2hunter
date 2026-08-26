from __future__ import annotations

import re
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any, cast

import pytest
from c2hunter_analysis.pcap_postings import PostingQueryLimits
from test_pcap_posting_index_repository import _prepare

from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    posting_index_identity,
)
from c2hunter_controller.pcap_posting_index_queue import PostingIndexAdmission, PostingIndexTaskSpec
from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.repositories import MemoryRepository


def _sql_without_literals(query: str) -> str:
    """Blank SQL literals so lexical checks inspect executable tokens only."""
    result: list[str] = []
    index = 0
    while index < len(query):
        if query[index] == "'":
            result.append(" ")
            index += 1
            while index < len(query):
                if query[index] == "'" and index + 1 < len(query) and query[index + 1] == "'":
                    result.extend((" ", " "))
                    index += 2
                    continue
                if query[index] == "'":
                    result.append(" ")
                    index += 1
                    break
                result.append(" ")
                index += 1
            else:
                raise AssertionError("unterminated SQL string literal")
            continue
        result.append(query[index])
        index += 1
    return "".join(result)


def _validate_postgres_sql(query: str, params: object = None, *, many: bool = False) -> None:
    """Reject common fake-only SQL mistakes before scripted responses can hide them."""
    code = _sql_without_literals(query)
    malformed_percent = re.search(r"%(?!s)", code)
    assert malformed_percent is None, "only psycopg %s placeholders are valid"
    placeholder_count = len(re.findall(r"%s", code))
    if many:
        assert params is not None, "executemany requires parameter rows"
        rows = list(cast(Any, params))
        assert all(len(row) == placeholder_count for row in rows), "placeholder count mismatch"
    else:
        values = () if params is None else cast(tuple[Any, ...], params)
        assert len(values) == placeholder_count, "placeholder count mismatch"

    tokens = re.findall(
        r"%s|[A-Za-z_][A-Za-z_0-9$]*|\d+|::|->>|->|<=|>=|<>|!=|=>|<<|[(),.*=<>+\-/]",
        code,
    )
    upper = [token.upper() for token in tokens]
    for update_index, token in enumerate(upper):
        if token != "UPDATE" or (update_index > 0 and upper[update_index - 1] == "FOR"):
            continue
        boundary = next(
            (
                index
                for index in range(update_index + 1, len(upper))
                if upper[index] in {"WHERE", "RETURNING", ";"}
            ),
            len(upper),
        )
        set_positions = [
            index for index in range(update_index + 1, boundary) if upper[index] == "SET"
        ]
        assert len(set_positions) == 1, "UPDATE must contain exactly one SET clause"
        set_index = set_positions[0]
        assert set_index + 1 < len(upper) and upper[set_index + 1] != "SET", "duplicate SET"

    for returning_index, token in enumerate(upper):
        if token != "RETURNING":
            continue
        assert returning_index + 1 < len(tokens), "RETURNING requires a projection"
        projection = upper[returning_index + 1]
        assert projection not in {",", ")", "WHERE", "RETURNING"}, "malformed RETURNING"

    if re.search(r"\bFOR\s+UPDATE\b", code, re.IGNORECASE):
        assert not re.search(r"\b(COUNT|MAX|MIN|SUM|AVG)\s*\(", code, re.IGNORECASE), (
            "PostgreSQL cannot lock aggregate rows"
        )


@pytest.mark.parametrize(
    "query,params",
    [
        ("UPDATE pcap_posting_index_jobs SET SET status='RUNNING'", None),
        ("UPDATE pcap_posting_index_jobs WHERE source_id=%s", ("source",)),
        ("UPDATE pcap_posting_index_jobs SET status=%q", ("RUNNING",)),
        ("UPDATE pcap_posting_index_jobs SET status=%s RETURNING", ("RUNNING",)),
        ("SELECT COUNT(*) FROM pcap_posting_index_jobs FOR UPDATE", None),
    ],
)
def test_postgres_runtime_sql_validator_rejects_structurally_invalid_sql(
    query: str, params: object
) -> None:
    with pytest.raises(AssertionError):
        _validate_postgres_sql(query, params)


def test_postgres_runtime_sql_validator_accepts_valid_update() -> None:
    _validate_postgres_sql(
        "UPDATE pcap_posting_index_jobs SET status=%s WHERE source_id=%s RETURNING source_id",
        ("RUNNING", "source"),
    )


class MigrationCursor:
    def __init__(self, connection: MigrationConnection) -> None:
        self.connection = connection
        self.rowcount = 0

    def __enter__(self) -> MigrationCursor:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def execute(self, query: str, params: object = None) -> None:
        self.connection.calls.append((query, params))

    def fetchall(self) -> list[tuple[Any, ...]]:
        return []


class MigrationConnection:
    def __init__(self) -> None:
        self.closed = False
        self.autocommit = False
        self.calls: list[tuple[str, object]] = []
        self.commits = 0

    def cursor(self) -> MigrationCursor:
        return MigrationCursor(self)

    def commit(self) -> None:
        self.commits += 1

    def close(self) -> None:
        self.closed = True


def test_stage11_postgres_migration_is_additive_normalized_and_idempotent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connections = [MigrationConnection(), MigrationConnection()]
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: connections.pop(0)),
    )

    for _ in range(2):
        repository = PostgresRepository(
            "postgresql://stage11.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
        )
        monkeypatch.setattr(repository, "_ensure_candidate_query_indexes", lambda _connection: None)
        connection = repository.connection
        schema = connection.calls[0][0]
        for table in (
            "pcap_posting_index_intents",
            "pcap_posting_index_jobs",
            "pcap_posting_index_generations",
            "pcap_posting_index_chunks",
            "pcap_posting_index_owners",
        ):
            assert f"CREATE TABLE IF NOT EXISTS {table}" in schema
        normalized = " ".join(schema.split())
        assert "canonical_value bytea NOT NULL" in normalized
        assert "encoded_ordinals bytea NOT NULL" in normalized
        assert (
            "REFERENCES pcap_capture_source_versions(source_kind,source_id) ON DELETE CASCADE"
            in normalized
        )
        assert "REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE" in normalized
        assert "CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT'))" in normalized
        assert "CHECK(state IN ('STAGING','READY'))" in normalized
        compact = normalized.replace(", ", ",")
        dimension_check = compact.split("CHECK(dimension IN (", 1)[1].split("))", 1)[0]
        assert {item.strip(" '") for item in dimension_check.split(",")} == {
            "ALL_PACKET",
            "SUPPORTED",
            "SRC_ADDRESS",
            "DST_ADDRESS",
            "SRC_PORT",
            "DST_PORT",
            "PROTOCOL",
            "HAS_PAYLOAD",
        }
        assert "CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_claim" in schema
        assert "CREATE INDEX IF NOT EXISTS pcap_posting_index_intents_reconcile" in schema
        assert "CREATE INDEX IF NOT EXISTS pcap_posting_index_generations_staging" in schema
        assert "CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_terminal" in schema
        constraint_sql = re.sub(r"\s*([(),])\s*", r"\1", normalized)
        compact_normalized = normalized.replace(", ", ",")
        assert "UNIQUE(source_kind,source_id,parent_structural_build_id)" in compact_normalized
        assert (
            "FOREIGN KEY(source_kind,source_id,parent_structural_build_id)REFERENCES "
            "pcap_posting_index_intents(source_kind,source_id,parent_structural_build_id)ON "
            "DELETE CASCADE" in constraint_sql
        )
        assert "DO $stage11$" in schema
        repository.close()


def test_postgres_ddl_model_rejects_task_whose_parent_differs_from_intent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MigrationConnection()
    monkeypatch.setitem(
        sys.modules,
        "psycopg",
        SimpleNamespace(connect=lambda *_args, **_kwargs: connection),
    )
    repository = PostgresRepository(
        "postgresql://stage11.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    schema_connection = repository.connection
    schema = re.sub(r"\s*([(),])\s*", r"\1", " ".join(schema_connection.calls[0][0].split()))
    repository.close()
    match = re.search(
        r"FOREIGN KEY\(([^)]+)\)REFERENCES "
        r"pcap_posting_index_intents\(([^)]+)\)ON DELETE CASCADE",
        schema,
    )
    assert match is not None
    child_columns = tuple(match.group(1).split(","))
    parent_columns = tuple(match.group(2).split(","))
    assert (
        child_columns
        == parent_columns
        == (
            "source_kind",
            "source_id",
            "parent_structural_build_id",
        )
    )
    intent_rows = {("PCAP_UPLOAD", "source-1", "parent-a")}
    mismatched_task = dict(zip(child_columns, ("PCAP_UPLOAD", "source-1", "parent-b"), strict=True))
    with pytest.raises(ValueError, match="composite foreign key"):
        task_key = tuple(mismatched_task[column] for column in child_columns)
        if task_key not in intent_rows:
            raise ValueError("composite foreign key violation")


class ScriptedCursor(MigrationCursor):
    def __init__(self, connection: ScriptedConnection) -> None:
        super().__init__(connection)
        self.rows: list[tuple[Any, ...]] = []

    def execute(self, query: str, params: object = None) -> None:
        _validate_postgres_sql(query, params)
        self.connection.calls.append((query, params))
        self.rows, self.rowcount = self.connection.respond(query, params)

    def fetchone(self) -> tuple[Any, ...] | None:
        return self.rows[0] if self.rows else None

    def fetchall(self) -> list[tuple[Any, ...]]:
        rows, self.rows = self.rows, []
        return rows

    def fetchmany(self, size: int) -> list[tuple[Any, ...]]:
        rows, self.rows = self.rows[:size], self.rows[size:]
        return rows

    def executemany(self, query: str, params: object) -> None:
        _validate_postgres_sql(query, params, many=True)
        self.connection.calls.append((query, params))
        self.rows, self.rowcount = self.connection.respond(query, params)


class ScriptedConnection(MigrationConnection):
    def __init__(self, respond: Any) -> None:
        super().__init__()
        self.respond = respond
        self.rollbacks = 0

    def cursor(self) -> ScriptedCursor:
        return ScriptedCursor(self)

    def rollback(self) -> None:
        self.rollbacks += 1


def _runtime_repository(connection: ScriptedConnection) -> PostgresRepository:
    repository = PostgresRepository(
        "postgresql://stage11.invalid/controller", cast(MinioBlobStore, SimpleNamespace())
    )
    repository._connection = connection
    return repository


def _spec_values(spec: PostingIndexTaskSpec) -> tuple[Any, ...]:
    return (
        spec.source_kind,
        spec.source_id,
        spec.source_version_id,
        spec.source_size_bytes,
        spec.source_sha256,
        spec.capture_format,
        spec.parent_structural_build_id,
        spec.parent_structural_index_sha256,
        spec.structural_schema_version,
        spec.structural_parser_contract_version,
        spec.posting_schema_version,
        spec.posting_parser_contract_version,
        spec.filter_contract_version,
    )


def _intent_row(
    spec: PostingIndexTaskSpec,
    now: datetime,
    *,
    status: str = "PENDING",
) -> tuple[Any, ...]:
    return (*_spec_values(spec), status, now, now, None, None)


def _task_row(
    spec: PostingIndexTaskSpec,
    now: datetime,
    *,
    status: str = "RUNNING",
    attempt: int = 1,
    max_attempts: int = 3,
    token: str | None = "owner-token",
) -> tuple[Any, ...]:
    return (
        *_spec_values(spec),
        status,
        attempt,
        max_attempts,
        token,
        now + timedelta(seconds=30) if token else None,
        now,
        now,
        now,
        None,
    )


def test_postgres_backfill_is_bounded_pre_filtered_locked_and_uses_database_clock() -> None:
    database_now = datetime(2026, 8, 26, tzinfo=UTC)

    def respond(query: str, params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.lstrip().startswith("WITH eligible_posting_parents AS"):
            return [("PCAP_UPLOAD", "source-a"), ("LIVE_SEGMENT", "segment-a")], 2
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert repository.request_posting_index_backfill(limit=2) == 2
    assert len(connection.calls) == 1
    query, params = connection.calls[0]
    normalized = " ".join(query.split())
    where = normalized.index(" WHERE ")
    order = normalized.index(" ORDER BY ")
    limit = normalized.index(" LIMIT %s")
    assert where < order < limit
    assert normalized.count("NOT EXISTS") >= 3
    assert "FOR UPDATE OF owner SKIP LOCKED" in normalized
    assert "clock_timestamp()" in normalized
    assert "INSERT INTO pcap_posting_index_intents" in normalized
    assert "INSERT INTO pcap_posting_index_jobs" not in normalized
    assert params == (
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        1,
        2,
    )
    assert connection.commits == 1 and connection.rollbacks == 0
    assert database_now.tzinfo is UTC  # Explicitly no application timestamp entered the payload.


def test_postgres_request_and_claim_use_database_clock_and_skip_locked() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())
    database_now = datetime(2026, 8, 26, tzinfo=UTC)

    def respond(query: str, params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_capture_source_versions" in query:
            return [
                (
                    source.source_kind,
                    source.source_id,
                    source.object_key,
                    source.source_version_id,
                    source.source_size_bytes,
                    source.source_sha256,
                )
            ], 1
        if "FROM pcap_offset_index_owners" in query:
            return [(parent.build_id, parent.index_sha256, "READY")], 1
        if query.startswith("SELECT source_version_id") and "pcap_posting_index_intents" in query:
            return [], 0
        if query.startswith("INSERT INTO pcap_posting_index_intents"):
            values = cast(tuple[Any, ...], params)
            return [(*values[:13], "PENDING", database_now, database_now, None, None)], 1
        if "UPDATE pcap_posting_index_jobs AS task" in query:
            token = cast(tuple[Any, ...], params)[1]
            spec = (
                source.source_version_id,
                source.source_size_bytes,
                source.source_sha256,
                "PCAP",
                parent.build_id,
                parent.index_sha256,
                1,
                1,
                1,
                1,
                1,
            )
            return [
                (
                    source.source_kind,
                    source.source_id,
                    *spec,
                    "RUNNING",
                    1,
                    3,
                    token,
                    database_now,
                    database_now,
                    database_now,
                    database_now,
                    None,
                )
            ], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    intent = repository.request_posting_index(source, parent)
    assert intent is not None and intent.requested_at == database_now
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.status.value == "RUNNING"
    sql = "\n".join(query for query, _params in connection.calls)
    assert "clock_timestamp()" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "ORDER BY task.next_attempt_at,task.queued_at,task.source_kind,task.source_id" in sql
    assert all(
        not isinstance(value, datetime)
        for query, params in connection.calls
        if "pcap_posting_index" in query and params
        for value in cast(tuple[Any, ...], params)
    )


def test_postgres_heartbeat_is_exact_fenced_by_database_clock() -> None:
    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        return ([], 1) if query.startswith("UPDATE pcap_posting_index_jobs") else ([], 0)

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)
    assert repository.heartbeat_posting_index(
        "PCAP_UPLOAD", "source-1", attempt=2, lease_token="opaque", lease_seconds=30
    )
    query, params = connection.calls[0]
    assert "status='RUNNING'" in query
    assert "attempt=%s AND lease_token=%s" in query
    assert "lease_expires_at>clock_timestamp()" in query
    assert "lease_expires_at=clock_timestamp()+make_interval(secs=>%s)" in query
    assert params == (30, "PCAP_UPLOAD", "source-1", 2, "opaque")


def test_postgres_bounded_lookup_checks_metadata_before_chunks_and_fetches_limit_plus_one() -> None:
    source, parent, posting, _replacement = _prepare(MemoryRepository())
    spec = PostingIndexTaskSpec.from_binding(source, parent)
    generation = posting.generation
    generation_row = (
        posting.build_id,
        *_spec_values(spec),
        "READY",
        datetime(2026, 8, 26, tzinfo=UTC),
        generation.packet_count,
        generation.supported_count,
        generation.membership_count,
        generation.distinct_key_count,
        len(generation.chunks),
        generation.encoded_byte_count,
        [dimension.value for dimension in generation.complete_dimensions],
        generation.digest,
        generation.binding_document,
        1,
        "winner",
        None,
    )
    source_row = (
        source.source_kind,
        source.source_id,
        source.object_key,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
    )
    chunk_rows = [
        (
            chunk.dimension.value,
            chunk.value,
            chunk.chunk_ordinal,
            chunk.first_packet_index,
            chunk.last_packet_index,
            chunk.count,
            chunk.encoded_ordinals,
        )
        for chunk in generation.chunks
    ]

    def responses(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_posting_index_owners" in query:
            return [(posting.build_id,)], 1
        if "FROM pcap_capture_source_versions" in query:
            return [source_row], 1
        if "FROM pcap_offset_index_owners" in query:
            return [(parent.build_id, parent.index_sha256, "READY")], 1
        if "FROM pcap_posting_index_generations" in query:
            return [generation_row], 1
        if "FROM pcap_posting_index_chunks" in query:
            return chunk_rows, len(chunk_rows)
        pytest.fail(f"unexpected bounded lookup SQL: {query}")

    oversized = ScriptedConnection(responses)
    oversized_lookup = _runtime_repository(oversized).get_posting_index(
        source,
        parent,
        PostingQueryLimits(max_directory_chunks=len(chunk_rows) - 1),
    )
    assert oversized_lookup.availability is PostingIndexAvailability.RESOURCE_LIMIT
    assert not any("FROM pcap_posting_index_chunks" in query for query, _params in oversized.calls)

    accepted = ScriptedConnection(responses)
    accepted_lookup = _runtime_repository(accepted).get_posting_index(
        source,
        parent,
        PostingQueryLimits(max_directory_chunks=len(chunk_rows)),
    )
    assert accepted_lookup.availability is PostingIndexAvailability.READY
    chunk_query, chunk_params = next(
        (query, params)
        for query, params in accepted.calls
        if "FROM pcap_posting_index_chunks" in query
    )
    assert "LIMIT %s" in chunk_query
    assert chunk_params == (posting.build_id, len(chunk_rows) + 1)


def test_postgres_posting_identity_is_one_parameterized_metadata_only_row() -> None:
    source, parent, posting, _replacement = _prepare(MemoryRepository())
    spec = PostingIndexTaskSpec.from_binding(source, parent)
    generation = posting.generation
    created_at = datetime(2026, 8, 26, tzinfo=UTC)
    row = (
        posting.build_id,
        *_spec_values(spec),
        "READY",
        created_at,
        generation.packet_count,
        generation.supported_count,
        generation.membership_count,
        generation.distinct_key_count,
        len(generation.chunks),
        generation.encoded_byte_count,
        [item.value for item in generation.complete_dimensions],
        generation.digest,
        generation.binding_document,
    )

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        assert "pcap_posting_index_owners" in query
        assert "pcap_posting_index_generations" in query
        assert "pcap_posting_index_chunks" not in query
        return [row], 1

    connection = ScriptedConnection(respond)
    compact = _runtime_repository(connection).get_posting_index_identity(source, parent)

    assert compact.availability is PostingIndexAvailability.READY
    assert compact.identity == posting_index_identity(replace(posting, created_at=created_at))
    assert len(connection.calls) == 1
    query, params = connection.calls[0]
    assert "LIMIT 1" in query
    assert params == (source.source_kind, source.source_id, parent.build_id)


@pytest.mark.parametrize(
    "failed_mutation",
    ["generation", "owner", "task", "intent"],
)
def test_postgres_publication_checks_every_mutation_rowcount_and_lock_order(
    failed_mutation: str,
) -> None:
    source, parent, posting, _replacement = _prepare(MemoryRepository())
    spec = PostingIndexTaskSpec.from_binding(source, parent)
    spec_values = (
        spec.source_kind,
        spec.source_id,
        spec.source_version_id,
        spec.source_size_bytes,
        spec.source_sha256,
        spec.capture_format,
        spec.parent_structural_build_id,
        spec.parent_structural_index_sha256,
        spec.structural_schema_version,
        spec.structural_parser_contract_version,
        spec.posting_schema_version,
        spec.posting_parser_contract_version,
        spec.filter_contract_version,
    )
    now = datetime(2026, 8, 26, tzinfo=UTC)
    intent_row = (*spec_values, "PENDING", now, now, None, None)
    task_row = (
        *spec_values,
        "RUNNING",
        1,
        3,
        "winner",
        now + timedelta(seconds=30),
        now,
        now,
        now,
        None,
    )
    generation = posting.generation
    generation_row = (
        posting.build_id,
        *spec_values,
        "STAGING",
        now,
        generation.packet_count,
        generation.supported_count,
        generation.membership_count,
        generation.distinct_key_count,
        len(generation.chunks),
        generation.encoded_byte_count,
        [dimension.value for dimension in generation.complete_dimensions],
        generation.digest,
        generation.binding_document,
        1,
        "winner",
        "old-owner",
    )
    chunk_rows = [
        (
            chunk.dimension.value,
            chunk.value,
            chunk.chunk_ordinal,
            chunk.first_packet_index,
            chunk.last_packet_index,
            chunk.count,
            chunk.encoded_ordinals,
        )
        for chunk in generation.chunks
    ]

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_capture_source_versions" in query:
            return [
                (
                    source.source_kind,
                    source.source_id,
                    source.object_key,
                    source.source_version_id,
                    source.source_size_bytes,
                    source.source_sha256,
                )
            ], 1
        if "FROM pcap_offset_index_owners" in query:
            return [(parent.build_id, parent.index_sha256, "READY")], 1
        if "FROM pcap_posting_index_intents" in query and "JOIN" not in query:
            return [intent_row], 1
        if "JOIN pcap_posting_index_jobs AS task" in query:
            return [task_row], 1
        if "FROM pcap_posting_index_generations" in query and "SELECT build_id," in query:
            return [generation_row], 1
        if "FROM pcap_posting_index_owners" in query:
            return [("old-owner",)], 1
        if "FROM pcap_posting_index_chunks" in query:
            return chunk_rows, len(chunk_rows)
        mutation = None
        if query.startswith("UPDATE pcap_posting_index_generations SET state='READY'"):
            mutation = "generation"
        elif query.startswith("INSERT INTO pcap_posting_index_owners"):
            mutation = "owner"
        elif query.startswith("UPDATE pcap_posting_index_jobs SET status='COMPLETED'"):
            mutation = "task"
        elif query.startswith("UPDATE pcap_posting_index_intents SET status='COMPLETED'"):
            mutation = "intent"
        return [], 0 if mutation == failed_mutation else 1

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(open=lambda *_args: pytest.fail("object store called during publication")),
    )

    assert not repository.publish_posting_index(
        posting.build_id,
        source_version=source,
        parent=parent,
        attempt=1,
        lease_token="winner",
    )
    assert connection.commits == 0 and connection.rollbacks == 1
    sql = [query for query, _params in connection.calls]
    lock_positions = [
        next(index for index, query in enumerate(sql) if marker in query)
        for marker in (
            "FROM pcap_capture_source_versions",
            "FROM pcap_offset_index_owners",
            "FROM pcap_posting_index_intents WHERE",
            "JOIN pcap_posting_index_jobs AS task",
            "FROM pcap_posting_index_generations",
            "FROM pcap_posting_index_owners",
        )
    ]
    assert lock_positions == sorted(lock_positions)


def test_postgres_structural_owner_replacement_is_blocked_by_active_posting_task() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())
    replacement_build_id = f"{parent.build_id}-replacement"
    job = {
        "id": source.source_id,
        "mode": "PCAP_UPLOAD",
        "source": {
            "packet_bytes_retained": True,
            "size_bytes": source.source_size_bytes,
            "sha256": source.source_sha256,
            "capture_format": parent.binding.capture_format,
        },
    }
    generation_row = (
        parent.binding.source_kind,
        parent.binding.source_id,
        parent.binding.source_version_id,
        parent.binding.source_size_bytes,
        parent.binding.source_sha256,
        parent.binding.capture_format,
        parent.binding.schema_version,
        parent.binding.parser_contract_version,
        parent.created_at,
    )

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM controller_objects WHERE kind='job'" in query:
            return [(job,)], 1
        if "FROM pcap_capture_source_versions" in query:
            return [
                (
                    source.source_kind,
                    source.source_id,
                    source.object_key,
                    source.source_version_id,
                    source.source_size_bytes,
                    source.source_sha256,
                )
            ], 1
        if "FROM pcap_offset_index_generations" in query and "state='STAGING'" in query:
            return [generation_row], 1
        if "COUNT(*) FROM pcap_offset_index_packets" in query:
            return [(len(parent.packets),)], 1
        if "FROM pcap_offset_index_packets" in query:
            return [tuple(vars(packet).values()) for packet in parent.packets], len(parent.packets)
        if "FROM pcap_offset_index_owners" in query:
            return [(parent.build_id,)], 1
        if "FROM pcap_posting_index_jobs" in query and "status IN ('QUEUED','RUNNING')" in query:
            assert "status IN ('QUEUED','RUNNING')" in query
            assert "parent_structural_build_id=%s" in query
            return [(1,)], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert not repository.publish_structural_index(
        replacement_build_id,
        parent.binding,
        parent.interfaces,
        len(parent.packets),
    )
    sql = "\n".join(query for query, _params in connection.calls)
    assert "FROM pcap_posting_index_jobs" in sql
    assert "UPDATE pcap_offset_index_generations SET state='READY'" not in sql
    assert connection.commits == 0 and connection.rollbacks == 1


@pytest.mark.parametrize("marker_failure", [None, "exception", "rowcount", "terminal"])
def test_postgres_structural_ready_and_posting_marker_share_one_transaction(
    marker_failure: str | None,
) -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())
    spec = PostingIndexTaskSpec.from_binding(source, parent)
    job = {
        "id": source.source_id,
        "mode": "PCAP_UPLOAD",
        "source": {
            "packet_bytes_retained": True,
            "size_bytes": source.source_size_bytes,
            "sha256": source.source_sha256,
            "capture_format": parent.binding.capture_format,
        },
    }
    generation_row = (
        parent.binding.source_kind,
        parent.binding.source_id,
        parent.binding.source_version_id,
        parent.binding.source_size_bytes,
        parent.binding.source_sha256,
        parent.binding.capture_format,
        parent.binding.schema_version,
        parent.binding.parser_contract_version,
        parent.created_at,
    )

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "INSERT INTO pcap_posting_index_intents" in query:
            if marker_failure == "exception":
                raise RuntimeError("marker write failed")
            if marker_failure in {"rowcount", "terminal"}:
                return [], 0
        if (
            marker_failure == "terminal"
            and query.startswith("SELECT source_kind,source_id,source_version_id")
            and "FROM pcap_posting_index_intents" in query
        ):
            return [_intent_row(spec, parent.created_at, status="COMPLETED")], 1
        if "FROM controller_objects WHERE kind='job'" in query:
            return [(job,)], 1
        if "FROM pcap_capture_source_versions" in query and "source_id=%s" in query:
            return [
                (
                    source.source_kind,
                    source.source_id,
                    source.object_key,
                    source.source_version_id,
                    source.source_size_bytes,
                    source.source_sha256,
                )
            ], 1
        if "state='STAGING'" in query:
            return [generation_row], 1
        if "COUNT(*) FROM pcap_offset_index_packets" in query:
            return [(len(parent.packets),)], 1
        if "FROM pcap_offset_index_packets" in query:
            return [tuple(vars(packet).values()) for packet in parent.packets], len(parent.packets)
        return [], 1

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    if marker_failure == "exception":
        with pytest.raises(RuntimeError, match="marker write failed"):
            repository.publish_structural_index(
                parent.build_id,
                parent.binding,
                parent.interfaces,
                len(parent.packets),
                request_postings=True,
            )
        assert connection.commits == 0 and connection.rollbacks == 1
    elif marker_failure == "rowcount":
        assert not repository.publish_structural_index(
            parent.build_id,
            parent.binding,
            parent.interfaces,
            len(parent.packets),
            request_postings=True,
        )
        assert connection.commits == 0 and connection.rollbacks == 1
    else:
        assert repository.publish_structural_index(
            parent.build_id,
            parent.binding,
            parent.interfaces,
            len(parent.packets),
            request_postings=True,
        )
        sql = "\n".join(query for query, _params in connection.calls)
        assert "INSERT INTO pcap_posting_index_intents" in sql
        assert "clock_timestamp()" in sql
        assert connection.commits == 1 and connection.rollbacks == 0


def test_postgres_source_version_replacement_cannot_request_against_old_parent() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())
    replaced_source = replace(source, source_version_id="version-replaced")

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_capture_source_versions" in query:
            return [
                (
                    replaced_source.source_kind,
                    replaced_source.source_id,
                    replaced_source.object_key,
                    replaced_source.source_version_id,
                    replaced_source.source_size_bytes,
                    replaced_source.source_sha256,
                )
            ], 1
        if "FROM pcap_offset_index_owners" in query:
            return [(parent.build_id, parent.index_sha256, "READY")], 1
        if "FROM pcap_posting_index_intents" in query:
            return [], 0
        return [], 1

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert repository.request_posting_index(replaced_source, parent) is None
    sql = "\n".join(query for query, _params in connection.calls)
    assert "INSERT INTO pcap_posting_index_intents" not in sql
    assert connection.commits == 0


@pytest.mark.parametrize(
    ("race", "source_row", "parent_row"),
    [
        ("source_deleted", None, None),
        ("source_replaced", ("replacement",), None),
        ("parent_deleted", "current", None),
        ("parent_replaced", "current", ("replacement", "0" * 64, "READY")),
    ],
)
def test_postgres_source_and_parent_races_block_publication_before_mutation(
    race: str,
    source_row: object,
    parent_row: tuple[Any, ...] | None,
) -> None:
    source, parent, posting, _replacement = _prepare(MemoryRepository())
    exact_source_row = (
        source.source_kind,
        source.source_id,
        source.object_key,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
    )

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_capture_source_versions" in query:
            if source_row == "current":
                return [exact_source_row], 1
            if source_row is None:
                return [], 0
            return [(*exact_source_row[:-3], "replacement", *exact_source_row[-2:])], 1
        if "FROM pcap_offset_index_owners" in query:
            return ([parent_row], 1) if parent_row is not None else ([], 0)
        pytest.fail(f"publication race {race} reached unexpected SQL: {query}")

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert not repository.publish_posting_index(
        posting.build_id,
        source_version=source,
        parent=parent,
        attempt=1,
        lease_token="stale-builder",
    )
    sql = "\n".join(query for query, _params in connection.calls)
    assert "UPDATE pcap_posting_index_generations" not in sql
    assert connection.commits == 0 and connection.rollbacks == 1


def test_postgres_expired_lease_recovers_and_is_reclaimable_with_a_new_token() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())
    spec = PostingIndexTaskSpec.from_binding(source, parent)
    now = datetime(2026, 8, 26, tzinfo=UTC)

    def respond(query: str, params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.startswith("SELECT intent.source_kind,intent.source_id"):
            return [(spec.source_kind, spec.source_id, parent.build_id)], 1
        if query.startswith("SELECT task.max_attempts"):
            return [(3, 1)], 1
        if query.startswith("UPDATE pcap_posting_index_jobs SET status=%s"):
            return [], 1
        if query.startswith("UPDATE pcap_posting_index_intents SET status=%s"):
            return [], 1
        if "UPDATE pcap_posting_index_jobs AS task" in query:
            token = cast(tuple[Any, ...], params)[0]
            return [_task_row(spec, now, attempt=2, token=str(token))], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert repository.recover_posting_indexes() == 1
    reclaimed = repository.claim_posting_index(lease_seconds=30)
    assert reclaimed is not None and reclaimed.attempt == 2
    assert reclaimed.lease_token not in {None, "expired-token"}
    sql = "\n".join(query for query, _params in connection.calls)
    assert "lease_expires_at<=clock_timestamp()" in sql
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "next_attempt_at=clock_timestamp()" in sql


def test_postgres_failure_locks_exact_eligible_intent_before_exact_running_task() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.startswith("SELECT parent_structural_build_id FROM pcap_posting_index_intents"):
            return [(parent.build_id,)], 1
        if query.startswith("SELECT task.max_attempts"):
            return [(3,)], 1
        if query.startswith("UPDATE"):
            return [], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert repository.fail_posting_index(
        source.source_kind,
        source.source_id,
        attempt=1,
        lease_token="owner",
        transient=True,
        error_code="POSTING_TIMEOUT",
        retry_base_seconds=1,
    )

    locks = [query for query, _params in connection.calls if "FOR UPDATE" in query]
    assert len(locks) == 2
    assert "pcap_posting_index_intents" in locks[0]
    assert "status IN ('PENDING','DEFERRED')" in locks[0]
    assert "pcap_posting_index_jobs" in locks[1]
    assert "parent_structural_build_id=%s" in locks[1]
    assert "status='RUNNING'" in locks[1]
    assert "attempt=%s AND task.lease_token=%s" in locks[1]
    assert "lease_expires_at>clock_timestamp()" in locks[1]


def test_postgres_recovery_locks_bounded_deterministic_intents_before_expired_tasks() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.startswith("SELECT intent.source_kind,intent.source_id"):
            return [(source.source_kind, source.source_id, parent.build_id)], 1
        if query.startswith("SELECT task.max_attempts"):
            return [(3, 1)], 1
        if query.startswith("UPDATE"):
            return [], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)

    assert repository.recover_posting_indexes() == 1

    locks = [query for query, _params in connection.calls if "FOR UPDATE" in query]
    assert len(locks) == 2
    assert "pcap_posting_index_intents AS intent" in locks[0]
    assert "EXISTS (SELECT 1 FROM pcap_posting_index_jobs AS task" in locks[0]
    assert "ORDER BY intent.updated_at,intent.source_kind,intent.source_id" in locks[0]
    assert "FOR UPDATE OF intent SKIP LOCKED LIMIT %s" in locks[0]
    assert connection.calls[0][1] == (100,)
    assert "pcap_posting_index_jobs AS task" in locks[1]
    assert "parent_structural_build_id=%s" in locks[1]
    assert "lease_expires_at<=clock_timestamp()" in locks[1]
    assert "FOR UPDATE SKIP LOCKED" in locks[1]
    assert not any(query.startswith("WITH expired AS") for query, _params in connection.calls)


def test_postgres_stale_lease_cannot_heartbeat_fail_begin_stage_publish_or_abort() -> None:
    source, parent, posting, _replacement = _prepare(MemoryRepository())
    connection = ScriptedConnection(lambda _query, _params: ([], 0))
    repository = _runtime_repository(connection)
    repository.blob_store = cast(
        MinioBlobStore,
        SimpleNamespace(
            open=lambda *_args: pytest.fail("object store called by posting transaction"),
            get=lambda *_args: pytest.fail("object store called by posting transaction"),
            put=lambda *_args: pytest.fail("object store called by posting transaction"),
            delete=lambda *_args: pytest.fail("object store called by posting transaction"),
        ),
    )

    assert not repository.heartbeat_posting_index(
        source.source_kind,
        source.source_id,
        attempt=1,
        lease_token="stale",
        lease_seconds=30,
    )
    assert not repository.fail_posting_index(
        source.source_kind,
        source.source_id,
        attempt=1,
        lease_token="stale",
        transient=True,
        error_code="POSTING_TIMEOUT",
        retry_base_seconds=1,
    )
    with pytest.raises(ValueError, match="posting task lease is not current"):
        repository.begin_posting_index(posting, attempt=1, lease_token="stale")
    with pytest.raises(ValueError, match="posting task lease is not current"):
        repository.stage_posting_index_chunks(
            posting.build_id,
            posting.generation.chunks,
            source_kind=source.source_kind,
            source_id=source.source_id,
            attempt=1,
            lease_token="stale",
        )
    assert not repository.publish_posting_index(
        posting.build_id,
        source_version=source,
        parent=parent,
        attempt=1,
        lease_token="stale",
    )
    assert not repository.abort_posting_index(
        posting.build_id,
        source_kind=source.source_kind,
        source_id=source.source_id,
        parent_structural_build_id=parent.build_id,
        attempt=1,
        lease_token="stale",
    )
    lifecycle_sql = [query for query, _params in connection.calls if "pcap_posting_index" in query]
    assert lifecycle_sql
    assert all(
        not isinstance(value, datetime)
        for query, params in connection.calls
        if "pcap_posting_index" in query and params
        for value in cast(tuple[Any, ...], params)
    )
    assert connection.commits == 0 and connection.rollbacks == 8


def test_postgres_admission_coalesces_before_capacity_and_defers_at_capacity() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())
    spec = PostingIndexTaskSpec.from_binding(source, parent)
    now = datetime(2026, 8, 26, tzinfo=UTC)

    def coalesced(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_posting_index_intents" in query:
            return [_intent_row(spec, now)], 1
        if "SELECT status FROM pcap_posting_index_jobs" in query:
            return [("RUNNING",)], 1
        pytest.fail(f"coalesced admission reached capacity SQL: {query}")

    coalesced_connection = ScriptedConnection(coalesced)
    assert (
        _runtime_repository(coalesced_connection).admit_posting_index(
            source.source_kind, source.source_id, capacity=1, max_attempts=3
        )
        is PostingIndexAdmission.COALESCED
    )
    assert not any("COUNT(*)" in query for query, _params in coalesced_connection.calls)

    def full(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if "FROM pcap_posting_index_intents" in query:
            return [_intent_row(spec, now)], 1
        if "SELECT status FROM pcap_posting_index_jobs" in query:
            return [], 0
        if "SELECT COUNT(*) FROM pcap_posting_index_jobs" in query:
            return [(1,)], 1
        if query.startswith("UPDATE pcap_posting_index_intents SET status='DEFERRED'"):
            return [], 1
        return [], 0

    full_connection = ScriptedConnection(full)
    assert (
        _runtime_repository(full_connection).admit_posting_index(
            source.source_kind, source.source_id, capacity=1, max_attempts=3
        )
        is PostingIndexAdmission.DEFERRED
    )
    assert not any(
        query.startswith("INSERT INTO pcap_posting_index_jobs")
        for query, _params in full_connection.calls
    )


def test_postgres_retry_exhaustion_terminalizes_task_and_intent_atomically() -> None:
    source, parent, _posting, _replacement = _prepare(MemoryRepository())

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.startswith("SELECT parent_structural_build_id FROM pcap_posting_index_intents"):
            return [(parent.build_id,)], 1
        if query.startswith("SELECT task.max_attempts"):
            return [(3,)], 1
        if query.startswith("UPDATE pcap_posting_index_jobs SET status=%s"):
            return [], 1
        if query.startswith("UPDATE pcap_posting_index_intents SET status=%s"):
            return [], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)
    assert repository.fail_posting_index(
        source.source_kind,
        source.source_id,
        attempt=3,
        lease_token="last-owner",
        transient=True,
        error_code="POSTING_TIMEOUT",
        retry_base_seconds=2,
    )
    mutations = [
        (query, cast(tuple[Any, ...], params))
        for query, params in connection.calls
        if query.startswith("UPDATE")
    ]
    assert mutations[0][1][0] == "FAILED"
    assert mutations[1][1][0] == "FAILED"
    assert connection.commits == 1 and connection.rollbacks == 0


def test_postgres_reconciliation_and_cleanup_are_bounded_and_filter_before_limit() -> None:
    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.startswith("SELECT source_kind,source_id FROM pcap_posting_index_jobs"):
            return [("PCAP_UPLOAD", "terminal-source")], 1
        if query.startswith(
            "SELECT generation.source_kind,generation.source_id,generation.build_id"
        ):
            return [("PCAP_UPLOAD", "stale-source", "stale-build")], 1
        if query.startswith("DELETE FROM pcap_posting_index_jobs"):
            return [("terminal-source",)], 1
        if query.startswith("DELETE FROM pcap_posting_index_generations"):
            return [("stale-build",)], 1
        return [], 0

    connection = ScriptedConnection(respond)
    repository = _runtime_repository(connection)
    assert repository.reconcile_posting_indexes(capacity=2, max_attempts=3, limit=7) == 0
    assert repository.cleanup_terminal_posting_indexes(max_age_seconds=60, limit=5) == 1
    assert repository.cleanup_stale_posting_indexes(max_age_seconds=60, limit=5) == 1

    reconcile_sql, reconcile_params = connection.calls[0]
    assert "status IN ('PENDING','DEFERRED')" in reconcile_sql
    assert "NOT EXISTS" in reconcile_sql
    assert reconcile_sql.index("NOT EXISTS") < reconcile_sql.index("LIMIT %s")
    assert reconcile_params == (7,)
    terminal_sql = next(
        query
        for query, _params in connection.calls
        if query.startswith("SELECT source_kind,source_id FROM pcap_posting_index_jobs")
    )
    assert "status IN ('COMPLETED','FAILED')" in terminal_sql
    assert "ORDER BY updated_at,source_kind,source_id LIMIT %s" in terminal_sql
    staging_sql = next(
        query
        for query, _params in connection.calls
        if query.startswith(
            "SELECT generation.source_kind,generation.source_id,generation.build_id"
        )
    )
    assert "generation.state='STAGING'" in staging_sql
    assert "NOT EXISTS" in staging_sql
    assert "FROM pcap_posting_index_owners" in staging_sql
    assert "task.status='RUNNING'" in staging_sql
    assert "task.lease_expires_at>clock_timestamp()" in staging_sql
    assert "ORDER BY generation.created_at,generation.build_id LIMIT %s" in staging_sql
    assert "generation.created_at<clock_timestamp()-make_interval(secs=>%s)" in staging_sql
    assert "generation.created_at<=" not in staging_sql


@pytest.mark.parametrize(
    ("mode", "live_rows", "expected_sources"),
    [
        ("PCAP_UPLOAD", [], ["delete-job"]),
        ("LIVE", [("delete-segment", "sensor-pcaps/delete-segment.pcap")], ["delete-segment"]),
    ],
)
def test_postgres_job_deletion_removes_exact_posting_lifecycle_before_blob_cleanup(
    mode: str,
    live_rows: list[tuple[str, str]],
    expected_sources: list[str],
) -> None:
    job_id = "delete-job"
    upload_object_key = f"captures/{job_id}/immutable-generation.pcap"

    def respond(query: str, _params: object) -> tuple[list[tuple[Any, ...]], int]:
        if query.startswith("SELECT 1 FROM pcap_export_jobs"):
            return [], 0
        if "SELECT data FROM controller_objects WHERE kind='job'" in query:
            return [({"id": job_id, "mode": mode},)], 1
        if query.startswith("SELECT data->>'status' FROM ai_analysis_runs"):
            return [], 0
        if "WHERE kind='export'" in query:
            return [], 0
        if "WHERE kind='sensor_pcap'" in query and "FOR UPDATE" in query:
            return live_rows, len(live_rows)
        if query.startswith("SELECT object_key FROM pcap_capture_source_versions"):
            return [(upload_object_key,)], 1
        if query.startswith("DELETE FROM controller_objects WHERE kind='job'"):
            return [], 1
        return [], 1

    connection = ScriptedConnection(respond)

    class BlobTracker:
        def __init__(self) -> None:
            self.deleted: list[str] = []

        def delete(self, object_key: str) -> None:
            assert connection.commits >= 1, "blob deletion ran inside the posting/job transaction"
            self.deleted.append(object_key)

    blob = BlobTracker()
    repository = _runtime_repository(connection)
    repository.blob_store = cast(MinioBlobStore, blob)

    assert repository.delete_job(job_id)

    source_cases: list[tuple[str, list[str], tuple[Any, ...]]] = [
        ("PCAP_UPLOAD", [job_id], (job_id,))
    ]
    if mode == "LIVE":
        source_cases.append(("LIVE_SEGMENT", expected_sources, (expected_sources,)))

    expected_lock_templates = [
        "SELECT source_id FROM pcap_capture_source_versions WHERE source_kind=%s "
        "AND source_id=ANY(%s) ORDER BY source_id FOR UPDATE",
        "SELECT owner.source_id,owner.build_id FROM pcap_offset_index_owners AS owner "
        "JOIN pcap_offset_index_generations AS generation ON generation.build_id="
        "owner.build_id WHERE owner.source_kind=%s AND owner.source_id=ANY(%s) "
        "ORDER BY owner.source_id,owner.build_id FOR UPDATE OF owner,generation",
        "SELECT source_id,build_id FROM pcap_offset_index_generations WHERE "
        "source_kind=%s AND source_id=ANY(%s) ORDER BY source_id,build_id FOR UPDATE",
        "SELECT source_id,parent_structural_build_id FROM pcap_posting_index_intents "
        "WHERE source_kind=%s AND source_id=ANY(%s) ORDER BY source_id FOR UPDATE",
        "SELECT source_id,parent_structural_build_id FROM pcap_posting_index_jobs "
        "WHERE source_kind=%s AND source_id=ANY(%s) ORDER BY source_id FOR UPDATE",
        "SELECT source_id,parent_structural_build_id,build_id FROM "
        "pcap_posting_index_generations WHERE source_kind=%s AND source_id=ANY(%s) "
        "ORDER BY source_id,parent_structural_build_id,build_id FOR UPDATE",
        "SELECT source_id,parent_structural_build_id,build_id FROM "
        "pcap_posting_index_owners WHERE source_kind=%s AND source_id=ANY(%s) "
        "ORDER BY source_id,parent_structural_build_id FOR UPDATE",
    ]
    expected_lock_calls = [
        (query, (source_kind, source_ids))
        for source_kind, source_ids, _delete_params in source_cases
        for query in expected_lock_templates
    ]
    posting_tables = (
        "pcap_capture_source_versions",
        "pcap_offset_index_owners",
        "pcap_offset_index_generations",
        "pcap_posting_index_intents",
        "pcap_posting_index_jobs",
        "pcap_posting_index_generations",
        "pcap_posting_index_owners",
    )
    actual_lock_calls = [
        (query, params)
        for query, params in connection.calls
        if "FOR UPDATE" in query and any(table in query for table in posting_tables)
    ]
    assert actual_lock_calls == expected_lock_calls

    expected_posting_deletes = [
        (
            f"DELETE FROM pcap_posting_index_intents WHERE source_kind='{source_kind}' "
            f"AND source_id={'ANY(%s)' if source_kind == 'LIVE_SEGMENT' else '%s'}",
            delete_params,
        )
        for source_kind, _source_ids, delete_params in source_cases
    ] + [
        (
            f"DELETE FROM pcap_posting_index_generations "
            f"WHERE source_kind='{source_kind}' AND "
            f"source_id={'ANY(%s)' if source_kind == 'LIVE_SEGMENT' else '%s'}",
            delete_params,
        )
        for source_kind, _source_ids, delete_params in source_cases
    ]
    if mode == "LIVE":
        expected_posting_deletes = [
            expected_posting_deletes[0],
            expected_posting_deletes[2],
            expected_posting_deletes[1],
            expected_posting_deletes[3],
        ]
    actual_posting_deletes = [
        (query, params)
        for query, params in connection.calls
        if query.startswith("DELETE FROM pcap_posting_index")
    ]
    assert actual_posting_deletes == expected_posting_deletes
    assert all(
        not query.startswith(
            (
                "DELETE FROM pcap_posting_index_jobs",
                "DELETE FROM pcap_posting_index_owners",
                "DELETE FROM pcap_posting_index_chunks",
            )
        )
        for query, _params in connection.calls
    ), "matching-kind posting dependents must be removed only by cascade"

    if mode == "PCAP_UPLOAD":
        assert blob.deleted == [upload_object_key]
    else:
        assert blob.deleted == [live_rows[0][1]]
