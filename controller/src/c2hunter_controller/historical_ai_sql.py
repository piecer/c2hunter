"""Cursor-local historical AI storage and additive owner migration.

Public repositories own the lock and transaction. No helper commits a caller's
transaction, and lifecycle UPDATE never assigns an owner column.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import _baseline_storage as baseline
from . import historical_ai as dto
from . import historical_ai_storage as custody
from . import historical_read as source
from .baseline_admission import BaselineLease

COLUMNS = (
    "historical_owner_version",
    "historical_request_json",
    "historical_request_byte_size",
    "historical_snapshot_json",
    "historical_snapshot_byte_size",
    "historical_expected_snapshot_sha256",
)
TYPES = ("TEXT", "TEXT", "INTEGER", "TEXT", "INTEGER", "TEXT")


def _shape(prefix: str = "", *, postgres: bool = False) -> str:
    v, r, rs, s, ss, d = [prefix + name for name in COLUMNS]
    nulls = " AND ".join(f"{prefix}{name} IS NULL" for name in COLUMNS)
    present = " AND ".join(f"{prefix}{name} IS NOT NULL" for name in COLUMNS)

    def length(col: str) -> str:
        return f"octet_length({col})" if postgres else f"length(CAST({col} AS BLOB))"

    kinds = (
        "TRUE"
        if postgres
        else " AND ".join(
            f"typeof({prefix}{col})='{kind}'"
            for col, kind in zip(
                COLUMNS, ("text", "text", "integer", "text", "integer", "text"), strict=True
            )
        )
    )
    digest = (
        f"{d} COLLATE \"C\" ~ '^[0-9a-f]{{64}}$'"
        if postgres
        else f"length(CAST({d} AS BLOB))=64 AND {d} NOT GLOB '*[^0-9a-f]*'"
    )
    return (
        f"(({nulls}) OR ({present} AND {kinds} AND {v}='historical-ai-owner-v1' "
        f"AND {rs} BETWEEN 1 AND 16384 AND {ss} BETWEEN 1 AND 4194304 "
        f"AND {length(r)}={rs} AND {length(s)}={ss} AND {digest}))"
    )


def sqlite_guards() -> dict[str, str]:
    result = {}
    immutable = " OR ".join(f"NEW.{col} IS NOT OLD.{col}" for col in COLUMNS)
    identity = " OR ".join(
        f"NEW.{col} IS NOT OLD.{col}"
        for col in ("run_id", "analysis_job_id", "idempotency_key", "created_at")
    )
    for event in ("INSERT", "UPDATE"):
        name = "ai_runs_hist_owner_" + event.lower()
        condition = f"({_shape('NEW.')}) IS NOT TRUE"
        if event == "UPDATE":
            condition += (
                f" OR {immutable} OR (OLD.historical_owner_version IS NOT NULL AND ({identity}))"
            )
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {event} ON ai_analysis_runs "
            f"WHEN {condition} BEGIN SELECT RAISE(ABORT,'historical owner invalid'); END"
        )
    return result


def _tokens(sql: str) -> tuple[str, ...]:
    # Do not lowercase quoted strings or collapse whitespace within literals.
    tokens = re.findall(
        r"--[^\n]*|/\*.*?\*/|'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\"|[A-Za-z_][A-Za-z_0-9]*|\d+|\S",
        sql,
        re.S,
    )
    return tuple(
        t if t.startswith(("'", '"')) else t.lower()
        for t in tokens
        if not t.startswith(("--", "/*"))
    )


def sqlite_schema(cursor: Any, *, install: bool = False) -> None:
    custody.require(
        cursor.execute(
            "SELECT 1 FROM sqlite_temp_schema WHERE name='ai_analysis_runs' "
            "OR name GLOB 'ai_runs_hist_owner_*'"
        ).fetchone()
        is None
    )
    columns = {row[1]: row for row in cursor.execute("PRAGMA main.table_xinfo(ai_analysis_runs)")}
    related = {name for name in columns if name.lower() in COLUMNS}
    objects = cursor.execute(
        "SELECT name,type,tbl_name,sql FROM main.sqlite_schema WHERE name "
        "GLOB 'ai_runs_hist_owner_*'"
    ).fetchall()
    if not related and not objects and install:
        for column, kind in zip(COLUMNS, TYPES, strict=True):
            cursor.execute(f"ALTER TABLE main.ai_analysis_runs ADD COLUMN {column} {kind}")
        for statement in sqlite_guards().values():
            cursor.execute(statement)
        return sqlite_schema(cursor)
    custody.require(related == set(COLUMNS))
    for name, kind in zip(COLUMNS, TYPES, strict=True):
        row = columns[name]
        custody.require(tuple(row[2:]) == (kind, 0, None, 0, 0))
    expected = sqlite_guards()
    custody.require({row[0] for row in objects} == set(expected))
    for name, kind, table, text in objects:
        custody.require(
            kind == "trigger"
            and table == "ai_analysis_runs"
            and _tokens(text) == _tokens(expected[name])
        )
    custody.require(
        cursor.execute(
            f"SELECT 1 FROM main.ai_analysis_runs WHERE ({_shape()}) IS NOT TRUE LIMIT 1"  # noqa: S608
        ).fetchone()
        is None
    )


class _CommitWitness:
    """Observe this caller's commit; baseline still owns commit and rollback."""

    def __init__(self, connection: Any) -> None:
        self.connection = connection
        self.uncertain = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self.connection, name)

    def commit(self) -> None:
        try:
            self.connection.commit()
        except BaseException:
            # A deferred SQLite constraint refusal leaves the transaction open.
            # An exception after it ended cannot establish rollback, even if the
            # baseline helper's subsequent rollback() returns successfully.
            self.uncertain = True
            if self.connection.in_transaction:
                self.uncertain = False
            raise

    def rollback(self) -> None:
        try:
            self.connection.rollback()
        except BaseException:
            self.uncertain = True
            raise

    @contextmanager
    def transaction(self) -> Iterator[None]:
        complete = False
        try:
            with self.connection.transaction():
                yield
                complete = True
        except BaseException:
            # PostgreSQL owns COMMIT in transaction.__exit__. Without a durable
            # observation, any failure leaving a successful body is uncertain.
            if complete:
                self.uncertain = True
            raise


def close_quarantined(connection: Any) -> None:
    try:
        connection.close()
    except BaseException:  # noqa: S110 -- caller unpublishes before best-effort close
        pass


@contextmanager
def transaction(connection: Any, *, postgres: bool, write: bool = False) -> Iterator[Any]:
    witness = _CommitWitness(connection)
    try:
        with baseline.transaction(
            witness, postgres=postgres, write=write, snapshot=not write
        ) as held:
            if postgres:
                if not write:
                    held.execute("SET TRANSACTION READ ONLY")
                yield held
            else:
                cursor = held.cursor()
                try:
                    yield cursor
                finally:
                    cursor.close()
    except BaseException:
        if witness.uncertain:
            raise custody.HistoricalStorageOutcomeUnknown() from None
        raise


def sqlite_readback_uri(cursor: Any) -> str:
    # Resolve the attached main file, not a possibly relative repository path.
    # Private :memory: databases cannot supply independent durable evidence.
    files = [row[2] for row in cursor.execute("PRAGMA database_list") if row[1] == "main"]
    custody.require(len(files) == 1 and bool(files[0]))
    return Path(files[0]).as_uri() + "?mode=ro"


def confirm_run(expected: dict[str, Any], connect: Callable[[], Any], *, postgres: bool) -> None:
    """No success publication until a fresh connection confirms the lifecycle."""
    try:
        with closing(connect()) as observer:
            with transaction(observer, postgres=postgres) as cursor:
                if not postgres:
                    sqlite_schema(cursor)
                observed = RunSQL(cursor, postgres).get("run_id=?", (expected["id"],))
            custody.require(observed == expected)
    except Exception:
        # Even a definite read failure says nothing about the preceding write.
        # Do not retry the read or manufacture a FAILED lifecycle here.
        raise custody.HistoricalStorageOutcomeUnknown() from None


def initialize_sqlite(connection: Any) -> None:
    with transaction(connection, postgres=False, write=True) as cursor:
        sqlite_schema(cursor, install=True)
    with transaction(connection, postgres=False) as cursor:
        sqlite_schema(cursor)


def _pg_guard_body() -> str:
    immutable = " OR ".join(f"NEW.{col} IS DISTINCT FROM OLD.{col}" for col in COLUMNS)
    identity = " OR ".join(
        f"NEW.{col} IS DISTINCT FROM OLD.{col}"
        for col in ("run_id", "analysis_job_id", "idempotency_key", "created_at")
    )
    return (
        "BEGIN IF "
        + immutable
        + " OR (OLD.historical_owner_version IS NOT NULL AND ("
        + identity
        + ")) THEN RAISE EXCEPTION 'historical owner invalid'; END IF; RETURN NEW; END;"
    )


def _check_ast(expression: str) -> Any:
    """Closed CHECK grammar, preserving boolean structure and operand order."""
    tokens = list(_tokens(expression))
    position = 0

    def take(expected: str | None = None) -> str:
        nonlocal position
        custody.require(position < len(tokens))
        value = tokens[position]
        custody.require(expected is None or expected == value)
        position += 1
        return value

    def peek(value: str) -> bool:
        return position < len(tokens) and tokens[position] == value

    def joined(operator: str, nodes: list[Any]) -> Any:
        result: list[Any] = []
        for node in nodes:
            result.extend(node[1:] if node[0] == operator else [node])
        return (operator, *result) if len(result) > 1 else result[0]

    def primary() -> Any:
        if peek("("):
            take("(")
            result = boolean("or")
            take(")")
        else:
            value = take()
            if value == "octet_length":
                take("(")
                result = (value, primary())
                take(")")
            else:
                custody.require(
                    value in COLUMNS
                    or value in {"true", "false", "null"}
                    or value.isdigit()
                    or value.startswith("'")
                )
                result = ("atom", value)
        if peek(":"):
            take(":")
            take(":")
            take("text")
            custody.require(result[0] == "atom" and result[1].startswith("'"))
        if peek("collate"):
            take("collate")
            take('"C"')
            result = ("collate", result, '"C"')
        return result

    def compare() -> Any:
        left = primary()
        if position == len(tokens) or tokens[position] in {")", "and", "or"}:
            return left
        op = take()
        if op == "is":
            suffix = take()
            if suffix == "not":
                suffix += " " + take()
            custody.require(suffix in {"null", "not null", "true"})
            return ("is " + suffix, left)
        if op == "between":
            lo = primary()
            take("and")
            return joined("and", [(">=", left, lo), ("<=", left, primary())])
        if op in {">", "<"} and peek("="):
            op += take("=")
        custody.require(op in {"=", ">=", "<=", "~"})
        return (op, left, primary())

    def boolean(operator: str) -> Any:
        child = compare if operator == "and" else lambda: boolean("and")
        values = [child()]
        while peek(operator):
            take(operator)
            values.append(child())
        return joined(operator, values)

    result = boolean("or")
    custody.require(position == len(tokens))
    return result


def postgres_schema(cursor: Any, *, install: bool = False) -> None:
    cursor.execute(
        "SELECT c.oid,n.oid,n.nspname FROM pg_class c JOIN pg_namespace n "
        "ON n.oid=c.relnamespace WHERE c.oid='ai_analysis_runs'::regclass AND c.relkind='r'"
    )
    row = cursor.fetchone()
    custody.require(row is not None)
    oid, namespace, name = row
    schema = '"' + name.replace('"', '""') + '"'
    cursor.execute(
        "SELECT a.attname,t.typname,a.atttypmod,a.attnotnull,a.attidentity,"
        "a.attgenerated,a.atthasdef "
        "FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid "
        "WHERE a.attrelid=%s AND a.attnum>0 AND NOT a.attisdropped "
        "AND lower(a.attname)=ANY(%s)",
        (oid, list(COLUMNS)),
    )
    columns = cursor.fetchall()
    cursor.execute(
        "SELECT conname,contype,convalidated,condeferrable,condeferred,"
        "connoinherit,pg_get_expr(conbin,conrelid) "
        "FROM pg_constraint WHERE conrelid=%s AND conname LIKE 'ai_runs_hist_owner_%%'",
        (oid,),
    )
    checks = cursor.fetchall()
    cursor.execute(
        "SELECT tgname,tgtype,tgenabled,tgisinternal,tgnargs,tgattr::text,tgqual IS NULL,tgfoid "
        "FROM pg_trigger WHERE tgrelid=%s AND tgname LIKE 'ai_runs_hist_owner_%%'",
        (oid,),
    )
    triggers = cursor.fetchall()
    cursor.execute(
        "SELECT p.oid,p.proname,p.pronargs,p.prorettype='trigger'::regtype,"
        "l.lanname,p.prosecdef,p.provolatile,p.proparallel,p.proconfig,p.prosrc "
        "FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.pronamespace=%s "
        "AND p.proname LIKE 'ai_runs_hist_owner_%%'",
        (namespace,),
    )
    functions = cursor.fetchall()
    if install and not (columns or checks or triggers or functions):
        for column, kind in zip(COLUMNS, TYPES, strict=True):
            cursor.execute(f"ALTER TABLE {schema}.ai_analysis_runs ADD COLUMN {column} {kind}")
        cursor.execute(
            f"ALTER TABLE {schema}.ai_analysis_runs ADD CONSTRAINT "
            f"ai_runs_hist_owner_shape CHECK (({_shape(postgres=True)}) IS TRUE)"
        )
        cursor.execute(
            f"CREATE FUNCTION {schema}.ai_runs_hist_owner_guard() RETURNS "
            f"trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER PARALLEL "
            f"UNSAFE SET search_path=pg_catalog AS $owner${_pg_guard_body()}$owner$"
        )
        cursor.execute(
            f"CREATE TRIGGER ai_runs_hist_owner_update BEFORE UPDATE ON "
            f"{schema}.ai_analysis_runs FOR EACH ROW EXECUTE FUNCTION "
            f"{schema}.ai_runs_hist_owner_guard()"
        )
        return postgres_schema(cursor)
    custody.require({r[0] for r in columns} == set(COLUMNS))
    expected_types = dict(
        zip(COLUMNS, ("text", "text", "int4", "text", "int4", "text"), strict=True)
    )
    custody.require(
        all(tuple(r[1:]) == (expected_types[r[0]], -1, False, "", "", False) for r in columns)
    )
    custody.require(len(functions) == len(checks) == len(triggers) == 1)
    function = functions[0]
    custody.require(
        tuple(function[1:9])
        == (
            "ai_runs_hist_owner_guard",
            0,
            True,
            "plpgsql",
            False,
            "v",
            "u",
            ["search_path=pg_catalog"],
        )
    )
    custody.require(function[9].strip("\n") == _pg_guard_body())
    custody.require(
        tuple(triggers[0])
        == ("ai_runs_hist_owner_update", 19, "O", False, 0, "", True, function[0])
    )
    custody.require(
        tuple(checks[0][:6]) == ("ai_runs_hist_owner_shape", "c", True, False, False, False)
    )
    custody.require(_check_ast(checks[0][6]) == _check_ast(f"({_shape(postgres=True)}) IS TRUE"))
    cursor.execute(
        f"SELECT 1 FROM {schema}.ai_analysis_runs WHERE "  # noqa: S608 -- schema is double-quote escaped at catalog read; _shape is code-owned
        f"({_shape(postgres=True)}) IS NOT TRUE LIMIT 1"
    )
    custody.require(cursor.fetchone() is None)


def initialize_postgres(connection: Any) -> None:
    with transaction(connection, postgres=True, write=True) as cursor:
        cursor.execute("LOCK TABLE ai_analysis_runs IN ACCESS EXCLUSIVE MODE")
        postgres_schema(cursor, install=True)
    with transaction(connection, postgres=True) as cursor:
        postgres_schema(cursor)


class RunSQL:
    def __init__(self, cursor: Any, postgres: bool) -> None:
        self.cursor, self.postgres = cursor, postgres
        self._sql = baseline._SQL(cursor, postgres)
        if postgres:
            postgres_schema(cursor)

    def execute(self, statement: str, values: tuple[Any, ...] = ()) -> Any:
        return self._sql.execute(statement, values)

    def get(
        self, selector: str, values: tuple[Any, ...], *, lock: bool = False, compact: bool = False
    ) -> dict[str, Any] | None:
        from .historical_ai_descendants import SQLAccess, guard

        # Metadata is acquired before any lifecycle/owner text crosses the driver.
        suffix = " FOR UPDATE" if lock and self.postgres else ""
        present = " OR ".join(f"{col} IS NOT NULL" for col in COLUMNS)
        metadata = SQLAccess(self.cursor, self.postgres)._meta(
            "R", "r0", "ai_analysis_runs r0", selector + suffix, values
        )
        guard([metadata], compact=compact)
        length = "octet_length(data::text)" if self.postgres else "length(CAST(data AS BLOB))"
        gate = f"({_shape(postgres=self.postgres)}) AND {length}<=65536"
        created = (
            "to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')"
            if self.postgres
            else "created_at"
        )
        fields = ",".join(f"CASE WHEN {gate} THEN {col} END" for col in COLUMNS)
        row = self.execute(
            f"SELECT run_id,analysis_job_id,idempotency_key,{created},"  # noqa: S608
            f"CASE WHEN NOT ({present}) OR ({gate}) THEN data END,{fields} "
            f"FROM ai_analysis_runs WHERE {selector}{suffix}",
            values,
        ).fetchone()
        if row is None:
            return None
        custody.require(row[4] is not None)
        historical = any(item is not None for item in row[5:])
        try:
            # Historical lifecycle is byte-gated in SQL, then duplicate-gated.
            raw = (
                row[4]
                if type(row[4]) is dict
                else (source._decode(row[4], max_bytes=65536) if historical else json.loads(row[4]))
            )
        except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise custody.HistoricalStorageError() from None
        custody.require(type(raw) is dict)
        if not historical:
            custody.require(not custody.historical_marker(raw))
            return raw
        internal = {**raw, custody.OWNER_KEY: dict(zip(custody.OWNER_FIELDS, row[5:], strict=True))}
        custody.historical_header(internal, tuple(row[:4]))
        return internal

    def insert(self, run: dict[str, Any]) -> None:
        owner = custody.historical_header(run)
        raw = {k: v for k, v in run.items() if k != custody.OWNER_KEY}
        placeholders = "?,?,?,?,?" + ("::jsonb" if self.postgres else "") + ",?,?,?,?,?,?"
        self.execute(
            "INSERT INTO ai_analysis_runs("  # noqa: S608 -- code-owned columns
            f"run_id,analysis_job_id,idempotency_key,created_at,data,{','.join(COLUMNS)}) "
            f"VALUES({placeholders})",
            tuple(run[k] for k in custody.IDENTITY_KEYS)
            + (json.dumps(raw),)
            + tuple(owner[k] for k in custody.OWNER_FIELDS),
        )

    def save(self, submitted: dict[str, Any]) -> dict[str, Any]:
        from .historical_ai_descendants import SQLAccess, guard

        if self.postgres:
            self.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('pcap-export-admission',0))"
            )
            nodes = SQLAccess(self.cursor, True).chain("R", submitted["id"])
            if guard(nodes):
                root = nodes[0]
                if root is None:
                    raise custody.HistoricalStorageError()
                custody.require(
                    self.execute(
                        "SELECT id FROM controller_objects WHERE kind='job' AND id=? FOR UPDATE",
                        (root.fields["analysis_job_id"],),
                    ).fetchone()
                    is not None
                )
        existing = self.get("run_id=?", (submitted["id"],), lock=True)
        if existing is not None and custody.OWNER_KEY in existing:
            saved = custody.lifecycle_save(existing, submitted)
            if saved == existing:
                return saved
        else:
            custody.require(not custody.historical_marker(submitted))
            if existing is None and self.postgres:
                raise KeyError(f"AI run not found: {submitted['id']}")
            if existing is not None and existing.get("status") in custody.TERMINAL:
                return existing
            saved = submitted
        data = {k: v for k, v in saved.items() if k != custody.OWNER_KEY}
        self.execute(
            "UPDATE ai_analysis_runs SET data=?::jsonb WHERE run_id=?"
            if self.postgres
            else "UPDATE ai_analysis_runs SET data=? WHERE run_id=?",
            (json.dumps(data, separators=(",", ":"), default=str), submitted["id"]),
        )
        self.audit(saved)
        return saved

    def audit(self, run: dict[str, Any]) -> None:
        if not self.postgres:
            return
        data = run
        if custody.OWNER_KEY in run:
            owner = custody.historical_header(run)
            try:
                custody.materialize_historical_run(run)
                fingerprint = custody._original_request(owner).request_fingerprint
            except dto.HistoricalAIError:
                fingerprint = None
            data = {
                "analysis_job_id": run["analysis_job_id"],
                "baseline_mode": "historical",
                "status": run["status"],
                "request_fingerprint": fingerprint,
                "snapshot_sha256": owner["expected_snapshot_sha256"],
            }
        self.execute(
            "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
            "VALUES('ai-run',?,?,?::jsonb)",
            (run["id"], datetime.now(UTC), json.dumps(data)),
        )

    def admit(
        self,
        request: dto.HistoricalAdmissionRequest,
        builder: custody.Builder,
        lease: BaselineLease,
    ) -> tuple[dict[str, Any], bool]:
        from .historical_ai_access import authorize

        authorize(True)
        if self.postgres:
            # Serialize idempotency and deletion before source/job/scope row locks.
            self.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('pcap-export-admission',0))"
            )
        existing = self.get(
            "analysis_job_id=? AND idempotency_key=?",
            (request.analysis_job_id, request.payload.idempotency_key),
        )
        if existing is not None:
            custody.replay_matches(existing, request)
            return existing, False
        custody.require(lease.acquire(), "BASELINE_BUSY")
        ref = request.payload.baseline_reference
        if ref is None:
            raise custody.HistoricalStorageError()
        store = baseline._SQL(self.cursor, self.postgres)
        scope = baseline._revision(store.get(ref.scope_id, lock=True), ref.expected_revision)
        generation = None
        if scope.active:
            row = self.execute(
                "SELECT publication_revision,document_json,content_sha256,byte_size "
                "FROM baseline_generations WHERE scope_id=? AND generation_id=?",
                (ref.scope_id, scope.active.generation_id),
            ).fetchone()
            custody.require(row is not None)
            generation = baseline._stored_document(scope, scope.active.generation_id, tuple(row))
        target = (source.postgres_ai_target if self.postgres else source.sqlite_ai_target)(
            self.cursor,
            request.analysis_job_id,
            scope.config,
            ref.quality_review,
        )
        run = custody.stage_admission(request, target, scope, generation, builder)
        self.insert(run)
        self.audit(run)
        return run, True
