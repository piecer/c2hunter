"""Separate durable Investigation Run custody; no API, source I/O or model calls.

Initialize explicitly at repository startup. The facade never creates schema on
admission. The MemoryRepository adapter is process-local, as is that repository.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from threading import RLock
from typing import Any
from weakref import WeakKeyDictionary

from .repositories import MemoryRepository, SQLiteRepository

RUN_KIND = "ai_investigation_run_v1"
STATE_KIND = "ai_investigation_state_v1"
TERMINAL = frozenset({"COMPLETED", "PARTIAL", "CANCELLED", "FAILED"})
STEP_KIND = "ai_investigation_step_v1"
EVIDENCE_KIND = "ai_investigation_evidence_v1"
BUDGETS = {
    "model_calls": 6,
    "tool_calls": 12,
    "transport_attempts": 12,
    "source_bytes": 67108864,
    "source_records": 100000,
}


@dataclass
class _MemoryRows:
    rows: dict[tuple[str, str], str] = field(default_factory=dict)
    index: dict[tuple[str, str], set[str]] = field(default_factory=dict)


_MEMORY: WeakKeyDictionary[MemoryRepository, _MemoryRows] = WeakKeyDictionary()
_MEMORY_LOCK = RLock()
_QUARANTINED: WeakKeyDictionary[Any, bool] = WeakKeyDictionary()


class InvestigationStoreError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class InvestigationStorageError(RuntimeError):
    """Persistence failed: do not acknowledge delivery or convert to model failure."""


class InvestigationOutcomeUnknown(InvestigationStorageError):
    """Commit/cleanup was ambiguous. Reopen with a new repository before replay."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise InvestigationStoreError(code)


def _encode(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    )


def _backend(repository: Any) -> str:
    from .production import PostgresRepository

    if isinstance(repository, MemoryRepository):
        return "memory"
    if isinstance(repository, SQLiteRepository):
        return "sqlite"
    if isinstance(repository, PostgresRepository):
        return "postgres"
    raise InvestigationStoreError("UNSUPPORTED_REPOSITORY")


def _expression(field: str, postgres: bool) -> str:
    return f"data->>'{field}'" if postgres else f"json_extract(data,'$.{field}')"


def _execute(tx: Any, sql: str, parameters: tuple[Any, ...], postgres: bool) -> Any:
    if postgres:
        sql = sql.replace("objects", "controller_objects").replace("?", "%s")
        sql = sql.replace("VALUES(%s,%s,%s)", "VALUES(%s,%s,%s::jsonb)")
    tx.execute(sql, parameters)
    return tx


@contextmanager
def _sql_transaction(repository: Any, postgres: bool) -> Iterator[Any]:
    with repository._lock:
        if repository in _QUARANTINED:
            raise InvestigationOutcomeUnknown("STORAGE_OUTCOME_UNKNOWN")
        try:
            connection = repository.connection
        except Exception:
            raise InvestigationStorageError("STORAGE_UNAVAILABLE") from None
        if postgres:
            from psycopg.pq import TransactionStatus

            _require(
                not connection.autocommit
                and connection.info.transaction_status == TransactionStatus.IDLE,
                "STORE_BUSY",
            )
        else:
            _require(not connection.in_transaction, "STORE_BUSY")
        cursor = None
        commit_started = False
        try:
            cursor = connection.cursor()
            if postgres:
                cursor.execute("BEGIN")
                cursor.execute("SET LOCAL lock_timeout='5s'")
                cursor.execute("SELECT pg_try_advisory_xact_lock(2026110501)")
                _require(cursor.fetchone() == (True,), "STORE_BUSY")
            else:
                cursor.execute("BEGIN IMMEDIATE")
            yield cursor
            cursor.close()
            cursor = None
            commit_started = True
            connection.commit()
        except BaseException as exc:
            cleanup_failed = False
            try:
                connection.rollback()
            except BaseException:
                cleanup_failed = True
            if cursor is not None:
                try:
                    cursor.close()
                except BaseException:
                    cleanup_failed = True
            if commit_started or cleanup_failed:
                _QUARANTINED[repository] = True
                if isinstance(exc, Exception):
                    raise InvestigationOutcomeUnknown("STORAGE_OUTCOME_UNKNOWN") from None
            if isinstance(exc, InvestigationStoreError):
                raise
            if isinstance(exc, Exception):
                raise InvestigationStorageError("STORAGE_UNAVAILABLE") from None
            raise


def initialize_investigation_store(repository: Any) -> None:
    """Explicit startup migration, AFTER the repository's own schema migration."""
    backend = _backend(repository)
    if backend == "memory":
        with _MEMORY_LOCK:
            _MEMORY.setdefault(repository, _MemoryRows())
        return
    postgres = backend == "postgres"
    with _sql_transaction(repository, postgres) as tx:
        for name, fields in (
            ("queue", ("status",)),
            ("owner", ("owner_id", "job_id")),
            ("slot", ("slot",)),
        ):
            expressions = ",".join(f"({_expression(f, postgres)})" for f in fields)
            _execute(
                tx,
                f"CREATE INDEX IF NOT EXISTS investigation_{name}_v1 ON objects "
                f"(kind,{expressions},id) WHERE kind='{STATE_KIND}'",
                (),
                postgres,
            )
        _execute(
            tx,
            "INSERT INTO objects(kind,id,data) VALUES(?,?,?) ON CONFLICT DO NOTHING",
            ("ai_investigation_schema", "v1", "{}"),
            postgres,
        )


def _document(raw: bytes, limit: int) -> str:
    _require(type(raw) is bytes and 0 < len(raw) <= limit, "INVALID_DOCUMENT")
    try:
        text = raw.decode("utf-8")
        value = json.loads(text)
        _require(type(value) is dict, "INVALID_DOCUMENT")
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            _require(depth <= 24, "INVALID_DOCUMENT")
            if isinstance(item, dict):
                _require(all("\x00" not in k for k in item), "INVALID_DOCUMENT")
                _require(
                    not {str(k).lower() for k in item}.intersection(
                        {"api_key", "authorization", "password", "access_token", "gateway_config"}
                    ),
                    "INVALID_DOCUMENT",
                )
                pending.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
            elif isinstance(item, str):
                _require("\x00" not in item, "INVALID_DOCUMENT")
        _require(_encode(value).encode() == raw, "INVALID_DOCUMENT")
        return text
    except (ValueError, UnicodeError, RecursionError):
        raise InvestigationStoreError("INVALID_DOCUMENT") from None


def _header(*values: object) -> None:
    _require(
        all(
            type(v) is str
            and 1 <= len(v) <= 200
            and v.isascii()
            and all(32 < ord(c) < 127 for c in v)
            for v in values
        ),
        "INVALID_HEADER",
    )


class InvestigationRunStore:
    def __init__(self, repository: Any, *, clock: Callable[[], float] = time.time) -> None:
        backend = _backend(repository)
        self.repository = repository
        self.clock = clock
        self._memory = backend == "memory"
        self._postgres = backend == "postgres"
        if self._memory:
            with _MEMORY_LOCK:
                _require(repository in _MEMORY, "STORE_NOT_INITIALIZED")
        else:
            with _sql_transaction(repository, self._postgres) as tx:
                _require(
                    _execute(
                        tx,
                        "SELECT 1 FROM objects WHERE kind=? AND id=?",
                        ("ai_investigation_schema", "v1"),
                        self._postgres,
                    ).fetchone()
                    is not None,
                    "STORE_NOT_INITIALIZED",
                )

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        with self.repository._lock:
            if self._memory:
                current = _MEMORY[self.repository]
                pending = _MemoryRows(
                    dict(current.rows), {k: set(v) for k, v in current.index.items()}
                )
                yield pending
                _MEMORY[self.repository] = pending
            else:
                with _sql_transaction(self.repository, self._postgres) as tx:
                    yield tx

    def _now(self) -> float:
        now = self.clock()
        _require(type(now) in (float, int) and math.isfinite(now) and now >= 0, "INVALID_CLOCK")
        return float(now)

    def _retained_count(self, tx: Any) -> int:
        if self._memory:
            return len(tx.index.get(("kind", RUN_KIND), set()))
        row = _execute(
            tx, "SELECT COUNT(*) FROM objects WHERE kind=?", (RUN_KIND,), self._postgres
        ).fetchone()
        return int(row[0])

    def _read(
        self,
        tx: Any,
        kind: str,
        identifier: str,
        *,
        owner: str | None = None,
        job: str | None = None,
    ) -> dict[str, Any] | None:
        filters = {k: v for k, v in (("owner_id", owner), ("job_id", job)) if v is not None}
        if self._memory:
            if kind == STATE_KIND and any(
                identifier not in tx.index.get((k, v), set()) for k, v in filters.items()
            ):
                return None
            text = tx.rows.get((kind, identifier))
        else:
            predicates = "".join(f" AND {_expression(k, self._postgres)}=?" for k in filters)
            row = _execute(
                tx,
                # Column expressions are fixed above; all caller values are parameters.
                "SELECT data FROM objects WHERE kind=? AND id=?" + predicates,  # noqa: S608
                (kind, identifier, *filters.values()),
                self._postgres,
            ).fetchone()
            text = row[0] if row else None
        result = (
            (text if isinstance(text, dict) else json.loads(text)) if text is not None else None
        )
        return (
            result
            if result is not None and all(result.get(k) == v for k, v in filters.items())
            else None
        )

    def _write(self, tx: Any, kind: str, identifier: str, value: dict[str, Any]) -> None:
        text = _encode(value)
        _require(len(text.encode()) <= (600000 if kind == RUN_KIND else 70000), "STORAGE_LIMIT")
        if self._memory:
            previous = tx.rows.get((kind, identifier))
            if kind == STATE_KIND:
                old = json.loads(previous) if previous is not None else None
                for key in ("owner_id", "job_id", "status", "slot"):
                    if old is not None:
                        tx.index[key, old[key]].discard(identifier)
                    tx.index.setdefault((key, value[key]), set()).add(identifier)
            tx.rows[kind, identifier] = text
            tx.index.setdefault(("kind", kind), set()).add(identifier)
        else:
            _execute(
                tx,
                "INSERT INTO objects(kind,id,data) VALUES(?,?,?) ON CONFLICT(kind,id) "
                "DO UPDATE SET data=excluded.data",
                (kind, identifier, text),
                self._postgres,
            )

    def _states(
        self,
        tx: Any,
        *,
        owner: str | None = None,
        job: str | None = None,
        status: str | None = None,
        slot: str | None = None,
        after: str = "",
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        filters = {
            k: v
            for k, v in (("owner_id", owner), ("job_id", job), ("status", status), ("slot", slot))
            if v is not None
        }
        if self._memory:
            identifiers = set(tx.index.get(("kind", STATE_KIND), set()))
            for key, value in filters.items():
                identifiers.intersection_update(tx.index.get((key, value), set()))
            return [
                json.loads(tx.rows[STATE_KIND, identifier])
                for identifier in sorted(i for i in identifiers if i > after)[:limit]
            ]
        predicates = "".join(f" AND {_expression(k, self._postgres)}=?" for k in filters)
        rows = _execute(
            tx,
            # Only fixed field expressions are interpolated; values/limit are parameters.
            "SELECT data FROM objects WHERE kind=? AND id>?" + predicates + " ORDER BY id LIMIT ?",  # noqa: S608
            (STATE_KIND, after, *filters.values(), limit),
            self._postgres,
        ).fetchall()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def page(
        self, owner_id: str, job_id: str, *, after: str = "", limit: int = 20
    ) -> list[dict[str, Any]]:
        _header(owner_id, job_id)
        _require(
            type(limit) is int and 1 <= limit <= 20 and type(after) is str and len(after) <= 64,
            "INVALID_PAGE",
        )
        with self._transaction() as tx:
            return [
                self._public(r)
                for r in self._states(tx, owner=owner_id, job=job_id, after=after, limit=limit)
            ]

    @staticmethod
    def _identity(owner_id: str, idempotency_key: str) -> str:
        return hashlib.sha256(_encode([owner_id, idempotency_key]).encode()).hexdigest()

    @staticmethod
    def _public(state: dict[str, Any]) -> dict[str, Any]:
        budgets = state.get("budgets")
        if type(budgets) is not dict:
            raise InvestigationStoreError("STORE_CORRUPT")
        _require(
            budgets.keys() == BUDGETS.keys()
            and all(
                type(budgets[k]) is int and 0 <= budgets[k] <= cap for k, cap in BUDGETS.items()
            ),
            "STORE_CORRUPT",
        )
        public = {
            key: state[key]
            for key in (
                "id",
                "owner_id",
                "job_id",
                "status",
                "revision",
                "created_at",
                "result",
                "reason",
            )
            if key in state
        }
        # This detached five-counter projection belongs to the same state epoch.
        public["progress"] = {key: budgets[key] for key in BUDGETS}
        return public

    def _lookup(
        self, tx: Any, owner: str, job: str, key: str, request: bytes
    ) -> dict[str, Any] | None:
        identifier = self._identity(owner, key)
        record = self._read(tx, RUN_KIND, identifier, owner=owner)
        if record is None:
            return None
        _require(
            record["job_id"] == job and record["request_json"] == request.decode(),
            "IDEMPOTENCY_CONFLICT",
        )
        state = self._read(tx, STATE_KIND, identifier)
        if state is None:
            raise InvestigationStoreError("STORE_CORRUPT")
        self._verify_record(record, state)
        return self._public(state)

    def lookup(
        self, *, owner_id: str, job_id: str, idempotency_key: str, request_json: bytes
    ) -> dict[str, Any] | None:
        """Resolve replay BEFORE reading any mutable current source."""
        _header(owner_id, job_id, idempotency_key)
        _document(request_json, 16384)
        with self._transaction() as tx:
            return self._lookup(tx, owner_id, job_id, idempotency_key, request_json)

    def admit(
        self,
        *,
        owner_id: str,
        job_id: str,
        idempotency_key: str,
        request_json: bytes,
        binding_json: bytes,
        snapshot_json: bytes,
    ) -> tuple[dict[str, Any], bool]:
        _header(owner_id, job_id, idempotency_key)
        request_text = _document(request_json, 16384)
        binding_text = _document(binding_json, 4096)
        snapshot_text = _document(snapshot_json, 262144)
        with self._transaction() as tx:
            winner = self._lookup(tx, owner_id, job_id, idempotency_key, request_json)
            if winner is not None:
                return winner, False
            _require(self._retained_count(tx) < 256, "RETENTION_FULL")
            _require(len(self._states(tx, status="QUEUED", limit=16)) < 16, "QUEUE_FULL")
            _require(
                len(self._states(tx, status="QUEUED", owner=owner_id, limit=4)) < 4,
                "OWNER_QUEUE_FULL",
            )
            identifier = self._identity(owner_id, idempotency_key)
            record = dict(
                id=identifier,
                owner_id=owner_id,
                job_id=job_id,
                request_json=request_text,
                binding_json=binding_text,
                snapshot_json=snapshot_text,
            )
            record["commitment"] = hashlib.sha256(_encode(record).encode()).hexdigest()
            state = dict(
                id=identifier,
                owner_id=owner_id,
                job_id=job_id,
                status="QUEUED",
                revision=0,
                created_at=self._now(),
                slot="FREE",
                generation=0,
                lease_token=None,
                worker_id=None,
                commitment=record["commitment"],
                observations_bytes=len(snapshot_json),
                stored_bytes=len(_encode(record).encode()) + 70000,
                step_count=0,
                evidence_count=0,
                budgets={k: 0 for k in BUDGETS},
            )
            self._write(tx, RUN_KIND, identifier, record)
            self._write(tx, STATE_KIND, identifier, state)
            return self._public(state), True

    def get(self, owner_id: str, job_id: str, run_id: str) -> dict[str, Any] | None:
        _header(owner_id, job_id, run_id)
        with self._transaction() as tx:
            state = self._read(tx, STATE_KIND, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            return self._public(state)

    def saved_input(self, owner_id: str, job_id: str, run_id: str) -> dict[str, Any] | None:
        """Private worker/source adapter input, never a public API response."""
        _header(owner_id, job_id, run_id)
        with self._transaction() as tx:
            state = self._read(tx, STATE_KIND, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            record = self._read(tx, RUN_KIND, run_id)
            if record is None:
                raise InvestigationStoreError("STORE_CORRUPT")
            self._verify_record(record, state)
            return {
                "commitment": record["commitment"],
                **{
                    k: record[k].encode() for k in ("request_json", "binding_json", "snapshot_json")
                },
            }

    @staticmethod
    def _verify_record(record: dict[str, Any], state: dict[str, Any]) -> None:
        body = {k: v for k, v in record.items() if k != "commitment"}
        _require(
            hashlib.sha256(_encode(body).encode()).hexdigest() == record.get("commitment")
            and all(
                record.get(k) == state.get(k) for k in ("id", "owner_id", "job_id", "commitment")
            ),
            "STORE_CORRUPT",
        )

    def claim(self, worker_id: str) -> dict[str, Any] | None:
        """Private claim. No expired lease is ever automatically re-executed."""
        _header(worker_id)
        with self._transaction() as tx:
            self._reconcile(tx)
            held = self._states(tx, slot="HELD", limit=2)
            if len(held) >= 2:
                return None
            owners = {r["owner_id"] for r in held}
            queued = self._states(tx, status="QUEUED", limit=16)
            for state in sorted(queued, key=lambda r: (r["created_at"], r["id"])):
                if state["owner_id"] in owners:
                    continue
                now = self._now()
                reason = self._queue_time_reason(state, now)
                if reason is not None:
                    state.update(status="FAILED", reason=reason)
                    self._save_state(tx, state)
                    continue
                original = dict(state)
                state.update(
                    status="PREPARING",
                    slot="HELD",
                    worker_id=worker_id,
                    lease_token=secrets.token_urlsafe(32),
                    generation=1,
                    deadline=now + 300,
                    lease_expires_at=now + 30,
                )
                self._save_state(tx, state, queued=original)
                if state["status"] == "PREPARING":
                    return state
            return None

    @staticmethod
    def _queue_time_reason(state: dict[str, Any], now: float) -> str | None:
        if now < max(state["created_at"], state.get("last_seen_at", state["created_at"])):
            return "CLOCK_ROLLBACK"
        if now >= state["created_at"] + 60:
            return "QUEUE_EXPIRED"
        return None

    def _save_state(
        self,
        tx: Any,
        state: dict[str, Any],
        *,
        claim: dict[str, Any] | None = None,
        queued: dict[str, Any] | None = None,
    ) -> None:
        if claim is not None:
            self._fenced(tx, claim)
        now = self._now()
        if queued is not None:
            # Keep the original queued bounds until the final timestamp/write.
            # A rejected candidate must never persist tentative worker custody.
            reason = self._queue_time_reason(queued, now)
            if reason is not None:
                state.clear()
                state.update(queued, status="FAILED", reason=reason)
        state["revision"] += 1
        state["last_seen_at"] = now
        self._write(tx, STATE_KIND, state["id"], state)

    def _owned(self, tx: Any, claim: dict[str, Any]) -> dict[str, Any]:
        _require(type(claim) is dict, "STALE_CLAIM")
        _header(claim.get("id"), claim.get("owner_id"), claim.get("job_id"))
        state = self._read(
            tx, STATE_KIND, claim["id"], owner=claim["owner_id"], job=claim["job_id"]
        )
        _require(
            state is not None
            and state["slot"] == "HELD"
            and all(
                state.get(k) == claim.get(k)
                for k in ("owner_id", "job_id", "worker_id", "generation", "lease_token")
            )
            and type(claim.get("lease_token")) is str,
            "STALE_CLAIM",
        )
        if state is None:
            raise InvestigationStoreError("STALE_CLAIM")
        return state

    def _fenced(self, tx: Any, claim: dict[str, Any]) -> dict[str, Any]:
        state = self._owned(tx, claim)
        now = self._now()
        _require(
            state["status"] not in TERMINAL
            and state["revision"] == claim.get("revision")
            and state["last_seen_at"] <= now < state["deadline"]
            and now < state["lease_expires_at"],
            "STALE_CLAIM",
        )
        return state

    def heartbeat(self, claim: dict[str, Any]) -> dict[str, Any]:
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            state["lease_expires_at"] = min(self._now() + 30, state["deadline"])
            self._save_state(tx, state, claim=claim)
            return state

    def transition(self, claim: dict[str, Any], status: str) -> dict[str, Any]:
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            _require(
                (state["status"], status)
                in {("PREPARING", "INVESTIGATING"), ("INVESTIGATING", "VALIDATING")},
                "INVALID_TRANSITION",
            )
            state["status"] = status
            self._save_state(tx, state, claim=claim)
            return state

    def publish(self, claim: dict[str, Any], status: str, result_json: bytes) -> dict[str, Any]:
        result = _document(result_json, 16384)
        _require(status in {"COMPLETED", "PARTIAL", "FAILED"}, "INVALID_TRANSITION")
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            _require(status == "FAILED" or state["status"] == "VALIDATING", "INVALID_TRANSITION")
            state.update(status=status, result=json.loads(result))
            self._save_state(tx, state, claim=claim)
            return self._public(state)

    def worker_exited(self, claim: dict[str, Any]) -> bool:
        """Supervisor attests actual exit; never call on cancellation acknowledgement."""
        with self._transaction() as tx:
            state = self._owned(tx, claim)
            if state["status"] not in TERMINAL:
                state.update(status="FAILED", reason="WORKER_EXITED")
                state["revision"] += 1
            state["slot"] = "FREE"
            self._write(tx, STATE_KIND, state["id"], state)
            return True

    def cancel(self, owner_id: str, job_id: str, run_id: str) -> dict[str, Any] | None:
        _header(owner_id, job_id, run_id)
        with self._transaction() as tx:
            state = self._read(tx, STATE_KIND, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            if state["status"] not in TERMINAL:
                state.update(status="CANCELLED", reason="USER_CANCELLED")
                self._save_state(tx, state)
            return self._public(state)

    def _reconcile(self, tx: Any) -> int:
        now = self._now()
        changed = 0
        for state in self._states(tx, status="QUEUED", limit=16) + self._states(
            tx, slot="HELD", limit=2
        ):
            if state["status"] in TERMINAL:
                continue
            reason = None
            if now < state.get("last_seen_at", state["created_at"]):
                reason = "CLOCK_ROLLBACK"
            elif state["status"] == "QUEUED" and now >= state["created_at"] + 60:
                reason = "QUEUE_EXPIRED"
            elif state["slot"] == "HELD":
                if now >= state["deadline"]:
                    reason = "DEADLINE_EXCEEDED"
                elif now >= state["lease_expires_at"]:
                    reason = "OWNER_LOST"
            if reason is not None:
                state.update(status="FAILED", reason=reason)
                self._save_state(tx, state)
                changed += 1
        return changed

    def reconcile(self) -> int:
        """At most 16 queued + 2 held rows. Unknown owners KEEP their slots."""
        with self._transaction() as tx:
            return self._reconcile(tx)

    def reserve(self, claim: dict[str, Any], **increments: int) -> dict[str, Any]:
        """Persist BEFORE work. Failed/ambiguous external calls never refund budget."""
        _require(
            bool(increments)
            and set(increments) <= BUDGETS.keys()
            and all(type(v) is int and v > 0 for v in increments.values()),
            "INVALID_BUDGET",
        )
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            counts = dict(state["budgets"])
            for key, value in increments.items():
                counts[key] += value
                _require(counts[key] <= BUDGETS[key], "BUDGET_EXHAUSTED")
            state["budgets"] = counts
            self._save_state(tx, state, claim=claim)
            return state

    def _child(self, state: dict[str, Any], text: str) -> dict[str, Any]:
        return dict(
            run_id=state["id"],
            owner_id=state["owner_id"],
            job_id=state["job_id"],
            commitment=state["commitment"],
            body=text,
            sha256=hashlib.sha256(text.encode()).hexdigest(),
        )

    def _add_child(
        self,
        tx: Any,
        state: dict[str, Any],
        kind: str,
        identifier: str,
        child: dict[str, Any],
        claim: dict[str, Any],
    ) -> None:
        state["stored_bytes"] += len(_encode(child).encode())
        _require(state["stored_bytes"] <= 1048576, "STORAGE_LIMIT")
        self._write(tx, kind, identifier, child)
        self._save_state(tx, state, claim=claim)

    def append_step(self, claim: dict[str, Any], step_json: bytes) -> dict[str, Any]:
        text = _document(step_json, 8192)
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            _require(state["step_count"] < 24, "STEP_LIMIT")
            state["step_count"] += 1
            self._add_child(
                tx,
                state,
                STEP_KIND,
                f"{state['id']}:{state['step_count']:02d}",
                self._child(state, text),
                claim,
            )
            return state

    def save_evidence(
        self, claim: dict[str, Any], evidence_id: str, evidence_json: bytes
    ) -> dict[str, Any]:
        _header(evidence_id)
        text = _document(evidence_json, 32768)
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            identifier = f"{state['id']}:{evidence_id}"
            _require(self._read(tx, EVIDENCE_KIND, identifier) is None, "EVIDENCE_EXISTS")
            _require(state["evidence_count"] < 12, "EVIDENCE_LIMIT")
            state["observations_bytes"] += len(evidence_json)
            _require(state["observations_bytes"] <= 262144, "OBSERVATION_LIMIT")
            state["evidence_count"] += 1
            self._add_child(tx, state, EVIDENCE_KIND, identifier, self._child(state, text), claim)
            return state

    def _child_body(self, state: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
        _require(
            all(child[k] == state[k] for k in ("owner_id", "job_id", "commitment"))
            and child["run_id"] == state["id"]
            and hashlib.sha256(child["body"].encode()).hexdigest() == child["sha256"],
            "STORE_CORRUPT",
        )
        return dict(json.loads(child["body"]))

    def evidence(
        self, owner_id: str, job_id: str, run_id: str, evidence_id: str
    ) -> dict[str, Any] | None:
        _header(owner_id, job_id, run_id, evidence_id)
        with self._transaction() as tx:
            state = self._read(tx, STATE_KIND, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            child = self._read(tx, EVIDENCE_KIND, f"{run_id}:{evidence_id}")
            return self._child_body(state, child) if child else None

    def steps(
        self, owner_id: str, job_id: str, run_id: str, *, after: int = 0, limit: int = 20
    ) -> list[dict[str, Any]]:
        _header(owner_id, job_id, run_id)
        _require(
            type(after) is int and 0 <= after <= 24 and type(limit) is int and 1 <= limit <= 20,
            "INVALID_PAGE",
        )
        with self._transaction() as tx:
            state = self._read(tx, STATE_KIND, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return []
            result = []
            for sequence in range(after + 1, min(state["step_count"], after + limit) + 1):
                child = self._read(tx, STEP_KIND, f"{run_id}:{sequence:02d}")
                if child is None:
                    raise InvestigationStoreError("STORE_CORRUPT")
                result.append({"sequence": sequence, "body": self._child_body(state, child)})
            return result
