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


@dataclass(frozen=True)
class _KindProfile:
    run: str
    state: str
    step: str
    evidence: str
    marker: str
    index_prefix: str

    def index_field(self, key: str) -> str:
        return key if self is _IP_PROFILE else f"{self.state}:{key}"

    def budget_limit(self, key: str) -> int:
        # JOB reserves 8 MiB flows + 256 KiB metadata, not measured source bytes.
        if self is _JOB_PROFILE:
            if key == "planning_responses":
                return 4
            if key == "source_bytes":
                return 8650752
            if key == "source_records":
                return 8192
        return BUDGETS[key]


_IP_PROFILE = _KindProfile(
    RUN_KIND, STATE_KIND, STEP_KIND, EVIDENCE_KIND, "ai_investigation_schema", "investigation"
)
_JOB_PROFILE = _KindProfile(
    "ai_job_investigation_run_v1",
    "ai_job_investigation_state_v1",
    "ai_job_investigation_step_v1",
    "ai_job_investigation_evidence_v1",
    "ai_job_investigation_schema",
    "job_investigation",
)


def _sealed_profile(profile: _KindProfile) -> None:
    _require(profile is _IP_PROFILE or profile is _JOB_PROFILE, "INVALID_PROFILE")


@dataclass
class _MemoryRows:
    rows: dict[tuple[str, str], str] = field(default_factory=dict)
    index: dict[tuple[str, str], set[str]] = field(default_factory=dict)
    initialized: set[str] = field(default_factory=set)


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
def _sql_transaction(
    repository: Any, postgres: bool, fence: Callable[[], None] | None = None
) -> Iterator[Any]:
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
            if fence is not None:
                fence()
            commit_started = True
            connection.commit()
            # A late return may follow a successful COMMIT. Do not acknowledge it
            # or claim the following rollback can erase the durable publication.
            if fence is not None:
                fence()
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
    _initialize_profile(repository, _IP_PROFILE)


def _initialize_profile(repository: Any, profile: _KindProfile) -> None:
    _sealed_profile(profile)
    backend = _backend(repository)
    if backend == "memory":
        with repository._lock, _MEMORY_LOCK:
            _MEMORY.setdefault(repository, _MemoryRows()).initialized.add(profile.marker)
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
                f"CREATE INDEX IF NOT EXISTS {profile.index_prefix}_{name}_v1 ON objects "
                f"(kind,{expressions},id) WHERE kind='{profile.state}'",
                (),
                postgres,
            )
        _execute(
            tx,
            "INSERT INTO objects(kind,id,data) VALUES(?,?,?) ON CONFLICT DO NOTHING",
            (profile.marker, "v1", "{}"),
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
    def __init__(
        self,
        repository: Any,
        *,
        clock: Callable[[], float] = time.time,
        _profile: _KindProfile = _IP_PROFILE,
    ) -> None:
        _sealed_profile(_profile)
        self.__profile = _profile
        backend = _backend(repository)
        self.repository = repository
        self.clock = clock
        self._memory = backend == "memory"
        self._postgres = backend == "postgres"
        if self._memory:
            with _MEMORY_LOCK:
                _require(
                    repository in _MEMORY and _profile.marker in _MEMORY[repository].initialized,
                    "STORE_NOT_INITIALIZED",
                )
        else:
            with _sql_transaction(repository, self._postgres) as tx:
                _require(
                    _execute(
                        tx,
                        "SELECT 1 FROM objects WHERE kind=? AND id=?",
                        (_profile.marker, "v1"),
                        self._postgres,
                    ).fetchone()
                    is not None,
                    "STORE_NOT_INITIALIZED",
                )

    @property
    def _profile(self) -> _KindProfile:
        return self.__profile

    @contextmanager
    def _transaction(self, fence: Callable[[], None] | None = None) -> Iterator[Any]:
        with self.repository._lock:
            if self._memory:
                current = _MEMORY[self.repository]
                pending = _MemoryRows(
                    dict(current.rows),
                    {k: set(v) for k, v in current.index.items()},
                    set(current.initialized),
                )
                yield pending
                if fence is not None:
                    fence()
                _MEMORY[self.repository] = pending
            else:
                with _sql_transaction(self.repository, self._postgres, fence) as tx:
                    yield tx

    def _now(self) -> float:
        now = self.clock()
        _require(type(now) in (float, int) and math.isfinite(now) and now >= 0, "INVALID_CLOCK")
        return float(now)

    def _retained_count(self, tx: Any) -> int:
        if self._memory:
            return sum(
                len(tx.index.get(("kind", profile.run), set()))
                for profile in (_IP_PROFILE, _JOB_PROFILE)
            )
        row = _execute(
            tx,
            "SELECT COUNT(*) FROM objects WHERE kind IN (?,?)",
            (_IP_PROFILE.run, _JOB_PROFILE.run),
            self._postgres,
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
            if kind == self._profile.state and any(
                identifier not in tx.index.get((self._profile.index_field(k), v), set())
                for k, v in filters.items()
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
        _require(
            len(text.encode()) <= (600000 if kind == self._profile.run else 70000), "STORAGE_LIMIT"
        )
        if self._memory:
            previous = tx.rows.get((kind, identifier))
            if kind == self._profile.state:
                old = json.loads(previous) if previous is not None else None
                for key in ("owner_id", "job_id", "status", "slot"):
                    if old is not None:
                        tx.index[self._profile.index_field(key), old[key]].discard(identifier)
                    tx.index.setdefault((self._profile.index_field(key), value[key]), set()).add(
                        identifier
                    )
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
        _profile: _KindProfile | None = None,
    ) -> list[dict[str, Any]]:
        profile = self._profile if _profile is None else _profile
        _sealed_profile(profile)
        filters = {
            k: v
            for k, v in (("owner_id", owner), ("job_id", job), ("status", status), ("slot", slot))
            if v is not None
        }
        if self._memory:
            identifiers = set(tx.index.get(("kind", profile.state), set()))
            for key, value in filters.items():
                identifiers.intersection_update(
                    tx.index.get((profile.index_field(key), value), set())
                )
            return [
                json.loads(tx.rows[profile.state, identifier])
                for identifier in sorted(i for i in identifiers if i > after)[:limit]
            ]
        predicates = "".join(f" AND {_expression(k, self._postgres)}=?" for k in filters)
        rows = _execute(
            tx,
            # Only fixed field expressions are interpolated; values/limit are parameters.
            "SELECT data FROM objects WHERE kind=? AND id>?" + predicates + " ORDER BY id LIMIT ?",  # noqa: S608
            (profile.state, after, *filters.values(), limit),
            self._postgres,
        ).fetchall()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def _capacity_states(
        self,
        tx: Any,
        *,
        owner: str | None = None,
        status: str | None = None,
        slot: str | None = None,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Bounded aggregate under the SAME lock/transaction as the mutation.

        New-capable IP/JOB stores cooperate; old-version fleet capacity is NOT
        supported. Claim, reconciliation and public reads stay profile-local.
        """
        result: list[dict[str, Any]] = []
        for profile in (_IP_PROFILE, _JOB_PROFILE):
            remaining = limit - len(result)
            if remaining <= 0:
                break
            result.extend(
                self._states(
                    tx, owner=owner, status=status, slot=slot, limit=remaining, _profile=profile
                )
            )
        return result

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
                self._public_state(r)
                for r in self._states(tx, owner=owner_id, job=job_id, after=after, limit=limit)
            ]

    def _run_identity(self, owner_id: str, idempotency_key: str) -> str:
        if self._profile is _IP_PROFILE:
            return self._identity(owner_id, idempotency_key)
        return hashlib.sha256(
            _encode([_JOB_PROFILE.run, owner_id, idempotency_key]).encode()
        ).hexdigest()

    def _public_state(self, state: dict[str, Any]) -> dict[str, Any]:
        if self._profile is _IP_PROFILE:
            return self._public(state)
        budgets = state.get("budgets")
        if type(budgets) is not dict:
            raise InvestigationStoreError("STORE_CORRUPT")
        _require(budgets.keys() == BUDGETS.keys() | {"planning_responses"}, "STORE_CORRUPT")
        _require(
            all(
                type(v) is int and 0 <= v <= self._profile.budget_limit(k)
                for k, v in budgets.items()
            ),
            "STORE_CORRUPT",
        )
        public = self._public({**state, "budgets": {k: budgets[k] for k in BUDGETS}})
        public["progress"]["planning_responses"] = budgets["planning_responses"]
        _require("selected_peer_ids" in state, "STORE_CORRUPT")
        peers = state["selected_peer_ids"]
        _require(
            peers is None
            or (
                type(peers) is list
                and 1 <= len(peers) <= 3
                and all(
                    type(peer) is str
                    and len(peer) == 64
                    and all(c in "0123456789abcdef" for c in peer)
                    for peer in peers
                )
                and len(set(peers)) == len(peers)
            ),
            "STORE_CORRUPT",
        )
        public["selection"] = {
            "state": "PENDING" if peers is None else "COMMITTED",
            "peer_ids": [] if peers is None else list(peers),
        }
        return public

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
        identifier = self._run_identity(owner, key)
        record = self._read(tx, self._profile.run, identifier, owner=owner)
        if record is None:
            return None
        _require(
            record["job_id"] == job and record["request_json"] == request.decode(),
            "IDEMPOTENCY_CONFLICT",
        )
        state = self._read(tx, self._profile.state, identifier)
        if state is None:
            raise InvestigationStoreError("STORE_CORRUPT")
        self._verify_record(record, state)
        return self._public_state(state)

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
        snapshot_text = _document(
            snapshot_json, 131072 if self._profile is _JOB_PROFILE else 262144
        )
        with self._transaction() as tx:
            winner = self._lookup(tx, owner_id, job_id, idempotency_key, request_json)
            if winner is not None:
                return winner, False
            _require(self._retained_count(tx) < 256, "RETENTION_FULL")
            _require(len(self._capacity_states(tx, status="QUEUED", limit=16)) < 16, "QUEUE_FULL")
            _require(
                len(self._capacity_states(tx, status="QUEUED", owner=owner_id, limit=4)) < 4,
                "OWNER_QUEUE_FULL",
            )
            identifier = self._run_identity(owner_id, idempotency_key)
            record = dict(
                id=identifier,
                owner_id=owner_id,
                job_id=job_id,
                request_json=request_text,
                binding_json=binding_text,
                snapshot_json=snapshot_text,
            )
            record["commitment"] = hashlib.sha256(_encode(record).encode()).hexdigest()
            state: dict[str, Any] = dict(
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
            if self._profile is _JOB_PROFILE:
                state.update(selected_peer_ids=None, selection_reserved=False, evidence_bytes=0)
                state["budgets"]["planning_responses"] = 0
            self._write(tx, self._profile.run, identifier, record)
            self._write(tx, self._profile.state, identifier, state)
            return self._public_state(state), True

    def get(self, owner_id: str, job_id: str, run_id: str) -> dict[str, Any] | None:
        _header(owner_id, job_id, run_id)
        with self._transaction() as tx:
            state = self._read(tx, self._profile.state, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            return self._public_state(state)

    def saved_input(self, owner_id: str, job_id: str, run_id: str) -> dict[str, Any] | None:
        """Private worker/source adapter input, never a public API response."""
        _header(owner_id, job_id, run_id)
        with self._transaction() as tx:
            state = self._read(tx, self._profile.state, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            record = self._read(tx, self._profile.run, run_id)
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
            held = self._capacity_states(tx, slot="HELD", limit=2)
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
        self._write(tx, self._profile.state, state["id"], state)

    def _owned(self, tx: Any, claim: dict[str, Any]) -> dict[str, Any]:
        _require(type(claim) is dict, "STALE_CLAIM")
        _header(claim.get("id"), claim.get("owner_id"), claim.get("job_id"))
        state = self._read(
            tx, self._profile.state, claim["id"], owner=claim["owner_id"], job=claim["job_id"]
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

    def _publication_fence(self, claim: dict[str, Any], deadline_monotonic: float | None) -> None:
        now = self._now()
        _require(
            claim["last_seen_at"] <= now < min(claim["deadline"], claim["lease_expires_at"])
            and (deadline_monotonic is None or time.monotonic() < deadline_monotonic),
            "STALE_CLAIM",
        )

    def publish(
        self,
        claim: dict[str, Any],
        status: str,
        result_json: bytes,
        *,
        deadline_monotonic: float | None = None,
    ) -> dict[str, Any]:
        result = _document(result_json, 16384)
        _require(status in {"COMPLETED", "PARTIAL", "FAILED"}, "INVALID_TRANSITION")
        fence = (
            (lambda: self._publication_fence(claim, deadline_monotonic))
            if self._profile is _JOB_PROFILE
            else None
        )
        with self._transaction(fence) as tx:
            state = self._fenced(tx, claim)
            _require(status == "FAILED" or state["status"] == "VALIDATING", "INVALID_TRANSITION")
            state.update(status=status, result=json.loads(result))
            self._save_state(tx, state, claim=claim)
            return self._public_state(state)

    def worker_exited(self, claim: dict[str, Any]) -> bool:
        """Supervisor attests actual exit; never call on cancellation acknowledgement."""
        with self._transaction() as tx:
            state = self._owned(tx, claim)
            if state["status"] not in TERMINAL:
                state.update(status="FAILED", reason="WORKER_EXITED")
                state["revision"] += 1
            state["slot"] = "FREE"
            self._write(tx, self._profile.state, state["id"], state)
            return True

    def cancel(self, owner_id: str, job_id: str, run_id: str) -> dict[str, Any] | None:
        _header(owner_id, job_id, run_id)
        with self._transaction() as tx:
            state = self._read(tx, self._profile.state, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            if state["status"] not in TERMINAL:
                state.update(status="CANCELLED", reason="USER_CANCELLED")
                self._save_state(tx, state)
            return self._public_state(state)

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
        return self._reserve(claim, increments)

    def reserve_selection(self, claim: dict[str, Any]) -> dict[str, Any]:
        """JOB broker MUST call before deciding membership, including bad attempts.

        This is the same lifetime tool meter as seeds and later retrieval. Even
        reselection attempts are charged. A failed validation never refunds it.
        """
        _require(self._profile is _JOB_PROFILE, "INVALID_PROFILE")
        return self._reserve(claim, {"tool_calls": 1}, selection=True)

    def _reserve(
        self, claim: dict[str, Any], increments: dict[str, int], *, selection: bool = False
    ) -> dict[str, Any]:
        _require(
            bool(increments)
            and set(increments)
            <= (
                BUDGETS.keys()
                | ({"planning_responses"} if self._profile is _JOB_PROFILE else set())
            )
            and all(type(v) is int and v > 0 for v in increments.values()),
            "INVALID_BUDGET",
        )
        with self._transaction() as tx:
            state = self._fenced(tx, claim)
            counts = dict(state["budgets"])
            for key, value in increments.items():
                counts[key] += value
                _require(counts[key] <= self._profile.budget_limit(key), "BUDGET_EXHAUSTED")
            state["budgets"] = counts
            if selection:
                state["selection_reserved"] = True
            self._save_state(tx, state, claim=claim)
            return state

    def commit_selection(
        self,
        claim: dict[str, Any],
        *,
        selected_peer_ids: tuple[str, ...],
        commitment: str,
        deadline_monotonic: float | None = None,
    ) -> dict[str, Any]:
        """Persist one JOB selection before seeds; return only after commit.

        The broker first reserves a selection attempt, then validates pool
        membership/source/execution semantics using the saved canonical input.
        This seam validates only scalar IDs, cardinality and immutable byte
        custody, NOT model semantics. The commitment binds ALL admitted bytes.
        Unknown storage outcome raises/quarantines; it is never an acceptance.
        """
        _require(self._profile is _JOB_PROFILE, "INVALID_PROFILE")
        _require(
            type(selected_peer_ids) is tuple
            and 1 <= len(selected_peer_ids) <= 3
            and all(
                type(peer) is str and len(peer) == 64 and all(c in "0123456789abcdef" for c in peer)
                for peer in selected_peer_ids
            )
            and len(set(selected_peer_ids)) == len(selected_peer_ids),
            "INVALID_SELECTION",
        )
        with self._transaction(lambda: self._publication_fence(claim, deadline_monotonic)) as tx:
            state = self._fenced(tx, claim)
            _require(state["selected_peer_ids"] is None, "INVALID_SELECTION_STATE")
            _require(state["selection_reserved"] is True, "SELECTION_NOT_RESERVED")
            _require(
                type(commitment) is str and commitment == state["commitment"],
                "COMMITMENT_MISMATCH",
            )
            record = self._read(tx, self._profile.run, state["id"])
            _require(record is not None, "STORE_CORRUPT")
            if record is None:
                raise InvestigationStoreError("STORE_CORRUPT")
            self._verify_record(record, state)
            state.update(selected_peer_ids=list(selected_peer_ids), selection_reserved=False)
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
                self._profile.step,
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
            if self._profile is _JOB_PROFILE:
                _require(state["selected_peer_ids"] is not None, "SELECTION_REQUIRED")
            identifier = f"{state['id']}:{evidence_id}"
            _require(self._read(tx, self._profile.evidence, identifier) is None, "EVIDENCE_EXISTS")
            _require(state["evidence_count"] < 12, "EVIDENCE_LIMIT")
            if self._profile is _JOB_PROFILE:
                state["evidence_bytes"] += len(evidence_json)
                _require(state["evidence_bytes"] <= 131072, "EVIDENCE_BYTES_LIMIT")
            state["observations_bytes"] += len(evidence_json)
            _require(state["observations_bytes"] <= 262144, "OBSERVATION_LIMIT")
            state["evidence_count"] += 1
            self._add_child(
                tx, state, self._profile.evidence, identifier, self._child(state, text), claim
            )
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
            state = self._read(tx, self._profile.state, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return None
            child = self._read(tx, self._profile.evidence, f"{run_id}:{evidence_id}")
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
            state = self._read(tx, self._profile.state, run_id, owner=owner_id, job=job_id)
            if state is None or (state["owner_id"], state["job_id"]) != (owner_id, job_id):
                return []
            result = []
            for sequence in range(after + 1, min(state["step_count"], after + limit) + 1):
                child = self._read(tx, self._profile.step, f"{run_id}:{sequence:02d}")
                if child is None:
                    raise InvestigationStoreError("STORE_CORRUPT")
                result.append({"sequence": sequence, "body": self._child_body(state, child)})
            return result
