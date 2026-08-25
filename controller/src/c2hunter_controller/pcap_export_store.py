from __future__ import annotations

import json
import secrets
import sqlite3
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from typing import Any

ACTIVE_EXPORT_STATES = frozenset({"QUEUED", "RUNNING"})
TERMINAL_EXPORT_STATES = frozenset({"COMPLETED", "FAILED", "CANCELLED"})
_PROGRESS_COUNTERS = (
    "percent",
    "scanned_source_bytes",
    "scanned_packet_count",
    "matched_packet_count",
    "exported_packet_count",
)


class ExportQueueStorageError(RuntimeError):
    pass


class ExportQueueFullError(RuntimeError):
    pass


class ExportPrincipalLimitError(RuntimeError):
    pass


class ExportSourceChangedError(RuntimeError):
    pass


class RepositoryQueueStore:
    """Durable PCAP-export queue facade.

    Memory and SQLite are first-class implementations used by local deployments and
    contract tests. PostgreSQL is implemented by repository methods with the same
    names, keeping this queue separate from controller/AI queue transports.
    """

    def __init__(self, repository: Any) -> None:
        self.repository = repository

    @staticmethod
    def _now(value: datetime | None = None) -> datetime:
        return value or datetime.now(UTC)

    @staticmethod
    def _iso(value: datetime) -> str:
        return value.astimezone(UTC).isoformat()

    def _memory(self) -> dict[str, dict[str, Any]] | None:
        return getattr(self.repository, "pcap_export_jobs", None)

    def _load_all_locked(self) -> list[dict[str, Any]]:
        memory = self._memory()
        if memory is not None:
            return [deepcopy(item) for item in memory.values()]
        rows = self.repository.connection.execute("SELECT data FROM pcap_export_jobs").fetchall()
        return [json.loads(row[0]) for row in rows]

    def _save_locked(self, job: dict[str, Any]) -> None:
        memory = self._memory()
        if memory is not None:
            memory[str(job["id"])] = deepcopy(job)
            return
        self.repository.connection.execute(
            """INSERT INTO pcap_export_jobs(
                 export_id,principal_scope,idempotency_key,request_fingerprint,
                 coalesce_fingerprint,status,next_attempt_at,queued_at,lease_expires_at,data
               ) VALUES(?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(export_id) DO UPDATE SET
                 status=excluded.status,next_attempt_at=excluded.next_attempt_at,
                 lease_expires_at=excluded.lease_expires_at,data=excluded.data""",
            (
                job["id"],
                job["principal_scope"],
                job.get("idempotency_key"),
                job["request_fingerprint"],
                job["coalesce_fingerprint"],
                job["status"],
                job.get("next_attempt_at"),
                job["queued_at"],
                job.get("lease_expires_at"),
                json.dumps(job, separators=(",", ":"), default=str),
            ),
        )

    def enqueue(
        self, job: dict[str, Any], *, capacity: int, per_principal_limit: int
    ) -> tuple[dict[str, Any], bool]:
        """Atomically replay/coalesce before applying active capacity limits."""
        with self.repository._lock:
            sqlite = self._memory() is None
            if sqlite:
                self.repository.connection.execute("BEGIN IMMEDIATE")
            try:
                existing = self._load_all_locked()
                key = job.get("idempotency_key")
                if key is not None:
                    keyed = next(
                        (
                            item
                            for item in existing
                            if item["principal_scope"] == job["principal_scope"]
                            and item.get("idempotency_key") == key
                        ),
                        None,
                    )
                    if keyed is not None:
                        if keyed["request_fingerprint"] != job["request_fingerprint"]:
                            raise ValueError("idempotency_conflict")
                        if sqlite:
                            self.repository.connection.commit()
                        return keyed, False
                reusable = next(
                    (
                        item
                        for item in existing
                        if item["principal_scope"] == job["principal_scope"]
                        and item["coalesce_fingerprint"] == job["coalesce_fingerprint"]
                        and item["status"] in {"QUEUED", "RUNNING", "COMPLETED"}
                    ),
                    None,
                )
                if reusable is not None:
                    if sqlite:
                        self.repository.connection.commit()
                    return reusable, False
                active = [item for item in existing if item["status"] in ACTIVE_EXPORT_STATES]
                if len(active) >= capacity:
                    raise ExportQueueFullError("pcap export queue is full")
                principal_active = sum(
                    item["principal_scope"] == job["principal_scope"] for item in active
                )
                if principal_active >= per_principal_limit:
                    raise ExportPrincipalLimitError("principal PCAP export limit reached")
                validate_source = getattr(self.repository, "validate_pcap_export_admission", None)
                if validate_source is not None and not validate_source(job):
                    raise ExportSourceChangedError("PCAP export source changed before admission")
                self._save_locked(job)
                if sqlite:
                    self.repository.connection.commit()
                return deepcopy(job), True
            except Exception:
                if sqlite:
                    self.repository.connection.rollback()
                raise

    def get(self, export_id: str) -> dict[str, Any] | None:
        with self.repository._lock:
            memory = self._memory()
            if memory is not None:
                value = memory.get(export_id)
                return deepcopy(value) if value is not None else None
            try:
                row = self.repository.connection.execute(
                    "SELECT data FROM pcap_export_jobs WHERE export_id=?", (export_id,)
                ).fetchone()
            except sqlite3.Error as exc:
                raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc
            return json.loads(row[0]) if row else None

    def claim(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> dict[str, Any] | None:
        now = self._now(now)
        with self.repository._lock:
            sqlite = self._memory() is None
            if sqlite:
                self.repository.connection.execute("BEGIN IMMEDIATE")
            try:
                jobs = sorted(
                    self._load_all_locked(), key=lambda item: (item["queued_at"], item["id"])
                )
                job = next(
                    (
                        item
                        for item in jobs
                        if item["status"] == "QUEUED"
                        and (
                            not item.get("next_attempt_at")
                            or datetime.fromisoformat(item["next_attempt_at"]) <= now
                        )
                    ),
                    None,
                )
                if job is None:
                    if sqlite:
                        self.repository.connection.commit()
                    return None
                job.update(
                    status="RUNNING",
                    attempt=int(job.get("attempt", 0)) + 1,
                    lease_token=secrets.token_urlsafe(32),
                    lease_expires_at=self._iso(now + timedelta(seconds=lease_seconds)),
                    started_at=job.get("started_at") or self._iso(now),
                    updated_at=self._iso(now),
                )
                job["progress"] = {**job.get("progress", {}), "phase": "SNAPSHOT_VALIDATION"}
                self._save_locked(job)
                if sqlite:
                    self.repository.connection.commit()
                return deepcopy(job)
            except Exception:
                if sqlite:
                    self.repository.connection.rollback()
                raise

    @staticmethod
    def _owns(job: dict[str, Any], *, attempt: int, lease_token: str) -> bool:
        return (
            job.get("status") == "RUNNING"
            and int(job.get("attempt", 0)) == attempt
            and secrets.compare_digest(str(job.get("lease_token", "")), lease_token)
        )

    def _guarded_update(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        mutate: Any,
    ) -> bool:
        with self.repository._lock:
            sqlite = self._memory() is None
            if sqlite:
                self.repository.connection.execute("BEGIN IMMEDIATE")
            try:
                job = next((x for x in self._load_all_locked() if x["id"] == export_id), None)
                if job is None or not self._owns(job, attempt=attempt, lease_token=lease_token):
                    if sqlite:
                        self.repository.connection.commit()
                    return False
                if not mutate(job):
                    if sqlite:
                        self.repository.connection.commit()
                    return False
                job["updated_at"] = self._iso(self._now())
                self._save_locked(job)
                if sqlite:
                    self.repository.connection.commit()
                return True
            except Exception:
                if sqlite:
                    self.repository.connection.rollback()
                raise

    def heartbeat(
        self, export_id: str, *, attempt: int, lease_token: str, lease_seconds: int
    ) -> bool:
        return self._guarded_update(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            mutate=lambda job: (
                job.__setitem__(
                    "lease_expires_at", self._iso(self._now() + timedelta(seconds=lease_seconds))
                )
                or True
            ),
        )

    def progress(
        self, export_id: str, *, attempt: int, lease_token: str, progress: dict[str, Any]
    ) -> bool:
        def mutate(job: dict[str, Any]) -> bool:
            current = dict(job.get("progress", {}))
            for key, value in progress.items():
                if key in _PROGRESS_COUNTERS:
                    current[key] = max(
                        int(current.get(key, 0)),
                        min(99, int(value)) if key == "percent" else int(value),
                    )
                elif key == "phase":
                    current[key] = str(value)
            job["progress"] = current
            return True

        return self._guarded_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )

    def complete(
        self, export_id: str, *, attempt: int, lease_token: str, artifact: dict[str, Any]
    ) -> bool:
        artifact_accepted = False

        def mutate(job: dict[str, Any]) -> bool:
            nonlocal artifact_accepted
            if job.get("cancellation_requested"):
                job.update(
                    status="CANCELLED",
                    completed_at=self._iso(self._now()),
                    lease_token=None,
                    lease_expires_at=None,
                    error_code="PCAP_EXPORT_CANCELLED",
                    error="PCAP export was cancelled",
                )
                return True
            artifact_status = str(artifact.get("status", "COMPLETED"))
            if artifact_status not in {"COMPLETED", "FAILED"}:
                return False
            if artifact_status == "COMPLETED" and artifact.get("published") is False:
                memory = self._memory()
                if memory is not None:
                    stored = self.repository.exports.get(export_id)
                    if (
                        stored is None
                        or stored.get("attempt") != attempt
                        or stored.get("lease_token") != lease_token
                        or stored.get("object_key") != artifact.get("object_key")
                    ):
                        return False
                    stored["published"] = True
                else:
                    row = self.repository.connection.execute(
                        "SELECT data FROM objects WHERE kind='export' AND id=?", (export_id,)
                    ).fetchone()
                    stored = json.loads(row[0]) if row is not None else None
                    if (
                        stored is None
                        or stored.get("attempt") != attempt
                        or stored.get("lease_token") != lease_token
                        or stored.get("object_key") != artifact.get("object_key")
                    ):
                        return False
                    stored["published"] = True
                    self.repository.connection.execute(
                        "UPDATE objects SET data=? WHERE kind='export' AND id=?",
                        (json.dumps(stored, separators=(",", ":"), default=str), export_id),
                    )
                artifact["published"] = True
            job.update(artifact)
            job.update(
                status=artifact_status,
                completed_at=self._iso(self._now()),
                lease_token=None,
                lease_expires_at=None,
            )
            if artifact_status == "COMPLETED":
                job.update(error_code=None, error=None)
            job["progress"] = {
                **job.get("progress", {}),
                "phase": "TERMINAL",
                "percent": (
                    100
                    if artifact_status == "COMPLETED"
                    else min(99, int(job.get("progress", {}).get("percent", 0)))
                ),
            }
            artifact_accepted = True
            return True

        updated = self._guarded_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )
        return updated and artifact_accepted

    def retry_or_fail(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        error: str,
        retry_base_seconds: int = 5,
    ) -> bool:
        def mutate(job: dict[str, Any]) -> bool:
            now = self._now()
            if job.get("cancellation_requested"):
                job.update(
                    status="CANCELLED",
                    error_code="PCAP_EXPORT_CANCELLED",
                    error="PCAP export was cancelled",
                    completed_at=self._iso(now),
                )
            elif transient and attempt < int(job.get("max_attempts", 3)):
                job.update(
                    status="QUEUED",
                    next_attempt_at=self._iso(
                        now + timedelta(seconds=retry_base_seconds * (2 ** (attempt - 1)))
                    ),
                )
            else:
                job.update(
                    status="FAILED",
                    error_code=("PCAP_EXPORT_RETRY_EXHAUSTED" if transient else error_code),
                    error=error,
                    completed_at=self._iso(now),
                )
            job.update(lease_token=None, lease_expires_at=None)
            return True

        return self._guarded_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )

    def cancel(self, export_id: str, *, reason: str | None = None) -> dict[str, Any]:
        with self.repository._lock:
            sqlite = self._memory() is None
            if sqlite:
                self.repository.connection.execute("BEGIN IMMEDIATE")
            try:
                job = next((x for x in self._load_all_locked() if x["id"] == export_id), None)
                if job is None:
                    raise KeyError(export_id)
                if job["status"] in {"COMPLETED", "FAILED"}:
                    if sqlite:
                        self.repository.connection.commit()
                    return job
                if job["status"] == "QUEUED":
                    job.update(
                        status="CANCELLED",
                        cancellation_requested=True,
                        cancellation_requested_at=self._iso(self._now()),
                        cancellation_reason=reason,
                        completed_at=self._iso(self._now()),
                        error_code="PCAP_EXPORT_CANCELLED",
                        error="PCAP export was cancelled",
                    )
                elif job["status"] == "RUNNING":
                    job.update(
                        cancellation_requested=True,
                        cancellation_requested_at=self._iso(self._now()),
                        cancellation_reason=reason,
                    )
                self._save_locked(job)
                if sqlite:
                    self.repository.connection.commit()
                return deepcopy(job)
            except Exception:
                if sqlite:
                    self.repository.connection.rollback()
                raise

    def recover_expired(self, *, now: datetime | None = None) -> int:
        now = self._now(now)
        recovered = 0
        with self.repository._lock:
            sqlite = self._memory() is None
            if sqlite:
                self.repository.connection.execute("BEGIN IMMEDIATE")
            try:
                for job in self._load_all_locked():
                    expiry = job.get("lease_expires_at")
                    if (
                        job["status"] != "RUNNING"
                        or not expiry
                        or datetime.fromisoformat(expiry) > now
                    ):
                        continue
                    if job.get("cancellation_requested"):
                        job.update(
                            status="CANCELLED",
                            completed_at=self._iso(now),
                            error_code="PCAP_EXPORT_CANCELLED",
                            error="PCAP export was cancelled",
                        )
                    elif int(job.get("attempt", 0)) >= int(job.get("max_attempts", 3)):
                        job.update(
                            status="FAILED",
                            completed_at=self._iso(now),
                            error_code="PCAP_EXPORT_RETRY_EXHAUSTED",
                            error="PCAP export retry attempts were exhausted",
                        )
                    else:
                        job.update(status="QUEUED", next_attempt_at=self._iso(now))
                    job.update(lease_token=None, lease_expires_at=None, updated_at=self._iso(now))
                    self._save_locked(job)
                    recovered += 1
                if sqlite:
                    self.repository.connection.commit()
                return recovered
            except Exception:
                if sqlite:
                    self.repository.connection.rollback()
                raise

    def retain_terminal(
        self,
        *,
        now: datetime,
        max_age_seconds: int,
        max_count: int,
        max_artifact_bytes: int,
    ) -> list[str]:
        """Apply age, count, and artifact-byte bounds independently, oldest first."""
        with self.repository._lock:
            sqlite = self._memory() is None
            if sqlite:
                self.repository.connection.execute("BEGIN IMMEDIATE")
            try:
                terminal = [
                    job
                    for job in self._load_all_locked()
                    if job.get("status") in TERMINAL_EXPORT_STATES
                ]
                terminal.sort(
                    key=lambda item: (
                        str(item.get("completed_at") or item.get("updated_at") or ""),
                        str(item["id"]),
                    )
                )
                selected: set[str] = set()
                cutoff = now - timedelta(seconds=max_age_seconds)
                for job in terminal:
                    timestamp = job.get("completed_at") or job.get("updated_at")
                    if timestamp and datetime.fromisoformat(str(timestamp)) < cutoff:
                        selected.add(str(job["id"]))
                survivors = [job for job in terminal if str(job["id"]) not in selected]
                while len(survivors) > max_count:
                    selected.add(str(survivors.pop(0)["id"]))
                retained_bytes = sum(int(job.get("size_bytes", 0) or 0) for job in survivors)
                while survivors and retained_bytes > max_artifact_bytes:
                    removed = survivors.pop(0)
                    retained_bytes -= int(removed.get("size_bytes", 0) or 0)
                    selected.add(str(removed["id"]))
                ordered = [str(job["id"]) for job in terminal if str(job["id"]) in selected]
                memory = self._memory()
                if memory is not None:
                    for export_id in ordered:
                        memory.pop(export_id, None)
                        self.repository.exports.pop(export_id, None)
                        self.repository.export_content.pop(export_id, None)
                elif ordered:
                    export_ids = [(export_id,) for export_id in ordered]
                    self.repository.connection.executemany(
                        "DELETE FROM export_blobs WHERE export_id=?", export_ids
                    )
                    self.repository.connection.executemany(
                        "DELETE FROM objects WHERE kind='export' AND id=?", export_ids
                    )
                    self.repository.connection.executemany(
                        "DELETE FROM pcap_export_jobs WHERE export_id=?", export_ids
                    )
                if sqlite:
                    self.repository.connection.commit()
                return ordered
            except Exception:
                if sqlite:
                    self.repository.connection.rollback()
                raise
