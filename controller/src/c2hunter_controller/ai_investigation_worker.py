"""Owned, bounded polling of the separate durable investigation queue.

Only the executor mutates claim revisions/heartbeats. Cancellation is a request,
not exit proof. An uncertain result retains its durable slot and local quarantine;
no automatic inference replay or acknowledgement is attempted. No borrowed
repository, legacy queue, gateway or peer worker is ever closed here.
"""

from __future__ import annotations

import math
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .ai_investigation import ExecutionOutcome, InvestigationService
from .ai_investigation_store import (
    InvestigationRunStore,
    InvestigationStorageError,
    InvestigationStoreError,
    initialize_investigation_store,
)
from .repositories import MemoryRepository, SQLiteRepository


def configured_service(
    repository: Any, configured_gateway: object, *, bootstrap_local: bool = False
) -> tuple[InvestigationService | None, str | None]:
    """Explicit app startup owns local schema. PostgreSQL needs migrate first."""
    try:
        if bootstrap_local and isinstance(repository, MemoryRepository | SQLiteRepository):
            initialize_investigation_store(repository)
        store = InvestigationRunStore(repository)
    except InvestigationStoreError as exc:
        return None, (
            exc.code
            if exc.code in {"STORE_NOT_INITIALIZED", "UNSUPPORTED_REPOSITORY"}
            else "STORAGE_UNAVAILABLE"
        )
    except InvestigationStorageError:
        return None, "STORAGE_UNAVAILABLE"
    service = InvestigationService.from_configured_gateway(repository, store, configured_gateway)
    return service, "PROVIDER_UNSUPPORTED" if service.gateway is None else None


@dataclass
class _Work:
    claim: dict[str, Any]
    deadline: float
    thread: threading.Thread | None = None
    outcome: ExecutionOutcome | None = None
    cancel_requested: bool = False


class InvestigationSupervisor:
    """Two physical executors, one supervisor, fixed finite polling interval.

    A false close result means ownership is NOT released. A timed-out supervisor
    keeps draining its own workers; callers must retain the borrowed repository.
    Quarantined outcomes require explicit operator reconciliation, not retry.
    """

    def __init__(self, service: InvestigationService, *, poll_seconds: float = 0.25) -> None:
        if not math.isfinite(poll_seconds) or not 0.05 <= poll_seconds <= 1:
            raise ValueError("invalid investigation poll interval")
        self.service = service
        self.poll_seconds = poll_seconds
        self.worker_id = "investigation-" + uuid.uuid4().hex
        self._stop = threading.Event()
        self._external_stop: threading.Event | None = None
        self._lock = threading.RLock()
        self._thread: threading.Thread | None = None
        self._active: list[_Work] = []
        self._quarantined: list[_Work] = []
        self._fault = False

    @property
    def owns_thread(self) -> bool:
        """A constructed supervisor remains owned, even if start raised."""
        with self._lock:
            return self._thread is not None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    @property
    def accepting(self) -> bool:
        with self._lock:
            return self.running and not self._stopping() and not self._fault

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active)

    @property
    def quarantined_count(self) -> int:
        with self._lock:
            return len(self._quarantined)

    def _stopping(self) -> bool:
        return self._stop.is_set() or (
            self._external_stop is not None and self._external_stop.is_set()
        )

    def start(self, stopped: threading.Event | None = None) -> None:
        with self._lock:
            if self._thread is not None or self._stop.is_set():
                raise RuntimeError("investigation supervisor cannot be restarted")
            self._external_stop = stopped
            thread = threading.Thread(target=self._run, name=self.worker_id, daemon=True)
            # start() can lose its result after native launch. Install ownership
            # first; a failed start must never authorize replacement or dispatch.
            self._thread = thread
            try:
                thread.start()
            except BaseException:
                self._stop.set()
                raise

    def _compute(self, work: _Work) -> None:
        try:
            work.outcome = self.service.execute_claim(work.claim, deadline_monotonic=work.deadline)
        except BaseException:
            # A callback may have committed. Never infer a safe ACK from an exit.
            work.outcome = None

    def _reap(self) -> None:
        with self._lock:
            active = tuple(self._active)
        for work in active:
            if work.thread is None:
                raise RuntimeError("missing investigation executor owner")
            if work.thread.is_alive():
                continue
            work.thread.join()  # physical join MUST precede worker_exited
            acknowledged = False
            if work.outcome is not None and work.outcome.acknowledge_exit:
                try:
                    acknowledged = self.service.store.worker_exited(work.outcome.claim)
                except Exception:
                    acknowledged = False
            with self._lock:
                self._active.remove(work)
                if not acknowledged:
                    self._quarantined.append(work)
                    self._fault = True

    def _cancel_owned(self) -> None:
        with self._lock:
            active = tuple(self._active)
        for work in active:
            if work.cancel_requested:
                continue
            work.cancel_requested = True
            try:
                self.service.store.cancel(
                    work.claim["owner_id"], work.claim["job_id"], work.claim["id"]
                )
            except Exception:
                with self._lock:
                    self._fault = True

    def _dispatch(self) -> None:
        for _ in range(2):
            with self._lock:
                if self._stopping() or self._fault or len(self._active) >= 2:
                    return
            deadline = time.monotonic() + 300
            try:
                claim = self.service.store.claim(self.worker_id)
            except Exception:
                with self._lock:
                    self._fault = True
                return
            if claim is None:
                return
            work = _Work(claim, deadline)
            try:
                if self._stopping():
                    self.service.store.cancel(claim["owner_id"], claim["job_id"], claim["id"])
                    work.cancel_requested = True
                thread = threading.Thread(
                    target=self._compute,
                    args=(work,),
                    name=self.worker_id + "-executor",
                    daemon=True,
                )
                work.thread = thread
                thread.start()
            except Exception:
                # Claim acquisition succeeded, thread start did not. Retain the
                # claim; worker_exited is reserved for a proved physical join.
                with self._lock:
                    self._quarantined.append(work)
                    self._fault = True
                return
            with self._lock:
                self._active.append(work)

    def _run(self) -> None:
        while True:
            self._reap()
            if self._stopping():
                self._cancel_owned()
                if not self.active_count:
                    return
                # Event.wait would busy-spin once the stop event is set.
                time.sleep(self.poll_seconds)
            else:
                self._dispatch()
                self._stop.wait(self.poll_seconds)

    def close(self, timeout: float = 2.0) -> bool:
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("invalid investigation shutdown timeout")
        self._stop.set()
        with self._lock:
            thread = self._thread
        if thread is not None:
            try:
                thread.join(timeout)
            except RuntimeError:
                # CPython registers native starts in enumerate() (including
                # bootstrap limbo) before launching. ident/is_alive alone cannot
                # prove no start. Check registration first, then persistent ident:
                # a concurrent bootstrap/exit must not be mistaken for no launch.
                # Only the owner calls start; native launch failures must obey
                # Thread.start's contract (no hidden launch after rejection).
                if thread in threading.enumerate() or thread.ident is not None:
                    return False
        with self._lock:
            return (
                not self.running and not self._active and not self._quarantined and not self._fault
            )
