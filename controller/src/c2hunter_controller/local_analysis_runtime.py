"""Opt-in single-process POC worker, not a durable queue or production deployment.

Only the coordinator accesses the repository. The worker receives copied payloads
and returns results through bounded queues; publication uses the app's normal path.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections import deque
from collections.abc import Callable
from pathlib import Path
from queue import Empty, Queue
from typing import Any, BinaryIO

from .queueing import MemoryControllerQueue
from .repositories import Repository

logger = logging.getLogger(__name__)


def result_releases_inflight(result: dict[str, Any]) -> bool:
    return result.get("status") != "EVENT" or result.get("event") == "ANALYSIS_DELIVERY_SUPERSEDED"


class LocalWorkerQueue:
    def __init__(self) -> None:
        self.jobs: Queue[dict[str, Any]] = Queue(maxsize=1)
        self.results: Queue[dict[str, Any]] = Queue(maxsize=2)

    def receive(self, timeout: int) -> dict[str, Any] | None:
        try:
            return self.jobs.get(timeout=timeout)
        except Empty:
            return None

    def complete(self, receipt: str, result: dict[str, Any]) -> None:
        self.results.put_nowait({**result, "receipt": receipt})

    def publish_event(self, event: dict[str, Any]) -> None:
        self.results.put_nowait({**event, "receipt": f"event:{event['job_id']}"})

    def close(self) -> None:
        pass


class LocalAnalysisRuntime:
    def __init__(
        self,
        queue: MemoryControllerQueue,
        repository: Repository,
        process_due: Callable[[], bool],
        publish: Callable[[dict[str, Any]], None],
        health_path: Path,
        enqueue: Callable[[dict[str, Any]], None],
        prepare: Callable[[], None] | None = None,
        ownership_path: Path | None = None,
    ) -> None:
        # Optional worker package is required only when this POC mode is requested.
        from c2hunter_worker.analysis import (  # type: ignore[import-not-found,import-untyped]
            execute_analysis,
        )
        from c2hunter_worker.runtime import Worker  # type: ignore[import-not-found,import-untyped]

        self.queue = queue
        self.repository = repository
        self.process_due = process_due
        self.publish = publish
        self.bridge = LocalWorkerQueue()
        self.stopped = threading.Event()
        self.worker = Worker(queue=self.bridge, execute=execute_analysis, health_path=health_path)
        self.thread = threading.Thread(
            target=self.worker.run, args=(self.stopped,), name="local-analysis-worker", daemon=True
        )
        self.task: asyncio.Task[None] | None = None
        self.inflight = False
        self.pending: dict[str, Any] | None = None
        self.last_error: str | None = None
        self.enqueue = enqueue
        self.recovery_ids: deque[str] = deque()
        self.prepare = prepare
        self.ownership_path = ownership_path
        self.ownership_file: BinaryIO | None = None

    async def start(self) -> None:
        if self.ownership_path is not None:
            # Single-host, cooperating local runtimes only. Lock the database
            # inode itself so differing health paths cannot bypass ownership.
            import fcntl

            owned = self.ownership_path.open("rb")
            try:
                fcntl.flock(owned.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                owned.close()
                raise RuntimeError("local runtime database is already owned") from error
            self.ownership_file = owned
        try:
            if self.prepare is not None:
                self.prepare()
            queued = {str(job["id"]) for job in self.queue.jobs}
            self.recovery_ids = deque(
                str(job["id"])
                for job in self.repository.list_jobs()
                if job.get("status") == "ANALYZING" and str(job["id"]) not in queued
            )
            self.thread.start()
            self.task = asyncio.create_task(self.run(), name="local-analysis-coordinator")
        except BaseException:
            if self.ownership_file is not None:
                self.ownership_file.close()
                self.ownership_file = None
            raise

    async def run(self) -> None:
        while not self.stopped.is_set():
            try:
                self.process_due()
                if self.pending is None:
                    try:
                        self.pending = self.bridge.results.get_nowait()
                    except Empty:
                        pass
                if self.pending is not None:
                    self.publish(self.pending)
                    releases_inflight = result_releases_inflight(self.pending)
                    self.pending = None
                    if releases_inflight:
                        self.inflight = False
                if not self.inflight and self.pending is None and self.recovery_ids:
                    self.recover_one()
                if not self.inflight and self.queue.jobs:
                    envelope = self.queue.jobs.pop(0)
                    current = self.repository.get_job_summary(str(envelope["id"]))
                    if current is not None and current["status"] == "ANALYZING":
                        self.bridge.jobs.put_nowait({**envelope, "receipt": str(envelope["id"])})
                        self.inflight = True
                self.last_error = None
            except Exception:
                self.last_error = "local analysis coordinator failed; retrying"
                logger.exception(self.last_error)
            await asyncio.sleep(0.05)

    def recover_one(self) -> None:
        from .schemas import FlowRecord

        job_id = self.recovery_ids[0]
        job = self.repository.get_job(job_id)
        if job is not None and job.get("status") == "ANALYZING":
            processing = job.get("processing")
            if isinstance(processing, dict) and processing.get("phase") in {
                "ANALYSIS_CLAIMED",
                "ANALYSIS_RUNNING",
            }:
                self.pending = {
                    "job_id": job_id,
                    "receipt": job_id,
                    "status": "ERROR",
                    "error_code": "ANALYSIS_WORKER_LOST",
                    "error": "local analysis worker stopped before a durable result",
                }
                self.recovery_ids.popleft()
                return
            try:
                records = job.get("flow_records")
                if not job.get("dataset_id") or not isinstance(records, list):
                    raise ValueError("missing saved dataset")
                if len(records) != job.get("flow_count"):
                    raise ValueError("saved flow count mismatch")
                for record in records:
                    FlowRecord.model_validate(record)
                if sum(int(record.get("packet_count", 1)) for record in records) != job.get(
                    "packet_count"
                ):
                    raise ValueError("saved packet count mismatch")
            except (ValueError, TypeError):
                logger.exception("invalid persisted analysis payload: %s", job_id)
                self.pending = {
                    "job_id": job_id,
                    "receipt": job_id,
                    "status": "ERROR",
                    "error": "persisted analysis payload is invalid; recovery refused",
                }
            else:
                # Reuse enqueue_worker_job; do not rebuild a snapshot from volatile flows.
                self.enqueue(job)
                logger.info("requeued persisted analysis job %s", job_id)
        self.recovery_ids.popleft()

    async def stop(self) -> None:
        self.stopped.set()
        if self.task is not None:
            await self.task
        # A running detector cannot be forcibly cancelled. It has no repository
        # access; uncommitted work remains ANALYZING for next-start recovery.
        await asyncio.to_thread(self.thread.join, 2)
        if self.thread.is_alive():
            logger.warning("local worker still computing at shutdown; publication deferred")
        if self.ownership_file is not None:
            self.ownership_file.close()
            self.ownership_file = None
