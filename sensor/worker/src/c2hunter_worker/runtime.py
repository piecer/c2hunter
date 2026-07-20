from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from typing import Any, Protocol


class JobQueue(Protocol):
    def receive(self, timeout: int) -> dict[str, Any] | None: ...

    def complete(self, receipt: str, result: dict[str, Any]) -> None: ...

    def close(self) -> None: ...


class Worker:
    def __init__(
        self,
        *,
        queue: JobQueue,
        execute: Callable[[dict[str, Any]], dict[str, Any]],
        health_path: Path,
    ) -> None:
        self.queue = queue
        self.execute = execute
        self.health_path = health_path
        self.processed_jobs = 0
        self.last_error: str | None = None

    def run(self, stopped: Event) -> None:
        self._write_health("RUNNING")
        try:
            while not stopped.is_set():
                try:
                    job = self.queue.receive(timeout=1)
                except Exception as error:  # queue connectivity is retried by the loop
                    self.last_error = str(error)
                    self._write_health("DEGRADED")
                    stopped.wait(1)
                    continue
                if job is None:
                    self._write_health("RUNNING")
                    continue
                result = self._execute_job(job)
                try:
                    receipt = str(job.get("receipt", ""))
                    if not receipt:
                        raise ValueError("claimed job receipt is required")
                    self.queue.complete(receipt, result)
                except Exception as error:
                    self.last_error = f"publish failed: {error}"
                    self._write_health("DEGRADED")
                    continue
                self.processed_jobs += 1
                self._write_health("RUNNING")
        finally:
            self.queue.close()
            self._write_health("STOPPED")

    def _execute_job(self, job: dict[str, Any]) -> dict[str, Any]:
        job_id = str(job.get("id", ""))
        if not job_id:
            return {"job_id": "", "status": "ERROR", "error": "job id is required"}
        try:
            result = self.execute(dict(job.get("payload", {})))
        except Exception as error:
            self.last_error = str(error)
            return {"job_id": job_id, "status": "ERROR", "error": str(error)}
        self.last_error = None
        return {"job_id": job_id, "status": "COMPLETED", "result": result}

    def _write_health(self, status: str) -> None:
        payload = {
            "status": status,
            "pid": os.getpid(),
            "updated_at": datetime.now(UTC).isoformat(),
            "processed_jobs": self.processed_jobs,
            "last_error": self.last_error,
        }
        self.health_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(dir=self.health_path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, separators=(",", ":"))
            os.replace(temporary, self.health_path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
