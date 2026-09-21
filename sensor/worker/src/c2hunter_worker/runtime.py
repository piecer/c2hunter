from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Thread
from typing import Any, Protocol


class JobQueue(Protocol):
    def receive(self, timeout: int) -> dict[str, Any] | None: ...

    def publish_event(self, event: dict[str, Any]) -> None: ...

    def complete(self, receipt: str, result: dict[str, Any]) -> None: ...

    def close(self) -> None: ...


class JobPayloadLoader(Protocol):
    def load(self, job_id: str) -> dict[str, Any]: ...

    def claim_analysis(
        self,
        job_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> tuple[str, str | None]: ...

    def renew_analysis(
        self, job_id: str, *, claim_token: str, lease_seconds: int
    ) -> bool: ...

    def close(self) -> None: ...


class Worker:
    def __init__(
        self,
        *,
        queue: JobQueue,
        execute: Callable[[dict[str, Any]], dict[str, Any]],
        health_path: Path,
        payload_loader: JobPayloadLoader | None = None,
        analysis_lease_seconds: int = 300,
        analysis_lease_renew_seconds: float = 60,
    ) -> None:
        self.queue = queue
        self.execute = execute
        self.health_path = health_path
        self.payload_loader = payload_loader
        self.analysis_lease_seconds = analysis_lease_seconds
        self.analysis_lease_renew_seconds = analysis_lease_renew_seconds
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
                if result.get("status") == "RETRY":
                    self._write_health("RUNNING")
                    continue
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
            if self.payload_loader is not None:
                self.payload_loader.close()
            self._write_health("STOPPED")

    def _execute_job(self, job: dict[str, Any]) -> dict[str, Any]:
        job_id = str(job.get("id", ""))
        if not job_id:
            return {
                "job_id": "",
                "status": "ERROR",
                "error_code": "INVALID_JOB_ENVELOPE",
                "error": "worker job envelope is invalid",
            }
        stage = "payload"
        heartbeat_stop = Event()
        heartbeat_thread: Thread | None = None
        try:
            raw_payload = job.get("payload")
            if isinstance(raw_payload, dict):
                payload = dict(raw_payload)
            elif self.payload_loader is not None:
                preparation_attempt = job.get("preparation_attempt")
                preparation_token = job.get("preparation_lease_token")
                if preparation_attempt is not None and preparation_token is not None:
                    claim_status, claim_token = self.payload_loader.claim_analysis(
                        job_id,
                        attempt=int(preparation_attempt),
                        lease_token=str(preparation_token),
                        lease_seconds=self.analysis_lease_seconds,
                    )
                    if claim_status == "ACTIVE":
                        return {"job_id": job_id, "status": "RETRY"}
                    if claim_status != "CLAIMED" or claim_token is None:
                        return self._superseded_result(job_id)
                    heartbeat_thread = self._start_analysis_heartbeat(
                        job_id, claim_token, heartbeat_stop
                    )
                payload = self.payload_loader.load(job_id)
            else:
                raise ValueError("job payload or configured payload loader is required")
            if self._delivery_is_superseded(job, payload):
                return self._superseded_result(job_id)
            stage = "analysis"
            try:
                started_event: dict[str, Any] = {
                    "job_id": job_id,
                    "status": "EVENT",
                    "event": "ANALYSIS_STARTED",
                    "occurred_at": datetime.now(UTC).isoformat(),
                }
                for key in ("preparation_attempt", "preparation_lease_token"):
                    if job.get(key) is not None:
                        started_event[key] = job[key]
                self.queue.publish_event(started_event)
            except Exception:
                # Progress is observational. The terminal result remains the
                # authoritative outcome and must not be replaced by this failure.
                pass
            result = self.execute(payload)
        except Exception as error:
            if isinstance(error, ValueError) and str(error).startswith(
                "unsupported analysis module"
            ):
                error_code = "UNSUPPORTED_ANALYSIS_MODULE"
                message = "worker does not support the requested analysis module"
            elif stage == "payload":
                error_code = "PAYLOAD_LOAD_FAILED"
                message = "worker could not load the analysis payload"
            else:
                error_code = "ANALYSIS_EXECUTION_FAILED"
                message = "worker analysis failed"
            self.last_error = error_code
            return {
                "job_id": job_id,
                "status": "ERROR",
                "error_code": error_code,
                "error": message,
            }
        finally:
            heartbeat_stop.set()
            if heartbeat_thread is not None:
                heartbeat_thread.join(
                    timeout=max(1.0, self.analysis_lease_renew_seconds * 2)
                )
                if heartbeat_thread.is_alive():
                    raise RuntimeError("analysis heartbeat did not stop")
        self.last_error = None
        return {"job_id": job_id, "status": "COMPLETED", "result": result}

    def _start_analysis_heartbeat(
        self, job_id: str, claim_token: str, stopped: Event
    ) -> Thread:
        loader = self.payload_loader
        assert loader is not None

        def heartbeat() -> None:
            while not stopped.wait(self.analysis_lease_renew_seconds):
                try:
                    renewed = loader.renew_analysis(
                        job_id,
                        claim_token=claim_token,
                        lease_seconds=self.analysis_lease_seconds,
                    )
                except Exception:
                    renewed = False
                if not renewed:
                    return

        thread = Thread(
            target=heartbeat, name=f"analysis-heartbeat-{job_id}", daemon=True
        )
        thread.start()
        return thread

    @staticmethod
    def _delivery_is_superseded(job: dict[str, Any], payload: dict[str, Any]) -> bool:
        token = job.get("preparation_lease_token")
        attempt = job.get("preparation_attempt")
        if token is None or attempt is None:
            return False
        if payload.get("status") in {
            "COMPLETED",
            "PARTIALLY_COMPLETED",
            "FAILED",
            "CANCELLED",
        }:
            return True
        processing = payload.get("processing")
        if not isinstance(processing, dict) or int(
            processing.get("attempt", -1)
        ) != int(attempt):
            return True
        if processing.get("phase") == "ANALYSIS_ENQUEUE_PENDING":
            return processing.get("lease_token") != token
        if processing.get("phase") == "ANALYSIS_QUEUED":
            return processing.get("lease_token") != token
        return processing.get("phase") != "ANALYSIS_CLAIMED"

    @staticmethod
    def _superseded_result(job_id: str) -> dict[str, Any]:
        return {
            "job_id": job_id,
            "status": "EVENT",
            "event": "ANALYSIS_DELIVERY_SUPERSEDED",
            "occurred_at": datetime.now(UTC).isoformat(),
        }

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
