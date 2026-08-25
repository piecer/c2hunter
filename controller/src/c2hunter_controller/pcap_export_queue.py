from __future__ import annotations

from datetime import datetime
from typing import Any

from .pcap_export_metrics import PcapExportMetrics
from .pcap_export_store import (
    ACTIVE_EXPORT_STATES,
    TERMINAL_EXPORT_STATES,
    ExportPrincipalLimitError,
    ExportQueueFullError,
    ExportQueueStorageError,
    ExportSourceChangedError,
)
from .repositories import Repository

PcapExportJob = dict[str, Any]


class PcapExportQueue:
    """Typed facade over the durable queue owned by the repository adapter."""

    def __init__(self, repository: Repository, *, metrics: PcapExportMetrics | None = None) -> None:
        self.repository = repository
        self.metrics = metrics
        self.reconcile_metrics()

    def reconcile_metrics(self) -> None:
        if self.metrics is not None:
            self.metrics.reconcile_queue_depth(self.repository.count_pcap_export_jobs_by_status())

    def enqueue(
        self, job: PcapExportJob, *, capacity: int, per_principal_limit: int
    ) -> tuple[PcapExportJob, bool]:
        try:
            result, created = self.repository.enqueue_pcap_export_job(
                job, capacity=capacity, per_principal_limit=per_principal_limit
            )
        except ExportQueueFullError:
            if self.metrics is not None:
                self.metrics.enqueue("queue_full")
            raise
        except ExportPrincipalLimitError:
            if self.metrics is not None:
                self.metrics.enqueue("principal_limit")
            raise
        if self.metrics is not None:
            self.metrics.enqueue("created" if created else "reused", result)
            self.reconcile_metrics()
        return result, created

    def get(self, export_id: str) -> PcapExportJob | None:
        return self.repository.get_pcap_export_job(export_id)

    def find_idempotent(
        self, principal_scope: str, idempotency_key: str, request_fingerprint: str
    ) -> PcapExportJob | None:
        return self.repository.find_pcap_export_job(
            principal_scope, idempotency_key, request_fingerprint
        )

    def claim(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> PcapExportJob | None:
        job = self.repository.claim_pcap_export_job(now=now, lease_seconds=lease_seconds)
        if job is not None and self.metrics is not None:
            self.metrics.transition(job)
            self.reconcile_metrics()
        return job

    def heartbeat(
        self, export_id: str, *, attempt: int, lease_token: str, lease_seconds: int
    ) -> bool:
        return self.repository.heartbeat_pcap_export_job(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            lease_seconds=lease_seconds,
        )

    def progress(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        progress: dict[str, object],
    ) -> bool:
        updated = self.repository.progress_pcap_export_job(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            progress=progress,
        )
        if not updated and self.metrics is not None:
            self.metrics.stale_progress()
        return updated

    def complete(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, object],
    ) -> bool:
        updated = self.repository.complete_pcap_export_job(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            artifact=artifact,
        )
        if updated and self.metrics is not None:
            try:
                current = self.get(export_id)
                if current is not None:
                    self.metrics.transition(current)
                self.reconcile_metrics()
            except ExportQueueStorageError:
                # Publication already won. Metrics refresh is best-effort and must
                # never turn the published winner into a compensation candidate.
                pass
        return updated

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
        updated = self.repository.retry_pcap_export_job(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            transient=transient,
            error_code=error_code,
            error=error,
            retry_base_seconds=retry_base_seconds,
        )
        if updated and self.metrics is not None:
            try:
                current = self.get(export_id)
                if current is not None:
                    if current.get("status") == "QUEUED":
                        reason = "storage" if "STORAGE" in error_code else "transient"
                        self.metrics.retry(reason)
                    self.metrics.transition(current)
                self.reconcile_metrics()
            except ExportQueueStorageError:
                # The durable retry/failure transition already committed. A
                # metrics read outage must not terminate the worker loop.
                pass
        return updated

    def cancel(self, export_id: str, *, reason: str | None = None) -> PcapExportJob:
        job = self.repository.cancel_pcap_export_job(export_id, reason=reason)
        if self.metrics is not None:
            self.metrics.transition(job)
            self.reconcile_metrics()
        return job

    def recover_expired(self, *, now: datetime | None = None) -> int:
        recovered = self.repository.recover_pcap_export_jobs(now=now)
        if self.metrics is not None:
            self.metrics.lease_expired(recovered)
            self.reconcile_metrics()
        return recovered

    def validate_source(self, job: PcapExportJob) -> bool:
        return self.repository.validate_pcap_export_source(job)

    def compensate_artifact(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, object],
    ) -> None:
        self.repository.compensate_pcap_export_artifact(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            artifact=artifact,
        )

    def cleanup_orphans(self, *, now: datetime, max_age_seconds: int, limit: int) -> list[str]:
        try:
            removed = self.repository.cleanup_pcap_export_orphans(
                now=now, max_age_seconds=max_age_seconds, limit=limit
            )
        except Exception:
            if self.metrics is not None:
                self.metrics.orphan_cleanup("failure")
            raise
        if self.metrics is not None:
            self.metrics.orphan_cleanup("success")
        return removed

    def retain_terminal(
        self,
        *,
        now: datetime,
        max_age_seconds: int,
        max_count: int,
        max_artifact_bytes: int,
    ) -> list[str]:
        return self.repository.retain_pcap_export_jobs(
            now=now,
            max_age_seconds=max_age_seconds,
            max_count=max_count,
            max_artifact_bytes=max_artifact_bytes,
        )


__all__ = [
    "ACTIVE_EXPORT_STATES",
    "TERMINAL_EXPORT_STATES",
    "ExportPrincipalLimitError",
    "ExportQueueFullError",
    "ExportQueueStorageError",
    "ExportSourceChangedError",
    "PcapExportJob",
    "PcapExportQueue",
]
