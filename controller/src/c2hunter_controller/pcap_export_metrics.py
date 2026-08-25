from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

logger = logging.getLogger(__name__)


class PcapExportMetrics:
    """Low-cardinality Stage 8 metrics with fail-open observation."""

    def __init__(self, registry: CollectorRegistry) -> None:
        self.queue_depth = Gauge(
            "c2hunter_pcap_export_queue_depth",
            "Durable PCAP export jobs by active status",
            ["status"],
            registry=registry,
        )
        self.enqueue_total = Counter(
            "c2hunter_pcap_export_enqueue_total",
            "PCAP export admission outcomes",
            ["result"],
            registry=registry,
        )
        self.duration_seconds = Histogram(
            "c2hunter_pcap_export_duration_seconds",
            "PCAP export lifecycle duration",
            ["mode", "status"],
            registry=registry,
        )
        self.retries_total = Counter(
            "c2hunter_pcap_export_retries_total",
            "PCAP export retries",
            ["reason"],
            registry=registry,
        )
        self.lease_expirations_total = Counter(
            "c2hunter_pcap_export_lease_expirations_total",
            "Expired PCAP export leases recovered",
            registry=registry,
        )
        self.progress_stale_total = Counter(
            "c2hunter_pcap_export_progress_stale_total",
            "Rejected stale PCAP export progress updates",
            registry=registry,
        )
        self.artifact_bytes = Gauge(
            "c2hunter_pcap_export_artifact_bytes",
            "Bytes in the most recently completed PCAP export artifact",
            registry=registry,
        )
        self.orphan_cleanup_total = Counter(
            "c2hunter_pcap_export_orphan_cleanup_total",
            "PCAP staging-orphan cleanup outcomes",
            ["result"],
            registry=registry,
        )
        for status in ("QUEUED", "RUNNING"):
            self.queue_depth.labels(status=status).set(0)

    @staticmethod
    def _safe(operation: Callable[[], None]) -> None:
        try:
            operation()
        except Exception:
            logger.debug("PCAP export metric update failed", exc_info=True)

    def enqueue(self, result: str, job: dict[str, Any] | None = None) -> None:
        self._safe(lambda: self.enqueue_total.labels(result=result).inc())
        if job is not None:
            self.transition(job)

    def transition(self, job: dict[str, Any]) -> None:
        def update() -> None:
            status = str(job["status"])
            if status in {"QUEUED", "RUNNING"}:
                return
            created = job.get("created_at") or job.get("queued_at")
            if created:
                elapsed = max(
                    0.0,
                    (datetime.now(UTC) - datetime.fromisoformat(str(created))).total_seconds(),
                )
                self.duration_seconds.labels(
                    mode=str(job.get("execution_mode", "UNKNOWN")), status=status
                ).observe(elapsed)
            if status == "COMPLETED":
                self.artifact_bytes.set(max(0, int(job.get("size_bytes", 0) or 0)))

        self._safe(update)

    def reconcile_queue_depth(self, counts: dict[str, int]) -> None:
        def update() -> None:
            for status in ("QUEUED", "RUNNING"):
                self.queue_depth.labels(status=status).set(max(0, int(counts.get(status, 0))))

        self._safe(update)

    def retry(self, reason: str) -> None:
        self._safe(lambda: self.retries_total.labels(reason=reason).inc())

    def lease_expired(self, count: int) -> None:
        if count:
            self._safe(lambda: self.lease_expirations_total.inc(count))

    def stale_progress(self) -> None:
        self._safe(self.progress_stale_total.inc)

    def orphan_cleanup(self, result: str) -> None:
        self._safe(lambda: self.orphan_cleanup_total.labels(result=result).inc())

    def checkpoint(self, **_progress: Any) -> None:
        """Worker observer hook; durable transition metrics live on the queue facade."""

    def completed(self, artifact: dict[str, Any]) -> None:
        self._safe(lambda: self.artifact_bytes.set(max(0, int(artifact.get("size_bytes", 0) or 0))))
