from __future__ import annotations

import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

from .pcap_export_service import RolloutFallbackReason, RolloutPath, ShadowParity

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
        self.indexed_executions_total = Counter(
            "c2hunter_pcap_indexed_export_executions_total",
            "PCAP indexed rollout executions by bounded path",
            ["path"],
            registry=registry,
        )
        self.indexed_fallback_total = Counter(
            "c2hunter_pcap_indexed_export_fallback_total",
            "PCAP indexed fallbacks by fixed reason",
            ["reason"],
            registry=registry,
        )
        self.indexed_requested_ranges_total = Counter(
            "c2hunter_pcap_indexed_export_requested_ranges_total",
            "Packet ranges requested before coalescing",
            registry=registry,
        )
        self.indexed_coalesced_ranges_total = Counter(
            "c2hunter_pcap_indexed_export_coalesced_ranges_total",
            "Byte ranges fetched after coalescing",
            registry=registry,
        )
        self.indexed_selected_payload_bytes_total = Counter(
            "c2hunter_pcap_indexed_export_selected_payload_bytes_total",
            "Selected packet payload bytes",
            registry=registry,
        )
        self.indexed_fetched_bytes_total = Counter(
            "c2hunter_pcap_indexed_export_fetched_bytes_total",
            "Indexed source bytes fetched",
            registry=registry,
        )
        self.indexed_source_saved_bytes_total = Counter(
            "c2hunter_pcap_indexed_export_source_saved_bytes_total",
            "Source bytes avoided by indexed fetching",
            registry=registry,
        )
        self.indexed_amplification_total = Counter(
            "c2hunter_pcap_indexed_export_amplification_total",
            "Indexed requests by bounded amplification bucket",
            ["bucket"],
            registry=registry,
        )
        self.indexed_source_fraction_total = Counter(
            "c2hunter_pcap_indexed_export_source_fraction_total",
            "Indexed requests by bounded fetched-source fraction bucket",
            ["bucket"],
            registry=registry,
        )
        self.indexed_shadow_parity_total = Counter(
            "c2hunter_pcap_indexed_export_shadow_parity_total",
            "Shadow comparisons by bounded parity outcome",
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

    @staticmethod
    def _amplification_bucket(fetched: int, selected: int) -> str:
        if fetched <= selected:
            return "le_1"
        if fetched <= selected * 2:
            return "le_2"
        if fetched <= selected * 4:
            return "le_4"
        if fetched <= selected * 8:
            return "le_8"
        return "gt_8"

    @staticmethod
    def _source_fraction_bucket(fetched: int, source: int) -> str:
        if fetched * 10 <= source:
            return "le_10pct"
        if fetched * 4 <= source:
            return "le_25pct"
        if fetched * 2 <= source:
            return "le_50pct"
        if fetched * 4 <= source * 3:
            return "le_75pct"
        return "le_100pct"

    def rollout_observer(
        self,
        *,
        path: RolloutPath,
        fallback_reason: RolloutFallbackReason,
        shadow_parity: ShadowParity,
        requested_range_count: int,
        coalesced_range_count: int,
        selected_payload_bytes: int,
        fetched_bytes: int,
        source_total_bytes: int,
    ) -> None:
        """Fixed-shape, fail-open adapter for executor rollout observations."""

        def update() -> None:
            requested = max(0, int(requested_range_count))
            coalesced = max(0, int(coalesced_range_count))
            selected = max(0, int(selected_payload_bytes))
            fetched = max(0, int(fetched_bytes))
            source = max(0, int(source_total_bytes))
            self.indexed_executions_total.labels(path=path).inc()
            if fallback_reason != "none":
                self.indexed_fallback_total.labels(reason=fallback_reason).inc()
            if shadow_parity != "not_applicable":
                self.indexed_shadow_parity_total.labels(result=shadow_parity).inc()
            if path not in {"indexed", "shadow"} or shadow_parity == "error":
                return
            self.indexed_requested_ranges_total.inc(requested)
            self.indexed_coalesced_ranges_total.inc(coalesced)
            self.indexed_selected_payload_bytes_total.inc(selected)
            self.indexed_fetched_bytes_total.inc(fetched)
            self.indexed_source_saved_bytes_total.inc(max(0, source - fetched))
            self.indexed_amplification_total.labels(
                bucket=self._amplification_bucket(fetched, selected)
            ).inc()
            self.indexed_source_fraction_total.labels(
                bucket=self._source_fraction_bucket(fetched, source)
            ).inc()

        self._safe(update)
