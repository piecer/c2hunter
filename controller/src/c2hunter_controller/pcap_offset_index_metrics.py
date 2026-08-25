from __future__ import annotations

from collections.abc import Mapping

from prometheus_client import CollectorRegistry, Counter, Gauge

_SOURCE_KINDS = frozenset({"LIVE_SEGMENT"})
_ADMISSION_OUTCOMES = frozenset({"queued", "coalesced", "deferred", "error"})
_TASK_OUTCOMES = frozenset({"completed", "retry", "failed", "stale"})
_REASONS = frozenset({"none", "build_rejected", "storage", "timeout", "lease_lost", "deleted"})
_STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED")


class PcapOffsetIndexMetrics:
    """Stage 10 metrics with a deliberately frozen, low-cardinality label vocabulary."""

    def __init__(self, registry: CollectorRegistry) -> None:
        self._admissions = Counter(
            "c2hunter_pcap_offset_index_admissions_total",
            "Durable LIVE segment index admission decisions",
            ("source_kind", "outcome"),
            registry=registry,
        )
        self._tasks = Counter(
            "c2hunter_pcap_offset_index_tasks_total",
            "LIVE segment index task outcomes",
            ("source_kind", "outcome", "reason"),
            registry=registry,
        )
        self._depth = Gauge(
            "c2hunter_pcap_offset_index_queue_depth",
            "Reconciled durable queue depth",
            ("status",),
            registry=registry,
        )

    def admission(self, source_kind: str, outcome: str) -> None:
        if source_kind not in _SOURCE_KINDS or outcome not in _ADMISSION_OUTCOMES:
            raise ValueError("unsupported PCAP offset index metric label")
        self._admissions.labels(source_kind=source_kind, outcome=outcome).inc()

    def task(self, source_kind: str, outcome: str, reason: str) -> None:
        if (
            source_kind not in _SOURCE_KINDS
            or outcome not in _TASK_OUTCOMES
            or reason not in _REASONS
        ):
            raise ValueError("unsupported PCAP offset index metric label")
        self._tasks.labels(source_kind=source_kind, outcome=outcome, reason=reason).inc()

    def reconcile_depth(self, counts: Mapping[str, int]) -> None:
        for status in _STATUSES:
            self._depth.labels(status=status).set(max(0, int(counts.get(status, 0))))
