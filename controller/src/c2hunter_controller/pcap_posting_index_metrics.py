from __future__ import annotations

from collections.abc import Mapping

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

SOURCE_KINDS = ("PCAP_UPLOAD", "LIVE_SEGMENT", "other")
ADMISSION_OUTCOMES = ("queued", "coalesced", "deferred", "ineligible", "error", "other")
TASK_OUTCOMES = ("completed", "retry", "failed", "stale", "other")
TASK_REASONS = (
    "none",
    "build_rejected",
    "storage",
    "timeout",
    "lease_lost",
    "deleted",
    "heartbeat_unavailable",
    "worker_fatal",
    "other",
)
QUEUE_STATUSES = ("QUEUED", "RUNNING", "COMPLETED", "FAILED", "other")
BUILD_OUTCOMES = ("completed", "failed", "stale", "timeout", "other")


def _bounded(value: object, allowed: tuple[str, ...]) -> str:
    candidate = str(value)
    return candidate if candidate in allowed else "other"


class PcapPostingIndexMetrics:
    """Posting metrics whose complete label vocabulary is fixed and bounded."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry or CollectorRegistry()
        self._admissions = Counter(
            "c2hunter_pcap_posting_index_admissions_total",
            "Posting index admission decisions",
            ("source_kind", "outcome"),
            registry=self.registry,
        )
        self._tasks = Counter(
            "c2hunter_pcap_posting_index_tasks_total",
            "Posting index task outcomes",
            ("source_kind", "outcome", "reason"),
            registry=self.registry,
        )
        self._depth = Gauge(
            "c2hunter_pcap_posting_index_queue_depth",
            "Reconciled posting index queue depth",
            ("status",),
            registry=self.registry,
        )
        self._build_seconds = Histogram(
            "c2hunter_pcap_posting_index_build_seconds",
            "Posting index build duration",
            ("source_kind", "outcome"),
            registry=self.registry,
        )
        self._memberships = Counter(
            "c2hunter_pcap_posting_index_memberships_total",
            "Published posting memberships",
            ("source_kind",),
            registry=self.registry,
        )
        self._encoded_bytes = Counter(
            "c2hunter_pcap_posting_index_encoded_bytes_total",
            "Published posting encoded bytes",
            ("source_kind",),
            registry=self.registry,
        )

    def admission(self, source_kind: object, outcome: object) -> None:
        self._admissions.labels(
            source_kind=_bounded(source_kind, SOURCE_KINDS),
            outcome=_bounded(outcome, ADMISSION_OUTCOMES),
        ).inc()

    def task(self, source_kind: object, outcome: object, reason: object) -> None:
        self._tasks.labels(
            source_kind=_bounded(source_kind, SOURCE_KINDS),
            outcome=_bounded(outcome, TASK_OUTCOMES),
            reason=_bounded(reason, TASK_REASONS),
        ).inc()

    def reconcile_depth(self, counts: Mapping[str, int]) -> None:
        for status in QUEUE_STATUSES[:-1]:
            self._depth.labels(status=status).set(max(0, int(counts.get(status, 0))))
        unknown = sum(
            max(0, int(count)) for status, count in counts.items() if status not in QUEUE_STATUSES
        )
        self._depth.labels(status="other").set(unknown)

    def build(self, source_kind: object, outcome: object, seconds: float) -> None:
        self._build_seconds.labels(
            source_kind=_bounded(source_kind, SOURCE_KINDS),
            outcome=_bounded(outcome, BUILD_OUTCOMES),
        ).observe(max(0.0, float(seconds)))

    def generation(self, source_kind: object, memberships: int, encoded_bytes: int) -> None:
        kind = _bounded(source_kind, SOURCE_KINDS)
        self._memberships.labels(source_kind=kind).inc(max(0, int(memberships)))
        self._encoded_bytes.labels(source_kind=kind).inc(max(0, int(encoded_bytes)))
