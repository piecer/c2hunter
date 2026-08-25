from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from threading import Event
from typing import Any, Protocol

from prometheus_client import CollectorRegistry, start_http_server

from .api_errors import ApiError
from .config import Settings
from .pcap_export_metrics import PcapExportMetrics
from .pcap_export_queue import ExportQueueStorageError, PcapExportQueue
from .pcap_export_service import PcapExportExecutor
from .production import MinioBlobStore, PostgresRepository
from .repositories import ArtifactStorageError, Repository
from .schemas import PcapExportCreate

logger = logging.getLogger(__name__)


class PcapExportWorkerMetrics(Protocol):
    def checkpoint(self, **progress: Any) -> None: ...

    def completed(self, artifact: dict[str, Any]) -> None: ...


class TransientExportError(RuntimeError):
    """Explicitly retryable database or object-storage failure."""


class ExportCancelled(RuntimeError):
    pass


class ExportSourceChanged(RuntimeError):
    pass


class ExportTimedOut(RuntimeError):
    pass


class PcapExportWorker:
    """One durable export worker, independent of analysis queue transports."""

    def __init__(
        self,
        queue: PcapExportQueue,
        executor: Callable[[dict[str, Any], Callable[..., None]], dict[str, Any]],
        *,
        lease_seconds: int = 120,
        renew_seconds: int = 30,
        retry_base_seconds: int = 5,
        terminal_retention_seconds: int = 604_800,
        terminal_max_count: int = 10_000,
        terminal_max_artifact_bytes: int = 100 * 1024**3,
        orphan_max_age_seconds: int = 3600,
        orphan_cleanup_batch_size: int = 100,
        job_timeout_seconds: int = 1800,
        monotonic_clock: Callable[[], float] = time.monotonic,
        heartbeat_queue_factory: Callable[[], tuple[PcapExportQueue, Callable[[], None]]]
        | None = None,
    ) -> None:
        self.queue = queue
        self.executor = executor
        self.lease_seconds = lease_seconds
        self.renew_seconds = renew_seconds
        self.retry_base_seconds = retry_base_seconds

        self.terminal_retention_seconds = terminal_retention_seconds
        self.terminal_max_count = terminal_max_count
        self.terminal_max_artifact_bytes = terminal_max_artifact_bytes
        self.orphan_max_age_seconds = orphan_max_age_seconds
        self.orphan_cleanup_batch_size = orphan_cleanup_batch_size
        self.job_timeout_seconds = job_timeout_seconds
        self.monotonic_clock = monotonic_clock
        self.heartbeat_queue_factory = heartbeat_queue_factory

    def _maintain(self) -> None:
        now = datetime.now(UTC)
        try:
            self.queue.retain_terminal(
                now=now,
                max_age_seconds=self.terminal_retention_seconds,
                max_count=self.terminal_max_count,
                max_artifact_bytes=self.terminal_max_artifact_bytes,
            )
        except Exception:
            logger.warning("PCAP export retention failed", exc_info=True)
        try:
            self.queue.cleanup_orphans(
                now=now,
                max_age_seconds=self.orphan_max_age_seconds,
                limit=self.orphan_cleanup_batch_size,
            )
        except Exception:
            logger.warning("PCAP export orphan cleanup failed", exc_info=True)

    def _compensate_preserving_primary(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> None:
        try:
            self.queue.compensate_artifact(
                export_id,
                attempt=attempt,
                lease_token=lease_token,
                artifact=artifact,
            )
        except Exception:
            logger.warning(
                "PCAP export attempt-artifact cleanup failed export_id=%s attempt=%s",
                export_id,
                attempt,
                exc_info=True,
            )

    def run_once(self) -> bool:
        self.queue.recover_expired()
        self._maintain()
        return self._run_once()

    def _run_once(self) -> bool:
        job = self.queue.claim(lease_seconds=self.lease_seconds)
        if job is None:
            return False
        export_id = str(job["id"])
        attempt = int(job["attempt"])
        token = str(job["lease_token"])
        stopped = threading.Event()
        deadline = self.monotonic_clock() + self.job_timeout_seconds
        heartbeat_queue = self.queue

        def close_heartbeat() -> None:
            return None

        if self.heartbeat_queue_factory is not None:
            heartbeat_queue, close_heartbeat = self.heartbeat_queue_factory()

        def heartbeat() -> None:
            while not stopped.wait(self.renew_seconds):
                if not heartbeat_queue.heartbeat(
                    export_id,
                    attempt=attempt,
                    lease_token=token,
                    lease_seconds=self.lease_seconds,
                ):
                    return

        heart = threading.Thread(
            target=heartbeat, name=f"pcap-export-heartbeat-{export_id}", daemon=True
        )
        heart.start()

        def checkpoint(**progress: Any) -> None:
            if self.monotonic_clock() >= deadline:
                raise ExportTimedOut
            current = self.queue.get(export_id)
            if current is None or current.get("cancellation_requested"):
                raise ExportCancelled
            if not self.queue.progress(
                export_id, attempt=attempt, lease_token=token, progress=progress
            ):
                raise ExportCancelled

        artifact: dict[str, Any] | None = None
        try:
            checkpoint(phase="SOURCE_FETCH")
            if not self.queue.validate_source(job):
                raise ExportSourceChanged
            artifact = self.executor(job, checkpoint)
            if not self.queue.validate_source(job):
                self._compensate_preserving_primary(
                    export_id,
                    attempt=attempt,
                    lease_token=token,
                    artifact=artifact,
                )
                raise ExportSourceChanged
            checkpoint(phase="PUBLISH", percent=99)
            won = self.queue.complete(
                export_id, attempt=attempt, lease_token=token, artifact=artifact
            )
            if not won:
                self._compensate_preserving_primary(
                    export_id,
                    attempt=attempt,
                    lease_token=token,
                    artifact=artifact,
                )
        except ExportCancelled:
            if artifact is not None:
                self._compensate_preserving_primary(
                    export_id,
                    attempt=attempt,
                    lease_token=token,
                    artifact=artifact,
                )
            self.queue.retry_or_fail(
                export_id,
                attempt=attempt,
                lease_token=token,
                transient=False,
                error_code="PCAP_EXPORT_CANCELLED",
                error="PCAP export was cancelled",
                retry_base_seconds=self.retry_base_seconds,
            )
        except (TransientExportError, ExportQueueStorageError, ArtifactStorageError):
            if artifact is not None:
                self._compensate_preserving_primary(
                    export_id,
                    attempt=attempt,
                    lease_token=token,
                    artifact=artifact,
                )
            self.queue.retry_or_fail(
                export_id,
                attempt=attempt,
                lease_token=token,
                transient=True,
                error_code="PCAP_EXPORT_STORAGE_ERROR",
                error="PCAP export storage is temporarily unavailable",
                retry_base_seconds=self.retry_base_seconds,
            )
        except ExportSourceChanged:
            self.queue.retry_or_fail(
                export_id,
                attempt=attempt,
                lease_token=token,
                transient=False,
                error_code="PCAP_SOURCE_GENERATION_CHANGED",
                error="PCAP export source changed after admission",
                retry_base_seconds=self.retry_base_seconds,
            )
        except ExportTimedOut:
            if artifact is not None:
                self._compensate_preserving_primary(
                    export_id, attempt=attempt, lease_token=token, artifact=artifact
                )
            self.queue.retry_or_fail(
                export_id,
                attempt=attempt,
                lease_token=token,
                transient=True,
                error_code="PCAP_EXPORT_TIMEOUT",
                error="PCAP export cooperative deadline exceeded",
                retry_base_seconds=self.retry_base_seconds,
            )
        except Exception:
            logger.exception(
                "PCAP export worker failed export_id=%s attempt=%s", export_id, attempt
            )
            if artifact is not None:
                self._compensate_preserving_primary(
                    export_id,
                    attempt=attempt,
                    lease_token=token,
                    artifact=artifact,
                )
            self.queue.retry_or_fail(
                export_id,
                attempt=attempt,
                lease_token=token,
                transient=False,
                error_code="PCAP_EXPORT_FAILED",
                error="PCAP export failed",
                retry_base_seconds=self.retry_base_seconds,
            )
        finally:
            stopped.set()
            heart.join(timeout=max(1.0, float(self.renew_seconds) + 1.0))
            try:
                close_heartbeat()
            except Exception:
                logger.warning("PCAP export heartbeat repository close failed", exc_info=True)
        return True

    def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
        """Recover leases before readiness, then drain until graceful shutdown."""
        self.queue.recover_expired()
        self._maintain()
        while not stopped.is_set():
            if not self._run_once():
                stopped.wait(idle_seconds)


def create_pcap_export_worker(
    repository: Repository,
    settings: Settings,
    *,
    metrics: PcapExportWorkerMetrics | None = None,
) -> PcapExportWorker:
    """Build the production worker without capturing HTTP application state."""
    shared = PcapExportExecutor(repository, settings)

    def heartbeat_queue_factory() -> tuple[PcapExportQueue, Callable[[], None]]:
        background_factory = getattr(repository, "for_background_worker", None)
        if background_factory is None:
            # Memory/SQLite adapters serialize access internally and do not own a
            # second connection factory; retain their lock-safe shared behavior.
            return PcapExportQueue(repository), lambda: None
        heartbeat_repository = background_factory()
        return PcapExportQueue(heartbeat_repository), heartbeat_repository.close

    def execute(job: dict[str, Any], checkpoint: Callable[..., None]) -> dict[str, Any]:
        def observed_checkpoint(**progress: Any) -> None:
            checkpoint(**progress)
            if metrics is not None:
                try:
                    metrics.checkpoint(**progress)
                except Exception:
                    logger.debug("PCAP export worker metric checkpoint failed", exc_info=True)

        try:
            payload = PcapExportCreate.model_validate(job["canonical_request"])
            artifact = shared.execute(
                payload,
                {},
                export_id=str(job["id"]),
                source_snapshot=job,
                checkpoint=observed_checkpoint,
            )
            if metrics is not None:
                try:
                    metrics.completed(artifact)
                except Exception:
                    logger.debug("PCAP export worker completion metric failed", exc_info=True)
            return artifact
        except ApiError as exc:
            if exc.status == 503:
                raise TransientExportError("PCAP export storage unavailable") from exc
            raise

    return PcapExportWorker(
        PcapExportQueue(
            repository, metrics=metrics if isinstance(metrics, PcapExportMetrics) else None
        ),
        execute,
        lease_seconds=settings.pcap_export_lease_seconds,
        renew_seconds=settings.pcap_export_lease_renew_seconds,
        retry_base_seconds=settings.pcap_export_retry_base_seconds,
        terminal_retention_seconds=settings.pcap_export_terminal_retention_seconds,
        terminal_max_count=settings.pcap_export_terminal_max_count,
        terminal_max_artifact_bytes=settings.pcap_export_terminal_max_artifact_bytes,
        orphan_max_age_seconds=settings.pcap_export_orphan_max_age_seconds,
        orphan_cleanup_batch_size=settings.pcap_export_orphan_cleanup_batch_size,
        job_timeout_seconds=settings.pcap_export_job_timeout_seconds,
        heartbeat_queue_factory=heartbeat_queue_factory,
    )


def worker_ready(repository: Repository) -> bool:
    """Readiness is storage readiness; queue recovery happens before the run loop."""
    try:
        return repository.ready()
    except Exception:
        return False


def parse_worker_command(argv: list[str]) -> str:
    parser = argparse.ArgumentParser(description="Durable PCAP export worker")
    parser.add_argument(
        "command", nargs="?", default="run", choices=("run", "readiness", "healthcheck")
    )
    return str(parser.parse_args(argv).command)


def main(argv: list[str] | None = None) -> int:
    command = parse_worker_command(sys.argv[1:] if argv is None else argv)
    settings = Settings()
    if not settings.database_url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("PCAP export worker requires PostgreSQL")
    if settings.s3_endpoint == "memory://":
        raise RuntimeError("PCAP export worker requires configured MinIO/S3 storage")
    repository = PostgresRepository(
        settings.database_url,
        MinioBlobStore(
            settings.s3_endpoint,
            settings.s3_access_key,
            settings.s3_secret_key,
            settings.s3_bucket,
        ),
    )
    if not worker_ready(repository):
        repository.close()
        if command in {"readiness", "healthcheck"}:
            return 1
        raise RuntimeError("PCAP export worker storage is not ready")
    if command in {"readiness", "healthcheck"}:
        repository.close()
        return 0
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)
    start_http_server(settings.pcap_export_metrics_port, registry=registry)
    stopped = Event()

    def stop(_signum: int, _frame: object) -> None:
        stopped.set()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    worker_repositories = [repository]
    worker_repositories.extend(
        repository.for_background_worker()
        for _ in range(settings.pcap_export_async_worker_concurrency - 1)
    )
    threads = [
        threading.Thread(
            target=create_pcap_export_worker(worker_repository, settings, metrics=metrics).run,
            args=(stopped,),
            name=f"pcap-export-worker-{index + 1}",
        )
        for index, worker_repository in enumerate(worker_repositories)
    ]
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
    finally:
        stopped.set()
        for thread in threads:
            thread.join(timeout=5)
        for worker_repository in worker_repositories:
            worker_repository.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
