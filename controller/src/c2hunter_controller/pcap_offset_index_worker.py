from __future__ import annotations

import argparse
import logging
import signal
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Event
from typing import Any

from prometheus_client import CollectorRegistry, start_http_server

from .config import Settings
from .pcap_offset_index import (
    LiveIndexPermanentError,
    LiveIndexTransientError,
    build_live_segment_index,
)
from .pcap_offset_index_metrics import PcapOffsetIndexMetrics
from .production import MinioBlobStore, PostgresRepository

logger = logging.getLogger(__name__)


class PcapOffsetIndexWorker:
    """Durable Stage 10 LIVE index worker; it never shares FastAPI request state."""

    def __init__(
        self,
        repository: Any,
        builder: Callable[..., bool],
        *,
        lease_seconds: int = 120,
        renew_seconds: int = 30,
        retry_base_seconds: int = 5,
        job_timeout_seconds: int = 1800,
        queue_capacity: int = 100,
        max_attempts: int = 3,
        reconcile_batch_size: int = 100,
        staging_max_age_seconds: int = 3600,
        staging_cleanup_batch_size: int = 100,
        terminal_retention_seconds: int = 604_800,
        terminal_cleanup_batch_size: int = 100,
        reconcile_interval_seconds: int = 30,
        metrics: PcapOffsetIndexMetrics | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        monotonic: Callable[[], float] = time.monotonic,
        heartbeat_repository_factory: Callable[[], tuple[Any, Callable[[], None]]] | None = None,
        fatal_event: Event | None = None,
    ) -> None:
        self.repository = repository
        self.builder = builder
        self.lease_seconds = lease_seconds
        self.renew_seconds = renew_seconds
        self.retry_base_seconds = retry_base_seconds
        self.job_timeout_seconds = job_timeout_seconds
        self.queue_capacity = queue_capacity
        self.max_attempts = max_attempts
        self.reconcile_batch_size = reconcile_batch_size
        self.staging_max_age_seconds = staging_max_age_seconds
        self.staging_cleanup_batch_size = staging_cleanup_batch_size
        self.terminal_retention_seconds = terminal_retention_seconds
        self.terminal_cleanup_batch_size = terminal_cleanup_batch_size
        self.reconcile_interval_seconds = reconcile_interval_seconds
        self.metrics = metrics
        self.now = now
        self.monotonic = monotonic
        self.heartbeat_repository_factory = heartbeat_repository_factory
        self.fatal_stop = False
        self.fatal_event = fatal_event

    def _metric(self, method: str, *args: Any) -> None:
        if self.metrics is None:
            return
        try:
            getattr(self.metrics, method)(*args)
        except Exception:
            logger.debug("PCAP offset index metric update failed", exc_info=True)

    def _fatal_requested(self) -> bool:
        return self.fatal_stop or bool(self.fatal_event is not None and self.fatal_event.is_set())

    def _set_fatal(self) -> None:
        self.fatal_stop = True
        if self.fatal_event is not None:
            self.fatal_event.set()

    def _fail_claimed_setup(
        self,
        claimed: Any,
        *,
        error_code: str,
        reason: str,
    ) -> bool:
        token = claimed.lease_token
        if token is None:
            self._set_fatal()
            return False
        try:
            won = self.repository.fail_live_segment_index(
                claimed.spec.source_id,
                attempt=claimed.attempt,
                lease_token=token,
                transient=True,
                error_code=error_code,
                now=self.now(),
                retry_base_seconds=self.retry_base_seconds,
            )
        except Exception:
            logger.exception("PCAP offset index primary repository failure CAS unavailable")
            self._set_fatal()
            return False
        self._metric(
            "task",
            "LIVE_SEGMENT",
            "retry" if won else "stale",
            reason if won else "lease_lost",
        )
        return True

    def startup(self) -> None:
        now = self.now()
        operations: tuple[Callable[[], Any], ...] = (
            lambda: self.repository.recover_live_segment_indexes(now=now),
            lambda: self.repository.reconcile_live_segment_indexes(
                capacity=self.queue_capacity,
                max_attempts=self.max_attempts,
                limit=self.reconcile_batch_size,
            ),
            lambda: self.repository.cleanup_stale_structural_indexes(
                before=now - timedelta(seconds=self.staging_max_age_seconds),
                limit=self.staging_cleanup_batch_size,
            ),
            lambda: self.repository.cleanup_terminal_live_segment_indexes(
                before=now - timedelta(seconds=self.terminal_retention_seconds),
                limit=self.terminal_cleanup_batch_size,
            ),
        )
        for operation in operations:
            try:
                operation()
            except Exception:
                logger.warning("PCAP offset index maintenance operation failed", exc_info=True)
        self._reconcile_metrics()

    def _reconcile_metrics(self) -> None:
        try:
            self._metric("reconcile_depth", self.repository.get_live_segment_index_queue_depth())
        except Exception:
            logger.debug("PCAP offset index depth reconciliation failed", exc_info=True)

    def run_once(self) -> bool:
        if self._fatal_requested():
            return False
        claimed = self.repository.claim_live_segment_index(
            now=self.now(), lease_seconds=self.lease_seconds
        )
        if claimed is None:
            return False
        if self._fatal_requested():
            self._fail_claimed_setup(
                claimed,
                error_code="INDEX_WORKER_FATAL",
                reason="storage",
            )
            return False
        source_id = claimed.spec.source_id
        attempt = claimed.attempt
        token = claimed.lease_token
        if token is None:
            return True
        heartbeat_repository = self.repository

        def close_heartbeat() -> None:
            return None

        if self.heartbeat_repository_factory is not None:
            try:
                heartbeat_repository, close_heartbeat = self.heartbeat_repository_factory()
            except Exception:
                logger.warning("PCAP offset index heartbeat repository unavailable", exc_info=True)
                return self._fail_claimed_setup(
                    claimed,
                    error_code="INDEX_HEARTBEAT_UNAVAILABLE",
                    reason="storage",
                )
        heartbeat_stopped = Event()

        def heartbeat() -> None:
            while not heartbeat_stopped.wait(self.renew_seconds):
                try:
                    won = heartbeat_repository.heartbeat_live_segment_index(
                        source_id,
                        attempt=attempt,
                        lease_token=token,
                        now=self.now(),
                        lease_seconds=self.lease_seconds,
                    )
                except Exception:
                    logger.warning("PCAP offset index heartbeat failed", exc_info=True)
                    return
                if not won:
                    return

        heart = threading.Thread(
            target=heartbeat, name=f"pcap-offset-index-heartbeat-{source_id}", daemon=True
        )
        heart.start()
        started = self.monotonic()
        cancelled = Event()
        finished = Event()
        result: list[bool] = []
        failure: list[BaseException] = []

        def deadline_reached() -> bool:
            return cancelled.is_set() or self.monotonic() - started >= self.job_timeout_seconds

        def execute() -> None:
            try:
                result.append(
                    self.builder(
                        self.repository,
                        source_id,
                        attempt=attempt,
                        lease_token=token,
                        should_cancel=deadline_reached,
                    )
                )
            except BaseException as exc:
                failure.append(exc)
            finally:
                finished.set()

        operation = threading.Thread(
            target=execute, name=f"pcap-offset-index-build-{source_id}", daemon=True
        )
        operation.start()
        transient = False
        code = "INDEX_BUILD_REJECTED"
        reason = "build_rejected"
        try:
            completed_in_time = finished.wait(float(self.job_timeout_seconds))
            if not completed_in_time or self.monotonic() - started >= self.job_timeout_seconds:
                cancelled.set()
                self.fatal_stop = operation.is_alive()
                if self.fatal_stop and self.fatal_event is not None:
                    self.fatal_event.set()
                transient, code, reason = True, "INDEX_BUILD_TIMEOUT", "timeout"
            elif failure:
                raise failure[0]
            elif result and result[0]:
                # Publication owns the completion CAS transaction.
                self._metric("task", "LIVE_SEGMENT", "completed", "none")
                return True
        except LiveIndexTransientError as exc:
            transient, code = True, exc.code
            reason = "timeout" if exc.code == "INDEX_BUILD_TIMEOUT" else "storage"
            logger.warning("PCAP offset index transient build failure", exc_info=True)
        except LiveIndexPermanentError as exc:
            transient, code, reason = False, exc.code, "build_rejected"
            logger.warning("PCAP offset index permanently rejected source", exc_info=True)
        except (OSError, ConnectionError, TimeoutError):
            transient, code, reason = True, "INDEX_STORAGE_UNAVAILABLE", "storage"
            logger.warning("PCAP offset index storage temporarily unavailable", exc_info=True)
        except (ValueError, TypeError):
            transient, code, reason = False, "INDEX_MALFORMED_SOURCE", "build_rejected"
            logger.warning("PCAP offset index source is malformed", exc_info=True)
        except Exception:
            transient, code, reason = False, "INDEX_BUILD_FAILED", "build_rejected"
            logger.exception("PCAP offset index build failed")
        finally:
            heartbeat_stopped.set()
            heart.join(timeout=max(1.0, float(self.renew_seconds) + 1.0))
            try:
                close_heartbeat()
            except Exception:
                logger.warning("PCAP offset index heartbeat repository close failed", exc_info=True)
        won = self.repository.fail_live_segment_index(
            source_id,
            attempt=attempt,
            lease_token=token,
            transient=transient,
            error_code=code,
            now=self.now(),
            retry_base_seconds=self.retry_base_seconds,
        )
        self._metric(
            "task",
            "LIVE_SEGMENT",
            "retry" if transient and won else "failed" if won else "stale",
            reason if won else "lease_lost",
        )
        return True

    def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
        if stopped.is_set():
            return
        self.startup()
        next_maintenance = self.monotonic() + self.reconcile_interval_seconds
        while not stopped.is_set() and not self._fatal_requested():
            if self.monotonic() >= next_maintenance:
                self.startup()
                next_maintenance = self.monotonic() + self.reconcile_interval_seconds
            if self._fatal_requested():
                break
            if not self.run_once():
                stopped.wait(idle_seconds)


def create_pcap_offset_index_worker(
    repository: Any,
    settings: Settings,
    metrics: PcapOffsetIndexMetrics | None = None,
    fatal_event: Event | None = None,
) -> PcapOffsetIndexWorker:
    def build(repository: Any, source_id: str, **lease: Any) -> bool:
        max_packets = settings.pcap_offset_index_max_packets
        if max_packets is None:
            raise RuntimeError("PCAP offset index packet bound was not resolved")
        return build_live_segment_index(
            repository,
            source_id,
            max_packets=max_packets,
            max_interfaces=settings.pcap_offset_index_max_interfaces,
            batch_size=settings.pcap_offset_index_batch_size,
            **lease,
        )

    def heartbeat_factory() -> tuple[Any, Callable[[], None]]:
        background = repository.for_background_worker()
        return background, background.close

    return PcapOffsetIndexWorker(
        repository,
        build,
        lease_seconds=settings.pcap_offset_index_lease_seconds,
        renew_seconds=settings.pcap_offset_index_lease_renew_seconds,
        retry_base_seconds=settings.pcap_offset_index_retry_base_seconds,
        job_timeout_seconds=settings.pcap_offset_index_job_timeout_seconds,
        queue_capacity=settings.pcap_offset_index_queue_capacity,
        max_attempts=settings.pcap_offset_index_max_attempts,
        reconcile_batch_size=settings.pcap_offset_index_reconcile_batch_size,
        staging_max_age_seconds=settings.pcap_offset_index_staging_max_age_seconds,
        staging_cleanup_batch_size=settings.pcap_offset_index_cleanup_batch_size,
        terminal_retention_seconds=settings.pcap_offset_index_terminal_retention_seconds,
        terminal_cleanup_batch_size=settings.pcap_offset_index_terminal_cleanup_batch_size,
        reconcile_interval_seconds=settings.pcap_offset_index_reconcile_interval_seconds,
        metrics=metrics,
        heartbeat_repository_factory=heartbeat_factory,
        fatal_event=fatal_event,
    )


def worker_ready(repository: Any) -> bool:
    try:
        return bool(repository.ready())
    except Exception:
        return False


def parse_worker_command(argv: list[str]) -> str:
    parser = argparse.ArgumentParser(description="Durable LIVE PCAP offset index worker")
    parser.add_argument(
        "command", nargs="?", default="run", choices=("run", "readiness", "healthcheck")
    )
    return str(parser.parse_args(argv).command)


def main(argv: list[str] | None = None) -> int:
    command = parse_worker_command(sys.argv[1:] if argv is None else argv)
    settings = Settings()
    if not settings.database_url.startswith(("postgresql://", "postgres://")):
        raise RuntimeError("PCAP offset index worker requires PostgreSQL")
    if settings.s3_endpoint == "memory://":
        raise RuntimeError("PCAP offset index worker requires configured MinIO/S3 storage")
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
        return 1 if command in {"readiness", "healthcheck"} else 2
    if command in {"readiness", "healthcheck"}:
        repository.close()
        return 0
    registry = CollectorRegistry()
    metrics = PcapOffsetIndexMetrics(registry)
    start_http_server(settings.pcap_offset_index_metrics_port, registry=registry)
    stopped = Event()
    fatal = Event()
    signal.signal(signal.SIGTERM, lambda *_args: stopped.set())
    signal.signal(signal.SIGINT, lambda *_args: stopped.set())
    repositories = [repository]
    repositories.extend(
        repository.for_background_worker()
        for _ in range(settings.pcap_offset_index_worker_concurrency - 1)
    )
    workers = [
        create_pcap_offset_index_worker(item, settings, metrics, fatal) for item in repositories
    ]
    threads = [
        threading.Thread(
            target=worker.run,
            args=(stopped,),
            name=f"pcap-offset-index-worker-{index + 1}",
            daemon=True,
        )
        for index, worker in enumerate(workers)
    ]
    try:
        for thread in threads:
            thread.start()
        while any(thread.is_alive() for thread in threads) and not stopped.is_set():
            if fatal.wait(0.05):
                stopped.set()
                break
    finally:
        stopped.set()
        deadline = time.monotonic() + settings.pcap_offset_index_shutdown_grace_seconds
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        for thread, item in zip(threads, repositories, strict=True):
            if thread.is_alive():
                logger.error("PCAP offset index worker exceeded shutdown grace; lease will recover")
            elif not fatal.is_set():
                item.close()
    return 2 if fatal.is_set() else 0


if __name__ == "__main__":
    raise SystemExit(main())
