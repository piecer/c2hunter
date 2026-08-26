from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Event, Lock, Thread
from typing import Any, Protocol, TypeGuard
from uuid import uuid4

from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
    PostingBuildLimits,
)

from .config import Settings
from .pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexLookup,
)
from .pcap_posting_index import (
    PostingIndexPermanentError,
    PostingIndexSnapshot,
    PostingIndexTransientError,
    build_and_publish_source_posting_index,
)
from .pcap_posting_index_metrics import PcapPostingIndexMetrics
from .pcap_posting_index_queue import (
    PostingIndexTask,
    PostingIndexTaskStatus,
    PostingSourceKind,
    sanitize_error_code,
)

logger = logging.getLogger(__name__)


class CaptureSource(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...

    def close(self) -> None: ...


def _is_capture_source(value: object) -> TypeGuard[CaptureSource]:
    return callable(getattr(value, "read", None)) and callable(getattr(value, "close", None))


def _close_rejected_source(value: object) -> None:
    close = getattr(value, "close", None)
    if callable(close):
        try:
            close()
        except Exception:
            logger.warning("rejected posting source close failed", exc_info=True)


class PostingIndexRepository(Protocol):
    def get_capture_source_version(self, source_id: str) -> CaptureSourceVersion | None: ...

    def get_live_capture_source_version(self, source_id: str) -> CaptureSourceVersion | None: ...

    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup: ...

    def open_job_capture(self, source_id: str) -> Any | None: ...

    def open_sensor_pcap(self, source_id: str) -> tuple[dict[str, Any], Any] | None: ...

    def recover_posting_indexes(self) -> int: ...

    def request_posting_index_backfill(self, *, limit: int) -> int: ...

    def reconcile_posting_indexes(self, *, capacity: int, max_attempts: int, limit: int) -> int: ...

    def claim_posting_index(self, *, lease_seconds: int) -> PostingIndexTask | None: ...

    def heartbeat_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> bool: ...

    def fail_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        retry_base_seconds: int,
    ) -> bool: ...

    def cleanup_terminal_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int: ...

    def cleanup_stale_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int: ...

    def abort_posting_index(
        self,
        build_id: str,
        *,
        source_kind: PostingSourceKind,
        source_id: str,
        parent_structural_build_id: str,
        attempt: int,
        lease_token: str,
    ) -> bool: ...

    def get_posting_index_queue_depth(self) -> dict[str, int]: ...


class PostingIndexMetrics(Protocol):
    def task(self, source_kind: object, outcome: object, reason: object) -> None: ...

    def reconcile_depth(self, counts: Mapping[str, int]) -> None: ...

    def build(self, source_kind: object, outcome: object, seconds: float) -> None: ...

    def generation(self, source_kind: object, memberships: int, encoded_bytes: int) -> None: ...


@dataclass(frozen=True)
class PostingOperationResult:
    published: bool
    membership_count: int = 0
    encoded_byte_count: int = 0


class PostingIndexOperation(Protocol):
    def __call__(self) -> PostingOperationResult | bool: ...


class PostingIndexOperationBuilder(Protocol):
    def __call__(
        self,
        repository: PostingIndexRepository,
        *,
        task: PostingIndexTask,
        attempt: int,
        lease_token: str,
        deadline: float,
        should_cancel: Callable[[], bool],
    ) -> PostingIndexOperation: ...


type HeartbeatRepositoryFactory = Callable[[], tuple[PostingIndexRepository, Callable[[], None]]]


def create_posting_operation_builder(
    settings: Settings,
    *,
    monotonic: Callable[[], float] = time.monotonic,
) -> PostingIndexOperationBuilder:
    """Create the production operation seam for one already-claimed posting task."""

    limits = PostingBuildLimits(
        max_packets=settings.pcap_posting_index_build_max_packets,
        max_memberships=settings.pcap_posting_index_build_max_memberships,
        max_distinct_keys=settings.pcap_posting_index_build_max_distinct_keys,
        max_encoded_bytes=settings.pcap_posting_index_build_max_encoded_bytes,
        max_chunks=settings.pcap_posting_index_build_max_chunks,
        batch_size=settings.pcap_posting_index_build_batch_size,
    )
    stage_batch_size = settings.pcap_posting_index_build_batch_size

    def builder(
        repository: PostingIndexRepository,
        *,
        task: PostingIndexTask,
        attempt: int,
        lease_token: str,
        deadline: float,
        should_cancel: Callable[[], bool],
    ) -> PostingIndexOperation:
        def cancelled() -> bool:
            return should_cancel() or monotonic() >= deadline

        def execute() -> PostingOperationResult | bool:
            spec = task.spec
            if (
                task.status is not PostingIndexTaskStatus.RUNNING
                or task.attempt != attempt
                or task.lease_token != lease_token
            ):
                raise PostingIndexPermanentError("POSTING_TASK_STALE")
            if (
                spec.posting_schema_version != PCAP_POSTING_INDEX_SCHEMA_VERSION
                or spec.posting_parser_contract_version
                != PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION
                or spec.filter_contract_version != PCAP_FILTER_CONTRACT_VERSION
            ):
                raise PostingIndexPermanentError("POSTING_CONTRACT_UNSUPPORTED")
            if cancelled():
                raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")

            try:
                source_version = (
                    repository.get_capture_source_version(spec.source_id)
                    if spec.source_kind == "PCAP_UPLOAD"
                    else repository.get_live_capture_source_version(spec.source_id)
                )
            except Exception as exc:
                raise PostingIndexTransientError("POSTING_METADATA_UNAVAILABLE") from exc
            if source_version is None:
                raise PostingIndexPermanentError("POSTING_SOURCE_MISSING")
            if (
                source_version.source_kind != spec.source_kind
                or source_version.source_id != spec.source_id
                or source_version.source_version_id != spec.source_version_id
                or source_version.source_size_bytes != spec.source_size_bytes
                or source_version.source_sha256 != spec.source_sha256
            ):
                raise PostingIndexPermanentError("POSTING_SOURCE_STALE")

            try:
                structural_binding = SourceIndexBinding(
                    source_version.source_kind,
                    source_version.source_id,
                    source_version.source_version_id,
                    source_version.source_size_bytes,
                    source_version.source_sha256,
                    spec.capture_format,
                    spec.structural_schema_version,
                    spec.structural_parser_contract_version,
                )
                parent_lookup = repository.get_structural_index(structural_binding)
            except (TypeError, ValueError) as exc:
                raise PostingIndexPermanentError("POSTING_PARENT_INVALID") from exc
            except Exception as exc:
                raise PostingIndexTransientError("POSTING_METADATA_UNAVAILABLE") from exc
            if parent_lookup.availability is not IndexAvailability.READY:
                code = {
                    IndexAvailability.MISSING: "POSTING_PARENT_MISSING",
                    IndexAvailability.STALE: "POSTING_PARENT_STALE",
                    IndexAvailability.CORRUPT: "POSTING_PARENT_CORRUPT",
                    IndexAvailability.UNSUPPORTED_SCHEMA: "POSTING_PARENT_UNSUPPORTED",
                }.get(parent_lookup.availability, "POSTING_PARENT_INVALID")
                raise PostingIndexPermanentError(code)
            parent = parent_lookup.snapshot
            if (
                parent is None
                or parent.build_id != spec.parent_structural_build_id
                or parent.index_sha256 != spec.parent_structural_index_sha256
                or parent.binding != structural_binding
            ):
                raise PostingIndexPermanentError("POSTING_PARENT_STALE")
            if cancelled():
                raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")

            try:
                opened = (
                    repository.open_job_capture(spec.source_id)
                    if spec.source_kind == "PCAP_UPLOAD"
                    else repository.open_sensor_pcap(spec.source_id)
                )
            except Exception as exc:
                raise PostingIndexTransientError("POSTING_SOURCE_OPEN_UNAVAILABLE") from exc
            if opened is None:
                raise PostingIndexPermanentError("POSTING_SOURCE_MISSING")

            metadata: dict[str, Any] | None = None
            source_candidate: object
            if spec.source_kind == "LIVE_SEGMENT":
                if not isinstance(opened, tuple) or len(opened) != 2:
                    raise PostingIndexPermanentError("POSTING_SOURCE_INVALID")
                metadata_candidate, source_candidate = opened
                if not isinstance(metadata_candidate, dict):
                    _close_rejected_source(source_candidate)
                    raise PostingIndexPermanentError("POSTING_SOURCE_INVALID")
                metadata = metadata_candidate
            else:
                source_candidate = opened
            if not _is_capture_source(source_candidate):
                _close_rejected_source(source_candidate)
                raise PostingIndexPermanentError("POSTING_SOURCE_INVALID")
            source = source_candidate

            opened_matches = getattr(source, "version_id", None) in {
                None,
                source_version.source_version_id,
            }
            if metadata is not None:
                linked_object_key = metadata.get("object_key") or (
                    f"sensor-pcaps/{metadata.get('sensor_id')}/{spec.source_id}.pcap"
                )
                opened_matches = opened_matches and (
                    metadata.get("id") == spec.source_id
                    and linked_object_key == source_version.object_key
                    and metadata.get("size_bytes") == source_version.source_size_bytes
                    and metadata.get("sha256") == source_version.source_sha256
                )
            if not opened_matches:
                try:
                    source.close()
                except Exception:
                    logger.warning("stale posting source close failed", exc_info=True)
                raise PostingIndexPermanentError("POSTING_SOURCE_STALE")

            published_snapshot: PostingIndexSnapshot | None = None

            def capture_published(snapshot: PostingIndexSnapshot) -> None:
                nonlocal published_snapshot
                if published_snapshot is None:
                    published_snapshot = snapshot

            published = build_and_publish_source_posting_index(
                repository,
                source,
                source_version=source_version,
                parent=parent,
                # Direction is not a posting dimension, but the shared decoder requires
                # at least one valid internal-network contract. Universal networks make
                # direction classification deterministic without affecting postings.
                internal_networks=("0.0.0.0/0", "::/0"),
                build_id=uuid4().hex,
                attempt=attempt,
                lease_token=lease_token,
                now=datetime.now(UTC),
                limits=limits,
                stage_batch_size=stage_batch_size,
                should_cancel=cancelled,
                on_published=capture_published,
            )
            if not published:
                return False
            if published_snapshot is None:
                raise PostingIndexPermanentError("POSTING_PUBLICATION_RESULT_MISSING")
            return PostingOperationResult(
                published=True,
                membership_count=published_snapshot.generation.membership_count,
                encoded_byte_count=published_snapshot.generation.encoded_byte_count,
            )

        return execute

    return builder


class _CloseOnce:
    """Thread-safe ownership transfer for a heartbeat facade."""

    def __init__(self, callback: Callable[[], None]) -> None:
        self._callback = callback
        self._lock = Lock()
        self._closed = False

    def __call__(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._callback()
            except Exception:
                # Closing is best-effort under the existing worker policy; never double-close.
                logger.warning("posting heartbeat repository close failed", exc_info=True)


@dataclass(frozen=True)
class PostingIndexWorkerConfig:
    lease_seconds: float = 120
    renew_seconds: float = 30
    retry_base_seconds: int = 5
    job_timeout_seconds: float = 1800
    queue_capacity: int = 100
    max_attempts: int = 3
    reconcile_batch_size: int = 100
    backfill_enabled: bool = False
    backfill_batch_size: int = 100
    staging_max_age_seconds: int = 3600
    staging_cleanup_batch_size: int = 100
    terminal_retention_seconds: int = 604_800
    terminal_cleanup_batch_size: int = 100
    reconcile_interval_seconds: float = 30
    operation_join_seconds: float = 0.05

    def __post_init__(self) -> None:
        positive = (
            self.lease_seconds,
            self.renew_seconds,
            self.retry_base_seconds,
            self.job_timeout_seconds,
            self.queue_capacity,
            self.max_attempts,
            self.reconcile_batch_size,
            self.backfill_batch_size,
            self.staging_max_age_seconds,
            self.staging_cleanup_batch_size,
            self.terminal_retention_seconds,
            self.terminal_cleanup_batch_size,
            self.reconcile_interval_seconds,
            self.operation_join_seconds,
        )
        if any(value <= 0 for value in positive):
            raise ValueError("posting worker bounds must be positive")
        if self.renew_seconds > self.lease_seconds / 2:
            raise ValueError("posting lease renewal must be at most half the lease")
        if self.job_timeout_seconds <= self.lease_seconds:
            raise ValueError("posting build timeout must exceed the lease")
        if self.queue_capacity < 1:
            raise ValueError("posting queue capacity must be positive")


@dataclass
class PostingWorkerControl:
    stop: Event
    fatal: Event

    @classmethod
    def create(cls) -> PostingWorkerControl:
        return cls(Event(), Event())

    def fail(self) -> None:
        self.fatal.set()
        self.stop.set()


@dataclass(frozen=True)
class PostingWorkerJoinResult:
    fatal: bool
    alive: tuple[str, ...]


def join_posting_workers(
    threads: tuple[Thread, ...] | list[Thread],
    control: PostingWorkerControl,
    *,
    grace_seconds: float,
    monotonic: Callable[[], float] = time.monotonic,
) -> PostingWorkerJoinResult:
    control.stop.set()
    deadline = monotonic() + max(0.0, grace_seconds)
    for thread in threads:
        thread.join(timeout=max(0.0, deadline - monotonic()))
    alive = tuple(thread.name for thread in threads if thread.is_alive())
    return PostingWorkerJoinResult(control.fatal.is_set(), alive)


def _reason(code: str) -> str:
    if code == "POSTING_BUILD_TIMEOUT":
        return "timeout"
    if code == "POSTING_HEARTBEAT_UNAVAILABLE":
        return "heartbeat_unavailable"
    if code == "POSTING_WORKER_FATAL":
        return "worker_fatal"
    if "DELETED" in code or "MISSING" in code:
        return "deleted"
    if any(value in code for value in ("UNAVAILABLE", "STORAGE", "STAGING", "PUBLICATION")):
        return "storage"
    return "build_rejected"


class PcapPostingIndexWorker:
    """Direct durable posting worker; publication owns the successful completion CAS."""

    def __init__(
        self,
        repository: PostingIndexRepository,
        operation_builder: PostingIndexOperationBuilder,
        *,
        config: PostingIndexWorkerConfig | None = None,
        metrics: PostingIndexMetrics | None = None,
        heartbeat_repository_factory: HeartbeatRepositoryFactory | None = None,
        control: PostingWorkerControl | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.repository = repository
        self.operation_builder = operation_builder
        self.config = config or PostingIndexWorkerConfig()
        self.metrics = metrics
        self.heartbeat_repository_factory = heartbeat_repository_factory
        self.control = control or PostingWorkerControl.create()
        self.monotonic = monotonic
        self.fatal_stop = False
        self._orphan: Thread | None = None
        self._orphan_heartbeat_close: Callable[[], None] | None = None

    def _fatal_requested(self) -> bool:
        return self.fatal_stop or self.control.fatal.is_set()

    def _set_fatal(self) -> None:
        self.fatal_stop = True
        self.control.fail()

    def _metric(self, method: str, *args: object) -> None:
        if self.metrics is None:
            return
        try:
            getattr(self.metrics, method)(*args)
        except Exception:
            logger.debug("posting metric update failed", exc_info=True)

    def maintain(self) -> bool:
        """Recover before reconcile; failure to recover makes claiming unsafe."""
        try:
            self.repository.recover_posting_indexes()
        except Exception:
            logger.warning("posting lease recovery failed", exc_info=True)
            self._metric("task", "other", "failed", "storage")
            return False
        if self.config.backfill_enabled:
            try:
                self.repository.request_posting_index_backfill(
                    limit=self.config.backfill_batch_size
                )
            except Exception:
                logger.warning("posting bounded backfill failed", exc_info=True)
                self._metric("task", "other", "failed", "storage")
        try:
            self.repository.reconcile_posting_indexes(
                capacity=self.config.queue_capacity,
                max_attempts=self.config.max_attempts,
                limit=self.config.reconcile_batch_size,
            )
        except Exception:
            logger.warning("posting reconciliation failed", exc_info=True)
            self._metric("task", "other", "failed", "storage")
        cleanup_operations: tuple[Callable[[], int], ...] = (
            lambda: self.repository.cleanup_stale_posting_indexes(
                max_age_seconds=self.config.staging_max_age_seconds,
                limit=self.config.staging_cleanup_batch_size,
            ),
            lambda: self.repository.cleanup_terminal_posting_indexes(
                max_age_seconds=self.config.terminal_retention_seconds,
                limit=self.config.terminal_cleanup_batch_size,
            ),
        )
        for operation in cleanup_operations:
            try:
                operation()
            except Exception:
                logger.warning("posting bounded cleanup failed", exc_info=True)
                self._metric("task", "other", "failed", "storage")
        try:
            self._metric("reconcile_depth", self.repository.get_posting_index_queue_depth())
        except Exception:
            logger.debug("posting queue metric reconciliation failed", exc_info=True)
        return True

    def _fail_exact(
        self,
        task: PostingIndexTask,
        *,
        transient: bool,
        code: str,
        reason: str | None = None,
    ) -> bool | None:
        token = task.lease_token
        if token is None:
            self._set_fatal()
            return None
        stable_code = sanitize_error_code(code)
        try:
            won = self.repository.fail_posting_index(
                task.spec.source_kind,
                task.spec.source_id,
                attempt=task.attempt,
                lease_token=token,
                transient=transient,
                error_code=stable_code,
                retry_base_seconds=self.config.retry_base_seconds,
            )
        except Exception:
            logger.exception("posting failure CAS unavailable")
            self._set_fatal()
            return None
        outcome = "retry" if transient and won else "failed" if won else "stale"
        metric_reason = (reason or _reason(stable_code)) if won else "lease_lost"
        self._metric("task", task.spec.source_kind, outcome, metric_reason)
        return won

    def _heartbeat_factory(self) -> tuple[PostingIndexRepository, Callable[[], None]]:
        if self.heartbeat_repository_factory is not None:
            created = self.heartbeat_repository_factory()
        else:
            factory = getattr(self.repository, "for_background_worker", None)
            if not callable(factory):
                raise OSError("independent heartbeat repository unavailable")
            heartbeat_repository = factory()
            created = (
                heartbeat_repository,
                heartbeat_repository.close
                if heartbeat_repository is not self.repository
                else (lambda: None),
            )
        if (
            not isinstance(created, tuple)
            or len(created) != 2
            or not callable(created[1])
            or not callable(getattr(created[0], "heartbeat_posting_index", None))
        ):
            raise OSError("invalid heartbeat repository factory result")
        return created

    def run_once(self, stopped: Event | None = None, *, maintain: bool = True) -> bool:
        local_stop = stopped or self.control.stop
        if local_stop.is_set() or self._fatal_requested():
            return False
        if maintain and not self.maintain():
            return False
        if local_stop.is_set() or self._fatal_requested():
            return False
        try:
            task = self.repository.claim_posting_index(lease_seconds=int(self.config.lease_seconds))
        except Exception:
            logger.warning("posting claim failed", exc_info=True)
            self._metric("task", "other", "failed", "storage")
            return False
        if task is None:
            return False
        if local_stop.is_set() or self._fatal_requested():
            self._fail_exact(
                task, transient=True, code="POSTING_WORKER_FATAL", reason="worker_fatal"
            )
            return False
        lease_token = task.lease_token
        if lease_token is None:
            self._set_fatal()
            return False

        try:
            heartbeat_repository, heartbeat_close = self._heartbeat_factory()
        except Exception:
            logger.warning("posting heartbeat repository unavailable", exc_info=True)
            setup_result = self._fail_exact(
                task,
                transient=True,
                code="POSTING_HEARTBEAT_UNAVAILABLE",
                reason="heartbeat_unavailable",
            )
            return setup_result is not None
        close_heartbeat = _CloseOnce(heartbeat_close)

        cancel = Event()
        heartbeat_stop = Event()
        heartbeat_lost = Event()
        finished = Event()
        started = self.monotonic()
        deadline = started + self.config.job_timeout_seconds
        results: list[PostingOperationResult | bool] = []
        failures: list[BaseException] = []

        def should_cancel() -> bool:
            return cancel.is_set() or heartbeat_lost.is_set() or self.monotonic() >= deadline

        try:
            operation = self.operation_builder(
                self.repository,
                task=task,
                attempt=task.attempt,
                lease_token=lease_token,
                deadline=deadline,
                should_cancel=should_cancel,
            )
        except BaseException as exc:
            failures.append(exc)
            finished.set()

            def operation() -> bool:
                return False

        def execute() -> None:
            if finished.is_set():
                return
            try:
                results.append(operation())
            except BaseException as exc:
                failures.append(exc)
            finally:
                heartbeat_stop.set()
                finished.set()
                close_heartbeat()

        def heartbeat() -> None:
            while not heartbeat_stop.wait(self.config.renew_seconds):
                try:
                    won = heartbeat_repository.heartbeat_posting_index(
                        task.spec.source_kind,
                        task.spec.source_id,
                        attempt=task.attempt,
                        lease_token=lease_token,
                        lease_seconds=int(self.config.lease_seconds),
                    )
                except Exception:
                    won = False
                if not won:
                    heartbeat_lost.set()
                    cancel.set()
                    return

        heart = Thread(target=heartbeat, name="pcap-posting-heartbeat", daemon=True)
        build = Thread(target=execute, name="pcap-posting-build", daemon=True)
        heart.start()
        build.start()
        timed_out = False
        while not finished.is_set():
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if heartbeat_lost.is_set() or self._fatal_requested() or local_stop.is_set():
                break
            finished.wait(min(remaining, self.config.operation_join_seconds))

        if not finished.is_set() and not heartbeat_lost.is_set():
            timed_out = self.monotonic() >= deadline
        if timed_out:
            cancel.set()
            heartbeat_stop.set()
            heart.join(timeout=self.config.operation_join_seconds)
            self._fail_exact(task, transient=True, code="POSTING_BUILD_TIMEOUT", reason="timeout")
            self._set_fatal()
            build.join(timeout=self.config.operation_join_seconds)
            if build.is_alive():
                self._orphan = build
                self._orphan_heartbeat_close = close_heartbeat
                return True
        elif heartbeat_lost.is_set():
            cancel.set()
            build.join(timeout=self.config.operation_join_seconds)
            self._metric("task", task.spec.source_kind, "stale", "lease_lost")
        elif not finished.is_set():
            cancel.set()
            self._fail_exact(
                task, transient=True, code="POSTING_WORKER_FATAL", reason="worker_fatal"
            )
            build.join(timeout=self.config.operation_join_seconds)

        heartbeat_stop.set()
        heart.join(
            timeout=max(self.config.operation_join_seconds, self.config.renew_seconds + 0.05)
        )
        if build.is_alive():
            self._set_fatal()
            self._orphan = build
            self._orphan_heartbeat_close = close_heartbeat
            return True
        close_heartbeat()

        elapsed = max(0.0, self.monotonic() - started)
        if timed_out or heartbeat_lost.is_set() or not finished.is_set():
            build_outcome = "timeout" if timed_out else "stale"
            self._metric("build", task.spec.source_kind, build_outcome, elapsed)
            return True
        if failures:
            failure_exc = failures[0]
            if isinstance(failure_exc, PostingIndexTransientError):
                transient, code = True, failure_exc.code
            elif isinstance(failure_exc, PostingIndexPermanentError):
                transient, code = False, failure_exc.code
            elif isinstance(failure_exc, OSError | ConnectionError | TimeoutError):
                transient, code = True, "POSTING_STORAGE_UNAVAILABLE"
            elif isinstance(failure_exc, ValueError | TypeError):
                transient, code = False, "POSTING_BUILD_REJECTED"
            else:
                transient, code = False, "POSTING_BUILD_FAILED"
            won = self._fail_exact(task, transient=transient, code=code)
            self._metric("build", task.spec.source_kind, "failed" if won else "stale", elapsed)
            return won is not None
        operation_result = results[0] if results else False
        if operation_result is False or (
            isinstance(operation_result, PostingOperationResult) and not operation_result.published
        ):
            won = self._fail_exact(
                task, transient=False, code="POSTING_BUILD_REJECTED", reason="build_rejected"
            )
            self._metric("build", task.spec.source_kind, "failed" if won else "stale", elapsed)
            return won is not None
        self._metric("task", task.spec.source_kind, "completed", "none")
        self._metric("build", task.spec.source_kind, "completed", elapsed)
        if isinstance(operation_result, PostingOperationResult) and operation_result.published:
            self._metric(
                "generation",
                task.spec.source_kind,
                operation_result.membership_count,
                operation_result.encoded_byte_count,
            )
        return True

    def run(self, stopped: Event | None = None, *, idle_seconds: float = 0.25) -> None:
        local_stop = stopped or self.control.stop
        next_maintenance = 0.0
        while not local_stop.is_set() and not self._fatal_requested():
            at = self.monotonic()
            maintain = at >= next_maintenance
            worked = self.run_once(local_stop, maintain=maintain)
            if maintain:
                next_maintenance = at + self.config.reconcile_interval_seconds
            if not worked:
                local_stop.wait(idle_seconds)


# Concrete metrics type is intentionally re-exported for simple B2 wiring.
DefaultPostingIndexMetrics = PcapPostingIndexMetrics
