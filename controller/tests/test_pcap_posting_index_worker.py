from __future__ import annotations

import hashlib
import io
import ipaddress
import struct
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from typing import Any

import pytest
from c2hunter_analysis.pcap_index import scan_structural_packet_index
from prometheus_client import CollectorRegistry

from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    SourceIndexBinding,
    StructuralIndexSnapshot,
    structural_index_digest,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexPermanentError,
    PostingIndexTransientError,
    build_source_posting_index,
)
from c2hunter_controller.pcap_posting_index_metrics import PcapPostingIndexMetrics
from c2hunter_controller.pcap_posting_index_queue import (
    PostingIndexTask,
    PostingIndexTaskSpec,
    PostingIndexTaskStatus,
)
from c2hunter_controller.pcap_posting_index_worker import (
    PcapPostingIndexWorker,
    PostingIndexWorkerConfig,
    PostingOperationResult,
    PostingWorkerControl,
    create_posting_operation_builder,
    join_posting_workers,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

NOW = datetime(2026, 8, 26, tzinfo=UTC)


def task(source_id: str = "source-1") -> PostingIndexTask:
    spec = PostingIndexTaskSpec(
        "PCAP_UPLOAD",
        source_id,
        "version-1",
        12,
        "a" * 64,
        "PCAP",
        "structural-1",
        "b" * 64,
        1,
        1,
    )
    return PostingIndexTask(
        spec,
        PostingIndexTaskStatus.RUNNING,
        1,
        3,
        "lease-1",
        NOW + timedelta(seconds=60),
        NOW,
        NOW,
        NOW,
    )


def config(**changes: Any) -> PostingIndexWorkerConfig:
    values: dict[str, Any] = {
        "lease_seconds": 2,
        "renew_seconds": 0.01,
        "job_timeout_seconds": 3,
        "operation_join_seconds": 0.02,
        "reconcile_interval_seconds": 0.02,
    }
    values.update(changes)
    return PostingIndexWorkerConfig(**values)


class Repo:
    def __init__(self, tasks: list[PostingIndexTask] | None = None) -> None:
        self.tasks = list(tasks if tasks is not None else [task()])
        self.calls: list[tuple[str, Any]] = []
        self.lock = Lock()
        self.fail_result = True
        self.heartbeat_result = True
        self.recover_error: Exception | None = None
        self.backfill_error: Exception | None = None
        self.reconcile_error: Exception | None = None
        self.fail_error: Exception | None = None

    def recover_posting_indexes(self) -> int:
        self.calls.append(("recover", None))
        if self.recover_error:
            raise self.recover_error
        return 0

    def reconcile_posting_indexes(self, *, capacity: int, max_attempts: int, limit: int) -> int:
        self.calls.append(
            (
                "reconcile",
                {"capacity": capacity, "max_attempts": max_attempts, "limit": limit},
            )
        )
        if self.reconcile_error:
            raise self.reconcile_error
        return 0

    def request_posting_index_backfill(self, *, limit: int) -> int:
        self.calls.append(("backfill", {"limit": limit}))
        if self.backfill_error:
            raise self.backfill_error
        return 0

    def cleanup_stale_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int:
        self.calls.append(("staging", {"max_age_seconds": max_age_seconds, "limit": limit}))
        return 0

    def cleanup_terminal_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int:
        self.calls.append(("terminal", {"max_age_seconds": max_age_seconds, "limit": limit}))
        return 0

    def get_posting_index_queue_depth(self) -> dict[str, int]:
        self.calls.append(("depth", None))
        return {"QUEUED": len(self.tasks), "RUNNING": 0, "COMPLETED": 0, "FAILED": 0}

    def claim_posting_index(self, *, lease_seconds: int) -> PostingIndexTask | None:
        with self.lock:
            self.calls.append(("claim", lease_seconds))
            return self.tasks.pop(0) if self.tasks else None

    def heartbeat_posting_index(
        self,
        source_kind: str,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> bool:
        self.calls.append(
            (
                "heartbeat-primary",
                (source_kind, source_id, attempt, lease_token, lease_seconds),
            )
        )
        return self.heartbeat_result

    def fail_posting_index(
        self,
        source_kind: str,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        retry_base_seconds: int,
    ) -> bool:
        self.calls.append(
            (
                "fail",
                (
                    source_kind,
                    source_id,
                    {
                        "attempt": attempt,
                        "lease_token": lease_token,
                        "transient": transient,
                        "error_code": error_code,
                        "retry_base_seconds": retry_base_seconds,
                    },
                ),
            )
        )
        if self.fail_error:
            raise self.fail_error
        return self.fail_result


class HeartbeatRepo:
    def __init__(self, *, result: bool = True, seen: Event | None = None) -> None:
        self.result = result
        self.seen = seen
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def heartbeat_posting_index(
        self,
        source_kind: str,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> bool:
        self.calls.append(
            (
                (source_kind, source_id),
                {
                    "attempt": attempt,
                    "lease_token": lease_token,
                    "lease_seconds": lease_seconds,
                },
            )
        )
        if self.seen:
            self.seen.set()
        return self.result


@dataclass
class Recorder:
    calls: list[tuple[str, tuple[Any, ...]]]

    def task(self, *args: Any) -> None:
        self.calls.append(("task", args))

    def reconcile_depth(self, *args: Any) -> None:
        self.calls.append(("depth", args))

    def build(self, *args: Any) -> None:
        self.calls.append(("build", args))

    def generation(self, *args: Any) -> None:
        self.calls.append(("generation", args))


def factory(
    heartbeat: HeartbeatRepo | None = None, close: Event | None = None
) -> tuple[HeartbeatRepo, Any]:
    return heartbeat or HeartbeatRepo(), (close.set if close else lambda: None)


def operation(value: Any = True) -> Any:
    def build(*_args: Any, **_kwargs: Any) -> Any:
        return lambda: value

    return build


def prepare_real_repository(
    repository: Any,
) -> tuple[CaptureSourceVersion, StructuralIndexSnapshot, Any]:
    payload = b"worker"
    udp = struct.pack("!HHHH", 50000, 443, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("10.0.0.8").packed,
        ipaddress.ip_address("203.0.113.8").packed,
    )
    packet = bytes.fromhex("0200000000020200000000010800") + ip + udp
    capture = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, len(packet), len(packet))
        + packet
    )
    digest = hashlib.sha256(capture).hexdigest()
    source_id = "worker-real-source"
    version = f"sha256:{digest}"
    repository.create_job(
        {
            "id": source_id,
            "idempotency_key": "worker-real-key",
            "mode": "PCAP_UPLOAD",
            "source": {
                "packet_bytes_retained": True,
                "size_bytes": len(capture),
                "sha256": digest,
                "capture_format": "PCAP",
            },
        }
    )
    repository.save_job_capture(source_id, capture)
    binding = SourceIndexBinding("PCAP_UPLOAD", source_id, version, len(capture), digest, "PCAP")
    scan = scan_structural_packet_index(io.BytesIO(capture), max_packets=10, max_interfaces=2)
    repository.begin_structural_index("worker-parent", binding, NOW)
    repository.stage_structural_index_packets("worker-parent", scan.packets)
    assert repository.publish_structural_index(
        "worker-parent", binding, scan.interfaces, scan.packet_count
    )
    parent = StructuralIndexSnapshot(
        "worker-parent",
        binding,
        NOW,
        structural_index_digest(binding, scan.interfaces, scan.packets),
        scan.interfaces,
        scan.packets,
    )
    source_version = CaptureSourceVersion(
        "PCAP_UPLOAD",
        source_id,
        f"captures/{source_id}.pcap",
        version,
        len(capture),
        digest,
    )

    class Source(io.BytesIO):
        version_id = version

    snapshot = build_source_posting_index(
        Source(capture),
        source_version=source_version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id="worker-posting",
        clock=lambda: NOW,
    )
    assert repository.request_posting_index(source_version, parent)
    assert (
        repository.admit_posting_index("PCAP_UPLOAD", source_id, capacity=2, max_attempts=3).value
        == "QUEUED"
    )
    return source_version, parent, snapshot


def test_worker_config_has_bounded_lifecycle_defaults() -> None:
    value = PostingIndexWorkerConfig()
    assert value.lease_seconds > 0
    assert 0 < value.renew_seconds <= value.lease_seconds / 2
    assert value.job_timeout_seconds > value.lease_seconds


@pytest.mark.parametrize(
    "changes,match",
    [
        ({"renew_seconds": 2, "lease_seconds": 2}, "renewal"),
        ({"job_timeout_seconds": 2, "lease_seconds": 2}, "timeout"),
        ({"queue_capacity": 0}, "positive"),
    ],
)
def test_worker_config_rejects_unsafe_bounds(changes: dict[str, Any], match: str) -> None:
    with pytest.raises(ValueError, match=match):
        config(**changes)


def test_success_is_atomic_publication_result_without_worker_completion_call() -> None:
    repo = Repo()
    close = Event()
    captured: dict[str, Any] = {}
    metrics = Recorder([])

    def builder(repository: Any, **kwargs: Any) -> Any:
        captured.update(kwargs)
        assert repository is repo
        return lambda: PostingOperationResult(True, 17, 23)

    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        metrics=metrics,
        heartbeat_repository_factory=lambda: factory(close=close),
    )

    assert worker.run_once()
    assert captured["task"].spec.source_id == "source-1"
    assert captured["attempt"] == 1 and captured["lease_token"] == "lease-1"
    assert callable(captured["should_cancel"]) and captured["deadline"] > 0
    assert not [call for call in repo.calls if call[0] == "fail"]
    assert not [call for call in repo.calls if call[0] == "complete"]
    assert close.is_set()
    assert ("generation", ("PCAP_UPLOAD", 17, 23)) in metrics.calls


@pytest.mark.parametrize(
    "raised,transient,code",
    [
        (
            PostingIndexTransientError("POSTING_SOURCE_READ_UNAVAILABLE"),
            True,
            "POSTING_SOURCE_READ_UNAVAILABLE",
        ),
        (PostingIndexPermanentError("POSTING_RESOURCE_LIMIT"), False, "POSTING_RESOURCE_LIMIT"),
        (OSError("secret-key"), True, "POSTING_STORAGE_UNAVAILABLE"),
        (ValueError("secret-address"), False, "POSTING_BUILD_REJECTED"),
        (RuntimeError("secret-token"), False, "POSTING_BUILD_FAILED"),
    ],
)
def test_typed_failures_map_to_stable_codes(raised: Exception, transient: bool, code: str) -> None:
    repo = Repo()

    def builder(*_args: Any, **_kwargs: Any) -> Any:
        def execute() -> bool:
            raise raised

        return execute

    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        heartbeat_repository_factory=factory,
    )
    assert worker.run_once()
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[2]["transient"] is transient
    assert failure[2]["error_code"] == code
    assert "secret" not in repr(failure)


def test_unbounded_typed_error_code_is_sanitized_before_failure_cas() -> None:
    repo = Repo()

    def builder(*_args: Any, **_kwargs: Any) -> Any:
        def execute() -> bool:
            raise PostingIndexTransientError("source-1/10.2.3.4/secret exception")

        return execute

    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        heartbeat_repository_factory=factory,
    )
    assert worker.run_once()
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[2]["error_code"] == "POSTING_BUILD_FAILED"


@pytest.mark.parametrize(
    "setup_error",
    [OSError("down"), ConnectionError("down"), TimeoutError("down"), RuntimeError("safe setup")],
)
def test_heartbeat_setup_failure_is_transient_and_does_not_build(setup_error: Exception) -> None:
    repo = Repo()
    builds = 0

    def builder(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal builds
        builds += 1
        return lambda: True

    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        heartbeat_repository_factory=lambda: (_ for _ in ()).throw(setup_error),
    )
    assert worker.run_once()
    failure = next(value for name, value in repo.calls if name == "fail")
    assert builds == 0
    assert failure[2]["transient"] is True
    assert failure[2]["error_code"] == "POSTING_HEARTBEAT_UNAVAILABLE"


def test_partial_heartbeat_factory_result_is_not_closed() -> None:
    repo = Repo()
    close_calls = 0

    def close() -> None:
        nonlocal close_calls
        close_calls += 1

    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(),
        heartbeat_repository_factory=lambda: (object(), close),  # type: ignore[return-value]
    )
    assert worker.run_once()
    assert close_calls == 0


def test_heartbeat_repository_closes_exactly_once_on_operation_failure() -> None:
    repo = Repo()
    closes = 0

    def close() -> None:
        nonlocal closes
        closes += 1

    worker = PcapPostingIndexWorker(
        repo,
        operation(False),
        config=config(),
        heartbeat_repository_factory=lambda: (HeartbeatRepo(), close),
    )
    assert worker.run_once()
    assert closes == 1


def test_setup_failure_cas_loss_is_stale_without_fatal() -> None:
    repo = Repo()
    repo.fail_result = False
    control = PostingWorkerControl.create()
    metrics = Recorder([])
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(),
        metrics=metrics,
        control=control,
        heartbeat_repository_factory=lambda: (_ for _ in ()).throw(OSError("down")),
    )
    assert worker.run_once()
    assert not control.fatal.is_set()
    assert ("task", ("PCAP_UPLOAD", "stale", "lease_lost")) in metrics.calls


def test_failure_cas_exception_sets_shared_fatal() -> None:
    repo = Repo()
    repo.fail_error = ConnectionError("primary down")
    control = PostingWorkerControl.create()
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(),
        control=control,
        heartbeat_repository_factory=lambda: (_ for _ in ()).throw(OSError("heartbeat down")),
    )
    assert worker.run_once() is False
    assert control.fatal.is_set() and control.stop.is_set() and worker.fatal_stop


def test_maintenance_order_bounds_and_safe_reconcile_failure() -> None:
    repo = Repo([])
    repo.reconcile_error = RuntimeError("temporary")
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(
            reconcile_batch_size=7, staging_cleanup_batch_size=8, terminal_cleanup_batch_size=9
        ),
        heartbeat_repository_factory=factory,
    )
    assert worker.run_once() is False
    names = [name for name, _value in repo.calls]
    assert names[:4] == ["recover", "reconcile", "staging", "terminal"]
    assert repo.calls[1][1]["limit"] == 7
    assert repo.calls[2][1]["limit"] == 8
    assert repo.calls[3][1]["limit"] == 9
    assert "claim" in names
    assert not any("live_segment" in name or "structural" in name for name in names)


def test_enabled_backfill_is_bounded_before_reconciliation() -> None:
    repo = Repo([])
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(backfill_enabled=True, backfill_batch_size=6),
        heartbeat_repository_factory=factory,
    )

    assert worker.run_once() is False
    names = [name for name, _value in repo.calls]
    assert names[:5] == ["recover", "backfill", "reconcile", "staging", "terminal"]
    assert repo.calls[1] == ("backfill", {"limit": 6})


def test_disabled_backfill_makes_zero_repository_calls() -> None:
    repo = Repo([])
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(backfill_enabled=False),
        heartbeat_repository_factory=factory,
    )

    assert worker.run_once() is False
    assert not [call for call in repo.calls if call[0] == "backfill"]


def test_backfill_failure_does_not_suppress_normal_recovery_reconcile_or_claim() -> None:
    repo = Repo()
    repo.backfill_error = RuntimeError("temporary backfill failure")
    metrics = Recorder([])
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(backfill_enabled=True, backfill_batch_size=4),
        metrics=metrics,
        heartbeat_repository_factory=factory,
    )

    assert worker.run_once()
    names = [name for name, _value in repo.calls]
    assert names.index("recover") < names.index("backfill") < names.index("reconcile")
    assert "claim" in names
    assert repo.calls[names.index("backfill")][1] == {"limit": 4}
    assert ("task", ("other", "failed", "storage")) in metrics.calls


def test_recovery_failure_makes_claim_unsafe() -> None:
    repo = Repo()
    repo.recover_error = RuntimeError("database unavailable")
    worker = PcapPostingIndexWorker(
        repo, operation(), config=config(), heartbeat_repository_factory=factory
    )
    assert worker.run_once() is False
    assert not [call for call in repo.calls if call[0] == "claim"]


def test_preclaim_shared_fatal_prevents_all_repository_work() -> None:
    repo = Repo()
    control = PostingWorkerControl.create()
    control.fatal.set()
    worker = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(),
        control=control,
        heartbeat_repository_factory=factory,
    )
    assert worker.run_once() is False
    assert repo.calls == []


def test_postclaim_shared_fatal_releases_exact_task_without_build() -> None:
    entered = Event()
    release = Event()
    repo = Repo()
    control = PostingWorkerControl.create()
    original_claim = repo.claim_posting_index

    def claim(**kwargs: Any) -> PostingIndexTask | None:
        claimed = original_claim(**kwargs)
        entered.set()
        assert release.wait(1)
        return claimed

    repo.claim_posting_index = claim  # type: ignore[method-assign]
    builds = 0

    def builder(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal builds
        builds += 1
        return lambda: True

    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        control=control,
        heartbeat_repository_factory=factory,
    )
    result: list[bool] = []
    thread = Thread(target=lambda: result.append(worker.run_once()), daemon=True)
    thread.start()
    assert entered.wait(1)
    control.fatal.set()
    release.set()
    thread.join(1)
    assert result == [False] and builds == 0
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[:2] == ("PCAP_UPLOAD", "source-1")
    assert failure[2]["error_code"] == "POSTING_WORKER_FATAL"


def test_heartbeat_loss_requests_cancel_and_records_stale_without_failure_publication() -> None:
    repo = Repo()
    heartbeat_seen = Event()
    cancelled = Event()

    def builder(*_args: Any, should_cancel: Any, **_kwargs: Any) -> Any:
        def execute() -> bool:
            assert heartbeat_seen.wait(1)
            if should_cancel():
                cancelled.set()
            return False

        return execute

    metrics = Recorder([])
    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        metrics=metrics,
        heartbeat_repository_factory=lambda: factory(
            HeartbeatRepo(result=False, seen=heartbeat_seen)
        ),
    )
    assert worker.run_once()
    assert cancelled.is_set()
    assert not [call for call in repo.calls if call[0] == "fail"]
    assert ("task", ("PCAP_UPLOAD", "stale", "lease_lost")) in metrics.calls
    assert not [call for call in metrics.calls if call[0] == "generation"]


def test_hard_timeout_returns_promptly_sets_fatal_and_retains_orphan_repositories() -> None:
    repo = Repo()
    entered = Event()
    release = Event()
    close_calls = 0
    ticks = 0

    def monotonic() -> float:
        nonlocal ticks
        ticks += 1
        return 0.0 if ticks == 1 else 4.0

    def close() -> None:
        nonlocal close_calls
        close_calls += 1

    def builder(*_args: Any, **_kwargs: Any) -> Any:
        def execute() -> bool:
            entered.set()
            return release.wait(2)

        return execute

    control = PostingWorkerControl.create()
    worker = PcapPostingIndexWorker(
        repo,
        builder,
        config=config(),
        control=control,
        heartbeat_repository_factory=lambda: (HeartbeatRepo(), close),
        monotonic=monotonic,
    )
    thread = Thread(target=worker.run_once, daemon=True)
    thread.start()
    assert entered.wait(0.5)
    thread.join(0.5)
    assert not thread.is_alive()
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[2]["transient"] is True
    assert failure[2]["error_code"] == "POSTING_BUILD_TIMEOUT"
    assert control.fatal.is_set() and worker.fatal_stop
    assert close_calls == 0 and worker._orphan is not None
    release.set()
    worker._orphan.join(1)
    assert not worker._orphan.is_alive()
    assert close_calls == 1
    # The main and operation-thread finally paths may both invoke the closer.
    assert worker._orphan_heartbeat_close is not None
    worker._orphan_heartbeat_close()
    assert close_calls == 1


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_real_repository_worker_publication_atomically_completes_once(
    tmp_path: Any, kind: str
) -> None:
    primary = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "worker-posting.sqlite")
    )
    source_version, parent, snapshot = prepare_real_repository(primary)
    heartbeat_facade = (
        None if kind == "memory" else SQLiteRepository(tmp_path / "worker-posting.sqlite")
    )
    close_calls = 0

    def close_heartbeat() -> None:
        nonlocal close_calls
        close_calls += 1
        if heartbeat_facade is not None:
            heartbeat_facade.close()

    def build(repository: Any, *, task: PostingIndexTask, **_kwargs: Any) -> Any:
        def execute() -> PostingOperationResult:
            repository.begin_posting_index(
                snapshot,
                attempt=task.attempt,
                lease_token=task.lease_token,
            )
            repository.stage_posting_index_chunks(
                snapshot.build_id,
                snapshot.generation.chunks,
                source_kind=task.spec.source_kind,
                source_id=task.spec.source_id,
                attempt=task.attempt,
                lease_token=task.lease_token,
            )
            assert repository.publish_posting_index(
                snapshot.build_id,
                source_version=source_version,
                parent=parent,
                attempt=task.attempt,
                lease_token=task.lease_token,
            )
            return PostingOperationResult(
                True,
                snapshot.generation.membership_count,
                snapshot.generation.encoded_byte_count,
            )

        return execute

    worker = PcapPostingIndexWorker(
        primary,
        build,
        config=config(),
        heartbeat_repository_factory=lambda: (
            heartbeat_facade or HeartbeatRepo(),
            close_heartbeat,
        ),
    )
    assert worker.run_once()
    assert close_calls == 1
    assert (
        primary.get_posting_index(source_version, parent).availability
        is PostingIndexAvailability.READY
    )
    completed = primary.get_posting_index_task("PCAP_UPLOAD", source_version.source_id)
    assert completed is not None and completed.status is PostingIndexTaskStatus.COMPLETED
    assert worker.run_once() is False
    assert primary.get_posting_index_task("PCAP_UPLOAD", source_version.source_id) == completed
    primary.close()


def test_production_factory_worker_emits_real_generation_metrics_exactly_once() -> None:
    repository = MemoryRepository()
    _source, _parent, snapshot = prepare_real_repository(repository)
    registry = CollectorRegistry()
    worker = PcapPostingIndexWorker(
        repository,
        create_posting_operation_builder(Settings(environment="test"), monotonic=lambda: 0.0),
        config=config(),
        metrics=PcapPostingIndexMetrics(registry),
        heartbeat_repository_factory=factory,
        monotonic=lambda: 0.0,
    )

    assert worker.run_once()
    assert worker.run_once() is False
    samples = {
        (sample.name, sample.labels.get("source_kind")): sample.value
        for metric in registry.collect()
        for sample in metric.samples
    }
    assert samples[("c2hunter_pcap_posting_index_memberships_total", "PCAP_UPLOAD")] == (
        snapshot.generation.membership_count
    )
    assert samples[("c2hunter_pcap_posting_index_encoded_bytes_total", "PCAP_UPLOAD")] == (
        snapshot.generation.encoded_byte_count
    )


def test_production_factory_deduplicates_completion_callback_before_worker_metrics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    _source, _parent, snapshot = prepare_real_repository(repository)
    registry = CollectorRegistry()

    def fake_build(*_args: Any, on_published: Any, **_kwargs: Any) -> bool:
        on_published(snapshot)
        on_published(snapshot)
        return True

    monkeypatch.setattr(
        "c2hunter_controller.pcap_posting_index_worker.build_and_publish_source_posting_index",
        fake_build,
    )
    worker = PcapPostingIndexWorker(
        repository,
        create_posting_operation_builder(Settings(environment="test"), monotonic=lambda: 0.0),
        config=config(),
        metrics=PcapPostingIndexMetrics(registry),
        heartbeat_repository_factory=factory,
        monotonic=lambda: 0.0,
    )

    assert worker.run_once()
    generation_samples = [
        sample
        for metric in registry.collect()
        for sample in metric.samples
        if sample.name
        in {
            "c2hunter_pcap_posting_index_memberships_total",
            "c2hunter_pcap_posting_index_encoded_bytes_total",
        }
        and sample.labels.get("source_kind") == "PCAP_UPLOAD"
    ]
    assert {sample.name: sample.value for sample in generation_samples} == {
        "c2hunter_pcap_posting_index_memberships_total": snapshot.generation.membership_count,
        "c2hunter_pcap_posting_index_encoded_bytes_total": snapshot.generation.encoded_byte_count,
    }


def test_default_memory_heartbeat_borrows_primary_without_closing_it() -> None:
    primary = MemoryRepository(_lease_clock=lambda: NOW)
    prepare_real_repository(primary)
    close_calls = 0

    def close() -> None:
        nonlocal close_calls
        close_calls += 1

    primary.close = close  # type: ignore[method-assign]
    worker = PcapPostingIndexWorker(primary, operation(), config=config())

    assert worker.run_once()
    assert close_calls == 0
    assert primary.get_posting_index_queue_depth()["RUNNING"] == 1


def test_default_sqlite_heartbeat_closes_only_facade_and_leaves_primary_usable(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    primary = SQLiteRepository(tmp_path / "default-heartbeat.sqlite", _lease_clock=lambda: NOW)
    prepare_real_repository(primary)
    original_close = SQLiteRepository.close
    closed: list[SQLiteRepository] = []

    def close(repository: SQLiteRepository) -> None:
        closed.append(repository)
        original_close(repository)

    monkeypatch.setattr(SQLiteRepository, "close", close)
    worker = PcapPostingIndexWorker(primary, operation(), config=config())

    assert worker.run_once()
    assert len(closed) == 1 and closed[0] is not primary
    assert primary.get_posting_index_queue_depth()["RUNNING"] == 1
    assert primary.connection.execute("SELECT 1").fetchone() == (1,)
    original_close(primary)


def test_deleted_or_reclaimed_task_maps_operation_failure_to_stale() -> None:
    repo = Repo()
    repo.fail_result = False
    metrics = Recorder([])

    def deleted(*_args: Any, **_kwargs: Any) -> Any:
        def execute() -> bool:
            raise PostingIndexPermanentError("POSTING_SOURCE_MISSING")

        return execute

    worker = PcapPostingIndexWorker(
        repo,
        deleted,
        config=config(),
        metrics=metrics,
        heartbeat_repository_factory=factory,
    )
    assert worker.run_once()
    assert ("task", ("PCAP_UPLOAD", "stale", "lease_lost")) in metrics.calls


def test_two_real_workers_have_zero_claim_growth_after_peer_fatal() -> None:
    repo = Repo([task("timeout-source")])
    release = Event()
    control = PostingWorkerControl.create()
    ticks = 0

    def monotonic() -> float:
        nonlocal ticks
        with repo.lock:
            ticks += 1
            return 0.0 if ticks == 1 else 4.0

    timeout_worker = PcapPostingIndexWorker(
        repo,
        lambda *_args, **_kwargs: lambda: release.wait(2),
        config=config(),
        control=control,
        heartbeat_repository_factory=factory,
        monotonic=monotonic,
    )
    peer = PcapPostingIndexWorker(
        repo,
        operation(),
        config=config(),
        control=control,
        heartbeat_repository_factory=factory,
    )
    timeout_thread = Thread(target=timeout_worker.run_once, daemon=True, name="timeout-worker")
    peer_thread = Thread(target=peer.run, args=(control.stop,), daemon=True, name="peer-worker")
    timeout_thread.start()
    peer_thread.start()
    assert control.fatal.wait(1)
    claims_at_fatal = len([call for call in repo.calls if call[0] == "claim"])
    repo.tasks.append(task("must-not-claim"))
    control.stop.wait(0.05)
    timeout_thread.join(1)
    peer_thread.join(1)
    claims_after = len([call for call in repo.calls if call[0] == "claim"])
    assert claims_after == claims_at_fatal
    assert len(repo.tasks) == 1
    joined = join_posting_workers([timeout_thread, peer_thread], control, grace_seconds=0.1)
    assert joined.fatal and joined.alive == ()
    release.set()
