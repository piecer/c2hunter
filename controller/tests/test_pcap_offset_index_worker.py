from __future__ import annotations

import hashlib
import struct
import time
from datetime import UTC, datetime, timedelta
from threading import Event, Lock, Thread
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from c2hunter_controller import pcap_offset_index_worker as worker_module
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_offset_index import (
    IndexAvailability,
    LiveIndexTransientError,
    SourceIndexBinding,
    build_live_segment_index,
)
from c2hunter_controller.pcap_offset_index_metrics import PcapOffsetIndexMetrics
from c2hunter_controller.pcap_offset_index_queue import LiveIndexTask, LiveIndexTaskSpec
from c2hunter_controller.pcap_offset_index_worker import (
    PcapOffsetIndexWorker,
    parse_worker_command,
)
from c2hunter_controller.repositories import MemoryRepository

NOW = datetime(2026, 8, 25, tzinfo=UTC)


def task() -> LiveIndexTask:
    spec = LiveIndexTaskSpec("LIVE_SEGMENT", "segment-1", "sensor-1", "job-1", "key", 24, "a" * 64)
    return LiveIndexTask(spec, "RUNNING", 1, 3, "token", NOW + timedelta(seconds=60), NOW, NOW, NOW)


class Repo:
    def __init__(self) -> None:
        self.current: LiveIndexTask | None = task()
        self.calls: list[tuple[str, Any]] = []

    def claim_live_segment_index(
        self, *, now: datetime, lease_seconds: int
    ) -> LiveIndexTask | None:
        self.calls.append(("claim", lease_seconds))
        claimed, self.current = self.current, None
        return claimed

    def fail_live_segment_index(self, source_id: str, **kwargs: Any) -> bool:
        self.calls.append(("fail", (source_id, kwargs)))
        return True

    def heartbeat_live_segment_index(self, source_id: str, **kwargs: Any) -> bool:
        self.calls.append(("heartbeat", source_id))
        return True

    def recover_live_segment_indexes(self, *, now: datetime) -> int:
        self.calls.append(("recover", now))
        return 0

    def reconcile_live_segment_indexes(self, **kwargs: Any) -> int:
        self.calls.append(("reconcile", kwargs))
        return 0

    def cleanup_stale_structural_indexes(self, *, before: datetime, limit: int) -> int:
        self.calls.append(("staging", limit))
        return 0

    def cleanup_terminal_live_segment_indexes(self, *, before: datetime, limit: int) -> int:
        self.calls.append(("terminal", limit))
        return 0

    def get_live_segment_index_queue_depth(self) -> dict[str, int]:
        return {"QUEUED": 1, "RUNNING": 0, "COMPLETED": 2, "FAILED": 0}


def test_settings_stage10_defaults_and_cross_field_validation() -> None:
    settings = Settings(environment="test")
    assert {
        "live_enabled": settings.pcap_offset_index_live_enabled,
        "queue_capacity": settings.pcap_offset_index_queue_capacity,
        "worker_concurrency": settings.pcap_offset_index_worker_concurrency,
        "lease_seconds": settings.pcap_offset_index_lease_seconds,
        "lease_renew_seconds": settings.pcap_offset_index_lease_renew_seconds,
        "max_attempts": settings.pcap_offset_index_max_attempts,
        "retry_base_seconds": settings.pcap_offset_index_retry_base_seconds,
        "job_timeout_seconds": settings.pcap_offset_index_job_timeout_seconds,
        "reconcile_interval_seconds": settings.pcap_offset_index_reconcile_interval_seconds,
        "reconcile_batch_size": settings.pcap_offset_index_reconcile_batch_size,
        "staging_max_age_seconds": settings.pcap_offset_index_staging_max_age_seconds,
        "cleanup_batch_size": settings.pcap_offset_index_cleanup_batch_size,
        "terminal_retention_seconds": settings.pcap_offset_index_terminal_retention_seconds,
        "terminal_cleanup_batch_size": settings.pcap_offset_index_terminal_cleanup_batch_size,
        "shutdown_grace_seconds": settings.pcap_offset_index_shutdown_grace_seconds,
        "metrics_port": settings.pcap_offset_index_metrics_port,
    } == {
        "live_enabled": True,
        "queue_capacity": 100,
        "worker_concurrency": 1,
        "lease_seconds": 120,
        "lease_renew_seconds": 30,
        "max_attempts": 3,
        "retry_base_seconds": 5,
        "job_timeout_seconds": 1800,
        "reconcile_interval_seconds": 30,
        "reconcile_batch_size": 100,
        "staging_max_age_seconds": 3600,
        "cleanup_batch_size": 100,
        "terminal_retention_seconds": 604_800,
        "terminal_cleanup_batch_size": 100,
        "shutdown_grace_seconds": 30,
        "metrics_port": 9104,
    }
    assert (
        settings.pcap_offset_index_worker_concurrency <= settings.pcap_offset_index_queue_capacity
    )
    with pytest.raises(ValueError, match="renewal"):
        Settings(
            environment="test",
            pcap_offset_index_lease_seconds=10,
            pcap_offset_index_lease_renew_seconds=6,
        )
    with pytest.raises(ValueError, match="timeout"):
        Settings(
            environment="test",
            pcap_offset_index_lease_seconds=10,
            pcap_offset_index_job_timeout_seconds=10,
        )
    with pytest.raises(ValueError, match="concurrency"):
        Settings(
            environment="test",
            pcap_offset_index_queue_capacity=1,
            pcap_offset_index_worker_concurrency=2,
        )


def test_worker_success_relies_on_publication_to_complete_task() -> None:
    repo = Repo()
    worker = PcapOffsetIndexWorker(repo, lambda *_args, **_kwargs: True, now=lambda: NOW)
    assert worker.run_once() is True
    assert not [call for call in repo.calls if call[0] == "fail"]
    assert not [call for call in repo.calls if call[0] == "complete"]


def test_worker_false_is_failed_with_stable_permanent_code() -> None:
    repo = Repo()
    worker = PcapOffsetIndexWorker(repo, lambda *_args, **_kwargs: False, now=lambda: NOW)
    assert worker.run_once() is True
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[1]["transient"] is False
    assert failure[1]["error_code"] == "INDEX_BUILD_REJECTED"


def test_worker_storage_exception_retries_without_error_text_label() -> None:
    repo = Repo()

    def fail(*_args: Any, **_kwargs: Any) -> bool:
        raise OSError("secret object id")

    registry = CollectorRegistry()
    metrics = PcapOffsetIndexMetrics(registry)
    worker = PcapOffsetIndexWorker(repo, fail, metrics=metrics, now=lambda: NOW)
    assert worker.run_once() is True
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[1]["transient"] is True
    assert failure[1]["error_code"] == "INDEX_STORAGE_UNAVAILABLE"
    assert b"secret object id" not in generate_latest(registry)


def test_real_builder_open_oserror_is_typed_transient_with_chained_cause() -> None:
    class OpenFailure:
        def get_live_segment_index_metadata(self, _source_id: str) -> dict[str, Any]:
            return {"id": "segment-1"}

        def open_sensor_pcap(self, _source_id: str) -> None:
            raise OSError("object unavailable")

    with pytest.raises(LiveIndexTransientError) as raised:
        build_live_segment_index(
            OpenFailure(),
            "segment-1",
            max_packets=10,
            max_interfaces=4,
            batch_size=1,
            attempt=1,
            lease_token="token",
        )
    assert raised.value.code == "INDEX_SOURCE_OPEN_UNAVAILABLE"
    assert isinstance(raised.value.__cause__, OSError)


def test_real_builder_staging_db_failure_is_typed_transient() -> None:
    repository = MemoryRepository()
    content = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1, 2, 3, 3)
        + b"abc"
    )
    repository.save_job(
        {"id": "job-1", "mode": "LIVE", "status": "CAPTURING", "capture": {"store_pcap": True}}
    )
    repository.save_sensor_pcap_limited(
        {
            "id": "segment-1",
            "sensor_id": "sensor-1",
            "analysis_job_id": "job-1",
            "filename": "segment-1.pcap",
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
        content,
        None,
    )
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    claim = repository.claim_live_segment_index(now=datetime.now(UTC), lease_seconds=30)
    assert claim is not None and claim.lease_token
    repository.begin_structural_index = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("database unavailable")
    )
    with pytest.raises(LiveIndexTransientError) as raised:
        build_live_segment_index(
            repository,
            "segment-1",
            max_packets=10,
            max_interfaces=4,
            batch_size=1,
            attempt=claim.attempt,
            lease_token=claim.lease_token,
        )
    assert raised.value.code == "INDEX_STAGING_UNAVAILABLE"
    assert isinstance(raised.value.__cause__, RuntimeError)


def test_startup_maintenance_order_and_bounds() -> None:
    repo = Repo()
    repo.current = None
    worker = PcapOffsetIndexWorker(repo, lambda *_args, **_kwargs: True, now=lambda: NOW)
    worker.startup()
    assert [name for name, _ in repo.calls[:4]] == ["recover", "reconcile", "staging", "terminal"]


def test_metrics_have_only_frozen_low_cardinality_labels_and_reconcile_depth() -> None:
    registry = CollectorRegistry()
    metrics = PcapOffsetIndexMetrics(registry)
    metrics.admission("LIVE_SEGMENT", "queued")
    metrics.task("LIVE_SEGMENT", "completed", "none")
    metrics.reconcile_depth({"QUEUED": 1, "RUNNING": 2, "COMPLETED": 3, "FAILED": 4})
    text = generate_latest(registry).decode()
    assert 'source_kind="LIVE_SEGMENT"' in text
    assert 'status="QUEUED"' in text
    assert "source_id" not in text and "error=" not in text
    with pytest.raises(ValueError):
        metrics.admission("PCAP_UPLOAD", "queued")


def test_worker_command_contract() -> None:
    assert parse_worker_command([]) == "run"
    assert parse_worker_command(["readiness"]) == "readiness"
    assert parse_worker_command(["healthcheck"]) == "healthcheck"


def test_run_stops_without_claiming_after_stop() -> None:
    repo = Repo()
    stopped = Event()
    stopped.set()
    PcapOffsetIndexWorker(repo, lambda *_args, **_kwargs: True, now=lambda: NOW).run(stopped)
    assert not [call for call in repo.calls if call[0] == "claim"]


def test_shared_fatal_prevents_run_once_and_loop_from_claiming() -> None:
    repo = Repo()
    fatal = Event()
    fatal.set()
    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: pytest.fail("builder ran"),
        fatal_event=fatal,
        now=lambda: NOW,
    )

    assert worker.run_once() is False
    worker.run(Event(), idle_seconds=0.001)
    assert not [call for call in repo.calls if call[0] == "claim"]


def test_shared_fatal_racing_after_claim_releases_task_without_building() -> None:
    fatal = Event()
    claim_entered = Event()
    release_claim = Event()
    repo = Repo()
    original_claim = repo.claim_live_segment_index

    def delayed_claim(*, now: datetime, lease_seconds: int) -> LiveIndexTask | None:
        claimed = original_claim(now=now, lease_seconds=lease_seconds)
        claim_entered.set()
        assert release_claim.wait(1), "fatal peer did not release claim"
        return claimed

    repo.claim_live_segment_index = delayed_claim  # type: ignore[method-assign]
    builds = 0

    def build(*_args: Any, **_kwargs: Any) -> bool:
        nonlocal builds
        builds += 1
        return True

    worker = PcapOffsetIndexWorker(repo, build, fatal_event=fatal, now=lambda: NOW)
    result: list[bool] = []
    peer = Thread(target=lambda: result.append(worker.run_once()), daemon=True)
    peer.start()
    assert claim_entered.wait(1)
    fatal.set()
    release_claim.set()
    peer.join(1)

    assert result == [False]
    assert builds == 0
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[1]["transient"] is True
    assert failure[1]["error_code"] == "INDEX_WORKER_FATAL"


@pytest.mark.parametrize("factory_error", [OSError("db down"), RuntimeError("setup bug")])
def test_heartbeat_repository_factory_failure_is_transient_and_bounded(
    factory_error: Exception,
) -> None:
    repo = Repo()
    registry = CollectorRegistry()

    def unavailable() -> tuple[Any, Any]:
        raise factory_error

    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: pytest.fail("builder ran"),
        heartbeat_repository_factory=unavailable,
        metrics=PcapOffsetIndexMetrics(registry),
        now=lambda: NOW,
    )

    assert worker.run_once() is True
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[1]["transient"] is True
    assert failure[1]["error_code"] == "INDEX_HEARTBEAT_UNAVAILABLE"
    metrics = generate_latest(registry)
    assert b'status="' not in metrics
    assert b'outcome="retry",reason="storage"' in metrics
    assert b"db down" not in metrics and b"setup bug" not in metrics and b"segment-1" not in metrics


def test_heartbeat_factory_failure_cas_loss_reports_stale_without_fatal() -> None:
    repo = Repo()
    repo.fail_live_segment_index = lambda *_args, **_kwargs: False  # type: ignore[method-assign]
    fatal = Event()
    registry = CollectorRegistry()
    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: pytest.fail("builder ran"),
        heartbeat_repository_factory=lambda: (_ for _ in ()).throw(OSError("down")),
        metrics=PcapOffsetIndexMetrics(registry),
        fatal_event=fatal,
        now=lambda: NOW,
    )

    assert worker.run_once() is True
    assert not fatal.is_set()
    assert b'outcome="stale",reason="lease_lost"' in generate_latest(registry)


def test_heartbeat_factory_failure_sets_shared_fatal_when_fail_cas_is_unavailable() -> None:
    repo = Repo()
    repo.fail_live_segment_index = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ConnectionError("primary unavailable")
    )
    fatal = Event()
    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: pytest.fail("builder ran"),
        heartbeat_repository_factory=lambda: (_ for _ in ()).throw(OSError("heartbeat down")),
        fatal_event=fatal,
        now=lambda: NOW,
    )

    assert worker.run_once() is False
    assert fatal.is_set() and worker.fatal_stop is True


def test_main_returns_two_when_heartbeat_setup_and_primary_fail_cas_are_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MainRepository(Repo):
        def ready(self) -> bool:
            return True

        def close(self) -> None:
            pytest.fail("fatal worker repository must remain open for orphan safety")

    repository = MainRepository()
    repository.fail_live_segment_index = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
        ConnectionError("primary unavailable")
    )
    settings = type(
        "WorkerSettings",
        (),
        {
            "database_url": "postgresql://example.invalid/controller",
            "s3_endpoint": "http://minio.invalid",
            "s3_access_key": "key",
            "s3_secret_key": "secret",
            "s3_bucket": "bucket",
            "pcap_offset_index_metrics_port": 19104,
            "pcap_offset_index_worker_concurrency": 1,
            "pcap_offset_index_shutdown_grace_seconds": 0.2,
        },
    )()
    monkeypatch.setattr(worker_module, "Settings", lambda: settings)
    monkeypatch.setattr(worker_module, "MinioBlobStore", lambda *_args: object())
    monkeypatch.setattr(worker_module, "PostgresRepository", lambda *_args: repository)
    monkeypatch.setattr(worker_module, "PcapOffsetIndexMetrics", lambda _registry: object())
    monkeypatch.setattr(worker_module, "start_http_server", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker_module.signal, "signal", lambda *_args: None)

    def create_worker(
        repo: MainRepository, _settings: Any, _metrics: Any, fatal: Event
    ) -> PcapOffsetIndexWorker:
        return PcapOffsetIndexWorker(
            repo,
            lambda *_args, **_kwargs: pytest.fail("builder ran"),
            heartbeat_repository_factory=lambda: (_ for _ in ()).throw(OSError("heartbeat down")),
            fatal_event=fatal,
            now=lambda: NOW,
        )

    monkeypatch.setattr(worker_module, "create_pcap_offset_index_worker", create_worker)

    assert worker_module.main(["run"]) == 2


def test_blocked_build_heartbeats_on_independent_repository_and_closes_cleanly() -> None:
    repo = Repo()
    entered = Event()
    release = Event()
    heartbeat_seen = Event()
    heartbeat_closed = Event()

    class HeartbeatRepo:
        def heartbeat_live_segment_index(self, *_args: Any, **_kwargs: Any) -> bool:
            heartbeat_seen.set()
            return True

    def build(*_args: Any, **_kwargs: Any) -> bool:
        entered.set()
        assert release.wait(2), "test release was not signalled"
        return False

    worker = PcapOffsetIndexWorker(
        repo,
        build,
        renew_seconds=0.01,  # type: ignore[arg-type]
        now=lambda: NOW,
        heartbeat_repository_factory=lambda: (HeartbeatRepo(), heartbeat_closed.set),
    )
    thread = Thread(target=worker.run_once, daemon=True)
    thread.start()
    assert entered.wait(1)
    assert heartbeat_seen.wait(1)
    release.set()
    thread.join(1)
    assert not thread.is_alive()
    assert heartbeat_closed.is_set()
    assert any(name == "heartbeat" for name, _value in repo.calls) is False


def test_timeout_is_a_transient_retry_even_when_builder_published_true() -> None:
    repo = Repo()
    ticks = iter((0.0, 10.0))
    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: True,
        job_timeout_seconds=10,
        monotonic=lambda: next(ticks),
        now=lambda: NOW,
    )

    assert worker.run_once()
    failure = next(value for name, value in repo.calls if name == "fail")
    assert failure[1]["transient"] is True
    assert failure[1]["error_code"] == "INDEX_BUILD_TIMEOUT"


def test_real_builder_blocked_open_times_out_fatal_stops_and_cannot_publish_late() -> None:
    repository = MemoryRepository()
    content = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1, 2, 3, 3)
        + b"abc"
    )
    digest = hashlib.sha256(content).hexdigest()
    repository.save_job(
        {
            "id": "job-1",
            "mode": "LIVE",
            "status": "CAPTURING",
            "capture": {"store_pcap": True},
        }
    )
    stored, status = repository.save_sensor_pcap_limited(
        {
            "id": "segment-1",
            "sensor_id": "sensor-1",
            "analysis_job_id": "job-1",
            "filename": "segment-1.pcap",
            "size_bytes": len(content),
            "sha256": digest,
            "uploaded_at": NOW.isoformat(),
        },
        content,
        None,
        require_open_job=True,
    )
    assert stored is not None and status == "OK"
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    claim_now = datetime.now(UTC) + timedelta(seconds=1)
    entered = Event()
    release = Event()
    late_done = Event()
    fatal = Event()
    heartbeat_seen = Event()
    heartbeat_calls = 0
    close_calls = 0
    original_open = repository.open_sensor_pcap
    original_heartbeat = repository.heartbeat_live_segment_index

    def close_repository() -> None:
        nonlocal close_calls
        close_calls += 1

    repository.close = close_repository  # type: ignore[method-assign]

    def heartbeat(source_id: str, **lease: Any) -> bool:
        nonlocal heartbeat_calls
        heartbeat_calls += 1
        heartbeat_seen.set()
        return original_heartbeat(source_id, **lease)

    repository.heartbeat_live_segment_index = heartbeat  # type: ignore[method-assign]

    def blocked_open(source_id: str) -> Any:
        entered.set()
        assert release.wait(2), "orphan release was not signalled"
        return original_open(source_id)

    repository.open_sensor_pcap = blocked_open  # type: ignore[method-assign]

    def real_builder(repo: MemoryRepository, source_id: str, **lease: Any) -> bool:
        try:
            return build_live_segment_index(
                repo,
                source_id,
                max_packets=10,
                max_interfaces=4,
                batch_size=1,
                **lease,
            )
        finally:
            late_done.set()

    worker = PcapOffsetIndexWorker(
        repository,
        real_builder,
        job_timeout_seconds=0.05,  # type: ignore[arg-type]
        renew_seconds=0.01,  # type: ignore[arg-type]
        retry_base_seconds=1,
        now=lambda: claim_now,
        fatal_event=fatal,
    )
    started = __import__("time").monotonic()
    assert worker.run_once()
    elapsed = __import__("time").monotonic() - started
    assert entered.is_set() and elapsed < 0.3
    retriable = repository.get_live_segment_index_task("segment-1")
    assert retriable is not None and retriable.status == "QUEUED" and retriable.attempt == 1
    assert heartbeat_seen.is_set()
    calls_after_timeout = heartbeat_calls
    __import__("time").sleep(0.04)
    assert heartbeat_calls == calls_after_timeout
    assert worker.fatal_stop is True and fatal.is_set()
    assert worker.run_once() is False
    assert close_calls == 0

    newer = repository.claim_live_segment_index(
        now=claim_now + timedelta(seconds=2), lease_seconds=30
    )
    assert newer is not None and newer.attempt == 2 and newer.lease_token
    release.set()
    assert late_done.wait(1), "real builder orphan did not exit"
    current = repository.get_live_segment_index_task("segment-1")
    assert current is not None and current.status == "RUNNING"
    assert current.attempt == newer.attempt and current.lease_token == newer.lease_token
    binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        "segment-1",
        "sha256:" + digest,
        len(content),
        digest,
        "PCAP",
    )
    assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING
    assert close_calls == 0


def test_lease_lost_worker_cannot_overwrite_reclaimed_task_and_reports_stale() -> None:
    repo = Repo()
    repo.fail_live_segment_index = lambda source_id, **kwargs: (  # type: ignore[method-assign]
        repo.calls.append(("stale-fail", (source_id, kwargs))) or False
    )
    registry = CollectorRegistry()
    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: False,
        metrics=PcapOffsetIndexMetrics(registry),
        now=lambda: NOW,
    )

    assert worker.run_once()
    text = generate_latest(registry).decode()
    assert 'outcome="stale",reason="lease_lost"' in text
    stale = next(value for name, value in repo.calls if name == "stale-fail")
    assert stale[1]["attempt"] == 1 and stale[1]["lease_token"] == "token"


def test_maintenance_continues_after_failure_with_exact_bounds_and_order() -> None:
    repo = Repo()
    repo.current = None

    def recover(*, now: datetime) -> int:
        repo.calls.append(("recover", now))
        raise OSError("maintenance unavailable")

    repo.recover_live_segment_indexes = recover  # type: ignore[method-assign]
    worker = PcapOffsetIndexWorker(
        repo,
        lambda *_args, **_kwargs: True,
        queue_capacity=7,
        max_attempts=4,
        reconcile_batch_size=5,
        staging_max_age_seconds=60,
        staging_cleanup_batch_size=6,
        terminal_retention_seconds=120,
        terminal_cleanup_batch_size=8,
        now=lambda: NOW,
    )

    worker.startup()

    assert [name for name, _value in repo.calls[:4]] == [
        "recover",
        "reconcile",
        "staging",
        "terminal",
    ]
    assert repo.calls[1][1] == {"capacity": 7, "max_attempts": 4, "limit": 5}
    assert repo.calls[2] == ("staging", 6)
    assert repo.calls[3] == ("terminal", 8)


def test_metric_failures_are_best_effort_for_success_failure_and_depth() -> None:
    class BrokenMetrics:
        def __getattr__(self, _name: str) -> Any:
            def fail(*_args: Any, **_kwargs: Any) -> None:
                raise RuntimeError("metric includes segment-1 secret")

            return fail

    success_repo = Repo()
    assert PcapOffsetIndexWorker(
        success_repo,
        lambda *_args, **_kwargs: True,
        metrics=BrokenMetrics(),  # type: ignore[arg-type]
        now=lambda: NOW,
    ).run_once()
    failed_repo = Repo()
    assert PcapOffsetIndexWorker(
        failed_repo,
        lambda *_args, **_kwargs: False,
        metrics=BrokenMetrics(),  # type: ignore[arg-type]
        now=lambda: NOW,
    ).run_once()
    idle_repo = Repo()
    idle_repo.current = None
    PcapOffsetIndexWorker(
        idle_repo,
        lambda *_args, **_kwargs: True,
        metrics=BrokenMetrics(),  # type: ignore[arg-type]
        now=lambda: NOW,
    ).startup()
    assert any(name == "fail" for name, _value in failed_repo.calls)


def test_main_bounds_forced_shutdown_and_leaves_repository_for_lease_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered = Event()
    release = Event()
    exited = Event()

    class BlockingWorker:
        def run(self, stopped: Event) -> None:
            entered.set()
            release.wait(2)
            exited.set()

    class FakeRepository:
        closes = 0

        def ready(self) -> bool:
            return True

        def close(self) -> None:
            self.closes += 1

    repository = FakeRepository()
    settings = type(
        "WorkerSettings",
        (),
        {
            "database_url": "postgresql://example.invalid/controller",
            "s3_endpoint": "http://minio.invalid",
            "s3_access_key": "key",
            "s3_secret_key": "secret",
            "s3_bucket": "bucket",
            "pcap_offset_index_metrics_port": 19104,
            "pcap_offset_index_worker_concurrency": 1,
            "pcap_offset_index_shutdown_grace_seconds": 0.01,
        },
    )()
    monkeypatch.setattr(worker_module, "Settings", lambda: settings)
    monkeypatch.setattr(worker_module, "MinioBlobStore", lambda *_args: object())
    monkeypatch.setattr(worker_module, "PostgresRepository", lambda *_args: repository)
    monkeypatch.setattr(worker_module, "PcapOffsetIndexMetrics", lambda _registry: object())
    monkeypatch.setattr(worker_module, "start_http_server", lambda *_args, **_kwargs: None)
    handlers: dict[int, Any] = {}
    monkeypatch.setattr(
        worker_module.signal,
        "signal",
        lambda kind, handler: handlers.setdefault(kind, handler),
    )
    monkeypatch.setattr(
        worker_module,
        "create_pcap_offset_index_worker",
        lambda *_args, **_kwargs: BlockingWorker(),
    )

    def stop_after_entry() -> None:
        assert entered.wait(1)
        handlers[worker_module.signal.SIGTERM]()

    trigger = Thread(target=stop_after_entry, daemon=True)
    trigger.start()
    assert worker_module.main(["run"]) == 0
    trigger.join(1)
    assert entered.is_set()
    assert repository.closes == 0
    release.set()
    assert exited.wait(1)


def test_main_fatal_stops_all_workers_without_closing_orphan_repositories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_ready = Event()
    fatal_set = Event()
    fatal_worker_exited = Event()
    emergency_release = Event()
    orphan_may_use_repository = Event()
    claim_lock = Lock()
    claims = 0
    claims_at_fatal = 0
    result: list[int] = []

    class FakeRepository:
        def __init__(self) -> None:
            self.closes = 0

        def ready(self) -> bool:
            return True

        def for_background_worker(self) -> FakeRepository:
            return FakeRepository()

        def close(self) -> None:
            assert not orphan_may_use_repository.is_set()
            self.closes += 1

        def claim_live_segment_index(
            self, *, now: datetime, lease_seconds: int
        ) -> LiveIndexTask | None:
            nonlocal claims
            with claim_lock:
                claims += 1
            peer_ready.set()
            return None

        def recover_live_segment_indexes(self, *, now: datetime) -> int:
            return 0

        def reconcile_live_segment_indexes(self, **_kwargs: Any) -> int:
            return 0

        def cleanup_stale_structural_indexes(self, **_kwargs: Any) -> int:
            return 0

        def cleanup_terminal_live_segment_indexes(self, **_kwargs: Any) -> int:
            return 0

        def get_live_segment_index_queue_depth(self) -> dict[str, int]:
            return {}

    repository = FakeRepository()
    repositories = [repository]
    settings = type(
        "WorkerSettings",
        (),
        {
            "database_url": "postgresql://example.invalid/controller",
            "s3_endpoint": "http://minio.invalid",
            "s3_access_key": "key",
            "s3_secret_key": "secret",
            "s3_bucket": "bucket",
            "pcap_offset_index_metrics_port": 19104,
            "pcap_offset_index_worker_concurrency": 2,
            "pcap_offset_index_shutdown_grace_seconds": 0.2,
        },
    )()

    class FatalWorker:
        def __init__(self, fatal: Event) -> None:
            self.fatal = fatal

        def run(self, _stopped: Event) -> None:
            nonlocal claims_at_fatal
            assert peer_ready.wait(1), "peer worker did not start"
            with claim_lock:
                orphan_may_use_repository.set()
                claims_at_fatal = claims
                self.fatal.set()
                fatal_set.set()
            fatal_worker_exited.set()

    def background_repository() -> FakeRepository:
        background = FakeRepository()
        repositories.append(background)
        return background

    repository.for_background_worker = background_repository  # type: ignore[method-assign]
    created = 0

    def create_worker(
        _repository: FakeRepository,
        _settings: Any,
        _metrics: Any,
        fatal: Event,
    ) -> FatalWorker | PcapOffsetIndexWorker:
        nonlocal created
        created += 1
        return (
            FatalWorker(fatal)
            if created == 1
            else PcapOffsetIndexWorker(
                _repository,
                lambda *_args, **_kwargs: pytest.fail("idle peer built without a task"),
                fatal_event=fatal,
                now=lambda: NOW,
            )
        )

    monkeypatch.setattr(worker_module, "Settings", lambda: settings)
    monkeypatch.setattr(worker_module, "MinioBlobStore", lambda *_args: object())
    monkeypatch.setattr(worker_module, "PostgresRepository", lambda *_args: repository)
    monkeypatch.setattr(worker_module, "PcapOffsetIndexMetrics", lambda _registry: object())
    monkeypatch.setattr(worker_module, "start_http_server", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker_module.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(worker_module, "create_pcap_offset_index_worker", create_worker)

    supervisor = Thread(target=lambda: result.append(worker_module.main(["run"])), daemon=True)
    started = time.monotonic()
    supervisor.start()
    try:
        assert fatal_set.wait(1), "fatal worker did not report its orphan"
        assert fatal_worker_exited.wait(0.1), "fatal worker did not exit after reporting fatal"
        supervisor.join(0.5)
        assert not supervisor.is_alive(), "main did not return after fatal stop"
    finally:
        emergency_release.set()
        supervisor.join(1)

    assert result == [2]
    assert time.monotonic() - started < 1
    assert claims == claims_at_fatal
    assert orphan_may_use_repository.is_set()
    assert len(repositories) == 2
    assert all(item.closes == 0 for item in repositories)


def test_deletion_during_worker_build_cannot_publish_fail_or_resurrect_source() -> None:
    repository = MemoryRepository()
    content = (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1, 2, 3, 3)
        + b"abc"
    )
    repository.save_job(
        {"id": "job-1", "mode": "LIVE", "status": "CAPTURING", "capture": {"store_pcap": True}}
    )
    stored, status = repository.save_sensor_pcap_limited(
        {
            "id": "segment-1",
            "sensor_id": "sensor-1",
            "analysis_job_id": "job-1",
            "filename": "segment-1.pcap",
            "size_bytes": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "uploaded_at": NOW.isoformat(),
        },
        content,
        None,
        require_open_job=True,
    )
    assert stored is not None and status == "OK"
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)

    def deleted_build(repo: MemoryRepository, source_id: str, **lease: Any) -> bool:
        assert repo.delete_job("job-1")
        return build_live_segment_index(
            repo,
            source_id,
            max_packets=10,
            max_interfaces=4,
            batch_size=1,
            **lease,
        )

    claim_now = datetime.now(UTC) + timedelta(seconds=1)
    assert PcapOffsetIndexWorker(repository, deleted_build, now=lambda: claim_now).run_once()
    binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        "segment-1",
        "sha256:" + hashlib.sha256(content).hexdigest(),
        len(content),
        hashlib.sha256(content).hexdigest(),
        "PCAP",
    )
    assert repository.get_sensor_pcap("segment-1") is None
    assert repository.get_live_segment_index_task("segment-1") is None
    assert repository.get_live_capture_source_version("segment-1") is None
    assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING
