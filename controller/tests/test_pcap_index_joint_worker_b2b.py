from __future__ import annotations

import signal
from threading import Event, Lock, Thread
from typing import Any

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from c2hunter_controller import pcap_offset_index_worker as worker_module
from c2hunter_controller.pcap_offset_index_metrics import PcapOffsetIndexMetrics
from c2hunter_controller.pcap_posting_index_metrics import PcapPostingIndexMetrics


class _Settings:
    database_url = "postgresql://example.invalid/controller"
    s3_endpoint = "http://minio.invalid"
    s3_access_key = "key"
    s3_secret_key = "secret"
    s3_bucket = "bucket"
    pcap_offset_index_live_enabled = True
    pcap_offset_index_worker_concurrency = 2
    pcap_offset_index_shutdown_grace_seconds = 0.2
    pcap_offset_index_metrics_port = 9104
    pcap_posting_index_enabled = True
    pcap_posting_index_metrics_enabled = True
    pcap_posting_index_worker_concurrency = 3
    pcap_posting_index_lease_seconds = 20
    pcap_posting_index_heartbeat_interval_seconds = 5
    pcap_posting_index_retry_base_seconds = 7
    pcap_posting_index_operation_timeout_seconds = 40
    pcap_posting_index_queue_capacity = 17
    pcap_posting_index_max_attempts = 4
    pcap_posting_index_reconcile_batch_size = 13
    pcap_posting_index_backfill_enabled = True
    pcap_posting_index_backfill_batch_size = 14
    pcap_posting_index_staging_max_age_seconds = 101
    pcap_posting_index_staging_cleanup_batch_size = 11
    pcap_posting_index_terminal_retention_seconds = 202
    pcap_posting_index_terminal_cleanup_batch_size = 12
    pcap_posting_index_reconcile_interval_seconds = 9
    pcap_posting_index_poll_interval_seconds = 0.01


class _Repository:
    def __init__(self, repositories: list[_Repository]) -> None:
        self.closes = 0
        repositories.append(self)
        self._repositories = repositories

    def ready(self) -> bool:
        return True

    def for_background_worker(self) -> _Repository:
        return _Repository(self._repositories)

    def close(self) -> None:
        self.closes += 1


class _WaitingWorker:
    def __init__(self, started: Event) -> None:
        self.started = started

    def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
        self.started.set()
        stopped.wait(2)


def _patch_process_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    settings: type[Any],
    root: _Repository,
) -> None:
    monkeypatch.setattr(worker_module, "Settings", settings)
    monkeypatch.setattr(worker_module, "MinioBlobStore", lambda *_args: object())
    monkeypatch.setattr(worker_module, "PostgresRepository", lambda *_args: root)
    monkeypatch.setattr(worker_module, "PcapOffsetIndexMetrics", lambda _registry: object())
    monkeypatch.setattr(worker_module, "PcapPostingIndexMetrics", lambda _registry: object())
    monkeypatch.setattr(worker_module, "start_http_server", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(worker_module.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(
        worker_module, "create_posting_operation_builder", lambda _settings: object()
    )


def test_joint_main_wires_independent_concurrency_shared_registry_and_one_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repositories: list[_Repository] = []
    root = _Repository(repositories)
    started = [Event() for _ in range(5)]
    handlers: dict[int, Any] = {}
    offset_calls: list[tuple[Any, Any, Any, Event]] = []
    posting_calls: list[dict[str, Any]] = []
    metric_calls: list[tuple[str, Any]] = []
    servers: list[tuple[int, Any]] = []
    operation_builders: list[Any] = []
    posting_idle_seconds: list[float] = []

    monkeypatch.setattr(worker_module, "Settings", _Settings)
    monkeypatch.setattr(worker_module, "MinioBlobStore", lambda *_args: object())
    monkeypatch.setattr(worker_module, "PostgresRepository", lambda *_args: root)
    monkeypatch.setattr(
        worker_module,
        "PcapOffsetIndexMetrics",
        lambda registry: metric_calls.append(("offset", registry)) or object(),
    )
    monkeypatch.setattr(
        worker_module,
        "PcapPostingIndexMetrics",
        lambda registry: metric_calls.append(("posting", registry)) or object(),
    )
    monkeypatch.setattr(
        worker_module,
        "start_http_server",
        lambda port, *, registry: servers.append((port, registry)),
    )
    monkeypatch.setattr(
        worker_module.signal,
        "signal",
        lambda kind, handler: handlers.setdefault(kind, handler),
    )

    def create_offset(repository: Any, settings: Any, metrics: Any, fatal: Event) -> Any:
        offset_calls.append((repository, settings, metrics, fatal))
        return _WaitingWorker(started[len(offset_calls) - 1])

    class PostingWorker(_WaitingWorker):
        def __init__(
            self,
            repository: Any,
            builder: Any,
            *,
            config: Any,
            metrics: Any,
            control: Any,
        ) -> None:
            posting_calls.append(
                {
                    "repository": repository,
                    "builder": builder,
                    "config": config,
                    "metrics": metrics,
                    "control": control,
                }
            )
            super().__init__(started[2 + len(posting_calls) - 1])

        def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
            posting_idle_seconds.append(idle_seconds)
            super().run(stopped, idle_seconds=idle_seconds)

    builder = object()
    monkeypatch.setattr(worker_module, "create_pcap_offset_index_worker", create_offset)
    monkeypatch.setattr(worker_module, "PcapPostingIndexWorker", PostingWorker)
    monkeypatch.setattr(
        worker_module,
        "create_posting_operation_builder",
        lambda settings: operation_builders.append(settings) or builder,
    )

    def terminate_when_started() -> None:
        assert all(event.wait(1) for event in started)
        handlers[signal.SIGTERM]()

    trigger = Thread(target=terminate_when_started, daemon=True)
    trigger.start()
    assert worker_module.main(["run"]) == 0
    trigger.join(1)

    assert len(offset_calls) == 2
    assert len(posting_calls) == 3
    assert len(repositories) == 5
    assert len({id(call[0]) for call in offset_calls}) == 2
    assert len({id(call["repository"]) for call in posting_calls}) == 3
    assert {id(call[0]) for call in offset_calls}.isdisjoint(
        {id(call["repository"]) for call in posting_calls}
    )
    assert operation_builders == [offset_calls[0][1]]
    assert all(call["builder"] is builder for call in posting_calls)
    assert all(call["control"].stop is posting_calls[0]["control"].stop for call in posting_calls)
    assert all(call["control"].fatal is offset_calls[0][3] for call in posting_calls)
    assert [name for name, _registry in metric_calls] == ["offset", "posting"]
    assert metric_calls[0][1] is metric_calls[1][1]
    assert servers == [(9104, metric_calls[0][1])]
    assert posting_idle_seconds == [0.01, 0.01, 0.01]
    assert set(handlers) == {signal.SIGTERM, signal.SIGINT}
    assert [repository.closes for repository in repositories] == [1, 1, 1, 1, 1]
    posting_config = posting_calls[0]["config"]
    assert (
        posting_config.queue_capacity,
        posting_config.max_attempts,
        posting_config.reconcile_batch_size,
        posting_config.backfill_enabled,
        posting_config.backfill_batch_size,
        posting_config.lease_seconds,
        posting_config.renew_seconds,
        posting_config.retry_base_seconds,
        posting_config.job_timeout_seconds,
    ) == (17, 4, 13, True, 14, 20, 5, 7, 40)


def test_posting_fatal_synchronously_stops_structural_claim_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_worker_concurrency = 1
        pcap_posting_index_worker_concurrency = 1

    repositories: list[_Repository] = []
    root = _Repository(repositories)
    _patch_process_dependencies(monkeypatch, Settings, root)
    lock = Lock()
    structural_ready = Event()
    claims = 0
    claims_at_fatal = -1

    class StructuralWorker:
        def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
            nonlocal claims
            structural_ready.set()
            while True:
                with lock:
                    if stopped.is_set():
                        return
                    claims += 1
                stopped.wait(0.001)

    class PostingWorker:
        def __init__(self, *_args: Any, control: Any, **_kwargs: Any) -> None:
            self.control = control

        def run(self, _stopped: Event, *, idle_seconds: float = 0.25) -> None:
            nonlocal claims_at_fatal
            assert structural_ready.wait(1)
            with lock:
                self.control.fail()
                claims_at_fatal = claims

    monkeypatch.setattr(
        worker_module, "create_pcap_offset_index_worker", lambda *_args: StructuralWorker()
    )
    monkeypatch.setattr(worker_module, "PcapPostingIndexWorker", PostingWorker)

    assert worker_module.main(["run"]) == 2
    assert claims > 0 and claims == claims_at_fatal
    assert all(repository.closes == 0 for repository in repositories)


def test_structural_fatal_synchronously_stops_posting_claim_growth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_worker_concurrency = 1
        pcap_posting_index_worker_concurrency = 1

    repositories: list[_Repository] = []
    root = _Repository(repositories)
    _patch_process_dependencies(monkeypatch, Settings, root)
    lock = Lock()
    posting_ready = Event()
    claims = 0
    claims_at_fatal = -1

    class StructuralWorker:
        def __init__(self, fatal: Event) -> None:
            self.fatal = fatal

        def run(self, _stopped: Event, *, idle_seconds: float = 0.25) -> None:
            nonlocal claims_at_fatal
            assert posting_ready.wait(1)
            with lock:
                self.fatal.set()
                claims_at_fatal = claims

    class PostingWorker:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
            nonlocal claims
            posting_ready.set()
            while True:
                with lock:
                    if stopped.is_set():
                        return
                    claims += 1
                stopped.wait(0.001)

    monkeypatch.setattr(
        worker_module,
        "create_pcap_offset_index_worker",
        lambda _repo, _settings, _metrics, fatal: StructuralWorker(fatal),
    )
    monkeypatch.setattr(worker_module, "PcapPostingIndexWorker", PostingWorker)

    assert worker_module.main(["run"]) == 2
    assert claims > 0 and claims == claims_at_fatal
    assert all(repository.closes == 0 for repository in repositories)


def test_blocked_posting_worker_does_not_block_structural_start_or_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_worker_concurrency = 1
        pcap_posting_index_worker_concurrency = 1

    repositories: list[_Repository] = []
    root = _Repository(repositories)
    _patch_process_dependencies(monkeypatch, Settings, root)
    posting_blocked = Event()
    structural_claimed = Event()

    class StructuralWorker:
        def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
            assert posting_blocked.wait(1)
            structural_claimed.set()
            stopped.set()

    class PostingWorker:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
            posting_blocked.set()
            assert structural_claimed.wait(1)
            stopped.wait(1)

    monkeypatch.setattr(
        worker_module, "create_pcap_offset_index_worker", lambda *_args: StructuralWorker()
    )
    monkeypatch.setattr(worker_module, "PcapPostingIndexWorker", PostingWorker)

    assert worker_module.main(["run"]) == 0
    assert structural_claimed.is_set()
    assert [repository.closes for repository in repositories] == [1, 1]


def test_metrics_disabled_and_repeated_main_use_fresh_registries_without_duplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_live_enabled = False
        pcap_posting_index_enabled = False
        pcap_posting_index_metrics_enabled = False

    repositories: list[_Repository] = []
    servers: list[Any] = []

    monkeypatch.setattr(worker_module, "Settings", Settings)
    monkeypatch.setattr(worker_module, "MinioBlobStore", lambda *_args: object())
    monkeypatch.setattr(
        worker_module,
        "PostgresRepository",
        lambda *_args: _Repository(repositories),
    )
    monkeypatch.setattr(worker_module.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(
        worker_module,
        "start_http_server",
        lambda _port, *, registry: servers.append(registry),
    )

    assert worker_module.main(["run"]) == 0
    assert worker_module.main(["run"]) == 0
    assert len(servers) == 2 and servers[0] is not servers[1]
    assert [repository.closes for repository in repositories] == [1, 1]


def test_both_metric_families_share_explicit_repeatable_registry_without_name_collisions() -> None:
    registries = [CollectorRegistry(), CollectorRegistry()]
    payloads: list[bytes] = []

    for registry in registries:
        PcapOffsetIndexMetrics(registry)
        PcapPostingIndexMetrics(registry)
        payloads.append(generate_latest(registry))

    for payload in payloads:
        assert b"c2hunter_pcap_offset_index_tasks_total" in payload
        assert b"c2hunter_pcap_posting_index_tasks_total" in payload


def test_startup_worker_factory_failure_stops_and_closes_every_created_repository_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_worker_concurrency = 2
        pcap_posting_index_enabled = False

    repositories: list[_Repository] = []
    root = _Repository(repositories)
    _patch_process_dependencies(monkeypatch, Settings, root)
    calls = 0

    def create_worker(*_args: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("worker init failed")
        return _WaitingWorker(Event())

    monkeypatch.setattr(worker_module, "create_pcap_offset_index_worker", create_worker)

    assert worker_module.main(["run"]) == 2
    assert calls == 2
    assert [repository.closes for repository in repositories] == [1, 1]


def test_partial_thread_start_failure_uses_same_deadline_and_closes_unowned_resources(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_worker_concurrency = 2
        pcap_posting_index_enabled = False

    repositories: list[_Repository] = []
    root = _Repository(repositories)
    _patch_process_dependencies(monkeypatch, Settings, root)
    starts = 0

    class Worker:
        def run(self, _stopped: Event) -> None:
            pass

    class FailingThread:
        def __init__(self, *, name: str, **_kwargs: Any) -> None:
            self.name = name

        def start(self) -> None:
            nonlocal starts
            starts += 1
            if starts == 2:
                raise RuntimeError("thread start failed")

        def join(self, timeout: float | None = None) -> None:
            pass

        def is_alive(self) -> bool:
            return False

    monkeypatch.setattr(worker_module, "create_pcap_offset_index_worker", lambda *_args: Worker())
    monkeypatch.setattr(worker_module.threading, "Thread", FailingThread)

    assert worker_module.main(["run"]) == 2
    assert starts == 2
    assert [repository.closes for repository in repositories] == [1, 1]


def test_one_shutdown_deadline_returns_two_and_retains_only_alive_worker_repository(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Settings(_Settings):
        pcap_offset_index_worker_concurrency = 1
        pcap_posting_index_worker_concurrency = 1
        pcap_offset_index_shutdown_grace_seconds = 0.01

    repositories: list[_Repository] = []
    root = _Repository(repositories)
    _patch_process_dependencies(monkeypatch, Settings, root)
    handlers: dict[int, Any] = {}
    posting_entered = Event()
    release_posting = Event()

    monkeypatch.setattr(
        worker_module.signal,
        "signal",
        lambda kind, handler: handlers.setdefault(kind, handler),
    )

    class StructuralWorker:
        def run(self, stopped: Event, *, idle_seconds: float = 0.25) -> None:
            stopped.wait(1)

    class PostingWorker:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            pass

        def run(self, _stopped: Event, *, idle_seconds: float = 0.25) -> None:
            posting_entered.set()
            release_posting.wait(1)

    monkeypatch.setattr(
        worker_module, "create_pcap_offset_index_worker", lambda *_args: StructuralWorker()
    )
    monkeypatch.setattr(worker_module, "PcapPostingIndexWorker", PostingWorker)

    def terminate() -> None:
        assert posting_entered.wait(1)
        handlers[signal.SIGINT]()

    trigger = Thread(target=terminate, daemon=True)
    trigger.start()
    try:
        assert worker_module.main(["run"]) == 2
    finally:
        release_posting.set()
        trigger.join(1)

    assert [repository.closes for repository in repositories] == [1, 0]
