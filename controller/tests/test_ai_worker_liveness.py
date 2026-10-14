"""Event-controlled worker liveness; no model, socket or deployed service."""

import json
from datetime import UTC, datetime, timedelta
from threading import Event, Thread

import pytest

from c2hunter_controller import ai_worker as module
from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue


class Clock(datetime):
    value = datetime(2026, 1, 1, tzinfo=UTC)

    @classmethod
    def now(cls, tz):
        return cls.value


class BlockedService:
    def __init__(self, *, fail=False):
        self.entered, self.release = Event(), Event()
        self.fail = fail

    def execute(self, run_id):
        self.entered.set()
        assert self.release.wait(5), "test failed to release service"
        if self.fail:
            raise ValueError("PRIVATE_EXECUTION_SENTINEL")
        return {"status": "COMPLETED"}


def test_blocked_legitimate_execution_refreshes_health_at_31_seconds(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "datetime", Clock)
    monkeypatch.setattr(module, "HEARTBEAT_INTERVAL_SECONDS", 0.01, raising=False)
    Clock.value = datetime(2026, 1, 1, tzinfo=UTC)
    service = BlockedService()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    refreshed = Event()
    write = worker._write_health

    def observe(status):
        write(status)
        # A publication can sample the clock before the test advances it.
        payload = json.loads(worker.health_path.read_text())
        if datetime.fromisoformat(payload["updated_at"]).second == 31 and status == "RUNNING":
            refreshed.set()

    monkeypatch.setattr(worker, "_write_health", observe)
    result = []
    thread = Thread(target=lambda: result.append(worker.run_once(timeout=0)))
    thread.start()
    try:
        assert service.entered.wait(2)
        Clock.value += timedelta(seconds=31)
        assert refreshed.wait(1), "live service had no in-flight heartbeat"
        assert module._healthy(worker.health_path, 30)
        assert queue.acked == [] and thread.is_alive()
    finally:
        service.release.set()
        thread.join(2)
    assert not thread.is_alive() and result == [True]
    assert queue.acked == ["receipt"]
    assert json.loads(worker.health_path.read_text())["processed_runs"] == 1


@pytest.fixture
def heartbeat_threads(monkeypatch):
    created = []

    def factory(*args, **kwargs):
        thread = Thread(*args, **kwargs)
        created.append(thread)
        return thread

    monkeypatch.setattr(module, "Thread", factory)
    monkeypatch.setattr(module, "HEARTBEAT_INTERVAL_SECONDS", 0.01)
    yield created
    assert all(not thread.is_alive() for thread in created), "heartbeat thread leaked"


@pytest.mark.parametrize("fail", [False, True])
def test_stop_while_blocked_joins_helper_and_never_republishes_running(
    tmp_path, monkeypatch, heartbeat_threads, fail
):
    service = BlockedService(fail=fail)
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    stopped, stopping = Event(), Event()
    statuses = []
    publish = worker._publish_health

    def record(status):
        publish(status)
        statuses.append(status)
        if status == "STOPPING":
            stopping.set()

    monkeypatch.setattr(worker, "_publish_health", record)
    thread = Thread(target=lambda: worker.run(stopped))
    thread.start()
    try:
        assert service.entered.wait(2)
        stopped.set()
        assert stopping.wait(1)
        assert not module._healthy(worker.health_path, 30)
        assert queue.acked == [] and thread.is_alive()
    finally:
        stopped.set()
        service.release.set()
        thread.join(2)
    assert not thread.is_alive()
    assert len(heartbeat_threads) == 1
    assert statuses[-1] == "STOPPED"
    assert "RUNNING" not in statuses[statuses.index("STOPPING") :]
    assert queue.acked == ([] if fail else ["receipt"])
    assert worker.processed_runs == (0 if fail else 1)
    assert "PRIVATE_EXECUTION_SENTINEL" not in worker.health_path.read_text()


def test_wedged_pass_is_not_kept_healthy_forever(tmp_path, monkeypatch, heartbeat_threads):
    clock = [0.0]
    monkeypatch.setattr(module, "perf_counter", lambda: clock[0])
    service = BlockedService()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    expired = Event()
    publish = worker._publish_health

    def record(status):
        publish(status)
        if status == "UNRESPONSIVE":
            expired.set()

    monkeypatch.setattr(worker, "_publish_health", record)
    thread = Thread(target=lambda: worker.run_once(timeout=0))
    thread.start()
    try:
        assert service.entered.wait(2)
        clock[0] = worker._liveness_seconds + 1
        assert expired.wait(1)
        assert not module._healthy(worker.health_path, 30)
        assert thread.is_alive() and queue.acked == []
    finally:
        service.release.set()
        thread.join(2)
    assert not thread.is_alive() and queue.acked == ["receipt"]


@pytest.mark.parametrize("point", ["construct", "start"])
def test_failed_heartbeat_acquisition_does_not_claim_or_join_unstarted(
    tmp_path, monkeypatch, point
):
    service = BlockedService()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    fault = RuntimeError("heartbeat acquisition failed")
    calls = []

    class Unstarted:
        def start(self):
            calls.append("start")
            raise fault

        def join(self):
            pytest.fail("joined a heartbeat that never started")

    def factory(**kwargs):
        calls.append("construct")
        if point == "construct":
            raise fault
        return Unstarted()

    monkeypatch.setattr(module, "Thread", factory)
    with pytest.raises(RuntimeError) as caught:
        worker.run_once(timeout=0)
    assert caught.value is fault
    assert calls == (["construct"] if point == "construct" else ["construct", "start"])
    assert queue.depth() == (1, 0) and queue.acked == []
    assert not service.entered.is_set()
    assert json.loads(worker.health_path.read_text())["status"] == "STOPPED"


@pytest.mark.parametrize("fail_service", [False, True])
def test_health_io_failure_is_nonsemantic_and_cleans_temporary_files(
    tmp_path, monkeypatch, heartbeat_threads, fail_service
):
    service = BlockedService(fail=fail_service)
    service.release.set()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    calls = []

    def fail_replace(*args):
        calls.append(True)
        raise OSError("PRIVATE_HEALTH_IO_SENTINEL")

    monkeypatch.setattr(module.os, "replace", fail_replace)
    assert worker.run_once(timeout=0) is (not fail_service)
    assert calls and service.entered.is_set()
    assert queue.acked == ([] if fail_service else ["receipt"])
    assert list(tmp_path.iterdir()) == []


def test_one_heartbeat_per_loop_not_per_run_or_candidate(tmp_path, heartbeat_threads):
    stopped = Event()
    calls = []

    class Service:
        def execute(self, run_id):
            calls.append(run_id)
            assert len(heartbeat_threads) == 1 and heartbeat_threads[0].is_alive()
            if len(calls) == 3:
                stopped.set()
            return {"status": "COMPLETED"}

    queue = MemoryAIAnalysisWorkerQueue(
        [{"ai_run_id": f"run-{i}", "receipt": f"receipt-{i}"} for i in range(3)]
    )
    worker = module.AIAnalysisWorker(queue, Service(), health_path=tmp_path / "health.json")
    worker.run(stopped)
    assert len(heartbeat_threads) == 1 and len(queue.acked) == 3
    assert json.loads(worker.health_path.read_text())["status"] == "STOPPED"


def test_inflight_health_publication_is_joined_before_stopped(
    tmp_path, monkeypatch, heartbeat_threads
):
    from threading import current_thread

    service = BlockedService()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    stopped, publishing, release_publish = Event(), Event(), Event()
    replace = module.os.replace
    writes = []

    def parked_replace(source, target):
        if current_thread().name == "ai-worker-heartbeat":
            publishing.set()
            assert release_publish.wait(3)
        replace(source, target)
        writes.append(json.loads(worker.health_path.read_text())["status"])

    monkeypatch.setattr(module.os, "replace", parked_replace)
    thread = Thread(target=lambda: worker.run(stopped))
    thread.start()
    try:
        assert service.entered.wait(2) and publishing.wait(2)
        stopped.set()
        service.release.set()
        assert thread.is_alive()
    finally:
        release_publish.set()
        stopped.set()
        service.release.set()
        thread.join(2)
    assert not thread.is_alive()
    assert writes[-1] == "STOPPED"
    assert "RUNNING" not in writes[writes.index("STOPPED") :]


def test_metrics_failure_does_not_log_exception_payload(caplog, monkeypatch):
    metrics = module.AIWorkerMetrics(provider="fake", model="fake")
    fired = []

    def fail(**kwargs):
        fired.append(True)
        raise ValueError("PRIVATE_METRIC_SENTINEL")

    monkeypatch.setattr(metrics.inference_duration, "labels", fail)
    with caplog.at_level("DEBUG", logger=module.__name__):
        metrics.observe_execution(1.0, {"status": "COMPLETED"})
    assert fired == [True]
    assert "PRIVATE_METRIC_SENTINEL" not in caplog.text


def test_inflight_heartbeat_io_failure_becomes_stale_without_affecting_ack(
    tmp_path, monkeypatch, heartbeat_threads
):
    from threading import current_thread

    Clock.value = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(module, "datetime", Clock)
    service = BlockedService()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    failed = Event()
    replace = module.os.replace

    def fail_refresh(source, target):
        if current_thread().name == "ai-worker-heartbeat":
            failed.set()
            raise OSError("PRIVATE_HEALTH_IO_SENTINEL")
        replace(source, target)

    monkeypatch.setattr(module.os, "replace", fail_refresh)
    result = []
    thread = Thread(target=lambda: result.append(worker.run_once(timeout=0)))
    thread.start()
    try:
        assert service.entered.wait(2)
        Clock.value += timedelta(seconds=31)
        assert failed.wait(1)
        assert not module._healthy(worker.health_path, 30)
    finally:
        service.release.set()
        thread.join(2)
    assert not thread.is_alive() and result == [True]
    assert queue.acked == ["receipt"]
    assert module._healthy(worker.health_path, 30)
    assert list(tmp_path.iterdir()) == [worker.health_path]


def test_failed_metric_and_debug_sinks_do_not_change_ack(tmp_path, monkeypatch, heartbeat_threads):
    service = BlockedService()
    service.release.set()
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, service, health_path=tmp_path / "health.json")
    faults = []

    def fail_metric(**kwargs):
        faults.append("metric")
        raise ValueError("PRIVATE_METRIC_SENTINEL")

    def fail_log(*args, **kwargs):
        faults.append("log")
        raise ValueError("PRIVATE_LOG_SENTINEL")

    monkeypatch.setattr(worker.metrics.inference_duration, "labels", fail_metric)
    monkeypatch.setattr(module.logger, "debug", fail_log)
    assert worker.run_once(timeout=0)
    assert faults == ["metric", "log"]
    assert queue.acked == ["receipt"]


def test_start_failure_preserves_original_when_health_io_also_fails(tmp_path, monkeypatch):
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": "run", "receipt": "receipt"}])
    worker = module.AIAnalysisWorker(queue, BlockedService(), health_path=tmp_path / "health.json")
    original = RuntimeError("heartbeat start failed")

    def fail_start(**kwargs):
        raise original

    def fail_io(*args, **kwargs):
        raise OSError("private filesystem detail")

    monkeypatch.setattr(module, "Thread", fail_start)
    monkeypatch.setattr(module.tempfile, "mkstemp", fail_io)
    with pytest.raises(RuntimeError) as caught:
        worker.run_once(timeout=0)
    assert caught.value is original and queue.depth() == (1, 0)


def test_claim_exception_escapes_after_helper_join(tmp_path, heartbeat_threads):
    class Queue(MemoryAIAnalysisWorkerQueue):
        def claim(self, timeout=1):
            raise RuntimeError("claim failed")

    worker = module.AIAnalysisWorker(
        Queue([]), BlockedService(), health_path=tmp_path / "health.json"
    )
    with pytest.raises(RuntimeError, match="claim failed"):
        worker.run(Event())
    assert len(heartbeat_threads) == 1
    assert not heartbeat_threads[0].is_alive()
    assert json.loads(worker.health_path.read_text())["status"] == "STOPPED"


def test_real_historical_service_stays_live_without_early_queue_ack(
    tmp_path, monkeypatch, heartbeat_threads
):
    from c2hunter_controller import ai_analysis as ai
    from tests.test_c2_failure_diagnostics import envelope, exercise

    repo, run, http, queue, worker = exercise(lambda b: [envelope(ai.FakeGateway().assess(b))])
    worker.health_path = tmp_path / "health.json"
    Clock.value = datetime(2026, 1, 1, tzinfo=UTC)
    monkeypatch.setattr(module, "datetime", Clock)
    entered, release, refreshed = Event(), Event(), Event()
    request, publish = http.request, worker._publish_health

    def blocked(*args, **kwargs):
        entered.set()
        assert release.wait(3)
        return request(*args, **kwargs)

    def observe(status):
        publish(status)
        # A publication can sample the clock before the test advances it.
        payload = json.loads(worker.health_path.read_text())
        if datetime.fromisoformat(payload["updated_at"]).second == 31:
            refreshed.set()

    monkeypatch.setattr(http, "request", blocked)
    monkeypatch.setattr(worker, "_publish_health", observe)
    result = []
    thread = Thread(target=lambda: result.append(worker.run_once(timeout=0)))
    thread.start()
    try:
        assert entered.wait(2)
        assert repo.get_ai_run(run["id"])["status"] == "ANALYZING"
        Clock.value += timedelta(seconds=31)
        assert refreshed.wait(1)
        assert module._healthy(worker.health_path, 30)
        assert queue.acked == []
    finally:
        release.set()
        thread.join(2)
    assert not thread.is_alive() and result == [True]
    assert repo.get_ai_run(run["id"])["status"] == "COMPLETED"
    assert len(http.requests) == 1 and queue.acked == ["receipt"]
    assert len(heartbeat_threads) == 1
