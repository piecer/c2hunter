"""Saved HTTP replay and built-in dispatch ownership (Redis uses a client fake)."""

import json
import threading
from collections import defaultdict

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller.ai_queueing import (
    InlineAIAnalysisTaskQueue,
    MemoryAIAnalysisTaskQueue,
    RedisAIAnalysisTaskQueue,
    RedisAIAnalysisWorkerQueue,
)
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.app import create_app
from c2hunter_controller.historical_ai_storage import OWNER_KEY
from c2hunter_controller.local_ai_runtime import LocalAITaskQueue
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_http_routes import headers, settings
from tests.test_historical_ai_execution import RecordingGateway, forbidden
from tests.test_historical_ai_storage import prepared


class RedisClientFake:
    """Models list/lease semantics; does NOT execute Lua or contact Redis."""

    def __init__(self):
        self.lists = defaultdict(list)
        self.leases = defaultdict(dict)
        self.scripts = []
        self.lock = threading.Lock()

    def ping(self):
        return True

    def lpush(self, key, value):
        self.lists[key].insert(0, value)

    def llen(self, key):
        return len(self.lists[key])

    def eval(self, script, numkeys, *args):
        assert numkeys == 2
        waiting, processing, envelope = args
        # Require one atomic call that checks both custody locations, then inserts.
        assert "LRANGE" in script and "LPUSH" in script
        assert "KEYS[1]" in script and "KEYS[2]" in script and "ARGV[1]" in script
        self.scripts.append((script, args))
        with self.lock:
            if envelope in self.lists[waiting] or envelope in self.lists[processing]:
                return 0
            self.lpush(waiting, envelope)
            return 1

    def brpoplpush(self, waiting, processing, timeout):
        with self.lock:
            if not self.lists[waiting]:
                return None
            value = self.lists[waiting].pop()
            self.lpush(processing, value)
            return value

    def zadd(self, key, mapping):
        self.leases[key].update(mapping)

    def zrangebyscore(self, key, lower, upper):
        return [value for value, expiry in self.leases[key].items() if expiry <= upper]

    def pipeline(self, transaction):
        assert transaction
        return self

    def lrem(self, key, count, value):
        assert count == 1
        if value in self.lists[key]:
            self.lists[key].remove(value)

    def zrem(self, key, value):
        self.leases[key].pop(value, None)

    def execute(self):
        pass


def task_queue(adapter, service):
    if adapter == "inline":
        return InlineAIAnalysisTaskQueue(service.execute)
    if adapter == "local":
        return LocalAITaskQueue()
    if adapter == "redis-fake":
        queue = RedisAIAnalysisTaskQueue("redis://unused.invalid", queue_key="test:historical")
        queue.client = RedisClientFake()
        return queue
    return MemoryAIAnalysisTaskQueue()


def client_for(repo, queue, gateway):
    return TestClient(
        create_app(
            settings().model_copy(update={"ai_analysis_enabled": True}),
            repo,
            ai_gateway=gateway,
            ai_task_queue=queue,
        ),
        raise_server_exceptions=False,
    )


@pytest.mark.parametrize("adapter", ["memory", "local", "inline", "redis-fake"])
@pytest.mark.parametrize("accepted", [False, True], ids=["not-enqueued", "accepted-then-raise"])
def test_http_replay_repairs_uncertain_dispatch_without_source_lookup(
    monkeypatch, adapter, accepted
):
    repo = MemoryRepository()
    request, _, _ = prepared(repo)
    gateway = RecordingGateway()
    queue = task_queue(adapter, ai.AIAnalysisService(repo, gateway))
    # This explicit seam must exist on every built-in task queue.
    dispatch = queue.ensure_enqueued
    fired = []

    def uncertain(run_id):
        if accepted:
            dispatch(run_id)
        fired.append(run_id)
        raise OSError("injected ambiguous queue response")

    monkeypatch.setattr(queue, "ensure_enqueued", uncertain)
    path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    with client_for(repo, queue, gateway) as client:
        first = client.post(path, json=request.payload.to_mapping(), headers=headers("analyst"))
        assert first.status_code == 503, first.text
        assert len(fired) == 1
        run = repo.get_ai_run(fired[0])
        owner = run[OWNER_KEY]
        monkeypatch.setattr(queue, "ensure_enqueued", dispatch)
        for name in (
            "get_job",
            "get_job_summary",
            "get_candidates",
            "read_historical_source",
            "get_baseline_scope",
        ):
            monkeypatch.setattr(repo, name, forbidden)
        for _ in range(2):
            replay = client.post(
                path, json=request.payload.to_mapping(), headers=headers("analyst")
            )
            assert replay.status_code == 200, replay.text
            assert replay.json()["id"] == run["id"]
        saved = repo.get_ai_run(run["id"])
        assert saved[OWNER_KEY] == owner
        if adapter == "inline":
            assert saved["status"] == "COMPLETED"
            assert len(gateway.calls) == 1
        else:
            assert saved["status"] == "QUEUED"
            assert queue.depth() == 1
            assert gateway.calls == []
        conflict = {**request.payload.to_mapping(), "language": "en"}
        assert client.post(path, json=conflict, headers=headers("analyst")).status_code == 409
        assert queue.depth() == (0 if adapter == "inline" else 1)
    repo.close()


@pytest.mark.parametrize("failure", ["baseline", "historical", "outcome-unknown"])
def test_inline_storage_uncertainty_keeps_storage_error_and_saved_outcome(monkeypatch, failure):
    from c2hunter_controller._baseline_storage import BaselineStorageError
    from c2hunter_controller.historical_ai_storage import (
        HistoricalStorageError,
        HistoricalStorageOutcomeUnknown,
    )

    error = {
        "baseline": BaselineStorageError,
        "historical": HistoricalStorageError,
        "outcome-unknown": HistoricalStorageOutcomeUnknown,
    }[failure]
    repo = MemoryRepository()
    request, _, _ = prepared(repo)
    gateway = RecordingGateway()
    queue = task_queue("inline", ai.AIAnalysisService(repo, gateway))
    original = repo.save_ai_run
    fired = []

    def fail(value):
        fired.append(value["id"])
        raise error()

    monkeypatch.setattr(repo, "save_ai_run", fail)
    path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    with client_for(repo, queue, gateway) as client:
        response = client.post(path, json=request.payload.to_mapping(), headers=headers("analyst"))
        assert response.status_code == 503
        assert len(fired) == 1
        assert response.json()["error"]["code"] == "BASELINE_STORAGE_UNAVAILABLE"
        assert repo.get_ai_run(fired[0])["status"] == "QUEUED"
        assert gateway.calls == []
        monkeypatch.setattr(repo, "save_ai_run", original)
        retry = client.post(path, json=request.payload.to_mapping(), headers=headers("analyst"))
        assert retry.status_code == 200 and retry.json()["status"] == "COMPLETED"
        assert len(gateway.calls) == 1
    repo.close()


def test_native_local_inflight_replay_and_stale_dispatch_do_not_repeat_model(monkeypatch):
    import time

    repo = MemoryRepository()
    request, _, _ = prepared(repo)
    entered, release = threading.Event(), threading.Event()

    class Gateway(RecordingGateway):
        def assess(self, bundle):
            entered.set()
            assert release.wait(5)
            return super().assess(bundle)

    gateway = Gateway()
    app = create_app(
        settings().model_copy(update={"ai_analysis_enabled": True}),
        repo,
        ai_gateway=gateway,
        local_ai_worker_enabled=True,
    )
    path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    with TestClient(app) as client:
        try:
            posted = client.post(
                path, json=request.payload.to_mapping(), headers=headers("analyst")
            )
            assert posted.status_code == 201, posted.text
            run_id = posted.json()["id"]
            assert entered.wait(3)
            queue = app.state.ai_analysis_queue
            runtime = app.state.local_ai_runtime
            assert runtime.inflight == run_id and queue.depth() == 0
            for name in (
                "get_job",
                "get_job_summary",
                "get_candidates",
                "read_historical_source",
                "get_baseline_scope",
            ):
                monkeypatch.setattr(repo, name, forbidden)
            active = client.post(
                path, json=request.payload.to_mapping(), headers=headers("analyst")
            )
            assert active.status_code == 200 and active.json()["status"] == "ANALYZING"
            # Dispatch may follow a QUEUED snapshot read just before a native claim.
            queue.ensure_enqueued(run_id)
            assert queue.depth() == 0
            release.set()
            deadline = time.monotonic() + 5
            while runtime.inflight is not None and time.monotonic() < deadline:
                time.sleep(0.01)
            assert runtime.inflight is None and queue.depth() == 0
            assert repo.get_ai_run(run_id)["status"] == "COMPLETED"
            monkeypatch.setattr(queue, "ensure_enqueued", forbidden)
            terminal = client.post(
                path, json=request.payload.to_mapping(), headers=headers("analyst")
            )
            assert terminal.status_code == 200 and terminal.json()["status"] == "COMPLETED"
            assert len(gateway.calls) == 1
        finally:
            release.set()
    assert runtime.thread is not None and not runtime.thread.is_alive()
    repo.close()


@pytest.mark.parametrize("adapter", ["memory", "local"])
def test_dispatch_replay_does_not_duplicate_claimed_local_work(adapter):
    queue = task_queue(adapter, None)
    queue.ensure_enqueued("saved-run")
    assert queue.claim_local() == "saved-run"
    assert queue.depth() == 0
    # Includes a stale HTTP QUEUED read racing with the coordinator's claim.
    queue.ensure_enqueued("saved-run")
    assert queue.depth() == 0
    queue.release_local("saved-run")
    queue.ensure_enqueued("saved-run")
    assert queue.depth() == 1


def test_redis_replay_checks_waiting_processing_and_worker_ack(monkeypatch):
    repo = MemoryRepository()
    request, _, _ = prepared(repo)
    gateway = RecordingGateway()
    service = ai.AIAnalysisService(repo, gateway)
    queue = task_queue("redis-fake", service)
    consumer = RedisAIAnalysisWorkerQueue("redis://unused.invalid", queue_key=queue.queue_key)
    consumer.client = queue.client
    path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
    with client_for(repo, queue, gateway) as client:
        posted = client.post(path, json=request.payload.to_mapping(), headers=headers("analyst"))
        assert posted.status_code == 201
        run_id = posted.json()["id"]
        # Existing legacy-format envelopes are recognized, with no marker migration.
        assert json.loads(queue.client.lists[queue.queue_key][0]) == {"ai_run_id": run_id}
        claimed = consumer.claim(timeout=0)
        assert claimed["ai_run_id"] == run_id
        for _ in range(2):
            assert (
                client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                ).status_code
                == 200
            )
        assert consumer.depth() == (0, 1)
        assert len(queue.client.scripts) == 3
        # Run the real worker with the actual claimed message, then actual adapter ACK.
        monkeypatch.setattr(consumer, "claim", lambda timeout: claimed)
        assert AIAnalysisWorker(consumer, service).run_once(timeout=0)
        assert consumer.depth() == (0, 0)
        assert queue.client.leases[consumer.leases_key] == {}
        calls = len(queue.client.scripts)
        assert (
            client.post(
                path, json=request.payload.to_mapping(), headers=headers("analyst")
            ).status_code
            == 200
        )
        assert len(queue.client.scripts) == calls
        assert len(gateway.calls) == 1
    repo.close()
