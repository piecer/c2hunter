import asyncio
import threading

import pytest
from test_network_ai import create, setup

from c2hunter_controller.ai_queueing import MemoryAIAnalysisTaskQueue
from c2hunter_controller.repositories import SQLiteRepository


def test_local_ai_queue_is_bounded_and_interrupted_runs_are_terminal(tmp_path):
    from c2hunter_controller.local_ai_runtime import LocalAIRuntime, LocalAITaskQueue

    queue = LocalAITaskQueue()
    for index in range(32):
        queue.enqueue(str(index))
    with pytest.raises(OverflowError):
        queue.enqueue("overflow")
    assert queue.depth() == 32
    repository, service, _ = setup(SQLiteRepository(tmp_path / "recovery.sqlite3"))
    run, _ = create(service)

    async def exercise():
        runtime = LocalAIRuntime(LocalAITaskQueue(), service)
        await runtime.start()
        assert repository.get_ai_run(run["id"])["status"] == "CANCELLED"
        await runtime.stop()

    asyncio.run(exercise())


@pytest.mark.parametrize("outcome", ["success", "error", "cancel"])
def test_local_ai_compute_is_async_and_repository_stays_on_owner(tmp_path, outcome):
    from c2hunter_controller.local_ai_runtime import LocalAIRuntime

    async def exercise():
        owner = threading.get_ident()
        repository, service, transport = setup(SQLiteRepository(tmp_path / "runtime.sqlite3"))
        entered = threading.Event()
        release = threading.Event()
        original = transport.request

        def request(*args, **kwargs):
            assert threading.get_ident() != owner
            entered.set()
            assert release.wait(3)
            if outcome == "error":
                raise TimeoutError("fixture timeout")
            return original(*args, **kwargs)

        transport.request = request
        for name in ("get_ai_run", "save_ai_run"):
            method = getattr(repository, name)

            def checked(*args, _method=method):
                assert threading.get_ident() == owner
                return _method(*args)

            setattr(repository, name, checked)
        queue = MemoryAIAnalysisTaskQueue()
        runtime = LocalAIRuntime(queue, service)
        run, _ = create(service)
        queue.enqueue(run["id"])
        await runtime.start()
        try:
            for _ in range(200):
                if entered.is_set():
                    break
                await asyncio.sleep(0.01)
            assert entered.is_set()
            assert repository.get_ai_run(run["id"])["status"] == "ANALYZING"
            if outcome == "cancel":
                service.cancel(run["id"], "fixture cancellation")
            release.set()
            for _ in range(300):
                if not runtime.inflight and queue.depth() == 0:
                    break
                await asyncio.sleep(0.01)
            expected = {"success": "COMPLETED", "error": "FAILED", "cancel": "CANCELLED"}[outcome]
            final = repository.get_ai_run(run["id"])
            assert final["status"] == expected
            assert not runtime.inflight
            assert queue.depth() == 0
            reopened = SQLiteRepository(tmp_path / "runtime.sqlite3")
            assert reopened.get_ai_run(run["id"])["status"] == expected
        finally:
            release.set()
            await runtime.stop()

    asyncio.run(exercise())


@pytest.mark.parametrize("outcome", ["success", "error", "cancel"])
def test_local_ai_app_api_consumes_manual_run_without_blocking(tmp_path, outcome):
    import time

    from fastapi.testclient import TestClient

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    repository, service, transport = setup(SQLiteRepository(tmp_path / "api.sqlite3"))
    entered = threading.Event()
    release = threading.Event()
    original = transport.request

    def request(*args, **kwargs):
        entered.set()
        assert release.wait(4)
        if outcome == "error":
            raise TimeoutError("fixture timeout")
        return original(*args, **kwargs)

    transport.request = request
    service.gateway.ready = lambda: True
    app = create_app(
        Settings(environment="test", ai_analysis_enabled=True),
        repository,
        ai_gateway=service.gateway,
        local_ai_worker_enabled=True,
    )
    with TestClient(app) as client:
        started = time.monotonic()
        posted = client.post(
            "/api/v1/analysis-jobs/network-job/ai-runs",
            json={
                "idempotency_key": outcome,
                "analysis_kind": "NETWORK_ANOMALY",
                "language": "ko",
            },
        )
        assert posted.status_code == 201
        assert time.monotonic() - started < 1
        run_id = posted.json()["id"]
        assert entered.wait(2)
        assert client.get("/api/v1/ai-runs/" + run_id).json()["status"] == "ANALYZING"
        if outcome == "cancel":
            assert (
                client.post(
                    "/api/v1/ai-runs/" + run_id + "/cancel", json={"reason": "test"}
                ).json()["status"]
                == "CANCELLED"
            )
        release.set()
        expected = {"success": "COMPLETED", "error": "FAILED", "cancel": "CANCELLED"}[outcome]
        for _ in range(300):
            response = client.get("/api/v1/ai-runs/" + run_id)
            assert response.status_code == 200, response.text
            final = response.json()
            if final["status"] == expected and not app.state.local_ai_runtime.inflight:
                break
            time.sleep(0.01)
        assert final["status"] == expected
        assert not app.state.local_ai_runtime.inflight
        assert app.state.ai_analysis_queue.depth() == 0
        assert SQLiteRepository(tmp_path / "api.sqlite3").get_ai_run(run_id)["status"] == expected
