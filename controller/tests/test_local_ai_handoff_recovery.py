"""Independent changed-caller probes, real ASGI/service/local coordinator; no engines."""

import asyncio
import json
import threading
from copy import deepcopy

import httpx
import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller._baseline_storage import BaselineStorageError
from c2hunter_controller.ai_queueing import InlineAIAnalysisTaskQueue, MemoryAIAnalysisTaskQueue
from c2hunter_controller.app import create_app
from c2hunter_controller.historical_ai_storage import OWNER_KEY, materialize_historical_run
from c2hunter_controller.local_ai_runtime import LocalAIRuntime, LocalAITaskQueue
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_http_routes import headers, settings
from tests.test_historical_ai_execution import RecordingGateway, admitted
from tests.test_historical_ai_storage import prepared


@pytest.fixture
def record(tmp_path):
    def write(name, observation):
        (tmp_path / (name + ".json")).write_text(json.dumps(observation, indent=2) + "\n")
        print(name, observation)

    return write


def test_off_dispatch_keeps_enqueue_only_and_original_replay(monkeypatch):
    repo = MemoryRepository()
    request, _, _ = prepared(repo)
    queue = MemoryAIAnalysisTaskQueue()
    enqueue = queue.enqueue
    calls = []

    def observed(run_id):
        calls.append(run_id)
        enqueue(run_id)

    def forbidden(*args):
        pytest.fail("off-mode must not use historical recovery seam")

    monkeypatch.setattr(queue, "enqueue", observed)
    monkeypatch.setattr(queue, "ensure_enqueued", forbidden)
    app = create_app(
        settings().model_copy(update={"ai_analysis_enabled": True}),
        repo,
        ai_gateway=ai.FakeGateway(),
        ai_task_queue=queue,
    )
    payload = {"idempotency_key": "off-replay", "baseline_mode": "off", "baseline_reference": None}
    with TestClient(app) as client:
        path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
        first = client.post(path, json=payload, headers=headers("analyst"))
        assert first.status_code == 201, first.text
        replay = client.post(path, json=payload, headers=headers("analyst"))
        assert replay.status_code == 200, replay.text
        assert calls == [first.json()["id"]]
        assert queue.depth() == 1
    repo.close()


def test_local_ensure_coalesces_before_full_capacity_check():
    queue = LocalAITaskQueue()
    queue.ensure_enqueued("active")
    assert queue.claim_local() == "active"
    for i in range(32):
        queue.ensure_enqueued(f"waiting-{i}")
    queue.ensure_enqueued("active")
    queue.ensure_enqueued("waiting-0")
    assert queue.depth() == 32
    with pytest.raises(OverflowError):
        queue.ensure_enqueued("new")
    queue.release_local("active")
    with pytest.raises(OverflowError):
        queue.ensure_enqueued("active")
    assert queue.claim_local() == "waiting-0"
    queue.release_local("waiting-0")
    queue.ensure_enqueued("active")
    assert queue.depth() == 32


def test_inline_active_coalescing_and_exception_release():
    entered, release = threading.Event(), threading.Event()
    calls, failures = [], []
    error = BaselineStorageError()

    def execute(run_id):
        calls.append(run_id)
        if len(calls) == 1:
            entered.set()
            assert release.wait(3)
            raise error
        return {"id": run_id, "status": "COMPLETED"}

    queue = InlineAIAnalysisTaskQueue(execute)

    def first():
        try:
            queue.ensure_enqueued("same")
        except Exception as exc:
            failures.append(exc)

    thread = threading.Thread(target=first)
    thread.start()
    try:
        assert entered.wait(3)
        queue.ensure_enqueued("same")
        assert calls == ["same"]
    finally:
        release.set()
        thread.join(3)
    assert not thread.is_alive() and failures == [error]
    queue.ensure_enqueued("same")
    assert calls == ["same", "same"]
    assert not queue._active


@pytest.mark.parametrize("kind", ["missing", "terminal"])
def test_local_claim_skips_release_ownership(kind):
    async def exercise():
        repo = MemoryRepository()
        run = admitted(repo)
        service = ai.AIAnalysisService(repo, RecordingGateway())
        if kind == "terminal":
            service.cancel(run["id"], "review terminal control")
        run_id = run["id"] if kind == "terminal" else "absent"
        queue = LocalAITaskQueue()
        queue.ensure_enqueued(run_id)
        runtime = LocalAIRuntime(queue, service)
        try:
            await runtime.start()
            async with asyncio.timeout(3):
                while queue.depth():
                    await asyncio.sleep(0.01)
            assert runtime.inflight is None and runtime.thread is None
            assert run_id not in queue._inflight
            queue.ensure_enqueued(run_id)
            assert queue.depth() == 1
            async with asyncio.timeout(3):
                while queue.depth():
                    await asyncio.sleep(0.01)
        finally:
            await runtime.stop()
            repo.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("fault", ["read-before-compute", "thread-start"])
def test_failed_local_claim_does_not_suppress_http_retry(monkeypatch, fault, record):
    async def exercise():
        repo = MemoryRepository()
        request, _, _ = prepared(repo)
        gateway = RecordingGateway()
        app = create_app(
            settings().model_copy(update={"ai_analysis_enabled": True}),
            repo,
            ai_gateway=gateway,
            local_ai_worker_enabled=True,
        )
        runtime = app.state.local_ai_runtime
        queue = app.state.ai_analysis_queue
        path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
        fired = []
        primary = (
            BaselineStorageError()
            if fault == "read-before-compute"
            else RuntimeError("injected thread start failure")
        )
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                posted = await client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                )
                assert posted.status_code == 201, posted.text
                run_id = posted.json()["id"]
                assert queue.run_ids == [run_id]
                # start() does its census without yielding; inject after that
                # before awaiting the newly created coordinator task.
                await runtime.start()
                with monkeypatch.context() as patch:
                    if fault == "read-before-compute":
                        original = repo.get_ai_run  # noqa: F841 - preserved independent probe

                        def failed_get(identifier):
                            fired.append(identifier)
                            raise primary

                        patch.setattr(repo, "get_ai_run", failed_get)
                    else:
                        original_start = threading.Thread.start

                        def failed_start(thread):
                            if thread.name == "local-ai-worker":
                                fired.append(run_id)
                                raise primary
                            return original_start(thread)

                        patch.setattr(threading.Thread, "start", failed_start)
                    with pytest.raises(type(primary)) as raised:
                        await asyncio.wait_for(runtime.task, 3)
                    assert raised.value is primary
                assert fired == [run_id]
                assert runtime.thread is None or not runtime.thread.is_alive()
                assert repo.get_ai_run(run_id)["status"] == "QUEUED"
                replay = await client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                )
                observed = {
                    "fault": fault,
                    "fault_fired": fired,
                    "first_http": posted.status_code,
                    "replay_http": replay.status_code,
                    "run_status": replay.json().get("status"),
                    "queue_depth": queue.depth(),
                    "queue_claims": sorted(queue._inflight),
                    "runtime_inflight": runtime.inflight,
                    "coordinator_done": runtime.task.done(),
                    "coordinator_error": type(runtime.task.exception()).__name__,
                    "thread_started": runtime.thread is not None
                    and runtime.thread.ident is not None,
                    "gateway_calls": len(gateway.calls),
                }
                record("local-claim-" + fault, observed)
                assert replay.status_code == 200, replay.text
                assert gateway.calls == []
                assert run_id not in queue._inflight, (
                    "failed ownership handoff leaves a permanent false active claim"
                )
                assert queue.depth() == 1, (
                    "same-request replay must not be coalesced against an owner that never started"
                )
        finally:
            try:
                await runtime.stop()
            except Exception as exc:
                assert exc is primary
            await app.state.baseline_transport.shutdown()
            repo.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("fault", ["read-before-compute", "thread-construction", "thread-start"])
def test_native_successor_after_failed_handoff(monkeypatch, fault):
    """Explicit test recovery, not automatic restart or durable local dispatch."""

    async def exercise():
        repo = MemoryRepository()
        request, _, _ = prepared(repo)
        entered, release_compute = threading.Event(), threading.Event()

        class Gateway(RecordingGateway):
            def assess(self, bundle):
                result = super().assess(bundle)
                entered.set()
                assert release_compute.wait(5)
                return result

        gateway = Gateway()
        app = create_app(
            settings().model_copy(update={"ai_analysis_enabled": True}),
            repo,
            ai_gateway=gateway,
            local_ai_worker_enabled=True,
        )
        runtime = app.state.local_ai_runtime
        queue = app.state.ai_analysis_queue
        successor = None
        primary = BaselineStorageError() if fault == "read-before-compute" else RuntimeError(fault)
        fired, releases, closes, joins = [], [], [], []
        release_local = queue.release_local
        close = repo.close
        join = threading.Thread.join

        def released(run_id):
            releases.append(run_id)
            release_local(run_id)

        def closed():
            closes.append("repo")
            close()

        def joined(thread, *args, **kwargs):
            if thread.name == "local-ai-worker":
                joins.append(thread)
            return join(thread, *args, **kwargs)

        monkeypatch.setattr(queue, "release_local", released)
        monkeypatch.setattr(repo, "close", closed)
        monkeypatch.setattr(threading.Thread, "join", joined)
        # An unrelated reservation must not be cleared as part of this unwind.
        queue.ensure_enqueued("other-owner")
        assert queue.claim_local() == "other-owner"
        path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                posted = await client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                )
                assert posted.status_code == 201, posted.text
                run_id = posted.json()["id"]
                saved = deepcopy(repo.get_ai_run(run_id))
                _, bundles = materialize_historical_run(saved)
                await runtime.start()
                with monkeypatch.context() as patch:

                    def fail():
                        assert queue._inflight == {"other-owner", run_id}
                        assert queue.depth() == 0
                        fired.append(run_id)
                        raise primary

                    if fault == "read-before-compute":

                        def failed_get(identifier):
                            assert identifier == run_id
                            fail()

                        patch.setattr(repo, "get_ai_run", failed_get)
                    elif fault == "thread-construction":
                        original_init = threading.Thread.__init__

                        def failed_init(thread, *args, **kwargs):
                            if kwargs.get("name") == "local-ai-worker":
                                fail()
                            original_init(thread, *args, **kwargs)

                        patch.setattr(threading.Thread, "__init__", failed_init)
                    else:
                        original_start = threading.Thread.start

                        def failed_start(thread):
                            if thread.name == "local-ai-worker":
                                fail()
                            return original_start(thread)

                        patch.setattr(threading.Thread, "start", failed_start)
                    with pytest.raises(type(primary)) as raised:
                        await asyncio.wait_for(runtime.task, 3)
                    assert raised.value is primary
                assert fired == [run_id]
                assert releases == [run_id]
                assert queue._inflight == {"other-owner"}
                assert queue.depth() == 0
                assert runtime.inflight is None and runtime.thread is None
                assert runtime.finished.empty() and runtime.calls.empty()
                assert runtime.task.done() and runtime.task.exception() is primary
                assert repo.get_ai_run(run_id) == saved
                assert gateway.calls == [] and closes == []
                with pytest.raises(type(primary)) as stopped:
                    await runtime.stop()
                assert stopped.value is primary
                assert joins == [] and closes == []
                assert repo.get_ai_run(run_id) == saved
                assert runtime.inflight is None and runtime.thread is None
                assert runtime.stopped.is_set()
                assert releases == [run_id]
                assert queue._inflight == {"other-owner"}
                for _ in range(2):
                    replay = await client.post(
                        path, json=request.payload.to_mapping(), headers=headers("analyst")
                    )
                    assert replay.status_code == 200, replay.text
                    assert replay.json()["id"] == run_id
                    assert replay.json()["status"] == "QUEUED"
                    assert queue.run_ids == [run_id]
                    assert queue._inflight == {"other-owner"}
                # A native new coordinator, with the SAME repository and queue.
                successor = LocalAIRuntime(queue, runtime.service)
                assert successor.queue is queue and successor.service.repository is repo
                await successor.start()
                async with asyncio.timeout(5):
                    while not entered.is_set():
                        await asyncio.sleep(0.01)
                assert successor.inflight == run_id
                assert successor.thread is not None and successor.thread.is_alive()
                assert queue._inflight == {"other-owner", run_id}
                assert releases == [run_id] and queue.depth() == 0
                active = await client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                )
                assert active.status_code == 200 and active.json()["status"] == "ANALYZING"
                queue.ensure_enqueued(run_id)  # A stale QUEUED snapshot also coalesces.
                assert queue.depth() == 0 and queue._inflight == {"other-owner", run_id}
                assert len(gateway.calls) == 1
                release_compute.set()
                async with asyncio.timeout(5):
                    while (
                        repo.get_ai_run(run_id)["status"] != "COMPLETED"
                        or successor.inflight is not None
                    ):
                        await asyncio.sleep(0.01)
                assert gateway.calls == [b.model_dump(mode="json", by_alias=True) for b in bundles]
                assert len(gateway.calls) == 1
                final = repo.get_ai_run(run_id)
                assert final[OWNER_KEY] == saved[OWNER_KEY]
                assert [step["to_status"] for step in final["transitions"]] == [
                    "QUEUED",
                    "PREPARING",
                    "ANALYZING",
                    "VALIDATING",
                    "COMPLETED",
                ]
                assessments = repo.list_ai_assessments(run_id)
                assert len(assessments) == 1
                assert assessments[0]["evidence_bundle"] == gateway.calls[0]
                assert len(repo.list_ai_artifacts(assessments[0]["id"])) == 3
                assert releases == [run_id, run_id]
                assert queue._inflight == {"other-owner"} and queue.depth() == 0
                assert closes == []
                await successor.stop()
                assert successor.thread is not None and not successor.thread.is_alive()
                assert joins == [successor.thread] and closes == []
        finally:
            release_compute.set()
            if successor is not None and not successor.stopped.is_set():
                await successor.stop()
            if not runtime.stopped.is_set():
                try:
                    await runtime.stop()
                except Exception as exc:
                    assert exc is primary
            await app.state.baseline_transport.shutdown()
            repo.close()

    asyncio.run(exercise())


def test_local_compute_storage_failure_releases_claim_for_http_retry(monkeypatch, record):
    async def exercise():
        repo = MemoryRepository()
        request, _, _ = prepared(repo)
        gateway = RecordingGateway()
        app = create_app(
            settings().model_copy(update={"ai_analysis_enabled": True}),
            repo,
            ai_gateway=gateway,
            local_ai_worker_enabled=True,
        )
        runtime = app.state.local_ai_runtime
        queue = app.state.ai_analysis_queue
        path = f"/api/v1/analysis-jobs/{request.analysis_job_id}/ai-runs"
        primary = BaselineStorageError()
        fired, uncaught = [], []
        original = repo.save_ai_run

        def fail_once(value):
            if not fired:
                fired.append(value["id"])
                raise primary
            return original(value)

        monkeypatch.setattr(repo, "save_ai_run", fail_once)
        monkeypatch.setattr(threading, "excepthook", lambda args: uncaught.append(args.exc_value))
        try:
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test"
            ) as client:
                first = await client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                )
                assert first.status_code == 201, first.text
                run_id = first.json()["id"]
                await runtime.start()
                async with asyncio.timeout(5):
                    while not uncaught or runtime.inflight is not None or queue.depth():
                        await asyncio.sleep(0.01)
                assert uncaught == [primary] and fired == [run_id]
                assert repo.get_ai_run(run_id)["status"] == "QUEUED"
                assert not queue._inflight and gateway.calls == []
                retry = await client.post(
                    path, json=request.payload.to_mapping(), headers=headers("analyst")
                )
                assert retry.status_code == 200, retry.text
                async with asyncio.timeout(5):
                    while (
                        repo.get_ai_run(run_id)["status"] != "COMPLETED"
                        or runtime.inflight is not None
                    ):
                        await asyncio.sleep(0.01)
                assert len(gateway.calls) == 1
                assert not queue._inflight and queue.depth() == 0
                record(
                    "local-compute-storage-recovery",
                    {
                        "faults": len(fired),
                        "uncaught": len(uncaught),
                        "completed": True,
                        "gateway_calls": len(gateway.calls),
                        "queue_claims": sorted(queue._inflight),
                    },
                )
        finally:
            await runtime.stop()
            await app.state.baseline_transport.shutdown()
            assert runtime.thread is None or not runtime.thread.is_alive()
            repo.close()

    asyncio.run(exercise())
