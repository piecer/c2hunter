"""Local callback ownership/liveness with private SQLite and no real detector."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path

import pytest

from c2hunter_controller.local_analysis_runtime import LocalAnalysisRuntime
from c2hunter_controller.queueing import MemoryControllerQueue
from c2hunter_controller.repositories import SQLiteRepository


@pytest.fixture(autouse=True)
def worker_package(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))


async def eventually(predicate):
    async with asyncio.timeout(3):
        while not predicate():
            await asyncio.sleep(0.01)


@pytest.mark.parametrize("phase", ["prepare", "process_due", "publish"])
def test_blocking_callbacks_leave_event_loop_responsive(tmp_path: Path, phase: str):
    async def exercise():
        loop = asyncio.get_running_loop()
        owner = threading.get_ident()
        repo = SQLiteRepository(tmp_path / "jobs.db")
        entered, release, heartbeat = (threading.Event() for _ in range(3))
        observed, calls = [], []

        def callback(name):
            calls.append((name, threading.get_ident()))
            # Exercise the actual shared SQLite connection on the callback owner.
            repo.list_jobs()
            if name == phase and not entered.is_set():
                entered.set()
                assert release.wait(3), "observer did not release callback"
            return False

        def observe():
            try:
                assert entered.wait(3), "callback never entered"
                loop.call_soon_threadsafe(heartbeat.set)
                observed.append(heartbeat.wait(1))
            finally:
                release.set()

        runtime = LocalAnalysisRuntime(
            MemoryControllerQueue(),
            repo,
            lambda: callback("process_due"),
            lambda result: callback("publish"),
            tmp_path / "health.json",
            lambda job: None,
            prepare=lambda: callback("prepare"),
            ownership_path=tmp_path / "jobs.db",
        )
        runtime.bridge.complete("receipt", {"status": "COMPLETED", "job_id": "fixture"})
        observer = threading.Thread(target=observe, name="callback-observer")
        observer.start()
        try:
            await runtime.start()
            await eventually(lambda: bool(observed))
        finally:
            release.set()
            await runtime.stop()
            observer.join(3)
            repo.close()
        assert not observer.is_alive()
        assert observed == [True], f"{phase} blocked the async event loop"
        assert calls and all(identity != owner for _, identity in calls)
        assert len({identity for _, identity in calls}) == 1
        assert not runtime.thread.is_alive()
        assert runtime.ownership_file is None

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("phase", "target"),
    [
        ("prepare", "start"),
        ("process_due", "task"),
        ("publish", "task"),
        ("process_due", "stop"),
        ("publish", "stop"),
    ],
)
def test_cancellation_retires_callback_before_returning(tmp_path, phase, target):
    async def exercise():
        repo = SQLiteRepository(tmp_path / "jobs.db")
        entered, release, retired = (threading.Event() for _ in range(3))
        callback_threads = []

        def callback(name):
            if name == phase:
                callback_threads.append(threading.current_thread())
                entered.set()
                try:
                    assert release.wait(3), "test did not release callback"
                    repo.list_jobs()
                finally:
                    retired.set()
            return False

        runtime = LocalAnalysisRuntime(
            MemoryControllerQueue(),
            repo,
            lambda: callback("process_due"),
            lambda result: callback("publish"),
            tmp_path / "health.json",
            lambda job: None,
            prepare=lambda: callback("prepare"),
            ownership_path=tmp_path / "jobs.db",
        )
        result = {"receipt": "receipt", "status": "COMPLETED", "job_id": "fixture"}
        runtime.bridge.results.put_nowait(result)
        runtime.inflight = True
        starter = asyncio.create_task(runtime.start())
        victim = None
        observations = {}
        try:
            await eventually(entered.is_set)
            if target != "start":
                await starter
            victim = (
                starter
                if target == "start"
                else runtime.task
                if target == "task"
                else asyncio.create_task(runtime.stop())
            )
            await asyncio.sleep(0)
            victim.cancel()
            # Deliver cancellation repeatedly, including during native retirement.
            await asyncio.sleep(0.02)
            victim.cancel()
            await asyncio.sleep(0.02)
            observations["returned_early"] = victim.done()
            observations["owned_while_blocked"] = (
                runtime.ownership_file is not None and not runtime.ownership_file.closed
            )
            observations["retired_early"] = retired.is_set()
            if phase == "publish":
                observations["pending_retained"] = runtime.pending is result and runtime.inflight
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await victim
            observations["retired_on_return"] = retired.is_set()
            try:
                await runtime.stop()
            except asyncio.CancelledError:
                pass
            observations["ownership_released"] = runtime.ownership_file is None
            observations["callbacks_joined"] = all(not t.is_alive() for t in callback_threads)
            if phase == "prepare":
                observations["no_detector_started"] = runtime.thread.ident is None
        finally:
            release.set()
            runtime.stopped.set()
            # Also retire the deliberately broken RED implementation before teardown.
            await asyncio.gather(starter, *([victim] if victim else []), return_exceptions=True)
            await asyncio.to_thread(runtime.coordinator.shutdown, wait=True)
            if runtime.thread.ident is not None:
                await asyncio.to_thread(runtime.thread.join, 2)
            if runtime.ownership_file is not None:
                runtime.ownership_file.close()
            repo.close()
        assert observations == {
            "returned_early": False,
            "owned_while_blocked": True,
            "retired_early": False,
            **({"pending_retained": True} if phase == "publish" else {}),
            "retired_on_return": True,
            "ownership_released": True,
            "callbacks_joined": True,
            **({"no_detector_started": True} if phase == "prepare" else {}),
        }

    asyncio.run(exercise())


@pytest.mark.parametrize("fault", ["prepare", "census", "thread-start", "coordinator"])
def test_failure_preserves_primary_and_releases_ownership(tmp_path, monkeypatch, fault):
    class FatalCallback(BaseException):
        pass

    async def exercise():
        repo = SQLiteRepository(tmp_path / "jobs.db")
        primary = FatalCallback("primary callback failure")
        owner_threads, joins, fired = [], [], []

        def fail():
            owner_threads.append(threading.current_thread())
            fired.append(fault)
            raise primary

        runtime = LocalAnalysisRuntime(
            MemoryControllerQueue(),
            repo,
            fail if fault == "coordinator" else lambda: False,
            lambda result: None,
            tmp_path / "health.json",
            lambda job: None,
            prepare=fail if fault == "prepare" else None,
            ownership_path=tmp_path / "jobs.db",
        )
        if fault == "census":
            monkeypatch.setattr(repo, "list_jobs", fail)
        if fault == "thread-start":
            monkeypatch.setattr(runtime.thread, "start", fail)
        original_join = runtime.thread.join

        def join(timeout=None):
            joins.append(timeout)
            original_join(timeout)

        monkeypatch.setattr(runtime.thread, "join", join)
        original_stop = runtime._stop

        def cleanup_failure():
            original_stop()
            raise RuntimeError("secondary cleanup failure")

        monkeypatch.setattr(runtime, "_stop", cleanup_failure)
        try:
            with pytest.raises(FatalCallback) as raised:
                await runtime.start()
                assert fault == "coordinator"
                await runtime.task
            assert raised.value is primary
            if fault == "coordinator":
                with pytest.raises(FatalCallback) as stopped:
                    await runtime.stop()
                assert stopped.value is primary
            assert fired == [fault]
            assert runtime.ownership_file is None
            assert not runtime.thread.is_alive()
            assert all(not thread.is_alive() for thread in owner_threads)
            assert joins == ([2] if fault == "coordinator" else [])
            assert runtime._worker_started == (fault == "coordinator")
        finally:
            runtime.stopped.set()
            await asyncio.to_thread(runtime.coordinator.shutdown, wait=True)
            repo.close()

    asyncio.run(exercise())


@pytest.mark.parametrize("phase", ["process_due", "publish"])
def test_stop_does_not_admit_work_after_blocked_callback(tmp_path, phase):
    async def exercise():
        repo = SQLiteRepository(tmp_path / "jobs.db")
        repo.save_job({"id": "next", "status": "ANALYZING"})
        queue = MemoryControllerQueue()
        queue.enqueue({"id": "next", "payload": {}})
        entered, release = threading.Event(), threading.Event()
        publications = []

        def block():
            entered.set()
            assert release.wait(3)

        def due():
            if phase == "process_due":
                block()
            return False

        def publish(result):
            publications.append(result)
            if phase == "publish":
                block()

        runtime = LocalAnalysisRuntime(
            queue,
            repo,
            due,
            publish,
            tmp_path / "health.json",
            lambda job: None,
            ownership_path=tmp_path / "jobs.db",
        )
        result = {"status": "COMPLETED", "job_id": "previous", "receipt": "previous"}
        runtime.bridge.results.put_nowait(result)
        runtime.inflight = True
        try:
            await runtime.start()
            await eventually(entered.is_set)
            stopping = asyncio.create_task(runtime.stop())
            await eventually(runtime.stopped.is_set)
            assert not stopping.done()
            release.set()
            await stopping
            assert publications == ([result] if phase == "publish" else [])
            assert queue.jobs == [{"id": "next", "payload": {}}]
            assert runtime.bridge.jobs.empty()
        finally:
            release.set()
            await runtime.stop()
            repo.close()

    asyncio.run(exercise())


def test_detector_join_budget_does_not_apply_to_callback_retirement(tmp_path, monkeypatch, caplog):
    async def exercise():
        repo = SQLiteRepository(tmp_path / "jobs.db")
        repo.save_job({"id": "job", "status": "ANALYZING"})
        queue = MemoryControllerQueue()
        queue.enqueue({"id": "job", "payload": {}})
        entered, release = threading.Event(), threading.Event()
        owner_threads, joins, publications = [], [], []

        def compute(payload):
            entered.set()
            assert release.wait(5)
            return {"candidates": []}

        monkeypatch.setattr("c2hunter_worker.analysis.execute_analysis", compute)

        def due():
            owner_threads.append(threading.current_thread())
            repo.list_jobs()
            return False

        runtime = LocalAnalysisRuntime(
            queue,
            repo,
            due,
            publications.append,
            tmp_path / "health.json",
            lambda job: None,
            ownership_path=tmp_path / "jobs.db",
        )
        original_join = runtime.thread.join

        def join(timeout=None):
            joins.append(timeout)
            original_join(timeout)

        monkeypatch.setattr(runtime.thread, "join", join)
        try:
            await runtime.start()
            await eventually(entered.is_set)
            await asyncio.gather(runtime.stop(), runtime.stop())
            assert joins == [2]
            assert runtime.thread.is_alive()  # The existing detector-only policy is retained.
            assert runtime.ownership_file is None
            assert all(not thread.is_alive() for thread in owner_threads)
            assert runtime.inflight
            assert "publication deferred" in caplog.text
            published_at_stop = list(publications)
            repo.close()  # The detector owns only copied payloads, never this connection.
            release.set()
            await asyncio.to_thread(original_join, 2)
            assert not runtime.thread.is_alive()
            assert publications == published_at_stop
            assert runtime.bridge.results.qsize() >= 1
        finally:
            release.set()
            await runtime.stop()
            if runtime.thread.ident is not None:
                await asyncio.to_thread(original_join, 2)
            repo.close()

    asyncio.run(exercise())


def test_real_publication_retries_audit_sql_without_reexecuting(tmp_path, monkeypatch):
    from c2hunter_controller.app import create_app
    from c2hunter_controller.auth_models import Actor
    from c2hunter_controller.auth_store import AuthStore
    from c2hunter_controller.config import Settings

    async def exercise():
        repo = SQLiteRepository(tmp_path / "jobs.db")
        auth = AuthStore(sqlite_path=tmp_path / "private" / "auth.db")
        auth.initialize()
        identity = "a" * 32
        auth.reserve_job(
            "analysis", identity, Actor(), "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "c" * 32
        )
        repo.save_job(
            {
                "id": identity,
                "status": "ANALYZING",
                "idempotency_key": "fixture",
                "analysis": {"module": "c2"},
                "candidate_count": 0,
                "transitions": [],
                "flow_records": [],
                "payload_signatures": [],
            }
        )
        queue = MemoryControllerQueue()
        queue.enqueue({"id": identity, "payload": {"id": identity}})
        computations, acks, audit_threads = [], [], []
        entered, release = threading.Event(), threading.Event()

        def compute(payload):
            computations.append((payload, threading.current_thread()))
            return {"candidates": [{"id": "new", "score": 90}]}

        monkeypatch.setattr("c2hunter_worker.analysis.execute_analysis", compute)
        monkeypatch.setattr(queue, "ack_result", acks.append)
        app = create_app(
            Settings(environment="test"),
            repo,
            queue=queue,
            auth_store=auth,
            local_analysis_worker_health_path=tmp_path / "health.json",
        )
        runtime = app.state.local_analysis_runtime
        original = auth.finish_job
        original_publish = runtime.publish
        publishing = False

        def publish(result):
            nonlocal publishing
            publishing = True
            try:
                original_publish(result)
            finally:
                publishing = False

        monkeypatch.setattr(runtime, "publish", publish)

        def finish(*args):
            if not publishing or args[2] != "COMPLETED":
                return original(*args)
            audit_threads.append(threading.current_thread())
            if len(audit_threads) == 2:
                entered.set()
                assert release.wait(3), "test did not release audit retry"
            return original(*args)

        monkeypatch.setattr(auth, "finish_job", finish)
        with auth.db.transaction() as sql:
            sql.execute(
                "CREATE TRIGGER fail_terminal BEFORE INSERT ON auth_audit "
                "WHEN NEW.outcome='succeeded' AND NEW.action='job.lifecycle' "
                "BEGIN SELECT RAISE(ABORT,'fixture audit fault'); END"
            )
        try:
            await runtime.start()
            await eventually(entered.is_set)
            assert runtime.last_error is not None  # The real SQL fault reached the owner.
            assert repo.get_job_summary(identity)["status"] == "COMPLETED"
            assert auth.job_audit_status("analysis", identity) == "pending"
            assert runtime.pending["status"] == "COMPLETED" and runtime.inflight
            assert acks == ["event:" + identity]
            assert len(computations) == 1
            assert runtime.bridge.jobs.maxsize == 1 and runtime.bridge.results.maxsize == 2
            assert runtime.bridge.jobs.empty()
            assert all(t is not threading.current_thread() for t in audit_threads)
            assert len(set(audit_threads)) == 1
            assert computations[0][1] is runtime.thread
            assert computations[0][1] not in audit_threads
            with auth.db.transaction() as sql:
                sql.execute("DROP TRIGGER fail_terminal")
            release.set()
            await eventually(lambda: runtime.pending is None and not runtime.inflight)
            assert acks == ["event:" + identity, identity]
            assert auth.job_audit_status("analysis", identity) == "complete"
            assert len(audit_threads) == 2 and len(computations) == 1
            with auth.db.transaction() as sql:
                count = sql.execute(
                    "SELECT COUNT(*) AS n FROM auth_audit WHERE job_id=? AND outcome='succeeded'",
                    (identity,),
                ).fetchone()
                assert count["n"] == 1
        finally:
            release.set()
            await runtime.stop()
            app.state.wait_for_candidate_enrichment()
            await app.state.baseline_transport.shutdown()
            repo.close()
        assert not runtime.thread.is_alive()
        assert all(not thread.is_alive() for thread in audit_threads)
        assert runtime.ownership_file is None

    asyncio.run(exercise())
