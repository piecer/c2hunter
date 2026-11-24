"""Independent public start/stop probes; real SQLite, runtime, bridge and Worker."""

import asyncio
import importlib
import threading
import time
from pathlib import Path

import pytest

from c2hunter_controller.local_analysis_runtime import LocalAnalysisRuntime
from c2hunter_controller.queueing import MemoryControllerQueue
from c2hunter_controller.repositories import SQLiteRepository
from c2hunter_controller.schemas import FlowRecord


async def eventually(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.005)


def fixture_job():
    record = FlowRecord.model_validate(
        {
            "sensor_id": "rereview",
            "timestamp": "2026-01-01T00:00:01Z",
            "source_ip": "10.0.0.1",
            "destination_ip": "203.0.113.1",
            "source_port": 50000,
            "destination_port": 443,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "packet_count": 1,
            "total_bytes": 60,
        }
    ).model_dump(mode="json")
    return {
        "id": "rereview-job",
        "status": "ANALYZING",
        "dataset_id": "rereview-dataset",
        "flow_records": [record],
        "flow_count": 1,
        "packet_count": 1,
        "payload_signatures": [],
        "analysis": {"module": "c2"},
    }


@pytest.mark.parametrize("phase", ["summary", "recovery", "census", "publish"])
@pytest.mark.parametrize("stop_during_read", [False, True])
def test_stop_phase(tmp_path, monkeypatch, phase, stop_during_read):
    """Controls and stopped schedules share identical fixture and real call paths."""
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "sensor/worker/src"))
    analysis = importlib.import_module("c2hunter_worker.analysis")

    async def exercise():
        rows = []
        row_lock = threading.Lock()
        owner_threads = set()
        loop_thread = threading.get_ident()
        entered, release, retired, receiving = (threading.Event() for _ in range(4))
        barrier_ok = []
        borrowed_closed = False
        stopping = None
        starter = None
        repo = SQLiteRepository(tmp_path / "private.sqlite")
        job = fixture_job()
        repo.save_job(job)
        queue = MemoryControllerQueue()
        if phase != "recovery":
            queue.enqueue({"id": job["id"], "payload": job})
        counts = {
            "compute": 0,
            "bridge_put": 0,
            "recovery_enqueue": 0,
            "publish_started": 0,
            "publish_finished": 0,
            "due": 0,
        }
        observations = {}

        def event(name, **extra):
            with row_lock:
                rows.append(
                    {
                        "event": name,
                        "monotonic_ns": time.monotonic_ns(),
                        "thread": threading.get_ident(),
                        **extra,
                    }
                )

        def barrier(sql=None):
            owner_threads.add(threading.current_thread())
            event("barrier_enter", sql=sql, repository_closed=borrowed_closed)
            entered.set()
            ok = release.wait(10)
            barrier_ok.append(ok)
            event(
                "barrier_return",
                released=ok,
                stopped=runtime.stopped.is_set(),
                repository_closed=borrowed_closed,
            )
            retired.set()

        targets = {
            "summary": "SELECT data FROM objects WHERE kind='job' AND id='rereview-job'",
            "recovery": "SELECT data FROM job_flow_records WHERE job_id='rereview-job'",
            "census": "SELECT data FROM objects WHERE kind='job' ORDER BY rowid",
        }

        def trace(sql):
            if phase in targets and sql == targets[phase] and not entered.is_set():
                barrier(sql)

        repo.connection.set_trace_callback(trace)

        def due():
            owner_threads.add(threading.current_thread())
            counts["due"] += 1
            return False

        def enqueue(saved):
            owner_threads.add(threading.current_thread())
            counts["recovery_enqueue"] += 1
            event("recovery_enqueue", stopped=runtime.stopped.is_set(), id=saved["id"])
            queue.enqueue({"id": saved["id"], "payload": saved})

        def publish(result):
            owner_threads.add(threading.current_thread())
            counts["publish_started"] += 1
            event("publish_start", stopped=runtime.stopped.is_set(), status=result["status"])
            if phase == "publish" and not entered.is_set():
                barrier()
            # Accepted publication still legitimately uses the borrowed repository.
            assert repo.get_job_summary(job["id"]) is not None
            counts["publish_finished"] += 1
            event(
                "publish_return",
                stopped=runtime.stopped.is_set(),
                repository_closed=borrowed_closed,
            )

        def compute(payload):
            counts["compute"] += 1
            event("compute", stopped=runtime.stopped.is_set(), id=payload["id"])
            return {"candidates": []}

        monkeypatch.setattr(analysis, "execute_analysis", compute)
        runtime = LocalAnalysisRuntime(
            queue,
            repo,
            due,
            publish,
            tmp_path / "health.json",
            enqueue,
            ownership_path=tmp_path / "private.sqlite",
        )
        original_put = runtime.bridge.jobs.put_nowait
        original_receive = runtime.bridge.receive

        def put(item):
            counts["bridge_put"] += 1
            event("bridge_put", stopped=runtime.stopped.is_set(), id=item["id"])
            return original_put(item)

        def receive(timeout):
            event("receive_enter", stopped=runtime.stopped.is_set())
            receiving.set()
            return original_receive(timeout)

        monkeypatch.setattr(runtime.bridge.jobs, "put_nowait", put)
        monkeypatch.setattr(runtime.bridge, "receive", receive)
        if phase == "publish":
            runtime.bridge.complete("prior", {"job_id": "prior", "status": "COMPLETED"})
            runtime.inflight = True
        try:
            starter = asyncio.create_task(runtime.start())
            await eventually(entered.is_set)
            event("barrier_observed")
            if phase != "census":
                await starter
                await eventually(receiving.is_set)
            if stop_during_read:
                stopping = asyncio.create_task(runtime.stop())
                await eventually(runtime.stopped.is_set)
                event("stop_intent_observed")
                observations["stop_pending_while_borrowed"] = not stopping.done()
                observations["ownership_held_while_borrowed"] = (
                    runtime.ownership_file is not None and not runtime.ownership_file.closed
                )
                observations["callback_not_retired_early"] = not retired.is_set()
            release.set()
            event("release")
            await starter
            if stopping is None:
                await eventually(lambda: counts["compute"] == 1)
                await eventually(lambda: not runtime.inflight and runtime.pending is None)
                stopping = asyncio.create_task(runtime.stop())
            await stopping
            event("stop_return", retired=retired.is_set())
            observations.update(
                {
                    "barrier_fired_once": len(barrier_ok) == 1,
                    "barrier_released": barrier_ok == [True],
                    "callback_retired_before_stop_return": retired.is_set(),
                    "owner_threads_joined": all(not thread.is_alive() for thread in owner_threads),
                    "detector_joined": not runtime.thread.is_alive(),
                    "ownership_released": runtime.ownership_file is None,
                    "owner_is_single_non_loop_thread": len(owner_threads) == 1
                    and all(thread.ident != loop_thread for thread in owner_threads),
                    "bridge_bounds_unchanged": (
                        runtime.bridge.jobs.maxsize,
                        runtime.bridge.results.maxsize,
                    )
                    == (1, 2),
                    "last_error": runtime.last_error,
                    "counts": dict(counts),
                    "controller_queue_count": len(queue.jobs),
                    "bridge_queue_count": runtime.bridge.jobs.qsize(),
                    "inflight": runtime.inflight,
                    "worker_started": runtime.thread.ident is not None,
                }
            )
        finally:
            release.set()
            try:
                if starter is not None:
                    await asyncio.gather(starter, return_exceptions=True)
                await runtime.stop()
                if stopping is not None:
                    await asyncio.gather(stopping, return_exceptions=True)
            finally:
                # All own helpers must retire even if a behavioral assertion fails.
                await asyncio.to_thread(runtime.coordinator.shutdown, wait=True)
                if runtime.thread.ident is not None:
                    await asyncio.to_thread(runtime.thread.join, 3)
                cleanup_ok = not runtime.thread.is_alive() and all(
                    not thread.is_alive() for thread in owner_threads
                )
                event(
                    "before_repository_close",
                    cleanup_ok=cleanup_ok,
                    ownership_released=runtime.ownership_file is None,
                )
                repo.connection.set_trace_callback(None)
                repo.close()
                borrowed_closed = True
                event("repository_closed")
                observations["cleanup_ok"] = cleanup_ok
        # These remain genuine contract assertions (not xfail/expected failures).
        assert observations["cleanup_ok"]
        assert observations["barrier_fired_once"] and observations["barrier_released"]
        assert observations["callback_retired_before_stop_return"]
        assert observations["owner_threads_joined"] and observations["ownership_released"]
        assert observations["owner_is_single_non_loop_thread"]
        assert observations["bridge_bounds_unchanged"]
        assert observations["last_error"] is None
        if stop_during_read:
            assert observations["stop_pending_while_borrowed"]
            assert observations["ownership_held_while_borrowed"]
            assert observations["callback_not_retired_early"]
            if phase == "publish":
                assert counts["publish_started"] == counts["publish_finished"] == 1
            if phase == "census":
                assert not observations["worker_started"]
            assert counts["recovery_enqueue"] == 0, (
                "new recovery enqueue callback admitted after stop intent"
            )
            assert counts["bridge_put"] == 0, (
                "new worker bridge admission after stop during repository read"
            )
            assert counts["compute"] == 0, (
                "new detector computation after stop during repository read"
            )
        else:
            assert counts["bridge_put"] == counts["compute"] == 1
            assert counts["recovery_enqueue"] == (1 if phase == "recovery" else 0)
            assert counts["publish_started"] == counts["publish_finished"]
            assert counts["publish_finished"] == (3 if phase == "publish" else 2)

    asyncio.run(exercise())
