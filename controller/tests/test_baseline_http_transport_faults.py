"""Transport lifetime failure and shared-pool delayed-start controls."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import anyio
import pytest

from c2hunter_controller import historical_baseline_api as api
from c2hunter_controller.api_errors import ApiError
from tests.test_baseline_http_transport import reached


@pytest.mark.parametrize("fault", ["predispatch", "submission", "start", "worker"])
def test_faults_conserve_capacity_and_exception_identity(fault: str, monkeypatch: Any) -> None:
    async def run() -> None:
        owner = api.BaselineTransport()
        marker = RuntimeError("private storage path must remain internal")

        def fail(*a: Any, **kw: Any) -> Any:
            raise marker

        async def submit_fail(*a: Any, **kw: Any) -> Any:
            raise marker

        with monkeypatch.context() as m:
            if fault == "predispatch":
                m.setattr(asyncio, "create_task", fail)
            elif fault == "submission":
                m.setattr(api, "run_in_threadpool", submit_fail)
            elif fault == "start":
                m.setattr(threading.Thread, "start", fail)
            with pytest.raises(RuntimeError) as error:
                await owner.call(fail if fault == "worker" else lambda: 1)
            assert error.value is marker
        assert await owner.call(lambda: 11) == 11
        assert await owner.call(lambda: 12) == 12
        await owner.shutdown()
        assert not owner._pending

    asyncio.run(run())


def test_shared_pool_waiting_and_cancel_before_start_still_owned() -> None:
    async def run() -> None:
        owner = api.BaselineTransport()
        limiter = anyio.to_thread.current_default_thread_limiter()
        original = limiter.total_tokens
        limiter.total_tokens = 1
        await limiter.acquire()
        calls = []
        tasks = [asyncio.create_task(owner.call(lambda: calls.append(True))) for _ in range(2)]
        try:
            for _ in range(5):
                await asyncio.sleep(0)
            assert calls == []
            for task in tasks:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            with pytest.raises(ApiError) as error:
                await owner.call(lambda: calls.append(False))
            assert error.value.code == "BASELINE_BUSY" and calls == []
            assert len(owner._pending) == 2
        finally:
            limiter.release()
            await owner.shutdown()
            limiter.total_tokens = original
        assert calls == [True, True] and not owner._pending

    asyncio.run(run())


def test_shutdown_cancellation_drains_real_worker_before_propagating() -> None:
    async def run() -> None:
        owner = api.BaselineTransport()
        started, release, stopped = threading.Event(), threading.Event(), threading.Event()

        def work() -> None:
            started.set()
            try:
                assert release.wait(5)
            finally:
                stopped.set()

        request = asyncio.create_task(owner.call(work))
        shutdown = None
        try:
            await reached(started)
            request.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request
            shutdown = asyncio.create_task(owner.shutdown())
            await asyncio.sleep(0)
            shutdown.cancel()
            await asyncio.sleep(0.02)
            assert not shutdown.done(), "shutdown must not relinquish live invocation ownership"
        finally:
            release.set()
            if shutdown is not None:
                try:
                    await shutdown
                except asyncio.CancelledError:
                    pass
            await owner.shutdown()
        assert stopped.is_set() and not owner._pending

    asyncio.run(run())
