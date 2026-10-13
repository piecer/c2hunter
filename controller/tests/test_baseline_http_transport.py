"""Corrected two-slot transport tests, distinct from historical RED probes."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import pytest


def transport_type() -> Any:
    from c2hunter_controller import historical_baseline_api as api

    value = getattr(api, "BaselineTransport", None)
    assert value is not None, "bounded transport owner must exist"
    return value


async def reached(event: threading.Event) -> None:
    async with asyncio.timeout(5):
        while not event.is_set():
            await asyncio.sleep(0.001)


def test_two_slots_no_queue_and_event_loop_responsive() -> None:
    kind = transport_type()

    async def run() -> None:
        transport = kind()
        first, second, release = threading.Event(), threading.Event(), threading.Event()
        calls = []

        def worker(signal: threading.Event) -> int:
            calls.append(True)
            signal.set()
            assert release.wait(5)
            return 7

        a = asyncio.create_task(transport.call(worker, first))
        b = asyncio.create_task(transport.call(worker, second))
        try:
            await reached(first)
            await reached(second)
            from c2hunter_controller.api_errors import ApiError

            with pytest.raises(ApiError) as error:
                await transport.call(worker, threading.Event())
            assert error.value.code == "BASELINE_BUSY"
            assert error.value.status == 503 and len(calls) == 2
            tick = False

            async def unrelated() -> None:
                nonlocal tick
                await asyncio.sleep(0)
                tick = True

            await asyncio.wait_for(unrelated(), 1)
            assert tick
        finally:
            release.set()
            assert await a == await b == 7
        assert await transport.call(lambda: 9) == 9
        await transport.shutdown()

    asyncio.run(run())


def test_cancelled_running_calls_retain_slots_until_shutdown() -> None:
    kind = transport_type()

    async def run() -> None:
        from c2hunter_controller.api_errors import ApiError

        transport = kind()
        first, second, release = threading.Event(), threading.Event(), threading.Event()
        stopped = []

        def worker(signal: threading.Event) -> None:
            signal.set()
            try:
                assert release.wait(5)
            finally:
                stopped.append(True)

        tasks = [asyncio.create_task(transport.call(worker, s)) for s in (first, second)]
        shutdown = None
        try:
            await reached(first)
            await reached(second)
            for task in tasks:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            with pytest.raises(ApiError) as error:
                await transport.call(lambda: "must not dispatch")
            assert error.value.code == "BASELINE_BUSY" and stopped == []
            shutdown = asyncio.create_task(transport.shutdown())
            await asyncio.sleep(0.02)
            assert not shutdown.done()
        finally:
            release.set()
            for task in tasks:
                if not task.done():
                    await task
            await transport.shutdown()
            if shutdown is not None:
                await shutdown
        assert len(stopped) == 2
        with pytest.raises(ApiError):
            await transport.call(lambda: "closed")

    asyncio.run(run())
