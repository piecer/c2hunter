"""Real app lifespan retirement and restart regression contracts."""

import asyncio
import importlib
import inspect
import json
import threading

import pytest
import test_account_auth_retention as support
from test_account_auth_retention import event, rows
from test_account_auth_retention_runtime import application

store = support.store


def record(tmp_path, name, **values):
    (tmp_path / (name + ".json")).write_text(json.dumps(values, indent=2))


@pytest.mark.parametrize("separate_loops", [False, True])
def test_real_app_repeated_lifespan_runs_retention_again(store, separate_loops, tmp_path):
    app = application(store)
    observed = []

    async def cycle(number):
        old = event(store, number)
        async with app.router.lifespan_context(app):
            owner = app.state.auth_retention
            observed.append(
                {
                    "cycle": number,
                    "old_event_survives": old in {r["id"] for r in rows(store)},
                    "task_done": owner.task.done(),
                    "stopped": owner.stopped.is_set(),
                    "prune_count": len([r for r in rows(store) if r["action"] == "audit.prune"]),
                }
            )
        assert owner.task.done()

    if separate_loops:
        asyncio.run(cycle(1))
        asyncio.run(cycle(2))
    else:

        async def run():
            await cycle(1)
            await cycle(2)

        asyncio.run(run())
    record(
        tmp_path,
        "restart-" + str(separate_loops),
        observations=observed,
        cleanup="both lifespan exits completed",
    )
    assert not observed[0]["old_event_survives"]
    assert not observed[1]["old_event_survives"], (
        "second normal app lifespan silently omits retention"
    )
    assert observed[1]["prune_count"] == 2


@pytest.mark.parametrize("cancel_count", [0, 2])
def test_real_lifespan_shutdown_retires_dependent_executor_without_retry(
    store, monkeypatch, cancel_count, tmp_path
):
    module = importlib.import_module("c2hunter_controller.auth_retention")
    app = application(store)
    handler = next(h for h in app.router.on_shutdown if h.__name__ == "stop_result_consumer")
    executor = inspect.getclosurevars(handler).nonlocals["enrichment_executor"]
    executor.submit(lambda: None).result(timeout=5)
    entered, release, retired = (threading.Event() for _ in range(3))
    original = store.prune_audit
    observed = {}

    def blocked(days):
        entered.set()
        try:
            assert release.wait(5)
            return original(days)
        finally:
            retired.set()

    async def run():
        tick = asyncio.Event()
        intervals = []

        async def interval(awaitable, timeout):
            intervals.append(timeout)
            if len(intervals) == 1:
                awaitable.close()
                await tick.wait()
                raise TimeoutError
            await awaitable

        monkeypatch.setattr(module, "wait_for", interval)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        monkeypatch.setattr(store, "prune_audit", blocked)
        tick.set()
        exiting = None
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            exiting = asyncio.create_task(lifespan.__aexit__(None, None, None))
            for _ in range(5):
                await asyncio.sleep(0)
            for _ in range(cancel_count):
                exiting.cancel()
                for _ in range(5):
                    await asyncio.sleep(0)
            assert not exiting.done() and not retired.is_set()
            assert not executor._shutdown
            release.set()
            result = await asyncio.gather(exiting, return_exceptions=True)
            observed.update(
                native_retired=retired.is_set(),
                retention_done=app.state.auth_retention.task.done(),
                shutdown_cancelled=exiting.cancelled(),
                executor_shutdown=executor._shutdown,
                executor_threads_alive=[t.is_alive() for t in executor._threads],
                result_type=type(result[0]).__name__,
                intervals=intervals,
            )
        finally:
            release.set()
            if exiting is not None:
                await asyncio.gather(exiting, return_exceptions=True)
            # Test-owned cleanup, explicitly NOT part of the single-exit observation.
            if not executor._shutdown:
                await app.router._shutdown()
        observed["cleanup_executor_shutdown"] = executor._shutdown
        observed["cleanup_executor_threads_alive"] = [t.is_alive() for t in executor._threads]
        assert retired.is_set() and app.state.auth_retention.task.done()
        assert executor._shutdown and not any(t.is_alive() for t in executor._threads)

    asyncio.run(run())
    record(tmp_path, "shutdown-" + str(cancel_count), **observed)
    assert observed["native_retired"] and observed["retention_done"]
    assert observed["executor_shutdown"], (
        "cancelled retention.stop aborts remaining real app teardown"
    )
    assert not any(observed["executor_threads_alive"])


@pytest.mark.parametrize("fails", [False, True])
def test_lifespan_exit_owns_later_async_cleanup_under_repeated_cancellation(store, fails):
    app = application(store)
    failure = RuntimeError("cleanup failure")

    async def run():
        entered, release = asyncio.Event(), asyncio.Event()
        completed = []

        async def dependent_close():
            entered.set()
            await release.wait()
            completed.append(True)
            if fails:
                raise failure

        app.router.add_event_handler("shutdown", dependent_close)
        lifespan = app.router.lifespan_context(app)
        await lifespan.__aenter__()
        exiting = asyncio.create_task(lifespan.__aexit__(None, None, None))
        try:
            async with asyncio.timeout(5):
                await entered.wait()
            for _ in range(2):
                exiting.cancel("original cancellation")
                for _ in range(5):
                    await asyncio.sleep(0)
            observed_pending = not exiting.done()
        finally:
            release.set()
            await asyncio.gather(exiting, return_exceptions=True)
        assert observed_pending, "lifespan exit lost ownership of dependent cleanup"
        assert completed == [True]
        assert exiting.cancelled()
        with pytest.raises(asyncio.CancelledError, match="original cancellation"):
            exiting.result()

    asyncio.run(run())


def test_lifespan_uncancelled_cleanup_failure_preserves_exception_identity(store):
    app = application(store)
    failure = RuntimeError("cleanup failure")

    async def dependent_close():
        raise failure

    app.router.add_event_handler("shutdown", dependent_close)

    async def run():
        with pytest.raises(RuntimeError) as caught:
            async with app.router.lifespan_context(app):
                pass
        assert caught.value is failure
        assert app.state.auth_retention.task.done()

    asyncio.run(run())


def test_real_lifespan_callback_failure_does_not_skip_dependent_teardown(
    store, monkeypatch, tmp_path, caplog
):
    original = store.prune_audit
    calls = []

    def prune(days):
        calls.append(days)
        if len(calls) == 2:
            raise RuntimeError("private callback failure")
        return original(days)

    monkeypatch.setattr(store, "prune_audit", prune)
    test_real_lifespan_shutdown_retires_dependent_executor_without_retry(
        store, monkeypatch, 2, tmp_path
    )
    assert calls == [180, 180]
    assert "Audit retention maintenance failed" in caplog.text
    assert "private callback failure" not in caplog.text


def test_restarted_lifespan_resumes_hourly_passes(store, monkeypatch):
    module = importlib.import_module("c2hunter_controller.auth_retention")
    app = application(store)

    async def run():
        async with app.router.lifespan_context(app):
            previous = app.state.auth_retention
        tick, waiting = asyncio.Queue(), asyncio.Queue()
        intervals = []

        async def interval(awaitable, timeout):
            intervals.append(timeout)
            stop = asyncio.create_task(awaitable)
            advance = asyncio.create_task(tick.get())
            waiting.put_nowait(None)
            try:
                done, _ = await asyncio.wait({stop, advance}, return_when=asyncio.FIRST_COMPLETED)
                if stop not in done:
                    raise TimeoutError
            finally:
                for task in (stop, advance):
                    task.cancel()
                await asyncio.gather(stop, advance, return_exceptions=True)

        monkeypatch.setattr(module, "wait_for", interval)
        async with asyncio.timeout(5):
            async with app.router.lifespan_context(app):
                current = app.state.auth_retention
                assert current is not previous and previous.task.done()
                await waiting.get()
                old = event(store, 3)
                tick.put_nowait(None)
                await waiting.get()
                assert old not in {row["id"] for row in rows(store)}
                assert intervals == [3600, 3600]
                assert len([r for r in rows(store) if r["action"] == "audit.prune"]) == 3
            assert current.task.done()

    asyncio.run(run())


def test_starting_lifespan_cannot_replace_owner_still_draining(store, monkeypatch):
    app = application(store)
    original = store.prune_audit
    entered, release, retired = (threading.Event() for _ in range(3))
    calls = []

    def prune(days):
        calls.append(days)
        if len(calls) == 1:
            entered.set()
            try:
                assert release.wait(5)
            finally:
                retired.set()
        else:
            assert retired.is_set()
        return original(days)

    monkeypatch.setattr(store, "prune_audit", prune)

    async def run():
        first, second = (app.router.lifespan_context(app) for _ in range(2))
        starting = asyncio.create_task(first.__aenter__())
        restarting = stopping = None
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            previous = app.state.auth_retention
            stopping = asyncio.create_task(previous.stop())
            for _ in range(5):
                await asyncio.sleep(0)
            assert previous.stopped.is_set() and not previous.task.done()
            restarting = asyncio.create_task(second.__aenter__())
            for _ in range(5):
                await asyncio.sleep(0)
            assert not restarting.done()
            assert app.state.auth_retention is previous
            assert calls == [180]
        finally:
            release.set()
            await asyncio.gather(
                starting, *[task for task in (stopping, restarting) if task is not None]
            )
            observed = app.state.auth_retention
            await second.__aexit__(None, None, None)
            await first.__aexit__(None, None, None)
        assert observed is not previous and previous.task.done()
        assert observed.task.done() and retired.is_set()
        assert calls == [180, 180]

    asyncio.run(run())


def test_lifespan_body_failure_preserves_exception_and_real_teardown(store):
    app = application(store)
    failure = RuntimeError("lifespan body failure")
    handler = next(h for h in app.router.on_shutdown if h.__name__ == "stop_result_consumer")
    executor = inspect.getclosurevars(handler).nonlocals["enrichment_executor"]
    executor.submit(lambda: None).result(timeout=5)

    async def run():
        with pytest.raises(RuntimeError) as caught:
            async with app.router.lifespan_context(app):
                raise failure
        assert caught.value is failure
        assert app.state.auth_retention.task.done()
        assert executor._shutdown and not any(t.is_alive() for t in executor._threads)

    asyncio.run(run())
