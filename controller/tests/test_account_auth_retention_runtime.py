"""Exercise retention through the real app lifespan and owned callback races."""

import asyncio
import importlib
import threading

import pytest
import test_account_auth_retention as support
from test_account_auth_retention import event, rows

from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository

store = support.store


def application(auth, **settings):
    module = importlib.import_module("c2hunter_controller.app")
    config = Settings(
        environment="test",
        account_auth_enabled=True,
        api_auth_required=True,
        auth_public_origin="https://example.test",
        ai_analysis_enabled=False,
        **settings,
    )
    return module.create_app(config, MemoryRepository(), auth_store=auth)


def test_real_app_lifespan_prunes_on_startup(store):
    old = event(store, 1)
    app = application(store)
    assert old in {row["id"] for row in rows(store)}  # Construction is not startup.

    async def run():
        async with app.router.lifespan_context(app):
            assert old not in {row["id"] for row in rows(store)}
            owner = app.state.auth_retention
            assert owner.store is store
            assert owner.last_deleted == 1 and owner.last_error is None
        assert owner.task.done()

    asyncio.run(run())


def test_hourly_singleflight_failure_recovery_without_catchup(store, monkeypatch, caplog):
    module = importlib.import_module("c2hunter_controller.auth_retention")
    calls = []
    original = store.prune_audit

    def prune(days):
        calls.append((days, threading.get_ident()))
        if len(calls) == 2:
            raise RuntimeError("private-dsn-sentinel")
        return original(days)

    monkeypatch.setattr(store, "prune_audit", prune)

    async def run():
        tick = asyncio.Queue()
        waiting = asyncio.Queue()
        timeouts = []

        async def interval(awaitable, timeout):
            timeouts.append(timeout)
            stop = asyncio.create_task(awaitable)
            advance = asyncio.create_task(tick.get())
            await waiting.put(None)
            try:
                done, _ = await asyncio.wait({stop, advance}, return_when=asyncio.FIRST_COMPLETED)
                if stop not in done:
                    raise TimeoutError
            finally:
                for task in (stop, advance):
                    task.cancel()
                await asyncio.gather(stop, advance, return_exceptions=True)

        monkeypatch.setattr(module, "wait_for", interval, raising=False)
        owner = module.AuditRetention(store)
        try:
            async with asyncio.timeout(5):
                await asyncio.gather(owner.start(), owner.start())
                await waiting.get()
                assert len(calls) == 1
                tick.put_nowait(None)
                await waiting.get()
                assert owner.last_error == "AUDIT_RETENTION_FAILED"
                assert owner.last_deleted is None
                tick.put_nowait(None)
                await waiting.get()
                assert len(calls) == 3
                assert owner.last_error is None and owner.last_deleted == 0
                assert timeouts == [3600, 3600, 3600]
                assert all(identity != threading.get_ident() for _, identity in calls)
                assert all(days == 180 for days, _ in calls)
        finally:
            await owner.stop()
        assert owner.task.done()
        assert len(calls) == 3

    asyncio.run(run())
    assert "Audit retention maintenance failed" in caplog.text
    assert "private-dsn-sentinel" not in caplog.text
    assert all(record.exc_info is None for record in caplog.records)


@pytest.mark.parametrize("cancel_target", ["start", "stop", "task", "none"])
@pytest.mark.parametrize("fails", [False, True])
def test_blocked_native_pass_drains_before_owner_retires(store, monkeypatch, cancel_target, fails):
    from c2hunter_controller.auth_retention import AuditRetention

    entered = threading.Event()
    release = threading.Event()
    retired = threading.Event()
    calls = []
    original = store.prune_audit

    def blocked(days):
        calls.append(threading.get_ident())
        entered.set()
        try:
            assert release.wait(5)
            if fails:
                raise RuntimeError("private callback failure")
            return original(days)
        finally:
            retired.set()

    monkeypatch.setattr(store, "prune_audit", blocked)

    async def run():
        owner = AuditRetention(store)
        start = asyncio.create_task(owner.start())
        stop = None
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            # The event loop remains responsive while native SQL is accepted.
            heartbeat = asyncio.Event()
            asyncio.get_running_loop().call_soon(heartbeat.set)
            await heartbeat.wait()
            if cancel_target == "start":
                target = start
            elif cancel_target == "task":
                target = owner.task
            else:
                stop = asyncio.create_task(owner.stop())
                target = stop
            await asyncio.sleep(0)
            if cancel_target != "none":
                target.cancel()
                await asyncio.sleep(0)
                target.cancel()
            for _ in range(5):
                await asyncio.sleep(0)
            assert not target.done(), "accepted SQL callback must remain owned"
            assert not retired.is_set()
            assert len(calls) == 1
        finally:
            release.set()
            await asyncio.gather(start, *([stop] if stop else []), return_exceptions=True)
            await asyncio.gather(owner.stop(), return_exceptions=True)
        assert retired.is_set()
        assert owner.task.done()
        assert len(calls) == 1
        if fails:
            assert owner.last_error == "AUDIT_RETENTION_FAILED"
            assert owner.last_deleted is None
        if cancel_target != "none":
            assert target.cancelled()

    asyncio.run(run())


def test_real_factory_uses_configured_retention(store):
    import time

    old = event(store, time.time() - 2 * 86400)
    module = importlib.import_module("c2hunter_controller.app")
    config = Settings(
        environment="test",
        account_auth_enabled=True,
        api_auth_required=True,
        auth_database_path=str(store.sqlite_path),
        auth_audit_retention_days=1,
        auth_public_origin="https://example.test",
        ai_analysis_enabled=False,
    )
    app = module.create_app(config, MemoryRepository())

    async def run():
        async with app.router.lifespan_context(app):
            assert old not in {row["id"] for row in rows(store)}
            assert app.state.auth_retention.retention_days == 1
        assert app.state.auth_retention.task.done()

    asyncio.run(run())


def test_stopped_owner_cannot_restart_or_wait_forever(store):
    from c2hunter_controller.auth_retention import AuditRetention

    async def run():
        owner = AuditRetention(store)
        await owner.stop()
        async with asyncio.timeout(1):
            await owner.start()
            await owner.stop()
        assert owner.task is None
        assert not [row for row in rows(store) if row["action"] == "audit.prune"]

    asyncio.run(run())


@pytest.mark.parametrize("inject", [True, False])
def test_disabled_mode_never_prunes_even_injected_store(store, monkeypatch, inject):
    module = importlib.import_module("c2hunter_controller.app")

    def forbidden(*args):
        pytest.fail("disabled account mode started maintenance")

    monkeypatch.setattr(store, "prune_audit", forbidden)
    app = module.create_app(
        Settings(environment="test", account_auth_enabled=False),
        MemoryRepository(),
        auth_store=store if inject else None,
    )

    async def run():
        async with app.router.lifespan_context(app):
            assert app.state.auth_retention is None

    asyncio.run(run())


@pytest.mark.parametrize("fault", ["missing", "schema"])
def test_unready_startup_is_safe_observable_and_never_initializes(tmp_path, fault, caplog):
    from c2hunter_controller.auth_store import AuthStore

    store = AuthStore(sqlite_path=tmp_path / "private" / "auth.sqlite")
    if fault == "schema":
        store.initialize()
        with store.db.transaction() as sql:
            sql.execute("DROP TABLE auth_sessions")
    app = application(store)

    async def run():
        async with app.router.lifespan_context(app):
            owner = app.state.auth_retention
            assert owner.last_error == "AUDIT_RETENTION_FAILED"
            assert owner.last_deleted is None
            assert not store.ready()
        assert owner.task.done()

    asyncio.run(run())
    assert "Audit retention maintenance failed" in caplog.text
    if fault == "missing":
        assert not store.sqlite_path.exists()
        assert not store.sqlite_path.parent.exists()


@pytest.mark.parametrize("cancel_shutdown", [False, True])
def test_real_app_shutdown_waits_for_periodic_sql_before_dependent_close(
    store, monkeypatch, cancel_shutdown
):
    module = importlib.import_module("c2hunter_controller.auth_retention")
    entered = threading.Event()
    release = threading.Event()
    retired = threading.Event()
    original = store.prune_audit
    closed = []

    def blocked(days):
        entered.set()
        try:
            assert release.wait(5)
            return original(days)
        finally:
            retired.set()

    app = application(store)

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

        def dependent_close():
            assert retired.is_set()
            closed.append(True)

        monkeypatch.setattr(module, "wait_for", interval)
        app.router.add_event_handler("shutdown", dependent_close)
        await app.router._startup()
        monkeypatch.setattr(store, "prune_audit", blocked)
        tick.set()
        shutdown = None
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            shutdown = asyncio.create_task(app.router._shutdown())
            for _ in range(5):
                await asyncio.sleep(0)
            if cancel_shutdown:
                shutdown.cancel()
                await asyncio.sleep(0)
                shutdown.cancel()
                for _ in range(5):
                    await asyncio.sleep(0)
            assert not shutdown.done()
            assert closed == []
        finally:
            release.set()
            if shutdown is not None:
                await asyncio.gather(shutdown, return_exceptions=True)
            if not closed:
                await app.router._shutdown()
        assert retired.is_set() and closed == [True]
        assert app.state.auth_retention.task.done()
        assert intervals == [3600, 3600]
        if cancel_shutdown:
            assert shutdown.cancelled()

    asyncio.run(run())


def test_existing_startup_failure_does_not_orphan_maintenance(store):
    app = application(store)

    def failed_startup():
        raise RuntimeError("existing startup failed")

    index = next(
        i
        for i, handler in enumerate(app.router.on_startup)
        if handler.__name__ == "start_result_consumer"
    )
    app.router.on_startup[index] = failed_startup

    async def run():
        try:
            with pytest.raises(RuntimeError, match="existing startup failed"):
                async with app.router.lifespan_context(app):
                    pytest.fail("startup must fail")
            assert app.state.auth_retention.task is None
        finally:
            await app.router._shutdown()

    asyncio.run(run())


def test_two_real_client_loops_share_one_app_maintenance_owner(store):
    from fastapi.testclient import TestClient

    app = application(store)
    with TestClient(app) as first:
        task = app.state.auth_retention.task
        with TestClient(app) as second:
            assert app.state.auth_retention.task is task
            assert first.get("/health").status_code == second.get("/health").status_code
            assert len([r for r in rows(store) if r["action"] == "audit.prune"]) == 1
        assert task.done()
    assert task.done()


@pytest.mark.parametrize("operation", ["start", "stop"])
def test_crossloop_cancellation_still_drains_native_callback(store, monkeypatch, operation):
    from concurrent.futures import ThreadPoolExecutor

    from c2hunter_controller.auth_retention import AuditRetention

    entered, release, retired, finish = (threading.Event() for _ in range(4))
    original = store.prune_audit
    owner = AuditRetention(store)

    def blocked(days):
        entered.set()
        try:
            assert release.wait(5)
            return original(days)
        finally:
            retired.set()

    monkeypatch.setattr(store, "prune_audit", blocked)

    async def owning_loop():
        try:
            await owner.start()
            await owner.task
            assert await asyncio.to_thread(finish.wait, 5)
        finally:
            await owner.stop()

    async def other_loop():
        call = asyncio.create_task(getattr(owner, operation)())
        try:
            for _ in range(5):
                await asyncio.sleep(0)
            call.cancel()
            await asyncio.sleep(0)
            call.cancel()
            for _ in range(5):
                await asyncio.sleep(0)
            assert not call.done() and not retired.is_set()
        finally:
            release.set()
            await asyncio.gather(call, return_exceptions=True)
            await owner.stop()
        assert call.cancelled() and retired.is_set()
        assert owner.task.done()

    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(asyncio.run, owning_loop())
        try:
            assert entered.wait(5)
            asyncio.run(other_loop())
        finally:
            release.set()
            finish.set()
            future.result(timeout=5)
