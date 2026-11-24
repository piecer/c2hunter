"""One app-owned, off-loop audit maintenance task; never initializes storage."""

from __future__ import annotations

import asyncio
import logging
import sys
import threading
from asyncio import wait_for
from collections.abc import AsyncIterator, Awaitable, Mapping
from contextlib import asynccontextmanager
from typing import Any, TypeVar, cast

from fastapi import FastAPI
from starlette.types import Lifespan

from .auth_store import AuthStore

_T = TypeVar("_T")

logger = logging.getLogger(__name__)


class AuditRetention:
    def __init__(self, store: AuthStore, retention_days: int = 180) -> None:
        self.store = store
        self.retention_days = retention_days
        self.task: asyncio.Task[None] | None = None
        self.stopped = asyncio.Event()
        self.first_pass = asyncio.Event()
        self.last_deleted: int | None = None
        self.last_error: str | None = None
        self._admission = threading.Lock()

    async def start(self) -> None:
        with self._admission:
            if self.task is None and not self.stopped.is_set():
                self.task = asyncio.create_task(self._run(), name="auth-audit-retention")
        if self.task is None:
            return
        if self.task.done():
            self.task.result()
            return
        if self.task.get_loop() is not asyncio.get_running_loop():
            # Multiple in-process clients can drive one app from separate loops.
            remote = asyncio.run_coroutine_threadsafe(self.start(), self.task.get_loop())
            await self._wait_owned(asyncio.wrap_future(remote))
            return
        try:
            await self.first_pass.wait()
        except asyncio.CancelledError:
            await self.stop()
            raise

    def _request_stop(self) -> None:
        task = self.task
        if (
            task is not None
            and not task.done()
            and task.get_loop() is not asyncio.get_running_loop()
        ):
            task.get_loop().call_soon_threadsafe(self.stopped.set)
        else:
            self.stopped.set()

    async def _wait_owned(self, future: asyncio.Future[_T]) -> _T:
        """Cancellation requests stop; it cannot retire accepted native SQL."""
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            self._request_stop()
            while not future.done():
                try:
                    await asyncio.shield(future)
                except asyncio.CancelledError:
                    pass
                except Exception:
                    break
            if not future.cancelled() and future.exception() is not None:
                self._failed()  # Retrieve/report secondary failure without its text.
            raise

    def _failed(self) -> None:
        self.last_deleted = None
        self.last_error = "AUDIT_RETENTION_FAILED"
        logger.error("Audit retention maintenance failed")

    async def stop(self) -> None:
        with self._admission:
            self._request_stop()
            task = self.task
        if task is None:
            return
        if task.done():
            task.result()
        elif task.get_loop() is asyncio.get_running_loop():
            await self._wait_owned(task)
        else:
            remote = asyncio.run_coroutine_threadsafe(self.stop(), task.get_loop())
            await self._wait_owned(asyncio.wrap_future(remote))

    async def _run(self) -> None:
        try:
            while not self.stopped.is_set():
                try:
                    callback = asyncio.create_task(
                        asyncio.to_thread(self.store.prune_audit, self.retention_days)
                    )
                    deleted = await self._wait_owned(callback)
                    self.last_deleted = deleted
                    self.last_error = None
                except Exception:
                    self._failed()
                self.first_pass.set()
                try:
                    await wait_for(self.stopped.wait(), timeout=3600)
                except TimeoutError:
                    pass
        finally:
            self.first_pass.set()
            self.stopped.set()


async def _drain_lifespan_exit(exit_call: Awaitable[bool | None]) -> bool | None:
    """Own the entire existing teardown, not just retention's first handler."""
    future = asyncio.ensure_future(exit_call)
    try:
        return await asyncio.shield(future)
    except asyncio.CancelledError:
        while not future.done():
            try:
                await asyncio.shield(future)
            except asyncio.CancelledError:
                pass
            except Exception:
                break
        if not future.cancelled() and future.exception() is not None:
            # Cancellation remains primary; retrieve the secondary cleanup error.
            logger.error("Application teardown failed during audit retention shutdown")
        raise


def bind_audit_retention(app: FastAPI, store: AuthStore, retention_days: int) -> None:
    """Compose retention ownership with the app's existing lifespan and hooks."""
    owner = AuditRetention(store, retention_days)
    app.state.auth_retention = owner
    admission = threading.Lock()

    async def start() -> None:
        nonlocal owner
        while True:
            with admission:
                previous = owner
                if not previous.stopped.is_set():
                    break
                if previous.task is None or previous.task.done():
                    owner = AuditRetention(store, retention_days)
                    app.state.auth_retention = owner
                    previous = owner
                    break
            # A new lifespan may arrive while the previous native pass drains.
            # Never replace its owner or admit a second pass before retirement.
            await previous.stop()
        await previous.start()

    async def stop() -> None:
        with admission:
            current = owner
        await current.stop()

    # Keep legacy direct startup/shutdown callers and cross-loop clients working.
    # Individual AuditRetention objects remain single-use, including stop-before-start.
    app.router.add_event_handler("startup", start)
    app.router.on_shutdown.insert(0, stop)
    original_lifespan = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[Mapping[str, Any] | None]:
        context = original_lifespan(application)
        state = await context.__aenter__()
        try:
            yield state
        except BaseException:
            if not await _drain_lifespan_exit(context.__aexit__(*sys.exc_info())):
                raise
        else:
            await _drain_lifespan_exit(context.__aexit__(None, None, None))

    # Wrap the configured context; do not replace framework dispatch or its handlers.
    # Starlette types stateful/stateless factories as a union; preserve either state.
    app.router.lifespan_context = cast(Lifespan[FastAPI], lifespan)
