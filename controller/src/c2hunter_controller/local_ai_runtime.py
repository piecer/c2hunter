"""Opt-in single-host AI worker. Not a durable or distributed queue.

Inference runs on one compute thread; repository calls are marshalled back to
an asyncio coordinator. No database connection is used by the compute thread.
"""

from __future__ import annotations

import asyncio
import threading
from concurrent.futures import Future
from copy import deepcopy
from queue import Empty, Queue
from typing import Any, cast

from .ai_analysis import TERMINAL_STATES, AIAnalysisService, AIRepository
from .ai_gateway import AIAnalysisCancelled
from .ai_queueing import MemoryAIAnalysisTaskQueue


class LocalAITaskQueue(MemoryAIAnalysisTaskQueue):
    def __init__(self) -> None:
        super().__init__()
        self.lock = threading.Lock()

    def enqueue(self, run_id: str) -> None:
        with self.lock:
            if run_id in self.run_ids:
                return
            if len(self.run_ids) >= 32:
                raise OverflowError("local AI queue capacity exceeded")
            self.run_ids.append(run_id)


class _OwnerRepository:
    def __init__(self, runtime: LocalAIRuntime) -> None:
        self.runtime = runtime

    def __getattr__(self, name: str) -> Any:
        if name not in AIRepository.__dict__ or name.startswith("_"):
            raise AttributeError(name)

        def call(*args: Any) -> Any:
            result: Future[Any] = Future()
            self.runtime.calls.put_nowait((name, deepcopy(args), result))
            while not result.done():
                if self.runtime.stopped.wait(0.01):
                    raise AIAnalysisCancelled("local AI worker stopped")
            return result.result()

        return call


class LocalAIRuntime:
    def __init__(self, queue: MemoryAIAnalysisTaskQueue, service: AIAnalysisService) -> None:
        self.queue = queue
        self.service = service
        self.calls: Queue[tuple[str, tuple[Any, ...], Future[Any]]] = Queue(maxsize=1)
        self.finished: Queue[str] = Queue(maxsize=1)
        self.stopped = threading.Event()
        self.task: asyncio.Task[None] | None = None
        self.thread: threading.Thread | None = None
        self.inflight: str | None = None
        self.worker_service = AIAnalysisService(
            cast(AIRepository, _OwnerRepository(self)), service.gateway
        )

    async def start(self) -> None:
        # A process restart loses the in-memory queue. Make interruption explicit,
        # rather than leave persisted runs waiting forever or silently replay them.
        for job in self.service.repository.list_jobs():
            for run in self.service.repository.list_ai_runs(job["id"]):
                if run["status"] not in TERMINAL_STATES and run["id"] not in self.queue.run_ids:
                    self.service.cancel(run["id"], "local worker interrupted; submit a new run")
        self.task = asyncio.create_task(self.run(), name="local-ai-coordinator")

    def compute(self, run_id: str) -> None:
        try:
            self.worker_service.execute(run_id)
        except AIAnalysisCancelled:
            pass
        finally:
            self.finished.put_nowait(run_id)

    def service_call(self) -> None:
        try:
            name, args, future = self.calls.get_nowait()
        except Empty:
            return
        try:
            # Cancellation wins over a late completion or model failure.
            if name == "save_ai_run":
                latest = self.service.repository.get_ai_run(args[0]["id"])
                if latest is not None and latest["status"] in TERMINAL_STATES:
                    future.set_result(deepcopy(latest))
                    return
            result = getattr(self.service.repository, name)(*args)
        except Exception as exc:
            future.set_exception(exc)
        else:
            future.set_result(deepcopy(result))

    async def run(self) -> None:
        while not self.stopped.is_set():
            self.service_call()
            try:
                self.finished.get_nowait()
                self.inflight = None
            except Empty:
                pass
            if self.inflight is None and self.queue.run_ids:
                run_id = self.queue.run_ids.pop(0)
                run = self.service.repository.get_ai_run(run_id)
                if run is not None and run["status"] not in TERMINAL_STATES:
                    self.inflight = run_id
                    self.thread = threading.Thread(
                        target=self.compute, args=(run_id,), name="local-ai-worker", daemon=True
                    )
                    self.thread.start()
            await asyncio.sleep(0.01)

    async def stop(self) -> None:
        if self.inflight is not None:
            self.service.cancel(self.inflight, "local worker shutdown")
        for run_id in self.queue.run_ids:
            self.service.cancel(run_id, "local worker shutdown")
        self.queue.run_ids.clear()
        self.stopped.set()
        if self.task is not None:
            await self.task
        if self.thread is not None:
            await asyncio.to_thread(self.thread.join, 2)
