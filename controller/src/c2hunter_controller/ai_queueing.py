from __future__ import annotations

import json
import time
from collections.abc import Callable
from copy import deepcopy
from threading import RLock
from typing import Any, Protocol, cast


class AIAnalysisTaskQueue(Protocol):
    def ready(self) -> bool: ...

    def enqueue(self, run_id: str) -> None: ...

    def ensure_enqueued(self, run_id: str) -> None:
        """Ensure one waiting/owned dispatch, atomically with queue claims.

        Historical admission and replay both use this seam. An uncertain reply
        may be retried without adding work already waiting or being processed.
        Completion racing a stale caller may produce a terminal no-op delivery.
        """
        ...

    def depth(self) -> int: ...


class InlineAIAnalysisTaskQueue:
    """Deterministic test queue that executes the same worker task boundary inline."""

    def __init__(self, execute: Callable[[str], dict[str, Any]]) -> None:
        self.execute = execute
        self._lock = RLock()
        self._active: set[str] = set()

    def ready(self) -> bool:
        return True

    def enqueue(self, run_id: str) -> None:
        self.execute(run_id)

    def ensure_enqueued(self, run_id: str) -> None:
        with self._lock:
            if run_id in self._active:
                return
            self._active.add(run_id)
        try:
            self.execute(run_id)
        finally:
            with self._lock:
                self._active.remove(run_id)

    def depth(self) -> int:
        return 0


class MemoryAIAnalysisTaskQueue:
    def __init__(self) -> None:
        self.run_ids: list[str] = []
        self.lock = RLock()
        self._inflight: set[str] = set()

    def ready(self) -> bool:
        return True

    def enqueue(self, run_id: str) -> None:
        with self.lock:
            if run_id not in self.run_ids:
                self.run_ids.append(run_id)

    def ensure_enqueued(self, run_id: str) -> None:
        with self.lock:
            if run_id not in self._inflight:
                self.enqueue(run_id)

    def claim_local(self) -> str | None:
        with self.lock:
            if not self.run_ids:
                return None
            run_id = self.run_ids.pop(0)
            self._inflight.add(run_id)
            return run_id

    def release_local(self, run_id: str) -> None:
        with self.lock:
            self._inflight.discard(run_id)

    def depth(self) -> int:
        with self.lock:
            return len(self.run_ids)


class RedisAIAnalysisTaskQueue:
    def __init__(self, redis_url: str, *, queue_key: str = "c2hunter:ai:jobs") -> None:
        import redis

        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.queue_key = queue_key

    def ready(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception:
            return False

    def enqueue(self, run_id: str) -> None:
        envelope = json.dumps({"ai_run_id": run_id}, separators=(",", ":"))
        self.client.lpush(self.queue_key, envelope)

    def ensure_enqueued(self, run_id: str) -> None:
        # The worker moves this exact envelope between waiting and processing
        # atomically. Check both in the same operation as insertion; a separate
        # existence test followed by LPUSH would race claims and HTTP retries.
        # No new marker/TTL is needed, including for previously queued runs.
        envelope = json.dumps({"ai_run_id": run_id}, separators=(",", ":"))
        script = """
        for _, key in ipairs({KEYS[1], KEYS[2]}) do
          for _, raw in ipairs(redis.call('LRANGE', key, 0, -1)) do
            if raw == ARGV[1] then return 0 end
          end
        end
        return redis.call('LPUSH', KEYS[1], ARGV[1])
        """
        self.client.eval(script, 2, self.queue_key, f"{self.queue_key}:processing", envelope)

    def depth(self) -> int:
        return cast(int, self.client.llen(self.queue_key))


class RedisAIAnalysisWorkerQueue:
    def __init__(
        self,
        redis_url: str,
        *,
        queue_key: str = "c2hunter:ai:jobs",
        visibility_timeout: int = 300,
    ) -> None:
        import redis

        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.queue_key = queue_key
        self.processing_key = f"{queue_key}:processing"
        self.leases_key = f"{queue_key}:leases"
        self.visibility_timeout = visibility_timeout

    def claim(self, timeout: int = 1) -> dict[str, str] | None:
        self.recover()
        raw = cast(
            str | None,
            self.client.brpoplpush(self.queue_key, self.processing_key, timeout=timeout),
        )
        if raw is None:
            return None
        self.client.zadd(self.leases_key, {raw: time.time() + self.visibility_timeout})
        payload: Any = json.loads(raw)
        if not isinstance(payload, dict) or not isinstance(payload.get("ai_run_id"), str):
            self.ack(raw)
            raise ValueError("AI queue message must contain ai_run_id")
        return {"ai_run_id": payload["ai_run_id"], "receipt": raw}

    def ack(self, receipt: str) -> None:
        pipeline = self.client.pipeline(transaction=True)
        pipeline.lrem(self.processing_key, 1, receipt)
        pipeline.zrem(self.leases_key, receipt)
        pipeline.execute()  # type: ignore[no-untyped-call]

    def recover(self) -> int:
        expired = cast(list[str], self.client.zrangebyscore(self.leases_key, "-inf", time.time()))
        script = """
        if redis.call('LREM', KEYS[1], 1, ARGV[1]) > 0 then
          redis.call('LPUSH', KEYS[2], ARGV[1])
        end
        redis.call('ZREM', KEYS[3], ARGV[1])
        return 1
        """
        for receipt in expired:
            self.client.eval(
                script,
                3,
                self.processing_key,
                self.queue_key,
                self.leases_key,
                receipt,
            )
        return len(expired)

    def depth(self) -> tuple[int, int]:
        return (
            cast(int, self.client.llen(self.queue_key)),
            cast(int, self.client.llen(self.processing_key)),
        )


class MemoryAIAnalysisWorkerQueue:
    def __init__(self, messages: list[dict[str, str]] | None = None) -> None:
        self.messages = deepcopy(messages or [])
        self.acked: list[str] = []

    def claim(self, timeout: int = 1) -> dict[str, str] | None:
        del timeout
        return self.messages.pop(0) if self.messages else None

    def ack(self, receipt: str) -> None:
        self.acked.append(receipt)

    def recover(self) -> int:
        return 0

    def depth(self) -> tuple[int, int]:
        return len(self.messages), 0
