from __future__ import annotations

import json
import time
from collections.abc import Callable
from copy import deepcopy
from typing import Any, Protocol, cast


class AIAnalysisTaskQueue(Protocol):
    def ready(self) -> bool: ...

    def enqueue(self, run_id: str) -> None: ...

    def depth(self) -> int: ...


class InlineAIAnalysisTaskQueue:
    """Deterministic test queue that executes the same worker task boundary inline."""

    def __init__(self, execute: Callable[[str], dict[str, Any]]) -> None:
        self.execute = execute

    def ready(self) -> bool:
        return True

    def enqueue(self, run_id: str) -> None:
        self.execute(run_id)

    def depth(self) -> int:
        return 0


class MemoryAIAnalysisTaskQueue:
    def __init__(self) -> None:
        self.run_ids: list[str] = []

    def ready(self) -> bool:
        return True

    def enqueue(self, run_id: str) -> None:
        if run_id not in self.run_ids:
            self.run_ids.append(run_id)

    def depth(self) -> int:
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
