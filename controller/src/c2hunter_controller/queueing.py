from __future__ import annotations

import json
import time
import uuid
from copy import deepcopy
from typing import Any, Protocol, cast


class ControllerQueue(Protocol):
    def ready(self) -> bool: ...
    def enqueue(self, job: dict[str, Any]) -> None: ...
    def claim_result(self, timeout: int = 0) -> dict[str, Any] | None: ...
    def ack_result(self, receipt: str) -> None: ...
    def recover(self) -> int: ...


class MemoryControllerQueue:
    """Explicit test/compatibility queue; never selected for operational URLs."""

    def __init__(self) -> None:
        self.jobs: list[dict[str, Any]] = []
        self.results: list[dict[str, Any]] = []

    def ready(self) -> bool:
        return True

    def enqueue(self, job: dict[str, Any]) -> None:
        self.jobs.append(deepcopy(job))

    def claim_result(self, timeout: int = 0) -> dict[str, Any] | None:
        del timeout
        return self.results.pop(0) if self.results else None

    def ack_result(self, receipt: str) -> None:
        del receipt

    def recover(self) -> int:
        return 0


class RedisControllerQueue:
    def __init__(
        self,
        redis_url: str,
        *,
        jobs_key: str = "c2hunter:analysis:jobs",
        results_key: str = "c2hunter:analysis:results",
        visibility_timeout: int = 300,
    ) -> None:
        import redis

        self.client = redis.Redis.from_url(redis_url, decode_responses=True)
        self.jobs_key = jobs_key
        self.results_key = results_key
        self.processing_key = f"{results_key}:processing"
        self.leases_key = f"{results_key}:leases"
        self.visibility_timeout = visibility_timeout

    def ready(self) -> bool:
        try:
            return bool(self.client.ping())
        except Exception:
            return False

    def enqueue(self, job: dict[str, Any]) -> None:
        envelope = {**job, "message_id": str(uuid.uuid4())}
        self.client.lpush(self.jobs_key, json.dumps(envelope, separators=(",", ":"), default=str))

    def claim_result(self, timeout: int = 0) -> dict[str, Any] | None:
        self.recover()
        if timeout:
            raw = cast(
                str | None,
                self.client.brpoplpush(self.results_key, self.processing_key, timeout=timeout),
            )
        else:
            raw = cast(str | None, self.client.rpoplpush(self.results_key, self.processing_key))
        if raw is None:
            return None
        self.client.zadd(self.leases_key, {raw: time.time() + self.visibility_timeout})
        decoded: Any = json.loads(raw)
        if not isinstance(decoded, dict):
            raise ValueError("analysis result must be a JSON object")
        decoded["receipt"] = raw
        return decoded

    def ack_result(self, receipt: str) -> None:
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
                self.results_key,
                self.leases_key,
                receipt,
            )
        return len(expired)
