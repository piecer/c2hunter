from __future__ import annotations

import json
import time
from typing import Any, cast


class RedisQueue:
    """Crash-safe Redis list queue with processing leases and atomic result+ACK."""

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
        self.processing_key = f"{jobs_key}:processing"
        self.leases_key = f"{jobs_key}:leases"
        self.results_key = results_key
        self.visibility_timeout = visibility_timeout

    def receive(self, timeout: int) -> dict[str, Any] | None:
        self.recover_expired()
        raw = cast(
            str | None,
            self.client.brpoplpush(self.jobs_key, self.processing_key, timeout=timeout),
        )
        if raw is None:
            return None
        self.client.zadd(self.leases_key, {raw: time.time() + self.visibility_timeout})
        decoded: Any = json.loads(raw)
        if not isinstance(decoded, dict):
            self._requeue(raw)
            raise ValueError("analysis job must be a JSON object")
        decoded["receipt"] = raw
        return decoded

    def complete(self, receipt: str, result: dict[str, Any]) -> None:
        encoded = json.dumps(result, separators=(",", ":"), default=str)
        script = """
        redis.call('RPUSH', KEYS[1], ARGV[1])
        redis.call('LREM', KEYS[2], 1, ARGV[2])
        redis.call('ZREM', KEYS[3], ARGV[2])
        return 1
        """
        self.client.eval(
            script,
            3,
            self.results_key,
            self.processing_key,
            self.leases_key,
            encoded,
            receipt,
        )

    def recover_expired(self) -> int:
        expired = cast(
            list[str], self.client.zrangebyscore(self.leases_key, "-inf", time.time())
        )
        for receipt in expired:
            self._requeue(receipt)
        return len(expired)

    def _requeue(self, receipt: str) -> None:
        script = """
        if redis.call('LREM', KEYS[1], 1, ARGV[1]) > 0 then
          redis.call('LPUSH', KEYS[2], ARGV[1])
        end
        redis.call('ZREM', KEYS[3], ARGV[1])
        return 1
        """
        self.client.eval(
            script, 3, self.processing_key, self.jobs_key, self.leases_key, receipt
        )

    def close(self) -> None:
        self.client.close()
