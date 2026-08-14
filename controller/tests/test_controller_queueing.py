import json
from typing import Any, cast

import pytest
import redis

from c2hunter_controller.queueing import MemoryControllerQueue, RedisControllerQueue


class FakePipeline:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    def lrem(self, *args: Any) -> None:
        self.calls.append(("lrem", args))

    def zrem(self, *args: Any) -> None:
        self.calls.append(("zrem", args))

    def execute(self) -> None:
        self.calls.append(("execute", ()))


class FakeRedis:
    def __init__(self) -> None:
        self.ping_result = True
        self.raise_on_ping = False
        self.blocking_result: str | None = None
        self.nonblocking_result: str | None = None
        self.expired: list[str] = []
        self.calls: list[tuple[str, tuple[Any, ...]]] = []
        self.pipeline_value = FakePipeline()

    def ping(self) -> bool:
        if self.raise_on_ping:
            raise RuntimeError("redis unavailable")
        return self.ping_result

    def lpush(self, *args: Any) -> None:
        self.calls.append(("lpush", args))

    def brpoplpush(self, *args: Any, **kwargs: Any) -> str | None:
        self.calls.append(("brpoplpush", args + (kwargs["timeout"],)))
        return self.blocking_result

    def rpoplpush(self, *args: Any) -> str | None:
        self.calls.append(("rpoplpush", args))
        return self.nonblocking_result

    def zadd(self, *args: Any) -> None:
        self.calls.append(("zadd", args))

    def pipeline(self, *, transaction: bool) -> FakePipeline:
        assert transaction is True
        return self.pipeline_value

    def zrangebyscore(self, *args: Any) -> list[str]:
        self.calls.append(("zrangebyscore", args))
        return self.expired

    def eval(self, *args: Any) -> None:
        self.calls.append(("eval", args))


def redis_queue(client: FakeRedis) -> RedisControllerQueue:
    queue = RedisControllerQueue.__new__(RedisControllerQueue)
    queue.client = cast(Any, client)
    queue.jobs_key = "jobs"
    queue.results_key = "results"
    queue.processing_key = "results:processing"
    queue.leases_key = "results:leases"
    queue.visibility_timeout = 300
    return queue


def test_redis_queue_initializes_client_and_namespaced_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeRedis()
    monkeypatch.setattr(redis.Redis, "from_url", lambda *_args, **_kwargs: client)

    queue = RedisControllerQueue(
        "redis://queue.example/0",
        jobs_key="custom-jobs",
        results_key="custom-results",
        visibility_timeout=45,
    )

    assert queue.client is client
    assert queue.jobs_key == "custom-jobs"
    assert queue.processing_key == "custom-results:processing"
    assert queue.leases_key == "custom-results:leases"
    assert queue.visibility_timeout == 45


def test_memory_controller_queue_copies_jobs_and_claims_results() -> None:
    queue = MemoryControllerQueue()
    job = {"job_id": "job-1", "nested": {"value": 1}}

    queue.enqueue(job)
    job["nested"]["value"] = 2
    queue.results.append({"job_id": "job-1"})

    assert queue.ready()
    assert queue.jobs[0]["nested"]["value"] == 1
    assert queue.claim_result(timeout=5) == {"job_id": "job-1"}
    assert queue.claim_result() is None
    assert queue.ack_result("receipt") is None
    assert queue.recover() == 0


def test_redis_queue_ready_enqueue_and_ack_paths() -> None:
    client = FakeRedis()
    queue = redis_queue(client)

    assert queue.ready()
    queue.enqueue({"job_id": "job-1"})
    queue.ack_result("receipt-1")

    pushed = next(args for name, args in client.calls if name == "lpush")
    envelope = json.loads(pushed[1])
    assert envelope["job_id"] == "job-1"
    assert envelope["message_id"]
    assert client.pipeline_value.calls == [
        ("lrem", ("results:processing", 1, "receipt-1")),
        ("zrem", ("results:leases", "receipt-1")),
        ("execute", ()),
    ]

    client.raise_on_ping = True
    assert queue.ready() is False


def test_redis_queue_claims_blocking_and_nonblocking_results() -> None:
    client = FakeRedis()
    queue = redis_queue(client)
    client.blocking_result = json.dumps({"job_id": "blocking"})

    blocking = queue.claim_result(timeout=2)

    assert blocking is not None
    assert blocking["job_id"] == "blocking"
    assert blocking["receipt"] == client.blocking_result

    client.blocking_result = None
    client.nonblocking_result = json.dumps({"job_id": "nonblocking"})
    nonblocking = queue.claim_result()
    assert nonblocking is not None
    assert nonblocking["job_id"] == "nonblocking"

    client.nonblocking_result = None
    assert queue.claim_result() is None


def test_redis_queue_rejects_non_object_results() -> None:
    client = FakeRedis()
    queue = redis_queue(client)
    client.nonblocking_result = "[]"

    with pytest.raises(ValueError, match="JSON object"):
        queue.claim_result()


def test_redis_queue_recovers_expired_leases() -> None:
    client = FakeRedis()
    queue = redis_queue(client)
    client.expired = ["receipt-1", "receipt-2"]

    assert queue.recover() == 2

    eval_calls = [args for name, args in client.calls if name == "eval"]
    assert len(eval_calls) == 2
    assert eval_calls[0][-1] == "receipt-1"
    assert eval_calls[1][-1] == "receipt-2"
