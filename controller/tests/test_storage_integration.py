from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.queueing import RedisControllerQueue
from c2hunter_controller.storage import ClickHouseFlowStore

pytestmark = pytest.mark.skipif(
    os.getenv("C2HUNTER_RUN_STORAGE_INTEGRATION") != "1",
    reason="set C2HUNTER_RUN_STORAGE_INTEGRATION=1 with dependency URLs",
)

sys.path.insert(0, str(Path(__file__).parents[2] / "sensor" / "worker" / "src"))
from c2hunter_worker.queue import RedisQueue  # noqa: E402


def test_postgres_minio_clickhouse_and_redis_durable_vertical_path() -> None:
    suffix = uuid.uuid4().hex
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", f"c2hunter-{suffix}"),
    )
    blob.put(f"probe/{suffix}", b"pcap")
    repository = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    assert repository.ready()
    repository.upsert_sensor({"sensor_id": suffix, "name": "integration"})
    assert repository.get_sensor(suffix) == {"sensor_id": suffix, "name": "integration"}

    flow_store = ClickHouseFlowStore(
        os.environ["C2HUNTER_CLICKHOUSE_URL"],
        database=os.getenv("C2HUNTER_CLICKHOUSE_DATABASE", "c2hunter"),
        username=os.getenv("C2HUNTER_CLICKHOUSE_USER", "default"),
        password=os.getenv("C2HUNTER_CLICKHOUSE_PASSWORD", ""),
    )
    record = {
        "sensor_id": suffix,
        "timestamp": "2026-07-20T00:00:00+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.1",
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "packet_count": 1,
        "total_bytes": 60,
    }
    assert flow_store.ingest_batch(suffix, "batch-1", [record]) == (True, 1)
    assert flow_store.ingest_batch(suffix, "batch-1", [record]) == (False, 1)
    from datetime import datetime

    snapshot = flow_store.snapshot(
        [suffix],
        datetime.fromisoformat("2026-07-20T00:00:00+00:00"),
        datetime.fromisoformat("2026-07-20T00:01:00+00:00"),
    )
    assert snapshot.records == (record,)

    jobs_key = f"c2hunter:test:{suffix}:jobs"
    results_key = f"c2hunter:test:{suffix}:results"
    controller = RedisControllerQueue(
        os.environ["C2HUNTER_REDIS_URL"], jobs_key=jobs_key, results_key=results_key
    )
    worker = RedisQueue(
        os.environ["C2HUNTER_REDIS_URL"], jobs_key=jobs_key, results_key=results_key
    )
    assert controller.ready()
    controller.enqueue({"id": suffix, "payload": {"flow_records": list(snapshot.records)}})
    claimed = worker.receive(timeout=1)
    assert claimed is not None
    worker.complete(
        claimed["receipt"],
        {"job_id": suffix, "status": "COMPLETED", "result": {"candidates": []}},
    )
    result = controller.claim_result(timeout=1)
    assert result is not None and result["job_id"] == suffix
    controller.ack_result(result["receipt"])
    assert controller.client.llen(controller.processing_key) == 0
    assert worker.client.llen(worker.processing_key) == 0
    worker.close()
    controller.client.close()
