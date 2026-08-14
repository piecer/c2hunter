from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from c2hunter_controller.storage import ClickHouseFlowStore


class RecordingClickHouseFlowStore(ClickHouseFlowStore):
    def __init__(self, responses: list[bytes] | None = None, **kwargs: int) -> None:
        super().__init__("http://clickhouse:8123", **kwargs)
        self.requests: list[tuple[str, bytes]] = []
        self.responses = list(responses or [])

    def _request(self, query: str, data: bytes = b"") -> bytes:
        self.requests.append((query, data))
        return self.responses.pop(0) if self.responses else b""


def test_clickhouse_store_rejects_non_http_urls() -> None:
    with pytest.raises(ValueError, match="must use HTTP or HTTPS"):
        ClickHouseFlowStore("file:///tmp/clickhouse")


def test_initial_schema_uses_time_partition_and_clickhouse_24_8_ttl() -> None:
    store = RecordingClickHouseFlowStore(flow_retention_days=45)

    store._initialize()

    queries = "\n".join(query for query, _ in store.requests)
    assert "PARTITION BY toYYYYMM(timestamp)" in queries
    assert "ORDER BY (sensor_id,timestamp,batch_id,record_index)" in queries
    assert "TTL toDateTime(timestamp) + INTERVAL 45 DAY DELETE" in queries
    assert "TTL toDateTime(ingested_at) + INTERVAL 45 DAY DELETE" in queries


def test_ingest_deduplication_lookup_does_not_use_final() -> None:
    store = RecordingClickHouseFlowStore(responses=[b""])
    store._initialized = True
    timestamp = datetime(2026, 7, 27, tzinfo=UTC)

    accepted, count = store.ingest_batch(
        "sensor-1",
        "batch-1",
        [
            {
                "sensor_id": "sensor-1",
                "timestamp": timestamp,
                "source_ip": "10.0.0.1",
                "destination_ip": "203.0.113.10",
            }
        ],
    )

    assert accepted is True
    assert count == 1
    lookup = store.requests[0][0]
    assert " FINAL " not in lookup
    assert "ORDER BY ingested_at DESC LIMIT 1" in lookup


def test_snapshot_avoids_final_and_global_sort_and_sets_limits() -> None:
    record = {
        "sensor_id": "sensor-1",
        "timestamp": "2026-07-27T00:00:01+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.10",
    }
    response = (json.dumps({"data": json.dumps(record, separators=(",", ":"))}) + "\n").encode()
    store = RecordingClickHouseFlowStore(
        responses=[response],
        snapshot_max_threads=2,
        snapshot_max_memory_bytes=536_870_912,
    )
    store._initialized = True
    start = datetime(2026, 7, 27, tzinfo=UTC)

    snapshot = store.snapshot(["sensor-1"], start, start + timedelta(minutes=1))

    assert snapshot.records == (record,)
    query = store.requests[0][0]
    assert "FROM flow_records PREWHERE" in query
    assert " FINAL " not in query
    assert "ORDER BY timestamp" not in query
    assert "max_threads=2" in query
    assert "max_memory_usage=536870912" in query


def test_snapshot_with_no_sensors_returns_without_query() -> None:
    store = RecordingClickHouseFlowStore()
    store._initialized = True
    start = datetime(2026, 7, 27, tzinfo=UTC)

    snapshot = store.snapshot([], start, start + timedelta(minutes=1))

    assert snapshot.records == ()
    assert store.requests == []
