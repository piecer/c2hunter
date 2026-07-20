from __future__ import annotations

import json
import threading
import urllib.parse
import urllib.request
import uuid
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Protocol, cast


@dataclass(frozen=True)
class FlowSnapshot:
    dataset_id: str
    records: tuple[dict[str, Any], ...]


class FlowStore(Protocol):
    def ready(self) -> bool: ...

    def ingest_batch(
        self, sensor_id: str, batch_id: str, records: list[dict[str, Any]]
    ) -> tuple[bool, int]: ...

    def snapshot(self, sensor_ids: list[str], start: datetime, end: datetime) -> FlowSnapshot: ...


class MemoryFlowStore:
    """Explicit test/compatibility adapter."""

    def __init__(self) -> None:
        self._records: list[dict[str, Any]] = []
        self._batches: dict[tuple[str, str], int] = {}
        self._lock = threading.RLock()

    @property
    def record_count(self) -> int:
        return len(self._records)

    def ready(self) -> bool:
        return True

    def ingest_batch(
        self, sensor_id: str, batch_id: str, records: list[dict[str, Any]]
    ) -> tuple[bool, int]:
        key = (sensor_id, batch_id)
        with self._lock:
            if key in self._batches:
                return False, self._batches[key]
            copied = deepcopy(records)
            self._records.extend(copied)
            self._batches[key] = len(copied)
            return True, len(copied)

    def snapshot(self, sensor_ids: list[str], start: datetime, end: datetime) -> FlowSnapshot:
        selected = []
        for record in self._records:
            timestamp = record["timestamp"]
            parsed = datetime.fromisoformat(timestamp) if isinstance(timestamp, str) else timestamp
            if record["sensor_id"] in sensor_ids and start <= parsed <= end:
                selected.append(deepcopy(record))
        return FlowSnapshot(str(uuid.uuid4()), tuple(selected))


class ClickHouseFlowStore:
    """HTTP ClickHouse adapter with a durable batch ledger and logical record deduplication."""

    def __init__(
        self,
        url: str,
        *,
        database: str = "c2hunter",
        username: str = "default",
        password: str = "",
        timeout: float = 5.0,
    ) -> None:
        self.url = url.rstrip("/")
        self.database = database
        self.username = username
        self.password = password
        self.timeout = timeout
        self._initialized = False

    def _request(self, query: str, data: bytes = b"") -> bytes:
        parameters = urllib.parse.urlencode({"database": self.database, "query": query})
        request = urllib.request.Request(f"{self.url}/?{parameters}", data=data, method="POST")
        if self.username:
            request.add_header("X-ClickHouse-User", self.username)
            request.add_header("X-ClickHouse-Key", self.password)
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return cast(bytes, response.read())

    def _initialize(self) -> None:
        self._request(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        self._request(
            "CREATE TABLE IF NOT EXISTS flow_batch_ledger ("
            "sensor_id String, batch_id String, record_count UInt32, "
            "ingested_at DateTime64(6, 'UTC') "
            ") ENGINE=ReplacingMergeTree(ingested_at) ORDER BY (sensor_id,batch_id)"
        )
        self._request(
            "CREATE TABLE IF NOT EXISTS flow_records ("
            "sensor_id String, batch_id String, record_index UInt32, "
            "timestamp DateTime64(6, 'UTC'), "
            "data String, ingested_at DateTime64(6, 'UTC')"
            ") ENGINE=ReplacingMergeTree(ingested_at) "
            "ORDER BY (sensor_id,batch_id,record_index)"
        )
        self._initialized = True

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            self._initialize()

    def ready(self) -> bool:
        try:
            self._ensure_initialized()
            return self._request("SELECT 1").strip() == b"1"
        except OSError:
            return False

    def ingest_batch(
        self, sensor_id: str, batch_id: str, records: list[dict[str, Any]]
    ) -> tuple[bool, int]:
        self._ensure_initialized()
        escaped_sensor = _clickhouse_literal(sensor_id)
        escaped_batch = _clickhouse_literal(batch_id)
        existing = self._request(
            "SELECT record_count FROM flow_batch_ledger FINAL "
            f"WHERE sensor_id={escaped_sensor} AND batch_id={escaped_batch} LIMIT 1"
        ).strip()
        if existing:
            return False, int(existing)
        now = _clickhouse_datetime(datetime.now(UTC))
        rows = []
        for index, record in enumerate(records):
            normalized = deepcopy(record)
            timestamp = normalized["timestamp"]
            if isinstance(timestamp, datetime):
                normalized["timestamp"] = timestamp.isoformat()
            rows.append(
                json.dumps(
                    {
                        "sensor_id": sensor_id,
                        "batch_id": batch_id,
                        "record_index": index,
                        "timestamp": _clickhouse_datetime(timestamp),
                        "data": json.dumps(normalized, separators=(",", ":")),
                        "ingested_at": now,
                    },
                    separators=(",", ":"),
                )
            )
        if rows:
            self._request(
                "INSERT INTO flow_records FORMAT JSONEachRow", ("\n".join(rows) + "\n").encode()
            )
        ledger = json.dumps(
            {
                "sensor_id": sensor_id,
                "batch_id": batch_id,
                "record_count": len(records),
                "ingested_at": now,
            },
            separators=(",", ":"),
        ).encode()
        self._request("INSERT INTO flow_batch_ledger FORMAT JSONEachRow", ledger)
        return True, len(records)

    def snapshot(self, sensor_ids: list[str], start: datetime, end: datetime) -> FlowSnapshot:
        self._ensure_initialized()
        sensors = ",".join(_clickhouse_literal(item) for item in sensor_ids)
        query = (
            "SELECT data FROM flow_records FINAL WHERE sensor_id IN ("
            f"{sensors}) AND timestamp >= "
            f"parseDateTime64BestEffort({_clickhouse_literal(start.isoformat())}) "
            f"AND timestamp <= parseDateTime64BestEffort({_clickhouse_literal(end.isoformat())}) "
            "ORDER BY timestamp,sensor_id,batch_id,record_index FORMAT JSONEachRow"
        )
        raw = self._request(query).decode()
        records = tuple(json.loads(json.loads(line)["data"]) for line in raw.splitlines() if line)
        return FlowSnapshot(str(uuid.uuid4()), records)


def _clickhouse_literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _clickhouse_datetime(value: str | datetime) -> str:
    parsed = datetime.fromisoformat(value) if isinstance(value, str) else value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")
