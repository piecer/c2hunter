from __future__ import annotations

import json
import secrets
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Literal

from c2hunter_analysis.pcap_index import (
    PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_OFFSET_INDEX_SCHEMA_VERSION,
)


class IndexAdmission(str, Enum):
    QUEUED = "QUEUED"
    COALESCED = "COALESCED"
    DEFERRED = "DEFERRED"


@dataclass(frozen=True)
class LiveIndexTaskSpec:
    source_kind: Literal["LIVE_SEGMENT"]
    source_id: str
    sensor_id: str
    analysis_job_id: str
    object_key: str
    source_size_bytes: int
    source_sha256: str
    capture_format: Literal["PCAP"] = "PCAP"
    schema_version: int = PCAP_OFFSET_INDEX_SCHEMA_VERSION
    parser_contract_version: int = PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION

    @classmethod
    def from_segment(cls, segment: dict[str, Any]) -> LiveIndexTaskSpec:
        filename = str(segment.get("filename", ""))
        if not filename.endswith(".pcap"):
            raise ValueError("LIVE indexing requires a finalized classic PCAP")
        sensor_id = str(segment.get("sensor_id", ""))
        source_id = str(segment.get("id", ""))
        analysis_job_id = str(segment.get("analysis_job_id", ""))
        if not sensor_id or not source_id or not analysis_job_id:
            raise ValueError("LIVE indexing requires canonical ownership")
        return cls(
            source_kind="LIVE_SEGMENT",
            source_id=source_id,
            sensor_id=sensor_id,
            analysis_job_id=analysis_job_id,
            object_key=str(
                segment.get("object_key") or f"sensor-pcaps/{sensor_id}/{source_id}.pcap"
            ),
            source_size_bytes=int(segment["size_bytes"]),
            source_sha256=str(segment["sha256"]),
        )


@dataclass(frozen=True)
class LiveIndexTask:
    spec: LiveIndexTaskSpec
    status: Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"]
    attempt: int
    max_attempts: int
    lease_token: str | None
    lease_expires_at: datetime | None
    next_attempt_at: datetime
    queued_at: datetime
    updated_at: datetime
    error_code: str | None = None


type LiveIndexTaskStatus = Literal["QUEUED", "RUNNING", "COMPLETED", "FAILED"]

_ELIGIBLE_INTENT_STATES = {"PENDING", "DEFERRED"}
_TERMINAL_INTENT_STATES = {"COMPLETED", "FAILED"}


def live_index_task_status(value: object) -> LiveIndexTaskStatus:
    match value:
        case "QUEUED" | "RUNNING" | "COMPLETED" | "FAILED":
            return value
        case _:
            raise ValueError("invalid LIVE index task status")


def eligible_live_segment(job: dict[str, Any] | None, segment: dict[str, Any]) -> bool:
    return bool(
        job
        and job.get("mode") == "LIVE"
        and job.get("capture", {}).get("store_pcap") is True
        and segment.get("analysis_job_id") == job.get("id")
        and str(segment.get("filename", "")).endswith(".pcap")
    )


def encode_task(task: LiveIndexTask) -> str:
    value = asdict(task)
    for field in ("lease_expires_at", "next_attempt_at", "queued_at", "updated_at"):
        item = value[field]
        value[field] = item.isoformat() if item is not None else None
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def decode_task(raw: str) -> LiveIndexTask:
    value = json.loads(raw)
    value["status"] = live_index_task_status(value.get("status"))
    value["spec"] = LiveIndexTaskSpec(**value["spec"])
    for field in ("lease_expires_at", "next_attempt_at", "queued_at", "updated_at"):
        if value[field] is not None:
            value[field] = datetime.fromisoformat(value[field])
    return LiveIndexTask(**value)


def _tasks(repository: Any) -> dict[str, LiveIndexTask]:
    return repository.live_segment_index_tasks


def _segment(repository: Any, source_id: str) -> dict[str, Any] | None:
    return (
        repository._get("sensor_pcap", source_id)
        if hasattr(repository, "connection")
        else deepcopy(repository.sensor_pcaps.get(source_id))
    )


def _mark_intent(repository: Any, source_id: str, state: str) -> None:
    segment = _segment(repository, source_id)
    if segment is None:
        return
    segment.update(
        index_intent_state=state,
        index_intent_schema_version=PCAP_OFFSET_INDEX_SCHEMA_VERSION,
        index_intent_parser_contract_version=PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
    )
    if hasattr(repository, "connection"):
        repository.connection.execute(
            "UPDATE objects SET data=? WHERE kind='sensor_pcap' AND id=?",
            (repository._serialize(segment), source_id),
        )
    else:
        repository.sensor_pcaps[source_id] = segment


def get_task(repository: Any, source_id: str) -> LiveIndexTask | None:
    if hasattr(repository, "connection"):
        row = repository.connection.execute(
            "SELECT data FROM pcap_offset_index_jobs "
            "WHERE source_kind='LIVE_SEGMENT' AND source_id=?",
            (source_id,),
        ).fetchone()
        return decode_task(row[0]) if row else None
    task = _tasks(repository).get(source_id)
    return deepcopy(task)


def _put(repository: Any, task: LiveIndexTask) -> None:
    if hasattr(repository, "connection"):
        repository.connection.execute(
            "INSERT INTO pcap_offset_index_jobs("
            "source_kind,source_id,status,next_attempt_at,queued_at,data) "
            "VALUES('LIVE_SEGMENT',?,?,?,?,?) ON CONFLICT(source_kind,source_id) DO UPDATE SET "
            "status=excluded.status,next_attempt_at=excluded.next_attempt_at,data=excluded.data",
            (
                task.spec.source_id,
                task.status,
                task.next_attempt_at.isoformat(),
                task.queued_at.isoformat(),
                encode_task(task),
            ),
        )
    else:
        _tasks(repository)[task.spec.source_id] = task


def admit(repository: Any, source_id: str, *, capacity: int, max_attempts: int) -> IndexAdmission:
    with repository._lock:
        existing = get_task(repository, source_id)
        if existing is not None:
            return IndexAdmission.COALESCED
        segment = _segment(repository, source_id)
        if not segment or not segment.get("index_requested_at"):
            return IndexAdmission.DEFERRED
        if segment.get("index_intent_state") in _TERMINAL_INTENT_STATES:
            return IndexAdmission.COALESCED
        active = (
            repository.connection.execute(
                "SELECT COUNT(*) FROM pcap_offset_index_jobs WHERE status IN ('QUEUED','RUNNING')"
            ).fetchone()[0]
            if hasattr(repository, "connection")
            else sum(task.status in {"QUEUED", "RUNNING"} for task in _tasks(repository).values())
        )
        if int(active) >= capacity:
            _mark_intent(repository, source_id, "DEFERRED")
            if hasattr(repository, "connection"):
                repository.connection.commit()
            return IndexAdmission.DEFERRED
        now = datetime.now(UTC)
        _put(
            repository,
            LiveIndexTask(
                LiveIndexTaskSpec.from_segment(segment),
                "QUEUED",
                0,
                max_attempts,
                None,
                None,
                now,
                now,
                now,
            ),
        )
        _mark_intent(repository, source_id, "PENDING")
        if hasattr(repository, "connection"):
            repository.connection.commit()
        return IndexAdmission.QUEUED


def claim(repository: Any, *, now: datetime, lease_seconds: int) -> LiveIndexTask | None:
    with repository._lock:
        if hasattr(repository, "connection"):
            rows = repository.connection.execute(
                "SELECT data FROM pcap_offset_index_jobs "
                "WHERE status='QUEUED' AND next_attempt_at<=? "
                "ORDER BY next_attempt_at,queued_at,source_id",
                (now.isoformat(),),
            ).fetchall()
            candidates = [decode_task(row[0]) for row in rows]
        else:
            candidates = [
                task
                for task in _tasks(repository).values()
                if task.status == "QUEUED" and task.next_attempt_at <= now
            ]
        if not candidates:
            return None
        current = min(
            candidates, key=lambda task: (task.next_attempt_at, task.queued_at, task.spec.source_id)
        )
        claimed = replace(
            current,
            status="RUNNING",
            attempt=current.attempt + 1,
            lease_token=secrets.token_hex(16),
            lease_expires_at=now + timedelta(seconds=lease_seconds),
            updated_at=now,
        )
        _put(repository, claimed)
        if hasattr(repository, "connection"):
            repository.connection.commit()
        return claimed


def heartbeat(
    repository: Any,
    source_id: str,
    *,
    attempt: int,
    lease_token: str,
    now: datetime,
    lease_seconds: int,
) -> bool:
    with repository._lock:
        task = get_task(repository, source_id)
        if (
            task is None
            or task.status != "RUNNING"
            or task.attempt != attempt
            or task.lease_token != lease_token
            or task.lease_expires_at is None
            or task.lease_expires_at <= now
        ):
            return False
        _put(
            repository,
            replace(task, lease_expires_at=now + timedelta(seconds=lease_seconds), updated_at=now),
        )
        if hasattr(repository, "connection"):
            repository.connection.commit()
        return True


def complete(
    repository: Any,
    source_id: str,
    *,
    attempt: int,
    lease_token: str,
    now: datetime | None = None,
) -> bool:
    with repository._lock:
        current = now or datetime.now(UTC)
        task = get_task(repository, source_id)
        if (
            task is None
            or task.status != "RUNNING"
            or task.attempt != attempt
            or task.lease_token != lease_token
            or task.lease_expires_at is None
            or task.lease_expires_at <= current
        ):
            return False
        _put(
            repository,
            replace(
                task,
                status="COMPLETED",
                lease_token=None,
                lease_expires_at=None,
                updated_at=current,
            ),
        )
        _mark_intent(repository, source_id, "COMPLETED")
        if hasattr(repository, "connection"):
            repository.connection.commit()
        return True


def fail(
    repository: Any,
    source_id: str,
    *,
    attempt: int,
    lease_token: str,
    transient: bool,
    error_code: str,
    now: datetime,
    retry_base_seconds: int,
) -> bool:
    with repository._lock:
        task = get_task(repository, source_id)
        if (
            task is None
            or task.status != "RUNNING"
            or task.attempt != attempt
            or task.lease_token != lease_token
            or task.lease_expires_at is None
            or task.lease_expires_at <= now
        ):
            return False
        retry = transient and task.attempt < task.max_attempts
        updated = replace(
            task,
            status="QUEUED" if retry else "FAILED",
            lease_token=None,
            lease_expires_at=None,
            next_attempt_at=now
            + timedelta(seconds=retry_base_seconds * 2 ** max(task.attempt - 1, 0))
            if retry
            else task.next_attempt_at,
            updated_at=now,
            error_code=error_code[:64],
        )
        _put(repository, updated)
        _mark_intent(repository, source_id, "PENDING" if retry else "FAILED")
        if hasattr(repository, "connection"):
            repository.connection.commit()
        return True


def recover(repository: Any, *, now: datetime) -> int:
    with repository._lock:
        if hasattr(repository, "connection"):
            rows = repository.connection.execute(
                "SELECT data FROM pcap_offset_index_jobs WHERE status='RUNNING'"
            ).fetchall()
            candidates = [decode_task(row[0]) for row in rows]
        else:
            candidates = list(_tasks(repository).values())
        recovered = 0
        for task in candidates:
            if (
                task.status != "RUNNING"
                or task.lease_expires_at is None
                or task.lease_expires_at > now
            ):
                continue
            status: LiveIndexTaskStatus = "QUEUED" if task.attempt < task.max_attempts else "FAILED"
            _put(
                repository,
                replace(
                    task,
                    status=status,
                    lease_token=None,
                    lease_expires_at=None,
                    next_attempt_at=now,
                    updated_at=now,
                    error_code=None if status == "QUEUED" else "LEASE_EXPIRED",
                ),
            )
            _mark_intent(
                repository, task.spec.source_id, "PENDING" if status == "QUEUED" else "FAILED"
            )
            recovered += 1
        if hasattr(repository, "connection"):
            repository.connection.commit()
        return recovered


def queue_depth(repository: Any) -> dict[str, int]:
    statuses = ("QUEUED", "RUNNING", "COMPLETED", "FAILED")
    with repository._lock:
        if hasattr(repository, "connection"):
            rows = repository.connection.execute(
                "SELECT status,COUNT(*) FROM pcap_offset_index_jobs "
                "WHERE source_kind='LIVE_SEGMENT' GROUP BY status"
            ).fetchall()
            counts = {str(status): int(count) for status, count in rows}
        else:
            counts = {
                status: sum(task.status == status for task in _tasks(repository).values())
                for status in statuses
            }
    return {status: counts.get(status, 0) for status in statuses}


def cleanup_terminal(repository: Any, *, before: datetime, limit: int) -> int:
    if limit <= 0:
        raise ValueError("terminal cleanup limit must be positive")
    with repository._lock:
        if hasattr(repository, "connection"):
            rows = repository.connection.execute(
                "SELECT source_id,data FROM pcap_offset_index_jobs "
                "WHERE source_kind='LIVE_SEGMENT' AND status IN ('COMPLETED','FAILED')"
            ).fetchall()
            selected = sorted(
                (
                    (str(source_id), decode_task(raw))
                    for source_id, raw in rows
                    if decode_task(raw).updated_at <= before
                ),
                key=lambda item: (item[1].updated_at, item[0]),
            )[:limit]
            repository.connection.executemany(
                "DELETE FROM pcap_offset_index_jobs "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=? "
                "AND status IN ('COMPLETED','FAILED')",
                [(source_id,) for source_id, _task in selected],
            )
            repository.connection.commit()
        else:
            selected = sorted(
                (
                    (source_id, task)
                    for source_id, task in _tasks(repository).items()
                    if task.status in {"COMPLETED", "FAILED"} and task.updated_at <= before
                ),
                key=lambda item: (item[1].updated_at, item[0]),
            )[:limit]
            for source_id, _task in selected:
                del _tasks(repository)[source_id]
        return len(selected)


def reconcile(repository: Any, *, capacity: int, max_attempts: int, limit: int) -> int:
    segments = repository.list_sensor_pcaps()
    selected = sorted(
        (
            item
            for item in segments
            if item.get("index_requested_at")
            and item.get("index_intent_state", "PENDING") in _ELIGIBLE_INTENT_STATES
        ),
        key=lambda item: (str(item["index_requested_at"]), str(item["id"])),
    )
    admitted = 0
    for segment in selected:
        if admitted >= limit:
            break
        if get_task(repository, str(segment["id"])) is not None:
            continue
        if (
            admit(repository, str(segment["id"]), capacity=capacity, max_attempts=max_attempts)
            is IndexAdmission.QUEUED
        ):
            admitted += 1
    return admitted
