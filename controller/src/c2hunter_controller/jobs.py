from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from c2hunter_analysis.detectors import run_detectors
from c2hunter_analysis.domain import AllowlistEntry, AnalysisContext, Flow
from c2hunter_analysis.scoring import score_candidates

from .schemas import AnalysisJobCreate


class JobState(StrEnum):
    CREATED = "CREATED"
    WAITING_FOR_SENSOR = "WAITING_FOR_SENSOR"
    CAPTURING = "CAPTURING"
    UPLOADING = "UPLOADING"
    INGESTING = "INGESTING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


TERMINAL = {JobState.COMPLETED, JobState.PARTIALLY_COMPLETED, JobState.FAILED, JobState.CANCELLED}


class StateMachine:
    transitions: dict[JobState, set[JobState]] = {
        JobState.CREATED: {JobState.WAITING_FOR_SENSOR, JobState.FAILED, JobState.CANCELLED},
        JobState.WAITING_FOR_SENSOR: {JobState.CAPTURING, JobState.FAILED, JobState.CANCELLED},
        JobState.CAPTURING: {JobState.UPLOADING, JobState.FAILED, JobState.CANCELLED},
        JobState.UPLOADING: {JobState.INGESTING, JobState.FAILED, JobState.CANCELLED},
        JobState.INGESTING: {JobState.ANALYZING, JobState.FAILED, JobState.CANCELLED},
        JobState.ANALYZING: {
            JobState.COMPLETED,
            JobState.PARTIALLY_COMPLETED,
            JobState.FAILED,
            JobState.CANCELLED,
        },
        JobState.COMPLETED: set(),
        JobState.PARTIALLY_COMPLETED: set(),
        JobState.FAILED: set(),
        JobState.CANCELLED: set(),
    }

    def validate(self, current: JobState, target: JobState) -> None:
        if target not in self.transitions[current]:
            raise ValueError(f"invalid job transition: {current} -> {target}")

    def transition(self, job: dict[str, Any], target: JobState, reason: str) -> None:
        current = JobState(job["status"])
        self.validate(current, target)
        occurred = datetime.now(UTC).isoformat()
        job["status"] = target.value
        job["transitions"].append(
            {
                "from_status": current.value,
                "to_status": target.value,
                "occurred_at": occurred,
                "reason": reason,
            }
        )


def build_job(
    payload: AnalysisJobCreate, *, parent_job_id: str | None = None, dataset_id: str | None = None
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    job_id = str(uuid.uuid4())
    return {
        "id": job_id,
        "dataset_id": dataset_id or str(uuid.uuid4()),
        "parent_job_id": parent_job_id,
        "name": payload.name,
        "idempotency_key": payload.idempotency_key,
        "mode": payload.mode,
        "status": JobState.CREATED.value,
        "sensor_ids": payload.sensor_ids,
        "start_time": payload.start_time.isoformat(),
        "end_time": payload.end_time.isoformat(),
        "capture": payload.capture.model_dump(mode="json"),
        "analysis": payload.analysis.model_dump(mode="json"),
        "internal_networks": payload.internal_networks,
        "flow_records": [item.model_dump(mode="json") for item in payload.flow_records],
        "created_at": now,
        "transitions": [
            {
                "from_status": None,
                "to_status": "CREATED",
                "occurred_at": now,
                "reason": "analysis requested",
            }
        ],
    }


def calculate(
    job: dict[str, Any], allowlist: list[dict[str, Any]] | None = None
) -> list[dict[str, Any]]:
    flows = []
    for stored in job["flow_records"]:
        record = dict(stored)
        if isinstance(record["timestamp"], str):
            record["timestamp"] = datetime.fromisoformat(record["timestamp"])
        record["packet_sizes"] = tuple(record.get("packet_sizes", ()))
        record.pop("raw_packet_hex", None)
        flows.append(Flow(**record))
    context = AnalysisContext(
        job["dataset_id"],
        datetime.fromisoformat(job["start_time"]),
        datetime.fromisoformat(job["end_time"]),
        flows,
        tuple(job["sensor_ids"]),
        tuple(job["internal_networks"]),
        parameters=job["analysis"],
    )
    evidence = run_detectors(context)
    entries = []
    for stored in allowlist or []:
        expires = stored.get("expires_at")
        entries.append(
            AllowlistEntry(
                stored["type"],
                stored["value"],
                stored["description"],
                datetime.fromisoformat(expires) if isinstance(expires, str) else expires,
                bool(stored.get("enabled", True)),
            )
        )
    scored = score_candidates(
        evidence,
        allowlist=entries,
        minimum_samples=int(job["analysis"]["periodicity_min_samples"]),
    )
    minimum_score = int(job["analysis"]["minimum_candidate_score"])
    result: list[dict[str, Any]] = []
    for candidate in scored:
        if candidate.score < minimum_score:
            continue
        serialized = asdict(candidate)
        serialized["id"] = str(uuid.uuid4())
        result.append(serialized)
    return result
