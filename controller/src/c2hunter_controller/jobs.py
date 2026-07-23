from __future__ import annotations

import uuid
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
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


def summarize_candidate_traffic(
    records: list[dict[str, Any]], candidate_ips: set[str]
) -> dict[str, dict[str, Any]]:
    if not candidate_ips:
        return {}
    grouped: dict[str, list[dict[str, Any]]] = {candidate: [] for candidate in candidate_ips}
    for record in records:
        for address in {record.get("source_ip"), record.get("destination_ip")} & candidate_ips:
            grouped[str(address)].append(record)

    result: dict[str, dict[str, Any]] = {}
    for candidate_ip, matched in grouped.items():
        timestamped: list[tuple[datetime, dict[str, Any]]] = []
        for record in matched:
            raw_timestamp = record.get("timestamp")
            try:
                timestamp = (
                    raw_timestamp
                    if isinstance(raw_timestamp, datetime)
                    else datetime.fromisoformat(str(raw_timestamp))
                )
            except (TypeError, ValueError):
                continue
            timestamped.append((timestamp, record))
        timestamped.sort(key=lambda item: item[0])

        buckets: list[dict[str, Any]] = []
        if timestamped:
            first, last = timestamped[0][0], timestamped[-1][0]
            span_seconds = max(0.0, (last - first).total_seconds())
            bucket_count = 1 if span_seconds == 0 else min(24, len(timestamped))
            bucket_width = max(1.0, span_seconds / bucket_count)
            aggregate: dict[int, dict[str, int]] = {}
            for timestamp, record in timestamped:
                index = min(
                    bucket_count - 1,
                    int((timestamp - first).total_seconds() / bucket_width),
                )
                bucket = aggregate.setdefault(index, {"packets": 0, "bytes": 0, "flows": 0})
                bucket["packets"] += int(record.get("packet_count", 1) or 0)
                bucket["bytes"] += int(record.get("total_bytes", 0) or 0)
                bucket["flows"] += 1
            buckets = [
                {
                    "start": (first + timedelta(seconds=index * bucket_width)).isoformat(),
                    **aggregate[index],
                }
                for index in sorted(aggregate)
            ]

        ports: set[int] = set()
        for record in matched:
            raw_port = (
                record.get("destination_port")
                if record.get("destination_ip") == candidate_ip
                else record.get("source_port")
            )
            if isinstance(raw_port, int) and not isinstance(raw_port, bool):
                ports.add(raw_port)
        result[candidate_ip] = {
            "protocols": sorted(
                {str(record["protocol"]).upper() for record in matched if record.get("protocol")}
            ),
            "ports": sorted(ports),
            "domains": sorted(
                {str(record["domain"]) for record in matched if record.get("domain")}
            ),
            "related_attack_targets": sorted(
                {
                    str(record["attack_target_ip"])
                    for record in matched
                    if record.get("attack_target_ip")
                }
            ),
            "flow_count": len(matched),
            "packet_count": sum(int(record.get("packet_count", 1) or 0) for record in matched),
            "byte_count": sum(int(record.get("total_bytes", 0) or 0) for record in matched),
            "traffic_buckets": buckets,
            "traffic_series": [bucket["packets"] for bucket in buckets],
        }
    return result


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
        job["updated_at"] = occurred
        if target in TERMINAL:
            job["completed_at"] = occurred


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
        "description": "",
        "idempotency_key": payload.idempotency_key,
        "mode": payload.mode,
        "source_type": "PCAP_UPLOAD" if payload.mode == "PCAP_UPLOAD" else "SENSOR_CAPTURE",
        "status": JobState.CREATED.value,
        "sensor_ids": payload.sensor_ids,
        "start_time": payload.start_time.isoformat(),
        "end_time": payload.end_time.isoformat(),
        "capture": payload.capture.model_dump(mode="json"),
        "analysis": payload.analysis.model_dump(mode="json"),
        "internal_networks": payload.internal_networks,
        "flow_records": [
            item.model_dump(mode="json", exclude_none=True) for item in payload.flow_records
        ],
        "created_at": now,
        "updated_at": now,
        "completed_at": None,
        "packet_count": sum(item.packet_count for item in payload.flow_records),
        "flow_count": len(payload.flow_records),
        "candidate_count": 0,
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
    retained = [candidate for candidate in scored if candidate.score >= minimum_score]
    traffic = summarize_candidate_traffic(
        job["flow_records"], {candidate.candidate_ip for candidate in retained}
    )
    result: list[dict[str, Any]] = []
    for candidate in retained:
        serialized = asdict(candidate)
        serialized["id"] = str(uuid.uuid4())
        serialized.update(traffic.get(candidate.candidate_ip, {}))
        result.append(serialized)
    return result
