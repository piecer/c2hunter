from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from c2hunter_analysis.detectors import run_detectors
from c2hunter_analysis.domain import AnalysisContext, Flow
from c2hunter_analysis.scoring import score_candidates


def execute_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    flows: list[Flow] = []
    for stored in payload.get("flow_records", []):
        record = dict(stored)
        timestamp = record.get("timestamp")
        if isinstance(timestamp, str):
            record["timestamp"] = datetime.fromisoformat(timestamp)
        record["packet_sizes"] = tuple(record.get("packet_sizes", ()))
        record.pop("raw_packet_hex", None)
        flows.append(Flow(**record))

    analysis = dict(payload.get("analysis", {}))
    context = AnalysisContext(
        dataset_id=str(payload["dataset_id"]),
        start=datetime.fromisoformat(str(payload["start_time"])),
        end=datetime.fromisoformat(str(payload["end_time"])),
        flows=flows,
        selected_sensors=tuple(payload.get("sensor_ids", ())),
        internal_cidrs=tuple(payload.get("internal_networks", ())),
        parameters=analysis,
    )
    evidence = run_detectors(context)
    candidates = score_candidates(
        evidence,
        minimum_samples=int(analysis.get("periodicity_min_samples", 1)),
    )
    minimum_score = int(analysis.get("minimum_candidate_score", 0))
    return {
        "candidates": [
            _json_value(asdict(candidate))
            for candidate in candidates
            if candidate.score >= minimum_score
        ]
    }


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {key: _json_value(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_json_value(item) for item in value]
    return value
