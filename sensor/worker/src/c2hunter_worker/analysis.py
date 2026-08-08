from __future__ import annotations

import os
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from c2hunter_analysis.custom import (
    DetectorRegistryCache,
    normalize_custom_detector_directory,
)
from c2hunter_analysis.detectors import DEFAULT_DETECTORS, run_detectors
from c2hunter_analysis.domain import AllowlistEntry, AnalysisContext, Flow
from c2hunter_analysis.scoring import score_candidates


_DETECTOR_REGISTRY = DetectorRegistryCache(DEFAULT_DETECTORS)


def execute_analysis(payload: dict[str, Any]) -> dict[str, Any]:
    flows: list[Flow] = []
    for stored in payload.get("flow_records", []):
        record = dict(stored)
        record.setdefault("source_port", None)
        record.setdefault("destination_port", None)
        timestamp = record.get("timestamp")
        if isinstance(timestamp, str):
            record["timestamp"] = datetime.fromisoformat(timestamp)
        record["packet_sizes"] = tuple(record.get("packet_sizes", ()))
        record.pop("raw_packet_hex", None)
        record.pop("payload_sample_hex", None)
        flows.append(Flow(**record))

    analysis = dict(payload.get("analysis", {}))
    analysis["payload_signatures"] = list(payload.get("payload_signatures", ()))
    allowlist = [
        AllowlistEntry.from_mapping(stored) for stored in payload.get("allowlist", [])
    ]
    now = datetime.now(UTC)
    analysis["trusted_dns_servers"] = [
        entry.value
        for entry in allowlist
        if entry.type.upper() == "TRUSTED_DNS" and entry.is_active(now)
    ]
    analysis["trusted_ntp_servers"] = [
        entry.value
        for entry in allowlist
        if entry.type.upper() == "TRUSTED_NTP" and entry.is_active(now)
    ]
    context = AnalysisContext(
        dataset_id=str(payload["dataset_id"]),
        start=datetime.fromisoformat(str(payload["start_time"])),
        end=datetime.fromisoformat(str(payload["end_time"])),
        flows=flows,
        selected_sensors=tuple(payload.get("sensor_ids", ())),
        internal_cidrs=tuple(payload.get("internal_networks", ())),
        parameters=analysis,
    )
    configured_directory = os.getenv("C2HUNTER_CUSTOM_DETECTORS_DIR")
    detector_directory = normalize_custom_detector_directory(configured_directory)
    evidence = run_detectors(
        context, detectors=_DETECTOR_REGISTRY.get(detector_directory)
    )
    candidates = score_candidates(
        evidence,
        allowlist=allowlist,
        minimum_samples=int(analysis.get("periodicity_min_samples", 1)),
        traffic_profiles=context.candidate_traffic_profiles(),
        high_volume_bytes_threshold=int(
            analysis.get("high_volume_bytes_threshold", 50 * 1024 * 1024)
        ),
        high_volume_packet_threshold=int(
            analysis.get("high_volume_packet_threshold", 100_000)
        ),
        high_volume_penalty=int(analysis.get("high_volume_penalty", 30)),
        high_volume_tcp_session_bytes_threshold=int(
            analysis.get("high_volume_tcp_session_bytes_threshold", 50 * 1024 * 1024)
        ),
        high_volume_tcp_session_packet_threshold=int(
            analysis.get("high_volume_tcp_session_packet_threshold", 100_000)
        ),
        high_volume_tcp_session_score_cap=int(
            analysis.get("high_volume_tcp_session_score_cap", 20)
        ),
        detector_weights={
            str(name): float(weight)
            for name, weight in dict(analysis.get("detector_weights", {})).items()
        },
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
