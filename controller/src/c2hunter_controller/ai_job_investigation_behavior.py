"""Strict bounded adapter to the real detector, never a candidate selector.

Unsupported context is not repaired with Flow/AnalysisContext measurement defaults.
The caller has already admitted and committed the original raw values. Defaults on
unused Flow attributes are not observations and are never exposed as evidence.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import ip_network
from math import isfinite
from typing import Any

from c2hunter_analysis import behavior_discovery as detector
from c2hunter_analysis.domain import AnalysisContext, Flow, normalize_tcp_syn_observations

from .ai_investigation_contract import literal_ip
from .ai_job_investigation_schema import DiscoveryCoverage
from .historical_baseline import project_source_quality

COUNTERS = (
    "packet_count",
    "total_bytes",
    "tcp_syn_count",
    "tcp_ack_count",
    "tcp_rst_count",
    "tcp_syn_only_count",
    "tcp_syn_ack_count",
    "tcp_ack_only_count",
)
BOOLS = ("tcp_flags_observed", "tcp_syn_only_observations_truncated", "bidirectional")
PAYLOADS = ("payload_hash", "last_payload_hash", "payload_prefix_hash", "payload_simhash")
FIELDS = (
    "sensor_id",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "direction",
    "duration_seconds",
    "payload_length",
    "tcp_flags",
    "tcp_syn_only_observations",
    *COUNTERS,
    *BOOLS,
    *PAYLOADS,
)


def _context(metadata: dict[str, Any], rows: list[dict[str, Any]]) -> AnalysisContext:
    sensors = metadata["sensor_ids"]
    cidrs = metadata["internal_networks"]
    operations = metadata["operations"]["sensors"]
    parameters = metadata["analysis"]
    if (
        type(sensors) is not list
        or type(cidrs) is not list
        or type(operations) is not dict
        or any(len(v) > 128 for v in (sensors, cidrs, operations, parameters))
        or not rows
    ):
        raise ValueError("unsupported context")
    if any(type(v) is not str or not 1 <= len(v) <= 200 for v in sensors):
        raise ValueError("unsupported sensors")
    for cidr in cidrs:
        if type(cidr) is not str or len(cidr) > 256:
            raise ValueError("unsupported CIDR")
        ip_network(cidr, strict=False)
    for name, low, high in (
        ("tcp_syn_retry_min_intervals", 3, 15),
        ("tcp_syn_retry_min_interval_ms", 1, 300000),
        ("tcp_syn_retry_max_interval_ms", 1, 300000),
        ("tcp_syn_retry_max_interval_multiple", 1, 32),
        ("tcp_syn_retry_absolute_tolerance_ms", 0, 10000),
    ):
        if name in parameters and (
            type(parameters[name]) is not int or not low <= parameters[name] <= high
        ):
            raise ValueError("unsupported suppression parameter")
    enabled = parameters.get("tcp_syn_retry_detection_enabled", True)
    ratio = parameters.get("tcp_syn_retry_tolerance_ratio", 0.20)
    if (
        type(enabled) is not bool
        or type(ratio) not in (int, float)
        or not isfinite(ratio)
        or not 0 <= ratio <= 0.5
        or parameters.get("tcp_syn_retry_max_interval_ms", 120000)
        < parameters.get("tcp_syn_retry_min_interval_ms", 500)
    ):
        raise ValueError("unsupported suppression parameter")
    offsets = {}
    for sensor, status in operations.items():
        offset = status["clock_offset_ms"]
        if type(offset) not in (int, float) or not isfinite(offset) or abs(offset) > 2**53:
            raise ValueError("unsupported clock")
        offsets[sensor] = float(offset)
    flows = []
    syn_count = 0
    for raw in rows:
        values = {key: raw[key] for key in FIELDS}
        values["source_ip"] = literal_ip(values["source_ip"])
        values["destination_ip"] = literal_ip(values["destination_ip"])
        if any(type(values[k]) is not int or not 0 <= values[k] <= 2**53 for k in COUNTERS):
            raise ValueError("unsupported counter")
        if any(type(values[k]) is not bool for k in BOOLS):
            raise ValueError("unsupported boolean")
        if any(
            v is not None and (type(v) is not str or len(v) > 256)
            for v in (values[k] for k in PAYLOADS)
        ):
            raise ValueError("unsupported payload observation")
        if values["sensor_id"] not in offsets:
            raise ValueError("unobserved clock")
        length = values["payload_length"]
        if length is not None and (type(length) is not int or not 0 <= length < 2**40):
            raise ValueError("unsupported payload length")
        duration = values["duration_seconds"]
        if type(duration) not in (int, float) or not isfinite(duration):
            raise ValueError("unsupported duration")
        flags = values["tcp_flags"]
        if flags is not None and (type(flags) is not dict or len(flags) > 16):
            raise ValueError("unsupported flags")
        observations = values["tcp_syn_only_observations"]
        if observations is not None:
            if type(observations) is not list:
                raise ValueError("unsupported SYN observations")
            syn_count += len(observations)
            if syn_count > 256:
                raise ValueError("unsupported SYN budget")
            for item in observations:
                if type(item) is dict and set(item) != {"offset_us", "sequence"}:
                    raise ValueError("unsupported SYN shape")
        values["tcp_syn_only_observations"] = normalize_tcp_syn_observations(observations)
        values["tcp_flags"] = None if flags is None else dict(flags)
        flow = Flow(timestamp=datetime.fromisoformat(raw["timestamp"]), **values)
        if not detector._valid_row(flow):
            raise ValueError("unsupported row")
        counters = [getattr(flow, name) for name in COUNTERS[2:]]
        if (
            any(v > flow.packet_count for v in counters)
            or (not flow.tcp_flags_observed and any(counters))
            or (flow.tcp_flags_observed and flow.protocol.upper() != "TCP")
            or flow.tcp_syn_only_count + flow.tcp_syn_ack_count > flow.tcp_syn_count
            or flow.tcp_syn_ack_count + flow.tcp_ack_only_count > flow.tcp_ack_count
            or sum(
                (
                    flow.tcp_syn_only_count,
                    flow.tcp_syn_ack_count,
                    flow.tcp_ack_only_count,
                    flow.tcp_rst_count,
                )
            )
            > flow.packet_count
        ):
            raise ValueError("unsupported TCP counter relations")
        syn = flow.tcp_syn_only_observations
        if syn is not None:
            offsets_us = [item[0] for item in syn]
            if (
                not flow.tcp_flags_observed
                or flow.protocol.upper() != "TCP"
                or offsets_us != sorted(set(offsets_us))
                or (offsets_us and offsets_us[-1] > round(flow.duration_seconds * 1000000))
                or (
                    not flow.tcp_syn_only_observations_truncated
                    and len(syn) != flow.tcp_syn_only_count
                )
            ):
                raise ValueError("unsupported SYN relations")
        elif flow.tcp_syn_only_observations_truncated:
            raise ValueError("unsupported SYN absence")
        flows.append(flow)
    # This is the observed row window, not invented capture start/end metadata.
    return AnalysisContext(
        dataset_id=metadata["dataset_id"],
        start=min(f.timestamp for f in flows),
        end=max(f.timestamp + timedelta(seconds=f.duration_seconds) for f in flows)
        + timedelta(microseconds=1),
        flows=tuple(flows),
        selected_sensors=tuple(sensors),
        internal_cidrs=tuple(cidrs),
        clock_offsets_ms=offsets,
        parameters=dict(parameters),
    )


def discover(
    metadata: dict[str, Any], rows: list[dict[str, Any]]
) -> tuple[dict[str, float], DiscoveryCoverage]:
    warnings: set[str] = set()
    try:
        quality = project_source_quality(metadata)
        if metadata["status"] == "PARTIALLY_COMPLETED" or (
            quality.capture_incomplete.present and quality.capture_incomplete.value is True
        ):
            warnings.add("SOURCE_PARTIAL")
        if any(
            item.present and item.value
            for item in (
                quality.dropped_packet_count,
                quality.skipped_packet_count,
                quality.discarded_packets,
                quality.failed_sensors,
                quality.error_code,
            )
        ):
            warnings.add("CAPTURE_LOSS_REPORTED")
        if any(
            not item.present
            for item in (
                quality.capture_incomplete,
                quality.dropped_packet_count,
                quality.clock_skew_detected,
            )
        ):
            warnings.add("CAPTURE_QUALITY_NOT_OBSERVED")
        context = _context(metadata, rows)
        if quality.clock_skew_detected.present and quality.clock_skew_detected.value is True:
            # A generic skew flag cannot be converted into a made-up sensor offset.
            warnings.add("CAPTURE_CLOCK_UNCERTAINTY")
            raise ValueError("unattributed capture skew")
    except (KeyError, TypeError, ValueError, OverflowError):
        return {}, DiscoveryCoverage(
            state="UNAVAILABLE",
            examined_peers=None,
            excluded_peers=None,
            warnings=tuple(sorted(warnings | {"BEHAVIOR_CONTEXT_UNAVAILABLE"})),
        )
    result = detector.discover_behavior_candidates(context)
    warnings.update(result.warnings)
    return {item.candidate_ip: item.anomaly_score for item in result.candidates}, DiscoveryCoverage(
        state="PARTIAL" if warnings or result.excluded_peer_count else "AVAILABLE",
        examined_peers=result.examined_peer_count,
        excluded_peers=result.excluded_peer_count,
        warnings=tuple(sorted(warnings)),
    )
