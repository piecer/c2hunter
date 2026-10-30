"""Conservative PG heartbeat audit policy; no cache or persistence side effects."""

from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Any


def routine_telemetry(
    before: dict[str, Any],
    after: dict[str, Any],
    *,
    clock_skew_threshold_seconds: float | None,
    heartbeat_timeout_seconds: float | None,
) -> bool:
    """True only for well-understood telemetry on an existing comparison baseline."""

    def number(value: Any) -> bool:
        return type(value) in (int, float) and math.isfinite(value)

    def counter(value: Any) -> bool:
        return type(value) is int and value >= 0

    try:
        if not all(
            v is not None and number(v) and v > 0
            for v in (clock_skew_threshold_seconds, heartbeat_timeout_seconds)
        ):
            return False
        if clock_skew_threshold_seconds is None or heartbeat_timeout_seconds is None:
            return False
        for field in ("reported_at", "last_heartbeat_at"):
            old, new = (datetime.fromisoformat(s[field]) for s in (before, after))
            if old.utcoffset() is None or new.utcoffset() is None:
                return False
            elapsed = (new - old).total_seconds()
            if elapsed < 0 or (
                field == "last_heartbeat_at" and elapsed > heartbeat_timeout_seconds
            ):
                return False
        offsets = [s["clock_offset_ms"] for s in (before, after)]
        if not all(number(v) for v in offsets):
            return False
        threshold = clock_skew_threshold_seconds * 1000
        if not math.isfinite(threshold) or (abs(offsets[0]) > threshold) != (
            abs(offsets[1]) > threshold
        ):
            return False
        for field in ("cpu_percent", "memory_percent", "disk_percent"):
            if not all(number(s[field]) and 0 <= s[field] <= 100 for s in (before, after)):
                return False
        for field in (
            "pending_bytes",
            "received_packets",
            "dropped_packets",
            "pcap_dropped_packets",
        ):
            if not all(counter(s[field]) for s in (before, after)):
                return False
        if after["received_packets"] < before["received_packets"]:
            return False
        stable = []
        volatile = {
            "reported_at",
            "last_heartbeat_at",
            "clock_offset_ms",
            "cpu_percent",
            "memory_percent",
            "disk_percent",
            "pending_bytes",
            "received_packets",
        }
        statuses = ("ONLINE", "OFFLINE", "DEGRADED", "CAPTURING", "ERROR")
        for sensor in (before, after):
            if any(
                sensor[field] not in statuses
                for field in ("status", "reported_status", "derived_status")
            ):
                return False
            if sensor["last_error"] is not None and not isinstance(sensor["last_error"], str):
                return False
            jobs = sensor["active_job_ids"]
            completions = sensor["completed_capture_jobs"]
            if not isinstance(jobs, list) or not all(isinstance(job, str) and job for job in jobs):
                return False
            if not isinstance(completions, list) or not all(
                isinstance(job, dict)
                and all(
                    isinstance(job.get(key), str) and job[key] for key in ("job_id", "stop_reason")
                )
                for job in completions
            ):
                return False
            rest = {k: v for k, v in sensor.items() if k not in volatile}
            interfaces = sensor["interfaces"]
            if not isinstance(interfaces, list):
                return False
            names = set()
            rest["interfaces"] = []
            for interface in interfaces:
                if not isinstance(interface, dict):
                    return False
                name = interface["interface"]
                if not isinstance(name, str) or not name or name in names:
                    return False
                names.add(name)
                if interface["status"] not in statuses or interface["direction"] not in (
                    "INBOUND",
                    "OUTBOUND",
                    "BIDIRECTIONAL",
                    "UNKNOWN",
                ):
                    return False
                if interface["last_error"] is not None and not isinstance(
                    interface["last_error"], str
                ):
                    return False
                if not counter(interface["received_packets"]) or not counter(
                    interface["dropped_packets"]
                ):
                    return False
                rest["interfaces"].append(
                    {k: v for k, v in interface.items() if k != "received_packets"}
                )
            stable.append(rest)
        # Compare all other fields, including unknown fields and loss counters.
        if json.dumps(stable[0], sort_keys=True, allow_nan=False) != json.dumps(
            stable[1], sort_keys=True, allow_nan=False
        ):
            return False
        return all(
            new["received_packets"] >= old["received_packets"]
            for old, new in zip(before["interfaces"], after["interfaces"], strict=True)
        )
    except (KeyError, TypeError, ValueError, OverflowError):
        # Uncertain input retains the old audit behavior, never rejects storage.
        return False
