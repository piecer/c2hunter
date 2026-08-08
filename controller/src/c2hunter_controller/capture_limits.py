from __future__ import annotations

from typing import Any

_TCP_COUNTER_FIELDS = (
    "tcp_flags.fin",
    "tcp_flags.syn",
    "tcp_flags.rst",
    "tcp_flags.psh",
    "tcp_flags.ack",
    "tcp_flags.urg",
    "tcp_flags.ece",
    "tcp_flags.cwr",
)


def _positive_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def allocate_sensor_limit(
    configured_limit: object, sensor_ids: list[str], sensor_id: str
) -> int | None:
    """Return this sensor's share of an analysis-wide hard limit.

    The existing wire protocol interprets zero as unlimited, so callers must
    omit a capture job when this function returns zero. Sorting makes the
    quotient/remainder allocation deterministic across controller processes.
    """

    limit = _positive_int(configured_limit)
    if limit is None:
        return None
    sensors = sorted(set(sensor_ids))
    if not sensors or sensor_id not in sensors:
        return 0
    quotient, remainder = divmod(limit, len(sensors))
    index = sensors.index(sensor_id)
    return quotient + (1 if index < remainder else 0)


def limit_flow_records(
    records: list[dict[str, Any]], configured_max_packets: object
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Apply a final analysis-wide packet cap to aggregated flow records.

    Sensors enforce their assigned quotas while capturing. This controller
    guard is still required for mixed agent versions, sensor restarts and
    batches already in flight. When the boundary falls inside an aggregated
    flow, packet_count and total_bytes are reduced proportionally.
    """

    limit = _positive_int(configured_max_packets)
    observed_packets = sum(_record_packets(record) for record in records)
    if limit is None or observed_packets <= limit:
        copied = [dict(record) for record in records]
        return copied, {
            "configured_max_packets": limit or 0,
            "observed_packets": observed_packets,
            "retained_packets": observed_packets,
            "discarded_packets": 0,
        }

    remaining = limit
    retained: list[dict[str, Any]] = []
    retained_packets = 0
    for record in records:
        packet_count = _record_packets(record)
        if remaining <= 0:
            break
        item = dict(record)
        if packet_count <= remaining:
            retained.append(item)
            remaining -= packet_count
            retained_packets += packet_count
            continue

        item["packet_count"] = remaining
        total_bytes = _record_bytes(item)
        item["total_bytes"] = total_bytes * remaining // packet_count
        # Clear TCP counters when packet boundaries are uncertain.
        tcp_flags = item.get("tcp_flags")
        if isinstance(tcp_flags, dict):
            for key in tuple(tcp_flags):
                if f"tcp_flags.{key}" in _TCP_COUNTER_FIELDS:
                    del tcp_flags[key]
        retained.append(item)
        retained_packets += remaining
        remaining = 0

    return retained, {
        "configured_max_packets": limit,
        "observed_packets": observed_packets,
        "retained_packets": retained_packets,
        "discarded_packets": observed_packets - retained_packets,
    }


def _record_packets(record: dict[str, Any]) -> int:
    value = record.get("packet_count", 1)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return 1
    return value


def _record_bytes(record: dict[str, Any]) -> int:
    value = record.get("total_bytes", 0)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value
