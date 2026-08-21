from __future__ import annotations

import math
import struct
from datetime import datetime
from typing import Any

from .flow_review import filter_packet_records


def filter_records(
    records: list[dict[str, Any]],
    filters: dict[str, Any],
    *,
    internal_networks: list[str] | None = None,
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    start = datetime.fromisoformat(filters["start_time"]) if filters.get("start_time") else None
    end = datetime.fromisoformat(filters["end_time"]) if filters.get("end_time") else None
    for record in records:
        raw_timestamp = record["timestamp"]
        timestamp = (
            raw_timestamp
            if isinstance(raw_timestamp, datetime)
            else datetime.fromisoformat(raw_timestamp)
        )
        if filters.get("candidate_ip") not in {None, record["source_ip"], record["destination_ip"]}:
            continue
        if filters.get("internal_host_ip") not in {
            None,
            record["source_ip"],
            record["destination_ip"],
        }:
            continue
        if start and timestamp < start or end and timestamp > end:
            continue
        if filters.get("port") not in {
            None,
            record.get("source_port"),
            record.get("destination_port"),
        }:
            continue
        if filters.get("protocol") and record["protocol"].upper() != filters["protocol"].upper():
            continue
        if filters.get("direction") and record["direction"] != filters["direction"]:
            continue
        if filters.get("sensor_id") and record["sensor_id"] != filters["sensor_id"]:
            continue
        result.append(record)
    return filter_packet_records(
        result,
        internal_networks=internal_networks or ["0.0.0.0/0", "::/0"],
        include_filters=filters.get("include_filters"),
        exclude_filters=filters.get("exclude_filters"),
    )


def _packet_rows(
    records: list[dict[str, Any]],
) -> list[tuple[datetime, int, int, int, int, bytes, int]]:
    rows: list[tuple[datetime, int, int, int, int, bytes, int]] = []
    for record in records:
        raw_hex = record.get("raw_packet_hex")
        if not raw_hex:
            continue
        packet = bytes.fromhex(str(raw_hex))
        raw_timestamp = record["timestamp"]
        timestamp = (
            raw_timestamp
            if isinstance(raw_timestamp, datetime)
            else datetime.fromisoformat(str(raw_timestamp))
        )
        rows.append(
            (
                timestamp,
                int(record.get("raw_packet_source_order", 0)),
                int(record.get("raw_packet_index", 0)),
                int(record.get("raw_packet_interface_id", 0)),
                int(record.get("raw_packet_link_type", 1)),
                packet,
                int(record.get("raw_packet_original_length", len(packet))),
            )
        )
    rows.sort(key=lambda row: (row[1], row[2]))
    return rows


def _timestamp_parts(timestamp: datetime) -> tuple[int, int]:
    return int(timestamp.timestamp()), timestamp.microsecond


def _block(kind: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def build_capture(
    records: list[dict[str, Any]], *, max_output_bytes: int | None = None
) -> tuple[bytes, int, str]:
    rows = _packet_rows(records)
    interface_keys = {(row[1], row[3], row[4]) for row in rows}
    classic_timestamps = all(0 <= _timestamp_parts(row[0])[0] <= 0xFFFFFFFF for row in rows)
    if len(interface_keys) <= 1 and classic_timestamps:
        link_type = next(iter(interface_keys), (0, 0, 1))[2]
        snaplen = max((len(row[5]) for row in rows), default=65535)
        output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link_type))
        for (
            timestamp,
            _source_order,
            _packet_index,
            _interface_id,
            _link_type,
            packet,
            original_length,
        ) in rows:
            seconds, microseconds = _timestamp_parts(timestamp)
            output.extend(struct.pack("<IIII", seconds, microseconds, len(packet), original_length))
            output.extend(packet)
            if max_output_bytes is not None and len(output) > max_output_bytes:
                raise ValueError("generated capture exceeds the output byte limit")
        return bytes(output), len(rows), "PCAP"

    ordered_interfaces = sorted(interface_keys)
    interface_ids = {key: index for index, key in enumerate(ordered_interfaces)}
    timestamp_offsets = {
        key: min(
            0,
            math.floor(min(row[0].timestamp() for row in rows if (row[1], row[3], row[4]) == key)),
        )
        for key in ordered_interfaces
    }
    output = bytearray(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    for key in ordered_interfaces:
        snaplen = max(len(row[5]) for row in rows if (row[1], row[3], row[4]) == key)
        options = b""
        if timestamp_offsets[key]:
            options = struct.pack("<HHqHH", 14, 8, timestamp_offsets[key], 0, 0)
        output.extend(_block(1, struct.pack("<HHI", key[2], 0, snaplen) + options))
    for (
        timestamp,
        source_order,
        _packet_index,
        interface_id,
        _link_type,
        packet,
        original_length,
    ) in rows:
        key = (source_order, interface_id, _link_type)
        ticks = round((timestamp.timestamp() - timestamp_offsets[key]) * 1_000_000)
        if not 0 <= ticks <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("packet timestamp exceeds the PCAPNG range")
        body = (
            struct.pack(
                "<IIIII",
                interface_ids[key],
                ticks >> 32,
                ticks & 0xFFFFFFFF,
                len(packet),
                original_length,
            )
            + packet
        )
        output.extend(_block(6, body))
        if max_output_bytes is not None and len(output) > max_output_bytes:
            raise ValueError("generated capture exceeds the output byte limit")
    return bytes(output), len(rows), "PCAPNG"


def build_pcap(records: list[dict[str, Any]]) -> tuple[bytes, int]:
    """Backward-compatible helper retained for callers that expect two return values."""
    content, count, _capture_format = build_capture(records)
    return content, count
