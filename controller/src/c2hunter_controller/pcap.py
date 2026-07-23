from __future__ import annotations

import struct
from datetime import datetime
from typing import Any


def filter_records(records: list[dict[str, Any]], filters: dict[str, Any]) -> list[dict[str, Any]]:
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
    return result


def build_pcap(records: list[dict[str, Any]]) -> tuple[bytes, int]:
    output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    count = 0
    for record in records:
        raw_hex = record.get("raw_packet_hex")
        if not raw_hex:
            continue
        packet = bytes.fromhex(raw_hex)
        raw_timestamp = record["timestamp"]
        parsed_timestamp = (
            raw_timestamp
            if isinstance(raw_timestamp, datetime)
            else datetime.fromisoformat(raw_timestamp)
        )
        timestamp = parsed_timestamp.timestamp()
        seconds = int(timestamp)
        microseconds = int((timestamp - seconds) * 1_000_000)
        output.extend(struct.pack("<IIII", seconds, microseconds, len(packet), len(packet)))
        output.extend(packet)
        count += 1
    return bytes(output), count
