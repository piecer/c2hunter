from __future__ import annotations

import math
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .flow_review import (
    compile_packet_filter_groups,
    filter_packet_records,
    matches_compiled_packet_groups,
)


@dataclass(frozen=True)
class CaptureBuildResult:
    content: bytes
    capture_format: str
    matched_packet_count: int
    exported_packet_count: int
    omitted_packet_count: int
    truncated: bool
    truncation_reasons: tuple[str, ...]


@dataclass(frozen=True)
class CompiledPacketPredicate:
    candidate_ip: str | None
    internal_host_ip: str | None
    start: datetime | None
    end: datetime | None
    port: int | None
    protocol: str | None
    direction: str | None
    sensor: str | None
    internal_networks: tuple[str, ...]
    include_filters: tuple[dict[str, Any], ...]
    exclude_filters: tuple[dict[str, Any], ...]

    def matches(self, packet: Any, *, sensor_id: str) -> bool:
        def value(name: str, default: Any = None) -> Any:
            if isinstance(packet, Mapping):
                return packet.get(name, default)
            return getattr(packet, name, default)

        source_ip = value("source_ip")
        destination_ip = value("destination_ip")
        timestamp = value("timestamp")
        if not isinstance(timestamp, datetime):
            timestamp = datetime.fromisoformat(str(timestamp))
        if self.candidate_ip not in {None, source_ip, destination_ip}:
            return False
        if self.internal_host_ip not in {None, source_ip, destination_ip}:
            return False
        if (self.start and timestamp < self.start) or (self.end and timestamp > self.end):
            return False
        if self.port not in {None, value("source_port"), value("destination_port")}:
            return False
        if self.protocol and str(value("protocol")).upper() != self.protocol:
            return False
        if self.direction and value("direction") != self.direction:
            return False
        if self.sensor and sensor_id != self.sensor:
            return False
        record = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": value("source_port"),
            "destination_port": value("destination_port"),
            "protocol": value("protocol"),
            "direction": value("direction"),
            "has_payload": value("has_payload", bool(value("payload_hash"))),
        }
        return matches_compiled_packet_groups(
            record,
            internal_networks=list(self.internal_networks),
            include_filters=self.include_filters,
            exclude_filters=self.exclude_filters,
        )


def compile_packet_predicate(
    filters: Mapping[str, Any], *, internal_networks: Sequence[str]
) -> CompiledPacketPredicate:
    copied = dict(filters)
    includes, excludes = compile_packet_filter_groups(
        [dict(item) for item in copied.get("include_filters", [])],
        [dict(item) for item in copied.get("exclude_filters", [])],
    )
    return CompiledPacketPredicate(
        str(copied["candidate_ip"]) if copied.get("candidate_ip") is not None else None,
        str(copied["internal_host_ip"]) if copied.get("internal_host_ip") is not None else None,
        datetime.fromisoformat(str(copied["start_time"])) if copied.get("start_time") else None,
        datetime.fromisoformat(str(copied["end_time"])) if copied.get("end_time") else None,
        int(copied["port"]) if copied.get("port") is not None else None,
        str(copied["protocol"]).upper() if copied.get("protocol") else None,
        str(copied["direction"]) if copied.get("direction") else None,
        str(copied["sensor_id"]) if copied.get("sensor_id") else None,
        tuple(str(item) for item in internal_networks),
        includes,
        excludes,
    )


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
        raw_bytes = record.get("raw_packet_bytes")
        raw_hex = record.get("raw_packet_hex")
        if isinstance(raw_bytes, bytes):
            packet = raw_bytes
        elif raw_hex:
            packet = bytes.fromhex(str(raw_hex))
        else:
            continue
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
    return math.floor(timestamp.timestamp()), timestamp.microsecond


def _block(kind: int, body: bytes) -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def build_capture_result(
    records: list[dict[str, Any]], *, max_output_bytes: int | None = None
) -> CaptureBuildResult:
    rows = _packet_rows(records)
    interface_keys = {(row[1], row[3], row[4]) for row in rows}
    classic_timestamps = all(0 <= _timestamp_parts(row[0])[0] <= 0xFFFFFFFF for row in rows)
    if len(interface_keys) <= 1 and classic_timestamps:
        link_type = next(iter(interface_keys), (0, 0, 1))[2]
        snaplen = max((len(row[5]) for row in rows), default=65535)
        output = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link_type))
        if max_output_bytes is not None and len(output) > max_output_bytes:
            raise ValueError("output byte limit is too small for the PCAP header")
        exported_packet_count = 0
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
            packet_record = (
                struct.pack("<IIII", seconds, microseconds, len(packet), original_length) + packet
            )
            if max_output_bytes is not None and len(output) + len(packet_record) > max_output_bytes:
                break
            output.extend(packet_record)
            exported_packet_count += 1
        omitted_packet_count = len(rows) - exported_packet_count
        return CaptureBuildResult(
            bytes(output),
            "PCAP",
            len(rows),
            exported_packet_count,
            omitted_packet_count,
            bool(omitted_packet_count),
            ("OUTPUT_BYTE_LIMIT",) if omitted_packet_count else (),
        )

    interface_snaplens: dict[tuple[int, int, int], int] = {}
    interface_min_timestamps: dict[tuple[int, int, int], float] = {}
    for timestamp, source_order, _packet_index, interface_id, link_type, packet, _ in rows:
        key = (source_order, interface_id, link_type)
        interface_snaplens[key] = max(interface_snaplens.get(key, 0), len(packet))
        unix_timestamp = timestamp.timestamp()
        interface_min_timestamps[key] = min(
            interface_min_timestamps.get(key, unix_timestamp), unix_timestamp
        )
    timestamp_offsets = {
        key: min(0, math.floor(timestamp)) for key, timestamp in interface_min_timestamps.items()
    }
    output = bytearray(_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)))
    if max_output_bytes is not None and len(output) > max_output_bytes:
        raise ValueError("output byte limit is too small for the PCAPNG section header")
    interface_ids: dict[tuple[int, int, int], int] = {}
    exported_packet_count = 0
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
        interface_block = b""
        if key not in interface_ids:
            options = b""
            if timestamp_offsets[key]:
                options = struct.pack("<HHqHH", 14, 8, timestamp_offsets[key], 0, 0)
            interface_block = _block(
                1, struct.pack("<HHI", key[2], 0, interface_snaplens[key]) + options
            )
        ticks = round((timestamp.timestamp() - timestamp_offsets[key]) * 1_000_000)
        if not 0 <= ticks <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("packet timestamp exceeds the PCAPNG range")
        body = (
            struct.pack(
                "<IIIII",
                interface_ids.get(key, len(interface_ids)),
                ticks >> 32,
                ticks & 0xFFFFFFFF,
                len(packet),
                original_length,
            )
            + packet
        )
        packet_block = _block(6, body)
        required_bytes = len(interface_block) + len(packet_block)
        if max_output_bytes is not None and len(output) + required_bytes > max_output_bytes:
            break
        if interface_block:
            interface_ids[key] = len(interface_ids)
            output.extend(interface_block)
        output.extend(packet_block)
        exported_packet_count += 1
    omitted_packet_count = len(rows) - exported_packet_count
    return CaptureBuildResult(
        bytes(output),
        "PCAPNG",
        len(rows),
        exported_packet_count,
        omitted_packet_count,
        bool(omitted_packet_count),
        ("OUTPUT_BYTE_LIMIT",) if omitted_packet_count else (),
    )


def build_capture(
    records: list[dict[str, Any]], *, max_output_bytes: int | None = None
) -> tuple[bytes, int, str]:
    result = build_capture_result(records, max_output_bytes=max_output_bytes)
    if max_output_bytes is not None and result.truncated:
        raise ValueError("generated capture exceeds the output byte limit")
    return result.content, result.exported_packet_count, result.capture_format


def build_pcap(records: list[dict[str, Any]]) -> tuple[bytes, int]:
    """Backward-compatible helper retained for callers that expect two return values."""
    content, count, _capture_format = build_capture(records)
    return content, count
