from __future__ import annotations

import json
import math
import struct
import tempfile
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from .capture_sink import (
    CaptureArtifact,
    CaptureLimitTooSmall,
    CaptureRecordError,
    CaptureSink,
    CaptureStorageError,
)
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


def _legacy_build_capture_result(
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


def _legacy_build_capture(
    records: list[dict[str, Any]], *, max_output_bytes: int | None = None
) -> tuple[bytes, int, str]:
    result = _legacy_build_capture_result(records, max_output_bytes=max_output_bytes)
    if max_output_bytes is not None and result.truncated:
        raise ValueError("generated capture exceeds the output byte limit")
    return result.content, result.exported_packet_count, result.capture_format


def _legacy_build_pcap(records: list[dict[str, Any]]) -> tuple[bytes, int]:
    """Materialized oracle retained for differential tests."""
    content, count, _capture_format = _legacy_build_capture(records)
    return content, count


@dataclass(frozen=True)
class ExportPacketRecord:
    timestamp: datetime
    source_id: str
    source_order: int
    packet_index: int
    section_index: int
    interface_id: int
    interface_ordinal: int
    link_type: int
    packet_bytes: bytes
    captured_length: int
    original_length: int


_SPOOL_MAGIC = b"C2CAPSP\x01"
_FRAME_LENGTH = struct.Struct("<I")
MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024
_MAX_FRAME_BYTES = MAX_CAPTURED_PACKET_BYTES + 64 * 1024


def _validate_export_record(
    record: ExportPacketRecord,
    previous_key: tuple[int, int] | None,
    source_ids: dict[int, str],
    interface_links: dict[tuple[int, int], int],
    local_interface_ordinals: dict[tuple[int, int, int], int],
) -> tuple[int, int]:
    if record.timestamp.utcoffset() is None:
        raise CaptureRecordError("packet timestamp must be timezone-aware")
    if not record.source_id:
        raise CaptureRecordError("source_id must be non-empty")
    if type(record.packet_bytes) is not bytes:
        raise CaptureRecordError("packet payload must be immutable bytes")
    identifiers = (
        record.source_order,
        record.packet_index,
        record.section_index,
        record.interface_id,
        record.interface_ordinal,
        record.link_type,
        record.captured_length,
        record.original_length,
    )
    if any(value < 0 for value in identifiers):
        raise CaptureRecordError("packet identifiers and lengths must be non-negative")
    if record.captured_length != len(record.packet_bytes):
        raise CaptureRecordError("captured_length must equal packet byte length")
    if record.original_length < record.captured_length:
        raise CaptureRecordError("original_length must not be smaller than captured_length")
    if record.captured_length > MAX_CAPTURED_PACKET_BYTES:
        raise CaptureRecordError("packet exceeds the maximum captured packet size")
    if record.link_type > 0xFFFF:
        raise CaptureRecordError("packet link type exceeds the supported range")
    if record.original_length > 0xFFFFFFFF:
        raise CaptureRecordError("packet original length exceeds the supported range")
    key = (record.source_order, record.packet_index)
    if previous_key is not None and key <= previous_key:
        raise CaptureRecordError("packet records must be in strictly canonical order")
    known_source = source_ids.setdefault(record.source_order, record.source_id)
    if known_source != record.source_id:
        raise CaptureRecordError("source_order cannot change source_id")
    interface_key = (record.source_order, record.interface_ordinal)
    known_link = interface_links.setdefault(interface_key, record.link_type)
    if known_link != record.link_type:
        raise CaptureRecordError("logical interface link type is contradictory")
    local_key = (record.source_order, record.section_index, record.interface_id)
    known_ordinal = local_interface_ordinals.setdefault(local_key, record.interface_ordinal)
    if known_ordinal != record.interface_ordinal:
        raise CaptureRecordError("section-local interface metadata is contradictory")
    return key


def _frame(record: ExportPacketRecord) -> bytes:
    metadata = json.dumps(
        {
            "timestamp": record.timestamp.isoformat(),
            "source_id": record.source_id,
            "source_order": record.source_order,
            "packet_index": record.packet_index,
            "section_index": record.section_index,
            "interface_id": record.interface_id,
            "interface_ordinal": record.interface_ordinal,
            "link_type": record.link_type,
            "captured_length": record.captured_length,
            "original_length": record.original_length,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    payload = _FRAME_LENGTH.pack(len(metadata)) + metadata + record.packet_bytes
    if len(payload) > _MAX_FRAME_BYTES:
        raise CaptureRecordError("packet exceeds the maximum neutral frame size")
    return _FRAME_LENGTH.pack(len(payload)) + payload


def _read_exact(spool: Any, size: int) -> bytes:
    try:
        value = spool.read(size)
    except OSError as exc:
        raise CaptureStorageError("capture temporary storage operation failed") from exc
    if len(value) != size:
        raise CaptureStorageError("capture temporary storage operation failed")
    return value


def _read_frame(spool: Any) -> ExportPacketRecord | None:
    try:
        prefix = spool.read(_FRAME_LENGTH.size)
    except OSError as exc:
        raise CaptureStorageError("capture temporary storage operation failed") from exc
    if not prefix:
        return None
    if len(prefix) != _FRAME_LENGTH.size:
        raise CaptureStorageError("capture temporary storage operation failed")
    frame_length = _FRAME_LENGTH.unpack(prefix)[0]
    if frame_length < _FRAME_LENGTH.size or frame_length > _MAX_FRAME_BYTES:
        raise CaptureRecordError("malformed neutral capture frame")
    payload = _read_exact(spool, frame_length)
    metadata_length = _FRAME_LENGTH.unpack_from(payload)[0]
    metadata_end = _FRAME_LENGTH.size + metadata_length
    if metadata_length == 0 or metadata_end > len(payload):
        raise CaptureRecordError("malformed neutral capture frame")
    try:
        metadata = json.loads(payload[_FRAME_LENGTH.size : metadata_end])
        packet = payload[metadata_end:]
        return ExportPacketRecord(
            datetime.fromisoformat(metadata["timestamp"]),
            metadata["source_id"],
            metadata["source_order"],
            metadata["packet_index"],
            metadata["section_index"],
            metadata["interface_id"],
            metadata["interface_ordinal"],
            metadata["link_type"],
            packet,
            metadata["captured_length"],
            metadata["original_length"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CaptureRecordError("malformed neutral capture frame") from exc


def _write_spool(spool: Any, content: bytes) -> None:
    try:
        written = spool.write(content)
    except OSError as exc:
        raise CaptureStorageError("capture temporary storage operation failed") from exc
    if written != len(content):
        raise CaptureStorageError("capture temporary storage operation failed")


def build_capture_to_sink(
    records: Iterable[ExportPacketRecord],
    *,
    max_output_bytes: int,
    spool_max_memory_bytes: int,
    spool_directory: str | None = None,
) -> CaptureArtifact:
    """Consume matched records once, plan globally, then replay to a capped output spool."""
    if spool_max_memory_bytes <= 0:
        raise ValueError("spool_max_memory_bytes must be positive")
    output: CaptureSink | None = None
    neutral: Any = None
    try:
        output = CaptureSink(
            max_output_bytes=max_output_bytes,
            spool_max_memory_bytes=spool_max_memory_bytes,
            spool_directory=spool_directory,
        )
        try:
            neutral = tempfile.SpooledTemporaryFile(
                max_size=spool_max_memory_bytes, mode="w+b", dir=spool_directory
            )
        except OSError as exc:
            raise CaptureStorageError("capture temporary storage operation failed") from exc
        _write_spool(neutral, _SPOOL_MAGIC)
        previous_key: tuple[int, int] | None = None
        source_ids: dict[int, str] = {}
        interface_links: dict[tuple[int, int], int] = {}
        local_interface_ordinals: dict[tuple[int, int, int], int] = {}
        interface_snaplens: dict[tuple[int, int], int] = {}
        interface_min_timestamps: dict[tuple[int, int], float] = {}
        matched = 0
        classic_timestamps = True
        for record in records:
            if not isinstance(record, ExportPacketRecord):
                raise CaptureRecordError("capture writer requires ExportPacketRecord values")
            previous_key = _validate_export_record(
                record,
                previous_key,
                source_ids,
                interface_links,
                local_interface_ordinals,
            )
            interface_key = (record.source_order, record.interface_ordinal)
            interface_snaplens[interface_key] = max(
                interface_snaplens.get(interface_key, 0), record.captured_length
            )
            unix_timestamp = record.timestamp.timestamp()
            interface_min_timestamps[interface_key] = min(
                interface_min_timestamps.get(interface_key, unix_timestamp), unix_timestamp
            )
            seconds, _ = _timestamp_parts(record.timestamp)
            classic_timestamps = classic_timestamps and 0 <= seconds <= 0xFFFFFFFF
            _write_spool(neutral, _frame(record))
            matched += 1
        capture_format = "PCAP" if len(interface_links) <= 1 and classic_timestamps else "PCAPNG"
        try:
            neutral.flush()
            neutral.seek(0)
        except OSError as exc:
            raise CaptureStorageError("capture temporary storage operation failed") from exc
        if _read_exact(neutral, len(_SPOOL_MAGIC)) != _SPOOL_MAGIC:
            raise CaptureStorageError("capture temporary storage operation failed")

        exported = 0
        if capture_format == "PCAP":
            if max_output_bytes < 24:
                raise CaptureLimitTooSmall("output byte limit is too small for the PCAP header")
            link_type = next(iter(interface_links.values()), 1)
            snaplen = max(interface_snaplens.values(), default=65535)
            header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, link_type)
            if not output.write_unit(header):
                raise CaptureLimitTooSmall("output byte limit is too small for the PCAP header")
            while True:
                replay_record = _read_frame(neutral)
                if replay_record is None:
                    break
                seconds, microseconds = _timestamp_parts(replay_record.timestamp)
                unit = (
                    struct.pack(
                        "<IIII",
                        seconds,
                        microseconds,
                        replay_record.captured_length,
                        replay_record.original_length,
                    )
                    + replay_record.packet_bytes
                )
                if not output.write_unit(unit):
                    break
                exported += 1
        else:
            if max_output_bytes < 28:
                raise CaptureLimitTooSmall(
                    "output byte limit is too small for the PCAPNG section header"
                )
            section = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            if not output.write_unit(section):
                raise CaptureLimitTooSmall(
                    "output byte limit is too small for the PCAPNG section header"
                )
            offsets = {
                key: min(0, math.floor(value)) for key, value in interface_min_timestamps.items()
            }
            output_ids: dict[tuple[int, int], int] = {}
            while True:
                replay_record = _read_frame(neutral)
                if replay_record is None:
                    break
                key = (replay_record.source_order, replay_record.interface_ordinal)
                interface_block = b""
                output_id = output_ids.get(key, len(output_ids))
                if key not in output_ids:
                    options = b""
                    if offsets[key]:
                        options = struct.pack("<HHqHH", 14, 8, offsets[key], 0, 0)
                    interface_block = _block(
                        1,
                        struct.pack("<HHI", replay_record.link_type, 0, interface_snaplens[key])
                        + options,
                    )
                ticks = round((replay_record.timestamp.timestamp() - offsets[key]) * 1_000_000)
                if not 0 <= ticks <= 0xFFFFFFFFFFFFFFFF:
                    raise CaptureRecordError("packet timestamp exceeds the PCAPNG range")
                packet_block = _block(
                    6,
                    struct.pack(
                        "<IIIII",
                        output_id,
                        ticks >> 32,
                        ticks & 0xFFFFFFFF,
                        replay_record.captured_length,
                        replay_record.original_length,
                    )
                    + replay_record.packet_bytes,
                )
                if not output.write_unit(interface_block, packet_block):
                    break
                if interface_block:
                    output_ids[key] = output_id
                exported += 1
        neutral_to_close = neutral
        neutral = None
        try:
            neutral_to_close.close()
        except OSError as exc:
            raise CaptureStorageError("capture temporary storage operation failed") from exc
        artifact = CaptureArtifact(
            output.detach(),
            capture_format=capture_format,
            size_bytes=output.size_bytes,
            sha256=output.sha256,
            matched_packet_count=matched,
            exported_packet_count=exported,
        )
        output = None
        return artifact
    except BaseException:
        if neutral is not None:
            try:
                neutral.close()
            except BaseException:  # noqa: S110 -- preserve the primary failure
                pass
        if output is not None:
            try:
                output.close()
            except BaseException:  # noqa: S110 -- preserve the primary failure
                pass
        raise


def _legacy_record_to_export(record: Mapping[str, Any], index: int) -> ExportPacketRecord | None:
    raw_bytes = record.get("raw_packet_bytes")
    raw_hex = record.get("raw_packet_hex")
    if isinstance(raw_bytes, bytes):
        packet = raw_bytes
    elif raw_hex:
        packet = bytes.fromhex(str(raw_hex))
    else:
        return None
    timestamp_value = record["timestamp"]
    timestamp = (
        timestamp_value
        if isinstance(timestamp_value, datetime)
        else datetime.fromisoformat(str(timestamp_value))
    )
    source_order = int(record.get("raw_packet_source_order", 0))
    interface_ordinal = int(record.get("raw_packet_interface_id", 0))
    return ExportPacketRecord(
        timestamp,
        str(record.get("source_id") or f"legacy:{source_order}"),
        source_order,
        int(record.get("raw_packet_index", index)),
        int(record.get("section_index", 0)),
        int(record.get("raw_packet_interface_local_id", interface_ordinal)),
        interface_ordinal,
        int(record.get("raw_packet_link_type", 1)),
        packet,
        len(packet),
        int(record.get("raw_packet_original_length", len(packet))),
    )


def build_capture_result(
    records: list[dict[str, Any]], *, max_output_bytes: int | None = None
) -> CaptureBuildResult:
    converted = [
        converted
        for index, record in enumerate(records)
        if (converted := _legacy_record_to_export(record, index)) is not None
    ]
    # Legacy dictionaries treated link type as part of interface identity. Preserve
    # that oracle behavior while the typed Stage 6 API rejects contradictions.
    legacy_interfaces: dict[tuple[int, int, int], int] = {}
    converted = [
        replace(
            item,
            interface_id=legacy_interfaces.setdefault(
                (item.source_order, item.interface_ordinal, item.link_type),
                len(legacy_interfaces),
            ),
            interface_ordinal=legacy_interfaces.setdefault(
                (item.source_order, item.interface_ordinal, item.link_type),
                len(legacy_interfaces),
            ),
        )
        for item in converted
    ]
    # Compatibility accepted unordered dictionaries and canonicalized them.
    converted.sort(key=lambda item: (item.source_order, item.packet_index))
    limit = max_output_bytes if max_output_bytes is not None else (1 << 63) - 1
    with build_capture_to_sink(
        converted,
        max_output_bytes=limit,
        spool_max_memory_bytes=8 * 1024 * 1024,
    ) as artifact:
        return CaptureBuildResult(
            artifact.read_bytes(),
            artifact.capture_format,
            artifact.matched_packet_count,
            artifact.exported_packet_count,
            artifact.omitted_packet_count,
            artifact.truncated,
            artifact.truncation_reasons,
        )


def build_capture(
    records: list[dict[str, Any]], *, max_output_bytes: int | None = None
) -> tuple[bytes, int, str]:
    result = build_capture_result(records, max_output_bytes=max_output_bytes)
    if max_output_bytes is not None and result.truncated:
        raise ValueError("generated capture exceeds the output byte limit")
    return result.content, result.exported_packet_count, result.capture_format


def build_pcap(records: list[dict[str, Any]]) -> tuple[bytes, int]:
    content, count, _capture_format = build_capture(records)
    return content, count
