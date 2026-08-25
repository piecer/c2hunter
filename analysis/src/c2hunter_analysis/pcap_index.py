from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from .pcap import PcapParseError

PCAP_OFFSET_INDEX_SCHEMA_VERSION = 1
PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION = 1
_MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024
_MAX_I64 = (1 << 63) - 1
_CLASSIC_MAGIC: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"


class CaptureReader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


class StructuralIndexError(Exception):
    pass


class StructuralIndexLimitError(StructuralIndexError):
    pass


@dataclass(frozen=True)
class StructuralInterfaceEntry:
    section_index: int
    interface_id: int
    interface_ordinal: int
    link_type: int
    snaplen: int
    timestamp_resolution_numerator: int
    timestamp_resolution_denominator: int
    timestamp_offset_seconds: int


@dataclass(frozen=True)
class StructuralPacketEntry:
    packet_index: int
    record_offset: int
    data_offset: int
    captured_length: int
    original_length: int
    framed_length: int
    section_index: int
    interface_id: int
    interface_ordinal: int
    raw_timestamp_ticks: int


@dataclass(frozen=True)
class StructuralScanResult:
    capture_format: Literal["PCAP", "PCAPNG"]
    size_bytes: int
    sha256: str
    interfaces: tuple[StructuralInterfaceEntry, ...]
    packets: tuple[StructuralPacketEntry, ...]
    packet_count: int


class _Cursor:
    def __init__(self, reader: CaptureReader) -> None:
        self.reader = reader
        self.offset = 0
        self.digest = hashlib.sha256()

    def read_exact(self, size: int, *, eof_ok: bool = False) -> bytes:
        if size < 0:
            raise ValueError("read size must be non-negative")
        result = bytearray()
        while len(result) < size:
            part = self.reader.read(size - len(result))
            if not part:
                if eof_ok and not result:
                    return b""
                raise EOFError
            if len(part) > size - len(result):
                raise PcapParseError("capture reader returned more bytes than requested")
            result.extend(part)
            self.offset += len(part)
            self.digest.update(part)
            if self.offset > _MAX_I64:
                raise StructuralIndexLimitError("capture offset exceeds structural index range")
        return bytes(result)

    def discard_exact(self, size: int) -> None:
        while size:
            chunk = min(size, 64 * 1024)
            self.read_exact(chunk)
            size -= chunk


PacketBatchConsumer = Callable[[tuple[StructuralPacketEntry, ...]], None]


def scan_structural_packet_index(
    reader: CaptureReader,
    *,
    max_packets: int,
    max_interfaces: int,
    batch_size: int = 1_000,
    consume_packet_batch: PacketBatchConsumer | None = None,
) -> StructuralScanResult:
    """Strictly scan one complete capture using only positively bounded reads.

    Supplying ``consume_packet_batch`` keeps packet memory bounded to ``batch_size``;
    the returned packet tuple is then empty while ``packet_count`` remains exact.
    """
    if max_packets <= 0 or max_interfaces <= 0 or batch_size <= 0:
        raise ValueError("structural index limits must be positive")
    cursor = _Cursor(reader)
    try:
        magic = cursor.read_exact(4)
    except EOFError as exc:
        raise PcapParseError("file is not a classic PCAP or PCAPNG capture") from exc
    if magic in _CLASSIC_MAGIC:
        capture_format: Literal["PCAP", "PCAPNG"] = "PCAP"
        interfaces, packets, packet_count = _scan_classic(
            cursor, magic, max_packets, max_interfaces, batch_size, consume_packet_batch
        )
    elif magic == _PCAPNG_SECTION:
        capture_format = "PCAPNG"
        interfaces, packets, packet_count = _scan_pcapng(
            cursor, magic, max_packets, max_interfaces, batch_size, consume_packet_batch
        )
    else:
        raise PcapParseError("file is not a classic PCAP or PCAPNG capture")
    return StructuralScanResult(
        capture_format,
        cursor.offset,
        cursor.digest.hexdigest(),
        tuple(interfaces),
        tuple(packets),
        packet_count,
    )


def _emit(
    packet: StructuralPacketEntry,
    batch: list[StructuralPacketEntry],
    retained: list[StructuralPacketEntry],
    batch_size: int,
    consumer: PacketBatchConsumer | None,
) -> None:
    if consumer is None:
        retained.append(packet)
        return
    batch.append(packet)
    if len(batch) >= batch_size:
        consumer(tuple(batch))
        batch.clear()


def _finish_batch(batch: list[StructuralPacketEntry], consumer: PacketBatchConsumer | None) -> None:
    if batch and consumer is not None:
        consumer(tuple(batch))
        batch.clear()


def _scan_classic(
    cursor: _Cursor,
    magic: bytes,
    max_packets: int,
    max_interfaces: int,
    batch_size: int,
    consumer: PacketBatchConsumer | None,
) -> tuple[list[StructuralInterfaceEntry], list[StructuralPacketEntry], int]:
    try:
        header = cursor.read_exact(20)
    except EOFError as exc:
        raise PcapParseError("classic PCAP global header is truncated") from exc
    endian, resolution = _CLASSIC_MAGIC[magic]
    major, minor, _zone, _accuracy, snaplen, link_type = struct.unpack(f"{endian}HHIIII", header)
    if major != 2 or minor != 4:
        raise PcapParseError(f"unsupported classic PCAP version {major}.{minor}")
    if snaplen < 1 or snaplen > _MAX_CAPTURED_PACKET_BYTES:
        raise PcapParseError("classic PCAP snap length is invalid")
    if max_interfaces < 1:
        raise StructuralIndexLimitError("structural interface limit exceeded")
    interfaces = [StructuralInterfaceEntry(0, 0, 0, link_type & 0xFFFF, snaplen, 1, resolution, 0)]
    retained: list[StructuralPacketEntry] = []
    batch: list[StructuralPacketEntry] = []
    count = 0
    while True:
        record_offset = cursor.offset
        try:
            packet_header = cursor.read_exact(16, eof_ok=True)
        except EOFError as exc:
            raise PcapParseError("classic PCAP packet header is truncated") from exc
        if not packet_header:
            if count == 0:
                raise PcapParseError("capture does not contain timestamped packets", "EMPTY_PCAP")
            _finish_batch(batch, consumer)
            return interfaces, retained, count
        seconds, fraction, captured_length, original_length = struct.unpack(
            f"{endian}IIII", packet_header
        )
        if captured_length > _MAX_CAPTURED_PACKET_BYTES:
            raise PcapParseError("classic PCAP packet data is truncated or oversized")
        try:
            cursor.discard_exact(captured_length)
        except EOFError as exc:
            raise PcapParseError("classic PCAP packet data is truncated or oversized") from exc
        if captured_length > original_length or captured_length > snaplen:
            raise PcapParseError(
                "classic PCAP packet length exceeds original length or snap length"
            )
        if count >= max_packets:
            raise StructuralIndexLimitError("structural packet limit exceeded")
        packet = StructuralPacketEntry(
            count,
            record_offset,
            record_offset + 16,
            captured_length,
            original_length,
            16 + captured_length,
            0,
            0,
            0,
            seconds * resolution + fraction,
        )
        _emit(packet, batch, retained, batch_size, consumer)
        count += 1


def _validate_ng_length(block_length: int) -> None:
    if block_length < 12 or block_length % 4:
        raise PcapParseError("PCAPNG block length is invalid")


def _validate_ng_trailer(trailer: bytes, block_length: int, endian: str) -> None:
    if struct.unpack(f"{endian}I", trailer)[0] != block_length:
        raise PcapParseError("PCAPNG block length trailer does not match")


def _read_ng_options(
    cursor: _Cursor, size: int, endian: str
) -> tuple[int, int, int, PcapParseError | None]:
    numerator, denominator, timestamp_offset = 1, 1_000_000, 0
    error: PcapParseError | None = None
    remaining = size
    while remaining:
        if remaining < 4:
            cursor.discard_exact(remaining)
            return (
                numerator,
                denominator,
                timestamp_offset,
                PcapParseError("PCAPNG interface option is truncated"),
            )
        header = cursor.read_exact(4)
        remaining -= 4
        code, length = struct.unpack(f"{endian}HH", header)
        if code == 0:
            cursor.discard_exact(remaining)
            break
        padded = (length + 3) & ~3
        if padded > remaining:
            cursor.discard_exact(remaining)
            return (
                numerator,
                denominator,
                timestamp_offset,
                PcapParseError("PCAPNG interface option is truncated"),
            )
        if code == 9 and length == 1:
            exponent = cursor.read_exact(1)[0]
            denominator = 2 ** (exponent & 0x7F) if exponent & 0x80 else 10**exponent
            cursor.discard_exact(padded - 1)
        elif code == 14 and length == 8:
            timestamp_offset = struct.unpack(f"{endian}q", cursor.read_exact(8))[0]
            cursor.discard_exact(padded - 8)
        else:
            cursor.discard_exact(padded)
        remaining -= padded
    return numerator, denominator, timestamp_offset, error


def _scan_pcapng(
    cursor: _Cursor,
    magic: bytes,
    max_packets: int,
    max_interfaces: int,
    batch_size: int,
    consumer: PacketBatchConsumer | None,
) -> tuple[list[StructuralInterfaceEntry], list[StructuralPacketEntry], int]:
    endian = "<"
    section_interfaces: list[StructuralInterfaceEntry] = []
    all_interfaces: list[StructuralInterfaceEntry] = []
    retained: list[StructuralPacketEntry] = []
    batch: list[StructuralPacketEntry] = []
    section_index = -1
    count = 0
    first = True
    while True:
        record_offset = cursor.offset - (4 if first else 0)
        try:
            if first:
                block_prefix = magic + cursor.read_exact(8)
                first = False
            else:
                block_prefix = cursor.read_exact(12, eof_ok=True)
        except EOFError as exc:
            raise PcapParseError("PCAPNG block header is truncated") from exc
        if not block_prefix:
            if count == 0:
                raise PcapParseError("capture does not contain timestamped packets", "EMPTY_PCAP")
            _finish_batch(batch, consumer)
            return all_interfaces, retained, count
        is_section = block_prefix[:4] == _PCAPNG_SECTION
        if is_section:
            bom = block_prefix[8:12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise PcapParseError("PCAPNG section has an invalid byte-order magic")
            block_length = struct.unpack(f"{endian}I", block_prefix[4:8])[0]
            _validate_ng_length(block_length)
            try:
                if block_length == 12:
                    trailer = block_prefix[8:12]
                else:
                    cursor.discard_exact(block_length - 16)
                    trailer = cursor.read_exact(4)
            except EOFError as exc:
                raise PcapParseError("PCAPNG block length is invalid") from exc
            _validate_ng_trailer(trailer, block_length, endian)
            section_index += 1
            section_interfaces = []
            continue
        semantic_error = (
            PcapParseError("PCAPNG data appears before a section header")
            if section_index < 0
            else None
        )
        block_type, block_length = struct.unpack(f"{endian}II", block_prefix[:8])
        _validate_ng_length(block_length)
        body_length = block_length - 12
        body_prefix = block_prefix[8:12] if body_length else b""
        try:
            if block_type == 1:
                if body_length < 8:
                    if body_length:
                        cursor.discard_exact(body_length - 4)
                    values = None
                    option_error = None
                else:
                    fixed = body_prefix + cursor.read_exact(4)
                    link_type = struct.unpack_from(f"{endian}H", fixed)[0]
                    snaplen = struct.unpack_from(f"{endian}I", fixed, 4)[0]
                    numerator, denominator, timestamp_offset, option_error = _read_ng_options(
                        cursor, body_length - 8, endian
                    )
                    values = (link_type, snaplen, numerator, denominator, timestamp_offset)
                trailer = block_prefix[8:12] if body_length == 0 else cursor.read_exact(4)
                _validate_ng_trailer(trailer, block_length, endian)
                if semantic_error is not None:
                    raise semantic_error
                if values is None:
                    raise PcapParseError("PCAPNG interface block is truncated")
                link_type, snaplen, numerator, denominator, timestamp_offset = values
                if snaplen < 1 or snaplen > _MAX_CAPTURED_PACKET_BYTES:
                    raise PcapParseError("PCAPNG interface snap length is invalid")
                if option_error is not None:
                    raise option_error
                if len(all_interfaces) >= max_interfaces:
                    raise StructuralIndexLimitError("structural interface limit exceeded")
                interface = StructuralInterfaceEntry(
                    section_index,
                    len(section_interfaces),
                    len(all_interfaces),
                    link_type,
                    snaplen,
                    numerator,
                    denominator,
                    timestamp_offset,
                )
                section_interfaces.append(interface)
                all_interfaces.append(interface)
                continue
            if block_type in {2, 6}:
                if body_length < 20:
                    if body_length:
                        cursor.discard_exact(body_length - 4)
                    values = None
                else:
                    fixed = body_prefix + cursor.read_exact(16)
                    if block_type == 6:
                        values = struct.unpack(f"{endian}IIIII", fixed)
                    else:
                        interface_id, _drops, high, low, caplen, origlen = struct.unpack(
                            f"{endian}HHIIII", fixed
                        )
                        values = (interface_id, high, low, caplen, origlen)
                    caplen = values[3]
                    padded = (caplen + 3) & ~3
                    available = body_length - 20
                    if caplen <= _MAX_CAPTURED_PACKET_BYTES and padded <= available:
                        cursor.discard_exact(caplen)
                        cursor.discard_exact(available - caplen)
                    else:
                        cursor.discard_exact(available)
                trailer = block_prefix[8:12] if body_length == 0 else cursor.read_exact(4)
                _validate_ng_trailer(trailer, block_length, endian)
                if semantic_error is not None:
                    raise semantic_error
                if values is None:
                    raise PcapParseError("PCAPNG packet block is truncated")
                interface_id, high, low, caplen, origlen = values
                if interface_id >= len(section_interfaces):
                    raise PcapParseError("PCAPNG packet references an unknown interface")
                padded = (caplen + 3) & ~3
                if caplen > _MAX_CAPTURED_PACKET_BYTES or padded > body_length - 20:
                    raise PcapParseError("PCAPNG packet data is truncated or oversized")
                interface = section_interfaces[interface_id]
                if caplen > origlen or caplen > interface.snaplen:
                    raise PcapParseError(
                        "PCAPNG packet length exceeds original length or interface snap length"
                    )
                if count >= max_packets:
                    raise StructuralIndexLimitError("structural packet limit exceeded")
                packet = StructuralPacketEntry(
                    count,
                    record_offset,
                    record_offset + 28,
                    caplen,
                    origlen,
                    block_length,
                    section_index,
                    interface_id,
                    interface.interface_ordinal,
                    (high << 32) | low,
                )
                _emit(packet, batch, retained, batch_size, consumer)
                count += 1
                continue
            if block_type == 3:
                if body_length:
                    cursor.discard_exact(body_length - 4)
                trailer = block_prefix[8:12] if body_length == 0 else cursor.read_exact(4)
                _validate_ng_trailer(trailer, block_length, endian)
                if semantic_error is not None:
                    raise semantic_error
                raise PcapParseError(
                    "PCAPNG simple packet blocks have no timestamp and are not supported",
                    "UNSUPPORTED_PCAPNG_BLOCK",
                )
            if body_length:
                cursor.discard_exact(body_length - 4)
            trailer = block_prefix[8:12] if body_length == 0 else cursor.read_exact(4)
            _validate_ng_trailer(trailer, block_length, endian)
            if semantic_error is not None:
                raise semantic_error
        except EOFError as exc:
            raise PcapParseError("PCAPNG block length is invalid") from exc
