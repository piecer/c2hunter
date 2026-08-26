from __future__ import annotations

import struct
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Literal, Protocol

from .pcap import PcapParseError

CaptureFormat = Literal["PCAP", "PCAPNG"]
Direction = Literal["INBOUND", "OUTBOUND", "UNKNOWN"]
Network = IPv4Network | IPv6Network

_CLASSIC_MAGIC: dict[bytes, tuple[str, int]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024


class CaptureReader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


@dataclass(frozen=True)
class PacketLocator:
    source_id: str
    source_order: int
    packet_index: int
    record_offset: int
    data_offset: int
    captured_length: int
    framed_length: int


@dataclass(frozen=True)
class CaptureInterface:
    section_index: int
    interface_id: int
    interface_ordinal: int
    link_type: int
    snaplen: int
    timestamp_resolution_numerator: int
    timestamp_resolution_denominator: int
    timestamp_offset_seconds: int


@dataclass(frozen=True)
class ExportPacket:
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    direction: Direction | None
    has_payload: bool | None
    supported: bool
    raw_packet_bytes: bytes
    locator: PacketLocator
    interface: CaptureInterface
    original_length: int


class _StreamCursor:
    def __init__(self, reader: CaptureReader, prefix: bytes = b"") -> None:
        self.reader = reader
        self.offset = len(prefix)
        self._prefix = prefix

    def read_exact(self, size: int, *, eof_ok: bool = False) -> bytes:
        result = bytearray()
        remaining = size
        if self._prefix:
            part = self._prefix[:remaining]
            self._prefix = self._prefix[len(part) :]
            result.extend(part)
            remaining -= len(part)
        while remaining:
            part = self.reader.read(remaining)
            if not part:
                if eof_ok and remaining == size:
                    return b""
                raise EOFError
            if len(part) > remaining:
                raise PcapParseError("capture reader returned more bytes than requested")
            result.extend(part)
            remaining -= len(part)
            self.offset += len(part)
        return bytes(result)

    def discard_exact(self, size: int) -> None:
        while size:
            chunk = min(size, 64 * 1024)
            self.read_exact(chunk)
            size -= chunk


class ExportCaptureDecoder:
    def __init__(
        self,
        cursor: _StreamCursor,
        capture_format: CaptureFormat,
        *,
        source_id: str,
        source_order: int,
        networks: tuple[Network, ...],
    ) -> None:
        self._cursor = cursor
        self._capture_format = capture_format
        self._source_id = source_id
        self._source_order = source_order
        self._networks = networks
        self._started = False

    @property
    def capture_format(self) -> CaptureFormat:
        return self._capture_format

    def iter_packets(self) -> Iterator[ExportPacket]:
        if self._started:
            raise RuntimeError("capture packets can only be iterated once")
        self._started = True
        return self._iter_classic() if self._capture_format == "PCAP" else self._iter_pcapng()

    def _iter_classic(self) -> Iterator[ExportPacket]:
        try:
            header = self._cursor.read_exact(20)
        except EOFError as exc:
            raise PcapParseError("classic PCAP global header is truncated") from exc
        endian, resolution = _CLASSIC_MAGIC[header[:0] or self._magic]
        major, minor, _zone, _accuracy, snaplen, link_type = struct.unpack(
            f"{endian}HHIIII", header
        )
        if major != 2 or minor != 4:
            raise PcapParseError(f"unsupported classic PCAP version {major}.{minor}")
        if snaplen < 1 or snaplen > _MAX_CAPTURED_PACKET_BYTES:
            raise PcapParseError("classic PCAP snap length is invalid")
        interface = CaptureInterface(0, 0, 0, link_type & 0xFFFF, snaplen, 1, resolution, 0)
        count = 0
        while True:
            record_offset = self._cursor.offset
            try:
                packet_header = self._cursor.read_exact(16, eof_ok=True)
            except EOFError as exc:
                raise PcapParseError("classic PCAP packet header is truncated") from exc
            if not packet_header:
                if count == 0:
                    raise PcapParseError(
                        "capture does not contain timestamped packets", "EMPTY_PCAP"
                    )
                return
            seconds, fraction, captured_length, original_length = struct.unpack(
                f"{endian}IIII", packet_header
            )
            if captured_length > _MAX_CAPTURED_PACKET_BYTES:
                raise PcapParseError("classic PCAP packet data is truncated or oversized")
            try:
                raw = self._cursor.read_exact(captured_length)
            except EOFError as exc:
                raise PcapParseError("classic PCAP packet data is truncated or oversized") from exc
            if captured_length > original_length or captured_length > snaplen:
                raise PcapParseError(
                    "classic PCAP packet length exceeds original length or snap length"
                )
            timestamp = export_timestamp_from_ticks(
                seconds * resolution + fraction,
                numerator=1,
                denominator=resolution,
                offset_seconds=0,
                classic_seconds=seconds,
                classic_fraction=fraction,
            )
            projection = project_export_packet(
                raw, link_type=interface.link_type, internal_networks=self._networks
            )
            locator = PacketLocator(
                self._source_id,
                self._source_order,
                count,
                record_offset,
                record_offset + 16,
                captured_length,
                16 + captured_length,
            )
            count += 1
            yield ExportPacket(
                timestamp,
                *projection,
                raw,
                locator,
                interface,
                original_length,
            )

    _magic: bytes

    def _iter_pcapng(self) -> Iterator[ExportPacket]:
        endian = "<"
        interfaces: list[tuple[CaptureInterface, float]] = []
        section_index = -1
        next_interface_ordinal = 0
        count = 0
        first = True
        while True:
            record_offset = self._cursor.offset - (4 if first else 0)
            try:
                if first:
                    rest = self._cursor.read_exact(8)
                    block_prefix = self._magic + rest
                    first = False
                else:
                    block_prefix = self._cursor.read_exact(12, eof_ok=True)
            except EOFError as exc:
                raise PcapParseError("PCAPNG block header is truncated") from exc
            if not block_prefix:
                if count == 0:
                    raise PcapParseError(
                        "capture does not contain timestamped packets", "EMPTY_PCAP"
                    )
                return
            is_section = block_prefix[:4] == _PCAPNG_SECTION
            if is_section:
                byte_order_magic = block_prefix[8:12]
                if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise PcapParseError("PCAPNG section has an invalid byte-order magic")
                block_length = struct.unpack(f"{endian}I", block_prefix[4:8])[0]
                self._validate_ng_length(block_length)
                try:
                    if block_length == 12:
                        trailer = block_prefix[8:12]
                    else:
                        self._cursor.discard_exact(block_length - 16)
                        trailer = self._cursor.read_exact(4)
                except EOFError as exc:
                    raise PcapParseError("PCAPNG block length is invalid") from exc
                self._validate_ng_trailer(trailer, block_length, endian)
                section_index += 1
                interfaces = []
                continue
            if section_index < 0:
                semantic_error = PcapParseError("PCAPNG data appears before a section header")
            else:
                semantic_error = None
            block_type, block_length = struct.unpack(f"{endian}II", block_prefix[:8])
            self._validate_ng_length(block_length)
            body_length = block_length - 12
            body_prefix = block_prefix[8:12] if body_length else b""
            try:
                if block_type == 1:
                    if body_length < 8:
                        if body_length:
                            self._cursor.discard_exact(body_length - 4)
                        interface_values = None
                        option_error = None
                    else:
                        fixed = body_prefix + self._cursor.read_exact(4)
                        link_type = struct.unpack_from(f"{endian}H", fixed)[0]
                        snaplen = struct.unpack_from(f"{endian}I", fixed, 4)[0]
                        options, option_error = self._read_ng_options(body_length - 8, endian)
                        numerator, denominator, resolution, timestamp_offset = options
                        interface_values = (
                            link_type,
                            snaplen,
                            numerator,
                            denominator,
                            resolution,
                            timestamp_offset,
                        )
                    trailer = block_prefix[8:12] if body_length == 0 else self._cursor.read_exact(4)
                    self._validate_ng_trailer(trailer, block_length, endian)
                    if semantic_error is not None:
                        raise semantic_error
                    if interface_values is None:
                        raise PcapParseError("PCAPNG interface block is truncated")
                    link_type, snaplen, numerator, denominator, resolution, timestamp_offset = (
                        interface_values
                    )
                    if snaplen < 1 or snaplen > _MAX_CAPTURED_PACKET_BYTES:
                        raise PcapParseError("PCAPNG interface snap length is invalid")
                    if option_error is not None:
                        raise option_error
                    interfaces.append(
                        (
                            CaptureInterface(
                                section_index,
                                len(interfaces),
                                next_interface_ordinal,
                                link_type,
                                snaplen,
                                numerator,
                                denominator,
                                timestamp_offset,
                            ),
                            resolution,
                        )
                    )
                    next_interface_ordinal += 1
                    continue
                if block_type in {2, 6}:
                    if body_length < 20:
                        if body_length:
                            self._cursor.discard_exact(body_length - 4)
                        packet_values = None
                        raw = b""
                    else:
                        fixed = body_prefix + self._cursor.read_exact(16)
                        if block_type == 6:
                            packet_values = struct.unpack(f"{endian}IIIII", fixed)
                        else:
                            interface_id, _drops, high, low, captured_length, original_length = (
                                struct.unpack(f"{endian}HHIIII", fixed)
                            )
                            packet_values = (
                                interface_id,
                                high,
                                low,
                                captured_length,
                                original_length,
                            )
                        captured_length = packet_values[3]
                        padded_length = (captured_length + 3) & ~3
                        available = body_length - 20
                        if (
                            captured_length <= _MAX_CAPTURED_PACKET_BYTES
                            and padded_length <= available
                        ):
                            raw = self._cursor.read_exact(captured_length)
                            self._cursor.discard_exact(available - captured_length)
                        else:
                            raw = b""
                            self._cursor.discard_exact(available)
                    trailer = block_prefix[8:12] if body_length == 0 else self._cursor.read_exact(4)
                    self._validate_ng_trailer(trailer, block_length, endian)
                    if semantic_error is not None:
                        raise semantic_error
                    if packet_values is None:
                        raise PcapParseError("PCAPNG packet block is truncated")
                    interface_id, high, low, captured_length, original_length = packet_values
                    if interface_id >= len(interfaces):
                        raise PcapParseError("PCAPNG packet references an unknown interface")
                    padded_length = (captured_length + 3) & ~3
                    if (
                        captured_length > _MAX_CAPTURED_PACKET_BYTES
                        or padded_length > body_length - 20
                    ):
                        raise PcapParseError("PCAPNG packet data is truncated or oversized")
                    interface, _timestamp_resolution = interfaces[interface_id]
                    if captured_length > original_length or captured_length > interface.snaplen:
                        raise PcapParseError(
                            "PCAPNG packet length exceeds original length or interface snap length"
                        )
                    raw_timestamp = (high << 32) | low
                    projection = project_export_packet(
                        raw, link_type=interface.link_type, internal_networks=self._networks
                    )
                    locator = PacketLocator(
                        self._source_id,
                        self._source_order,
                        count,
                        record_offset,
                        record_offset + 28,
                        captured_length,
                        block_length,
                    )
                    count += 1
                    yield ExportPacket(
                        export_timestamp_from_ticks(
                            raw_timestamp,
                            numerator=interface.timestamp_resolution_numerator,
                            denominator=interface.timestamp_resolution_denominator,
                            offset_seconds=interface.timestamp_offset_seconds,
                        ),
                        *projection,
                        raw,
                        locator,
                        interface,
                        original_length,
                    )
                    continue
                if block_type == 3:
                    if body_length:
                        self._cursor.discard_exact(body_length - 4)
                    trailer = block_prefix[8:12] if body_length == 0 else self._cursor.read_exact(4)
                    self._validate_ng_trailer(trailer, block_length, endian)
                    if semantic_error is not None:
                        raise semantic_error
                    raise PcapParseError(
                        "PCAPNG simple packet blocks have no timestamp and are not supported",
                        "UNSUPPORTED_PCAPNG_BLOCK",
                    )
                if body_length:
                    self._cursor.discard_exact(body_length - 4)
                trailer = block_prefix[8:12] if body_length == 0 else self._cursor.read_exact(4)
                self._validate_ng_trailer(trailer, block_length, endian)
                if semantic_error is not None:
                    raise semantic_error
            except EOFError as exc:
                raise PcapParseError("PCAPNG block length is invalid") from exc

    @staticmethod
    def _validate_ng_length(block_length: int, minimum: int = 12) -> None:
        if block_length < minimum or block_length % 4:
            raise PcapParseError("PCAPNG block length is invalid")

    @staticmethod
    def _validate_ng_trailer(trailer: bytes, block_length: int, endian: str) -> None:
        if struct.unpack(f"{endian}I", trailer)[0] != block_length:
            raise PcapParseError("PCAPNG block length trailer does not match")

    def _read_ng_options(
        self, size: int, endian: str
    ) -> tuple[tuple[int, int, float, int], PcapParseError | None]:
        numerator, denominator, resolution, timestamp_offset = 1, 1_000_000, 0.000001, 0
        error: PcapParseError | None = None
        remaining = size
        while remaining:
            if remaining < 4:
                self._cursor.discard_exact(remaining)
                error = PcapParseError("PCAPNG interface option is truncated")
                break
            header = self._cursor.read_exact(4)
            remaining -= 4
            code, length = struct.unpack(f"{endian}HH", header)
            if code == 0:
                self._cursor.discard_exact(remaining)
                break
            padded = (length + 3) & ~3
            if padded > remaining:
                self._cursor.discard_exact(remaining)
                error = PcapParseError("PCAPNG interface option is truncated")
                break
            if code == 9 and length == 1:
                exponent = self._cursor.read_exact(1)[0]
                if exponent & 0x80:
                    denominator = 2 ** (exponent & 0x7F)
                    resolution = 2.0 ** -(exponent & 0x7F)
                else:
                    denominator = 10**exponent
                    resolution = 10.0**-exponent
                self._cursor.discard_exact(padded - 1)
            elif code == 14 and length == 8:
                timestamp_offset = struct.unpack(f"{endian}q", self._cursor.read_exact(8))[0]
                self._cursor.discard_exact(padded - 8)
            else:
                self._cursor.discard_exact(padded)
            remaining -= padded
        return (numerator, denominator, resolution, timestamp_offset), error


def open_export_capture(
    reader: CaptureReader,
    *,
    source_id: str,
    source_order: int,
    internal_networks: Sequence[str],
) -> ExportCaptureDecoder:
    networks = _networks(internal_networks)
    cursor = _StreamCursor(reader)
    try:
        magic = cursor.read_exact(4)
    except EOFError as exc:
        raise PcapParseError("file is not a classic PCAP or PCAPNG capture") from exc
    if magic not in _CLASSIC_MAGIC and magic != _PCAPNG_SECTION:
        raise PcapParseError("file is not a classic PCAP or PCAPNG capture")
    decoder = ExportCaptureDecoder(
        cursor,
        "PCAP" if magic in _CLASSIC_MAGIC else "PCAPNG",
        source_id=source_id,
        source_order=source_order,
        networks=networks,
    )
    decoder._magic = magic
    return decoder


def _networks(values: Sequence[str]) -> tuple[Network, ...]:
    try:
        networks = tuple(ip_network(value, strict=False) for value in values)
    except ValueError as exc:
        raise PcapParseError(
            f"invalid internal network: {exc}", "INVALID_INTERNAL_NETWORK"
        ) from exc
    if not networks:
        raise PcapParseError(
            "at least one internal network is required", "INVALID_INTERNAL_NETWORK"
        )
    return networks


def _timestamp(seconds: float) -> datetime:
    try:
        return datetime.fromtimestamp(seconds, UTC)
    except (OverflowError, OSError, ValueError) as exc:
        raise PcapParseError("capture contains an invalid packet timestamp") from exc


PacketProjection = tuple[
    str | None,
    str | None,
    int | None,
    int | None,
    str | None,
    Direction | None,
    bool | None,
    bool,
]


def export_timestamp_from_ticks(
    raw_ticks: int,
    *,
    numerator: int,
    denominator: int,
    offset_seconds: int,
    classic_seconds: int | None = None,
    classic_fraction: int | None = None,
) -> datetime:
    """Convert structural timestamp metadata with sequential float semantics."""
    if (
        raw_ticks < 0
        or numerator <= 0
        or denominator <= 0
        or (classic_seconds is None) != (classic_fraction is None)
        or (classic_seconds is not None and classic_seconds < 0)
        or (classic_fraction is not None and classic_fraction < 0)
    ):
        raise PcapParseError("capture contains invalid structural timestamp metadata")
    if classic_seconds is not None and classic_fraction is not None:
        if numerator != 1:
            raise PcapParseError("capture contains invalid structural timestamp metadata")
        return _timestamp(classic_seconds + classic_fraction / denominator + offset_seconds)
    return _timestamp(raw_ticks * (numerator / denominator) + offset_seconds)


def project_export_packet(
    raw_packet_bytes: bytes,
    *,
    link_type: int,
    internal_networks: Sequence[str] | tuple[Network, ...],
) -> PacketProjection:
    """Project one packet through the same decoder used by sequential export."""
    networks = (
        internal_networks
        if all(isinstance(item, IPv4Network | IPv6Network) for item in internal_networks)
        else _networks(internal_networks)  # type: ignore[arg-type]
    )
    return _project(raw_packet_bytes, link_type, networks)  # type: ignore[arg-type]


def export_packet_from_structural_locator(
    raw_packet_bytes: bytes,
    *,
    locator: PacketLocator,
    interface: CaptureInterface,
    original_length: int,
    raw_timestamp_ticks: int,
    internal_networks: Sequence[str] | tuple[Network, ...],
) -> ExportPacket:
    """Reconstruct the existing export packet shape from trusted structural metadata."""
    if type(raw_packet_bytes) is not bytes or len(raw_packet_bytes) != locator.captured_length:
        raise PcapParseError("selected packet bytes do not match structural captured length")
    if (
        locator.captured_length < 0
        or original_length < locator.captured_length
        or locator.captured_length > interface.snaplen
    ):
        raise PcapParseError("selected packet structural lengths are invalid")
    projection = project_export_packet(
        raw_packet_bytes,
        link_type=interface.link_type,
        internal_networks=internal_networks,
    )
    timestamp_kwargs: dict[str, int] = {}
    if (
        locator.data_offset == locator.record_offset + 16
        and locator.framed_length == 16 + locator.captured_length
    ):
        seconds, fraction = divmod(raw_timestamp_ticks, interface.timestamp_resolution_denominator)
        timestamp_kwargs = {"classic_seconds": seconds, "classic_fraction": fraction}
    return ExportPacket(
        export_timestamp_from_ticks(
            raw_timestamp_ticks,
            numerator=interface.timestamp_resolution_numerator,
            denominator=interface.timestamp_resolution_denominator,
            offset_seconds=interface.timestamp_offset_seconds,
            **timestamp_kwargs,
        ),
        *projection,
        raw_packet_bytes,
        locator,
        interface,
        original_length,
    )


def _project(
    packet: bytes, link_type: int, networks: tuple[Network, ...]
) -> tuple[
    str | None, str | None, int | None, int | None, str | None, Direction | None, bool | None, bool
]:
    network = _network_packet(packet, link_type)
    if network is None:
        return None, None, None, None, None, None, None, False
    version, raw = network
    decoded = _decode_ipv4(raw) if version == 4 else _decode_ipv6(raw)
    if decoded is None:
        return None, None, None, None, None, None, None, False
    source, destination, source_port, destination_port, protocol, payload = decoded
    return (
        source,
        destination,
        source_port,
        destination_port,
        protocol,
        _direction(source, destination, networks),
        bool(payload),
        True,
    )


def _network_packet(packet: bytes, link_type: int) -> tuple[int, bytes] | None:
    if link_type == 1:
        if len(packet) < 14:
            return None
        protocol = int.from_bytes(packet[12:14], "big")
        offset = 14
        for _ in range(2):
            if protocol not in {0x8100, 0x88A8, 0x9100}:
                break
            if len(packet) < offset + 4:
                return None
            protocol = int.from_bytes(packet[offset + 2 : offset + 4], "big")
            offset += 4
        return _ethertype_payload(protocol, packet[offset:])
    if link_type in {12, 101}:
        return _raw_ip(packet)
    if link_type == 228:
        return (4, packet) if packet and packet[0] >> 4 == 4 else None
    if link_type == 229:
        return (6, packet) if packet and packet[0] >> 4 == 6 else None
    if link_type == 113:
        if len(packet) < 16:
            return None
        return _ethertype_payload(int.from_bytes(packet[14:16], "big"), packet[16:])
    if link_type == 276:
        if len(packet) < 20:
            return None
        return _ethertype_payload(int.from_bytes(packet[0:2], "big"), packet[20:])
    if link_type in {0, 108}:
        if len(packet) < 4:
            return None
        families = {int.from_bytes(packet[:4], "little"), int.from_bytes(packet[:4], "big")}
        if 2 in families:
            return 4, packet[4:]
        if families & {10, 24, 28, 30}:
            return 6, packet[4:]
    return None


def _ethertype_payload(protocol: int, payload: bytes) -> tuple[int, bytes] | None:
    if protocol == 0x0800:
        return 4, payload
    if protocol == 0x86DD:
        return 6, payload
    return None


def _raw_ip(packet: bytes) -> tuple[int, bytes] | None:
    if not packet:
        return None
    version = packet[0] >> 4
    return (version, packet) if version in {4, 6} else None


def _decode_ipv4(packet: bytes) -> tuple[str, str, int | None, int | None, str, bytes] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if header_length < 20 or total_length < header_length or len(packet) < header_length:
        return None
    end = min(len(packet), total_length)
    protocol_number = packet[9]
    first_fragment = (int.from_bytes(packet[6:8], "big") & 0x1FFF) == 0
    protocol, source_port, destination_port, payload = _transport(
        protocol_number, packet[header_length:end], first_fragment
    )
    return (
        str(ip_address(packet[12:16])),
        str(ip_address(packet[16:20])),
        source_port,
        destination_port,
        protocol,
        payload,
    )


def _decode_ipv6(packet: bytes) -> tuple[str, str, int | None, int | None, str, bytes] | None:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    payload_length = int.from_bytes(packet[4:6], "big")
    end = min(len(packet), 40 + payload_length) if payload_length else len(packet)
    next_header = packet[6]
    offset = 40
    first_fragment = True
    for _ in range(8):
        if next_header in {0, 43, 60}:
            if offset + 2 > end:
                return None
            length = (packet[offset + 1] + 1) * 8
            following = packet[offset]
        elif next_header == 44:
            if offset + 8 > end:
                return None
            following = packet[offset]
            first_fragment = (int.from_bytes(packet[offset + 2 : offset + 4], "big") >> 3) == 0
            length = 8
        elif next_header == 51:
            if offset + 2 > end:
                return None
            following = packet[offset]
            length = (packet[offset + 1] + 2) * 4
        else:
            break
        if length < 8 or offset + length > end:
            return None
        next_header = following
        offset += length
    protocol, source_port, destination_port, payload = _transport(
        next_header, packet[offset:end], first_fragment
    )
    return (
        str(ip_address(packet[8:24])),
        str(ip_address(packet[24:40])),
        source_port,
        destination_port,
        protocol,
        payload,
    )


def _transport(
    protocol_number: int, transport: bytes, first_fragment: bool
) -> tuple[str, int | None, int | None, bytes]:
    protocol = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPV6"}.get(
        protocol_number, f"IP_{protocol_number}"
    )
    if not first_fragment:
        return protocol, None, None, b""
    if protocol_number == 6 and len(transport) >= 20:
        source_port, destination_port = struct.unpack_from("!HH", transport)
        header_length = (transport[12] >> 4) * 4
        payload = transport[header_length:] if 20 <= header_length <= len(transport) else b""
        return protocol, source_port, destination_port, payload
    if protocol_number == 17 and len(transport) >= 8:
        source_port, destination_port, udp_length = struct.unpack_from("!HHH", transport)
        end = min(len(transport), udp_length) if udp_length >= 8 else len(transport)
        return protocol, source_port, destination_port, transport[8:end]
    header_length = 8 if protocol_number in {1, 58} and len(transport) >= 8 else 0
    return protocol, None, None, transport[header_length:]


def _direction(source: str, destination: str, networks: tuple[Network, ...]) -> Direction:
    source_address = ip_address(source)
    destination_address = ip_address(destination)
    source_internal = any(
        source_address.version == network.version and source_address in network
        for network in networks
    )
    destination_internal = any(
        destination_address.version == network.version and destination_address in network
        for network in networks
    )
    if source_internal and not destination_internal:
        return "OUTBOUND"
    if destination_internal and not source_internal:
        return "INBOUND"
    return "UNKNOWN"
