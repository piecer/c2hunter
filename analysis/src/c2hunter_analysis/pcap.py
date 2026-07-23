from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from typing import Any

from .payload_features import extract_payload_features


class PcapParseError(ValueError):
    def __init__(self, message: str, code: str = "INVALID_PCAP") -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class PcapParseResult:
    records: tuple[dict[str, Any], ...]
    capture_format: str
    captured_packet_count: int
    parsed_packet_count: int
    skipped_packet_count: int
    link_types: tuple[int, ...]
    start_time: datetime
    end_time: datetime


@dataclass(frozen=True)
class _CapturedPacket:
    timestamp: datetime
    link_type: int
    data: bytes


@dataclass(frozen=True)
class _PcapNgInterface:
    link_type: int
    timestamp_resolution: float = 0.000001
    timestamp_offset: int = 0


Network = IPv4Network | IPv6Network

_CLASSIC_MAGIC: dict[bytes, tuple[str, float]] = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024


def parse_pcap(
    content: bytes,
    *,
    sensor_id: str,
    internal_networks: Sequence[str],
    max_packets: int = 2_000_000,
    retain_packet_bytes: bool = True,
    retain_payload_sample_bytes: int = 0,
) -> PcapParseResult:
    """Parse bounded PCAP/PCAPNG bytes into the existing flow-analysis contract."""
    if max_packets < 1:
        raise ValueError("max_packets must be positive")
    if not 0 <= retain_payload_sample_bytes <= 256:
        raise ValueError("retain_payload_sample_bytes must be between 0 and 256")
    networks = _networks(internal_networks)
    if content[:4] in _CLASSIC_MAGIC:
        capture_format = "PCAP"
        packets = _iter_classic_pcap(content, max_packets)
    elif content[:4] == _PCAPNG_SECTION:
        capture_format = "PCAPNG"
        packets = _iter_pcapng(content, max_packets)
    else:
        raise PcapParseError("file is not a classic PCAP or PCAPNG capture")
    records: list[dict[str, Any]] = []
    captured_packet_count = 0
    link_types: set[int] = set()
    for packet in packets:
        captured_packet_count += 1
        link_types.add(packet.link_type)
        decoded = _decode_packet(
            packet,
            sensor_id,
            networks,
            retain_packet_bytes,
            retain_payload_sample_bytes,
        )
        if decoded is not None:
            records.append(decoded)
    if captured_packet_count == 0:
        raise PcapParseError("capture does not contain timestamped packets", "EMPTY_PCAP")
    if not records:
        raise PcapParseError(
            "capture contains no supported IPv4 or IPv6 packets",
            "NO_SUPPORTED_IP_PACKETS",
        )
    timestamps = [record["timestamp"] for record in records]
    return PcapParseResult(
        tuple(records),
        capture_format,
        captured_packet_count,
        len(records),
        captured_packet_count - len(records),
        tuple(sorted(link_types)),
        min(timestamps),
        max(timestamps),
    )


def find_pcap_record(
    content: bytes,
    *,
    sensor_id: str,
    internal_networks: Sequence[str],
    predicate: Callable[[dict[str, Any]], bool],
    max_packets: int = 2_000_000,
    retain_payload_sample_bytes: int = 0,
) -> dict[str, Any] | None:
    """Decode until a target record is found without materializing the full capture."""
    if max_packets < 1:
        raise ValueError("max_packets must be positive")
    if not 0 <= retain_payload_sample_bytes <= 256:
        raise ValueError("retain_payload_sample_bytes must be between 0 and 256")
    networks = _networks(internal_networks)
    if content[:4] in _CLASSIC_MAGIC:
        packets = _iter_classic_pcap(content, max_packets)
    elif content[:4] == _PCAPNG_SECTION:
        packets = _iter_pcapng(content, max_packets)
    else:
        raise PcapParseError("file is not a classic PCAP or PCAPNG capture")
    captured_packet_count = 0
    for packet in packets:
        captured_packet_count += 1
        decoded = _decode_packet(
            packet,
            sensor_id,
            networks,
            False,
            retain_payload_sample_bytes,
        )
        if decoded is not None and predicate(decoded):
            return decoded
    if captured_packet_count == 0:
        raise PcapParseError("capture does not contain timestamped packets", "EMPTY_PCAP")
    return None


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


def _iter_classic_pcap(content: bytes, max_packets: int) -> Iterator[_CapturedPacket]:
    if len(content) < 24:
        raise PcapParseError("classic PCAP global header is truncated")
    endian, resolution = _CLASSIC_MAGIC[content[:4]]
    major, minor, _zone, _accuracy, snaplen, link_type = struct.unpack_from(
        f"{endian}HHIIII", content, 4
    )
    if major != 2 or minor != 4:
        raise PcapParseError(f"unsupported classic PCAP version {major}.{minor}")
    if snaplen < 1 or snaplen > _MAX_CAPTURED_PACKET_BYTES:
        raise PcapParseError("classic PCAP snap length is invalid")
    offset = 24
    count = 0
    while offset < len(content):
        if len(content) - offset < 16:
            raise PcapParseError("classic PCAP packet header is truncated")
        seconds, fraction, captured_length, _original_length = struct.unpack_from(
            f"{endian}IIII", content, offset
        )
        offset += 16
        if captured_length > _MAX_CAPTURED_PACKET_BYTES or captured_length > len(content) - offset:
            raise PcapParseError("classic PCAP packet data is truncated or oversized")
        count += 1
        if count > max_packets:
            raise PcapParseError(
                f"capture exceeds the {max_packets} packet limit", "PCAP_PACKET_LIMIT_EXCEEDED"
            )
        packet = content[offset : offset + captured_length]
        offset += captured_length
        yield _CapturedPacket(
            _timestamp(seconds + fraction / resolution), int(link_type & 0xFFFF), packet
        )


def _pcapng_endian(content: bytes, offset: int) -> str:
    if len(content) - offset < 12:
        raise PcapParseError("PCAPNG section header is truncated")
    byte_order_magic = content[offset + 8 : offset + 12]
    if byte_order_magic == b"\x4d\x3c\x2b\x1a":
        return "<"
    if byte_order_magic == b"\x1a\x2b\x3c\x4d":
        return ">"
    raise PcapParseError("PCAPNG section has an invalid byte-order magic")


def _iter_pcapng(content: bytes, max_packets: int) -> Iterator[_CapturedPacket]:
    offset = 0
    endian = "<"
    interfaces: list[_PcapNgInterface] = []
    count = 0
    saw_section = False
    while offset < len(content):
        if len(content) - offset < 12:
            raise PcapParseError("PCAPNG block header is truncated")
        is_section = content[offset : offset + 4] == _PCAPNG_SECTION
        if is_section:
            endian = _pcapng_endian(content, offset)
        block_type, block_length = struct.unpack_from(f"{endian}II", content, offset)
        if block_length < 12 or block_length % 4 or block_length > len(content) - offset:
            raise PcapParseError("PCAPNG block length is invalid")
        trailing_length = struct.unpack_from(f"{endian}I", content, offset + block_length - 4)[0]
        if trailing_length != block_length:
            raise PcapParseError("PCAPNG block length trailer does not match")

        if is_section:
            saw_section = True
            interfaces = []
        elif not saw_section:
            raise PcapParseError("PCAPNG data appears before a section header")
        elif block_type == 1:
            if block_length < 20:
                raise PcapParseError("PCAPNG interface block is truncated")
            link_type = struct.unpack_from(f"{endian}H", content, offset + 8)[0]
            resolution, timestamp_offset = _pcapng_interface_options(
                content, offset + 16, offset + block_length - 4, endian
            )
            interfaces.append(_PcapNgInterface(link_type, resolution, timestamp_offset))
        elif block_type in {2, 6}:
            minimum = 28 if block_type == 6 else 28
            if block_length < minimum + 4:
                raise PcapParseError("PCAPNG packet block is truncated")
            if block_type == 6:
                interface_id, high, low, captured_length, _original_length = struct.unpack_from(
                    f"{endian}IIIII", content, offset + 8
                )
                packet_offset = offset + 28
            else:
                interface_id, _drops, high, low, captured_length, _original_length = (
                    struct.unpack_from(f"{endian}HHIIII", content, offset + 8)
                )
                packet_offset = offset + 28
            if interface_id >= len(interfaces):
                raise PcapParseError("PCAPNG packet references an unknown interface")
            padded_length = (captured_length + 3) & ~3
            if (
                captured_length > _MAX_CAPTURED_PACKET_BYTES
                or packet_offset + padded_length > offset + block_length - 4
            ):
                raise PcapParseError("PCAPNG packet data is truncated or oversized")
            count += 1
            if count > max_packets:
                raise PcapParseError(
                    f"capture exceeds the {max_packets} packet limit",
                    "PCAP_PACKET_LIMIT_EXCEEDED",
                )
            interface = interfaces[interface_id]
            raw_timestamp = (high << 32) | low
            timestamp = raw_timestamp * interface.timestamp_resolution + interface.timestamp_offset
            yield _CapturedPacket(
                _timestamp(timestamp),
                interface.link_type,
                content[packet_offset : packet_offset + captured_length],
            )
        elif block_type == 3:
            raise PcapParseError(
                "PCAPNG simple packet blocks have no timestamp and are not supported",
                "UNSUPPORTED_PCAPNG_BLOCK",
            )
        offset += block_length


def _pcapng_interface_options(
    content: bytes, start: int, end: int, endian: str
) -> tuple[float, int]:
    resolution = 0.000001
    timestamp_offset = 0
    offset = start
    while offset + 4 <= end:
        code, length = struct.unpack_from(f"{endian}HH", content, offset)
        offset += 4
        if code == 0:
            break
        padded = (length + 3) & ~3
        if offset + padded > end:
            raise PcapParseError("PCAPNG interface option is truncated")
        value = content[offset : offset + length]
        if code == 9 and length == 1:
            exponent = value[0]
            resolution = 2.0 ** -(exponent & 0x7F) if exponent & 0x80 else 10.0**-exponent
        elif code == 14 and length == 8:
            timestamp_offset = int(struct.unpack(f"{endian}q", value)[0])
        offset += padded
    return resolution, timestamp_offset


def _decode_packet(
    captured: _CapturedPacket,
    sensor_id: str,
    networks: tuple[Network, ...],
    retain_packet_bytes: bool,
    retain_payload_sample_bytes: int,
) -> dict[str, Any] | None:
    network = _network_packet(captured.data, captured.link_type)
    if network is None:
        return None
    version, packet = network
    decoded = _decode_ipv4(packet) if version == 4 else _decode_ipv6(packet)
    if decoded is None:
        return None
    source_ip = str(decoded["source_ip"])
    destination_ip = str(decoded["destination_ip"])
    payload = bytes(decoded.pop("payload"))
    source_port = decoded.get("source_port")
    destination_port = decoded.get("destination_port")
    protocol = str(decoded["protocol"])
    features = extract_payload_features(payload)
    record: dict[str, Any] = {
        "sensor_id": sensor_id,
        "timestamp": captured.timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "direction": _direction(source_ip, destination_ip, networks),
        "packet_count": 1,
        "total_bytes": len(captured.data),
        "payload_hash": hashlib.sha256(payload).hexdigest() if payload else None,
        "domain": _application_domain(protocol, source_port, destination_port, payload),
        "packet_sizes": (len(captured.data),),
    }
    if features is not None:
        record.update(features.as_dict())
    if retain_payload_sample_bytes and payload:
        record["payload_sample_hex"] = payload[:retain_payload_sample_bytes].hex()
    if retain_packet_bytes:
        record["raw_packet_hex"] = captured.data.hex()
    return record


def _network_packet(packet: bytes, link_type: int) -> tuple[int, bytes] | None:
    if link_type == 1:  # Ethernet
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
    if link_type in {12, 101}:  # DLT_RAW values used by common libpcap platforms
        return _raw_ip(packet)
    if link_type == 228:
        return (4, packet) if packet and packet[0] >> 4 == 4 else None
    if link_type == 229:
        return (6, packet) if packet and packet[0] >> 4 == 6 else None
    if link_type == 113:  # Linux cooked capture v1
        if len(packet) < 16:
            return None
        return _ethertype_payload(int.from_bytes(packet[14:16], "big"), packet[16:])
    if link_type == 276:  # Linux cooked capture v2
        if len(packet) < 20:
            return None
        return _ethertype_payload(int.from_bytes(packet[0:2], "big"), packet[20:])
    if link_type in {0, 108}:  # BSD loopback/null
        if len(packet) < 4:
            return None
        families = {int.from_bytes(packet[:4], "little"), int.from_bytes(packet[:4], "big")}
        if 2 in families:
            return (4, packet[4:])
        if families & {10, 24, 28, 30}:
            return (6, packet[4:])
    return None


def _ethertype_payload(protocol: int, payload: bytes) -> tuple[int, bytes] | None:
    if protocol == 0x0800:
        return (4, payload)
    if protocol == 0x86DD:
        return (6, payload)
    return None


def _raw_ip(packet: bytes) -> tuple[int, bytes] | None:
    if not packet:
        return None
    version = packet[0] >> 4
    return (version, packet) if version in {4, 6} else None


def _decode_ipv4(packet: bytes) -> dict[str, Any] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    total_length = int.from_bytes(packet[2:4], "big")
    if header_length < 20 or total_length < header_length or len(packet) < header_length:
        return None
    end = min(len(packet), total_length)
    protocol_number = packet[9]
    fragment_offset = int.from_bytes(packet[6:8], "big") & 0x1FFF
    transport = packet[header_length:end]
    protocol, source_port, destination_port, payload = _transport(
        protocol_number, transport, fragment_offset == 0
    )
    return {
        "source_ip": ip_address(packet[12:16]),
        "destination_ip": ip_address(packet[16:20]),
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "payload": payload,
    }


def _decode_ipv6(packet: bytes) -> dict[str, Any] | None:
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
    return {
        "source_ip": ip_address(packet[8:24]),
        "destination_ip": ip_address(packet[24:40]),
        "source_port": source_port,
        "destination_port": destination_port,
        "protocol": protocol,
        "payload": payload,
    }


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


def _direction(source: str, destination: str, networks: tuple[Network, ...]) -> str:
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


def _application_domain(
    protocol: str,
    source_port: int | None,
    destination_port: int | None,
    payload: bytes,
) -> str | None:
    if payload.startswith(b"sni-"):
        return payload[:253].decode("ascii", errors="ignore").lower() or None
    if 53 in {source_port, destination_port}:
        dns_payload = payload[2:] if protocol == "TCP" and len(payload) >= 2 else payload
        domain = _dns_query_name(dns_payload)
        if domain:
            return domain
    if protocol == "TCP" and {source_port, destination_port} & {80, 8000, 8080, 8888}:
        for line in payload[:8192].split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host = line.split(b":", 1)[1].strip().split(b":", 1)[0]
                return host[:253].decode("ascii", errors="ignore").lower() or None
    return None


def _dns_query_name(payload: bytes) -> str | None:
    if len(payload) < 13 or int.from_bytes(payload[4:6], "big") < 1:
        return None
    labels: list[str] = []
    offset = 12
    while offset < len(payload):
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0 or length > 63 or offset + length > len(payload):
            return None
        label = payload[offset : offset + length].decode("ascii", errors="ignore")
        if not label:
            return None
        labels.append(label)
        offset += length
        if sum(len(item) + 1 for item in labels) > 253:
            return None
    return ".".join(labels).lower() or None
