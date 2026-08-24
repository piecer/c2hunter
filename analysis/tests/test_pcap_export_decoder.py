from __future__ import annotations

import ast
import ipaddress
import struct
from dataclasses import FrozenInstanceError
from io import BytesIO

import pytest

from c2hunter_analysis.pcap import PcapParseError, parse_pcap
from c2hunter_analysis.pcap_export import open_export_capture


class ShortReader:
    def __init__(self, content: bytes, chunk_size: int = 3) -> None:
        self.content = content
        self.chunk_size = chunk_size
        self.offset = 0
        self.read_sizes: list[int] = []

    def read(self, size: int = -1, /) -> bytes:
        self.read_sizes.append(size)
        if size < 0:
            size = len(self.content) - self.offset
        size = min(size, self.chunk_size)
        result = self.content[self.offset : self.offset + size]
        self.offset += len(result)
        return result


def udp_packet(payload: bytes = b"beacon") -> bytes:
    udp = struct.pack("!HHHH", 50000, 443, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        7,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("10.0.0.8").packed,
        ipaddress.ip_address("203.0.113.8").packed,
    )
    return bytes.fromhex("0200000000020200000000010800") + ipv4 + udp


def classic(
    packets: list[bytes],
    *,
    endian: str = "<",
    nanoseconds: bool = False,
    link_type: int = 1,
    snaplen: int = 65535,
) -> bytes:
    magic = {
        ("<", False): b"\xd4\xc3\xb2\xa1",
        (">", False): b"\xa1\xb2\xc3\xd4",
        ("<", True): b"\x4d\x3c\xb2\xa1",
        (">", True): b"\xa1\xb2\x3c\x4d",
    }[(endian, nanoseconds)]
    result = bytearray(magic + struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, snaplen, link_type))
    fraction = 500_000_000 if nanoseconds else 500_000
    for index, packet in enumerate(packets):
        result.extend(
            struct.pack(f"{endian}IIII", 1_784_544_000 + index, fraction, len(packet), len(packet))
        )
        result.extend(packet)
    return bytes(result)


def test_nonseekable_short_read_classic_foundation() -> None:
    packet = udp_packet()
    reader = ShortReader(classic([packet]))

    decoder = open_export_capture(
        reader,
        source_id="version-1",
        source_order=7,
        internal_networks=["10.0.0.0/8"],
    )
    assert decoder.capture_format == "PCAP"
    item = next(decoder.iter_packets())

    assert item.source_ip == "10.0.0.8"
    assert item.destination_ip == "203.0.113.8"
    assert item.source_port == 50000
    assert item.destination_port == 443
    assert item.protocol == "UDP"
    assert item.direction == "OUTBOUND"
    assert item.has_payload is True
    assert item.supported is True
    assert item.raw_packet_bytes == packet
    assert item.original_length == len(packet)
    assert item.interface.section_index == 0
    assert item.interface.interface_id == item.interface.interface_ordinal == 0
    assert item.interface.link_type == 1
    assert item.interface.snaplen == 65535
    assert item.interface.timestamp_resolution_numerator == 1
    assert item.interface.timestamp_resolution_denominator == 1_000_000
    assert item.locator.source_id == "version-1"
    assert item.locator.source_order == 7
    assert item.locator.packet_index == 0
    assert item.locator.record_offset == 24
    assert item.locator.data_offset == 40
    assert item.locator.captured_length == len(packet)
    assert item.locator.framed_length == 16 + len(packet)
    with pytest.raises(FrozenInstanceError):
        item.original_length = 1  # type: ignore[misc]


@pytest.mark.parametrize(
    ("endian", "nanoseconds"), [("<", False), (">", False), ("<", True), (">", True)]
)
def test_classic_magic_timestamp_and_differential_parity(endian: str, nanoseconds: bool) -> None:
    packet = udp_packet()
    capture = classic([packet], endian=endian, nanoseconds=nanoseconds)
    expected = parse_pcap(
        capture,
        sensor_id="oracle",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes_as_bytes=True,
    ).records[0]

    decoder = open_export_capture(
        ShortReader(capture, 1),
        source_id="v",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )
    actual = list(decoder.iter_packets())[0]

    assert actual.timestamp == expected["timestamp"]
    assert actual.source_ip == expected["source_ip"]
    assert actual.destination_ip == expected["destination_ip"]
    assert actual.source_port == expected["source_port"]
    assert actual.destination_port == expected["destination_port"]
    assert actual.protocol == expected["protocol"]
    assert actual.direction == expected["direction"]
    assert actual.has_payload is bool(expected["payload_hash"])
    assert actual.interface.timestamp_resolution_denominator == (
        1_000_000_000 if nanoseconds else 1_000_000
    )


def test_classic_is_one_shot_and_reports_late_truncation_lazily() -> None:
    packet = udp_packet()
    decoder = open_export_capture(
        ShortReader(classic([packet]) + b"x"),
        source_id="v",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )
    packets = decoder.iter_packets()
    assert next(packets).raw_packet_bytes == packet
    with pytest.raises(PcapParseError, match="packet header is truncated"):
        next(packets)
    with pytest.raises(RuntimeError, match="only be iterated once"):
        decoder.iter_packets()


@pytest.mark.parametrize(
    ("capture", "message"),
    [
        (b"\xd4\xc3\xb2\xa1" + b"\0" * 19, "global header is truncated"),
        (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 3, 0, 0, 0, 65535, 1), "version 3.0"),
        (b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 0, 1), "snap length"),
    ],
)
def test_classic_header_errors(capture: bytes, message: str) -> None:
    decoder = open_export_capture(
        ShortReader(capture), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError, match=message):
        list(decoder.iter_packets())


@pytest.mark.parametrize(("snaplen", "original_length"), [(65535, 5), (8, 5)])
def test_classic_truncated_data_precedes_length_semantics_differential(
    snaplen: int, original_length: int
) -> None:
    capture = classic([], snaplen=snaplen) + struct.pack("<IIII", 0, 0, 10, original_length)

    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())

    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))


def test_empty_classic_uses_existing_error_contract() -> None:
    decoder = open_export_capture(
        ShortReader(classic([])), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError, match="does not contain timestamped") as error:
        list(decoder.iter_packets())
    assert error.value.code == "EMPTY_PCAP"


def ng_block(kind: int, body: bytes, endian: str = "<") -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = 12 + len(body)
    return struct.pack(f"{endian}II", kind, length) + body + struct.pack(f"{endian}I", length)


def ng_section(endian: str = "<") -> bytes:
    return ng_block(0x0A0D0D0A, struct.pack(f"{endian}IHHq", 0x1A2B3C4D, 1, 0, -1), endian)


def ng_interface(
    *, endian: str = "<", link_type: int = 1, snaplen: int = 65535, options: bytes = b""
) -> bytes:
    return ng_block(1, struct.pack(f"{endian}HHI", link_type, 0, snaplen) + options, endian)


def ng_packet(
    packet: bytes,
    *,
    endian: str = "<",
    kind: int = 6,
    interface_id: int = 0,
    timestamp: int = 1_784_544_000_500_000,
    original_length: int | None = None,
) -> bytes:
    original_length = len(packet) if original_length is None else original_length
    if kind == 6:
        header = struct.pack(
            f"{endian}IIIII",
            interface_id,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet),
            original_length,
        )
    else:
        header = struct.pack(
            f"{endian}HHIIII",
            interface_id,
            0,
            timestamp >> 32,
            timestamp & 0xFFFFFFFF,
            len(packet),
            original_length,
        )
    return ng_block(kind, header + packet, endian)


@pytest.mark.parametrize("kind", [2, 6])
def test_pcapng_forward_only_framing_and_packet_blocks(kind: int) -> None:
    packet = udp_packet(b"odd")
    unknown = ng_block(0x12345678, b"x" * 4097)
    capture = ng_section() + unknown + ng_interface() + ng_packet(packet, kind=kind)
    decoder = open_export_capture(
        ShortReader(capture, 2),
        source_id="ng",
        source_order=4,
        internal_networks=["10.0.0.0/8"],
    )
    assert decoder.capture_format == "PCAPNG"
    actual = list(decoder.iter_packets())[0]
    packet_offset = len(ng_section()) + len(unknown) + len(ng_interface())
    assert actual.raw_packet_bytes == packet
    assert actual.locator.record_offset == packet_offset
    assert actual.locator.data_offset == packet_offset + 28
    assert actual.locator.framed_length == len(ng_packet(packet, kind=kind))
    assert actual.locator.captured_length == len(packet)


def test_pcapng_rejects_simple_packet_block_and_bad_trailer() -> None:
    simple = ng_section() + ng_interface() + ng_block(3, b"data")
    decoder = open_export_capture(
        ShortReader(simple), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError, match="simple packet") as error:
        list(decoder.iter_packets())
    assert error.value.code == "UNSUPPORTED_PCAPNG_BLOCK"

    malformed = bytearray(ng_section() + ng_interface() + ng_packet(udp_packet()))
    malformed[-4:] = struct.pack("<I", 12)
    decoder = open_export_capture(
        ShortReader(bytes(malformed)),
        source_id="v",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )
    with pytest.raises(PcapParseError, match="trailer does not match"):
        list(decoder.iter_packets())


def _bad_ng_trailer(block: bytes) -> bytes:
    return block[:-4] + struct.pack("<I", 12)


@pytest.mark.parametrize("fault", ["short", "unknown_interface", "snaplen", "oversized"])
def test_pcapng_bad_trailer_precedes_packet_semantics_differential(fault: str) -> None:
    packet = b"xx"
    if fault == "short":
        block = ng_block(6, b"\0" * 16)
        prefix = ng_section() + ng_interface()
    elif fault == "unknown_interface":
        block = ng_packet(b"", interface_id=99)
        prefix = ng_section() + ng_interface()
    elif fault == "snaplen":
        block = ng_packet(packet)
        prefix = ng_section() + ng_interface(snaplen=1)
    else:
        fixed = struct.pack("<IIIII", 0, 0, 0, 10, 10)
        block = ng_block(6, fixed)
        prefix = ng_section() + ng_interface()
    capture = prefix + _bad_ng_trailer(block)

    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())

    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))


def ng_option(code: int, value: bytes, endian: str = "<") -> bytes:
    return struct.pack(f"{endian}HH", code, len(value)) + value + b"\0" * (-len(value) % 4)


def test_pcapng_end_of_options_ignores_declared_length_differential() -> None:
    capture = ng_section() + ng_interface(options=struct.pack("<HH", 0, 65535))

    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture, 1), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())

    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))
    assert (actual.value.code, str(actual.value)) == (
        "EMPTY_PCAP",
        "capture does not contain timestamped packets",
    )


def test_pcapng_end_of_options_preserves_trailer_precedence_differential() -> None:
    interface = _bad_ng_trailer(ng_interface(options=struct.pack("<HH", 0, 65535)))
    capture = ng_section() + interface

    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())

    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))
    assert str(actual.value) == "PCAPNG block length trailer does not match"


@pytest.mark.parametrize(
    ("snaplen", "message"),
    [
        (0, "PCAPNG interface snap length is invalid"),
        (65535, "PCAPNG interface option is truncated"),
    ],
)
def test_pcapng_snaplen_precedes_option_error_differential(snaplen: int, message: str) -> None:
    malformed_option = struct.pack("<HH", 9, 65535)
    capture = ng_section() + ng_interface(snaplen=snaplen, options=malformed_option)

    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture, 1), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())

    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))
    assert (actual.value.code, str(actual.value)) == ("INVALID_PCAP", message)


def test_pcapng_sections_interfaces_and_timestamp_options() -> None:
    packet = udp_packet()
    little_options = ng_option(9, b"\x09") + ng_option(14, struct.pack("<q", -2))
    big_options = ng_option(9, b"\x8a", ">") + ng_option(14, struct.pack(">q", 3), ">")
    first_ticks = 2_500_000_000_000
    second_ticks = 1024
    capture = (
        ng_section("<")
        + ng_interface(endian="<", options=little_options)
        + ng_packet(packet, endian="<", timestamp=first_ticks)
        + ng_section(">")
        + ng_interface(endian=">", options=big_options)
        + ng_packet(packet, endian=">", timestamp=second_ticks)
    )

    packets = list(
        open_export_capture(
            ShortReader(capture, 5),
            source_id="sections",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ).iter_packets()
    )

    assert [item.locator.packet_index for item in packets] == [0, 1]
    assert [item.interface.section_index for item in packets] == [0, 1]
    assert [item.interface.interface_id for item in packets] == [0, 0]
    assert [item.interface.interface_ordinal for item in packets] == [0, 1]
    assert packets[0].interface.timestamp_resolution_denominator == 1_000_000_000
    assert packets[0].interface.timestamp_offset_seconds == -2
    assert packets[1].interface.timestamp_resolution_denominator == 1024
    assert packets[1].interface.timestamp_offset_seconds == 3
    assert packets[0].timestamp.timestamp() == pytest.approx(first_ticks / 1e9 - 2)
    assert packets[1].timestamp.timestamp() == pytest.approx(second_ticks / 1024 + 3)


def test_pcapng_decimal_timestamp_operation_order_differential() -> None:
    ticks = 17_845_439_999_000_005
    capture = (
        ng_section()
        + ng_interface(options=ng_option(9, b"\x07"))
        + ng_packet(udp_packet(), timestamp=ticks)
    )
    expected = parse_pcap(
        capture,
        sensor_id="oracle",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes_as_bytes=True,
    ).records[0]["timestamp"]

    actual = list(
        open_export_capture(
            ShortReader(capture),
            source_id="v",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ).iter_packets()
    )[0]

    assert actual.timestamp == expected
    assert actual.timestamp.isoformat() == "2026-07-20T10:39:59.900000+00:00"
    assert actual.interface.timestamp_resolution_numerator == 1
    assert actual.interface.timestamp_resolution_denominator == 10_000_000


@pytest.mark.parametrize("block_length", [16, 20, 24])
def test_pcapng_accepts_complete_short_sections_differential(block_length: int) -> None:
    capture = (
        b"\x0a\x0d\x0d\x0a"
        + struct.pack("<I", block_length)
        + struct.pack("<I", 0x1A2B3C4D)
        + b"\0" * (block_length - 16)
        + struct.pack("<I", block_length)
    )
    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture),
        source_id="v",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())
    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))


def test_pcapng_twelve_byte_section_uses_trailer_precedence_differential() -> None:
    capture = b"\x0a\x0d\x0d\x0a" + struct.pack("<I", 12) + struct.pack("<I", 0x1A2B3C4D)
    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())
    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))


@pytest.mark.parametrize(
    "suffix",
    [
        *(b"x" * size for size in range(1, 12)),
        struct.pack("<II", 0x12345678, 12),
        struct.pack("<II", 0x0A0D0D0A, 12),
    ],
)
def test_pcapng_requires_complete_common_block_prefix_differential(suffix: bytes) -> None:
    capture = ng_section() + suffix
    with pytest.raises(PcapParseError) as expected:
        parse_pcap(capture, sensor_id="oracle", internal_networks=["10.0.0.0/8"])
    decoder = open_export_capture(
        ShortReader(capture, 1), source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError) as actual:
        list(decoder.iter_packets())

    assert (actual.value.code, str(actual.value)) == (expected.value.code, str(expected.value))
    assert (actual.value.code, str(actual.value)) == (
        "INVALID_PCAP",
        "PCAPNG block header is truncated",
    )


def ipv6_udp_packet(payload: bytes = b"v6") -> bytes:
    udp = struct.pack("!HHHH", 5353, 53, 8 + len(payload), 0) + payload
    ipv6 = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(udp),
        17,
        64,
        ipaddress.ip_address("2001:db8::1").packed,
        ipaddress.ip_address("2001:db8::2").packed,
    )
    return ipv6 + udp


@pytest.mark.parametrize(
    ("link_type", "raw"),
    [
        (1, udp_packet()),
        (1, udp_packet()[:12] + b"\x81\x00\x00\x01\x08\x00" + udp_packet()[14:]),
        (1, udp_packet()[:12] + b"\x88\xa8\x00\x01\x91\x00\x00\x02\x08\x00" + udp_packet()[14:]),
        (12, udp_packet()[14:]),
        (101, udp_packet()[14:]),
        (228, udp_packet()[14:]),
        (113, b"\0" * 14 + b"\x08\x00" + udp_packet()[14:]),
        (276, b"\x08\x00" + b"\0" * 18 + udp_packet()[14:]),
        (0, struct.pack("<I", 2) + udp_packet()[14:]),
        (108, struct.pack(">I", 2) + udp_packet()[14:]),
        (229, ipv6_udp_packet()),
    ],
)
def test_link_layer_and_l3_l4_projection_differential(link_type: int, raw: bytes) -> None:
    capture = classic([raw], link_type=link_type)
    expected = parse_pcap(
        capture,
        sensor_id="oracle",
        internal_networks=["10.0.0.0/8", "2001:db8::/64"],
        retain_packet_bytes_as_bytes=True,
        allow_no_supported_packets=True,
    )
    actual = list(
        open_export_capture(
            ShortReader(capture, 7),
            source_id="v",
            source_order=0,
            internal_networks=["10.0.0.0/8", "2001:db8::/64"],
        ).iter_packets()
    )[0]
    assert actual.supported is bool(expected.records)
    if expected.records:
        record = expected.records[0]
        assert (
            actual.source_ip,
            actual.destination_ip,
            actual.source_port,
            actual.destination_port,
            actual.protocol,
            actual.direction,
            actual.has_payload,
        ) == (
            record["source_ip"],
            record["destination_ip"],
            record["source_port"],
            record["destination_port"],
            record["protocol"],
            record["direction"],
            bool(record["payload_hash"]),
        )


def test_unsupported_timestamped_packet_is_yielded_with_nullable_projection() -> None:
    arp = bytes.fromhex("ffffffffffff0000000000000806") + b"\0" * 28
    packet = list(
        open_export_capture(
            BytesIO(classic([arp])),
            source_id="v",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ).iter_packets()
    )[0]
    assert packet.supported is False
    assert (
        packet.source_ip,
        packet.destination_ip,
        packet.source_port,
        packet.destination_port,
        packet.protocol,
        packet.direction,
        packet.has_payload,
    ) == (None, None, None, None, None, None, None)


def ipv4_transport(protocol: int, transport: bytes, *, fragment_offset: int = 0) -> bytes:
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(transport),
            1,
            fragment_offset,
            64,
            protocol,
            0,
            ipaddress.ip_address("10.1.2.3").packed,
            ipaddress.ip_address("198.51.100.9").packed,
        )
        + transport
    )


@pytest.mark.parametrize(
    "raw",
    [
        ipv4_transport(6, struct.pack("!HHIIHHHH", 1234, 80, 0, 0, 5 << 12, 0, 0, 0) + b"x"),
        ipv4_transport(17, b"abc"),
        ipv4_transport(17, struct.pack("!HHHH", 10, 20, 4, 0) + b"payload"),
        ipv4_transport(1, b"\x08\0\0\0\0\0\0\0ping"),
        ipv4_transport(99, b"unknown"),
        ipv4_transport(17, struct.pack("!HHHH", 10, 20, 8, 0), fragment_offset=1),
    ],
)
def test_transport_and_fragment_semantics_match_analysis_parser(raw: bytes) -> None:
    capture = classic([raw], link_type=228)
    expected = parse_pcap(
        capture,
        sensor_id="oracle",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes_as_bytes=True,
    ).records[0]
    actual = list(
        open_export_capture(
            ShortReader(capture),
            source_id="v",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ).iter_packets()
    )[0]
    assert (actual.source_port, actual.destination_port, actual.protocol, actual.has_payload) == (
        expected["source_port"],
        expected["destination_port"],
        expected["protocol"],
        bool(expected["payload_hash"]),
    )


def test_decoder_is_lazy_borrows_reader_and_streams_unknown_blocks() -> None:
    packet = udp_packet()
    capture = classic([packet] * 100)
    reader = ShortReader(capture, chunk_size=len(capture))
    decoder = open_export_capture(
        reader, source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    packets = decoder.iter_packets()
    next(packets)
    assert reader.offset == 24 + 16 + len(packet)

    huge_unknown = ng_block(0x44444444, b"x" * (2 * 1024 * 1024))
    ng_reader = ShortReader(
        ng_section() + huge_unknown + ng_interface() + ng_packet(packet), chunk_size=128 * 1024
    )
    list(
        open_export_capture(
            ng_reader, source_id="v", source_order=0, internal_networks=["10.0.0.0/8"]
        ).iter_packets()
    )
    assert max(ng_reader.read_sizes) <= 64 * 1024


def test_export_decoder_import_and_production_isolation() -> None:
    module_path = __file__.replace(
        "tests/test_pcap_export_decoder.py", "src/c2hunter_analysis/pcap_export.py"
    )
    source = open(module_path, encoding="utf-8").read()

    def imported_paths(module_source: str) -> set[str]:
        paths: set[str] = set()
        for node in ast.walk(ast.parse(module_source)):
            if isinstance(node, ast.Import):
                paths.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                module = "." * node.level + (node.module or "")
                paths.add(module)
                paths.update(
                    f"{module}.{alias.name}" if module else alias.name for alias in node.names
                )
        return paths

    forbidden = {
        "hashlib",
        "payload_features",
        "domain",
        "tcp_sessions",
        "controller",
        "detector",
        "detectors",
        "scoring",
        "c2hunter_analysis.payload_features",
        "c2hunter_analysis.domain",
        "c2hunter_analysis.tcp_sessions",
        "c2hunter_analysis.detectors",
        "c2hunter_analysis.scoring",
        "c2hunter_controller",
    }
    synthetic = imported_paths(
        "import c2hunter_analysis.payload_features\n"
        "from c2hunter_analysis import tcp_sessions\n"
        "from c2hunter_controller.pcap import ingest\n"
    )
    assert {
        "c2hunter_analysis.payload_features",
        "c2hunter_analysis.tcp_sessions",
        "c2hunter_controller.pcap.ingest",
    } <= synthetic

    imports = imported_paths(source)
    assert not {
        imported
        for imported in imports
        if any(imported == name or imported.startswith(f"{name}.") for name in forbidden)
    }
    controller_source = open(
        __file__.replace(
            "analysis/tests/test_pcap_export_decoder.py",
            "controller/src/c2hunter_controller/app.py",
        ),
        encoding="utf-8",
    ).read()
    assert "c2hunter_analysis.pcap_export" not in controller_source
    assert "from c2hunter_analysis import pcap_export" not in controller_source
