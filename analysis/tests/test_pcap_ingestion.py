from __future__ import annotations

import ipaddress
import struct

import pytest

from c2hunter_analysis.pcap import (
    PcapParseError,
    bounded_pcap_prefix,
    find_pcap_record,
    parse_pcap,
)


def udp_packet() -> bytes:
    payload = b"beacon"
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


def classic_pcap(packet: bytes, link_type: int = 1, count: int = 1) -> bytes:
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
    for index in range(count):
        content.extend(
            struct.pack("<IIII", 1_784_544_000 + index, 500_000, len(packet), len(packet))
        )
        content.extend(packet)
    return bytes(content)


def pcapng(packet: bytes, count: int = 1) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    timestamp = 1_784_544_000_500_000
    enhanced = b"".join(
        block(
            6,
            struct.pack(
                "<IIIII",
                0,
                (timestamp + index) >> 32,
                (timestamp + index) & 0xFFFFFFFF,
                len(packet),
                len(packet),
            )
            + packet,
        )
        for index in range(count)
    )
    return section + interface + enhanced


@pytest.mark.parametrize(
    ("capture", "capture_format"),
    [(classic_pcap(udp_packet()), "PCAP"), (pcapng(udp_packet()), "PCAPNG")],
)
def test_parse_pcap_and_pcapng_to_directional_flow(capture: bytes, capture_format: str) -> None:
    result = parse_pcap(
        capture,
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
    )

    assert result.capture_format == capture_format
    assert result.captured_packet_count == result.parsed_packet_count == 1
    assert result.skipped_packet_count == 0
    record = result.records[0]
    assert record["source_ip"] == "10.0.0.8"
    assert record["destination_ip"] == "203.0.113.8"
    assert record["source_port"] == 50000
    assert record["destination_port"] == 443
    assert record["protocol"] == "UDP"
    assert record["direction"] == "OUTBOUND"
    assert record["total_bytes"] == len(udp_packet())
    assert record["packet_sizes"] == (len(udp_packet()),)
    assert record["payload_length"] == len(b"beacon")
    assert record["payload_entropy"] == 2.585
    assert record["payload_printable_ratio"] == 1.0
    assert record["payload_simhash"] == "e627bf19152d67b3"
    assert record["raw_packet_hex"] == udp_packet().hex()
    assert record["raw_packet_link_type"] == 1
    assert record["raw_packet_captured_length"] == len(udp_packet())
    assert record["raw_packet_original_length"] == len(udp_packet())
    assert record["raw_packet_index"] == 0
    assert record["raw_packet_interface_id"] == 0


def test_payload_preview_is_bounded_and_opt_in() -> None:
    without_preview = parse_pcap(
        classic_pcap(udp_packet()),
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
    )
    with_preview = parse_pcap(
        classic_pcap(udp_packet()),
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_payload_sample_bytes=4,
    )

    assert "payload_sample_hex" not in without_preview.records[0]
    assert with_preview.records[0]["payload_sample_hex"] == b"beac".hex()


def test_parser_can_retain_packet_bytes_without_hex_amplification() -> None:
    packet = udp_packet()

    result = parse_pcap(
        classic_pcap(packet),
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes_as_bytes=True,
    )

    assert result.records[0]["raw_packet_bytes"] == packet
    assert "raw_packet_hex" not in result.records[0]


def test_targeted_payload_preview_stops_without_materializing_capture() -> None:
    inspected: list[str] = []

    def select(record: dict[str, object]) -> bool:
        inspected.append(str(record["timestamp"]))
        return True

    selected = find_pcap_record(
        classic_pcap(udp_packet(), count=3),
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        retain_payload_sample_bytes=4,
        predicate=select,
    )

    assert selected is not None
    assert selected["payload_sample_hex"] == b"beac".hex()
    assert len(inspected) == 1


def test_linux_cooked_capture_and_packet_limit() -> None:
    ethernet = udp_packet()
    cooked = b"\0" * 14 + bytes.fromhex("0800") + ethernet[14:]
    result = parse_pcap(
        classic_pcap(cooked, link_type=113),
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
    )
    assert result.link_types == (113,)
    assert result.records[0]["direction"] == "OUTBOUND"
    assert result.records[0]["raw_packet_link_type"] == 113

    with pytest.raises(PcapParseError, match="packet limit") as error:
        parse_pcap(
            classic_pcap(ethernet, count=2),
            sensor_id="uploaded",
            internal_networks=["10.0.0.0/8"],
            max_packets=1,
        )
    assert error.value.code == "PCAP_PACKET_LIMIT_EXCEEDED"


@pytest.mark.parametrize(
    "capture", [classic_pcap(udp_packet(), count=3), pcapng(udp_packet(), count=3)]
)
def test_parse_pcap_can_return_a_bounded_packet_prefix(capture: bytes) -> None:
    result = parse_pcap(
        capture,
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        max_packets=2,
        truncate_at_max_packets=True,
    )

    assert result.captured_packet_count == 2
    assert result.parsed_packet_count == 2
    assert result.truncated is True


@pytest.mark.parametrize(
    "capture", [classic_pcap(udp_packet(), count=2), pcapng(udp_packet(), count=2)]
)
def test_parse_pcap_prefix_is_complete_at_exact_packet_limit(capture: bytes) -> None:
    result = parse_pcap(
        capture,
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        max_packets=2,
        truncate_at_max_packets=True,
    )

    assert result.captured_packet_count == 2
    assert result.truncated is False


def test_classic_pcap_source_byte_limit_includes_only_complete_packet_records() -> None:
    packet = udp_packet()
    capture = classic_pcap(packet, count=2)
    first_packet_boundary = 24 + 16 + len(packet)

    exact = bounded_pcap_prefix(capture, first_packet_boundary)
    below = bounded_pcap_prefix(capture, first_packet_boundary - 1)

    assert exact.content == capture[:first_packet_boundary]
    assert exact.scanned_bytes == first_packet_boundary
    assert exact.packet_count == 1
    assert exact.byte_limited is True
    assert exact.packet_limited is False
    assert exact.truncated is True
    assert below.content == capture[:24]
    assert below.scanned_bytes == 24
    assert below.packet_count == 0
    assert below.byte_limited is True
    assert below.packet_limited is False
    assert below.truncated is True
    reparsed = parse_pcap(
        exact.content,
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
    )
    assert reparsed.captured_packet_count == 1
    assert reparsed.truncated is False


def test_bounded_prefix_distinguishes_packet_limit_from_byte_limit() -> None:
    packet = udp_packet()
    capture = classic_pcap(packet, count=2)
    first_packet_boundary = 24 + 16 + len(packet)

    prefix = bounded_pcap_prefix(capture, len(capture), max_packets=1)

    assert prefix.content == capture[:first_packet_boundary]
    assert prefix.scanned_bytes == first_packet_boundary
    assert prefix.packet_count == 1
    assert prefix.packet_limited is True
    assert prefix.byte_limited is False
    assert prefix.truncated is True


def test_strict_classic_parse_rejects_malformed_tail_after_valid_packet() -> None:
    capture = classic_pcap(udp_packet(), count=2)

    with pytest.raises(PcapParseError, match="truncated"):
        parse_pcap(
            capture[:-1],
            sensor_id="uploaded",
            internal_networks=["10.0.0.0/8"],
        )


def test_pcapng_source_byte_limit_includes_only_complete_blocks() -> None:
    packet = udp_packet()
    one_packet = pcapng(packet)
    capture = pcapng(packet, count=2)
    first_packet_boundary = len(one_packet)
    header_blocks_boundary = len(one_packet) - (32 + ((len(packet) + 3) & ~3))

    exact = bounded_pcap_prefix(capture, first_packet_boundary)
    below = bounded_pcap_prefix(capture, first_packet_boundary - 1)

    assert exact.content == capture[:first_packet_boundary]
    assert exact.scanned_bytes == first_packet_boundary
    assert exact.packet_count == 1
    assert exact.truncated is True
    assert below.content == capture[:header_blocks_boundary]
    assert below.scanned_bytes == header_blocks_boundary
    assert below.packet_count == 0
    assert below.truncated is True
    reparsed = parse_pcap(
        exact.content,
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
    )
    assert reparsed.captured_packet_count == 1
    assert reparsed.truncated is False


def test_strict_pcapng_parse_rejects_malformed_tail_after_valid_packet() -> None:
    capture = pcapng(udp_packet(), count=2)

    with pytest.raises(PcapParseError, match="block length"):
        parse_pcap(
            capture[:-1],
            sensor_id="uploaded",
            internal_networks=["10.0.0.0/8"],
        )


@pytest.mark.parametrize(
    ("valid_prefix", "malformed_tail"),
    [
        (classic_pcap(udp_packet()), b"\0" * 15),
        (
            classic_pcap(udp_packet()),
            struct.pack("<IIII", 1_784_544_001, 500_000, 8, 8) + b"x",
        ),
        (pcapng(udp_packet()), b"\0" * 11),
        (pcapng(udp_packet()), struct.pack("<II", 6, 32) + b"\0" * 4),
    ],
    ids=[
        "classic-partial-next-header",
        "classic-declared-packet-data-truncated",
        "pcapng-partial-next-header",
        "pcapng-declared-block-truncated",
    ],
)
def test_bounded_prefix_ignores_malformed_tail_outside_exact_byte_limit(
    valid_prefix: bytes, malformed_tail: bytes
) -> None:
    malformed = valid_prefix + malformed_tail

    prefix = bounded_pcap_prefix(malformed, len(valid_prefix))

    assert prefix.content == valid_prefix
    assert prefix.scanned_bytes == len(valid_prefix)
    assert prefix.packet_count == 1
    assert prefix.byte_limited is True
    assert prefix.packet_limited is False
    with pytest.raises(PcapParseError):
        bounded_pcap_prefix(malformed, len(malformed) + 1)


@pytest.mark.parametrize(
    "malformed",
    [classic_pcap(udp_packet(), count=2)[:-1], pcapng(udp_packet(), count=2)[:-1]],
)
def test_bounded_prefix_rejects_malformed_tail_when_limit_covers_full_source(
    malformed: bytes,
) -> None:
    with pytest.raises(PcapParseError):
        bounded_pcap_prefix(malformed, len(malformed))


@pytest.mark.parametrize(
    ("valid_prefix", "malformed_next_packet"),
    [
        (
            classic_pcap(udp_packet()),
            struct.pack("<IIII", 1_784_544_001, 500_000, 8, 8) + b"x",
        ),
        (
            pcapng(udp_packet()),
            struct.pack("<II", 6, 32) + b"\0" * 4,
        ),
    ],
    ids=["classic-declared-data-unavailable", "pcapng-declared-block-unavailable"],
)
def test_packet_limit_stops_before_malformed_next_packet(
    valid_prefix: bytes, malformed_next_packet: bytes
) -> None:
    malformed = valid_prefix + malformed_next_packet

    prefix = bounded_pcap_prefix(malformed, len(malformed), max_packets=1)

    assert prefix.content == valid_prefix
    assert prefix.scanned_bytes == len(valid_prefix)
    assert prefix.packet_count == 1
    assert prefix.packet_limited is True
    assert prefix.byte_limited is False
    with pytest.raises(PcapParseError):
        bounded_pcap_prefix(malformed, len(malformed))
    with pytest.raises(PcapParseError):
        bounded_pcap_prefix(malformed, len(malformed), max_packets=2)


def test_pcapng_packet_limit_keeps_valid_non_packet_blocks_before_malformed_packet() -> None:
    valid_prefix = pcapng(udp_packet())
    non_packet_body = b"metadata"
    non_packet_body += b"\0" * (-len(non_packet_body) % 4)
    non_packet_length = 12 + len(non_packet_body)
    non_packet = (
        struct.pack("<II", 4, non_packet_length)
        + non_packet_body
        + struct.pack("<I", non_packet_length)
    )
    malformed_next_packet = struct.pack("<II", 6, 32) + b"\0" * 4
    malformed = valid_prefix + non_packet + malformed_next_packet

    prefix = bounded_pcap_prefix(malformed, len(malformed), max_packets=1)

    assert prefix.content == valid_prefix + non_packet
    assert prefix.scanned_bytes == len(valid_prefix + non_packet)
    assert prefix.packet_count == 1
    assert prefix.packet_limited is True
    assert prefix.byte_limited is False


def test_malformed_and_non_ip_captures_are_rejected() -> None:
    with pytest.raises(PcapParseError, match="truncated"):
        parse_pcap(
            classic_pcap(udp_packet())[:-1],
            sensor_id="uploaded",
            internal_networks=["10.0.0.0/8"],
        )
    with pytest.raises(PcapParseError) as error:
        parse_pcap(
            classic_pcap(bytes.fromhex("ffffffffffff0000000000000806") + b"\0" * 28),
            sensor_id="uploaded",
            internal_networks=["10.0.0.0/8"],
        )
    assert error.value.code == "NO_SUPPORTED_IP_PACKETS"


def test_non_ip_segment_can_be_admitted_for_multi_segment_export() -> None:
    arp_frame = bytes.fromhex("ffffffffffff0000000000000806") + b"\0" * 28

    result = parse_pcap(
        classic_pcap(arp_frame),
        sensor_id="uploaded",
        internal_networks=["10.0.0.0/8"],
        allow_no_supported_packets=True,
    )

    assert result.records == ()
    assert result.captured_packet_count == 1
    assert result.parsed_packet_count == 0


@pytest.mark.parametrize("capture_format", ["PCAP", "PCAPNG"])
def test_packet_lengths_must_not_exceed_original_length_or_snaplen(
    capture_format: str,
) -> None:
    packet = udp_packet()
    malformed_original = bytearray(
        classic_pcap(packet) if capture_format == "PCAP" else pcapng(packet)
    )
    malformed_snaplen = bytearray(malformed_original)
    if capture_format == "PCAP":
        struct.pack_into("<I", malformed_original, 36, len(packet) - 1)
        struct.pack_into("<I", malformed_snaplen, 16, len(packet) - 1)
    else:
        section_length = struct.unpack_from("<I", malformed_original, 4)[0]
        interface_length = struct.unpack_from("<I", malformed_original, section_length + 4)[0]
        packet_offset = section_length + interface_length
        struct.pack_into("<I", malformed_original, packet_offset + 24, len(packet) - 1)
        struct.pack_into("<I", malformed_snaplen, section_length + 12, len(packet) - 1)

    for capture in (malformed_original, malformed_snaplen):
        with pytest.raises(PcapParseError, match="length"):
            parse_pcap(
                bytes(capture),
                sensor_id="uploaded",
                internal_networks=["10.0.0.0/8"],
            )
