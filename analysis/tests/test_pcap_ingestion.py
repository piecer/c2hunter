from __future__ import annotations

import ipaddress
import struct

import pytest

from c2hunter_analysis.pcap import PcapParseError, find_pcap_record, parse_pcap


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


def pcapng(packet: bytes) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    timestamp = 1_784_544_000_500_000
    enhanced = block(
        6,
        struct.pack("<IIIII", 0, timestamp >> 32, timestamp & 0xFFFFFFFF, len(packet), len(packet))
        + packet,
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

    with pytest.raises(PcapParseError, match="packet limit") as error:
        parse_pcap(
            classic_pcap(ethernet, count=2),
            sensor_id="uploaded",
            internal_networks=["10.0.0.0/8"],
            max_packets=1,
        )
    assert error.value.code == "PCAP_PACKET_LIMIT_EXCEEDED"


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
