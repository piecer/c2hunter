from __future__ import annotations

import struct
from datetime import UTC, datetime

from c2hunter_analysis.pcap import parse_pcap

from c2hunter_controller.pcap import build_capture, filter_records


def _record(
    *,
    link_type: int = 1,
    original_length: int = 4,
    source_order: int = 0,
    packet_index: int = 0,
    interface_id: int = 0,
    timestamp: datetime | None = None,
) -> dict[str, object]:
    return {
        "timestamp": timestamp or datetime(2026, 8, 21, 9, 0, tzinfo=UTC),
        "source_ip": "10.0.0.8",
        "destination_ip": "203.0.113.8",
        "source_port": 51000,
        "destination_port": 443,
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "sensor_id": "sensor-a",
        "payload_hash": "hash",
        "raw_packet_hex": "01020304",
        "raw_packet_link_type": link_type,
        "raw_packet_captured_length": 4,
        "raw_packet_original_length": original_length,
        "raw_packet_source_order": source_order,
        "raw_packet_index": packet_index,
        "raw_packet_interface_id": interface_id,
    }


def test_build_capture_preserves_single_link_type_and_packet_lengths() -> None:
    capture, count, capture_format = build_capture([_record(link_type=113, original_length=60)])

    assert count == 1
    assert capture_format == "PCAP"
    assert struct.unpack_from("<I", capture, 20)[0] == 113
    assert struct.unpack_from("<II", capture, 32) == (4, 60)


def test_build_capture_uses_pcapng_for_mixed_link_types() -> None:
    ethernet_ipv4_udp = (
        "00000000000000000000000008004500001c00000000401100000a000005cb007107c35001bb00080000"
    )
    first = {
        **_record(original_length=len(bytes.fromhex(ethernet_ipv4_udp))),
        "raw_packet_hex": ethernet_ipv4_udp,
    }
    second = {**_record(link_type=113), "raw_packet_index": 1}
    capture, count, capture_format = build_capture([first, second])

    assert count == 2
    assert capture_format == "PCAPNG"
    assert capture[:4] == bytes.fromhex("0a0d0d0a")
    reparsed = parse_pcap(
        capture,
        sensor_id="roundtrip",
        internal_networks=["10.0.0.0/8"],
        max_packets=10,
    )
    assert reparsed.captured_packet_count == 2


def test_build_capture_preserves_distinct_interfaces_with_the_same_link_type() -> None:
    capture, count, capture_format = build_capture(
        [_record(source_order=0), _record(source_order=1)]
    )

    assert count == 2
    assert capture_format == "PCAPNG"


def test_build_capture_preserves_source_packet_order_when_timestamps_regress() -> None:
    first = {
        **_record(timestamp=datetime(2026, 8, 21, 9, 0, 1, tzinfo=UTC)),
        "raw_packet_hex": "01020304",
    }
    second = {
        **_record(packet_index=1, timestamp=datetime(2026, 8, 21, 9, 0, tzinfo=UTC)),
        "raw_packet_hex": "05060708",
    }

    capture, _, _ = build_capture([first, second])

    assert capture[40:44] == bytes.fromhex("01020304")
    assert capture[60:64] == bytes.fromhex("05060708")


def test_build_capture_uses_pcapng_for_timestamps_outside_classic_range() -> None:
    capture, _, capture_format = build_capture(
        [_record(timestamp=datetime(2107, 1, 1, tzinfo=UTC))]
    )

    assert capture_format == "PCAPNG"
    assert capture[:4] == bytes.fromhex("0a0d0d0a")


def test_build_capture_uses_pcapng_for_negative_timestamps() -> None:
    capture, _, capture_format = build_capture(
        [_record(timestamp=datetime(1960, 1, 1, tzinfo=UTC))]
    )

    assert capture_format == "PCAPNG"
    assert capture[:4] == bytes.fromhex("0a0d0d0a")


def test_filter_records_applies_nested_include_and_exclude_groups() -> None:
    included = _record()
    excluded = {**_record(), "destination_ip": "198.51.100.7"}

    result = filter_records(
        [included, excluded],
        {
            "include_filters": [{"candidate_ip": "0.0.0.0/0", "port": 443}],
            "exclude_filters": [{"candidate_ip": "198.51.100.0/24"}],
        },
        internal_networks=["10.0.0.0/8"],
    )

    assert result == [included]
