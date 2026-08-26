from __future__ import annotations

import io
import struct
from datetime import UTC, datetime

import pytest

from c2hunter_analysis.pcap import PcapParseError
from c2hunter_analysis.pcap_export import (
    CaptureInterface,
    PacketLocator,
    export_packet_from_structural_locator,
    export_timestamp_from_ticks,
    open_export_capture,
    project_export_packet,
)


def _ipv4_udp() -> bytes:
    ip = bytes.fromhex("4500002000000000401100000a00000108080808")
    udp = bytes.fromhex("04d20035000c0000") + b"dns!"
    return b"\x00" * 12 + bytes.fromhex("0800") + ip + udp


def test_shared_projection_and_structural_packet_match_existing_semantics() -> None:
    raw = _ipv4_udp()
    projection = project_export_packet(raw, link_type=1, internal_networks=("10.0.0.0/8",))
    interface = CaptureInterface(0, 0, 0, 1, 65535, 1, 1_000_000, 0)
    locator = PacketLocator("source", 2, 3, 24, 40, len(raw), 16 + len(raw))

    packet = export_packet_from_structural_locator(
        raw,
        locator=locator,
        interface=interface,
        original_length=len(raw),
        raw_timestamp_ticks=1_500_000,
        internal_networks=("10.0.0.0/8",),
    )

    assert packet.timestamp == datetime(1970, 1, 1, 0, 0, 1, 500000, tzinfo=UTC)
    assert projection == ("10.0.0.1", "8.8.8.8", 1234, 53, "UDP", "OUTBOUND", True, True)
    assert packet.raw_packet_bytes == raw
    assert packet.locator == locator


@pytest.mark.parametrize(
    ("ticks", "numerator", "denominator", "offset", "expected"),
    [
        (1_000_001, 1, 1_000_000, 0, datetime(1970, 1, 1, 0, 0, 1, 1, UTC)),
        (
            1_000_000_001,
            1,
            1_000_000_000,
            0,
            datetime(1970, 1, 1, 0, 0, 1, tzinfo=UTC),
        ),
        (3, 1, 2, -1, datetime(1970, 1, 1, 0, 0, 0, 500000, UTC)),
    ],
)
def test_structural_timestamp_reuses_float_compatibility(
    ticks: int, numerator: int, denominator: int, offset: int, expected: datetime
) -> None:
    assert (
        export_timestamp_from_ticks(
            ticks, numerator=numerator, denominator=denominator, offset_seconds=offset
        )
        == expected
    )


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize(
    ("resolution", "fraction"),
    [
        (1_000_000, 0),
        (1_000_000, 1),
        (1_000_000, 30_000),
        (1_000_000, 999_999),
        (1_000_000_000, 0),
        (1_000_000_000, 1),
        (1_000_000_000, 30_000),
        (1_000_000_000, 999_999_999),
    ],
)
def test_classic_timestamp_exactly_preserves_legacy_operation_order_for_decoder_and_locator(
    endian: str, resolution: int, fraction: int
) -> None:
    seconds = 0xFFFFFFFF
    magic = {
        ("<", 1_000_000): b"\xd4\xc3\xb2\xa1",
        (">", 1_000_000): b"\xa1\xb2\xc3\xd4",
        ("<", 1_000_000_000): b"\x4d\x3c\xb2\xa1",
        (">", 1_000_000_000): b"\xa1\xb2\x3c\x4d",
    }[(endian, resolution)]
    capture = magic + struct.pack(
        f"{endian}HHIIIIIIII", 2, 4, 0, 0, 65_535, 1, seconds, fraction, 0, 0
    )
    sequential = tuple(
        open_export_capture(
            io.BytesIO(capture),
            source_id="source",
            source_order=0,
            internal_networks=("10.0.0.0/8",),
        ).iter_packets()
    )[0]
    reconstructed = export_packet_from_structural_locator(
        b"",
        locator=sequential.locator,
        interface=sequential.interface,
        original_length=0,
        raw_timestamp_ticks=seconds * resolution + fraction,
        internal_networks=("10.0.0.0/8",),
    )
    legacy_oracle = datetime.fromtimestamp(seconds + fraction / resolution, UTC)

    assert sequential.timestamp == legacy_oracle
    assert reconstructed.timestamp == legacy_oracle
    assert reconstructed == sequential


def test_structural_packet_rejects_length_and_interface_mismatches() -> None:
    interface = CaptureInterface(1, 2, 3, 1, 8, 1, 1_000_000, 0)
    locator = PacketLocator("s", 0, 0, 0, 16, 4, 20)
    with pytest.raises(PcapParseError):
        export_packet_from_structural_locator(
            b"abc",
            locator=locator,
            interface=interface,
            original_length=4,
            raw_timestamp_ticks=0,
            internal_networks=("10.0.0.0/8",),
        )
    with pytest.raises(PcapParseError):
        export_packet_from_structural_locator(
            b"abcd",
            locator=locator,
            interface=interface,
            original_length=3,
            raw_timestamp_ticks=0,
            internal_networks=("10.0.0.0/8",),
        )


def test_zero_length_and_unsupported_link_require_no_reader() -> None:
    interface = CaptureInterface(0, 0, 0, 999, 8, 1, 1_000_000, 0)
    locator = PacketLocator("s", 0, 0, 0, 16, 0, 16)
    packet = export_packet_from_structural_locator(
        b"",
        locator=locator,
        interface=interface,
        original_length=0,
        raw_timestamp_ticks=0,
        internal_networks=("10.0.0.0/8",),
    )
    assert packet.supported is False
    assert packet.raw_packet_bytes == b""


def test_structural_reconstruction_preserves_order_duplicates_and_timestamp_parity() -> None:
    first = _ipv4_udp()
    second = b"\x00" * len(first)
    records = ((2, 500_000, first), (2, 500_000, first), (1, 900_000, second))
    capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1) + b"".join(
        struct.pack("<IIII", seconds, fraction, len(raw), len(raw)) + raw
        for seconds, fraction, raw in records
    )
    sequential = tuple(
        open_export_capture(
            io.BytesIO(capture),
            source_id="source",
            source_order=7,
            internal_networks=("10.0.0.0/8",),
        ).iter_packets()
    )
    reconstructed = tuple(
        export_packet_from_structural_locator(
            packet.raw_packet_bytes,
            locator=packet.locator,
            interface=packet.interface,
            original_length=packet.original_length,
            raw_timestamp_ticks=seconds * 1_000_000 + fraction,
            internal_networks=("10.0.0.0/8",),
        )
        for packet, (seconds, fraction, _raw) in zip(sequential, records, strict=True)
    )

    assert reconstructed == sequential
    assert [packet.locator.packet_index for packet in reconstructed] == [0, 1, 2]
    assert reconstructed[0].raw_packet_bytes == reconstructed[1].raw_packet_bytes
    assert reconstructed[0].locator != reconstructed[1].locator
    assert reconstructed[0].timestamp == reconstructed[1].timestamp
    assert reconstructed[2].timestamp < reconstructed[1].timestamp
