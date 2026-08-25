from __future__ import annotations

import io
import struct

import pytest

from c2hunter_analysis.pcap import PcapParseError
from c2hunter_analysis.pcap_index import (
    StructuralIndexLimitError,
    StructuralInterfaceEntry,
    StructuralPacketEntry,
    scan_structural_packet_index,
)


def _classic(
    magic: bytes = b"\xd4\xc3\xb2\xa1",
    *,
    endian: str = "<",
    packets: tuple[tuple[int, int, bytes, int], ...] = ((7, 11, b"abc", 5),),
    snaplen: int = 65_535,
) -> bytes:
    data = bytearray(magic)
    data.extend(struct.pack(f"{endian}HHIIII", 2, 4, 0, 0, snaplen, 1))
    for seconds, fraction, payload, original_length in packets:
        data.extend(struct.pack(f"{endian}IIII", seconds, fraction, len(payload), original_length))
        data.extend(payload)
    return bytes(data)


def test_classic_one_packet_emits_exact_structural_offsets() -> None:
    capture = _classic()

    result = scan_structural_packet_index(io.BytesIO(capture), max_packets=10, max_interfaces=2)

    assert result.capture_format == "PCAP"
    assert result.size_bytes == len(capture)
    assert result.interfaces == (StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0),)
    assert result.packets == (StructuralPacketEntry(0, 24, 40, 3, 5, 19, 0, 0, 0, 7_000_011),)


@pytest.mark.parametrize(
    ("magic", "endian", "resolution"),
    [
        (b"\xd4\xc3\xb2\xa1", "<", 1_000_000),
        (b"\xa1\xb2\xc3\xd4", ">", 1_000_000),
        (b"\x4d\x3c\xb2\xa1", "<", 1_000_000_000),
        (b"\xa1\xb2\x3c\x4d", ">", 1_000_000_000),
    ],
)
def test_classic_all_magic_variants_preserve_physical_order(
    magic: bytes, endian: str, resolution: int
) -> None:
    result = scan_structural_packet_index(
        io.BytesIO(
            _classic(
                magic,
                endian=endian,
                packets=((9, 7, b"a", 2), (8, 6, b"bc", 4)),
            )
        ),
        max_packets=2,
        max_interfaces=1,
    )
    assert [packet.packet_index for packet in result.packets] == [0, 1]
    assert [packet.record_offset for packet in result.packets] == [24, 41]
    assert [packet.raw_timestamp_ticks for packet in result.packets] == [
        9 * resolution + 7,
        8 * resolution + 6,
    ]


def _ng_block(endian: str, block_type: int, body: bytes) -> bytes:
    length = 12 + len(body)
    return struct.pack(f"{endian}II", block_type, length) + body + struct.pack(f"{endian}I", length)


def _ng_section(endian: str) -> bytes:
    body = struct.pack(f"{endian}IHHq", 0x1A2B3C4D, 1, 0, -1)
    return _ng_block(endian, 0x0A0D0D0A, body)


def _ng_idb(endian: str, *, snaplen: int, exponent: int, offset: int) -> bytes:
    options = (
        struct.pack(f"{endian}HH", 9, 1)
        + bytes([exponent])
        + b"\0" * 3
        + struct.pack(f"{endian}HHq", 14, 8, offset)
        + struct.pack(f"{endian}HH", 0, 0)
    )
    return _ng_block(endian, 1, struct.pack(f"{endian}HHI", 1, 0, snaplen) + options)


def _ng_packet(endian: str, block_type: int, payload: bytes, ticks: int) -> bytes:
    padding = b"\0" * ((-len(payload)) % 4)
    if block_type == 6:
        fixed = struct.pack(
            f"{endian}IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(payload), len(payload) + 2
        )
    else:
        fixed = struct.pack(
            f"{endian}HHIIII",
            0,
            0,
            ticks >> 32,
            ticks & 0xFFFFFFFF,
            len(payload),
            len(payload) + 2,
        )
    return _ng_block(endian, block_type, fixed + payload + padding)


def test_pcapng_sections_interfaces_padding_unknown_and_exact_timestamp_options() -> None:
    unknown = _ng_block("<", 0xBAD, b"x" * (64 * 1024 + 4))
    first = _ng_packet("<", 6, b"abc", (3 << 32) | 4)
    second = _ng_packet(">", 2, b"12345", 9)
    capture = (
        _ng_section("<")
        + _ng_idb("<", snaplen=100, exponent=0x8A, offset=-7)
        + unknown
        + first
        + _ng_section(">")
        + _ng_idb(">", snaplen=200, exponent=7, offset=11)
        + second
    )

    result = scan_structural_packet_index(io.BytesIO(capture), max_packets=2, max_interfaces=2)

    assert result.capture_format == "PCAPNG"
    assert [
        (item.section_index, item.interface_id, item.interface_ordinal)
        for item in result.interfaces
    ] == [
        (0, 0, 0),
        (1, 0, 1),
    ]
    assert [
        (item.timestamp_resolution_denominator, item.timestamp_offset_seconds)
        for item in result.interfaces
    ] == [
        (2**10, -7),
        (10**7, 11),
    ]
    assert [packet.raw_timestamp_ticks for packet in result.packets] == [(3 << 32) | 4, 9]
    assert result.packets[0].record_offset == capture.index(first)
    assert result.packets[1].record_offset == capture.index(second)
    assert result.packets[0].captured_length == 3
    assert result.packets[0].framed_length == len(first)
    assert result.packets[1].interface_ordinal == 1


class _BoundedReader(io.BytesIO):
    def __init__(self, value: bytes) -> None:
        super().__init__(value)
        self.requests: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.requests.append(size)
        assert 0 < size <= 64 * 1024
        return super().read(size)


def test_unknown_pcapng_blocks_are_discarded_with_bounded_reads() -> None:
    reader = _BoundedReader(
        _ng_section("<")
        + _ng_idb("<", snaplen=100, exponent=6, offset=0)
        + _ng_block("<", 99, b"z" * (3 * 64 * 1024))
        + _ng_packet("<", 6, b"a", 1)
    )
    result = scan_structural_packet_index(reader, max_packets=1, max_interfaces=1)
    assert result.packet_count == 1
    assert max(reader.requests) <= 64 * 1024


def test_pcapng_simple_packet_and_bad_trailer_are_rejected_atomically() -> None:
    prefix = _ng_section("<") + _ng_idb("<", snaplen=100, exponent=6, offset=0)
    simple = _ng_block("<", 3, struct.pack("<I", 1) + b"abcd")
    with pytest.raises(PcapParseError, match="no timestamp") as raised:
        scan_structural_packet_index(io.BytesIO(prefix + simple), max_packets=2, max_interfaces=1)
    assert raised.value.code == "UNSUPPORTED_PCAPNG_BLOCK"

    packet = bytearray(_ng_packet("<", 6, b"abc", 1))
    packet[-4:] = struct.pack("<I", len(packet) + 4)
    with pytest.raises(PcapParseError, match="trailer does not match"):
        scan_structural_packet_index(io.BytesIO(prefix + packet), max_packets=2, max_interfaces=1)


@pytest.mark.parametrize("resolution", [1_000_000, 1_000_000_000])
def test_classic_timestamp_fraction_matches_decoder_acceptance_and_preserves_raw_ticks(
    resolution: int,
) -> None:
    magic = b"\xd4\xc3\xb2\xa1" if resolution == 1_000_000 else b"\x4d\x3c\xb2\xa1"
    fraction = resolution + 17
    capture = _classic(magic, packets=((1, fraction, b"a", 1),))

    result = scan_structural_packet_index(io.BytesIO(capture), max_packets=1, max_interfaces=1)

    assert result.packets[0].raw_timestamp_ticks == resolution + fraction


def test_packet_limit_is_inclusive_only_for_the_complete_capture() -> None:
    capture = _classic(packets=((1, 1, b"a", 1), (2, 2, b"b", 1)))
    result = scan_structural_packet_index(io.BytesIO(capture), max_packets=2, max_interfaces=1)
    assert result.packet_count == 2
    with pytest.raises(StructuralIndexLimitError, match="packet limit exceeded"):
        scan_structural_packet_index(io.BytesIO(capture), max_packets=1, max_interfaces=1)
