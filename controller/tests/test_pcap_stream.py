from __future__ import annotations

import hashlib
import io
import struct
from datetime import UTC, datetime

import pytest
from c2hunter_analysis.pcap import PcapParseError, bounded_pcap_prefix
from c2hunter_analysis.pcap_export import open_export_capture

from c2hunter_controller.pcap_stream import (
    CaptureIntegrityError,
    MatchedPacketRecord,
    VerifiedMatchedPackets,
    open_bounded_verified_capture,
)
from c2hunter_controller.repositories import CaptureSource


def _classic(*packets: bytes) -> bytes:
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        content += struct.pack("<IIII", index + 1, 0, len(packet), len(packet)) + packet
    return bytes(content)


def _block(kind: int, body: bytes = b"") -> bytes:
    body += b"\0" * (-len(body) % 4)
    length = len(body) + 12
    return struct.pack("<II", kind, length) + body + struct.pack("<I", length)


def _pcapng(*blocks: bytes) -> bytes:
    return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)) + b"".join(blocks)


def _epb(packet: bytes = b"\0" * 14) -> bytes:
    return _block(6, struct.pack("<IIIII", 0, 0, 1, len(packet), len(packet)) + packet)


def _source(content: bytes, *, version: str = "opaque-v1") -> CaptureSource:
    return CaptureSource(io.BytesIO(content), version)


def _open(content: bytes, max_bytes: int, max_packets: int = 100):
    return open_bounded_verified_capture(
        _source(content),
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        max_admitted_bytes=max_bytes,
        max_admitted_packets=max_packets,
    )


def test_verified_matched_adapter_preserves_identity_and_is_one_shot() -> None:
    content = _classic(b"\0" * 14)
    session = _open(content, len(content), 1)
    decoder = open_export_capture(
        session.reader, source_id="opaque-source", source_order=3, internal_networks=["10.0.0.0/8"]
    )
    packet = next(decoder.iter_packets())
    record = MatchedPacketRecord.from_export_packet(packet, sensor_id="sensor-a")
    session.drain_and_verify()
    records = VerifiedMatchedPackets((record,))
    assert [item.source_id for item in records] == ["opaque-source"]
    assert record.source_order == 3
    assert record.section_index == 0
    assert record.interface_id == 0
    assert record.interface_ordinal == 0
    assert record.captured_length == 14
    assert record.raw_packet_bytes == b"\0" * 14
    with pytest.raises(RuntimeError, match="only be iterated once"):
        list(records)


def test_legacy_matched_adapter_populates_deterministic_typed_shape() -> None:
    timestamp = datetime(2026, 8, 24, 1, 2, 3, tzinfo=UTC)
    record = MatchedPacketRecord.from_legacy_record(
        {
            "source_id": "legacy-source",
            "raw_packet_source_order": 4,
            "raw_packet_index": 7,
            "section_index": 2,
            "raw_packet_interface_local_id": 3,
            "raw_packet_interface_id": 5,
            "raw_packet_link_type": 101,
            "timestamp": timestamp.isoformat(),
            "raw_packet_hex": "010203",
            "raw_packet_captured_length": 3,
            "raw_packet_original_length": 9,
            "sensor_id": "sensor-z",
            "source_ip": "10.0.0.1",
            "destination_ip": "203.0.113.7",
            "source_port": 51000,
            "destination_port": 443,
            "protocol": "UDP",
            "direction": "OUTBOUND",
            "has_payload": True,
        },
        source_job_id="job-a",
        fallback_packet_index=99,
        default_sensor_id="sensor-default",
    )

    assert record == MatchedPacketRecord(
        source_id="legacy-source",
        source_order=4,
        packet_index=7,
        section_index=2,
        interface_id=3,
        interface_ordinal=5,
        link_type=101,
        timestamp=timestamp,
        raw_packet_bytes=b"\x01\x02\x03",
        captured_length=3,
        original_length=9,
        sensor_id="sensor-z",
        source_ip="10.0.0.1",
        destination_ip="203.0.113.7",
        source_port=51000,
        destination_port=443,
        protocol="UDP",
        direction="OUTBOUND",
        has_payload=True,
    )


@pytest.mark.parametrize(
    ("expected_size", "expected_sha256"),
    [(-1, "0" * 64), (1, "short"), (1, "z" * 64)],
)
def test_factory_validation_closes_owned_source_once(
    expected_size: int, expected_sha256: str
) -> None:
    class CountingClose(io.BytesIO):
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            super().close()

    stream = CountingClose(b"x")
    source = CaptureSource(stream, "factory-validation-v1")

    with pytest.raises(ValueError):
        open_bounded_verified_capture(
            source,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            max_admitted_bytes=1,
            max_admitted_packets=1,
        )

    assert source.closed
    assert stream.close_calls == 1


def test_integrity_reader_drains_short_reads_verifies_and_closes() -> None:
    class Short(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            return super().read(min(size, 3))

    content = _classic(b"abc") + b"discarded-tail"
    source = CaptureSource(Short(content), "opaque-v7")
    session = open_bounded_verified_capture(
        source,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        max_admitted_bytes=len(_classic(b"abc")),
        max_admitted_packets=1,
    )
    assert session.reader.read(4) == content[:4]
    result = session.drain_and_verify()
    assert result.actual_size == len(content)
    assert result.actual_sha256 == hashlib.sha256(content).hexdigest()
    assert result.verified_version_id == "opaque-v7"
    assert source.closed
    session.close()
    assert source.closed


def test_admitted_read_failure_is_preserved_through_final_verification() -> None:
    class FailingRead(io.BytesIO):
        def read(self, size: int = -1) -> bytes:
            raise OSError("backend unavailable")

    content = _classic(b"abc")
    source = CaptureSource(FailingRead(content), "opaque-failing-read")
    session = open_bounded_verified_capture(
        source,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        max_admitted_bytes=len(content),
        max_admitted_packets=1,
    )

    with pytest.raises(CaptureIntegrityError, match="backend unavailable"):
        session.reader.read(4)
    with pytest.raises(CaptureIntegrityError, match="backend unavailable"):
        session.drain_and_verify()
    assert source.closed


def test_close_failure_prevents_successful_verification() -> None:
    class FailingClose(io.BytesIO):
        def close(self) -> None:
            raise OSError("close unavailable")

    content = _classic(b"abc")
    source = CaptureSource(FailingClose(content), "opaque-failing-close")
    session = open_bounded_verified_capture(
        source,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        max_admitted_bytes=len(content),
        max_admitted_packets=1,
    )

    with pytest.raises(CaptureIntegrityError, match="close unavailable"):
        session.drain_and_verify()
    assert source.closed


@pytest.mark.parametrize("kind", ["size", "digest"])
def test_integrity_mismatch_closes(kind: str) -> None:
    content = _classic(b"x")
    source = _source(content)
    session = open_bounded_verified_capture(
        source,
        expected_size=len(content) + (kind == "size"),
        expected_sha256=("0" * 64 if kind == "digest" else hashlib.sha256(content).hexdigest()),
        max_admitted_bytes=len(content),
        max_admitted_packets=1,
    )
    with pytest.raises(CaptureIntegrityError):
        session.drain_and_verify()
    assert source.closed


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_classic_admission_matches_materialized_oracle(delta: int) -> None:
    content = _classic(b"abc", b"defgh")
    limit = 24 + 16 + 3 + delta
    session = _open(content, limit)
    admitted = b"".join(iter(lambda: session.reader.read(7), b""))
    result = session.drain_and_verify()
    oracle = bounded_pcap_prefix(content, limit, max_packets=100)
    assert admitted == oracle.content
    assert (result.admitted_bytes, result.admitted_packets) == (
        oracle.scanned_bytes,
        oracle.packet_count,
    )
    assert (result.byte_limited, result.packet_limited) == (
        oracle.byte_limited,
        oracle.packet_limited,
    )


@pytest.mark.parametrize("limit", [68, 69, 70])
def test_classic_coincident_limits_match_byte_reason_precedence(limit: int) -> None:
    content = _classic(b"a" * 29, b"b")
    session = _open(content, limit, 1)
    admitted = b"".join(iter(lambda: session.reader.read(7), b""))
    result = session.drain_and_verify()
    oracle = bounded_pcap_prefix(content, limit, max_packets=1)

    assert admitted == oracle.content
    assert (result.admitted_bytes, result.admitted_packets) == (
        oracle.scanned_bytes,
        oracle.packet_count,
    )
    assert (result.byte_limited, result.packet_limited) == (
        oracle.byte_limited,
        oracle.packet_limited,
    )


def test_classic_header_cap_and_packet_cap() -> None:
    content = _classic(b"abc", b"def")
    tiny = _open(content, 23)
    assert tiny.reader.read() == b""
    assert tiny.drain_and_verify().byte_limited
    capped = _open(content, len(content), 1)
    admitted = b"".join(iter(lambda: capped.reader.read(99), b""))
    result = capped.drain_and_verify()
    assert admitted == _classic(b"abc")
    assert result.packet_limited and result.admitted_packets == 1


def test_malformed_classic_tail_outside_boundary_is_invisible() -> None:
    prefix = _classic(b"abc")
    content = prefix + struct.pack("<IIII", 1, 0, 100, 100) + b"x"
    session = _open(content, len(prefix), 1)
    decoder = open_export_capture(
        session.reader, source_id="opaque", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    assert len(list(decoder.iter_packets())) == 1
    result = session.drain_and_verify()
    oracle = bounded_pcap_prefix(content, len(prefix), max_packets=1)
    assert oracle.content == prefix
    assert (result.admitted_bytes, result.admitted_packets) == (
        oracle.scanned_bytes,
        oracle.packet_count,
    )
    assert (
        (result.byte_limited, result.packet_limited)
        == (
            oracle.byte_limited,
            oracle.packet_limited,
        )
        == (True, False)
    )


def test_truncated_classic_record_is_not_counted_as_an_admitted_packet() -> None:
    content = _classic() + struct.pack("<IIII", 1, 0, 3, 3) + b"x"
    session = _open(content, len(content))
    decoder = open_export_capture(
        session.reader,
        source_id="opaque",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )

    with pytest.raises(PcapParseError):
        list(decoder.iter_packets())
    assert session.drain_and_verify().admitted_packets == 0


@pytest.mark.parametrize("limit", [23, 24, 25, 26, 27, 28])
def test_pcapng_initial_section_is_atomic_at_byte_cap(limit: int) -> None:
    content = _pcapng()
    session = _open(content, limit)
    admitted = b"".join(iter(lambda: session.reader.read(5), b""))
    result = session.drain_and_verify()
    oracle = bounded_pcap_prefix(content, limit, max_packets=100)

    assert admitted == oracle.content
    assert result.admitted_bytes == oracle.scanned_bytes
    assert result.byte_limited == oracle.byte_limited


def test_large_pcapng_initial_section_stays_parser_invisible_beyond_cap() -> None:
    content = _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + b"x" * 1_000_000)
    source = _source(content)
    session = open_bounded_verified_capture(
        source,
        expected_size=len(content),
        expected_sha256=hashlib.sha256(content).hexdigest(),
        max_admitted_bytes=28,
        max_admitted_packets=100,
    )

    assert session.reader.read() == b""
    result = session.drain_and_verify()
    assert result.admitted_bytes == 0
    assert result.byte_limited
    assert result.actual_size == len(content)
    assert source.closed


def test_pcapng_admission_matches_oracle_and_keeps_metadata_after_packet_cap() -> None:
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535))
    metadata = _block(4, b"metadata")
    first = _epb()
    second = _epb()
    content = _pcapng(idb, first, metadata, second)
    limit = len(content)
    session = _open(content, limit, 1)
    admitted = b"".join(iter(lambda: session.reader.read(5), b""))
    result = session.drain_and_verify()
    oracle = bounded_pcap_prefix(content, limit, max_packets=1)
    assert admitted == oracle.content
    assert admitted.endswith(metadata)
    assert result.packet_limited and result.admitted_packets == 1


def test_pcapng_malformed_intervening_metadata_is_visible() -> None:
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535))
    bad = bytearray(_block(4, b"meta"))
    bad[-4:] = struct.pack("<I", 999)
    content = _pcapng(idb, _epb(), bytes(bad), _epb())
    session = _open(content, len(content), 1)
    decoder = open_export_capture(
        session.reader, source_id="opaque", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    with pytest.raises(PcapParseError, match="trailer"):
        list(decoder.iter_packets())
    session.drain_and_verify()


def test_pcapng_malformed_next_packet_is_invisible_after_cap() -> None:
    idb = _block(1, struct.pack("<HHI", 1, 0, 65535))
    malformed_next = struct.pack("<II", 6, 8)
    content = _pcapng(idb, _epb(), malformed_next)
    session = _open(content, len(content), 1)
    decoder = open_export_capture(
        session.reader, source_id="opaque", source_order=0, internal_networks=["10.0.0.0/8"]
    )
    assert len(list(decoder.iter_packets())) == 1
    assert session.drain_and_verify().packet_limited
