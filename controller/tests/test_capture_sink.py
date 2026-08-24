from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from c2hunter_controller import capture_sink, pcap
from c2hunter_controller.capture_sink import (
    CaptureArtifact,
    CaptureLimitTooSmall,
    CaptureRecordError,
    CaptureSink,
    CaptureStorageError,
)
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap import ExportPacketRecord, build_capture_to_sink


def record(
    index: int = 0,
    *,
    source: int = 0,
    source_id: str = "source-a",
    interface: int = 0,
    link_type: int = 1,
    timestamp: datetime | None = None,
    payload: bytes = b"data",
    original_length: int | None = None,
) -> ExportPacketRecord:
    return ExportPacketRecord(
        timestamp or datetime(2026, 8, 24, 1, 2, 3, 456789, tzinfo=UTC),
        source_id,
        source,
        index,
        0,
        interface,
        interface,
        link_type,
        payload,
        len(payload),
        original_length if original_length is not None else len(payload),
    )


def test_sink_accepts_exact_fit_rejects_overflow_and_rolls_over() -> None:
    sink = CaptureSink(max_output_bytes=8, spool_max_memory_bytes=3)
    try:
        assert sink.write_unit(b"ab", b"cd") is True
        assert sink.rolled is True
        assert sink.write_unit(b"efgh") is True
        assert sink.write_unit(b"i") is False
        assert sink.size_bytes == 8
        assert sink.read_bytes() == b"abcdefgh"
    finally:
        sink.close()
        sink.close()


@pytest.mark.parametrize("configured", ["", "   \t"])
def test_blank_spool_directory_uses_system_temp_for_rollover(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, configured: str
) -> None:
    monkeypatch.setenv("C2HUNTER_PCAP_EXPORT_SPOOL_DIRECTORY", configured)
    settings = Settings(environment="test")
    assert settings.pcap_export_spool_directory is None

    nonwritable = tmp_path / "nonwritable"
    nonwritable.mkdir(mode=0o500)
    previous_cwd = Path.cwd()
    os.chdir(nonwritable)
    try:
        sink = CaptureSink(
            max_output_bytes=8,
            spool_max_memory_bytes=1,
            spool_directory=settings.pcap_export_spool_directory,
        )
        try:
            assert sink.write_unit(b"rollover")
            assert sink.rolled
            assert sink.read_bytes() == b"rollover"
        finally:
            sink.close()
    finally:
        os.chdir(previous_cwd)


def test_explicit_spool_directory_is_preserved_and_bad_path_is_not_masked(tmp_path: Path) -> None:
    explicit = str(tmp_path / "explicit")
    configured = Settings(environment="test", pcap_export_spool_directory=explicit)
    assert configured.pcap_export_spool_directory == explicit
    missing = tmp_path / "missing"
    sink = CaptureSink(
        max_output_bytes=8,
        spool_max_memory_bytes=1,
        spool_directory=str(missing),
    )
    with pytest.raises(CaptureStorageError):
        sink.write_unit(b"rollover")
    sink.close()
    assert not missing.exists()


def test_compose_effective_blank_spool_directory_is_safe() -> None:
    repository = Path(__file__).resolve().parents[2]
    try:
        completed = subprocess.run(
            [
                "docker",
                "compose",
                "--env-file",
                ".env.example",
                "config",
                "--format",
                "json",
            ],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        pytest.skip(f"Docker Compose unavailable: {exc}")
    effective = json.loads(completed.stdout)["services"]["controller"]["environment"]
    settings = Settings(
        environment="test",
        pcap_export_spool_directory=effective["C2HUNTER_PCAP_EXPORT_SPOOL_DIRECTORY"],
    )
    assert settings.pcap_export_spool_directory is None


def test_classic_writer_is_one_pass_and_exact_at_boundaries() -> None:
    iterations = 0

    def records():
        nonlocal iterations
        iterations += 1
        yield record()

    for cap, exported, size in ((43, 0, 24), (44, 1, 44), (45, 1, 44)):
        artifact = build_capture_to_sink(records(), max_output_bytes=cap, spool_max_memory_bytes=8)
        with artifact:
            assert artifact.capture_format == "PCAP"
            assert artifact.matched_packet_count == 1
            assert artifact.exported_packet_count == exported
            assert artifact.omitted_packet_count == 1 - exported
            assert artifact.size_bytes == size
            assert artifact.sha256 == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert iterations == 3


def test_classic_header_limit_is_exact() -> None:
    with pytest.raises(CaptureLimitTooSmall, match="too small for the PCAP header"):
        build_capture_to_sink([], max_output_bytes=23, spool_max_memory_bytes=8)


def test_multiple_logical_interfaces_use_atomic_pcapng_idb_and_epb() -> None:
    records = [record(), record(1, source=1, source_id="source-b")]
    full = build_capture_to_sink(records, max_output_bytes=10_000, spool_max_memory_bytes=8)
    with full:
        content = full.read_bytes()
        assert full.capture_format == "PCAPNG"
        assert content[:4] == b"\x0a\x0d\x0d\x0a"
        assert full.exported_packet_count == 2
    # SHB + first IDB/EPB is 28 + 20 + 36 for a 4-byte payload.
    limited = build_capture_to_sink(records, max_output_bytes=84, spool_max_memory_bytes=8)
    with limited:
        assert limited.size_bytes == 84
        assert limited.exported_packet_count == 1
        assert limited.omitted_packet_count == 1
        assert limited.truncation_reasons == ("OUTPUT_BYTE_LIMIT",)
        block_types = []
        content = limited.read_bytes()
        offset = 0
        while offset < len(content):
            block_types.append(struct.unpack_from("<I", content, offset)[0])
            offset += struct.unpack_from("<I", content, offset + 4)[0]
        assert block_types == [0x0A0D0D0A, 1, 6]


def test_interface_identity_uses_source_global_ordinal_and_validates_link_type() -> None:
    first = record(interface=0)
    same_logical_interface_new_section = ExportPacketRecord(
        first.timestamp,
        first.source_id,
        first.source_order,
        1,
        1,
        0,
        0,
        first.link_type,
        b"next",
        4,
        4,
    )
    artifact = build_capture_to_sink(
        [first, same_logical_interface_new_section],
        max_output_bytes=10_000,
        spool_max_memory_bytes=8,
    )
    with artifact:
        assert artifact.capture_format == "PCAP"

    contradictory = ExportPacketRecord(
        first.timestamp,
        first.source_id,
        first.source_order,
        1,
        0,
        0,
        0,
        113,
        b"next",
        4,
        4,
    )
    with pytest.raises(ValueError, match="link type"):
        build_capture_to_sink(
            [first, contradictory], max_output_bytes=10_000, spool_max_memory_bytes=8
        )


def test_writer_rejects_noncanonical_and_invalid_records() -> None:
    with pytest.raises(ValueError, match="canonical"):
        build_capture_to_sink(
            [record(1), record(0)], max_output_bytes=1000, spool_max_memory_bytes=8
        )
    with pytest.raises(ValueError, match="timezone-aware"):
        build_capture_to_sink(
            [record(timestamp=datetime(2026, 1, 1))],
            max_output_bytes=1000,
            spool_max_memory_bytes=8,
        )


def test_writer_rejects_contradictory_source_and_interface_metadata() -> None:
    first = record()
    changed_source = record(1, source_id="source-b")
    with pytest.raises(CaptureRecordError, match="source_id"):
        build_capture_to_sink(
            [first, changed_source], max_output_bytes=1000, spool_max_memory_bytes=8
        )
    changed_ordinal = ExportPacketRecord(
        first.timestamp,
        first.source_id,
        first.source_order,
        1,
        first.section_index,
        first.interface_id,
        1,
        first.link_type,
        b"next",
        4,
        4,
    )
    with pytest.raises(CaptureRecordError, match="interface metadata"):
        build_capture_to_sink(
            [first, changed_ordinal], max_output_bytes=1000, spool_max_memory_bytes=8
        )
    mutable_packet = ExportPacketRecord(
        first.timestamp,
        first.source_id,
        first.source_order,
        1,
        first.section_index,
        first.interface_id,
        first.interface_ordinal,
        first.link_type,
        bytearray(b"next"),  # type: ignore[arg-type]
        4,
        4,
    )
    with pytest.raises(CaptureRecordError, match="immutable bytes"):
        build_capture_to_sink(
            [first, mutable_packet], max_output_bytes=1000, spool_max_memory_bytes=8
        )


def test_artifact_chunks_are_exact_single_use_and_close_is_idempotent() -> None:
    artifact = build_capture_to_sink(
        [record(payload=b"abcdefgh")], max_output_bytes=1000, spool_max_memory_bytes=8
    )
    expected_size = artifact.size_bytes
    chunks = list(artifact.iter_chunks(7))
    assert sum(map(len, chunks)) == expected_size
    assert all(len(chunk) == 7 for chunk in chunks[:-1])
    with pytest.raises(RuntimeError, match="already been consumed"):
        artifact.read_bytes()
    artifact.close()
    artifact.close()
    with pytest.raises(ValueError, match="closed"):
        artifact.read_bytes()


class FaultySpool(io.BytesIO):
    def __init__(self, *, fail: str | None = None, short_write: bool = False) -> None:
        super().__init__()
        self.fail = fail
        self.short_write = short_write
        self.close_calls = 0

    def write(self, value: bytes) -> int:
        if self.fail == "write":
            raise OSError(28, "host detail must stay private")
        if self.short_write and value:
            return super().write(value[:-1])
        return super().write(value)

    def flush(self) -> None:
        if self.fail == "flush":
            raise OSError(5, "private")
        super().flush()

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if self.fail == "seek":
            raise OSError(5, "private")
        return super().seek(offset, whence)

    def read(self, size: int = -1) -> bytes:
        if self.fail == "read":
            raise OSError(5, "private")
        return super().read(size)

    def close(self) -> None:
        self.close_calls += 1
        if self.fail == "close":
            raise OSError(5, "private")
        super().close()


@pytest.mark.parametrize("failure", ["write", "flush", "seek", "read"])
def test_sink_maps_spool_io_failures_without_host_details(
    monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    spool = FaultySpool(fail=failure)
    monkeypatch.setattr(capture_sink.tempfile, "SpooledTemporaryFile", lambda **_: spool)
    sink = CaptureSink(max_output_bytes=64, spool_max_memory_bytes=8)
    with pytest.raises(CaptureStorageError, match="^capture temporary storage operation failed$"):
        if failure == "write":
            sink.write_unit(b"data")
        elif failure in {"flush", "seek"}:
            sink.rewind()
        else:
            sink.read_bytes()


def test_sink_rejects_short_write_and_maps_enospc(monkeypatch: pytest.MonkeyPatch) -> None:
    short = FaultySpool(short_write=True)
    monkeypatch.setattr(capture_sink.tempfile, "SpooledTemporaryFile", lambda **_: short)
    sink = CaptureSink(max_output_bytes=64, spool_max_memory_bytes=8)
    with pytest.raises(CaptureStorageError):
        sink.write_unit(b"data")
    assert sink.size_bytes == 0


def test_spool_creation_failure_is_typed_and_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(**_: object) -> object:
        raise OSError(13, "secret directory")

    monkeypatch.setattr(capture_sink.tempfile, "SpooledTemporaryFile", fail)
    with pytest.raises(CaptureStorageError, match="^capture temporary storage operation failed$"):
        CaptureSink(max_output_bytes=64, spool_max_memory_bytes=8)


def test_primary_record_error_survives_both_spool_close_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = FaultySpool(fail="close")
    neutral = FaultySpool(fail="close")
    created = iter((output, neutral))
    monkeypatch.setattr(capture_sink.tempfile, "SpooledTemporaryFile", lambda **_: next(created))
    monkeypatch.setattr(pcap.tempfile, "SpooledTemporaryFile", lambda **_: next(created))

    with pytest.raises(CaptureRecordError, match="timezone-aware"):
        build_capture_to_sink(
            [record(timestamp=datetime(2026, 1, 1))],
            max_output_bytes=1_000,
            spool_max_memory_bytes=8,
        )
    assert output.close_calls == neutral.close_calls == 1


def test_neutral_close_failure_is_attempted_once_and_cleans_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = FaultySpool()
    neutral = FaultySpool(fail="close")
    created = iter((output, neutral))
    monkeypatch.setattr(capture_sink.tempfile, "SpooledTemporaryFile", lambda **_: next(created))
    monkeypatch.setattr(pcap.tempfile, "SpooledTemporaryFile", lambda **_: next(created))

    with pytest.raises(CaptureStorageError):
        build_capture_to_sink([record()], max_output_bytes=1_000, spool_max_memory_bytes=8)
    assert neutral.close_calls == 1
    assert output.close_calls == 1


def test_malformed_or_oversized_neutral_frames_are_record_errors() -> None:
    malformed = io.BytesIO(struct.pack("<I", 3) + b"bad")
    with pytest.raises(CaptureRecordError, match="malformed neutral capture frame"):
        pcap._read_frame(malformed)
    with pytest.raises(CaptureRecordError, match="maximum captured packet size"):
        build_capture_to_sink(
            [record(payload=b"x" * (pcap.MAX_CAPTURED_PACKET_BYTES + 1))],
            max_output_bytes=1_000,
            spool_max_memory_bytes=8,
        )


def test_neutral_payload_read_oserror_is_storage_error_and_cleans_both_spools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PayloadReadFaultSpool(FaultySpool):
        def read(self, size: int = -1) -> bytes:
            if size > len(pcap._SPOOL_MAGIC):
                raise OSError(5, "private neutral spool detail")
            return super().read(size)

    output = FaultySpool()
    neutral = PayloadReadFaultSpool()
    created = iter((output, neutral))
    monkeypatch.setattr(capture_sink.tempfile, "SpooledTemporaryFile", lambda **_: next(created))

    with pytest.raises(CaptureStorageError, match="^capture temporary storage operation failed$"):
        build_capture_to_sink([record()], max_output_bytes=1_000, spool_max_memory_bytes=8)
    assert output.close_calls == neutral.close_calls == 1


def test_clean_truncated_neutral_frame_is_record_error() -> None:
    payload = struct.pack("<I", 99) + b"data"
    complete_physical_frame = io.BytesIO(struct.pack("<I", len(payload)) + payload)
    with pytest.raises(CaptureRecordError, match="malformed neutral capture frame"):
        pcap._read_frame(complete_physical_frame)


def test_physically_short_neutral_frame_is_storage_error() -> None:
    physically_short = io.BytesIO(struct.pack("<I", 12) + b"short")
    with pytest.raises(CaptureStorageError, match="^capture temporary storage operation failed$"):
        pcap._read_frame(physically_short)


@pytest.mark.parametrize(
    ("content", "declared", "digest"),
    [
        (b"ab", 4, hashlib.sha256(b"abcd").hexdigest()),
        (b"abcde", 4, hashlib.sha256(b"abcd").hexdigest()),
        (b"abce", 4, hashlib.sha256(b"abcd").hexdigest()),
    ],
    ids=["short-eof", "extra-bytes", "same-size-corruption"],
)
def test_artifact_chunk_iteration_validates_immutable_accounting(
    content: bytes, declared: int, digest: str
) -> None:
    artifact = CaptureArtifact(
        io.BytesIO(content),
        capture_format="PCAP",
        size_bytes=declared,
        sha256=digest,
        matched_packet_count=0,
        exported_packet_count=0,
    )
    try:
        with pytest.raises(
            CaptureStorageError, match="^capture temporary storage operation failed$"
        ):
            list(artifact.iter_chunks(2))
    finally:
        artifact.close()


def test_artifact_chunk_iteration_maps_read_oserror() -> None:
    artifact = CaptureArtifact(
        FaultySpool(fail="read"),
        capture_format="PCAP",
        size_bytes=0,
        sha256=hashlib.sha256().hexdigest(),
        matched_packet_count=0,
        exported_packet_count=0,
    )
    try:
        with pytest.raises(
            CaptureStorageError, match="^capture temporary storage operation failed$"
        ):
            list(artifact.iter_chunks())
    finally:
        artifact.close()


def test_artifact_chunk_iteration_rejects_mutable_read_data() -> None:
    class MutableReadSpool(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:  # type: ignore[override]
            return bytearray(super().read(size))  # type: ignore[return-value]

    artifact = CaptureArtifact(
        MutableReadSpool(b"data"),
        capture_format="PCAP",
        size_bytes=4,
        sha256=hashlib.sha256(b"data").hexdigest(),
        matched_packet_count=0,
        exported_packet_count=0,
    )
    try:
        with pytest.raises(
            CaptureStorageError, match="^capture temporary storage operation failed$"
        ):
            list(artifact.iter_chunks())
    finally:
        artifact.close()


def test_artifact_preserves_primary_exception_when_context_close_fails() -> None:
    artifact = CaptureArtifact(
        FaultySpool(fail="close"),
        capture_format="PCAP",
        size_bytes=0,
        sha256=hashlib.sha256().hexdigest(),
        matched_packet_count=0,
        exported_packet_count=0,
    )
    with pytest.raises(LookupError, match="primary"):
        with artifact:
            raise LookupError("primary")


def test_artifact_rejects_concurrent_consumption_and_non_bytes_reads() -> None:
    artifact = build_capture_to_sink(
        [record(payload=b"abcdefgh")], max_output_bytes=1000, spool_max_memory_bytes=8
    )
    iterator = artifact.iter_chunks(3)
    assert isinstance(next(iterator), bytes)
    with pytest.raises(RuntimeError, match="already being consumed"):
        next(artifact.iter_chunks())
    iterator.close()
    with pytest.raises(RuntimeError, match="already been consumed"):
        next(artifact.iter_chunks())
    artifact.close()
