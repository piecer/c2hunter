from __future__ import annotations

import hashlib
import hmac
import logging
import struct
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from time import perf_counter
from typing import Protocol

from c2hunter_analysis.pcap_export import ExportPacket

from .repositories import CaptureSource

logger = logging.getLogger(__name__)

_CLASSIC_MAGIC = {
    b"\xd4\xc3\xb2\xa1": "<",
    b"\xa1\xb2\xc3\xd4": ">",
    b"\x4d\x3c\xb2\xa1": "<",
    b"\xa1\xb2\x3c\x4d": ">",
}
_PCAPNG_SECTION = b"\x0a\x0d\x0d\x0a"
_PACKET_BLOCKS = {2, 6}
_DRAIN_CHUNK = 64 * 1024


class CaptureIntegrityError(ValueError):
    """The opened capture did not match its immutable descriptor."""


class CaptureReader(Protocol):
    def read(self, size: int = -1, /) -> bytes: ...


@dataclass(frozen=True)
class SourceScanResult:
    admitted_bytes: int
    admitted_packets: int
    byte_limited: bool
    packet_limited: bool
    actual_size: int
    actual_sha256: str
    verified_version_id: str


@dataclass(frozen=True)
class MatchedPacketRecord:
    source_id: str
    source_order: int
    packet_index: int
    section_index: int
    interface_id: int
    interface_ordinal: int
    link_type: int
    timestamp: datetime
    raw_packet_bytes: bytes
    captured_length: int
    original_length: int
    sensor_id: str
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    direction: str | None
    has_payload: bool | None

    @classmethod
    def from_export_packet(cls, packet: ExportPacket, *, sensor_id: str) -> MatchedPacketRecord:
        return cls(
            packet.locator.source_id,
            packet.locator.source_order,
            packet.locator.packet_index,
            packet.interface.section_index,
            packet.interface.interface_id,
            packet.interface.interface_ordinal,
            packet.interface.link_type,
            packet.timestamp,
            packet.raw_packet_bytes,
            len(packet.raw_packet_bytes),
            packet.original_length,
            sensor_id,
            packet.source_ip,
            packet.destination_ip,
            packet.source_port,
            packet.destination_port,
            packet.protocol,
            packet.direction,
            packet.has_payload,
        )

    @classmethod
    def from_legacy_record(
        cls,
        record: Mapping[str, object],
        *,
        source_job_id: str,
        fallback_packet_index: int,
        default_sensor_id: str,
    ) -> MatchedPacketRecord:
        def integer(name: str, default: int) -> int:
            return int(str(record.get(name, default)))

        raw = bytes.fromhex(str(record["raw_packet_hex"]))
        raw_timestamp = record.get("timestamp", record.get("raw_packet_timestamp"))
        timestamp = (
            raw_timestamp
            if isinstance(raw_timestamp, datetime)
            else datetime.fromisoformat(str(raw_timestamp))
        )
        source_order = integer("raw_packet_source_order", 0)
        interface_ordinal = integer("raw_packet_interface_id", 0)
        has_payload = record.get("has_payload", bool(record.get("payload_hash")))
        return cls(
            str(record.get("source_id") or f"legacy:{source_job_id}"),
            source_order,
            integer("raw_packet_index", fallback_packet_index),
            integer("section_index", 0),
            integer("raw_packet_interface_local_id", interface_ordinal),
            interface_ordinal,
            integer("raw_packet_link_type", 1),
            timestamp,
            raw,
            integer("raw_packet_captured_length", len(raw)),
            integer("raw_packet_original_length", len(raw)),
            str(record.get("sensor_id") or default_sensor_id),
            str(record["source_ip"]) if record.get("source_ip") is not None else None,
            (str(record["destination_ip"]) if record.get("destination_ip") is not None else None),
            int(str(record["source_port"])) if record.get("source_port") is not None else None,
            (
                int(str(record["destination_port"]))
                if record.get("destination_port") is not None
                else None
            ),
            str(record["protocol"]) if record.get("protocol") is not None else None,
            str(record["direction"]) if record.get("direction") is not None else None,
            bool(has_payload) if has_payload is not None else None,
        )

    def to_writer_record(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "section_index": self.section_index,
            "raw_packet_interface_local_id": self.interface_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "direction": self.direction,
            "sensor_id": self.sensor_id,
            "payload_hash": "present" if self.has_payload else None,
            "raw_packet_bytes": self.raw_packet_bytes,
            "raw_packet_source_order": self.source_order,
            "raw_packet_index": self.packet_index,
            "raw_packet_interface_id": self.interface_ordinal,
            "raw_packet_link_type": self.link_type,
            "raw_packet_captured_length": self.captured_length,
            "raw_packet_original_length": self.original_length,
        }


class VerifiedMatchedPackets:
    """A verified, canonical-order record batch consumable exactly once."""

    def __init__(self, records: tuple[MatchedPacketRecord, ...]) -> None:
        self._records = records
        self._iterated = False

    def __iter__(self) -> Iterator[MatchedPacketRecord]:
        if self._iterated:
            raise RuntimeError("verified matched packets can only be iterated once")
        self._iterated = True
        return iter(self._records)


class _AdmissionReader:
    def __init__(self, owner: BoundedVerifiedCapture) -> None:
        self._owner = owner

    def read(self, size: int = -1, /) -> bytes:
        return self._owner._read_admitted(size)


class BoundedVerifiedCapture:
    """One-pass capture framing whose results commit only after EOF integrity."""

    def __init__(
        self,
        source: CaptureSource,
        *,
        expected_size: int,
        expected_sha256: str,
        max_admitted_bytes: int,
        max_admitted_packets: int,
        stage_seconds: dict[str, float] | None = None,
    ) -> None:
        if expected_size < 0:
            raise ValueError("expected_size must be non-negative")
        if len(expected_sha256) != 64:
            raise ValueError("expected_sha256 must be a SHA-256 hex digest")
        try:
            bytes.fromhex(expected_sha256)
        except ValueError as exc:
            raise ValueError("expected_sha256 must be a SHA-256 hex digest") from exc
        if max_admitted_bytes < 1 or max_admitted_packets < 1:
            raise ValueError("capture admission limits must be positive")
        self._source = source
        self._expected_size = expected_size
        self._expected_sha256 = expected_sha256.lower()
        self._max_bytes = max_admitted_bytes
        self._max_packets = max_admitted_packets
        self._stage_seconds = stage_seconds
        self._hash = hashlib.sha256()
        self._actual_size = 0
        self._admitted_bytes = 0
        self._admitted_packets = 0
        self._byte_limited = False
        self._packet_limited = False
        self._pending = bytearray()
        self._unit_remaining = 0
        self._unit_is_packet = False
        self._format: str | None = None
        self._endian = "<"
        self._stopped = False
        self._closed = False
        self._read_failure: CaptureIntegrityError | None = None
        self._verified: SourceScanResult | None = None
        self._reader = _AdmissionReader(self)

    @property
    def reader(self) -> CaptureReader:
        return self._reader

    def _physical_read(self, size: int) -> bytes:
        started = perf_counter()
        try:
            try:
                chunk = self._source.read(size)
            except BaseException as exc:
                failure = CaptureIntegrityError(f"capture source read failed: {exc}")
                self._read_failure = failure
                raise failure from exc
        finally:
            self._add_stage("source_read", perf_counter() - started)
        started = perf_counter()
        self._hash.update(chunk)
        self._add_stage("hash", perf_counter() - started)
        self._actual_size += len(chunk)
        return chunk

    def _add_stage(self, stage: str, duration: float) -> None:
        if self._stage_seconds is not None:
            self._stage_seconds[stage] = self._stage_seconds.get(stage, 0.0) + duration

    def _read_up_to(self, size: int) -> bytes:
        result = bytearray()
        while len(result) < size:
            chunk = self._physical_read(size - len(result))
            if not chunk:
                break
            result.extend(chunk)
        return bytes(result)

    def _remaining_budget(self) -> int:
        return self._max_bytes - self._admitted_bytes - len(self._pending) - self._unit_remaining

    def _prepare(self) -> None:
        if self._stopped or self._pending or self._unit_remaining:
            return
        if self._format is None:
            self._prepare_initial()
        elif self._format == "PCAP":
            self._prepare_classic_record()
        else:
            self._prepare_ng_block()

    def _prepare_initial(self) -> None:
        if self._max_bytes < 24:
            self._byte_limited = self._expected_size > 0
            self._stopped = True
            return
        prefix = self._read_up_to(24 if self._expected_size >= 24 else self._expected_size)
        self._pending.extend(prefix)
        if len(prefix) < 4:
            self._stopped = True
            return
        magic = prefix[:4]
        if magic in _CLASSIC_MAGIC:
            self._format = "PCAP"
            self._endian = _CLASSIC_MAGIC[magic]
            if len(prefix) < 24:
                self._stopped = True
            return
        if magic == _PCAPNG_SECTION:
            self._format = "PCAPNG"
            if len(prefix) < 12:
                self._stopped = True
                return
            bom = prefix[8:12]
            self._endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            block_length = struct.unpack(f"{self._endian}I", prefix[4:8])[0]
            if block_length < 12 or block_length % 4:
                self._stopped = True
                return
            if block_length > self._max_bytes and self._expected_size > self._max_bytes:
                self._pending.clear()
                self._byte_limited = True
                self._stopped = True
                return
            # We fetched 24 for format discovery. Only the first block belongs to
            # this unit; retain any bytes after it as already-read block input.
            if block_length < len(prefix):
                extra = prefix[block_length:]
                del self._pending[block_length:]
                self._lookahead = bytearray(extra)
            else:
                self._lookahead = bytearray()
                self._unit_remaining = block_length - len(prefix)
            return
        self._stopped = True

    def _take_physical(self, size: int) -> bytes:
        lookahead = getattr(self, "_lookahead", bytearray())
        result = bytearray()
        if lookahead:
            take = min(size, len(lookahead))
            result.extend(lookahead[:take])
            del lookahead[:take]
            size -= take
        if size:
            result.extend(self._read_up_to(size))
        return bytes(result)

    def _prepare_classic_record(self) -> None:
        if self._admitted_bytes >= self._expected_size:
            self._stopped = True
            return
        remaining = self._max_bytes - self._admitted_bytes
        if self._expected_size > self._max_bytes and remaining < 16:
            self._byte_limited = True
            self._stopped = True
            return
        if self._admitted_packets >= self._max_packets:
            self._packet_limited = True
            self._stopped = True
            return
        header = self._read_up_to(16)
        if not header:
            self._stopped = True
            return
        if len(header) < 16:
            self._pending.extend(header)
            self._stopped = True
            return
        captured = struct.unpack_from(f"{self._endian}I", header, 8)[0]
        framed = 16 + captured
        if framed > remaining and self._expected_size > self._max_bytes:
            self._byte_limited = True
            self._stopped = True
            return
        self._pending.extend(header)
        self._unit_remaining = captured
        self._unit_is_packet = True

    def _prepare_ng_block(self) -> None:
        if self._admitted_bytes >= self._expected_size:
            self._stopped = True
            return
        remaining = self._max_bytes - self._admitted_bytes
        if self._expected_size > self._max_bytes and remaining < 12:
            self._byte_limited = True
            self._stopped = True
            return
        first = self._take_physical(4)
        if not first:
            self._stopped = True
            return
        if len(first) < 4:
            self._pending.extend(first)
            self._stopped = True
            return
        is_section = first == _PCAPNG_SECTION
        if not is_section:
            block_type = struct.unpack(f"{self._endian}I", first)[0]
            if block_type in _PACKET_BLOCKS and self._admitted_packets >= self._max_packets:
                self._packet_limited = True
                self._stopped = True
                return
        rest = self._take_physical(8)
        prefix = first + rest
        if len(rest) < 8:
            self._pending.extend(prefix)
            self._stopped = True
            return
        if is_section:
            bom = prefix[8:12]
            if bom == b"\x4d\x3c\x2b\x1a":
                self._endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                self._endian = ">"
        block_type, block_length = struct.unpack(f"{self._endian}II", prefix[:8])
        if block_length < 12 or block_length % 4:
            self._pending.extend(prefix)
            self._stopped = True
            return
        if block_length > remaining and self._expected_size > self._max_bytes:
            self._byte_limited = True
            self._stopped = True
            return
        self._pending.extend(prefix)
        self._unit_remaining = block_length - 12
        self._unit_is_packet = block_type in _PACKET_BLOCKS

    def _complete_unit(self) -> None:
        if self._unit_is_packet:
            self._admitted_packets += 1
        self._unit_is_packet = False

    def _read_admitted(self, size: int = -1) -> bytes:
        if self._closed:
            raise ValueError("I/O operation on closed capture source")
        target = _DRAIN_CHUNK if size is None or size < 0 else size
        if target == 0:
            return b""
        result = bytearray()
        source_before = (self._stage_seconds or {}).get("source_read", 0.0)
        hash_before = (self._stage_seconds or {}).get("hash", 0.0)
        started = perf_counter()
        try:
            while len(result) < target:
                self._prepare()
                if self._pending:
                    take = min(target - len(result), len(self._pending))
                    result.extend(self._pending[:take])
                    del self._pending[:take]
                    self._admitted_bytes += take
                    if not self._pending and not self._unit_remaining:
                        self._complete_unit()
                    continue
                if self._unit_remaining:
                    take = min(target - len(result), self._unit_remaining, _DRAIN_CHUNK)
                    chunk = self._take_physical(take)
                    result.extend(chunk)
                    self._admitted_bytes += len(chunk)
                    self._unit_remaining -= len(chunk)
                    if len(chunk) < take:
                        self._unit_remaining = 0
                        self._unit_is_packet = False
                        self._stopped = True
                    elif not self._unit_remaining:
                        self._complete_unit()
                    continue
                break
            return bytes(result)
        finally:
            elapsed = perf_counter() - started
            source_elapsed = (self._stage_seconds or {}).get("source_read", 0.0) - source_before
            hash_elapsed = (self._stage_seconds or {}).get("hash", 0.0) - hash_before
            self._add_stage("frame", max(0.0, elapsed - source_elapsed - hash_elapsed))

    def drain_and_verify(self) -> SourceScanResult:
        if self._verified is not None:
            return self._verified
        failure: BaseException | None = self._read_failure
        if failure is None:
            try:
                while self._physical_read(_DRAIN_CHUNK):
                    pass
            except BaseException as exc:
                failure = exc
        try:
            self.close()
        except BaseException as exc:
            if failure is None:
                failure = exc
            else:
                logger.debug(
                    "Capture source close failed during verification cleanup; "
                    "preserving primary failure",
                    exc_info=True,
                )
        digest = self._hash.hexdigest()
        if failure is not None:
            if isinstance(failure, CaptureIntegrityError):
                raise failure
            raise CaptureIntegrityError(f"capture source read failed: {failure}") from failure
        if self._actual_size != self._expected_size:
            raise CaptureIntegrityError("retained PCAP size mismatch")
        if not hmac.compare_digest(digest, self._expected_sha256):
            raise CaptureIntegrityError("retained PCAP digest mismatch")
        self._verified = SourceScanResult(
            self._admitted_bytes,
            self._admitted_packets,
            self._byte_limited,
            self._packet_limited,
            self._actual_size,
            digest,
            self._source.version_id,
        )
        return self._verified

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._source.close()


def open_bounded_verified_capture(
    source: CaptureSource,
    *,
    expected_size: int,
    expected_sha256: str,
    max_admitted_bytes: int,
    max_admitted_packets: int,
    stage_seconds: dict[str, float] | None = None,
) -> BoundedVerifiedCapture:
    try:
        return BoundedVerifiedCapture(
            source,
            expected_size=expected_size,
            expected_sha256=expected_sha256,
            max_admitted_bytes=max_admitted_bytes,
            max_admitted_packets=max_admitted_packets,
            stage_seconds=stage_seconds,
        )
    except BaseException:
        try:
            source.close()
        except BaseException:
            logger.debug(
                "Capture source close failed after bounded capture constructor failure; "
                "preserving constructor failure",
                exc_info=True,
            )
        raise
