from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal, Protocol

from c2hunter_analysis.pcap_index import (
    PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_OFFSET_INDEX_SCHEMA_VERSION,
    StructuralInterfaceEntry,
    StructuralPacketEntry,
    scan_structural_packet_index,
)

logger = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_I64 = (1 << 63) - 1
_MAX_U64 = (1 << 64) - 1


@dataclass(frozen=True)
class CaptureSourceVersion:
    source_kind: Literal["PCAP_UPLOAD"]
    source_id: str
    object_key: str
    source_version_id: str
    source_size_bytes: int
    source_sha256: str

    def __post_init__(self) -> None:
        if (
            self.source_kind != "PCAP_UPLOAD"
            or not self.source_id
            or not self.object_key
            or not self.source_version_id
        ):
            raise ValueError("invalid capture source version identity")
        if self.source_size_bytes < 0 or self.source_size_bytes > _MAX_I64:
            raise ValueError("invalid capture source version size")
        if not _SHA256.fullmatch(self.source_sha256):
            raise ValueError("capture source SHA-256 must be lowercase hexadecimal")


@dataclass(frozen=True)
class SourceIndexBinding:
    source_kind: Literal["PCAP_UPLOAD"]
    source_id: str
    source_version_id: str
    source_size_bytes: int
    source_sha256: str
    capture_format: Literal["PCAP", "PCAPNG"]
    schema_version: int = PCAP_OFFSET_INDEX_SCHEMA_VERSION
    parser_contract_version: int = PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if self.source_kind != "PCAP_UPLOAD" or not self.source_id or not self.source_version_id:
            raise ValueError("invalid structural index source identity")
        if self.source_size_bytes < 0 or self.source_size_bytes > _MAX_I64:
            raise ValueError("invalid structural index source size")
        if not _SHA256.fullmatch(self.source_sha256):
            raise ValueError("source SHA-256 must be lowercase hexadecimal")
        if self.capture_format not in {"PCAP", "PCAPNG"}:
            raise ValueError("invalid structural index capture format")


@dataclass(frozen=True)
class StructuralIndexSnapshot:
    build_id: str
    binding: SourceIndexBinding
    created_at: datetime
    index_sha256: str
    interfaces: tuple[StructuralInterfaceEntry, ...]
    packets: tuple[StructuralPacketEntry, ...]


class IndexAvailability(str, Enum):
    READY = "READY"
    MISSING = "MISSING"
    STALE = "STALE"
    CORRUPT = "CORRUPT"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"


@dataclass(frozen=True)
class StructuralIndexLookup:
    availability: IndexAvailability
    snapshot: StructuralIndexSnapshot | None = None


class StructuralIndexRepository(Protocol):
    def get_job_summary(self, job_id: str) -> dict[str, Any] | None: ...
    def open_job_capture(self, job_id: str) -> Any: ...
    def get_capture_source_version(self, job_id: str) -> CaptureSourceVersion | None: ...
    def begin_structural_index(
        self, build_id: str, binding: SourceIndexBinding, created_at: datetime
    ) -> None: ...
    def stage_structural_index_packets(
        self, build_id: str, packets: tuple[StructuralPacketEntry, ...]
    ) -> None: ...
    def publish_structural_index(
        self,
        build_id: str,
        binding: SourceIndexBinding,
        interfaces: tuple[StructuralInterfaceEntry, ...],
        packet_count: int,
    ) -> bool: ...
    def abort_structural_index(self, build_id: str) -> None: ...


def binding_document(binding: SourceIndexBinding) -> bytes:
    return json.dumps(asdict(binding), sort_keys=True, separators=(",", ":")).encode()


def structural_index_digest(
    binding: SourceIndexBinding,
    interfaces: Iterable[StructuralInterfaceEntry],
    packets: Iterable[StructuralPacketEntry],
) -> str:
    digest = hashlib.sha256()
    digest.update(b"c2hunter-pcap-offset-index-v1\n")
    digest.update(binding_document(binding))
    digest.update(b"\n")
    for interface in interfaces:
        digest.update(json.dumps(asdict(interface), sort_keys=True, separators=(",", ":")).encode())
        digest.update(b"\n")
    for packet in packets:
        digest.update(json.dumps(asdict(packet), sort_keys=True, separators=(",", ":")).encode())
        digest.update(b"\n")
    return digest.hexdigest()


def validate_structural_index(snapshot: StructuralIndexSnapshot) -> bool:
    binding = snapshot.binding
    if (
        binding.schema_version != PCAP_OFFSET_INDEX_SCHEMA_VERSION
        or binding.parser_contract_version != PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION
        or not _SHA256.fullmatch(snapshot.index_sha256)
    ):
        return False
    interfaces = snapshot.interfaces
    packets = snapshot.packets
    if not interfaces or tuple(item.interface_ordinal for item in interfaces) != tuple(
        range(len(interfaces))
    ):
        return False
    interface_map = {
        (item.section_index, item.interface_id, item.interface_ordinal): item for item in interfaces
    }
    if len(interface_map) != len(interfaces):
        return False
    previous_end = 0
    for expected_index, packet in enumerate(packets):
        interface = interface_map.get(
            (packet.section_index, packet.interface_id, packet.interface_ordinal)
        )
        if interface is None or packet.packet_index != expected_index:
            return False
        values = (
            packet.record_offset,
            packet.data_offset,
            packet.captured_length,
            packet.original_length,
            packet.framed_length,
        )
        if (
            any(value < 0 or value > _MAX_I64 for value in values)
            or packet.raw_timestamp_ticks < 0
            or packet.raw_timestamp_ticks > _MAX_U64
        ):
            return False
        record_end = packet.record_offset + packet.framed_length
        data_end = packet.data_offset + packet.captured_length
        if (
            record_end > binding.source_size_bytes
            or data_end > record_end
            or packet.record_offset < previous_end
            or packet.captured_length > packet.original_length
            or packet.captured_length > interface.snaplen
        ):
            return False
        if binding.capture_format == "PCAP":
            if (
                packet.data_offset != packet.record_offset + 16
                or packet.framed_length != 16 + packet.captured_length
            ):
                return False
        elif (
            packet.data_offset != packet.record_offset + 28
            or packet.framed_length < 32
            or packet.framed_length % 4
            or data_end > record_end - 4
        ):
            return False
        previous_end = record_end
    return snapshot.index_sha256 == structural_index_digest(binding, interfaces, packets)


def build_offline_upload_index(
    repository: StructuralIndexRepository,
    job_id: str,
    *,
    max_packets: int,
    max_interfaces: int,
    batch_size: int,
) -> bool:
    """Best-effort synchronous build for one canonical retained upload."""
    job = repository.get_job_summary(job_id)
    if job is None or job.get("mode") != "PCAP_UPLOAD":
        return False
    source_metadata = job.get("source")
    if (
        not isinstance(source_metadata, dict)
        or source_metadata.get("packet_bytes_retained") is not True
    ):
        return False
    source = None
    build_id = uuid.uuid4().hex
    begun = False
    try:
        source = repository.open_job_capture(job_id)
        if source is None:
            return False
        source_version = repository.get_capture_source_version(job_id)
        if (
            source_version is None
            or source_version.source_kind != "PCAP_UPLOAD"
            or source_version.source_id != job_id
            or source_version.object_key != f"captures/{job_id}.pcap"
            or source_version.source_size_bytes != int(source_metadata["size_bytes"])
            or source_version.source_sha256 != str(source_metadata["sha256"])
        ):
            return False
        binding = SourceIndexBinding(
            source_kind="PCAP_UPLOAD",
            source_id=job_id,
            source_version_id=source_version.source_version_id,
            source_size_bytes=source_version.source_size_bytes,
            source_sha256=source_version.source_sha256,
            capture_format=str(source_metadata["capture_format"]),  # type: ignore[arg-type]
        )
        repository.begin_structural_index(build_id, binding, datetime.now(UTC))
        begun = True
        with source:
            result = scan_structural_packet_index(
                source,
                max_packets=max_packets,
                max_interfaces=max_interfaces,
                batch_size=batch_size,
                consume_packet_batch=lambda batch: repository.stage_structural_index_packets(
                    build_id, batch
                ),
            )
        if (
            result.size_bytes != binding.source_size_bytes
            or result.sha256 != binding.source_sha256
            or result.capture_format != binding.capture_format
        ):
            return False
        return repository.publish_structural_index(
            build_id, binding, result.interfaces, result.packet_count
        )
    except Exception:
        logger.warning("Offline structural index build unavailable", exc_info=True)
        return False
    finally:
        if begun:
            try:
                repository.abort_structural_index(build_id)
            except Exception:
                logger.warning(
                    "Offline structural index staging cleanup unavailable", exc_info=True
                )
        if source is not None and not source.closed:
            source.close()


def rebuild_offline_upload_index(
    repository: StructuralIndexRepository,
    job_id: str,
    *,
    max_packets: int,
    max_interfaces: int,
    batch_size: int,
) -> bool:
    return build_offline_upload_index(
        repository,
        job_id,
        max_packets=max_packets,
        max_interfaces=max_interfaces,
        batch_size=batch_size,
    )
