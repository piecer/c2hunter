from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal, Protocol

from c2hunter_analysis.pcap_index import (
    PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_OFFSET_INDEX_SCHEMA_VERSION,
    StructuralIndexLimitError,
    StructuralInterfaceEntry,
    StructuralPacketEntry,
    scan_structural_packet_index,
)
from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
)

logger = logging.getLogger(__name__)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_I64 = (1 << 63) - 1
_MAX_U64 = (1 << 64) - 1
_MIN_I64 = -(1 << 63)
_MAX_CAPTURED_PACKET_BYTES = 16 * 1024 * 1024


class LiveIndexBuildError(RuntimeError):
    """Stable-code failure raised by the durable LIVE builder."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class LiveIndexTransientError(LiveIndexBuildError):
    """Object-store, database, or deadline availability failure."""


class LiveIndexPermanentError(LiveIndexBuildError):
    """Malformed source, resource bound, ownership, or digest failure."""


@dataclass(frozen=True)
class CaptureSourceVersion:
    source_kind: Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]
    source_id: str
    object_key: str
    source_version_id: str
    source_size_bytes: int
    source_sha256: str

    def __post_init__(self) -> None:
        if (
            self.source_kind not in {"PCAP_UPLOAD", "LIVE_SEGMENT"}
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
    source_kind: Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]
    source_id: str
    source_version_id: str
    source_size_bytes: int
    source_sha256: str
    capture_format: Literal["PCAP", "PCAPNG"]
    schema_version: int = PCAP_OFFSET_INDEX_SCHEMA_VERSION
    parser_contract_version: int = PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if (
            self.source_kind not in {"PCAP_UPLOAD", "LIVE_SEGMENT"}
            or not self.source_id
            or not self.source_version_id
        ):
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


@dataclass(frozen=True)
class StructuralIndexIdentity:
    """Exact READY generation identity, excluding interfaces and packet rows."""

    build_id: str
    binding: SourceIndexBinding
    created_at: datetime
    index_sha256: str


@dataclass(frozen=True)
class StructuralIndexIdentityLookup:
    availability: IndexAvailability
    identity: StructuralIndexIdentity | None = None


class StructuralIndexParentIdentity(Protocol):
    """Narrow structural-parent contract used by posting identity operations."""

    @property
    def build_id(self) -> str: ...

    @property
    def binding(self) -> SourceIndexBinding: ...

    @property
    def created_at(self) -> datetime: ...

    @property
    def index_sha256(self) -> str: ...


def structural_index_identity(
    snapshot: StructuralIndexParentIdentity,
) -> StructuralIndexIdentity:
    return StructuralIndexIdentity(
        snapshot.build_id,
        snapshot.binding,
        snapshot.created_at,
        snapshot.index_sha256,
    )


def structural_index_identity_availability(
    identity: StructuralIndexIdentity, source: CaptureSourceVersion
) -> IndexAvailability:
    binding = identity.binding
    if (
        binding.schema_version != PCAP_OFFSET_INDEX_SCHEMA_VERSION
        or binding.parser_contract_version != PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION
    ):
        return IndexAvailability.UNSUPPORTED_SCHEMA
    if (
        binding.source_kind != source.source_kind
        or binding.source_id != source.source_id
        or binding.source_version_id != source.source_version_id
        or binding.source_size_bytes != source.source_size_bytes
        or binding.source_sha256 != source.source_sha256
    ):
        return IndexAvailability.STALE
    if (
        not identity.build_id
        or identity.created_at.tzinfo is None
        or identity.created_at.utcoffset() is None
        or not _SHA256.fullmatch(identity.index_sha256)
    ):
        return IndexAvailability.CORRUPT
    return IndexAvailability.READY


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
        *,
        request_postings: bool = False,
        posting_schema_version: int = PCAP_POSTING_INDEX_SCHEMA_VERSION,
        posting_parser_contract_version: int = PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        filter_contract_version: int = PCAP_FILTER_CONTRACT_VERSION,
    ) -> bool: ...
    def abort_structural_index(self, build_id: str) -> None: ...
    def get_structural_index_identity(
        self, source: CaptureSourceVersion
    ) -> StructuralIndexIdentityLookup: ...


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
    for interface_entry in interfaces:
        integer_values = (
            interface_entry.section_index,
            interface_entry.interface_id,
            interface_entry.interface_ordinal,
            interface_entry.link_type,
            interface_entry.snaplen,
            interface_entry.timestamp_resolution_numerator,
            interface_entry.timestamp_resolution_denominator,
            interface_entry.timestamp_offset_seconds,
        )
        if any(type(value) is not int for value in integer_values):
            return False
        if (
            not 0 <= interface_entry.section_index <= _MAX_I64
            or not 0 <= interface_entry.interface_id <= _MAX_I64
            or not 0 <= interface_entry.interface_ordinal <= _MAX_I64
            or not 0 <= interface_entry.link_type <= 0xFFFF
            or not 1 <= interface_entry.snaplen <= _MAX_CAPTURED_PACKET_BYTES
            or not 1 <= interface_entry.timestamp_resolution_numerator <= _MAX_I64
            or not 1 <= interface_entry.timestamp_resolution_denominator <= _MAX_I64
            or not _MIN_I64 <= interface_entry.timestamp_offset_seconds <= _MAX_I64
        ):
            return False
    interface_map = {
        (item.section_index, item.interface_id, item.interface_ordinal): item for item in interfaces
    }
    if len(interface_map) != len(interfaces):
        return False
    previous_end = 0
    for expected_index, packet in enumerate(packets):
        packet_integer_values = (
            packet.packet_index,
            packet.record_offset,
            packet.data_offset,
            packet.captured_length,
            packet.original_length,
            packet.framed_length,
            packet.section_index,
            packet.interface_id,
            packet.interface_ordinal,
            packet.raw_timestamp_ticks,
        )
        if any(type(value) is not int for value in packet_integer_values):
            return False
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
            or not 0 <= packet.section_index <= _MAX_I64
            or not 0 <= packet.interface_id <= _MAX_I64
            or not 0 <= packet.interface_ordinal <= _MAX_I64
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
    request_postings: bool = False,
    posting_schema_version: int = PCAP_POSTING_INDEX_SCHEMA_VERSION,
    posting_parser_contract_version: int = PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    filter_contract_version: int = PCAP_FILTER_CONTRACT_VERSION,
    posting_queue_capacity: int = 100,
    posting_max_attempts: int = 3,
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
            or not source_version.object_key
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
        published = repository.publish_structural_index(
            build_id,
            binding,
            result.interfaces,
            result.packet_count,
            request_postings=request_postings,
            posting_schema_version=posting_schema_version,
            posting_parser_contract_version=posting_parser_contract_version,
            filter_contract_version=filter_contract_version,
        )
        if not published:
            return False
        if request_postings:
            try:
                repository.admit_posting_index(  # type: ignore[attr-defined]
                    "PCAP_UPLOAD",
                    job_id,
                    capacity=posting_queue_capacity,
                    max_attempts=posting_max_attempts,
                )
            except Exception:
                logger.warning("Posting index post-commit admission unavailable", exc_info=True)
        return True
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


def build_live_segment_index(
    repository: Any,
    segment_id: str,
    *,
    max_packets: int,
    max_interfaces: int,
    batch_size: int,
    attempt: int | None = None,
    lease_token: str | None = None,
    should_cancel: Callable[[], bool] | None = None,
    request_postings: bool = False,
    posting_schema_version: int = PCAP_POSTING_INDEX_SCHEMA_VERSION,
    posting_parser_contract_version: int = PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    filter_contract_version: int = PCAP_FILTER_CONTRACT_VERSION,
    posting_queue_capacity: int = 100,
    posting_max_attempts: int = 3,
) -> bool:
    """Build and atomically publish one immutable marked LIVE segment."""
    source = None
    build_id = uuid.uuid4().hex
    begun = False

    def check_cancelled() -> None:
        if should_cancel is not None and should_cancel():
            raise LiveIndexTransientError("INDEX_BUILD_TIMEOUT")

    check_cancelled()
    if attempt is None or attempt < 1 or not lease_token:
        raise LiveIndexPermanentError("INDEX_LEASE_INVALID")
    try:
        segment = repository.get_live_segment_index_metadata(segment_id)
    except Exception as exc:
        raise LiveIndexTransientError("INDEX_METADATA_UNAVAILABLE") from exc
    if segment is None:
        raise LiveIndexPermanentError("INDEX_SOURCE_NOT_ELIGIBLE")
    try:
        opened = repository.open_sensor_pcap(segment_id)
    except Exception as exc:
        raise LiveIndexTransientError("INDEX_SOURCE_OPEN_UNAVAILABLE") from exc
    if opened is None:
        raise LiveIndexPermanentError("INDEX_SOURCE_MISSING")
    opened_metadata, source = opened
    try:
        expected_key = str(
            segment.get("object_key")
            or f"sensor-pcaps/{segment.get('sensor_id')}/{segment_id}.pcap"
        )
        if (
            opened_metadata != segment
            or not source.version_id
            or segment.get("id") != segment_id
            or not segment.get("index_requested_at")
            or str(segment.get("filename", "")).endswith(".pcap") is False
            or int(segment.get("size_bytes", -1)) < 0
            or not _SHA256.fullmatch(str(segment.get("sha256", "")))
        ):
            raise LiveIndexPermanentError("INDEX_SOURCE_OWNERSHIP_MISMATCH")
        try:
            source_version = CaptureSourceVersion(
                "LIVE_SEGMENT",
                segment_id,
                expected_key,
                source.version_id,
                int(segment["size_bytes"]),
                str(segment["sha256"]),
            )
            binding = SourceIndexBinding(
                "LIVE_SEGMENT",
                segment_id,
                source.version_id,
                source_version.source_size_bytes,
                source_version.source_sha256,
                "PCAP",
            )
        except (TypeError, ValueError) as exc:
            raise LiveIndexPermanentError("INDEX_SOURCE_FRAMING_INVALID") from exc
        check_cancelled()
        try:
            repository.begin_structural_index(build_id, binding, datetime.now(UTC))
            begun = True
        except Exception as exc:
            raise LiveIndexTransientError("INDEX_STAGING_UNAVAILABLE") from exc
        try:
            result = scan_structural_packet_index(
                source,
                max_packets=max_packets,
                max_interfaces=max_interfaces,
                batch_size=batch_size,
                consume_packet_batch=lambda batch: repository.stage_structural_index_packets(
                    build_id, batch
                ),
            )
        except LiveIndexBuildError:
            raise
        except StructuralIndexLimitError as exc:
            raise LiveIndexPermanentError("INDEX_RESOURCE_LIMIT") from exc
        except (OSError, ConnectionError, TimeoutError) as exc:
            raise LiveIndexTransientError("INDEX_SOURCE_READ_UNAVAILABLE") from exc
        except (ValueError, TypeError) as exc:
            raise LiveIndexPermanentError("INDEX_SOURCE_FRAMING_INVALID") from exc
        except Exception as exc:
            raise LiveIndexTransientError("INDEX_STAGING_UNAVAILABLE") from exc
        if (
            result.packet_count < 1
            or result.size_bytes != binding.source_size_bytes
            or result.sha256 != binding.source_sha256
            or result.capture_format != "PCAP"
            or source.version_id != binding.source_version_id
        ):
            raise LiveIndexPermanentError("INDEX_SOURCE_DIGEST_MISMATCH")
        # This check is deliberately adjacent to the atomic publication call.
        check_cancelled()
        try:
            published = repository.publish_live_structural_index(
                build_id,
                binding,
                result.interfaces,
                result.packet_count,
                source_version,
                attempt=attempt,
                lease_token=lease_token,
                request_postings=request_postings,
                posting_schema_version=posting_schema_version,
                posting_parser_contract_version=posting_parser_contract_version,
                filter_contract_version=filter_contract_version,
            )
        except Exception as exc:
            raise LiveIndexTransientError("INDEX_PUBLICATION_UNAVAILABLE") from exc
        if not published:
            raise LiveIndexPermanentError("INDEX_PUBLICATION_REJECTED")
        if request_postings:
            try:
                repository.admit_posting_index(
                    "LIVE_SEGMENT",
                    segment_id,
                    capacity=posting_queue_capacity,
                    max_attempts=posting_max_attempts,
                )
            except Exception:
                logger.warning(
                    "LIVE posting index post-commit admission unavailable", exc_info=True
                )
        return True
    finally:
        if begun:
            try:
                repository.abort_structural_index(build_id)
            except Exception:
                logger.warning("LIVE structural index staging cleanup unavailable", exc_info=True)
        if source is not None:
            try:
                source.close()
            except Exception:
                logger.warning("LIVE capture source close unavailable", exc_info=True)


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
