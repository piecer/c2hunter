from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from c2hunter_analysis.pcap import PcapParseError
from c2hunter_analysis.pcap_export import open_export_capture
from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
    PostingBuildLimits,
    PostingDimension,
    PostingGeneration,
    PostingResourceLimitError,
    PostingStructuralMismatchError,
    build_packet_postings,
    validate_posting_generation,
)

from .pcap_offset_index import (
    CaptureSourceVersion,
    StructuralIndexSnapshot,
    validate_structural_index,
)

logger = logging.getLogger(__name__)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PostingIndexBuildError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class PostingIndexPermanentError(PostingIndexBuildError):
    pass


class PostingIndexTransientError(PostingIndexBuildError):
    pass


@dataclass(frozen=True)
class PostingIndexBinding:
    source_kind: Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]
    source_id: str
    source_version_id: str
    source_size_bytes: int
    source_sha256: str
    capture_format: Literal["PCAP", "PCAPNG"]
    parent_structural_build_id: str
    parent_structural_index_sha256: str
    structural_schema_version: int
    structural_parser_contract_version: int
    posting_schema_version: int = PCAP_POSTING_INDEX_SCHEMA_VERSION
    posting_parser_contract_version: int = PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION
    filter_contract_version: int = PCAP_FILTER_CONTRACT_VERSION

    def __post_init__(self) -> None:
        if (
            self.source_kind not in {"PCAP_UPLOAD", "LIVE_SEGMENT"}
            or not self.source_id
            or not self.source_version_id
            or self.source_size_bytes < 0
            or self.capture_format not in {"PCAP", "PCAPNG"}
            or not self.parent_structural_build_id
            or not _SHA256.fullmatch(self.source_sha256)
            or not _SHA256.fullmatch(self.parent_structural_index_sha256)
        ):
            raise ValueError("invalid posting index binding")

    def document(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":")).encode()


@dataclass(frozen=True)
class PostingIndexSnapshot:
    build_id: str
    binding: PostingIndexBinding
    created_at: datetime
    generation: PostingGeneration


class PostingIndexAvailability(str, Enum):
    READY = "READY"
    MISSING = "MISSING"
    STALE = "STALE"
    CORRUPT = "CORRUPT"
    UNSUPPORTED_SCHEMA = "UNSUPPORTED_SCHEMA"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"


@dataclass(frozen=True)
class PostingIndexLookup:
    availability: PostingIndexAvailability
    snapshot: PostingIndexSnapshot | None = None


@dataclass(frozen=True)
class PostingIndexIdentity:
    """Exact compact identity of one READY posting generation, excluding chunk payloads."""

    build_id: str
    binding: PostingIndexBinding
    created_at: datetime
    schema_version: int
    parser_contract_version: int
    filter_contract_version: int
    packet_count: int
    supported_count: int
    membership_count: int
    distinct_key_count: int
    chunk_count: int
    encoded_byte_count: int
    complete_dimensions: tuple[str, ...]
    digest: str
    binding_document: bytes


@dataclass(frozen=True)
class PostingIndexIdentityLookup:
    availability: PostingIndexAvailability
    identity: PostingIndexIdentity | None = None


def posting_index_identity(snapshot: PostingIndexSnapshot) -> PostingIndexIdentity:
    generation = snapshot.generation
    return PostingIndexIdentity(
        snapshot.build_id,
        snapshot.binding,
        snapshot.created_at,
        generation.schema_version,
        generation.parser_contract_version,
        generation.filter_contract_version,
        generation.packet_count,
        generation.supported_count,
        generation.membership_count,
        generation.distinct_key_count,
        len(generation.chunks),
        generation.encoded_byte_count,
        tuple(sorted(item.value for item in generation.complete_dimensions)),
        generation.digest,
        generation.binding_document,
    )


def posting_index_identity_availability(
    identity: PostingIndexIdentity,
    *,
    source_version: CaptureSourceVersion,
    parent: StructuralIndexSnapshot,
) -> PostingIndexAvailability:
    try:
        expected = _binding(source_version, parent)
    except ValueError:
        return PostingIndexAvailability.STALE
    if (
        identity.binding.source_kind != expected.source_kind
        or identity.binding.source_id != expected.source_id
        or identity.binding.source_version_id != expected.source_version_id
        or identity.binding.source_size_bytes != expected.source_size_bytes
        or identity.binding.source_sha256 != expected.source_sha256
        or identity.binding.capture_format != expected.capture_format
        or identity.binding.parent_structural_build_id != expected.parent_structural_build_id
        or identity.binding.parent_structural_index_sha256
        != expected.parent_structural_index_sha256
        or identity.binding.structural_schema_version != expected.structural_schema_version
        or identity.binding.structural_parser_contract_version
        != expected.structural_parser_contract_version
    ):
        return PostingIndexAvailability.STALE
    if (
        identity.binding.posting_schema_version != PCAP_POSTING_INDEX_SCHEMA_VERSION
        or identity.binding.posting_parser_contract_version
        != PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION
        or identity.binding.filter_contract_version != PCAP_FILTER_CONTRACT_VERSION
        or identity.schema_version != PCAP_POSTING_INDEX_SCHEMA_VERSION
        or identity.parser_contract_version != PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION
        or identity.filter_contract_version != PCAP_FILTER_CONTRACT_VERSION
    ):
        return PostingIndexAvailability.UNSUPPORTED_SCHEMA
    numeric_metadata = (
        identity.packet_count,
        identity.supported_count,
        identity.membership_count,
        identity.distinct_key_count,
        identity.chunk_count,
        identity.encoded_byte_count,
    )
    valid_dimensions = {item.value for item in PostingDimension}
    if (
        not identity.build_id
        or identity.created_at.tzinfo is None
        or identity.created_at.utcoffset() is None
        or any(type(value) is not int or value < 0 for value in numeric_metadata)
        or identity.supported_count > identity.packet_count
        or identity.membership_count < identity.supported_count
        or tuple(sorted(set(identity.complete_dimensions))) != identity.complete_dimensions
        or not set(identity.complete_dimensions) <= valid_dimensions
        or not _SHA256.fullmatch(identity.digest)
        or identity.binding_document != identity.binding.document()
    ):
        return PostingIndexAvailability.CORRUPT
    return PostingIndexAvailability.READY


class _DigestingReader:
    def __init__(self, source: Any, should_cancel: Callable[[], bool] | None) -> None:
        self.source = source
        self.should_cancel = should_cancel
        self.size_bytes = 0
        self.sha256 = hashlib.sha256()

    def read(self, size: int = -1, /) -> bytes:
        if size <= 0:
            raise ValueError("posting source reads must be positively bounded")
        if self.should_cancel is not None and self.should_cancel():
            raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")
        value = self.source.read(size)
        if not isinstance(value, bytes) or len(value) > size:
            raise PostingIndexPermanentError("POSTING_SOURCE_READER_INVALID")
        self.size_bytes += len(value)
        self.sha256.update(value)
        return value


def _binding(source: CaptureSourceVersion, parent: StructuralIndexSnapshot) -> PostingIndexBinding:
    structural = parent.binding
    return PostingIndexBinding(
        source.source_kind,
        source.source_id,
        source.source_version_id,
        source.source_size_bytes,
        source.source_sha256,
        structural.capture_format,
        parent.build_id,
        parent.index_sha256,
        structural.schema_version,
        structural.parser_contract_version,
    )


def validate_posting_index(
    snapshot: PostingIndexSnapshot,
    *,
    source_version: CaptureSourceVersion,
    parent: StructuralIndexSnapshot,
) -> bool:
    try:
        expected = _binding(source_version, parent)
    except ValueError:
        return False
    return (
        bool(snapshot.build_id)
        and validate_structural_index(parent)
        and snapshot.binding == expected
        and snapshot.generation.binding_document == expected.document()
        and validate_posting_generation(snapshot.generation)
    )


def build_source_posting_index(
    source: Any,
    *,
    source_version: CaptureSourceVersion,
    parent: StructuralIndexSnapshot,
    internal_networks: Sequence[str],
    build_id: str,
    limits: PostingBuildLimits | None = None,
    should_cancel: Callable[[], bool] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> PostingIndexSnapshot:
    """Build from one complete sequential source pass; ownership publication is separate."""
    try:
        if not validate_structural_index(parent):
            raise PostingIndexPermanentError("POSTING_PARENT_INVALID")
        if (
            parent.binding.source_kind != source_version.source_kind
            or parent.binding.source_id != source_version.source_id
            or parent.binding.source_version_id != source_version.source_version_id
            or parent.binding.source_size_bytes != source_version.source_size_bytes
            or parent.binding.source_sha256 != source_version.source_sha256
        ):
            raise PostingIndexPermanentError("POSTING_SOURCE_PARENT_MISMATCH")
        if getattr(source, "version_id", None) != source_version.source_version_id:
            raise PostingIndexPermanentError("POSTING_SOURCE_VERSION_MISMATCH")
        if should_cancel is not None and should_cancel():
            raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")
        binding = _binding(source_version, parent)
        reader = _DigestingReader(source, should_cancel)
        decoder = open_export_capture(
            reader,
            source_id=source_version.source_version_id,
            source_order=0,
            internal_networks=internal_networks,
        )
        if decoder.capture_format != binding.capture_format:
            raise PostingIndexPermanentError("POSTING_SOURCE_FORMAT_MISMATCH")
        generation = build_packet_postings(
            decoder,
            structural_packets=parent.packets,
            structural_interfaces=parent.interfaces,
            limits=limits,
            binding_document=binding.document(),
        )
        if (
            reader.size_bytes != source_version.source_size_bytes
            or reader.sha256.hexdigest() != source_version.source_sha256
            or getattr(source, "version_id", None) != source_version.source_version_id
        ):
            raise PostingIndexPermanentError("POSTING_SOURCE_DIGEST_MISMATCH")
        snapshot = PostingIndexSnapshot(
            build_id,
            binding,
            (clock or (lambda: datetime.now(UTC)))(),
            generation,
        )
        if not validate_posting_index(snapshot, source_version=source_version, parent=parent):
            raise PostingIndexPermanentError("POSTING_INTEGRITY_MISMATCH")
        return snapshot
    except PostingIndexBuildError:
        raise
    except PostingResourceLimitError as exc:
        raise PostingIndexPermanentError("POSTING_RESOURCE_LIMIT") from exc
    except PostingStructuralMismatchError as exc:
        raise PostingIndexPermanentError("POSTING_STRUCTURAL_MISMATCH") from exc
    except PcapParseError as exc:
        raise PostingIndexPermanentError("POSTING_SOURCE_FRAMING_INVALID") from exc
    except (OSError, ConnectionError, TimeoutError) as exc:
        raise PostingIndexTransientError("POSTING_SOURCE_READ_UNAVAILABLE") from exc
    except (TypeError, ValueError) as exc:
        raise PostingIndexPermanentError("POSTING_SOURCE_INVALID") from exc
    finally:
        if not getattr(source, "closed", False):
            try:
                source.close()
            except (OSError, ConnectionError, TimeoutError):
                pass


def build_and_publish_source_posting_index(
    repository: Any,
    source: Any,
    *,
    source_version: CaptureSourceVersion,
    parent: StructuralIndexSnapshot,
    internal_networks: Sequence[str],
    build_id: str,
    attempt: int,
    lease_token: str,
    now: datetime,
    limits: PostingBuildLimits | None = None,
    stage_batch_size: int = 1_000,
    should_cancel: Callable[[], bool] | None = None,
    on_published: Callable[[PostingIndexSnapshot], None] | None = None,
) -> bool:
    if stage_batch_size <= 0:
        raise ValueError("posting staging batch size must be positive")
    snapshot = build_source_posting_index(
        source,
        source_version=source_version,
        parent=parent,
        internal_networks=internal_networks,
        build_id=build_id,
        limits=limits,
        should_cancel=should_cancel,
        clock=lambda: now,
    )
    begun = False
    try:
        if should_cancel is not None and should_cancel():
            raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")
        try:
            repository.begin_posting_index(snapshot, attempt=attempt, lease_token=lease_token)
            begun = True
            chunks = snapshot.generation.chunks
            for offset in range(0, len(chunks), stage_batch_size):
                if should_cancel is not None and should_cancel():
                    raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")
                repository.stage_posting_index_chunks(
                    build_id,
                    chunks[offset : offset + stage_batch_size],
                    source_kind=source_version.source_kind,
                    source_id=source_version.source_id,
                    attempt=attempt,
                    lease_token=lease_token,
                )
        except PostingIndexBuildError:
            raise
        except Exception as exc:
            raise PostingIndexTransientError("POSTING_STAGING_UNAVAILABLE") from exc
        if should_cancel is not None and should_cancel():
            raise PostingIndexTransientError("POSTING_BUILD_CANCELLED")
        try:
            published = repository.publish_posting_index(
                build_id,
                source_version=source_version,
                parent=parent,
                attempt=attempt,
                lease_token=lease_token,
            )
        except Exception as exc:
            raise PostingIndexTransientError("POSTING_PUBLICATION_UNAVAILABLE") from exc
        if not published:
            raise PostingIndexPermanentError("POSTING_PUBLICATION_REJECTED")
        if on_published is not None:
            try:
                on_published(snapshot)
            except Exception:
                logger.warning("posting publication callback failed after success", exc_info=True)
        return True
    except Exception:
        if begun:
            try:
                repository.abort_posting_index(
                    build_id,
                    source_kind=source_version.source_kind,
                    source_id=source_version.source_id,
                    parent_structural_build_id=parent.build_id,
                    attempt=attempt,
                    lease_token=lease_token,
                )
            except Exception:
                logger.warning(
                    "posting index abort failed while preserving primary failure",
                    exc_info=True,
                )
        raise
