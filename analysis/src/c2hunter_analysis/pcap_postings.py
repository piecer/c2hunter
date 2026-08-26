from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any

PCAP_POSTING_INDEX_SCHEMA_VERSION = 1
PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION = 1
PCAP_FILTER_CONTRACT_VERSION = 1
MAX_POSTING_ORDINAL = 2**64 - 1

_DIGEST_DOMAIN = b"c2hunter-pcap-posting-index-v1\n"
_PROTOCOL = re.compile(r"^(?:[A-Z][A-Z0-9_]*|IP_(?:0|[1-9][0-9]{0,2}))$")


class PostingDimension(str, Enum):
    ALL_PACKET = "ALL_PACKET"
    SUPPORTED = "SUPPORTED"
    SRC_ADDRESS = "SRC_ADDRESS"
    DST_ADDRESS = "DST_ADDRESS"
    SRC_PORT = "SRC_PORT"
    DST_PORT = "DST_PORT"
    PROTOCOL = "PROTOCOL"
    HAS_PAYLOAD = "HAS_PAYLOAD"


class PostingError(ValueError):
    def __init__(self, message: str, code: str) -> None:
        super().__init__(message)
        self.code = code


class PostingCodecError(PostingError):
    def __init__(self, message: str) -> None:
        super().__init__(message, "POSTING_CODEC_INVALID")


class PostingBuildError(PostingError):
    pass


class PostingResourceLimitError(PostingBuildError):
    def __init__(self, message: str = "posting resource limit exceeded") -> None:
        super().__init__(message, "POSTING_RESOURCE_LIMIT")


class PostingStructuralMismatchError(PostingBuildError):
    def __init__(self, message: str = "posting source does not match structural snapshot") -> None:
        super().__init__(message, "POSTING_STRUCTURAL_MISMATCH")


@dataclass(frozen=True)
class PostingBuildLimits:
    max_packets: int = 10_000_000
    max_memberships: int = 20_000_000
    max_distinct_keys: int = 1_000_000
    max_encoded_bytes: int = 512 * 1024 * 1024
    max_chunks: int = 1_000_000
    batch_size: int = 1_000

    def __post_init__(self) -> None:
        if (
            min(
                self.max_packets,
                self.max_memberships,
                self.max_distinct_keys,
                self.max_encoded_bytes,
                self.max_chunks,
                self.batch_size,
            )
            <= 0
        ):
            raise ValueError("posting build limits must be positive")


@dataclass(frozen=True)
class PostingQueryLimits:
    max_operations: int = 100_000
    max_result_ordinals: int = 100_000
    max_decoded_memberships: int = 100_000
    max_directory_chunks: int = 100_000
    max_dictionary_terms: int = 100_000

    def __post_init__(self) -> None:
        if (
            min(
                self.max_operations,
                self.max_result_ordinals,
                self.max_decoded_memberships,
                self.max_directory_chunks,
                self.max_dictionary_terms,
            )
            <= 0
        ):
            raise ValueError("posting query limits must be positive")


@dataclass(frozen=True)
class PostingChunk:
    dimension: PostingDimension
    value: bytes
    chunk_ordinal: int
    first_packet_index: int
    last_packet_index: int
    count: int
    encoded_ordinals: bytes


@dataclass(frozen=True)
class PacketPostingProjection:
    packet_index: int
    source_address: bytes | None
    destination_address: bytes | None
    source_port: bytes | None
    destination_port: bytes | None
    protocol: bytes | None
    has_payload: bytes | None
    supported: bool


@dataclass(frozen=True)
class PostingGeneration:
    schema_version: int
    parser_contract_version: int
    filter_contract_version: int
    packet_count: int
    supported_count: int
    membership_count: int
    distinct_key_count: int
    encoded_byte_count: int
    complete_dimensions: frozenset[PostingDimension]
    chunks: tuple[PostingChunk, ...]
    digest: str
    binding_document: bytes = b""

    def digest_document(self) -> bytes:
        document = bytearray()
        _stream_generation_digest_document(self, document.extend)
        return bytes(document)


_ALL_DIMENSIONS = frozenset(PostingDimension)


def canonical_address(value: str) -> bytes:
    address = ipaddress.ip_address(value)
    return bytes((address.version,)) + address.packed


def canonical_port(value: int) -> bytes:
    if isinstance(value, bool) or not 0 <= value <= 65_535:
        raise ValueError("port must be an unsigned 16-bit integer")
    return value.to_bytes(2, "big")


def canonical_protocol(value: str) -> bytes:
    normalized = value.upper()
    if not _PROTOCOL.fullmatch(normalized):
        raise ValueError("protocol is not canonicalizable")
    if normalized.startswith("IP_") and int(normalized[3:]) > 255:
        raise ValueError("IP protocol number must be at most 255")
    return normalized.encode("ascii")


def canonical_payload(value: bool) -> bytes:
    if not isinstance(value, bool):
        raise ValueError("payload term must be boolean")
    return b"\x01" if value else b"\x00"


def _varint(value: int) -> bytes:
    if not 0 <= value <= MAX_POSTING_ORDINAL:
        raise PostingCodecError("delta must fit in an unsigned 64-bit integer")
    result = bytearray()
    while value >= 0x80:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def encode_ordinals(values: Iterable[int]) -> bytes:
    result = bytearray()
    previous = -1
    for value in values:
        if not isinstance(value, int) or isinstance(value, bool):
            raise PostingCodecError("packet ordinals must be unsigned 64-bit integers")
        if value < 0 or value > MAX_POSTING_ORDINAL:
            raise PostingCodecError("packet ordinal exceeds unsigned 64-bit range")
        if value <= previous:
            raise PostingCodecError("packet ordinals must be strictly increasing")
        delta = value - previous
        if delta > MAX_POSTING_ORDINAL:
            raise PostingCodecError("delta must fit in an unsigned 64-bit integer")
        result.extend(_varint(delta))
        previous = value
    return bytes(result)


def _iter_decoded_ordinals(value: bytes, *, max_ordinal: int | None = None) -> Iterable[int]:
    if max_ordinal is not None and (
        not isinstance(max_ordinal, int)
        or isinstance(max_ordinal, bool)
        or not 0 <= max_ordinal <= MAX_POSTING_ORDINAL
    ):
        raise PostingCodecError("maximum ordinal must be an unsigned 64-bit integer")
    previous = -1
    offset = 0
    while offset < len(value):
        start = offset
        decoded = 0
        for byte_index in range(10):
            if offset >= len(value):
                raise PostingCodecError("truncated or oversized delta varint")
            byte = value[offset]
            offset += 1
            payload = byte & 0x7F
            if byte_index == 9 and (byte & 0x80 or payload > 0x01):
                raise PostingCodecError("truncated or oversized delta varint")
            shift = byte_index * 7
            if payload > (MAX_POSTING_ORDINAL >> shift):
                raise PostingCodecError("delta varint exceeds unsigned 64-bit range")
            decoded |= payload << shift
            if not byte & 0x80:
                break
        else:
            raise PostingCodecError("truncated or oversized delta varint")
        if value[start:offset] != _varint(decoded):
            raise PostingCodecError("delta varint is not canonical")
        if decoded == 0:
            raise PostingCodecError("decoded ordinals are not strictly increasing")
        if previous > MAX_POSTING_ORDINAL - decoded:
            raise PostingCodecError("decoded ordinal exceeds unsigned 64-bit range")
        ordinal = previous + decoded
        if max_ordinal is not None and ordinal > max_ordinal:
            raise PostingCodecError("decoded ordinal exceeds packet universe")
        yield ordinal
        previous = ordinal


def decode_ordinals(value: bytes, *, max_ordinal: int | None = None) -> tuple[int, ...]:
    return tuple(_iter_decoded_ordinals(value, max_ordinal=max_ordinal))


@dataclass(frozen=True)
class _LogicalPostingStats:
    memberships: int
    encoded_bytes: int
    distinct_keys: int
    supported: int
    all_packets: int


def _digest_header(generation: PostingGeneration) -> bytes:
    header = {
        "binding": generation.binding_document.hex(),
        "complete_dimensions": sorted(item.value for item in generation.complete_dimensions),
        "distinct_key_count": generation.distinct_key_count,
        "filter_contract_version": generation.filter_contract_version,
        "membership_count": generation.membership_count,
        "packet_count": generation.packet_count,
        "parser_contract_version": generation.parser_contract_version,
        "schema_version": generation.schema_version,
        "supported_count": generation.supported_count,
    }
    return json.dumps(header, sort_keys=True, separators=(",", ":")).encode()


def _valid_posting_value(dimension: PostingDimension, value: bytes) -> bool:
    if dimension in {PostingDimension.ALL_PACKET, PostingDimension.SUPPORTED}:
        return value == b""
    if dimension in {PostingDimension.SRC_ADDRESS, PostingDimension.DST_ADDRESS}:
        return (len(value) == 5 and value[:1] == b"\x04") or (
            len(value) == 17 and value[:1] == b"\x06"
        )
    if dimension in {PostingDimension.SRC_PORT, PostingDimension.DST_PORT}:
        return len(value) == 2
    if dimension is PostingDimension.HAS_PAYLOAD:
        return value in {b"\x00", b"\x01"}
    if dimension is PostingDimension.PROTOCOL:
        try:
            decoded = value.decode("ascii")
            return canonical_protocol(decoded) == value
        except (UnicodeDecodeError, ValueError):
            return False
    return False


def _stream_generation_digest_document(
    generation: PostingGeneration, update: Any
) -> _LogicalPostingStats:
    update(_DIGEST_DOMAIN)
    update(_digest_header(generation))
    update(b"\n")
    directory: defaultdict[tuple[PostingDimension, bytes], list[PostingChunk]] = defaultdict(list)
    encoded_bytes = 0
    for chunk in generation.chunks:
        directory[(chunk.dimension, chunk.value)].append(chunk)
        encoded_bytes += len(chunk.encoded_ordinals)

    memberships = 0
    supported = 0
    all_packets = 0
    for dimension, value in sorted(directory, key=lambda item: (item[0].value, item[1])):
        if not _valid_posting_value(dimension, value):
            raise PostingCodecError("posting dictionary value is not canonical")
        update(b'{"dimension":')
        update(json.dumps(dimension.value, separators=(",", ":")).encode())
        update(b',"ordinals":"')
        logical_previous = -1
        ordered = sorted(directory[(dimension, value)], key=lambda item: item.chunk_ordinal)
        for expected_chunk, chunk in enumerate(ordered):
            first: int | None = None
            last: int | None = None
            count = 0
            for ordinal in _iter_decoded_ordinals(
                chunk.encoded_ordinals, max_ordinal=generation.packet_count - 1
            ):
                if ordinal <= logical_previous:
                    raise PostingCodecError("decoded chunks are not strictly increasing")
                update(_varint(ordinal - logical_previous).hex().encode("ascii"))
                logical_previous = ordinal
                first = ordinal if first is None else first
                last = ordinal
                count += 1
                memberships += 1
                if dimension is PostingDimension.SUPPORTED:
                    supported += 1
                if dimension is PostingDimension.ALL_PACKET:
                    if ordinal != all_packets:
                        raise PostingCodecError("ALL_PACKET is not contiguous")
                    all_packets += 1
            if (
                chunk.chunk_ordinal != expected_chunk
                or count < 1
                or count != chunk.count
                or first != chunk.first_packet_index
                or last != chunk.last_packet_index
            ):
                raise PostingCodecError("posting chunk metadata does not match ordinals")
        update(b'","value":')
        update(json.dumps(value.hex(), separators=(",", ":")).encode())
        update(b"}\n")
    return _LogicalPostingStats(memberships, encoded_bytes, len(directory), supported, all_packets)


def _generation_digest(generation: PostingGeneration) -> str:
    digest = hashlib.sha256()
    _stream_generation_digest_document(generation, digest.update)
    return digest.hexdigest()


def _same_interface(decoded: Any, structural: Any) -> bool:
    return all(
        getattr(decoded, name) == getattr(structural, name)
        for name in (
            "section_index",
            "interface_id",
            "interface_ordinal",
            "link_type",
            "snaplen",
            "timestamp_resolution_numerator",
            "timestamp_resolution_denominator",
            "timestamp_offset_seconds",
        )
    )


def _projection(packet: Any) -> PacketPostingProjection:
    index = int(packet.locator.packet_index)
    return PacketPostingProjection(
        index,
        canonical_address(packet.source_ip) if packet.supported and packet.source_ip else None,
        canonical_address(packet.destination_ip)
        if packet.supported and packet.destination_ip
        else None,
        canonical_port(packet.source_port)
        if packet.supported and packet.source_port is not None
        else None,
        canonical_port(packet.destination_port)
        if packet.supported and packet.destination_port is not None
        else None,
        canonical_protocol(packet.protocol) if packet.supported and packet.protocol else None,
        canonical_payload(packet.has_payload)
        if packet.supported and packet.has_payload is not None
        else None,
        bool(packet.supported),
    )


def _projection_memberships(
    item: PacketPostingProjection,
) -> tuple[tuple[PostingDimension, bytes], ...]:
    memberships: list[tuple[PostingDimension, bytes]] = [(PostingDimension.ALL_PACKET, b"")]
    if not item.supported:
        return tuple(memberships)
    memberships.append((PostingDimension.SUPPORTED, b""))
    for dimension, value in (
        (PostingDimension.SRC_ADDRESS, item.source_address),
        (PostingDimension.DST_ADDRESS, item.destination_address),
        (PostingDimension.SRC_PORT, item.source_port),
        (PostingDimension.DST_PORT, item.destination_port),
        (PostingDimension.PROTOCOL, item.protocol),
        (PostingDimension.HAS_PAYLOAD, item.has_payload),
    ):
        if value is not None:
            memberships.append((dimension, value))
    return tuple(memberships)


def build_packet_postings(
    decoder: Any,
    *,
    structural_packets: Sequence[Any],
    structural_interfaces: Sequence[Any],
    limits: PostingBuildLimits | None = None,
    binding_document: bytes = b"",
) -> PostingGeneration:
    """Consume one decoder completely and atomically return a complete posting generation."""
    limits = limits or PostingBuildLimits()
    chunks: list[PostingChunk] = []
    next_chunk: defaultdict[tuple[PostingDimension, bytes], int] = defaultdict(int)
    distinct: set[tuple[PostingDimension, bytes]] = set()
    memberships = 0
    encoded_bytes = 0
    supported = 0
    count = 0
    batch: defaultdict[tuple[PostingDimension, bytes], list[int]] = defaultdict(list)

    def flush() -> None:
        nonlocal encoded_bytes
        pending: list[PostingChunk] = []
        pending_bytes = 0
        for key in sorted(batch, key=lambda item: (item[0].value, item[1])):
            ordinals = tuple(batch[key])
            encoded = encode_ordinals(ordinals)
            pending_bytes += len(encoded)
            pending.append(
                PostingChunk(
                    key[0],
                    key[1],
                    next_chunk[key],
                    ordinals[0],
                    ordinals[-1],
                    len(ordinals),
                    encoded,
                )
            )
        if encoded_bytes + pending_bytes > limits.max_encoded_bytes:
            raise PostingResourceLimitError("posting encoded-byte limit exceeded")
        if len(chunks) + len(pending) > limits.max_chunks:
            raise PostingResourceLimitError("posting chunk limit exceeded")
        for item in pending:
            next_chunk[(item.dimension, item.value)] += 1
        chunks.extend(pending)
        encoded_bytes += pending_bytes
        batch.clear()

    interface_by_ordinal = {int(item.interface_ordinal): item for item in structural_interfaces}
    if len(interface_by_ordinal) != len(structural_interfaces):
        raise PostingStructuralMismatchError("structural interface identities are invalid")
    for packet in decoder.iter_packets():
        if count >= limits.max_packets:
            raise PostingResourceLimitError("posting packet limit exceeded")
        if count >= len(structural_packets):
            raise PostingStructuralMismatchError("decoder produced extra packet")
        expected = structural_packets[count]
        locator = packet.locator
        expected_locator = (
            expected.packet_index,
            expected.record_offset,
            expected.data_offset,
            expected.captured_length,
            expected.framed_length,
        )
        actual_locator = (
            locator.packet_index,
            locator.record_offset,
            locator.data_offset,
            locator.captured_length,
            locator.framed_length,
        )
        structural_interface = interface_by_ordinal.get(int(expected.interface_ordinal))
        if (
            actual_locator != expected_locator
            or packet.original_length != expected.original_length
            or structural_interface is None
            or (expected.section_index, expected.interface_id, expected.interface_ordinal)
            != (
                packet.interface.section_index,
                packet.interface.interface_id,
                packet.interface.interface_ordinal,
            )
            or not _same_interface(packet.interface, structural_interface)
        ):
            raise PostingStructuralMismatchError()
        projection = _projection(packet)
        packet_memberships = _projection_memberships(projection)
        if memberships + len(packet_memberships) > limits.max_memberships:
            raise PostingResourceLimitError("posting membership limit exceeded")
        new_keys = tuple(key for key in packet_memberships if key not in distinct)
        if len(distinct) + len(new_keys) > limits.max_distinct_keys:
            raise PostingResourceLimitError("posting distinct-key limit exceeded")
        distinct.update(new_keys)
        memberships += len(packet_memberships)
        supported += projection.supported
        for key in packet_memberships:
            batch[key].append(count)
        count += 1
        if count % limits.batch_size == 0:
            flush()
    flush()
    if count != len(structural_packets) or count < 1:
        raise PostingStructuralMismatchError(
            "decoder packet count does not match structural snapshot"
        )
    generation = PostingGeneration(
        PCAP_POSTING_INDEX_SCHEMA_VERSION,
        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        PCAP_FILTER_CONTRACT_VERSION,
        count,
        supported,
        memberships,
        len(distinct),
        encoded_bytes,
        _ALL_DIMENSIONS,
        tuple(chunks),
        "",
        bytes(binding_document),
    )
    generation = replace(generation, digest=_generation_digest(generation))
    if not validate_posting_generation(generation):
        raise PostingBuildError(
            "built posting generation failed validation", "POSTING_INTEGRITY_MISMATCH"
        )
    return generation


def posting_values(
    generation: PostingGeneration, dimension: PostingDimension, value: bytes
) -> tuple[int, ...]:
    result: list[int] = []
    for chunk in sorted(
        (item for item in generation.chunks if item.dimension is dimension and item.value == value),
        key=lambda item: item.chunk_ordinal,
    ):
        result.extend(
            decode_ordinals(chunk.encoded_ordinals, max_ordinal=generation.packet_count - 1)
        )
    return tuple(result)


def validate_posting_generation(
    generation: PostingGeneration, *, limits: PostingBuildLimits | None = None
) -> bool:
    limits = limits or PostingBuildLimits()
    counts = (
        generation.packet_count,
        generation.supported_count,
        generation.membership_count,
        generation.distinct_key_count,
        generation.encoded_byte_count,
    )
    if (
        any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts)
        or generation.schema_version != PCAP_POSTING_INDEX_SCHEMA_VERSION
        or generation.parser_contract_version != PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION
        or generation.filter_contract_version != PCAP_FILTER_CONTRACT_VERSION
        or not 1 <= generation.packet_count <= min(limits.max_packets, MAX_POSTING_ORDINAL + 1)
        or generation.supported_count > generation.packet_count
        or generation.membership_count > limits.max_memberships
        or generation.distinct_key_count > limits.max_distinct_keys
        or generation.encoded_byte_count > limits.max_encoded_bytes
        or len(generation.chunks) > limits.max_chunks
        or len(generation.chunks) > generation.membership_count
        or len(generation.binding_document) > limits.max_encoded_bytes
        or generation.complete_dimensions != _ALL_DIMENSIONS
        or not re.fullmatch(r"[0-9a-f]{64}", generation.digest)
    ):
        return False

    declared_memberships = 0
    declared_encoded_bytes = 0
    keys: set[tuple[PostingDimension, bytes]] = set()
    for chunk in generation.chunks:
        if (
            not isinstance(chunk.dimension, PostingDimension)
            or not isinstance(chunk.value, bytes)
            or not _valid_posting_value(chunk.dimension, chunk.value)
            or not isinstance(chunk.encoded_ordinals, bytes)
            or not chunk.encoded_ordinals
            or not isinstance(chunk.chunk_ordinal, int)
            or isinstance(chunk.chunk_ordinal, bool)
            or chunk.chunk_ordinal < 0
            or not isinstance(chunk.count, int)
            or isinstance(chunk.count, bool)
            or chunk.count < 1
            or not isinstance(chunk.first_packet_index, int)
            or isinstance(chunk.first_packet_index, bool)
            or not isinstance(chunk.last_packet_index, int)
            or isinstance(chunk.last_packet_index, bool)
            or not 0
            <= chunk.first_packet_index
            <= chunk.last_packet_index
            < generation.packet_count
        ):
            return False
        declared_memberships += chunk.count
        declared_encoded_bytes += len(chunk.encoded_ordinals)
        keys.add((chunk.dimension, chunk.value))
        if (
            declared_memberships > generation.membership_count
            or declared_encoded_bytes > generation.encoded_byte_count
            or len(keys) > generation.distinct_key_count
        ):
            return False
    if (
        declared_memberships != generation.membership_count
        or declared_encoded_bytes != generation.encoded_byte_count
        or len(keys) != generation.distinct_key_count
    ):
        return False

    try:
        digest = hashlib.sha256()
        stats = _stream_generation_digest_document(generation, digest.update)
    except (PostingCodecError, TypeError, ValueError):
        return False
    return (
        stats.memberships == generation.membership_count
        and stats.encoded_bytes == generation.encoded_byte_count
        and stats.distinct_keys == generation.distinct_key_count
        and stats.supported == generation.supported_count
        and stats.all_packets == generation.packet_count
        and digest.hexdigest() == generation.digest
    )


class _QueryLimitExceeded(Exception):
    pass


@dataclass
class _QueryBudget:
    limits: PostingQueryLimits
    operations: int = 0
    decoded_memberships: int = 0

    def operation(self, count: int = 1) -> None:
        if count < 0 or self.operations > self.limits.max_operations - count:
            raise _QueryLimitExceeded
        self.operations += count

    def decoded(self) -> None:
        if self.decoded_memberships >= self.limits.max_decoded_memberships:
            raise _QueryLimitExceeded
        self.decoded_memberships += 1
        self.operation()


def _query_generation_directory(
    generation: PostingGeneration, limits: PostingQueryLimits
) -> dict[tuple[PostingDimension, bytes], tuple[PostingChunk, ...]]:
    build_limits = PostingBuildLimits()
    integer_counts = (
        generation.packet_count,
        generation.supported_count,
        generation.membership_count,
        generation.distinct_key_count,
        generation.encoded_byte_count,
    )
    invalid_count = any(
        not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in integer_counts
    )
    if (
        invalid_count
        or generation.packet_count < 1
        or generation.packet_count > build_limits.max_packets
        or generation.supported_count > generation.packet_count
        or generation.membership_count > build_limits.max_memberships
        or generation.distinct_key_count > build_limits.max_distinct_keys
        or generation.encoded_byte_count > build_limits.max_encoded_bytes
        or generation.schema_version != PCAP_POSTING_INDEX_SCHEMA_VERSION
        or generation.parser_contract_version != PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION
        or generation.filter_contract_version != PCAP_FILTER_CONTRACT_VERSION
        or generation.complete_dimensions != _ALL_DIMENSIONS
        or not re.fullmatch(r"[0-9a-f]{64}", generation.digest)
        or len(generation.chunks) > limits.max_directory_chunks
        or generation.distinct_key_count > limits.max_dictionary_terms
        or len(generation.chunks) > generation.membership_count
    ):
        raise _QueryLimitExceeded

    pending: defaultdict[tuple[PostingDimension, bytes], list[PostingChunk]] = defaultdict(list)
    memberships = 0
    encoded_bytes = 0
    for chunk in generation.chunks:
        if (
            not isinstance(chunk.dimension, PostingDimension)
            or not isinstance(chunk.value, bytes)
            or not _valid_posting_value(chunk.dimension, chunk.value)
            or not isinstance(chunk.encoded_ordinals, bytes)
            or not isinstance(chunk.chunk_ordinal, int)
            or isinstance(chunk.chunk_ordinal, bool)
            or chunk.chunk_ordinal < 0
            or not isinstance(chunk.count, int)
            or isinstance(chunk.count, bool)
            or chunk.count < 1
            or chunk.first_packet_index < 0
            or chunk.last_packet_index < chunk.first_packet_index
            or chunk.last_packet_index >= generation.packet_count
            or not chunk.encoded_ordinals
        ):
            raise _QueryLimitExceeded
        memberships += chunk.count
        encoded_bytes += len(chunk.encoded_ordinals)
        if (
            memberships > generation.membership_count
            or encoded_bytes > generation.encoded_byte_count
        ):
            raise _QueryLimitExceeded
        pending[(chunk.dimension, chunk.value)].append(chunk)
    if (
        memberships != generation.membership_count
        or encoded_bytes != generation.encoded_byte_count
        or len(pending) != generation.distinct_key_count
    ):
        raise _QueryLimitExceeded

    directory: dict[tuple[PostingDimension, bytes], tuple[PostingChunk, ...]] = {}
    for key, chunks in pending.items():
        ordered = tuple(sorted(chunks, key=lambda item: item.chunk_ordinal))
        if any(
            chunk.chunk_ordinal != index
            or (index and chunk.first_packet_index <= ordered[index - 1].last_packet_index)
            for index, chunk in enumerate(ordered)
        ):
            raise _QueryLimitExceeded
        directory[key] = ordered
    return directory


# Duck typing keeps this analysis module independent of controller predicate code.
def select_posting_candidates(
    generation: PostingGeneration,
    predicate: Any,
    *,
    sensor_id: str | None = None,
    max_query_work: int | None = None,
    limits: PostingQueryLimits | None = None,
) -> tuple[int, ...] | None:
    """Return bounded posting candidates, or ``None`` to require a sequential scan."""
    requested_sensor = getattr(predicate, "sensor", None)
    if requested_sensor is not None and sensor_id is not None and requested_sensor != sensor_id:
        return ()
    if limits is not None and max_query_work is not None:
        raise ValueError("provide either limits or max_query_work, not both")
    if max_query_work is not None:
        if max_query_work <= 0:
            return None
        limits = replace(PostingQueryLimits(), max_operations=max_query_work)
    limits = limits or PostingQueryLimits()
    universe_counts = (generation.packet_count, generation.supported_count)
    if any(
        not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in universe_counts
    ):
        return None
    if (
        generation.packet_count > limits.max_result_ordinals
        or generation.packet_count > limits.max_operations
        or generation.supported_count > limits.max_result_ordinals
        or generation.supported_count > limits.max_decoded_memberships
    ):
        return None

    budget = _QueryBudget(limits)
    try:
        directory = _query_generation_directory(generation, limits)
        cache: dict[tuple[PostingDimension, bytes], frozenset[int]] = {}

        def get(dimension: PostingDimension, value: bytes) -> frozenset[int]:
            key = (dimension, value)
            existing = cache.get(key)
            if existing is not None:
                return existing
            if dimension not in generation.complete_dimensions:
                raise _QueryLimitExceeded
            chunks = directory.get(key, ())
            result: set[int] = set()
            previous = -1
            for expected_chunk, chunk in enumerate(chunks):
                first: int | None = None
                last: int | None = None
                count = 0
                for ordinal in _iter_decoded_ordinals(
                    chunk.encoded_ordinals, max_ordinal=generation.packet_count - 1
                ):
                    budget.decoded()
                    if ordinal <= previous:
                        raise PostingCodecError("decoded chunks are not strictly increasing")
                    budget.operation()  # set insertion
                    result.add(ordinal)
                    first = ordinal if first is None else first
                    last = ordinal
                    previous = ordinal
                    count += 1
                if (
                    chunk.chunk_ordinal != expected_chunk
                    or count != chunk.count
                    or first != chunk.first_packet_index
                    or last != chunk.last_packet_index
                ):
                    raise PostingCodecError("posting chunk metadata does not match ordinals")
            frozen = frozenset(result)
            cache[key] = frozen
            return frozen

        def union_values(*values: frozenset[int] | set[int]) -> set[int]:
            result: set[int] = set()
            for value in values:
                for ordinal in value:
                    budget.operation()  # union member examined
                    budget.operation()  # insertion attempt
                    result.add(ordinal)
            return result

        def intersect_values(
            left: frozenset[int] | set[int], right: frozenset[int] | set[int]
        ) -> set[int]:
            result: set[int] = set()
            for ordinal in left:
                budget.operation()  # intersection member examined
                if ordinal in right:
                    budget.operation()  # result insertion
                    result.add(ordinal)
            return result

        def subtract_values(
            left: frozenset[int] | set[int], right: frozenset[int] | set[int]
        ) -> set[int]:
            result: set[int] = set()
            for ordinal in left:
                budget.operation()  # subtraction member examined
                if ordinal not in right:
                    budget.operation()  # result insertion
                    result.add(ordinal)
            return result

        def endpoints(term: object) -> set[int]:
            network = (
                term
                if isinstance(term, ipaddress.IPv4Network | ipaddress.IPv6Network)
                else ipaddress.ip_network(str(term), strict=False)
            )
            if network.prefixlen == network.max_prefixlen:
                key = canonical_address(str(network.network_address))
                return union_values(
                    get(PostingDimension.SRC_ADDRESS, key),
                    get(PostingDimension.DST_ADDRESS, key),
                )
            terms: set[bytes] = set()
            for dimension, value in directory:
                if dimension not in {
                    PostingDimension.SRC_ADDRESS,
                    PostingDimension.DST_ADDRESS,
                }:
                    continue
                budget.operation()  # address dictionary term examined
                if value not in terms:
                    budget.operation()  # dictionary-value set insertion
                    terms.add(value)
            result: set[int] = set()
            for value in terms:
                if len(value) not in {5, 17} or value[0] not in {4, 6}:
                    raise ValueError("address dictionary term is not canonical")
                address = ipaddress.ip_address(value[1:])
                if address.version == network.version and address in network:
                    result = union_values(
                        result,
                        get(PostingDimension.SRC_ADDRESS, value),
                        get(PostingDimension.DST_ADDRESS, value),
                    )
            return result

        universe = get(PostingDimension.SUPPORTED, b"")

        def group_candidates(
            group: Mapping[str, Any], *, for_exclude: bool
        ) -> tuple[frozenset[int] | set[int], bool]:
            result: frozenset[int] | set[int] | None = None
            exact = True
            active = False
            for name, raw in group.items():
                if raw is None:
                    continue
                active = True
                posting: frozenset[int] | set[int] | None = None
                if name == "endpoint_network":
                    posting = endpoints(raw)
                elif name == "protocol":
                    posting = get(PostingDimension.PROTOCOL, canonical_protocol(str(raw)))
                elif name == "source_port":
                    posting = get(PostingDimension.SRC_PORT, canonical_port(int(raw)))
                elif name == "destination_port":
                    posting = get(PostingDimension.DST_PORT, canonical_port(int(raw)))
                elif name == "has_payload":
                    posting = get(PostingDimension.HAS_PAYLOAD, canonical_payload(raw))
                elif name == "port":
                    exact = False
                    if not for_exclude:
                        key = canonical_port(int(raw))
                        posting = union_values(
                            get(PostingDimension.SRC_PORT, key),
                            get(PostingDimension.DST_PORT, key),
                        )
                else:
                    # Direction and context-derived atoms are intentionally non-narrowing.
                    exact = False
                if posting is not None:
                    result = posting if result is None else intersect_values(result, posting)
            return (universe if result is None else result), exact and active

        result: frozenset[int] | set[int] = universe
        for value in (
            getattr(predicate, "candidate_ip", None),
            getattr(predicate, "internal_host_ip", None),
        ):
            if value is not None:
                result = intersect_values(result, endpoints(str(value)))
        port = getattr(predicate, "port", None)
        if port is not None:
            port_key = canonical_port(int(port))
            result = intersect_values(
                result,
                union_values(
                    get(PostingDimension.SRC_PORT, port_key),
                    get(PostingDimension.DST_PORT, port_key),
                ),
            )
        protocol = getattr(predicate, "protocol", None)
        if protocol:
            result = intersect_values(
                result, get(PostingDimension.PROTOCOL, canonical_protocol(str(protocol)))
            )
        includes = tuple(getattr(predicate, "include_filters", ()) or ())
        if includes:
            included: set[int] = set()
            for group in includes:
                candidates, _ = group_candidates(group, for_exclude=False)
                included = union_values(included, candidates)
            result = intersect_values(result, included)
        for group in tuple(getattr(predicate, "exclude_filters", ()) or ()):
            excluded, exact = group_candidates(group, for_exclude=True)
            if exact:
                result = subtract_values(result, excluded)
        if len(result) > limits.max_result_ordinals:
            raise _QueryLimitExceeded
        budget.operation(len(result))  # every output ordinal
        return tuple(sorted(result))
    except (PostingCodecError, _QueryLimitExceeded, ValueError, KeyError, TypeError):
        return None
