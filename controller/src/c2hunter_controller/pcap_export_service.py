from __future__ import annotations

import hashlib
import hmac
import json
import logging
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from time import perf_counter
from typing import Any, Literal, cast

from c2hunter_analysis.pcap import PcapParseError, bounded_pcap_prefix, parse_pcap
from c2hunter_analysis.pcap_export import open_export_capture

from .api_errors import ApiError
from .capture_sink import CaptureLimitTooSmall, CaptureRecordError, CaptureStorageError
from .config import Settings
from .jobs import JobState
from .pcap import (
    ExportPacketRecord,
    build_capture_result,
    build_capture_to_sink,
    compile_packet_predicate,
    filter_records,
)
from .pcap_stream import (
    CaptureIntegrityError,
    MatchedPacketRecord,
    VerifiedMatchedPackets,
    open_bounded_verified_capture,
)
from .repositories import (
    ArtifactAlreadyExistsError,
    ArtifactProducerError,
    ArtifactStorageError,
    CaptureSource,
    Repository,
)
from .schemas import PcapExportCreate

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class PcapExportDependencies:
    """Injectable Stage 3-7 processing seams shared by HTTP and workers."""

    bounded_source_factory: Callable[..., Any] = open_bounded_verified_capture
    decoder_factory: Callable[..., Any] = open_export_capture
    predicate_compiler: Callable[..., Any] = compile_packet_predicate
    capture_writer: Callable[..., Any] = build_capture_to_sink
    legacy_prefix_builder: Callable[..., Any] = bounded_pcap_prefix
    legacy_parser: Callable[..., Any] = parse_pcap
    legacy_filter: Callable[..., Any] = filter_records
    legacy_capture_builder: Callable[..., Any] = build_capture_result
    clock: Callable[[], datetime] = _utcnow


def _raw_packet_hex_size(value: Any) -> int:
    raw_packet = str(value)
    if len(raw_packet) % 2 or any(
        character not in "0123456789abcdefABCDEF" for character in raw_packet
    ):
        raise ValueError("retained raw packet is not valid hexadecimal data")
    return len(raw_packet) // 2


def _is_sha256_hex_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _close_capture_source_preserving_primary(source: CaptureSource, context: str) -> None:
    if source.closed:
        return
    try:
        source.close()
    except BaseException:
        logger.debug("%s; preserving primary failure", context, exc_info=True)


@contextmanager
def _measure_pcap_export_stage(stage_seconds: dict[str, float], stage: str) -> Iterator[None]:
    started = perf_counter()
    try:
        yield
    finally:
        stage_seconds[stage] = stage_seconds.get(stage, 0.0) + perf_counter() - started


class PcapExportExecutor:
    """Request-independent Stage 3-7 PCAP export processor and publisher."""

    def __init__(
        self,
        repository: Repository,
        settings: Settings,
        dependencies: PcapExportDependencies | None = None,
    ) -> None:
        self.repository = repository
        self.settings = settings
        self.dependencies = dependencies or PcapExportDependencies()

    def execute(
        self,
        payload: PcapExportCreate,
        stage_seconds: dict[str, float],
        *,
        export_id: str | None = None,
        source_snapshot: dict[str, Any] | None = None,
        checkpoint: Callable[..., None] | None = None,
    ) -> dict[str, Any]:
        checkpoint = checkpoint or (lambda **_progress: None)
        checkpoint(phase="SNAPSHOT_VALIDATION", percent=1)
        job = self.repository.get_job_summary(payload.job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        if job.get("mode") == "LIVE" and job.get("status") != JobState.COMPLETED:
            raise ApiError(
                409,
                "PCAP_SOURCE_NOT_FINAL",
                "LIVE analysis must be completed before PCAP export",
            )
        candidate_ip = None
        if payload.candidate_id:
            found_candidate = self.repository.get_candidate(payload.candidate_id)
            if found_candidate is None or found_candidate[0] != payload.job_id:
                raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
            candidate = found_candidate[1]
            candidate_ip = candidate["candidate_ip"]
        normalized = payload.model_dump(mode="json", exclude_none=True, exclude={"idempotency_key"})
        normalized["candidate_ip"] = candidate_ip
        source_job = job
        visited: set[str] = set()
        retained_capture: bytes | None = None
        canonical_capture_metadata: dict[str, Any] | None = None
        segment_metadata: list[dict[str, Any]] = []
        immutable_manifest = (
            list(source_snapshot.get("source_manifest", []))
            if source_snapshot is not None and "source_manifest" in source_snapshot
            else None
        )
        if immutable_manifest is not None:
            if source_snapshot is None:
                raise ApiError(
                    409,
                    "PCAP_SOURCE_PROVENANCE_INVALID",
                    "PCAP source snapshot is unavailable",
                )
            source_job_id = str(source_snapshot["source_job_id"])
            resolved = self.repository.get_job_summary(source_job_id)
            if resolved is None:
                raise ApiError(
                    409, "PCAP_SOURCE_PROVENANCE_INVALID", "PCAP source analysis missing"
                )
            source_job = resolved
            if source_snapshot.get("source_kind") == "canonical_capture" and immutable_manifest:
                canonical_capture_metadata = {**immutable_manifest[0], "_canonical": True}
            else:
                segment_metadata = [dict(item) for item in immutable_manifest]
        else:
            while True:
                source_job_id = str(source_job["id"])
                if source_job_id in visited:
                    raise ApiError(
                        409, "PCAP_SOURCE_PROVENANCE_INVALID", "PCAP source provenance cycle"
                    )
                visited.add(source_job_id)
                source_metadata = source_job.get("source")
                if isinstance(source_metadata, dict) and source_metadata.get(
                    "packet_bytes_retained"
                ):
                    canonical_capture_metadata = source_metadata
                    break
                with _measure_pcap_export_stage(stage_seconds, "source_read"):
                    retained_capture = self.repository.get_job_capture(source_job_id)
                if retained_capture is not None:
                    break
                segment_metadata = self.repository.list_sensor_pcaps_for_job(source_job_id)
                if segment_metadata:
                    if (
                        source_job.get("mode") == "LIVE"
                        and source_job.get("status") != JobState.COMPLETED
                    ):
                        raise ApiError(
                            409,
                            "PCAP_SOURCE_NOT_FINAL",
                            "LIVE analysis must be completed before PCAP export",
                        )
                    break
                parent_id = source_job.get("parent_job_id")
                if not parent_id:
                    break
                parent = self.repository.get_job_summary(str(parent_id))
                if parent is None:
                    raise ApiError(
                        409, "PCAP_SOURCE_PROVENANCE_INVALID", "PCAP source analysis missing"
                    )
                source_job = parent

        checkpoint(phase="SOURCE_FETCH", percent=5)
        source_records: list[dict[str, Any]] = []
        matched_records: list[MatchedPacketRecord] = []
        source_manifest: list[dict[str, str]] = []
        sensor_ids = source_job.get("sensor_ids") or ["uploaded"]
        if canonical_capture_metadata is not None:
            source_descriptors: list[tuple[dict[str, Any], bytes | None]] = [
                (
                    {
                        "id": source_job_id,
                        "sensor_id": str(sensor_ids[0]),
                        "size_bytes": canonical_capture_metadata.get("size_bytes"),
                        "sha256": canonical_capture_metadata.get("sha256"),
                        "_canonical": True,
                    },
                    None,
                )
            ]
        elif retained_capture is not None:
            expected_digest = (source_job.get("source") or {}).get("sha256")
            source_descriptors = [
                (
                    {
                        "id": source_job_id,
                        "sensor_id": str(sensor_ids[0]),
                        "size_bytes": len(retained_capture),
                        "sha256": str(expected_digest or ""),
                    },
                    retained_capture,
                )
            ]
        else:
            source_descriptors = [(segment, None) for segment in segment_metadata]

        source_capture_count = len(source_descriptors)
        use_streaming_pipeline = self.settings.pcap_export_pipeline == "streaming" and all(
            content is None for _descriptor, content in source_descriptors
        )
        try:
            declared_source_sizes = []
            for descriptor, _content in source_descriptors:
                size_value = descriptor.get("size_bytes")
                if isinstance(size_value, bool) or not isinstance(size_value, int | str):
                    raise ValueError
                declared_source_sizes.append(int(size_value))
        except (TypeError, ValueError) as exc:
            raise ApiError(
                409,
                "PCAP_SOURCE_INTEGRITY_ERROR",
                "retained PCAP size metadata is invalid",
            ) from exc
        if any(size < 0 for size in declared_source_sizes):
            raise ApiError(
                409,
                "PCAP_SOURCE_INTEGRITY_ERROR",
                "retained PCAP size metadata is invalid",
            )
        for descriptor, _content in source_descriptors:
            if not _is_sha256_hex_digest(descriptor.get("sha256")):
                raise ApiError(
                    409,
                    "PCAP_SOURCE_INTEGRITY_ERROR",
                    "retained PCAP digest metadata is invalid",
                )
        source_total_bytes = sum(declared_source_sizes)
        scan_max_bytes = cast(int, self.settings.pcap_export_scan_max_bytes)
        scan_max_packets = cast(int, self.settings.pcap_export_scan_max_packets)
        scanned_source_bytes = 0
        scanned_source_capture_count = 0
        remaining_packets = scan_max_packets
        source_truncation_reasons: list[str] = []
        checkpoint(phase="SOURCE_SCAN", percent=10)
        if use_streaming_pipeline and source_descriptors:
            predicate = self.dependencies.predicate_compiler(
                normalized, internal_networks=list(job["internal_networks"])
            )
            for source_order, (descriptor, _retained_content) in enumerate(source_descriptors):
                if remaining_packets < 1:
                    source_truncation_reasons.append("SOURCE_PACKET_LIMIT")
                    break
                remaining_source_bytes = scan_max_bytes - scanned_source_bytes
                if remaining_source_bytes < 1:
                    source_truncation_reasons.append("SOURCE_BYTE_LIMIT")
                    break
                expected_digest = descriptor.get("sha256")
                if not expected_digest:
                    raise ApiError(
                        409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP digest missing"
                    )
                is_canonical = descriptor.get("_canonical") is True
                if is_canonical:
                    checkpoint(phase="SOURCE_FETCH")
                    with _measure_pcap_export_stage(stage_seconds, "source_read"):
                        opened_source = self.repository.open_job_capture(source_job_id)
                    if opened_source is None:
                        raise ApiError(
                            409,
                            "PCAP_SOURCE_INTEGRITY_ERROR",
                            "retained canonical PCAP missing",
                        )
                    stored_metadata = descriptor
                    source = opened_source
                else:
                    checkpoint(phase="SOURCE_FETCH")
                    with _measure_pcap_export_stage(stage_seconds, "source_read"):
                        opened_segment = self.repository.open_sensor_pcap(str(descriptor["id"]))
                    if opened_segment is None:
                        raise ApiError(
                            409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP segment missing"
                        )
                    stored_metadata, source = opened_segment
                    stored_size_value = stored_metadata.get("size_bytes")
                    try:
                        if isinstance(stored_size_value, bool) or not isinstance(
                            stored_size_value, int | str
                        ):
                            raise ValueError
                        stored_size = int(stored_size_value)
                    except (TypeError, ValueError) as exc:
                        _close_capture_source_preserving_primary(
                            source,
                            "Capture source close failed after invalid retained size metadata",
                        )
                        raise ApiError(
                            409,
                            "PCAP_SOURCE_INTEGRITY_ERROR",
                            "retained PCAP size metadata is invalid",
                        ) from exc
                    stored_digest = stored_metadata.get("sha256")
                    if not _is_sha256_hex_digest(stored_digest):
                        _close_capture_source_preserving_primary(
                            source,
                            "Capture source close failed after invalid retained digest metadata",
                        )
                        raise ApiError(
                            409,
                            "PCAP_SOURCE_INTEGRITY_ERROR",
                            "retained PCAP digest metadata is invalid",
                        )
                    if (
                        str(stored_metadata.get("id", "")) != str(descriptor.get("id", ""))
                        or str(stored_metadata.get("sensor_id", ""))
                        != str(descriptor.get("sensor_id", ""))
                        or stored_metadata.get("analysis_job_id") != source_job_id
                        or stored_size != declared_source_sizes[source_order]
                        or stored_digest != descriptor.get("sha256")
                    ):
                        _close_capture_source_preserving_primary(
                            source,
                            "Capture source close failed after retained metadata mismatch",
                        )
                        raise ApiError(
                            409,
                            "PCAP_SOURCE_INTEGRITY_ERROR",
                            "retained PCAP metadata mismatch",
                        )
                try:
                    session = self.dependencies.bounded_source_factory(
                        source,
                        expected_size=declared_source_sizes[source_order],
                        expected_sha256=str(expected_digest),
                        max_admitted_bytes=remaining_source_bytes,
                        max_admitted_packets=remaining_packets,
                        stage_seconds=stage_seconds,
                    )
                except BaseException:
                    # A successful factory call transfers ownership to the session.
                    # On failure, this guard covers factories that did not take it.
                    _close_capture_source_preserving_primary(
                        source,
                        "Capture source close failed after bounded capture factory failure",
                    )
                    raise
                provisional: list[MatchedPacketRecord] = []
                provisional_packets = 0
                parse_error: PcapParseError | None = None
                try:
                    try:
                        decoder = self.dependencies.decoder_factory(
                            session.reader,
                            source_id=source.version_id,
                            source_order=source_order,
                            internal_networks=list(job["internal_networks"]),
                        )
                        packets = iter(decoder.iter_packets())
                        while True:
                            source_before = stage_seconds.get("source_read", 0.0)
                            hash_before = stage_seconds.get("hash", 0.0)
                            frame_before = stage_seconds.get("frame", 0.0)
                            started_decode = perf_counter()
                            try:
                                packet = next(packets)
                            except StopIteration:
                                break
                            finally:
                                nested = (
                                    stage_seconds.get("source_read", 0.0)
                                    - source_before
                                    + stage_seconds.get("hash", 0.0)
                                    - hash_before
                                    + stage_seconds.get("frame", 0.0)
                                    - frame_before
                                )
                                stage_seconds["decode"] = stage_seconds.get("decode", 0.0) + max(
                                    0.0, perf_counter() - started_decode - nested
                                )
                            provisional_packets += 1
                            if provisional_packets % 256 == 0:
                                checkpoint(
                                    phase="SOURCE_SCAN",
                                    scanned_packet_count=(
                                        scan_max_packets - remaining_packets + provisional_packets
                                    ),
                                )
                            if not packet.supported:
                                continue
                            with _measure_pcap_export_stage(stage_seconds, "filter"):
                                matched = predicate.matches(
                                    packet, sensor_id=str(stored_metadata["sensor_id"])
                                )
                            if not matched:
                                continue
                            provisional.append(
                                MatchedPacketRecord.from_export_packet(
                                    packet, sensor_id=str(stored_metadata["sensor_id"])
                                )
                            )
                    except PcapParseError as exc:
                        parse_error = exc
                    except CaptureIntegrityError:
                        # The session remembers the primary read failure; finalization
                        # closes the source and re-raises it with integrity precedence.
                        pass
                    try:
                        scan = session.drain_and_verify()
                    except CaptureIntegrityError as exc:
                        raise ApiError(409, "PCAP_SOURCE_INTEGRITY_ERROR", str(exc)) from exc
                    if parse_error is not None and not (
                        parse_error.code == "EMPTY_PCAP"
                        and scan.admitted_packets == 0
                        and (scan.byte_limited or scan.packet_limited)
                    ):
                        raise ApiError(422, parse_error.code, str(parse_error)) from parse_error
                    source_manifest.append(
                        {"id": str(stored_metadata["id"]), "sha256": scan.actual_sha256}
                    )
                    scanned_source_bytes += scan.admitted_bytes
                    remaining_packets -= scan.admitted_packets
                    if provisional_packets:
                        scanned_source_capture_count += 1
                    matched_records.extend(provisional)
                    if scan.byte_limited:
                        source_truncation_reasons.append("SOURCE_BYTE_LIMIT")
                    if scan.packet_limited:
                        source_truncation_reasons.append("SOURCE_PACKET_LIMIT")
                    if scan.byte_limited or scan.packet_limited:
                        break
                finally:
                    try:
                        session.close()
                    except BaseException:
                        logger.debug(
                            "Capture session close failed after export processing; "
                            "preserving primary failure",
                            exc_info=True,
                        )
        for source_order, (descriptor, retained_content) in enumerate(
            source_descriptors if not use_streaming_pipeline else []
        ):
            declared_size = declared_source_sizes[source_order]
            if remaining_packets < 1:
                source_truncation_reasons.append("SOURCE_PACKET_LIMIT")
                break
            remaining_source_bytes = scan_max_bytes - scanned_source_bytes
            if remaining_source_bytes < 1:
                source_truncation_reasons.append("SOURCE_BYTE_LIMIT")
                break
            is_canonical = descriptor.get("_canonical") is True
            if is_canonical:
                with _measure_pcap_export_stage(stage_seconds, "source_read"):
                    capture_content = self.repository.get_job_capture(source_job_id)
                if capture_content is None:
                    raise ApiError(
                        409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained canonical PCAP missing"
                    )
                stored_metadata = descriptor
            elif retained_content is None:
                with _measure_pcap_export_stage(stage_seconds, "source_read"):
                    stored_segment = self.repository.get_sensor_pcap(str(descriptor["id"]))
                if stored_segment is None:
                    raise ApiError(
                        409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP segment missing"
                    )
                stored_metadata, capture_content = stored_segment
            else:
                stored_metadata, capture_content = descriptor, retained_content
            stored_size_value = stored_metadata.get("size_bytes")
            try:
                if isinstance(stored_size_value, bool) or not isinstance(
                    stored_size_value, int | str
                ):
                    raise ValueError
                stored_size = int(stored_size_value)
            except (TypeError, ValueError) as exc:
                raise ApiError(
                    409,
                    "PCAP_SOURCE_INTEGRITY_ERROR",
                    "retained PCAP size metadata is invalid",
                ) from exc
            if stored_size < 0 or stored_size != len(capture_content):
                raise ApiError(409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP size mismatch")
            if (
                retained_content is None
                and not is_canonical
                and (
                    str(stored_metadata.get("id", "")) != str(descriptor.get("id", ""))
                    or str(stored_metadata.get("sensor_id", ""))
                    != str(descriptor.get("sensor_id", ""))
                    or stored_metadata.get("analysis_job_id") != source_job_id
                    or stored_size != declared_size
                    or str(stored_metadata.get("sha256", "")) != str(descriptor.get("sha256", ""))
                )
            ):
                raise ApiError(
                    409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP metadata mismatch"
                )
            with _measure_pcap_export_stage(stage_seconds, "hash"):
                digest = hashlib.sha256(capture_content).hexdigest()
            expected_digest = stored_metadata.get("sha256")
            if expected_digest and not hmac.compare_digest(str(expected_digest), digest):
                raise ApiError(409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP digest mismatch")
            if not expected_digest:
                raise ApiError(409, "PCAP_SOURCE_INTEGRITY_ERROR", "retained PCAP digest missing")
            source_manifest.append({"id": str(stored_metadata["id"]), "sha256": digest})
            try:
                with _measure_pcap_export_stage(stage_seconds, "frame"):
                    bounded_prefix = self.dependencies.legacy_prefix_builder(
                        capture_content,
                        remaining_source_bytes,
                        max_packets=remaining_packets,
                    )
                if bounded_prefix.packet_count == 0 and bounded_prefix.truncated:
                    scanned_source_bytes += bounded_prefix.scanned_bytes
                    if bounded_prefix.byte_limited:
                        source_truncation_reasons.append("SOURCE_BYTE_LIMIT")
                    if bounded_prefix.packet_limited:
                        source_truncation_reasons.append("SOURCE_PACKET_LIMIT")
                    break
                with _measure_pcap_export_stage(stage_seconds, "decode"):
                    parsed = self.dependencies.legacy_parser(
                        bounded_prefix.content,
                        sensor_id=str(stored_metadata["sensor_id"]),
                        internal_networks=list(job["internal_networks"]),
                        max_packets=remaining_packets,
                        retain_packet_bytes=True,
                        retain_packet_bytes_as_bytes=True,
                        allow_no_supported_packets=True,
                    )
            except PcapParseError as exc:
                raise ApiError(422, exc.code, str(exc)) from exc
            scanned_source_bytes += bounded_prefix.scanned_bytes
            scanned_source_capture_count += 1
            remaining_packets -= parsed.captured_packet_count
            source_records.extend(
                {**record, "raw_packet_source_order": source_order} for record in parsed.records
            )
            if bounded_prefix.byte_limited:
                source_truncation_reasons.append("SOURCE_BYTE_LIMIT")
            if bounded_prefix.packet_limited:
                source_truncation_reasons.append("SOURCE_PACKET_LIMIT")
            if bounded_prefix.truncated:
                break

        if not source_descriptors:
            hydrated_source_job = (
                source_snapshot.get("_legacy_source_job") if source_snapshot is not None else None
            ) or self.repository.get_job(source_job_id)
            fallback_records = [
                dict(record)
                for record in (hydrated_source_job or {}).get("flow_records", [])
                if record.get("raw_packet_hex")
            ]
            try:
                fallback_sizes = [
                    _raw_packet_hex_size(record["raw_packet_hex"]) for record in fallback_records
                ]
            except ValueError as exc:
                raise ApiError(409, "PCAP_SOURCE_INTEGRITY_ERROR", str(exc)) from exc
            source_total_bytes = sum(fallback_sizes)
            source_records = []
            predicate = self.dependencies.predicate_compiler(
                normalized, internal_networks=list(job["internal_networks"])
            )
            for fallback_packet_index, (record, packet_size) in enumerate(
                zip(fallback_records, fallback_sizes, strict=True)
            ):
                if fallback_packet_index % 256 == 0:
                    checkpoint(phase="SOURCE_SCAN", scanned_packet_count=fallback_packet_index)
                if scanned_source_bytes + packet_size > scan_max_bytes:
                    source_truncation_reasons.append("SOURCE_BYTE_LIMIT")
                    break
                if len(source_records) >= scan_max_packets:
                    source_truncation_reasons.append("SOURCE_PACKET_LIMIT")
                    break
                source_records.append(record)
                scanned_source_bytes += packet_size
                matched_record = MatchedPacketRecord.from_legacy_record(
                    record,
                    source_job_id=source_job_id,
                    fallback_packet_index=fallback_packet_index,
                    default_sensor_id=str(sensor_ids[0]),
                )
                with _measure_pcap_export_stage(stage_seconds, "filter"):
                    matched = predicate.matches(matched_record, sensor_id=matched_record.sensor_id)
                if matched:
                    matched_records.append(matched_record)
        scanned_packet_count = (
            scan_max_packets - remaining_packets if source_descriptors else len(source_records)
        )
        checkpoint(
            phase="FILTER",
            percent=70,
            scanned_source_bytes=scanned_source_bytes,
            scanned_packet_count=scanned_packet_count,
            matched_packet_count=len(matched_records),
        )
        artifact = None
        capture_result: Any
        try:
            checkpoint(phase="SERIALIZE", percent=80)
            max_output_bytes = cast(int, self.settings.pcap_export_max_bytes)
            with _measure_pcap_export_stage(stage_seconds, "write"):
                if use_streaming_pipeline and source_descriptors or not source_descriptors:
                    verified_matches = VerifiedMatchedPackets(tuple(matched_records))
                    export_records = (
                        ExportPacketRecord(
                            record.timestamp,
                            record.source_id,
                            record.source_order,
                            record.packet_index,
                            record.section_index,
                            record.interface_id,
                            record.interface_ordinal,
                            record.link_type,
                            record.raw_packet_bytes,
                            record.captured_length,
                            record.original_length,
                        )
                        for record in verified_matches
                    )
                    artifact = self.dependencies.capture_writer(
                        export_records,
                        max_output_bytes=max_output_bytes,
                        spool_max_memory_bytes=self.settings.pcap_export_spool_max_memory_bytes,
                        spool_directory=self.settings.pcap_export_spool_directory,
                    )
                    capture_result = artifact
                else:
                    with _measure_pcap_export_stage(stage_seconds, "filter"):
                        records = self.dependencies.legacy_filter(
                            source_records,
                            normalized,
                            internal_networks=list(job["internal_networks"]),
                        )
                    capture_result = self.dependencies.legacy_capture_builder(
                        records, max_output_bytes=max_output_bytes
                    )
        except CaptureStorageError as exc:
            raise ApiError(
                500,
                "PCAP_EXPORT_STORAGE_ERROR",
                "temporary PCAP export storage failed",
            ) from exc
        except CaptureRecordError as exc:
            raise ApiError(409, "PCAP_SOURCE_INTEGRITY_ERROR", str(exc)) from exc
        except CaptureLimitTooSmall as exc:
            raise ApiError(413, "PCAP_EXPORT_LIMIT_EXCEEDED", str(exc)) from exc
        except ValueError as exc:
            raise ApiError(413, "PCAP_EXPORT_LIMIT_EXCEEDED", str(exc)) from exc
        content_size = artifact.size_bytes if artifact is not None else len(capture_result.content)
        packet_count = capture_result.exported_packet_count
        capture_format = capture_result.capture_format
        truncation_reasons = list(
            dict.fromkeys([*source_truncation_reasons, *capture_result.truncation_reasons])
        )
        export_id = export_id or str(uuid.uuid4())
        status = "COMPLETED" if packet_count else "FAILED"
        source_available = bool(source_descriptors or source_records)
        if packet_count:
            error_code = None
            error_message = None
        elif capture_result.matched_packet_count:
            error_code = "PCAP_OUTPUT_LIMIT_TOO_SMALL"
            error_message = "output byte limit cannot fit a complete matched packet"
        elif source_truncation_reasons and not scanned_packet_count:
            error_code = "PCAP_SOURCE_SCAN_LIMIT_TOO_SMALL"
            error_message = "source scan byte limit cannot fit the first complete packet"
        elif source_truncation_reasons:
            error_code = "PCAP_SOURCE_SCAN_INCOMPLETE"
            error_message = "no packets matched in the incomplete source prefix"
        elif source_available:
            error_code = "PCAP_NO_MATCH"
            error_message = "no packets matched the applied filters"
        else:
            error_code = "PCAP_SOURCE_UNAVAILABLE"
            error_message = "retained source packet bytes are unavailable"
        safe_job_id = (
            "".join(
                character
                for character in payload.job_id
                if character.isalnum() or character in "-_"
            )[:64]
            or "analysis"
        )
        extension = "pcapng" if capture_format == "PCAPNG" else "pcap"
        completeness = "-partial" if truncation_reasons else ""
        metadata = {
            "id": export_id,
            "job_id": payload.job_id,
            "source_job_id": str(source_job["id"]),
            "candidate_id": payload.candidate_id,
            "status": status,
            "matched_packet_count": capture_result.matched_packet_count,
            "exported_packet_count": packet_count,
            "omitted_packet_count": capture_result.omitted_packet_count,
            "truncated": bool(truncation_reasons),
            "truncation_reasons": truncation_reasons,
            "size_bytes": content_size,
            "sha256": "",
            "capture_format": capture_format,
            "filename": (f"c2hunter-{safe_job_id}-filtered{completeness}-{export_id}.{extension}"),
            "filter": normalized,
            "source_capture_count": source_capture_count,
            "scanned_source_capture_count": scanned_source_capture_count,
            "omitted_source_capture_count": (source_capture_count - scanned_source_capture_count),
            "source_total_bytes": source_total_bytes,
            "scanned_source_bytes": scanned_source_bytes,
            "scanned_packet_count": scanned_packet_count,
            "output_byte_limit": max_output_bytes,
            "source_scan_byte_limit": scan_max_bytes,
            "source_scan_packet_limit": scan_max_packets,
            "source_manifest": source_manifest,
            "created_at": self.dependencies.clock().isoformat(),
            "error_code": error_code,
            "error": error_message,
            "principal_scope": (
                source_snapshot.get("_principal_scope", source_snapshot.get("principal_scope"))
                if source_snapshot is not None
                else None
            ),
        }
        if source_snapshot is not None and source_snapshot.get("lease_token"):
            metadata["attempt"] = int(source_snapshot["attempt"])
            metadata["lease_token"] = str(source_snapshot["lease_token"])
            metadata["published"] = False
        checkpoint(phase="PUBLISH", percent=95, exported_packet_count=packet_count)
        if artifact is not None:
            try:
                with artifact:
                    with _measure_pcap_export_stage(stage_seconds, "save"):
                        if self.settings.pcap_artifact_io == "streaming":
                            stored_export = self.repository.save_export_stream(
                                metadata,
                                artifact.iter_chunks(),
                                size_hint=artifact.size_bytes,
                            )
                        else:
                            metadata["sha256"] = artifact.sha256
                            stored_export = self.repository.save_export(
                                metadata, artifact.read_bytes()
                            )
            except CaptureStorageError as exc:
                raise ApiError(
                    500,
                    "PCAP_EXPORT_STORAGE_ERROR",
                    "temporary PCAP export storage failed",
                ) from exc
            except ArtifactStorageError as exc:
                raise ApiError(
                    503,
                    "PCAP_EXPORT_STORAGE_ERROR",
                    "PCAP export persistence is temporarily unavailable",
                ) from exc
            except (ArtifactProducerError, ArtifactAlreadyExistsError) as exc:
                raise ApiError(
                    500,
                    "PCAP_EXPORT_STORAGE_ERROR",
                    "PCAP export artifact production failed",
                ) from exc
        else:
            content = capture_result.content
            if self.settings.pcap_artifact_io == "streaming":
                try:
                    with _measure_pcap_export_stage(stage_seconds, "save"):
                        stored_export = self.repository.save_export_stream(
                            metadata, iter((content,)), size_hint=len(content)
                        )
                except ArtifactStorageError as exc:
                    raise ApiError(
                        503,
                        "PCAP_EXPORT_STORAGE_ERROR",
                        "PCAP export persistence is temporarily unavailable",
                    ) from exc
                except (ArtifactProducerError, ArtifactAlreadyExistsError) as exc:
                    raise ApiError(
                        500,
                        "PCAP_EXPORT_STORAGE_ERROR",
                        "PCAP export artifact production failed",
                    ) from exc
            else:
                with _measure_pcap_export_stage(stage_seconds, "hash"):
                    metadata["sha256"] = hashlib.sha256(content).hexdigest()
                with _measure_pcap_export_stage(stage_seconds, "save"):
                    stored_export = self.repository.save_export(metadata, content)
        if stored_export is None:
            raise ApiError(
                409,
                "PCAP_SOURCE_UNAVAILABLE",
                "analysis job was deleted before the PCAP export could be saved",
            )
        return stored_export


POLICY_VERSION = "pcap-export-v8"


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def request_fingerprint(
    *,
    principal_scope: str,
    requested_job_id: str,
    candidate_id: str | None,
    canonical_request: dict[str, Any],
    effective_limits: dict[str, int],
) -> str:
    """Cheap idempotency fingerprint independent of source discovery."""
    return fingerprint(
        {
            "principal_scope": principal_scope,
            "requested_job_id": requested_job_id,
            "candidate_id": candidate_id,
            "request": canonical_request,
            "effective_limits": effective_limits,
            "policy_version": "pcap-export-v8",
        }
    )


def choose_execution_mode(
    settings: Settings, *, source_bytes: int | None, packet_count: int | None
) -> Literal["SYNC", "ASYNC"]:
    if settings.pcap_export_execution_mode == "sync_only":
        return "SYNC"
    if source_bytes is None or packet_count is None:
        return "ASYNC"
    planned_bytes = min(source_bytes, int(settings.pcap_export_scan_max_bytes or source_bytes))
    planned_packets = min(packet_count, int(settings.pcap_export_scan_max_packets or packet_count))
    if (
        planned_bytes <= settings.pcap_export_sync_max_source_bytes
        and planned_packets <= settings.pcap_export_sync_max_packets
    ):
        return "SYNC"
    return "ASYNC"


def source_generation(manifest: list[dict[str, Any]]) -> str:
    normalized = [
        {
            "order": int(item["order"]),
            "id": str(item["id"]),
            "sensor_id": str(item["sensor_id"]),
            "version_id": str(item["version_id"]),
            "size_bytes": int(item["size_bytes"]),
            "sha256": str(item["sha256"]),
        }
        for item in manifest
    ]
    return fingerprint(normalized)


def build_async_job(
    *,
    settings: Settings,
    principal_scope: str,
    requested_job_id: str,
    snapshot: dict[str, Any],
    candidate_id: str | None,
    idempotency_key: str | None,
) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    export_id = str(uuid.uuid4())
    request_document = {
        "principal_scope": principal_scope,
        "requested_job_id": requested_job_id,
        "source_job_id": snapshot["source_job_id"],
        "source_generation": snapshot["source_generation"],
        "candidate_id": candidate_id,
        "request": snapshot["canonical_request"],
        "effective_limits": snapshot["effective_limits"],
        "policy_version": snapshot["policy_version"],
    }
    request_fingerprint_value = request_fingerprint(
        principal_scope=principal_scope,
        requested_job_id=requested_job_id,
        candidate_id=candidate_id,
        canonical_request=dict(snapshot["canonical_request"]),
        effective_limits=dict(snapshot["effective_limits"]),
    )
    coalesce = fingerprint(
        {key: value for key, value in request_document.items() if key != "principal_scope"}
    )
    return {
        "id": export_id,
        "principal_scope": principal_scope,
        "idempotency_key": idempotency_key,
        "request_fingerprint": request_fingerprint_value,
        "coalesce_fingerprint": coalesce,
        "job_id": requested_job_id,
        "source_job_id": snapshot["source_job_id"],
        "provenance_job_ids": snapshot["provenance_job_ids"],
        "candidate_id": candidate_id,
        "status": "QUEUED",
        "execution_mode": "ASYNC",
        "progress": {
            "phase": "QUEUED",
            "percent": 0,
            "scanned_source_bytes": 0,
            "scanned_packet_count": 0,
            "matched_packet_count": 0,
            "exported_packet_count": 0,
        },
        "cancellation_requested": False,
        "attempt": 0,
        "max_attempts": settings.pcap_export_max_attempts,
        "source_generation": snapshot["source_generation"],
        "source_manifest": snapshot["source_manifest"],
        "source_kind": snapshot["source_kind"],
        "source_total_bytes": snapshot.get("source_total_bytes"),
        "source_packet_count": snapshot.get("source_packet_count"),
        "canonical_request": snapshot["canonical_request"],
        "effective_limits": snapshot["effective_limits"],
        "policy_version": snapshot["policy_version"],
        "queued_at": now,
        "created_at": now,
        "updated_at": now,
        "started_at": None,
        "completed_at": None,
        "next_attempt_at": now,
        "status_url": f"/api/v1/pcap-exports/{export_id}",
        "download_url": None,
        "error_code": None,
        "error": None,
    }


def public_job(job: dict[str, Any]) -> dict[str, Any]:
    hidden = {
        "principal_scope",
        "idempotency_key",
        "request_fingerprint",
        "coalesce_fingerprint",
        "canonical_request",
        "effective_limits",
        "policy_version",
        "lease_token",
        "lease_expires_at",
        "source_packet_count",
        "source_job_id",
        "provenance_job_ids",
        "source_generation",
        "source_kind",
        "published",
    }
    result = {key: value for key, value in job.items() if key not in hidden}
    if result.get("status") == "COMPLETED":
        result["download_url"] = f"/api/v1/pcap-exports/{result['id']}/download"
    else:
        for key in (
            "sha256",
            "size_bytes",
            "capture_format",
            "filename",
            "filter",
            "source_capture_count",
            "scanned_source_capture_count",
            "omitted_source_capture_count",
            "source_total_bytes",
            "scanned_source_bytes",
            "scanned_packet_count",
            "output_byte_limit",
            "source_scan_byte_limit",
            "source_scan_packet_limit",
            "source_manifest",
        ):
            result.pop(key, None)
        result["download_url"] = None
    return result


def adapt_sync_export(metadata: dict[str, Any]) -> dict[str, Any]:
    created = metadata["created_at"]
    completed = metadata.get("completed_at") or created
    status = metadata["status"]
    progress = {
        "phase": "TERMINAL",
        "percent": 100 if status == "COMPLETED" else 0,
        "scanned_source_bytes": int(metadata.get("scanned_source_bytes", 0)),
        "scanned_packet_count": int(metadata.get("scanned_packet_count", 0)),
        "matched_packet_count": int(metadata.get("matched_packet_count", 0)),
        "exported_packet_count": int(metadata.get("exported_packet_count", 0)),
    }
    generation = fingerprint(metadata.get("source_manifest", []))
    return {
        **metadata,
        "execution_mode": "SYNC",
        "progress": progress,
        "cancellation_requested": False,
        "attempt": 1,
        "max_attempts": 1,
        "source_generation": generation,
        "queued_at": created,
        "updated_at": completed,
        "started_at": created,
        "completed_at": completed,
        "next_attempt_at": None,
        "status_url": f"/api/v1/pcap-exports/{metadata['id']}",
        "download_url": (
            f"/api/v1/pcap-exports/{metadata['id']}/download" if status == "COMPLETED" else None
        ),
    }
