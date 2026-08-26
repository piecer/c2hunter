from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import threading
from _thread import RLock
from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, Self, TypeGuard, TypeVar, cast

from c2hunter_analysis.pcap_index import (
    PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_OFFSET_INDEX_SCHEMA_VERSION,
    StructuralInterfaceEntry,
    StructuralPacketEntry,
)
from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
    PostingChunk,
    PostingDimension,
    PostingGeneration,
    PostingQueryLimits,
)

from .pcap_export_store import ExportQueueStorageError, RepositoryQueueStore
from .pcap_indexed_export import (
    CaptureByteRange,
    CaptureRangeMissing,
    CaptureRangeShortRead,
    CaptureRangeUnavailable,
    CaptureRangeVersionDrift,
)
from .pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexIdentityLookup,
    StructuralIndexLookup,
    StructuralIndexParentIdentity,
    StructuralIndexSnapshot,
    structural_index_digest,
    structural_index_identity,
    structural_index_identity_availability,
    validate_structural_index,
)
from .pcap_offset_index_queue import (
    IndexAdmission,
    LiveIndexTask,
    _mark_intent,
    eligible_live_segment,
    encode_task,
)
from .pcap_offset_index_queue import (
    admit as admit_live_index,
)
from .pcap_offset_index_queue import (
    claim as claim_live_index,
)
from .pcap_offset_index_queue import (
    cleanup_terminal as cleanup_terminal_live_indexes,
)
from .pcap_offset_index_queue import (
    complete as complete_live_index,
)
from .pcap_offset_index_queue import (
    fail as fail_live_index,
)
from .pcap_offset_index_queue import (
    get_task as get_live_index_task,
)
from .pcap_offset_index_queue import (
    heartbeat as heartbeat_live_index,
)
from .pcap_offset_index_queue import (
    queue_depth as live_index_queue_depth,
)
from .pcap_offset_index_queue import (
    reconcile as reconcile_live_indexes,
)
from .pcap_offset_index_queue import (
    recover as recover_live_indexes,
)
from .pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexBinding,
    PostingIndexIdentity,
    PostingIndexIdentityLookup,
    PostingIndexLookup,
    PostingIndexSnapshot,
    posting_index_identity,
    posting_index_identity_availability,
    validate_posting_index,
)
from .pcap_posting_index_queue import (
    PostingIndexAdmission,
    PostingIndexIntent,
    PostingIndexIntentStatus,
    PostingIndexTask,
    PostingIndexTaskSpec,
    PostingIndexTaskStatus,
    PostingSourceKind,
    is_posting_source_kind,
)
from .pcap_posting_index_queue import (
    _encode as encode_posting_lifecycle,
)
from .pcap_posting_index_queue import _put_intent as put_posting_intent
from .pcap_posting_index_queue import (
    admit as admit_posting_task,
)
from .pcap_posting_index_queue import (
    claim as claim_posting_task,
)
from .pcap_posting_index_queue import (
    cleanup_terminal as cleanup_terminal_posting_tasks,
)
from .pcap_posting_index_queue import (
    fail as fail_posting_task,
)
from .pcap_posting_index_queue import (
    heartbeat as heartbeat_posting_task,
)
from .pcap_posting_index_queue import (
    owns_unexpired as owns_unexpired_posting_task,
)
from .pcap_posting_index_queue import (
    queue_depth as posting_queue_depth,
)
from .pcap_posting_index_queue import (
    reconcile as reconcile_posting_tasks,
)
from .pcap_posting_index_queue import (
    recover as recover_posting_tasks,
)
from .pcap_posting_index_queue import (
    request as request_posting_task,
)
from .pcap_posting_index_queue import request_backfill as request_posting_backfill

_AI_TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED"}
_JOB_TERMINAL_STATUSES = {"COMPLETED", "PARTIALLY_COMPLETED", "FAILED", "CANCELLED"}
_DEFAULT_CAPTURE_CHUNK_SIZE = 64 * 1024
_DEFAULT_ARTIFACT_CHUNK_SIZE = 1024 * 1024
_PCAP_EXPORT_POLICY_VERSION = "pcap-export-v8"
_T = TypeVar("_T")


def _pcap_export_snapshot(
    repository: Any,
    job_id: str,
    canonical_request: dict[str, Any],
    effective_limits: dict[str, int],
) -> dict[str, Any] | None:
    """Build an immutable metadata-only source snapshot while the adapter lock is held."""
    memory_jobs = getattr(repository, "jobs", None)

    def job_summary(value: str) -> dict[str, Any] | None:
        if memory_jobs is not None:
            found = memory_jobs.get(value)
            return deepcopy(found) if found is not None else None
        return cast(dict[str, Any] | None, repository.get_job_summary(value))

    def source_segments(value: str) -> list[dict[str, Any]]:
        memory_segments = getattr(repository, "sensor_pcaps", None)
        if memory_segments is not None:
            return deepcopy(
                sorted(
                    (
                        item
                        for item in memory_segments.values()
                        if item.get("analysis_job_id") == value
                    ),
                    key=lambda item: (str(item.get("uploaded_at", "")), str(item.get("id", ""))),
                )
            )
        return cast(list[dict[str, Any]], repository.list_sensor_pcaps_for_job(value))

    job = job_summary(job_id)
    if job is None:
        return None
    source_job = job
    visited: set[str] = set()
    provenance_job_ids: list[str] = []
    segments: list[dict[str, Any]] = []
    canonical: dict[str, Any] | None = None
    while True:
        source_id = str(source_job["id"])
        if source_id in visited:
            raise ValueError("source_provenance_cycle")
        visited.add(source_id)
        provenance_job_ids.append(source_id)
        source = source_job.get("source")
        if isinstance(source, dict) and source.get("packet_bytes_retained"):
            canonical = source
            break
        segments = source_segments(source_id)
        if segments:
            break
        parent_id = source_job.get("parent_job_id")
        if not parent_id:
            break
        parent = repository.get_job_summary(str(parent_id))
        if parent is None:
            raise ValueError("source_provenance_missing")
        source_job = parent
    source_id = str(source_job["id"])
    sensor_ids = source_job.get("sensor_ids") or ["uploaded"]
    descriptors = (
        [{"id": source_id, "sensor_id": str(sensor_ids[0]), **canonical}]
        if canonical is not None
        else segments
    )
    manifest: list[dict[str, Any]] = []
    for order, descriptor in enumerate(descriptors):
        size = descriptor.get("size_bytes")
        digest = descriptor.get("sha256")
        if isinstance(size, bool) or not isinstance(size, int | str):
            raise ValueError("source_size_invalid")
        parsed_size = int(size)
        if parsed_size < 0 or not isinstance(digest, str) or len(digest) != 64:
            raise ValueError("source_integrity_invalid")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise ValueError("source_integrity_invalid") from exc
        manifest.append(
            {
                "order": order,
                "id": str(descriptor["id"]),
                "sensor_id": str(descriptor.get("sensor_id", sensor_ids[0])),
                "version_id": str(
                    descriptor.get("version_id")
                    or descriptor.get("object_version_id")
                    or f"sha256:{digest}"
                ),
                "size_bytes": parsed_size,
                "sha256": digest,
            }
        )
    packet_count: int | None = None
    source_total: int | None = sum(item["size_bytes"] for item in manifest) if manifest else None
    trusted_packets = (source_job.get("source") or {}).get("packet_count")
    if (
        isinstance(trusted_packets, int)
        and not isinstance(trusted_packets, bool)
        and trusted_packets >= 0
    ):
        packet_count = trusted_packets
    if manifest and packet_count is None and source_total is not None:
        # Conservative repository estimate: no physical packet can occupy fewer than one byte.
        packet_count = source_total
    generation_document = {
        "source_job_id": source_id,
        "provenance_job_ids": provenance_job_ids,
        "source_manifest": manifest,
        "source_total_bytes": source_total,
        "source_packet_count": packet_count,
    }
    generation = hashlib.sha256(
        json.dumps(generation_document, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    result = {
        **generation_document,
        "source_generation": generation,
        "source_kind": (
            "canonical_capture"
            if canonical is not None
            else "segment_manifest"
            if manifest
            else "legacy_inline"
        ),
        "canonical_request": deepcopy(canonical_request),
        "effective_limits": deepcopy(effective_limits),
        "policy_version": _PCAP_EXPORT_POLICY_VERSION,
    }
    return result


def _pcap_export_admission_matches(repository: Any, job: dict[str, Any]) -> bool:
    if "canonical_request" not in job:
        return True
    snapshot = _pcap_export_snapshot(
        repository,
        str(job["job_id"]),
        dict(job.get("canonical_request", {})),
        dict(job.get("effective_limits", {})),
    )
    return bool(
        snapshot is not None
        and snapshot["source_generation"] == job.get("source_generation")
        and snapshot["source_manifest"] == job.get("source_manifest", [])
    )


class ArtifactError(Exception):
    """Base class for typed export-artifact failures."""


class ArtifactProducerError(ArtifactError):
    """The artifact producer violated its one-pass byte stream contract."""


class ArtifactStorageError(ArtifactError):
    """Artifact persistence or retrieval failed."""


class ArtifactMissingError(ArtifactError):
    """Published artifact metadata references absent content."""


class ArtifactAlreadyExistsError(ArtifactError):
    """An immutable export identifier is already published."""


@dataclass(frozen=True)
class ArtifactWriteResult:
    size_bytes: int
    sha256: str


def _consume_artifact_chunks(
    chunks: Iterable[bytes], *, size_hint: int
) -> tuple[tuple[bytes, ...], ArtifactWriteResult]:
    if size_hint < 0:
        raise ArtifactProducerError("artifact size hint must be non-negative")
    collected: list[bytes] = []
    digest = hashlib.sha256()
    size = 0
    try:
        for chunk in chunks:
            if type(chunk) is not bytes:
                raise ArtifactProducerError("artifact chunks must be exact bytes values")
            if not chunk:
                continue
            size += len(chunk)
            if size > size_hint:
                raise ArtifactProducerError("artifact producer yielded more than size hint")
            digest.update(chunk)
            collected.append(chunk)
    except ArtifactProducerError:
        raise
    except Exception as exc:
        raise ArtifactProducerError("artifact producer failed") from exc
    if size != size_hint:
        raise ArtifactProducerError("artifact producer ended before size hint")
    return tuple(collected), ArtifactWriteResult(size, digest.hexdigest())


class _CaptureStream(Protocol):
    def read(self, size: int | None = -1, /) -> bytes: ...
    def close(self) -> None: ...


class CaptureSource:
    """An owned stream for one immutable capture version.

    ``read()`` is always bounded: omitted, ``None``, and non-positive sizes read at
    most one 64 KiB chunk. Positive sizes are forwarded exactly, and EOF is
    reported as ``b""``. Use :meth:`iter_chunks` or a compatibility adapter to
    drain the stream.
    """

    def __init__(
        self, stream: _CaptureStream, version_id: str, *, release_conn: Any = None
    ) -> None:
        if not version_id:
            raise ValueError("capture source requires an immutable version identity")
        self._stream = stream
        self._version_id = version_id
        self._release_conn = release_conn
        self._closed = False

    @property
    def version_id(self) -> str:
        return self._version_id

    @property
    def closed(self) -> bool:
        return self._closed

    def read(self, size: int | None = -1) -> bytes:
        """Read one bounded chunk without requesting an unbounded backend read."""
        if self._closed:
            raise ValueError("I/O operation on closed capture source")
        bounded_size = size if size is not None and size > 0 else _DEFAULT_CAPTURE_CHUNK_SIZE
        chunk = self._stream.read(bounded_size)
        if not isinstance(chunk, bytes):
            raise TypeError("capture stream read must return bytes")
        return chunk

    def iter_chunks(self, chunk_size: int = _DEFAULT_CAPTURE_CHUNK_SIZE) -> Iterator[bytes]:
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        while (chunk := self.read(chunk_size)) != b"":
            yield chunk

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close_error: BaseException | None = None
        try:
            self._stream.close()
        except BaseException as exc:
            close_error = exc
        try:
            if self._release_conn is not None:
                self._release_conn()
        except BaseException:
            if close_error is None:
                raise
        if close_error is not None:
            raise close_error

    def __enter__(self) -> CaptureSource:
        if self._closed:
            raise ValueError("I/O operation on closed capture source")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


def _bytes_source(content: bytes) -> CaptureSource:
    snapshot = bytes(content)
    digest = hashlib.sha256(snapshot).hexdigest()
    return CaptureSource(io.BytesIO(snapshot), f"sha256:{digest}")


def _job_matches_structural_binding(
    job: dict[str, Any] | None, binding: SourceIndexBinding
) -> bool:
    if job is None or job.get("id") != binding.source_id or job.get("mode") != "PCAP_UPLOAD":
        return False
    source = job.get("source")
    return bool(
        isinstance(source, dict)
        and source.get("packet_bytes_retained") is True
        and source.get("size_bytes") == binding.source_size_bytes
        and source.get("sha256") == binding.source_sha256
        and source.get("capture_format") == binding.capture_format
    )


def _live_segment_matches_structural_binding(repository: Any, binding: SourceIndexBinding) -> bool:
    segment = repository.sensor_pcaps.get(binding.source_id)
    if segment is None:
        return False
    job = repository.jobs.get(str(segment.get("analysis_job_id")))
    return bool(
        eligible_live_segment(job, segment)
        and segment.get("index_requested_at")
        and segment.get("size_bytes") == binding.source_size_bytes
        and segment.get("sha256") == binding.source_sha256
    )


def _valid_candidate_decision_record(decision: dict[str, Any]) -> bool:
    if not all(
        isinstance(decision.get(field), str) and bool(decision.get(field))
        for field in (
            "id",
            "candidate_id",
            "verdict",
            "confidence",
            "note",
            "created_by",
            "created_at",
        )
    ):
        return False
    try:
        created_at = datetime.fromisoformat(str(decision["created_at"]).replace("Z", "+00:00"))
    except ValueError:
        return False
    if created_at.utcoffset() is None:
        return False
    return decision.get("verdict") in {
        "CONFIRMED_C2",
        "FALSE_POSITIVE",
        "UNDER_REVIEW",
    } and decision.get("confidence") in {"CONFIRMED", "HIGH", "MEDIUM", "LOW"}


def _candidate_workflow_counts_from_records(
    candidate_ids: list[str],
    decisions: list[dict[str, Any]],
    actions: list[dict[str, Any]],
) -> dict[str, int]:
    latest_decisions: dict[str, dict[str, Any]] = {}
    valid_decisions = [
        decision for decision in decisions if _valid_candidate_decision_record(decision)
    ]
    for decision in sorted(valid_decisions, key=lambda item: str(item["created_at"])):
        latest_decisions[str(decision.get("candidate_id", ""))] = decision
    latest_actions: dict[str, dict[str, Any]] = {}
    for action in sorted(actions, key=lambda item: str(item.get("created_at", ""))):
        candidate_id = str(action.get("candidate_id", ""))
        current_decision = latest_decisions.get(candidate_id)
        if current_decision is not None and action.get("verdict_id") == current_decision.get("id"):
            latest_actions[candidate_id] = action
    counts = {
        "needs_review": 0,
        "in_review": 0,
        "action_required": 0,
        "action_in_progress": 0,
        "action_completed": 0,
        "false_positive": 0,
        "done": 0,
    }
    for candidate_id in candidate_ids:
        current_decision = latest_decisions.get(candidate_id)
        verdict = (
            str(current_decision.get("verdict")) if current_decision is not None else "UNREVIEWED"
        )
        if verdict == "UNDER_REVIEW":
            counts["in_review"] += 1
        elif verdict == "FALSE_POSITIVE":
            counts["false_positive"] += 1
            counts["done"] += 1
        elif verdict == "CONFIRMED_C2":
            status = str(latest_actions.get(candidate_id, {}).get("status", "PENDING"))
            if status == "IN_PROGRESS":
                counts["action_in_progress"] += 1
            elif status == "COMPLETED":
                counts["action_completed"] += 1
                counts["done"] += 1
            else:
                counts["action_required"] += 1
        else:
            counts["needs_review"] += 1
    return counts


class Repository(Protocol):
    def for_background_worker(self) -> Self: ...
    def close(self) -> None: ...

    """PostgreSQL adapter가 구현해야 하는 제어 영역 경계."""

    def ready(self) -> bool: ...
    def snapshot_pcap_export_source(
        self,
        job_id: str,
        canonical_request: dict[str, Any],
        effective_limits: dict[str, int],
    ) -> dict[str, Any] | None: ...
    def validate_pcap_export_admission(self, job: dict[str, Any]) -> bool: ...
    def enqueue_pcap_export_job(
        self, job: dict[str, Any], *, capacity: int, per_principal_limit: int
    ) -> tuple[dict[str, Any], bool]: ...
    def get_pcap_export_job(self, export_id: str) -> dict[str, Any] | None: ...
    def find_pcap_export_job(
        self, principal_scope: str, idempotency_key: str, request_fingerprint: str
    ) -> dict[str, Any] | None: ...
    def count_pcap_export_jobs_by_status(self) -> dict[str, int]: ...
    def claim_pcap_export_job(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> dict[str, Any] | None: ...
    def heartbeat_pcap_export_job(
        self, export_id: str, *, attempt: int, lease_token: str, lease_seconds: int
    ) -> bool: ...
    def progress_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        progress: dict[str, Any],
    ) -> bool: ...
    def complete_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> bool: ...
    def retry_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        error: str,
        retry_base_seconds: int = 5,
    ) -> bool: ...
    def cancel_pcap_export_job(
        self, export_id: str, *, reason: str | None = None
    ) -> dict[str, Any]: ...
    def recover_pcap_export_jobs(self, *, now: datetime | None = None) -> int: ...
    def has_active_pcap_exports(self, job_id: str) -> bool: ...
    def validate_pcap_export_source(self, job: dict[str, Any]) -> bool: ...
    def compensate_pcap_export_artifact(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> None: ...
    def cleanup_pcap_export_orphans(
        self, *, now: datetime, max_age_seconds: int, limit: int
    ) -> list[str]: ...
    def retain_pcap_export_jobs(
        self,
        *,
        now: datetime,
        max_age_seconds: int,
        max_count: int,
        max_artifact_bytes: int,
    ) -> list[str]: ...
    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]: ...
    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None: ...
    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None: ...
    def list_sensors(self) -> list[dict[str, Any]]: ...
    def create_group(self, group: dict[str, Any]) -> dict[str, Any]: ...
    def list_groups(self) -> list[dict[str, Any]]: ...
    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...
    def save_job(self, job: dict[str, Any]) -> dict[str, Any]: ...
    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]: ...
    def get_job(self, job_id: str) -> dict[str, Any] | None: ...
    def get_job_summary(self, job_id: str) -> dict[str, Any] | None: ...
    def get_job_summaries(self, job_ids: list[str]) -> dict[str, dict[str, Any]]: ...
    def list_jobs(self) -> list[dict[str, Any]]: ...
    def list_active_live_jobs(self) -> list[dict[str, Any]]: ...
    def delete_job(self, job_id: str) -> bool: ...
    def delete_retained_source(self, job_id: str) -> bool: ...
    def save_job_capture(self, job_id: str, content: bytes) -> None: ...
    def open_job_capture(self, job_id: str) -> CaptureSource | None: ...
    def get_capture_source_version(self, source_id: str, /) -> CaptureSourceVersion | None: ...
    def get_live_capture_source_version(self, source_id: str, /) -> CaptureSourceVersion | None: ...
    def read_capture_range(
        self, source: CaptureSourceVersion, byte_range: CaptureByteRange
    ) -> bytes: ...
    def get_job_capture(self, job_id: str) -> bytes | None: ...
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
    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup: ...
    def get_structural_index_identity(
        self, source: CaptureSourceVersion
    ) -> StructuralIndexIdentityLookup: ...
    def delete_structural_indexes_for_source(
        self, source_id: str, *, source_kind: str = "PCAP_UPLOAD"
    ) -> None: ...
    def cleanup_stale_structural_indexes(self, *, before: datetime, limit: int) -> int: ...
    def request_posting_index(
        self, source_version: CaptureSourceVersion, parent: StructuralIndexSnapshot
    ) -> PostingIndexIntent | None: ...

    def request_posting_index_backfill(self, *, limit: int) -> int: ...

    def admit_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        capacity: int,
        max_attempts: int,
    ) -> PostingIndexAdmission: ...

    def claim_posting_index(self, *, lease_seconds: int) -> PostingIndexTask | None: ...

    def heartbeat_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> bool: ...

    def fail_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        retry_base_seconds: int,
    ) -> bool: ...

    def recover_posting_indexes(self) -> int: ...

    def reconcile_posting_indexes(
        self,
        *,
        capacity: int,
        max_attempts: int,
        limit: int,
    ) -> int: ...

    def get_posting_index_queue_depth(self) -> dict[str, int]: ...

    def cleanup_terminal_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int: ...

    def cleanup_stale_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int: ...

    def begin_posting_index(
        self,
        snapshot: PostingIndexSnapshot,
        *,
        attempt: int,
        lease_token: str,
    ) -> None:
        raise NotImplementedError("posting indexes are unavailable")

    def stage_posting_index_chunks(
        self,
        build_id: str,
        chunks: tuple[PostingChunk, ...],
        *,
        source_kind: PostingSourceKind,
        source_id: str,
        attempt: int,
        lease_token: str,
    ) -> None:
        raise NotImplementedError("posting indexes are unavailable")

    def publish_posting_index(
        self,
        build_id: str,
        *,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        attempt: int,
        lease_token: str,
    ) -> bool:
        raise NotImplementedError("posting indexes are unavailable")

    def get_posting_index(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        limits: PostingQueryLimits | None = None,
    ) -> PostingIndexLookup:
        raise NotImplementedError("posting indexes are unavailable")

    def get_posting_index_identity(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexParentIdentity,
    ) -> PostingIndexIdentityLookup:
        raise NotImplementedError("posting indexes are unavailable")

    def abort_posting_index(
        self,
        build_id: str,
        *,
        source_kind: PostingSourceKind,
        source_id: str,
        parent_structural_build_id: str,
        attempt: int,
        lease_token: str,
    ) -> bool:
        raise NotImplementedError("posting indexes are unavailable")

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None: ...
    def get_candidates(self, job_id: str) -> list[dict[str, Any]]: ...
    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None: ...
    def query_candidates(
        self,
        *,
        minimum_score: int = 0,
        severity: str | None = None,
        include_suppressed: bool = False,
    ) -> list[tuple[str, dict[str, Any]]]: ...
    def query_candidate_page(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
        sort: str,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[str, dict[str, Any]]], int]: ...
    def query_candidate_refs(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> list[tuple[str, bool]]: ...
    def candidate_workflow_counts(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> dict[str, int]: ...
    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]: ...
    def get_integration_settings(self) -> dict[str, Any] | None: ...
    def save_integration_settings(
        self, settings: dict[str, Any], expected_version: int
    ) -> tuple[dict[str, Any] | None, str]: ...
    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]: ...
    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_run(self, run_id: str) -> dict[str, Any] | None: ...
    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]: ...
    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None: ...
    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]: ...
    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]: ...
    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None: ...
    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]: ...
    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]: ...
    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]: ...
    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None: ...
    def update_candidate(
        self, candidate_id: str, updates: dict[str, Any]
    ) -> dict[str, Any] | None: ...
    def delete_candidate(self, candidate_id: str) -> bool: ...
    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]: ...
    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]: ...
    def save_candidate_action(self, action: dict[str, Any]) -> dict[str, Any]: ...
    def list_candidate_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]: ...
    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]: ...
    def list_candidate_ti_lookups(
        self, candidate_id: str | None = None
    ) -> list[dict[str, Any]]: ...
    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]: ...
    def claim_candidate_misp_action(self, action: dict[str, Any]) -> bool: ...
    def list_candidate_misp_actions(
        self, candidate_id: str | None = None
    ) -> list[dict[str, Any]]: ...
    def list_candidate_workflow_records(
        self, candidate_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]: ...
    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]: ...
    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]: ...
    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]: ...
    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None: ...
    def list_payload_signatures(self) -> list[dict[str, Any]]: ...
    def delete_payload_signature(self, signature_id: str) -> bool: ...
    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]: ...
    def list_allowlist(self) -> list[dict[str, Any]]: ...
    def delete_allowlist(self, entry_id: str) -> bool: ...
    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]: ...
    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None: ...
    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None: ...
    def list_detector_weight_presets(self) -> list[dict[str, Any]]: ...
    def delete_detector_weight_preset(self, preset_id: str) -> bool: ...
    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None: ...
    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any] | None: ...
    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None: ...
    def save_export_stream(
        self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
    ) -> dict[str, Any] | None: ...
    def get_export_metadata(self, export_id: str) -> dict[str, Any] | None: ...
    def open_export_stream(
        self, export_id: str
    ) -> tuple[dict[str, Any], AbstractContextManager[Iterator[bytes]]] | None: ...
    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]: ...
    def admit_live_segment_index(
        self, source_id: str, *, capacity: int, max_attempts: int
    ) -> IndexAdmission: ...
    def save_sensor_pcap_limited(
        self,
        segment: dict[str, Any],
        content: bytes,
        max_total_bytes: int | None,
        *,
        require_open_job: bool = False,
    ) -> tuple[dict[str, Any] | None, str]: ...
    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None: ...
    def open_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], CaptureSource] | None: ...
    def list_sensor_pcaps(self) -> list[dict[str, Any]]: ...
    def list_sensor_pcaps_for_job(self, job_id: str) -> list[dict[str, Any]]: ...
    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]: ...
    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None: ...
    def list_enrollments(self) -> list[dict[str, Any]]: ...
    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]: ...
    def claim_enrollment(
        self, token_hash: str, now: datetime
    ) -> tuple[dict[str, Any] | None, str]: ...
    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]: ...
    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None: ...
    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]: ...


class _LiveIndexRepositoryBackend(Protocol):
    _lock: RLock

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None: ...

    def _posting_now(self) -> datetime: ...

    def get_posting_index_intent(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexIntent | None: ...


class _SQLiteLiveIndexRepositoryBackend(_LiveIndexRepositoryBackend, Protocol):
    connection: sqlite3.Connection

    def _get(self, kind: str, object_id: str) -> dict[str, Any] | None: ...

    @staticmethod
    def _serialize(value: Any) -> str: ...


class _MemoryLiveIndexRepositoryBackend(_LiveIndexRepositoryBackend, Protocol):
    jobs: dict[str, dict[str, Any]]
    sensor_pcaps: dict[str, dict[str, Any]]
    capture_source_versions: dict[str, CaptureSourceVersion]
    structural_index_staging: dict[
        str, tuple[SourceIndexBinding, datetime, list[StructuralPacketEntry]]
    ]
    structural_index_generations: dict[str, StructuralIndexSnapshot]
    structural_index_owners: dict[tuple[str, str], str]
    live_segment_index_tasks: dict[str, LiveIndexTask]
    posting_index_intents: dict[tuple[str, str], PostingIndexIntent]


def _is_sqlite_live_index_backend(
    repository: _LiveIndexRepositoryBackend,
) -> TypeGuard[_SQLiteLiveIndexRepositoryBackend]:
    return isinstance(getattr(repository, "connection", None), sqlite3.Connection)


def _is_memory_live_index_backend(
    repository: _LiveIndexRepositoryBackend,
) -> TypeGuard[_MemoryLiveIndexRepositoryBackend]:
    return not hasattr(repository, "connection")


class LiveIndexQueueRepositoryMixin:
    def get_live_segment_index_metadata(
        self: _LiveIndexRepositoryBackend, source_id: str
    ) -> dict[str, Any] | None:
        """Return marked canonical metadata without retaining a repository lock."""
        with self._lock:
            if _is_sqlite_live_index_backend(self):
                segment = self._get("sensor_pcap", source_id)
                job = (
                    self._get("job", str(segment.get("analysis_job_id")))
                    if segment is not None
                    else None
                )
            else:
                if not _is_memory_live_index_backend(self):
                    raise TypeError("unsupported LIVE index repository backend")
                segment = deepcopy(self.sensor_pcaps.get(source_id))
                job = (
                    self.jobs.get(str(segment.get("analysis_job_id")))
                    if segment is not None
                    else None
                )
            if (
                segment is None
                or not segment.get("index_requested_at")
                or not eligible_live_segment(job, segment)
            ):
                return None
            return deepcopy(segment)

    def admit_live_segment_index(
        self, source_id: str, *, capacity: int, max_attempts: int
    ) -> IndexAdmission:
        return admit_live_index(self, source_id, capacity=capacity, max_attempts=max_attempts)

    def get_live_segment_index_task(self, source_id: str) -> LiveIndexTask | None:
        return get_live_index_task(self, source_id)

    def claim_live_segment_index(
        self, *, now: datetime, lease_seconds: int
    ) -> LiveIndexTask | None:
        return claim_live_index(self, now=now, lease_seconds=lease_seconds)

    def heartbeat_live_segment_index(
        self,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        now: datetime,
        lease_seconds: int,
    ) -> bool:
        return heartbeat_live_index(
            self,
            source_id,
            attempt=attempt,
            lease_token=lease_token,
            now=now,
            lease_seconds=lease_seconds,
        )

    def complete_live_segment_index(
        self,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        now: datetime | None = None,
    ) -> bool:
        return complete_live_index(
            self, source_id, attempt=attempt, lease_token=lease_token, now=now
        )

    def fail_live_segment_index(
        self,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        now: datetime,
        retry_base_seconds: int,
    ) -> bool:
        return fail_live_index(
            self,
            source_id,
            attempt=attempt,
            lease_token=lease_token,
            transient=transient,
            error_code=error_code,
            now=now,
            retry_base_seconds=retry_base_seconds,
        )

    def recover_live_segment_indexes(self, *, now: datetime) -> int:
        return recover_live_indexes(self, now=now)

    def get_live_segment_index_queue_depth(self) -> dict[str, int]:
        return live_index_queue_depth(self)

    def cleanup_terminal_live_segment_indexes(self, *, before: datetime, limit: int) -> int:
        return cleanup_terminal_live_indexes(self, before=before, limit=limit)

    def reconcile_live_segment_indexes(
        self, *, capacity: int, max_attempts: int, limit: int
    ) -> int:
        return reconcile_live_indexes(
            self, capacity=capacity, max_attempts=max_attempts, limit=limit
        )

    def get_live_capture_source_version(
        self: _LiveIndexRepositoryBackend, source_id: str
    ) -> CaptureSourceVersion | None:
        if _is_sqlite_live_index_backend(self):
            row = self.connection.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                "source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=?",
                (source_id,),
            ).fetchone()
            return CaptureSourceVersion(*row) if row is not None else None
        if not _is_memory_live_index_backend(self):
            raise TypeError("unsupported LIVE index repository backend")
        return self.capture_source_versions.get(f"LIVE_SEGMENT:{source_id}")

    def publish_live_structural_index(
        self: _LiveIndexRepositoryBackend,
        build_id: str,
        binding: SourceIndexBinding,
        interfaces: tuple[StructuralInterfaceEntry, ...],
        packet_count: int,
        source_version: CaptureSourceVersion,
        *,
        attempt: int,
        lease_token: str,
        request_postings: bool = False,
        posting_schema_version: int = PCAP_POSTING_INDEX_SCHEMA_VERSION,
        posting_parser_contract_version: int = PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        filter_contract_version: int = PCAP_FILTER_CONTRACT_VERSION,
    ) -> bool:
        if binding.source_kind != "LIVE_SEGMENT" or packet_count < 1:
            return False
        with self._lock:
            if _is_sqlite_live_index_backend(self):
                # A per-instance lock cannot exclude another SQLite connection.
                # Serialize all canonical, staging, owner, and task checks with publication.
                self.connection.execute("BEGIN IMMEDIATE")
                segment = self._get("sensor_pcap", binding.source_id)
            else:
                if not _is_memory_live_index_backend(self):
                    raise TypeError("unsupported LIVE index repository backend")
                segment = self.sensor_pcaps.get(binding.source_id)
            job = self.get_job_summary(str(segment.get("analysis_job_id"))) if segment else None
            expected_key = (
                str(segment.get("object_key"))
                if segment and segment.get("object_key")
                else f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
                if segment
                else ""
            )
            task = get_live_index_task(self, binding.source_id)
            now = datetime.now(UTC)
            if (
                segment is None
                or not eligible_live_segment(job, segment)
                or not segment.get("index_requested_at")
                or source_version
                != CaptureSourceVersion(
                    "LIVE_SEGMENT",
                    binding.source_id,
                    expected_key,
                    binding.source_version_id,
                    binding.source_size_bytes,
                    binding.source_sha256,
                )
                or int(segment.get("size_bytes", -1)) != binding.source_size_bytes
                or segment.get("sha256") != binding.source_sha256
                or task is None
                or task.spec.source_kind != binding.source_kind
                or task.spec.source_id != binding.source_id
                or task.spec.sensor_id != segment.get("sensor_id")
                or task.spec.analysis_job_id != segment.get("analysis_job_id")
                or task.spec.object_key != expected_key
                or task.spec.source_size_bytes != binding.source_size_bytes
                or task.spec.source_sha256 != binding.source_sha256
                or task.status != "RUNNING"
                or task.attempt != attempt
                or task.lease_token != lease_token
                or task.lease_expires_at is None
                or task.lease_expires_at <= now
            ):
                if _is_sqlite_live_index_backend(self):
                    self.connection.rollback()
                return False
            if _is_sqlite_live_index_backend(self):
                generation = self.connection.execute(
                    "SELECT binding,created_at FROM pcap_offset_index_generations "
                    "WHERE build_id=? AND state='STAGING'",
                    (build_id,),
                ).fetchone()
                packets = tuple(
                    StructuralPacketEntry(**json.loads(row[0]))
                    for row in self.connection.execute(
                        "SELECT data FROM pcap_offset_index_packets "
                        "WHERE build_id=? ORDER BY packet_index",
                        (build_id,),
                    ).fetchall()
                )
                created_at = (
                    datetime.fromisoformat(generation[1])
                    if generation
                    else datetime.now().astimezone()
                )
                stored_binding = (
                    SourceIndexBinding(**json.loads(generation[0])) if generation else None
                )
            else:
                if not _is_memory_live_index_backend(self):
                    raise TypeError("unsupported LIVE index repository backend")
                staged = self.structural_index_staging.get(build_id)
                stored_binding = staged[0] if staged else None
                created_at = staged[1] if staged else datetime.now().astimezone()
                packets = tuple(staged[2]) if staged else ()
            snapshot = StructuralIndexSnapshot(
                build_id,
                binding,
                created_at,
                structural_index_digest(binding, interfaces, packets),
                interfaces,
                packets,
            )
            if (
                stored_binding != binding
                or len(packets) != packet_count
                or not validate_structural_index(snapshot)
            ):
                if _is_sqlite_live_index_backend(self):
                    self.connection.rollback()
                return False
            posting_intent = None
            if request_postings:
                spec = replace(
                    PostingIndexTaskSpec.from_binding(source_version, snapshot),
                    posting_schema_version=posting_schema_version,
                    posting_parser_contract_version=posting_parser_contract_version,
                    filter_contract_version=filter_contract_version,
                )
                current = self.get_posting_index_intent(spec.source_kind, spec.source_id)
                if current is None or current.spec.identity != spec.identity:
                    requested_at = self._posting_now()
                    posting_intent = PostingIndexIntent(
                        spec,
                        PostingIndexIntentStatus.PENDING,
                        requested_at,
                        requested_at,
                    )
            if _is_sqlite_live_index_backend(self):
                try:
                    self.connection.execute(
                        "INSERT INTO pcap_capture_source_versions("
                        "source_kind,source_id,object_key,source_version_id,source_size_bytes,source_sha256"
                        ") VALUES(?,?,?,?,?,?) ON CONFLICT(source_kind,source_id) DO NOTHING",
                        (
                            source_version.source_kind,
                            source_version.source_id,
                            source_version.object_key,
                            source_version.source_version_id,
                            source_version.source_size_bytes,
                            source_version.source_sha256,
                        ),
                    )
                    persisted_version = self.connection.execute(
                        "SELECT source_kind,source_id,object_key,source_version_id,"
                        "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                        "WHERE source_kind='LIVE_SEGMENT' AND source_id=?",
                        (binding.source_id,),
                    ).fetchone()
                    if (
                        persisted_version is None
                        or CaptureSourceVersion(*persisted_version) != source_version
                    ):
                        self.connection.rollback()
                        return False
                    self.connection.executemany(
                        "INSERT INTO pcap_offset_index_interfaces("
                        "build_id,interface_ordinal,data) VALUES(?,?,?)",
                        [
                            (build_id, item.interface_ordinal, self._serialize(asdict(item)))
                            for item in interfaces
                        ],
                    )
                    self.connection.execute(
                        "UPDATE pcap_offset_index_generations SET state='READY',packet_count=?,"
                        "interface_count=?,index_sha256=? WHERE build_id=? AND state='STAGING'",
                        (packet_count, len(interfaces), snapshot.index_sha256, build_id),
                    )
                    previous = self.connection.execute(
                        "SELECT build_id FROM pcap_offset_index_owners "
                        "WHERE source_kind=? AND source_id=?",
                        (binding.source_kind, binding.source_id),
                    ).fetchone()
                    self.connection.execute(
                        "INSERT INTO pcap_offset_index_owners("
                        "source_kind,source_id,build_id) VALUES(?,?,?) "
                        "ON CONFLICT(source_kind,source_id) "
                        "DO UPDATE SET build_id=excluded.build_id",
                        (binding.source_kind, binding.source_id, build_id),
                    )
                    if previous and previous[0] != build_id:
                        self.connection.execute(
                            "DELETE FROM pcap_offset_index_generations WHERE build_id=?", previous
                        )
                    completed = replace(
                        task,
                        status="COMPLETED",
                        lease_token=None,
                        lease_expires_at=None,
                        updated_at=now,
                    )
                    cursor = self.connection.execute(
                        "UPDATE pcap_offset_index_jobs SET status='COMPLETED',data=? "
                        "WHERE source_kind='LIVE_SEGMENT' AND source_id=? AND status='RUNNING' "
                        "AND json_extract(data,'$.attempt')=? "
                        "AND json_extract(data,'$.lease_token')=? "
                        "AND json_extract(data,'$.lease_expires_at')>?",
                        (
                            encode_task(completed),
                            binding.source_id,
                            attempt,
                            lease_token,
                            now.isoformat(),
                        ),
                    )
                    if cursor.rowcount != 1:
                        self.connection.rollback()
                        return False
                    _mark_intent(self, binding.source_id, "COMPLETED")
                    if posting_intent is not None:
                        put_posting_intent(self, posting_intent)
                    self.connection.commit()
                except Exception:
                    self.connection.rollback()
                    raise
            else:
                if not _is_memory_live_index_backend(self):
                    raise TypeError("unsupported LIVE index repository backend")
                # Marker creation is the only injected mapping operation in this branch;
                # perform it before publishing READY ownership or acknowledging the task.
                if posting_intent is not None:
                    self.posting_index_intents[(binding.source_kind, binding.source_id)] = (
                        posting_intent
                    )
                self.capture_source_versions[f"LIVE_SEGMENT:{binding.source_id}"] = source_version
                previous = self.structural_index_owners.get(
                    (binding.source_kind, binding.source_id)
                )
                self.structural_index_generations[build_id] = snapshot
                self.structural_index_owners[(binding.source_kind, binding.source_id)] = build_id
                self.structural_index_staging.pop(build_id, None)
                self.live_segment_index_tasks[binding.source_id] = replace(
                    task,
                    status="COMPLETED",
                    lease_token=None,
                    lease_expires_at=None,
                    updated_at=now,
                )
                _mark_intent(self, binding.source_id, "COMPLETED")
                if previous and previous != build_id:
                    self.structural_index_generations.pop(previous, None)
            return True


def _posting_generation_metadata(generation: PostingGeneration) -> str:
    return json.dumps(
        {
            "schema_version": generation.schema_version,
            "parser_contract_version": generation.parser_contract_version,
            "filter_contract_version": generation.filter_contract_version,
            "packet_count": generation.packet_count,
            "supported_count": generation.supported_count,
            "membership_count": generation.membership_count,
            "distinct_key_count": generation.distinct_key_count,
            "chunk_count": len(generation.chunks),
            "encoded_byte_count": generation.encoded_byte_count,
            "complete_dimensions": sorted(item.value for item in generation.complete_dimensions),
            "digest": generation.digest,
            "binding_document": generation.binding_document.hex(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _posting_generation_from_metadata(
    metadata: str, chunks: tuple[PostingChunk, ...]
) -> PostingGeneration:
    value = json.loads(metadata)
    return PostingGeneration(
        int(value["schema_version"]),
        int(value["parser_contract_version"]),
        int(value["filter_contract_version"]),
        int(value["packet_count"]),
        int(value["supported_count"]),
        int(value["membership_count"]),
        int(value["distinct_key_count"]),
        int(value["encoded_byte_count"]),
        frozenset(PostingDimension(item) for item in value["complete_dimensions"]),
        chunks,
        str(value["digest"]),
        bytes.fromhex(str(value["binding_document"])),
    )


def _posting_identity_from_metadata(
    build_id: object,
    binding: object,
    created_at: object,
    metadata: object,
) -> PostingIndexIdentity:
    if (
        not isinstance(build_id, str)
        or not isinstance(binding, str)
        or not isinstance(created_at, str)
        or not isinstance(metadata, str)
    ):
        raise TypeError("posting identity metadata has invalid storage types")
    value = json.loads(metadata)
    integer_fields = (
        "schema_version",
        "parser_contract_version",
        "filter_contract_version",
        "packet_count",
        "supported_count",
        "membership_count",
        "distinct_key_count",
        "chunk_count",
        "encoded_byte_count",
    )
    if any(type(value.get(field)) is not int for field in integer_fields):
        raise TypeError("posting identity numeric metadata is invalid")
    dimensions = value.get("complete_dimensions")
    if not isinstance(dimensions, list) or not all(isinstance(item, str) for item in dimensions):
        raise TypeError("posting identity dimensions are invalid")
    digest = value.get("digest")
    binding_document = value.get("binding_document")
    if not isinstance(digest, str) or not isinstance(binding_document, str):
        raise TypeError("posting identity digest metadata is invalid")
    return PostingIndexIdentity(
        build_id,
        PostingIndexBinding(**json.loads(binding)),
        datetime.fromisoformat(created_at),
        value["schema_version"],
        value["parser_contract_version"],
        value["filter_contract_version"],
        value["packet_count"],
        value["supported_count"],
        value["membership_count"],
        value["distinct_key_count"],
        value["chunk_count"],
        value["encoded_byte_count"],
        tuple(sorted(dimensions)),
        digest,
        bytes.fromhex(binding_document),
    )


def _posting_chunks_from_rows(rows: Iterable[tuple[Any, ...]]) -> tuple[PostingChunk, ...]:
    return tuple(
        PostingChunk(
            PostingDimension(str(row[0])),
            bytes(row[1]),
            int(row[2]),
            int(row[3]),
            int(row[4]),
            int(row[5]),
            bytes(row[6]),
        )
        for row in rows
    )


def _posting_task_matches_snapshot(
    task: PostingIndexTask | None, snapshot: PostingIndexSnapshot
) -> bool:
    try:
        expected = PostingIndexTaskSpec(**asdict(snapshot.binding))
    except (TypeError, ValueError):
        return False
    return task is not None and task.spec == expected


def _aware_posting_time(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"posting {field} must be timezone-aware")
    return value.astimezone(UTC)


class _PostingIndexRepositoryBackend(Protocol):
    _lock: RLock

    def _posting_now(self) -> datetime: ...

    def get_posting_index_task(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexTask | None: ...

    def get_posting_index_intent(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexIntent | None: ...


class _SQLitePostingIndexRepositoryBackend(_PostingIndexRepositoryBackend, Protocol):
    connection: sqlite3.Connection


class _MemoryPostingIndexRepositoryBackend(_PostingIndexRepositoryBackend, Protocol):
    capture_source_versions: dict[str, CaptureSourceVersion]
    structural_index_generations: dict[str, StructuralIndexSnapshot]
    structural_index_owners: dict[tuple[str, str], str]
    posting_index_staging: dict[
        str, tuple[PostingIndexSnapshot, int, str, str | None, list[PostingChunk]]
    ]
    posting_index_generations: dict[str, PostingIndexSnapshot]
    posting_index_owners: dict[tuple[str, str, str], str]
    posting_index_intents: dict[tuple[str, str], PostingIndexIntent]
    posting_index_tasks: dict[tuple[str, str], PostingIndexTask]


def _is_sqlite_posting_index_backend(
    repository: _PostingIndexRepositoryBackend,
) -> TypeGuard[_SQLitePostingIndexRepositoryBackend]:
    return isinstance(getattr(repository, "connection", None), sqlite3.Connection)


def _is_memory_posting_index_backend(
    repository: _PostingIndexRepositoryBackend,
) -> TypeGuard[_MemoryPostingIndexRepositoryBackend]:
    return not hasattr(repository, "connection")


class PostingIndexQueueRepositoryMixin:
    _lock: RLock

    def _posting_now(self) -> datetime:
        raise NotImplementedError

    def request_posting_index(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        *,
        requested_at: datetime | None = None,
    ) -> PostingIndexIntent | None:
        return request_posting_task(self, source_version, parent, requested_at=requested_at)

    def request_posting_index_backfill(self, *, limit: int) -> int:
        return request_posting_backfill(self, limit=limit)

    def get_posting_index_intent(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexIntent | None:
        from .pcap_posting_index_queue import _get_intent

        with self._lock:
            return _get_intent(self, source_kind, source_id)

    def admit_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        capacity: int,
        max_attempts: int,
        now: datetime | None = None,
    ) -> PostingIndexAdmission:
        return admit_posting_task(
            self, source_kind, source_id, capacity=capacity, max_attempts=max_attempts, now=now
        )

    def get_posting_index_task(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexTask | None:
        from .pcap_posting_index_queue import _get_task

        with self._lock:
            return _get_task(self, source_kind, source_id)

    def claim_posting_index(
        self, *, now: datetime | None = None, lease_seconds: int
    ) -> PostingIndexTask | None:
        return claim_posting_task(self, now=now, lease_seconds=lease_seconds)

    def heartbeat_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        now: datetime | None = None,
        lease_seconds: int,
    ) -> bool:
        return heartbeat_posting_task(
            self,
            source_kind,
            source_id,
            attempt=attempt,
            lease_token=lease_token,
            now=now,
            lease_seconds=lease_seconds,
        )

    def fail_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        now: datetime | None = None,
        retry_base_seconds: int,
    ) -> bool:
        return fail_posting_task(
            self,
            source_kind,
            source_id,
            attempt=attempt,
            lease_token=lease_token,
            transient=transient,
            error_code=error_code,
            now=now,
            retry_base_seconds=retry_base_seconds,
        )

    def recover_posting_indexes(self, *, now: datetime | None = None) -> int:
        return recover_posting_tasks(self, now=now)

    def reconcile_posting_indexes(
        self,
        *,
        capacity: int,
        max_attempts: int,
        limit: int,
        now: datetime | None = None,
    ) -> int:
        return reconcile_posting_tasks(
            self, capacity=capacity, max_attempts=max_attempts, limit=limit, now=now
        )

    def get_posting_index_queue_depth(self) -> dict[str, int]:
        return posting_queue_depth(self)

    def cleanup_terminal_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int:
        return cleanup_terminal_posting_tasks(self, max_age_seconds=max_age_seconds, limit=limit)

    def cleanup_stale_posting_indexes(
        self: _PostingIndexRepositoryBackend,
        *,
        max_age_seconds: int,
        limit: int,
    ) -> int:
        if limit <= 0 or max_age_seconds <= 0:
            raise ValueError("posting staging cleanup bounds must be positive")
        current = _aware_posting_time(self._posting_now(), field="cleanup time")
        cutoff = current - timedelta(seconds=max_age_seconds)
        with self._lock:
            if _is_sqlite_posting_index_backend(self):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    rows = self.connection.execute(
                        "SELECT g.build_id FROM pcap_posting_index_generations g "
                        "WHERE g.state='STAGING' AND g.created_at<? "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_posting_index_owners o "
                        "WHERE o.build_id=g.build_id) AND NOT EXISTS ("
                        "SELECT 1 FROM pcap_posting_index_jobs j WHERE "
                        "j.source_kind=g.source_kind AND j.source_id=g.source_id "
                        "AND j.parent_structural_build_id=g.parent_structural_build_id "
                        "AND j.status='RUNNING' AND j.attempt=g.builder_attempt "
                        "AND j.lease_token=g.lease_token AND j.lease_expires_at>?) "
                        "ORDER BY g.created_at,g.build_id LIMIT ?",
                        (cutoff.isoformat(), current.isoformat(), limit),
                    ).fetchall()
                    self.connection.executemany(
                        "DELETE FROM pcap_posting_index_generations "
                        "WHERE build_id=? AND state='STAGING'",
                        rows,
                    )
                    self.connection.commit()
                    return len(rows)
                except Exception:
                    self.connection.rollback()
                    raise
            if not _is_memory_posting_index_backend(self):
                raise TypeError("unsupported posting index repository backend")
            owners = set(self.posting_index_owners.values())
            selected = sorted(
                (
                    (staged[0].created_at, build_id)
                    for build_id, staged in self.posting_index_staging.items()
                    if staged[0].created_at < cutoff
                    and build_id not in owners
                    and not owns_unexpired_posting_task(
                        self.posting_index_tasks.get(
                            (staged[0].binding.source_kind, staged[0].binding.source_id)
                        ),
                        attempt=staged[1],
                        lease_token=staged[2],
                        now=current,
                    )
                )
            )[:limit]
            for _created_at, build_id in selected:
                self.posting_index_staging.pop(build_id, None)
            return len(selected)


class PostingIndexRepositoryMixin:
    """Additive Phase-A STAGING/READY posting repository contract.

    Publication here is an internal synchronous Phase-A seam. Durable task lease
    ownership and worker CAS deliberately remain Phase B responsibilities.
    """

    def begin_posting_index(
        self: _PostingIndexRepositoryBackend,
        snapshot: PostingIndexSnapshot,
        *,
        attempt: int,
        lease_token: str,
        now: datetime | None = None,
    ) -> None:
        if not lease_token or attempt <= 0:
            raise ValueError("posting task lease is required")
        # ``now`` is compatibility-only; durable creation time is repository-owned.
        staged_at = _aware_posting_time(self._posting_now(), field="begin time")
        if not is_posting_source_kind(snapshot.binding.source_kind):
            raise ValueError("posting source kind is invalid")
        key = (
            snapshot.binding.source_kind,
            snapshot.binding.source_id,
            snapshot.binding.parent_structural_build_id,
        )
        with self._lock:
            if _is_sqlite_posting_index_backend(self):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    task = self.get_posting_index_task(key[0], key[1])
                    if not owns_unexpired_posting_task(
                        task,
                        attempt=attempt,
                        lease_token=lease_token,
                        now=self._posting_now(),
                    ) or not _posting_task_matches_snapshot(task, snapshot):
                        self.connection.rollback()
                        raise ValueError("posting task lease is not current")
                    owner = self.connection.execute(
                        "SELECT build_id FROM pcap_posting_index_owners "
                        "WHERE source_kind=? AND source_id=? AND parent_structural_build_id=?",
                        key,
                    ).fetchone()
                    self.connection.execute(
                        "INSERT INTO pcap_posting_index_generations("
                        "build_id,source_kind,source_id,parent_structural_build_id,state,binding,"
                        "created_at,generation_metadata,builder_attempt,lease_token,"
                        "expected_owner_build_id) VALUES(?,?,?,?,'STAGING',?,?,?,?,?,?)",
                        (
                            snapshot.build_id,
                            *key,
                            json.dumps(
                                asdict(snapshot.binding), sort_keys=True, separators=(",", ":")
                            ),
                            staged_at.isoformat(),
                            _posting_generation_metadata(snapshot.generation),
                            attempt,
                            lease_token,
                            str(owner[0]) if owner else None,
                        ),
                    )
                    self.connection.commit()
                    return
                except Exception:
                    self.connection.rollback()
                    raise
            if not _is_memory_posting_index_backend(self):
                raise TypeError("unsupported posting index repository backend")
            task = self.get_posting_index_task(key[0], key[1])
            if not owns_unexpired_posting_task(
                task,
                attempt=attempt,
                lease_token=lease_token,
                now=self._posting_now(),
            ) or not _posting_task_matches_snapshot(task, snapshot):
                raise ValueError("posting task lease is not current")
            owner = self.posting_index_owners.get(key)
            metadata_generation = replace(snapshot.generation, chunks=())
            metadata_snapshot = replace(
                snapshot, created_at=staged_at, generation=metadata_generation
            )
            self.posting_index_staging[snapshot.build_id] = (
                metadata_snapshot,
                attempt,
                lease_token,
                owner,
                [],
            )

    def stage_posting_index_chunks(
        self: _PostingIndexRepositoryBackend,
        build_id: str,
        chunks: tuple[PostingChunk, ...],
        *,
        source_kind: PostingSourceKind,
        source_id: str,
        attempt: int,
        lease_token: str,
        now: datetime | None = None,
    ) -> None:
        with self._lock:
            if _is_sqlite_posting_index_backend(self):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    task = self.get_posting_index_task(source_kind, source_id)
                    generation = self.connection.execute(
                        "SELECT builder_attempt,lease_token FROM pcap_posting_index_generations "
                        "WHERE build_id=? AND source_kind=? AND source_id=? AND state='STAGING'",
                        (build_id, source_kind, source_id),
                    ).fetchone()
                    if not owns_unexpired_posting_task(
                        task,
                        attempt=attempt,
                        lease_token=lease_token,
                        now=self._posting_now(),
                    ) or generation != (attempt, lease_token):
                        self.connection.rollback()
                        raise ValueError("posting task lease is not current")
                    self.connection.executemany(
                        "INSERT INTO pcap_posting_index_chunks("
                        "build_id,dimension,canonical_value,chunk_ordinal,first_packet_index,"
                        "last_packet_index,membership_count,encoded_ordinals) "
                        "VALUES(?,?,?,?,?,?,?,?)",
                        [
                            (
                                build_id,
                                item.dimension.value,
                                sqlite3.Binary(item.value),
                                item.chunk_ordinal,
                                item.first_packet_index,
                                item.last_packet_index,
                                item.count,
                                sqlite3.Binary(item.encoded_ordinals),
                            )
                            for item in chunks
                        ],
                    )
                    self.connection.commit()
                    return
                except Exception:
                    self.connection.rollback()
                    raise
            if not _is_memory_posting_index_backend(self):
                raise TypeError("unsupported posting index repository backend")
            staged = self.posting_index_staging.get(build_id)
            task = self.get_posting_index_task(source_kind, source_id)
            if (
                staged is None
                or staged[1:3] != (attempt, lease_token)
                or staged[0].binding.source_kind != source_kind
                or staged[0].binding.source_id != source_id
                or not owns_unexpired_posting_task(
                    task,
                    attempt=attempt,
                    lease_token=lease_token,
                    now=self._posting_now(),
                )
            ):
                raise ValueError("posting task lease is not current")
            snapshot, stored_attempt, token, expected_owner, stored = staged
            stored.extend(chunks)
            self.posting_index_staging[build_id] = (
                snapshot,
                stored_attempt,
                token,
                expected_owner,
                stored,
            )

    def publish_posting_index(
        self: _PostingIndexRepositoryBackend,
        build_id: str,
        *,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        attempt: int,
        lease_token: str,
        now: datetime | None = None,
    ) -> bool:
        if not is_posting_source_kind(source_version.source_kind):
            return False
        key = (source_version.source_kind, source_version.source_id, parent.build_id)
        with self._lock:
            authoritative_now = _aware_posting_time(self._posting_now(), field="publication time")
            if _is_sqlite_posting_index_backend(self):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    generation_row = self.connection.execute(
                        "SELECT binding,created_at,generation_metadata,builder_attempt,lease_token,"
                        "expected_owner_build_id FROM pcap_posting_index_generations "
                        "WHERE build_id=? AND state='STAGING'",
                        (build_id,),
                    ).fetchone()
                    task = self.get_posting_index_task(key[0], key[1])
                    intent = self.get_posting_index_intent(key[0], key[1])
                    source_row = self.connection.execute(
                        "SELECT source_kind,source_id,object_key,source_version_id,"
                        "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                        "WHERE source_kind=? AND source_id=?",
                        key[:2],
                    ).fetchone()
                    structural_owner = self.connection.execute(
                        "SELECT build_id FROM pcap_offset_index_owners "
                        "WHERE source_kind=? AND source_id=?",
                        key[:2],
                    ).fetchone()
                    parent_row = self.connection.execute(
                        "SELECT index_sha256,state FROM pcap_offset_index_generations "
                        "WHERE build_id=?",
                        (parent.build_id,),
                    ).fetchone()
                    owner = self.connection.execute(
                        "SELECT build_id FROM pcap_posting_index_owners "
                        "WHERE source_kind=? AND source_id=? AND parent_structural_build_id=?",
                        key,
                    ).fetchone()
                    if generation_row is None:
                        self.connection.rollback()
                        return False
                    expected_owner = generation_row[5]
                    current_owner = str(owner[0]) if owner else None
                    if (
                        int(generation_row[3]) != attempt
                        or str(generation_row[4]) != lease_token
                        or not owns_unexpired_posting_task(
                            task,
                            attempt=attempt,
                            lease_token=lease_token,
                            now=authoritative_now,
                        )
                        or intent is None
                        or task is None
                        or intent.spec.identity != task.spec.identity
                        or intent.spec.parent_structural_build_id != parent.build_id
                        or expected_owner != current_owner
                        or source_row is None
                        or CaptureSourceVersion(*source_row) != source_version
                        or structural_owner is None
                        or str(structural_owner[0]) != parent.build_id
                        or parent_row != (parent.index_sha256, "READY")
                    ):
                        self.connection.rollback()
                        return False
                    rows = self.connection.execute(
                        "SELECT dimension,canonical_value,chunk_ordinal,first_packet_index,"
                        "last_packet_index,membership_count,encoded_ordinals "
                        "FROM pcap_posting_index_chunks WHERE build_id=? "
                        "ORDER BY dimension,canonical_value,chunk_ordinal",
                        (build_id,),
                    ).fetchall()
                    snapshot = PostingIndexSnapshot(
                        build_id,
                        PostingIndexBinding(**json.loads(generation_row[0])),
                        datetime.fromisoformat(generation_row[1]),
                        _posting_generation_from_metadata(
                            generation_row[2], _posting_chunks_from_rows(rows)
                        ),
                    )
                    if not validate_posting_index(
                        snapshot, source_version=source_version, parent=parent
                    ):
                        self.connection.rollback()
                        return False
                    generation_cas = self.connection.execute(
                        "UPDATE pcap_posting_index_generations SET state='READY' "
                        "WHERE build_id=? AND state='STAGING'",
                        (build_id,),
                    )
                    owner_cas = self.connection.execute(
                        "INSERT INTO pcap_posting_index_owners("
                        "source_kind,source_id,parent_structural_build_id,build_id) "
                        "VALUES(?,?,?,?) "
                        "ON CONFLICT(source_kind,source_id,parent_structural_build_id) "
                        "DO UPDATE SET build_id=excluded.build_id",
                        (*key, build_id),
                    )
                    if current_owner and current_owner != build_id:
                        self.connection.execute(
                            "DELETE FROM pcap_posting_index_generations WHERE build_id=?",
                            (current_owner,),
                        )
                    completed_task = replace(
                        task,
                        status=PostingIndexTaskStatus.COMPLETED,
                        lease_token=None,
                        lease_expires_at=None,
                        updated_at=authoritative_now,
                        error_code=None,
                    )
                    completed_intent = replace(
                        intent,
                        status=PostingIndexIntentStatus.COMPLETED,
                        updated_at=authoritative_now,
                        published_build_id=build_id,
                        error_code=None,
                    )
                    task_cas = self.connection.execute(
                        "UPDATE pcap_posting_index_jobs SET status='COMPLETED',lease_token=NULL,"
                        "lease_expires_at=NULL,updated_at=?,data=? WHERE "
                        "source_kind=? AND source_id=? "
                        "AND parent_structural_build_id=? AND status='RUNNING' AND attempt=? "
                        "AND lease_token=? AND lease_expires_at>?",
                        (
                            authoritative_now.isoformat(),
                            encode_posting_lifecycle(completed_task),
                            key[0],
                            key[1],
                            key[2],
                            attempt,
                            lease_token,
                            authoritative_now.isoformat(),
                        ),
                    )
                    intent_cas = self.connection.execute(
                        "UPDATE pcap_posting_index_intents SET "
                        "status='COMPLETED',updated_at=?,data=? "
                        "WHERE source_kind=? AND source_id=? AND parent_structural_build_id=? "
                        "AND status IN ('PENDING','DEFERRED')",
                        (
                            authoritative_now.isoformat(),
                            encode_posting_lifecycle(completed_intent),
                            key[0],
                            key[1],
                            key[2],
                        ),
                    )
                    if any(
                        cursor.rowcount != 1
                        for cursor in (generation_cas, owner_cas, task_cas, intent_cas)
                    ):
                        self.connection.rollback()
                        return False
                    self.connection.commit()
                    return True
                except Exception:
                    self.connection.rollback()
                    raise
            if not _is_memory_posting_index_backend(self):
                raise TypeError("unsupported posting index repository backend")
            staged = self.posting_index_staging.get(build_id)
            current_source = self.capture_source_versions.get(
                source_version.source_id
                if source_version.source_kind == "PCAP_UPLOAD"
                else f"LIVE_SEGMENT:{source_version.source_id}"
            )
            current_owner = self.posting_index_owners.get(key)
            current_parent = self.structural_index_generations.get(parent.build_id)
            task = self.get_posting_index_task(key[0], key[1])
            intent = self.get_posting_index_intent(key[0], key[1])
            if (
                staged is None
                or staged[1:3] != (attempt, lease_token)
                or staged[3] != current_owner
                or not owns_unexpired_posting_task(
                    task,
                    attempt=attempt,
                    lease_token=lease_token,
                    now=authoritative_now,
                )
                or task is None
                or intent is None
                or task.spec.identity != intent.spec.identity
                or intent.spec.parent_structural_build_id != parent.build_id
                or current_source != source_version
                or self.structural_index_owners.get(key[:2]) != parent.build_id
                or current_parent is None
                or current_parent.binding != parent.binding
                or current_parent.index_sha256 != parent.index_sha256
                or current_parent.interfaces != parent.interfaces
                or current_parent.packets != parent.packets
            ):
                return False
            metadata_snapshot, _, _, _, chunks = staged
            snapshot = replace(
                metadata_snapshot,
                generation=replace(metadata_snapshot.generation, chunks=tuple(chunks)),
            )
            if not validate_posting_index(snapshot, source_version=source_version, parent=parent):
                return False
            generation_before = {
                generation_id: deepcopy(self.posting_index_generations[generation_id])
                for generation_id in {build_id, current_owner}
                if generation_id is not None and generation_id in self.posting_index_generations
            }
            generation_presence = {
                generation_id: generation_id in self.posting_index_generations
                for generation_id in {build_id, current_owner}
                if generation_id is not None
            }
            owner_present = key in self.posting_index_owners
            owner_before = deepcopy(self.posting_index_owners.get(key))
            lifecycle_key = key[:2]
            task_present = lifecycle_key in self.posting_index_tasks
            task_before = deepcopy(self.posting_index_tasks.get(lifecycle_key))
            intent_present = lifecycle_key in self.posting_index_intents
            intent_before = deepcopy(self.posting_index_intents.get(lifecycle_key))
            staging_present = build_id in self.posting_index_staging
            staging_before = deepcopy(self.posting_index_staging.get(build_id))

            def restore(mapping: dict[Any, Any], item_key: Any, present: bool, value: Any) -> None:
                if present:
                    mapping[item_key] = deepcopy(value)
                else:
                    mapping.pop(item_key, None)

            try:
                self.posting_index_generations[build_id] = snapshot
                self.posting_index_owners[key] = build_id
                self.posting_index_staging.pop(build_id, None)
                self.posting_index_tasks[lifecycle_key] = replace(
                    task,
                    status=PostingIndexTaskStatus.COMPLETED,
                    lease_token=None,
                    lease_expires_at=None,
                    updated_at=authoritative_now,
                    error_code=None,
                )
                self.posting_index_intents[lifecycle_key] = replace(
                    intent,
                    status=PostingIndexIntentStatus.COMPLETED,
                    updated_at=authoritative_now,
                    published_build_id=build_id,
                    error_code=None,
                )
                if current_owner and current_owner != build_id:
                    self.posting_index_generations.pop(current_owner, None)
            except Exception:
                for generation_id, present in generation_presence.items():
                    restore(
                        self.posting_index_generations,
                        generation_id,
                        present,
                        generation_before.get(generation_id),
                    )
                restore(self.posting_index_owners, key, owner_present, owner_before)
                restore(self.posting_index_tasks, lifecycle_key, task_present, task_before)
                restore(self.posting_index_intents, lifecycle_key, intent_present, intent_before)
                restore(self.posting_index_staging, build_id, staging_present, staging_before)
                raise
            return True

    def get_posting_index_identity(
        self: _PostingIndexRepositoryBackend,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexParentIdentity,
    ) -> PostingIndexIdentityLookup:
        key = (source_version.source_kind, source_version.source_id, parent.build_id)
        with self._lock:
            if _is_sqlite_posting_index_backend(self):
                row = self.connection.execute(
                    "SELECT owner.build_id,generation.binding,generation.created_at,"
                    "generation.generation_metadata,generation.state FROM "
                    "pcap_posting_index_owners AS owner LEFT JOIN "
                    "pcap_posting_index_generations AS generation ON "
                    "generation.build_id=owner.build_id WHERE owner.source_kind=? AND "
                    "owner.source_id=? AND owner.parent_structural_build_id=? LIMIT 1",
                    key,
                ).fetchone()
                if row is None:
                    return PostingIndexIdentityLookup(PostingIndexAvailability.MISSING)
                if row[1] is None or row[4] != "READY":
                    return PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT)
                try:
                    identity = _posting_identity_from_metadata(*row[:4])
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    return PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT)
            else:
                if not _is_memory_posting_index_backend(self):
                    raise TypeError("unsupported posting index repository backend")
                owner_id = self.posting_index_owners.get(key)
                if owner_id is None:
                    return PostingIndexIdentityLookup(PostingIndexAvailability.MISSING)
                snapshot = self.posting_index_generations.get(owner_id)
                if snapshot is None or snapshot.build_id != owner_id:
                    return PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT)
                identity = posting_index_identity(snapshot)
            availability = posting_index_identity_availability(
                identity, source_version=source_version, parent=parent
            )
            return PostingIndexIdentityLookup(
                availability,
                identity if availability is PostingIndexAvailability.READY else None,
            )

    def get_posting_index(
        self: _PostingIndexRepositoryBackend,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        limits: PostingQueryLimits | None = None,
    ) -> PostingIndexLookup:
        key = (source_version.source_kind, source_version.source_id, parent.build_id)
        with self._lock:
            if _is_sqlite_posting_index_backend(self):
                owner = self.connection.execute(
                    "SELECT build_id FROM pcap_posting_index_owners "
                    "WHERE source_kind=? AND source_id=? AND parent_structural_build_id=?",
                    key,
                ).fetchone()
                if owner is None:
                    return PostingIndexLookup(PostingIndexAvailability.MISSING)
                generation_row = self.connection.execute(
                    "SELECT binding,created_at,generation_metadata,state "
                    "FROM pcap_posting_index_generations WHERE build_id=?",
                    (owner[0],),
                ).fetchone()
                if generation_row is None or generation_row[3] != "READY":
                    return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
                try:
                    metadata = json.loads(generation_row[2])
                    metadata_chunk_count = metadata.get("chunk_count")
                    if metadata_chunk_count is None:
                        counted = self.connection.execute(
                            "SELECT COUNT(*) FROM pcap_posting_index_chunks WHERE build_id=?",
                            (owner[0],),
                        ).fetchone()
                        if counted is None:
                            return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
                        chunk_count = int(counted[0])
                    else:
                        chunk_count = int(metadata_chunk_count)
                    if limits is not None and chunk_count > limits.max_directory_chunks:
                        return PostingIndexLookup(PostingIndexAvailability.RESOURCE_LIMIT)
                    chunk_limit = (
                        limits.max_directory_chunks + 1 if limits is not None else chunk_count + 1
                    )
                    rows = self.connection.execute(
                        "SELECT dimension,canonical_value,chunk_ordinal,first_packet_index,"
                        "last_packet_index,membership_count,encoded_ordinals "
                        "FROM pcap_posting_index_chunks WHERE build_id=? "
                        "ORDER BY dimension,canonical_value,chunk_ordinal LIMIT ?",
                        (owner[0], chunk_limit),
                    ).fetchall()
                    if len(rows) > chunk_count or (
                        limits is not None and len(rows) > limits.max_directory_chunks
                    ):
                        return PostingIndexLookup(PostingIndexAvailability.RESOURCE_LIMIT)
                    snapshot = PostingIndexSnapshot(
                        str(owner[0]),
                        PostingIndexBinding(**json.loads(generation_row[0])),
                        datetime.fromisoformat(generation_row[1]),
                        _posting_generation_from_metadata(
                            generation_row[2], _posting_chunks_from_rows(rows)
                        ),
                    )
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
            else:
                if not _is_memory_posting_index_backend(self):
                    raise TypeError("unsupported posting index repository backend")
                owner_id = self.posting_index_owners.get(key)
                if owner_id is None:
                    return PostingIndexLookup(PostingIndexAvailability.MISSING)
                memory_snapshot = self.posting_index_generations.get(owner_id)
                if memory_snapshot is None:
                    return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
                if (
                    limits is not None
                    and len(memory_snapshot.generation.chunks) > limits.max_directory_chunks
                ):
                    return PostingIndexLookup(PostingIndexAvailability.RESOURCE_LIMIT)
                snapshot = memory_snapshot
            if snapshot.binding != PostingIndexBinding(
                source_version.source_kind,
                source_version.source_id,
                source_version.source_version_id,
                source_version.source_size_bytes,
                source_version.source_sha256,
                parent.binding.capture_format,
                parent.build_id,
                parent.index_sha256,
                parent.binding.schema_version,
                parent.binding.parser_contract_version,
            ):
                return PostingIndexLookup(PostingIndexAvailability.STALE)
            if not validate_posting_index(snapshot, source_version=source_version, parent=parent):
                return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
            return PostingIndexLookup(PostingIndexAvailability.READY, snapshot)

    def abort_posting_index(
        self: _PostingIndexRepositoryBackend,
        build_id: str,
        *,
        source_kind: PostingSourceKind,
        source_id: str,
        parent_structural_build_id: str,
        attempt: int,
        lease_token: str,
    ) -> bool:
        if not is_posting_source_kind(source_kind) or attempt <= 0 or not lease_token:
            return False
        key = (source_kind, source_id)
        with self._lock:
            authoritative_now = self._posting_now()
            if _is_sqlite_posting_index_backend(self):
                self.connection.execute("BEGIN IMMEDIATE")
                try:
                    task = self.get_posting_index_task(*key)
                    intent = self.get_posting_index_intent(*key)
                    generation = self.connection.execute(
                        "SELECT source_kind,source_id,parent_structural_build_id,state,"
                        "builder_attempt,lease_token FROM pcap_posting_index_generations "
                        "WHERE build_id=?",
                        (build_id,),
                    ).fetchone()
                    eligible = (
                        owns_unexpired_posting_task(
                            task,
                            attempt=attempt,
                            lease_token=lease_token,
                            now=authoritative_now,
                        )
                        and task is not None
                        and intent is not None
                        and task.spec.identity == intent.spec.identity
                        and task.spec.parent_structural_build_id == parent_structural_build_id
                        and intent.spec.parent_structural_build_id == parent_structural_build_id
                        and intent.status
                        in {PostingIndexIntentStatus.PENDING, PostingIndexIntentStatus.DEFERRED}
                        and generation
                        == (
                            source_kind,
                            source_id,
                            parent_structural_build_id,
                            "STAGING",
                            attempt,
                            lease_token,
                        )
                    )
                    if not eligible:
                        self.connection.rollback()
                        return False
                    deleted = self.connection.execute(
                        "DELETE FROM pcap_posting_index_generations "
                        "WHERE build_id=? AND source_kind=? AND source_id=? "
                        "AND parent_structural_build_id=? AND state='STAGING' "
                        "AND builder_attempt=? AND lease_token=?",
                        (
                            build_id,
                            source_kind,
                            source_id,
                            parent_structural_build_id,
                            attempt,
                            lease_token,
                        ),
                    )
                    if deleted.rowcount != 1:
                        self.connection.rollback()
                        return False
                    self.connection.commit()
                    return True
                except Exception:
                    self.connection.rollback()
                    raise
            if not _is_memory_posting_index_backend(self):
                raise TypeError("unsupported posting index repository backend")
            task = self.posting_index_tasks.get(key)
            intent = self.posting_index_intents.get(key)
            staged = self.posting_index_staging.get(build_id)
            if (
                not owns_unexpired_posting_task(
                    task,
                    attempt=attempt,
                    lease_token=lease_token,
                    now=authoritative_now,
                )
                or task is None
                or intent is None
                or task.spec.identity != intent.spec.identity
                or task.spec.parent_structural_build_id != parent_structural_build_id
                or intent.spec.parent_structural_build_id != parent_structural_build_id
                or intent.status
                not in {PostingIndexIntentStatus.PENDING, PostingIndexIntentStatus.DEFERRED}
                or staged is None
                or staged[0].binding.source_kind != source_kind
                or staged[0].binding.source_id != source_id
                or staged[0].binding.parent_structural_build_id != parent_structural_build_id
                or staged[1:3] != (attempt, lease_token)
            ):
                return False
            self.posting_index_staging.pop(build_id)
            return True


class MemoryRepository(
    PostingIndexQueueRepositoryMixin, PostingIndexRepositoryMixin, LiveIndexQueueRepositoryMixin
):
    def __init__(self, *, _lease_clock: Callable[[], datetime] | None = None) -> None:
        self._lease_clock = _lease_clock or (lambda: datetime.now(UTC))
        self.sensors: dict[str, dict[str, Any]] = {}
        self.groups: dict[str, dict[str, Any]] = {}
        self.jobs: dict[str, dict[str, Any]] = {}
        self.idempotency_keys: dict[str, str] = {}
        self.candidates: dict[str, list[dict[str, Any]]] = {}
        self.ai_runs: dict[str, dict[str, Any]] = {}
        self.ai_run_idempotency_keys: dict[tuple[str, str], str] = {}
        self.ai_assessments: dict[str, dict[str, Any]] = {}
        self.ai_artifacts: dict[str, dict[str, Any]] = {}
        self.ai_feedback: dict[str, dict[str, Any]] = {}
        self.audit_events: list[dict[str, Any]] = []
        self.candidate_decisions: dict[str, dict[str, Any]] = {}
        self.candidate_actions: dict[str, dict[str, Any]] = {}
        self.candidate_ti_lookups: dict[str, dict[str, Any]] = {}
        self.candidate_misp_actions: dict[str, dict[str, Any]] = {}
        self.integration_settings: dict[str, Any] | None = None
        self.job_captures: dict[str, bytes] = {}
        self.capture_source_versions: dict[str, CaptureSourceVersion] = {}
        self.flow_labels: dict[str, dict[str, Any]] = {}
        self.payload_signatures: dict[str, dict[str, Any]] = {}
        self.allowlist: dict[str, dict[str, Any]] = {}
        self.detector_weight_presets: dict[str, dict[str, Any]] = {}
        self.exports: dict[str, dict[str, Any]] = {}
        self.export_content: dict[str, bytes] = {}
        self.pcap_export_jobs: dict[str, dict[str, Any]] = {}
        self.live_segment_index_tasks: dict[str, LiveIndexTask] = {}
        self.sensor_pcaps: dict[str, dict[str, Any]] = {}
        self.sensor_pcap_content: dict[str, bytes] = {}
        self.enrollments: dict[str, dict[str, Any]] = {}
        self.sensor_credentials: dict[str, dict[str, Any]] = {}
        self.structural_index_staging: dict[
            str, tuple[SourceIndexBinding, datetime, list[StructuralPacketEntry]]
        ] = {}
        self.structural_index_generations: dict[str, StructuralIndexSnapshot] = {}
        self.structural_index_owners: dict[object, str] = {}
        self.posting_index_intents: dict[tuple[str, str], PostingIndexIntent] = {}
        self.posting_index_tasks: dict[tuple[str, str], PostingIndexTask] = {}
        self.posting_index_staging: dict[
            str, tuple[PostingIndexSnapshot, int, str, str | None, list[PostingChunk]]
        ] = {}
        self.posting_index_generations: dict[str, PostingIndexSnapshot] = {}
        self.posting_index_owners: dict[tuple[str, str, str], str] = {}
        self._lock = threading.RLock()

    def _posting_now(self) -> datetime:
        return self._lease_clock()

    def ready(self) -> bool:
        return True

    def for_background_worker(self) -> MemoryRepository:
        return self

    def close(self) -> None:
        return None

    def snapshot_pcap_export_source(
        self,
        job_id: str,
        canonical_request: dict[str, Any],
        effective_limits: dict[str, int],
    ) -> dict[str, Any] | None:
        with self._lock:
            return _pcap_export_snapshot(self, job_id, canonical_request, effective_limits)

    def validate_pcap_export_admission(self, job: dict[str, Any]) -> bool:
        with self._lock:
            return _pcap_export_admission_matches(self, job)

    def _pcap_store(self) -> RepositoryQueueStore:
        return RepositoryQueueStore(self)

    def enqueue_pcap_export_job(
        self, job: dict[str, Any], *, capacity: int, per_principal_limit: int
    ) -> tuple[dict[str, Any], bool]:
        return self._pcap_store().enqueue(
            job, capacity=capacity, per_principal_limit=per_principal_limit
        )

    def get_pcap_export_job(self, export_id: str) -> dict[str, Any] | None:
        return self._pcap_store().get(export_id)

    def find_pcap_export_job(
        self, principal_scope: str, idempotency_key: str, request_fingerprint: str
    ) -> dict[str, Any] | None:
        with self._lock:
            found = next(
                (
                    deepcopy(job)
                    for job in self.pcap_export_jobs.values()
                    if job.get("principal_scope") == principal_scope
                    and job.get("idempotency_key") == idempotency_key
                ),
                None,
            )
        if found is not None and found.get("request_fingerprint") != request_fingerprint:
            raise ValueError("idempotency_conflict")
        return found

    def count_pcap_export_jobs_by_status(self) -> dict[str, int]:
        with self._lock:
            return {
                status: sum(job.get("status") == status for job in self.pcap_export_jobs.values())
                for status in ("QUEUED", "RUNNING")
            }

    def claim_pcap_export_job(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> dict[str, Any] | None:
        return self._pcap_store().claim(now=now, lease_seconds=lease_seconds)

    def heartbeat_pcap_export_job(
        self, export_id: str, *, attempt: int, lease_token: str, lease_seconds: int
    ) -> bool:
        return self._pcap_store().heartbeat(
            export_id, attempt=attempt, lease_token=lease_token, lease_seconds=lease_seconds
        )

    def progress_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        progress: dict[str, Any],
    ) -> bool:
        return self._pcap_store().progress(
            export_id, attempt=attempt, lease_token=lease_token, progress=progress
        )

    def complete_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> bool:
        return self._pcap_store().complete(
            export_id, attempt=attempt, lease_token=lease_token, artifact=artifact
        )

    def retry_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        error: str,
        retry_base_seconds: int = 5,
    ) -> bool:
        return self._pcap_store().retry_or_fail(
            export_id,
            attempt=attempt,
            lease_token=lease_token,
            transient=transient,
            error_code=error_code,
            error=error,
            retry_base_seconds=retry_base_seconds,
        )

    def cancel_pcap_export_job(
        self, export_id: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        return self._pcap_store().cancel(export_id, reason=reason)

    def recover_pcap_export_jobs(self, *, now: datetime | None = None) -> int:
        return self._pcap_store().recover_expired(now=now)

    def has_active_pcap_exports(self, job_id: str) -> bool:
        with self._lock:
            return any(
                job_id
                in set(
                    item.get("provenance_job_ids")
                    or [item.get("job_id"), item.get("source_job_id")]
                )
                and item.get("status") in {"QUEUED", "RUNNING"}
                for item in self.pcap_export_jobs.values()
            )

    def validate_pcap_export_source(self, job: dict[str, Any]) -> bool:
        if "canonical_request" not in job:
            return True
        snapshot = self.snapshot_pcap_export_source(
            str(job["job_id"]),
            dict(job.get("canonical_request", {})),
            dict(job.get("effective_limits", {})),
        )
        return bool(
            snapshot is not None
            and snapshot["source_generation"] == job.get("source_generation")
            and snapshot["source_manifest"] == job.get("source_manifest", [])
        )

    def compensate_pcap_export_artifact(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> None:
        with self._lock:
            object_key = artifact.get("object_key")
            lifecycle = self.pcap_export_jobs.get(export_id)
            published_winner = bool(
                lifecycle is not None
                and lifecycle.get("status") == "COMPLETED"
                and int(lifecycle.get("attempt", 0)) == attempt
                and isinstance(artifact.get("sha256"), str)
                and isinstance(artifact.get("size_bytes"), int)
                and lifecycle.get("sha256") == artifact.get("sha256")
                and lifecycle.get("size_bytes") == artifact.get("size_bytes")
            )
            if published_winner or (
                object_key and lifecycle is not None and lifecycle.get("object_key") == object_key
            ):
                return
            metadata = self.exports.get(export_id)
            if metadata is None:
                return
            if (
                metadata.get("attempt") == attempt
                and metadata.get("lease_token") == lease_token
                and metadata.get("object_key") == artifact.get("object_key")
            ):
                self.exports.pop(export_id, None)
                self.export_content.pop(export_id, None)

    def cleanup_pcap_export_orphans(
        self, *, now: datetime, max_age_seconds: int, limit: int
    ) -> list[str]:
        cutoff = now - timedelta(seconds=max_age_seconds)
        with self._lock:
            referenced = {
                str(job.get("object_key"))
                for job in self.pcap_export_jobs.values()
                if job.get("object_key")
            }
            candidates = sorted(
                (
                    (str(metadata.get("created_at", "")), export_id, str(metadata["object_key"]))
                    for export_id, metadata in self.exports.items()
                    if metadata.get("published") is False
                    and metadata.get("object_key")
                    and str(metadata["object_key"]) not in referenced
                    and metadata.get("created_at")
                    and datetime.fromisoformat(str(metadata["created_at"])) <= cutoff
                )
            )[:limit]
            for _created_at, export_id, _object_key in candidates:
                self.exports.pop(export_id, None)
                self.export_content.pop(export_id, None)
            return [object_key for _created_at, _export_id, object_key in candidates]

    def retain_pcap_export_jobs(
        self,
        *,
        now: datetime,
        max_age_seconds: int,
        max_count: int,
        max_artifact_bytes: int,
    ) -> list[str]:
        return self._pcap_store().retain_terminal(
            now=now,
            max_age_seconds=max_age_seconds,
            max_count=max_count,
            max_artifact_bytes=max_artifact_bytes,
        )

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.sensors[sensor["sensor_id"]] = deepcopy(sensor)
            return deepcopy(sensor)

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        value = self.sensors.get(sensor_id)
        return deepcopy(value) if value else None

    def list_sensors(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.sensors.values()))

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.groups[group["id"]] = deepcopy(group)
            return deepcopy(group)

    def list_groups(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.groups.values()))

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            existing_id = self.idempotency_keys.get(job["idempotency_key"])
            if existing_id:
                return deepcopy(self.jobs[existing_id]), False
            self.jobs[job["id"]] = deepcopy(job)
            self.idempotency_keys[job["idempotency_key"]] = job["id"]
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            stored = deepcopy(job)
            existing = self.jobs.get(job["id"])
            if "flow_records" not in stored and existing is not None:
                stored["flow_records"] = deepcopy(existing.get("flow_records", []))
            if "payload_signatures" not in stored and existing is not None:
                stored["payload_signatures"] = deepcopy(existing.get("payload_signatures", []))
            self.jobs[job["id"]] = stored
            return deepcopy(job)

    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]:
        summary = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        return self.save_job(summary)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        value = self.jobs.get(job_id)
        return deepcopy(value) if value else None

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        value = self.jobs.get(job_id)
        if value is None:
            return None
        return deepcopy(
            {
                key: item
                for key, item in value.items()
                if key not in {"flow_records", "payload_signatures"}
            }
        )

    def get_job_summaries(self, job_ids: list[str]) -> dict[str, dict[str, Any]]:
        summaries: dict[str, dict[str, Any]] = {}
        for job_id in dict.fromkeys(job_ids):
            job_summary = self.get_job_summary(job_id)
            if job_summary is not None:
                summaries[job_id] = job_summary
        return summaries

    def list_jobs(self) -> list[dict[str, Any]]:
        return [
            deepcopy(
                {
                    key: item
                    for key, item in job.items()
                    if key not in {"flow_records", "payload_signatures"}
                }
            )
            for job in self.jobs.values()
        ]

    def list_active_live_jobs(self) -> list[dict[str, Any]]:
        return [
            deepcopy(
                {
                    key: item
                    for key, item in job.items()
                    if key not in {"flow_records", "payload_signatures"}
                }
            )
            for job in self.jobs.values()
            if job.get("mode") == "LIVE" and job.get("status") in {"CAPTURING", "UPLOADING"}
        ]

    def delete_job(self, job_id: str) -> bool:
        with self._lock:
            lifecycle_jobs = getattr(self, "pcap_export_jobs", {})
            if any(
                job_id
                in set(
                    export.get("provenance_job_ids")
                    or [export.get("job_id"), export.get("source_job_id")]
                )
                and export.get("status") in {"QUEUED", "RUNNING"}
                for export in lifecycle_jobs.values()
            ):
                return False
            if any(
                run.get("analysis_job_id") == job_id
                and run.get("status") not in _AI_TERMINAL_STATUSES
                for run in self.ai_runs.values()
            ):
                return False
            job = self.jobs.pop(job_id, None)
            if job is None:
                return False
            run_ids = {
                run_id
                for run_id, run in self.ai_runs.items()
                if run.get("analysis_job_id") == job_id
            }
            assessment_ids = {
                assessment_id
                for assessment_id, assessment in self.ai_assessments.items()
                if assessment.get("ai_run_id") in run_ids
            }
            for feedback_id in [
                feedback_id
                for feedback_id, feedback in self.ai_feedback.items()
                if feedback.get("assessment_id") in assessment_ids
            ]:
                self.ai_feedback.pop(feedback_id, None)
            for artifact_id in [
                artifact_id
                for artifact_id, artifact in self.ai_artifacts.items()
                if artifact.get("assessment_id") in assessment_ids
            ]:
                self.ai_artifacts.pop(artifact_id, None)
            for assessment_id in assessment_ids:
                self.ai_assessments.pop(assessment_id, None)
            for run_id in run_ids:
                self.ai_runs.pop(run_id, None)
            for key, run_id in list(self.ai_run_idempotency_keys.items()):
                if run_id in run_ids:
                    self.ai_run_idempotency_keys.pop(key, None)
            if job.get("idempotency_key") is not None:
                self.idempotency_keys.pop(str(job["idempotency_key"]), None)
            self.candidates.pop(job_id, None)
            self.job_captures.pop(job_id, None)
            self.capture_source_versions.pop(job_id, None)
            self._delete_posting_indexes_for_source("PCAP_UPLOAD", job_id)
            self.delete_structural_indexes_for_source(job_id)
            export_ids = [
                export_id
                for export_id, metadata in self.exports.items()
                if metadata.get("job_id") == job_id
            ]
            for export_id in export_ids:
                self.exports.pop(export_id, None)
                self.export_content.pop(export_id, None)
            for export_id in [
                export_id
                for export_id, export in lifecycle_jobs.items()
                if export.get("job_id") == job_id
            ]:
                lifecycle_jobs.pop(export_id, None)
            live_segment_ids = [
                segment_id
                for segment_id, segment in self.sensor_pcaps.items()
                if segment.get("analysis_job_id") == job_id
            ]
            for segment_id in live_segment_ids:
                self.sensor_pcaps.pop(segment_id, None)
                self.sensor_pcap_content.pop(segment_id, None)
                self.live_segment_index_tasks.pop(segment_id, None)
                self.capture_source_versions.pop(f"LIVE_SEGMENT:{segment_id}", None)
                self._delete_posting_indexes_for_source("LIVE_SEGMENT", segment_id)
                self.delete_structural_indexes_for_source(segment_id, source_kind="LIVE_SEGMENT")
            return True

    def delete_retained_source(self, job_id: str) -> bool:
        """Retention seam: metadata/index deletion shares the canonical job transaction."""
        return self.delete_job(job_id)

    def save_job_capture(self, job_id: str, content: bytes) -> None:
        with self._lock:
            snapshot = bytes(content)
            digest = hashlib.sha256(snapshot).hexdigest()
            self.job_captures[job_id] = snapshot
            self.capture_source_versions[job_id] = CaptureSourceVersion(
                "PCAP_UPLOAD",
                job_id,
                f"captures/{job_id}.pcap",
                f"sha256:{digest}",
                len(snapshot),
                digest,
            )

    def get_capture_source_version(self, job_id: str) -> CaptureSourceVersion | None:
        with self._lock:
            return self.capture_source_versions.get(job_id)

    def read_capture_range(
        self, source: CaptureSourceVersion, byte_range: CaptureByteRange
    ) -> bytes:
        byte_range.validate_for_source(source)
        key = (
            source.source_id
            if source.source_kind == "PCAP_UPLOAD"
            else f"LIVE_SEGMENT:{source.source_id}"
        )
        with self._lock:
            current = self.capture_source_versions.get(key)
            if current is None:
                raise CaptureRangeMissing("capture source row is missing")
            if current != source:
                raise CaptureRangeVersionDrift("capture source version changed")
            content = (
                self.job_captures.get(source.source_id)
                if source.source_kind == "PCAP_UPLOAD"
                else self.sensor_pcap_content.get(source.source_id)
            )
            if content is None:
                raise CaptureRangeMissing("capture object is missing")
            start = byte_range.offset
            result = bytes(content[start : start + byte_range.length])
        with self._lock:
            current = self.capture_source_versions.get(key)
            if current is None:
                raise CaptureRangeMissing("capture source disappeared during range read")
            if current != source:
                raise CaptureRangeVersionDrift("capture source changed during range read")
        if len(result) != byte_range.length:
            raise CaptureRangeShortRead("capture range returned fewer bytes than requested")
        return result

    def open_job_capture(self, job_id: str) -> CaptureSource | None:
        with self._lock:
            content = self.job_captures.get(job_id)
            return _bytes_source(content) if content is not None else None

    def get_job_capture(self, job_id: str) -> bytes | None:
        source = self.open_job_capture(job_id)
        if source is None:
            return None
        with source:
            return b"".join(source.iter_chunks())

    def begin_structural_index(
        self, build_id: str, binding: SourceIndexBinding, created_at: datetime
    ) -> None:
        with self._lock:
            if build_id in self.structural_index_staging:
                raise ValueError("structural index build already exists")
            self.structural_index_staging[build_id] = (binding, created_at, [])

    def stage_structural_index_packets(
        self, build_id: str, packets: tuple[StructuralPacketEntry, ...]
    ) -> None:
        with self._lock:
            binding, created_at, stored = self.structural_index_staging[build_id]
            if packets and packets[0].packet_index != len(stored):
                raise ValueError("structural packet rows are not contiguous")
            stored.extend(packets)
            self.structural_index_staging[build_id] = (binding, created_at, stored)

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
    ) -> bool:
        with self._lock:
            staged = self.structural_index_staging.get(build_id)
            source_version = self.capture_source_versions.get(binding.source_id)
            expected_version = CaptureSourceVersion(
                binding.source_kind,
                binding.source_id,
                source_version.object_key if source_version is not None else "",
                binding.source_version_id,
                binding.source_size_bytes,
                binding.source_sha256,
            )
            if (
                staged is None
                or staged[0] != binding
                or len(staged[2]) != packet_count
                or not _job_matches_structural_binding(self.jobs.get(binding.source_id), binding)
                or source_version != expected_version
            ):
                return False
            snapshot = StructuralIndexSnapshot(
                build_id,
                binding,
                staged[1],
                structural_index_digest(binding, interfaces, staged[2]),
                interfaces,
                tuple(staged[2]),
            )
            if not validate_structural_index(snapshot):
                return False
            owner_key = (binding.source_kind, binding.source_id)
            previous = self.structural_index_owners.get(owner_key)
            if (
                previous is not None
                and previous != build_id
                and any(
                    task.spec.source_kind == binding.source_kind
                    and task.spec.source_id == binding.source_id
                    and task.spec.parent_structural_build_id == previous
                    and task.status
                    in {
                        PostingIndexTaskStatus.QUEUED,
                        PostingIndexTaskStatus.RUNNING,
                    }
                    for task in self.posting_index_tasks.values()
                )
            ):
                return False
            posting_intent = None
            if request_postings:
                spec = replace(
                    PostingIndexTaskSpec.from_binding(expected_version, snapshot),
                    posting_schema_version=posting_schema_version,
                    posting_parser_contract_version=posting_parser_contract_version,
                    filter_contract_version=filter_contract_version,
                )
                current = self.posting_index_intents.get(owner_key)
                if current is None or current.spec.identity != spec.identity:
                    requested_at = self._posting_now()
                    posting_intent = PostingIndexIntent(
                        spec,
                        PostingIndexIntentStatus.PENDING,
                        requested_at,
                        requested_at,
                    )
            if previous is not None and previous != build_id:
                lifecycle = (
                    self.posting_index_tasks.copy(),
                    self.posting_index_intents.copy(),
                    self.posting_index_staging.copy(),
                    self.posting_index_generations.copy(),
                    self.posting_index_owners.copy(),
                )
                try:
                    self._delete_posting_indexes_for_source(
                        binding.source_kind,
                        binding.source_id,
                        parent_structural_build_id=previous,
                    )
                    if posting_intent is not None:
                        self.posting_index_intents[owner_key] = posting_intent
                except Exception:
                    (
                        self.posting_index_tasks,
                        self.posting_index_intents,
                        self.posting_index_staging,
                        self.posting_index_generations,
                        self.posting_index_owners,
                    ) = lifecycle
                    raise
            elif posting_intent is not None:
                # Install the marker before publishing READY ownership. A failing
                # mapping backend must leave the still-STAGING build untouched.
                self.posting_index_intents[owner_key] = posting_intent
            self.structural_index_generations[build_id] = snapshot
            self.structural_index_owners[owner_key] = build_id
            self.structural_index_staging.pop(build_id, None)
            if previous is not None and previous != build_id:
                self.structural_index_generations.pop(previous, None)
            return True

    def _delete_posting_indexes_for_source(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        parent_structural_build_id: str | None = None,
    ) -> None:
        """Delete one source's posting lifecycle while the repository lock is held."""
        with self._lock:

            def matches_parent(candidate: str) -> bool:
                return parent_structural_build_id is None or candidate == parent_structural_build_id

            key = (source_kind, source_id)
            task = self.posting_index_tasks.get(key)
            if task is not None and matches_parent(task.spec.parent_structural_build_id):
                self.posting_index_tasks.pop(key, None)
            intent = self.posting_index_intents.get(key)
            if intent is not None and matches_parent(intent.spec.parent_structural_build_id):
                self.posting_index_intents.pop(key, None)
            for build_id, staged in list(self.posting_index_staging.items()):
                binding = staged[0].binding
                if (
                    binding.source_kind == source_kind
                    and binding.source_id == source_id
                    and matches_parent(binding.parent_structural_build_id)
                ):
                    self.posting_index_staging.pop(build_id, None)
            for owner_key, owner_id in list(self.posting_index_owners.items()):
                if owner_key[:2] == key and matches_parent(owner_key[2]):
                    self.posting_index_owners.pop(owner_key, None)
                    self.posting_index_generations.pop(owner_id, None)
            for build_id, generation in list(self.posting_index_generations.items()):
                binding = generation.binding
                if (
                    binding.source_kind == source_kind
                    and binding.source_id == source_id
                    and matches_parent(binding.parent_structural_build_id)
                ):
                    self.posting_index_generations.pop(build_id, None)

    def abort_structural_index(self, build_id: str) -> None:
        with self._lock:
            self.structural_index_staging.pop(build_id, None)

    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup:
        with self._lock:
            owner_key: object = (binding.source_kind, binding.source_id)
            build_id = self.structural_index_owners.get(owner_key)
            if build_id is None:
                return StructuralIndexLookup(IndexAvailability.MISSING)
            snapshot = self.structural_index_generations.get(build_id)
            if snapshot is None:
                return StructuralIndexLookup(IndexAvailability.CORRUPT)
            if (
                snapshot.binding.schema_version != binding.schema_version
                or snapshot.binding.parser_contract_version != binding.parser_contract_version
            ):
                return StructuralIndexLookup(IndexAvailability.UNSUPPORTED_SCHEMA)
            if snapshot.binding != binding:
                return StructuralIndexLookup(IndexAvailability.STALE)
            if binding.source_kind == "LIVE_SEGMENT":
                segment = self.sensor_pcaps.get(binding.source_id)
                object_key = (
                    str(segment.get("object_key"))
                    if segment and segment.get("object_key")
                    else f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
                    if segment
                    else ""
                )
                source_key = f"LIVE_SEGMENT:{binding.source_id}"
                canonical_matches = _live_segment_matches_structural_binding(self, binding)
            else:
                source_key = binding.source_id
                stored_source = self.capture_source_versions.get(source_key)
                object_key = stored_source.object_key if stored_source is not None else ""
                canonical_matches = _job_matches_structural_binding(
                    self.jobs.get(binding.source_id), binding
                )
            expected_version = CaptureSourceVersion(
                binding.source_kind,
                binding.source_id,
                object_key,
                binding.source_version_id,
                binding.source_size_bytes,
                binding.source_sha256,
            )
            if (
                not canonical_matches
                or self.capture_source_versions.get(source_key) != expected_version
            ):
                return StructuralIndexLookup(IndexAvailability.STALE)
            if not validate_structural_index(snapshot):
                return StructuralIndexLookup(IndexAvailability.CORRUPT)
            return StructuralIndexLookup(IndexAvailability.READY, deepcopy(snapshot))

    def get_structural_index_identity(
        self, source: CaptureSourceVersion
    ) -> StructuralIndexIdentityLookup:
        with self._lock:
            build_id = self.structural_index_owners.get((source.source_kind, source.source_id))
            if build_id is None:
                return StructuralIndexIdentityLookup(IndexAvailability.MISSING)
            snapshot = self.structural_index_generations.get(build_id)
            if snapshot is None or snapshot.build_id != build_id:
                return StructuralIndexIdentityLookup(IndexAvailability.CORRUPT)
            identity = structural_index_identity(snapshot)
            availability = structural_index_identity_availability(identity, source)
            if availability is IndexAvailability.READY:
                binding = identity.binding
                if binding.source_kind == "LIVE_SEGMENT":
                    segment = self.sensor_pcaps.get(binding.source_id)
                    object_key = (
                        str(segment.get("object_key"))
                        if segment and segment.get("object_key")
                        else f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
                        if segment
                        else ""
                    )
                    source_key = f"LIVE_SEGMENT:{binding.source_id}"
                    canonical_matches = _live_segment_matches_structural_binding(self, binding)
                else:
                    source_key = binding.source_id
                    stored_source = self.capture_source_versions.get(source_key)
                    object_key = stored_source.object_key if stored_source is not None else ""
                    canonical_matches = _job_matches_structural_binding(
                        self.jobs.get(binding.source_id), binding
                    )
                expected_version = CaptureSourceVersion(
                    binding.source_kind,
                    binding.source_id,
                    object_key,
                    binding.source_version_id,
                    binding.source_size_bytes,
                    binding.source_sha256,
                )
                if (
                    not canonical_matches
                    or self.capture_source_versions.get(source_key) != expected_version
                ):
                    availability = IndexAvailability.STALE
            return StructuralIndexIdentityLookup(
                availability,
                identity if availability is IndexAvailability.READY else None,
            )

    def delete_structural_indexes_for_source(
        self, source_id: str, *, source_kind: str = "PCAP_UPLOAD"
    ) -> None:
        with self._lock:
            if is_posting_source_kind(source_kind):
                self._delete_posting_indexes_for_source(source_kind, source_id)
            self.structural_index_owners.pop((source_kind, source_id), None)
            for build_id, snapshot in list(self.structural_index_generations.items()):
                if (
                    snapshot.binding.source_kind == source_kind
                    and snapshot.binding.source_id == source_id
                ):
                    self.structural_index_generations.pop(build_id, None)
            for build_id, (structural_binding, _created_at, _packets) in list(
                self.structural_index_staging.items()
            ):
                if (
                    structural_binding.source_kind == source_kind
                    and structural_binding.source_id == source_id
                ):
                    self.structural_index_staging.pop(build_id, None)

    def cleanup_stale_structural_indexes(self, *, before: datetime, limit: int) -> int:
        with self._lock:
            selected = sorted(
                (
                    (created_at, build_id)
                    for build_id, (
                        _binding,
                        created_at,
                        _packets,
                    ) in self.structural_index_staging.items()
                    if created_at <= before
                )
            )[:limit]
            for _created_at, build_id in selected:
                self.structural_index_staging.pop(build_id, None)
            return len(selected)

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock:
            self.candidates[job_id] = deepcopy(candidates)

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        return deepcopy(self.candidates.get(job_id, []))

    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None:
        for job_id, candidates in self.candidates.items():
            candidate = next((item for item in candidates if item.get("id") == candidate_id), None)
            if candidate is not None:
                return job_id, deepcopy(candidate)
        return None

    def query_candidates(
        self,
        *,
        minimum_score: int = 0,
        severity: str | None = None,
        include_suppressed: bool = False,
    ) -> list[tuple[str, dict[str, Any]]]:
        return [
            (job_id, deepcopy(candidate))
            for job_id, candidates in self.candidates.items()
            for candidate in candidates
            if int(candidate.get("score", 0)) >= minimum_score
            and (severity is None or candidate.get("severity") == severity)
            and (include_suppressed or not candidate.get("excluded", False))
        ]

    def query_candidate_page(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
        sort: str,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[str, dict[str, Any]]], int]:
        rows = self.query_candidates(
            minimum_score=minimum_score,
            severity=severity,
            include_suppressed=include_suppressed,
        )
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field == "score":
            rows.sort(
                key=lambda row: (float(row[1].get(field, 0) or 0), str(row[1]["id"])),
                reverse=descending,
            )
        else:
            rows.sort(
                key=lambda row: (str(row[1].get(field, "")), str(row[1]["id"])), reverse=descending
            )
        start = (page - 1) * page_size
        return rows[start : start + page_size], len(rows)

    def query_candidate_refs(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> list[tuple[str, bool]]:
        return [
            (str(candidate["id"]), bool(candidate.get("excluded", False)))
            for _, candidate in self.query_candidates(
                minimum_score=minimum_score,
                severity=severity,
                include_suppressed=include_suppressed,
            )
        ]

    def candidate_workflow_counts(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> dict[str, int]:
        candidate_ids = [
            str(candidate["id"])
            for candidates in self.candidates.values()
            for candidate in candidates
            if int(candidate.get("score", 0)) >= minimum_score
            and (severity is None or candidate.get("severity") == severity)
            and (include_suppressed or not candidate.get("excluded", False))
        ]
        return _candidate_workflow_counts_from_records(
            candidate_ids,
            list(self.candidate_decisions.values()),
            list(self.candidate_actions.values()),
        )

    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        key = (run["analysis_job_id"], run["idempotency_key"])
        with self._lock:
            existing_id = self.ai_run_idempotency_keys.get(key)
            if existing_id is not None:
                return deepcopy(self.ai_runs[existing_id]), False
            self.ai_runs[run["id"]] = deepcopy(run)
            self.ai_run_idempotency_keys[key] = run["id"]
            return deepcopy(run), True

    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            existing = self.ai_runs.get(run["id"])
            if existing is not None and existing.get("status") in {
                "COMPLETED",
                "FAILED",
                "CANCELLED",
            }:
                return deepcopy(existing)
            self.ai_runs[run["id"]] = deepcopy(run)
            return deepcopy(run)

    def get_ai_run(self, run_id: str) -> dict[str, Any] | None:
        value = self.ai_runs.get(run_id)
        return deepcopy(value) if value is not None else None

    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (run for run in self.ai_runs.values() if run["analysis_job_id"] == job_id),
                key=lambda run: run["created_at"],
                reverse=True,
            )
        )

    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ai_assessments.setdefault(assessment["id"], deepcopy(assessment))
            return deepcopy(self.ai_assessments[assessment["id"]])

    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        value = self.ai_assessments.get(assessment_id)
        return deepcopy(value) if value is not None else None

    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    assessment
                    for assessment in self.ai_assessments.values()
                    if assessment["ai_run_id"] == run_id
                ),
                key=lambda assessment: assessment["created_at"],
            )
        )

    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ai_artifacts[artifact["id"]] = deepcopy(artifact)
            return deepcopy(artifact)

    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        value = self.ai_artifacts.get(artifact_id)
        return deepcopy(value) if value is not None else None

    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    artifact
                    for artifact in self.ai_artifacts.values()
                    if artifact["assessment_id"] == assessment_id
                ),
                key=lambda artifact: (artifact["created_at"], artifact["artifact_type"]),
            )
        )

    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.ai_feedback.setdefault(feedback["id"], deepcopy(feedback))
            return deepcopy(self.ai_feedback[feedback["id"]])

    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    feedback
                    for feedback in self.ai_feedback.values()
                    if feedback["assessment_id"] == assessment_id
                ),
                key=lambda feedback: feedback["created_at"],
            )
        )

    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.audit_events.append(
                {
                    "kind": kind,
                    "object_id": object_id,
                    "occurred_at": datetime.now().astimezone().isoformat(),
                    "data": deepcopy(data),
                }
            )

    def update_candidate(self, candidate_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a candidate and return it, or None if not found."""
        with self._lock:
            for job_id, candidates in self.candidates.items():
                for i, candidate in enumerate(candidates):
                    if candidate.get("id") == candidate_id:
                        # Create updated candidate
                        updated = deepcopy(candidate)
                        updates_copy = deepcopy(updates)

                        if "score_adjustment" in updates_copy:
                            old_score = updated.get("score", 0)
                            adj = updates_copy.pop("score_adjustment")
                            updated["score"] = max(0, min(100, old_score + adj))

                        if "exclude_reason" in updates_copy:
                            updated["excluded"] = True
                            updated["exclude_reason"] = updates_copy.pop("exclude_reason")

                        # Apply any other direct field updates
                        for key, value in updates_copy.items():
                            if isinstance(updated.get(key), list) and isinstance(value, list):
                                updated[key] = value
                            elif isinstance(updated.get(key), dict) and isinstance(value, dict):
                                updated[key].update(value)
                            else:
                                updated[key] = deepcopy(value)

                        # Update timestamp
                        from datetime import UTC

                        updated["updated_at"] = datetime.now(UTC).isoformat()

                        self.candidates[job_id][i] = updated
                        return deepcopy(updated)
        return None

    def delete_candidate(self, candidate_id: str) -> bool:
        """Delete a candidate by ID. Returns True if deleted."""
        with self._lock:
            for job_id, candidates in list(self.candidates.items()):
                original_len = len(candidates)
                self.candidates[job_id] = [c for c in candidates if c.get("id") != candidate_id]
                if len(self.candidates[job_id]) < original_len:
                    return True
            return False

    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]:
        return deepcopy(self.candidates)

    def get_integration_settings(self) -> dict[str, Any] | None:
        with self._lock:
            return deepcopy(self.integration_settings)

    def save_integration_settings(
        self, settings: dict[str, Any], expected_version: int
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            current_version = int((self.integration_settings or {}).get("version", 0))
            if current_version != expected_version:
                return deepcopy(self.integration_settings), "CONFLICT"
            self.integration_settings = deepcopy(settings)
            return deepcopy(settings), "OK"

    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_decisions[decision["id"]] = deepcopy(decision)
            return deepcopy(decision)

    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self.candidate_decisions.values()
        selected = [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]
        return sorted(deepcopy(selected), key=lambda item: str(item["created_at"]))

    def save_candidate_action(self, action: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_actions[action["id"]] = deepcopy(action)
            return deepcopy(action)

    def list_candidate_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self.candidate_actions.values()
        selected = [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]
        return sorted(deepcopy(selected), key=lambda item: str(item["created_at"]))

    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_ti_lookups[lookup["id"]] = deepcopy(lookup)
            return deepcopy(lookup)

    def list_candidate_ti_lookups(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            selected = [
                deepcopy(item)
                for item in self.candidate_ti_lookups.values()
                if candidate_id is None or item["candidate_id"] == candidate_id
            ]
        return sorted(deepcopy(selected), key=lambda item: str(item["fetched_at"]))

    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.candidate_misp_actions[action["id"]] = deepcopy(action)
            return deepcopy(action)

    def claim_candidate_misp_action(self, action: dict[str, Any]) -> bool:
        with self._lock:
            if action["id"] in self.candidate_misp_actions:
                return False
            self.candidate_misp_actions[action["id"]] = deepcopy(action)
            return True

    def list_candidate_misp_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self.candidate_misp_actions.values()
        selected = [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]
        return sorted(deepcopy(selected), key=lambda item: str(item["created_at"]))

    def list_candidate_workflow_records(
        self, candidate_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        selected = set(candidate_ids)
        return {
            "decisions": [
                deepcopy(item)
                for item in self.candidate_decisions.values()
                if item.get("candidate_id") in selected
            ],
            "actions": [
                deepcopy(item)
                for item in self.candidate_actions.values()
                if item.get("candidate_id") in selected
            ],
            "lookups": [
                deepcopy(item)
                for item in self.candidate_ti_lookups.values()
                if item.get("candidate_id") in selected
            ],
            "misp_actions": [
                deepcopy(item)
                for item in self.candidate_misp_actions.values()
                if item.get("candidate_id") in selected
            ],
        }

    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.flow_labels[label["id"]] = deepcopy(label)
            return deepcopy(label)

    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]:
        labels = list(self.flow_labels.values())
        if job_id is not None:
            labels = [label for label in labels if label.get("job_id") == job_id]
        return sorted(deepcopy(labels), key=lambda item: str(item["created_at"]))

    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.payload_signatures[signature["id"]] = deepcopy(signature)
            return deepcopy(signature)

    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None:
        value = self.payload_signatures.get(signature_id)
        return deepcopy(value) if value else None

    def list_payload_signatures(self) -> list[dict[str, Any]]:
        return sorted(
            deepcopy(list(self.payload_signatures.values())),
            key=lambda item: str(item["created_at"]),
        )

    def delete_payload_signature(self, signature_id: str) -> bool:
        with self._lock:
            return self.payload_signatures.pop(signature_id, None) is not None

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.allowlist[entry["id"]] = deepcopy(entry)
            return deepcopy(entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.allowlist.values()))

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock:
            return self.allowlist.pop(entry_id, None) is not None

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any] | None:
        return self.save_export_stream(export, iter((content,)), size_hint=len(content))

    def save_export_stream(
        self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
    ) -> dict[str, Any] | None:
        private_chunks, result = _consume_artifact_chunks(chunks, size_hint=size_hint)
        stored = {
            **deepcopy(export),
            "size_bytes": result.size_bytes,
            "sha256": result.sha256,
        }
        with self._lock:
            if str(export["job_id"]) not in self.jobs:
                return None
            if str(export["id"]) in self.exports:
                raise ArtifactAlreadyExistsError(f"export already exists: {export['id']}")
            self.exports[str(export["id"])] = stored
            self.export_content[str(export["id"])] = b"".join(private_chunks)
            return deepcopy(stored)

    def get_export_metadata(self, export_id: str) -> dict[str, Any] | None:
        with self._lock:
            metadata = self.exports.get(export_id)
            if metadata is not None and metadata.get("published") is False:
                return None
            return deepcopy(metadata) if metadata is not None else None

    def open_export_stream(
        self, export_id: str
    ) -> tuple[dict[str, Any], AbstractContextManager[Iterator[bytes]]] | None:
        with self._lock:
            metadata = self.exports.get(export_id)
            content = self.export_content.get(export_id)
            if metadata is not None and metadata.get("published") is False:
                return None
            if metadata is None:
                return None
            if content is None:
                raise ArtifactMissingError(f"artifact content is missing: {export_id}")
            snapshot = bytes(content)

        @contextmanager
        def opened() -> Iterator[Iterator[bytes]]:
            def iterator() -> Iterator[bytes]:
                for offset in range(0, len(snapshot), _DEFAULT_ARTIFACT_CHUNK_SIZE):
                    yield snapshot[offset : offset + _DEFAULT_ARTIFACT_CHUNK_SIZE]

            yield iterator()

        return deepcopy(metadata), opened()

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        opened = self.open_export_stream(export_id)
        if opened is None:
            return None
        metadata, stream = opened
        with stream as chunks:
            return metadata, b"".join(chunks)

    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]:
        stored, status = self.save_sensor_pcap_limited(segment, content, None)
        if stored is None or status not in {"OK", "EXISTS"}:
            raise RuntimeError(f"sensor PCAP save failed: {status}")
        return stored

    def save_sensor_pcap_limited(
        self,
        segment: dict[str, Any],
        content: bytes,
        max_total_bytes: int | None,
        *,
        require_open_job: bool = False,
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            analysis_job_id = segment.get("analysis_job_id")
            job = self.jobs.get(str(analysis_job_id)) if analysis_job_id is not None else None
            if require_open_job and analysis_job_id is not None:
                if job is None or job.get("status") in _JOB_TERMINAL_STATUSES:
                    return None, "JOB_CLOSED"
            existing = self.sensor_pcaps.get(segment["id"])
            if existing is not None:
                matches = all(
                    existing.get(field) == segment.get(field)
                    for field in ("sensor_id", "analysis_job_id", "sha256")
                )
                return (deepcopy(existing), "EXISTS") if matches else (None, "CONFLICT")
            if max_total_bytes is not None and analysis_job_id is not None:
                used = sum(
                    int(item.get("size_bytes", 0) or 0)
                    for item in self.sensor_pcaps.values()
                    if item.get("analysis_job_id") == analysis_job_id
                )
                if used + len(content) > max_total_bytes:
                    return None, "LIMIT"
            stored = deepcopy(segment)
            if eligible_live_segment(job, stored):
                stored["index_requested_at"] = datetime.now().astimezone().isoformat()
                stored["index_intent_state"] = "PENDING"
                stored["index_intent_schema_version"] = PCAP_OFFSET_INDEX_SCHEMA_VERSION
                stored["index_intent_parser_contract_version"] = (
                    PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION
                )
            self.sensor_pcaps[segment["id"]] = stored
            self.sensor_pcap_content[segment["id"]] = bytes(content)
            return deepcopy(stored), "OK"

    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None:
        opened = self.open_sensor_pcap(segment_id)
        if opened is None:
            return None
        metadata, source = opened
        with source:
            return metadata, b"".join(source.iter_chunks())

    def open_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], CaptureSource] | None:
        with self._lock:
            metadata = self.sensor_pcaps.get(segment_id)
            content = self.sensor_pcap_content.get(segment_id)
            if metadata is None or content is None:
                return None
            return deepcopy(metadata), _bytes_source(content)

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.sensor_pcaps.values()))

    def list_sensor_pcaps_for_job(self, job_id: str) -> list[dict[str, Any]]:
        return deepcopy(
            sorted(
                (
                    segment
                    for segment in self.sensor_pcaps.values()
                    if segment.get("analysis_job_id") == job_id
                ),
                key=lambda segment: (
                    str(segment.get("uploaded_at", "")),
                    str(segment.get("id", "")),
                ),
            )
        )

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.enrollments[enrollment["enrollment_id"]] = deepcopy(enrollment)
            return deepcopy(enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        value = self.enrollments.get(enrollment_id)
        return deepcopy(value) if value else None

    def list_enrollments(self) -> list[dict[str, Any]]:
        return deepcopy(list(self.enrollments.values()))

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            enrollment = next(
                (item for item in self.enrollments.values() if item["token_hash"] == token_hash),
                None,
            )
            if enrollment is None:
                return None, "NOT_FOUND"
            if enrollment.get("revoked_at") is not None:
                return deepcopy(enrollment), "REVOKED"
            if enrollment.get("claimed_at") is not None:
                return deepcopy(enrollment), "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                return deepcopy(enrollment), "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            return deepcopy(enrollment), "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.sensor_credentials[credential["sensor_id"]] = deepcopy(credential)
            return deepcopy(credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        value = self.sensor_credentials.get(sensor_id)
        return deepcopy(value) if value else None

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            sensor = self.sensors.get(sensor_id)
            if sensor is None:
                return None, "NOT_FOUND"
            if sensor.get("config_version") != expected_version:
                return deepcopy(sensor), "CONFLICT"
            sensor.update(deepcopy(configuration))
            sensor["config_version"] = expected_version + 1
            return deepcopy(sensor), "OK"

    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None:
        with self._lock:
            sensor = self.sensors.get(sensor_id)
            if sensor is None:
                return None
            sensor.update(deepcopy(fields))
            return deepcopy(sensor)

    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            if preset.get("is_default"):
                for item in self.detector_weight_presets.values():
                    item["is_default"] = False
            self.detector_weight_presets[preset["id"]] = deepcopy(preset)
            return deepcopy(preset)

    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        with self._lock:
            preset = self.detector_weight_presets.get(preset_id)
            return deepcopy(preset) if preset is not None else None

    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None:
        with self._lock:
            preset = self.detector_weight_presets.get(preset_id)
            if preset is None:
                return None
            preset.update(deepcopy(updates))
            if set_as_default:
                for item in self.detector_weight_presets.values():
                    item["is_default"] = item["id"] == preset_id
            return deepcopy(preset)

    def list_detector_weight_presets(self) -> list[dict[str, Any]]:
        with self._lock:
            return deepcopy(list(self.detector_weight_presets.values()))

    def delete_detector_weight_preset(self, preset_id: str) -> bool:
        with self._lock:
            return self.detector_weight_presets.pop(preset_id, None) is not None

    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        with self._lock:
            selected = self.detector_weight_presets.get(preset_id)
            if selected is None:
                return None
            for preset in self.detector_weight_presets.values():
                preset["is_default"] = preset["id"] == preset_id
            return deepcopy(selected)


class SQLiteRepository(
    PostingIndexQueueRepositoryMixin, PostingIndexRepositoryMixin, LiveIndexQueueRepositoryMixin
):
    """외부 서비스 없이 계약 테스트 가능한 SQLite adapter. 같은 경계로 PostgreSQL 교체 가능."""

    def __init__(
        self,
        path: str | Path,
        *,
        _lease_clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._path = str(path)
        self._lease_clock = _lease_clock or (lambda: datetime.now(UTC))
        self.connection = sqlite3.connect(self._path, check_same_thread=False)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self._lock = threading.RLock()
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS objects (
              kind TEXT NOT NULL, id TEXT NOT NULL, data TEXT NOT NULL,
              PRIMARY KEY(kind, id)
            );
            CREATE TABLE IF NOT EXISTS idempotency (
              key TEXT PRIMARY KEY, job_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidates (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS candidate_records (
              candidate_id TEXT PRIMARY KEY,
              job_id TEXT NOT NULL,
              position INTEGER NOT NULL,
              score INTEGER NOT NULL DEFAULT 0,
              severity TEXT NOT NULL DEFAULT '',
              excluded INTEGER NOT NULL DEFAULT 0,
              data TEXT NOT NULL,
              UNIQUE(job_id,position)
            );
            CREATE INDEX IF NOT EXISTS candidate_records_job_position
              ON candidate_records(job_id,position);
            CREATE TABLE IF NOT EXISTS ai_analysis_runs (
              run_id TEXT PRIMARY KEY,
              analysis_job_id TEXT NOT NULL,
              idempotency_key TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL,
              UNIQUE(analysis_job_id, idempotency_key)
            );
            CREATE INDEX IF NOT EXISTS ai_analysis_runs_job_created
              ON ai_analysis_runs(analysis_job_id, created_at DESC);
            CREATE TABLE IF NOT EXISTS ai_candidate_assessments (
              assessment_id TEXT PRIMARY KEY,
              ai_run_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ai_candidate_assessments_run_created
              ON ai_candidate_assessments(ai_run_id, created_at);
            CREATE TABLE IF NOT EXISTS ai_generated_artifacts (
              artifact_id TEXT PRIMARY KEY,
              assessment_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ai_generated_artifacts_assessment_created
              ON ai_generated_artifacts(assessment_id, created_at);
            CREATE TABLE IF NOT EXISTS ai_feedback (
              feedback_id TEXT PRIMARY KEY,
              assessment_id TEXT NOT NULL,
              created_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ai_feedback_assessment_created
              ON ai_feedback(assessment_id, created_at);
            CREATE TABLE IF NOT EXISTS audit_events (
              sequence INTEGER PRIMARY KEY AUTOINCREMENT,
              kind TEXT NOT NULL,
              object_id TEXT NOT NULL,
              occurred_at TEXT NOT NULL,
              data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_flow_records (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_payload_signatures (
              job_id TEXT PRIMARY KEY, data TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_capture_blobs (
              job_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pcap_capture_source_versions (
              source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              object_key TEXT NOT NULL,
              source_version_id TEXT NOT NULL,
              source_size_bytes INTEGER NOT NULL CHECK(source_size_bytes>=0),
              source_sha256 TEXT NOT NULL,
              PRIMARY KEY(source_kind,source_id)
            );
            CREATE TABLE IF NOT EXISTS export_blobs (
              export_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pcap_export_jobs (
              export_id TEXT PRIMARY KEY,
              principal_scope TEXT NOT NULL,
              idempotency_key TEXT,
              request_fingerprint TEXT NOT NULL,
              coalesce_fingerprint TEXT NOT NULL,
              status TEXT NOT NULL,
              next_attempt_at TEXT,
              queued_at TEXT NOT NULL,
              lease_expires_at TEXT,
              data TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS pcap_export_jobs_principal_idempotency
              ON pcap_export_jobs(principal_scope,idempotency_key)
              WHERE idempotency_key IS NOT NULL;
            CREATE INDEX IF NOT EXISTS pcap_export_jobs_claim
              ON pcap_export_jobs(status,next_attempt_at,queued_at);
            CREATE INDEX IF NOT EXISTS pcap_export_jobs_lease
              ON pcap_export_jobs(status,lease_expires_at);
            CREATE INDEX IF NOT EXISTS pcap_export_jobs_parent
              ON pcap_export_jobs(json_extract(data,'$.job_id'),status);
            CREATE TABLE IF NOT EXISTS sensor_pcap_blobs (
              segment_id TEXT PRIMARY KEY, content BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pcap_offset_index_jobs (
              source_kind TEXT NOT NULL CHECK(source_kind='LIVE_SEGMENT'),
              source_id TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
              next_attempt_at TEXT NOT NULL,
              queued_at TEXT NOT NULL,
              data TEXT NOT NULL,
              PRIMARY KEY(source_kind,source_id)
            );
            CREATE INDEX IF NOT EXISTS pcap_offset_index_jobs_claim
              ON pcap_offset_index_jobs(status,next_attempt_at,queued_at,source_id);
            CREATE TABLE IF NOT EXISTS pcap_offset_index_generations (
              build_id TEXT PRIMARY KEY,
              source_kind TEXT NOT NULL DEFAULT 'PCAP_UPLOAD'
                CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              state TEXT NOT NULL CHECK(state IN ('STAGING','READY')),
              binding TEXT NOT NULL,
              created_at TEXT NOT NULL,
              packet_count INTEGER,
              interface_count INTEGER,
              index_sha256 TEXT
            );
            CREATE TABLE IF NOT EXISTS pcap_offset_index_interfaces (
              build_id TEXT NOT NULL REFERENCES pcap_offset_index_generations(build_id)
                ON DELETE CASCADE,
              interface_ordinal INTEGER NOT NULL,
              data TEXT NOT NULL,
              PRIMARY KEY(build_id,interface_ordinal)
            );
            CREATE TABLE IF NOT EXISTS pcap_offset_index_packets (
              build_id TEXT NOT NULL REFERENCES pcap_offset_index_generations(build_id)
                ON DELETE CASCADE,
              packet_index INTEGER NOT NULL,
              data TEXT NOT NULL,
              PRIMARY KEY(build_id,packet_index)
            );
            CREATE TABLE IF NOT EXISTS pcap_offset_index_owners (
              source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              build_id TEXT NOT NULL UNIQUE REFERENCES pcap_offset_index_generations(build_id)
                ON DELETE CASCADE,
              PRIMARY KEY(source_kind,source_id)
            );
            CREATE INDEX IF NOT EXISTS pcap_offset_index_packets_lookup
              ON pcap_offset_index_packets(build_id,packet_index);
            CREATE INDEX IF NOT EXISTS pcap_offset_index_generations_staging
              ON pcap_offset_index_generations(state,created_at,build_id);
            CREATE TABLE IF NOT EXISTS pcap_posting_index_intents (
              source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              parent_structural_build_id TEXT NOT NULL
                REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
              status TEXT NOT NULL CHECK(status IN ('PENDING','DEFERRED','COMPLETED','FAILED')),
              requested_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              data TEXT NOT NULL,
              PRIMARY KEY(source_kind,source_id),
              UNIQUE(source_kind,source_id,parent_structural_build_id),
              FOREIGN KEY(source_kind,source_id)
                REFERENCES pcap_capture_source_versions(source_kind,source_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS pcap_posting_index_intents_reconcile
              ON pcap_posting_index_intents(status,requested_at,source_kind,source_id);
            CREATE TABLE IF NOT EXISTS pcap_posting_index_jobs (
              source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              parent_structural_build_id TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
              attempt INTEGER NOT NULL CHECK(attempt>=0),
              lease_token TEXT,
              lease_expires_at TEXT,
              next_attempt_at TEXT NOT NULL,
              queued_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              data TEXT NOT NULL,
              PRIMARY KEY(source_kind,source_id),
              FOREIGN KEY(source_kind,source_id,parent_structural_build_id)
                REFERENCES pcap_posting_index_intents(
                  source_kind,source_id,parent_structural_build_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_claim
              ON pcap_posting_index_jobs(status,next_attempt_at,queued_at,source_kind,source_id);
            CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_lease
              ON pcap_posting_index_jobs(status,lease_expires_at,source_kind,source_id);
            CREATE TABLE IF NOT EXISTS pcap_posting_index_generations (
              build_id TEXT PRIMARY KEY,
              source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              parent_structural_build_id TEXT NOT NULL
                REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
              state TEXT NOT NULL CHECK(state IN ('STAGING','READY')),
              binding TEXT NOT NULL,
              created_at TEXT NOT NULL,
              generation_metadata TEXT NOT NULL,
              builder_attempt INTEGER NOT NULL CHECK(builder_attempt>0),
              lease_token TEXT NOT NULL,
              expected_owner_build_id TEXT,
              UNIQUE(source_kind,source_id,parent_structural_build_id,build_id)
            );
            CREATE TABLE IF NOT EXISTS pcap_posting_index_chunks (
              build_id TEXT NOT NULL REFERENCES pcap_posting_index_generations(build_id)
                ON DELETE CASCADE,
              dimension TEXT NOT NULL CHECK(dimension IN (
                'ALL_PACKET','SUPPORTED','SRC_ADDRESS','DST_ADDRESS',
                'SRC_PORT','DST_PORT','PROTOCOL','HAS_PAYLOAD')),
              canonical_value BLOB NOT NULL,
              chunk_ordinal INTEGER NOT NULL CHECK(chunk_ordinal>=0),
              first_packet_index INTEGER NOT NULL CHECK(first_packet_index>=0),
              last_packet_index INTEGER NOT NULL CHECK(last_packet_index>=first_packet_index),
              membership_count INTEGER NOT NULL CHECK(membership_count>0),
              encoded_ordinals BLOB NOT NULL,
              PRIMARY KEY(build_id,dimension,canonical_value,chunk_ordinal)
            );
            CREATE TABLE IF NOT EXISTS pcap_posting_index_owners (
              source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
              source_id TEXT NOT NULL,
              parent_structural_build_id TEXT NOT NULL
                REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
              build_id TEXT NOT NULL UNIQUE,
              PRIMARY KEY(source_kind,source_id,parent_structural_build_id),
              FOREIGN KEY(source_kind,source_id,parent_structural_build_id,build_id)
                REFERENCES pcap_posting_index_generations(
                  source_kind,source_id,parent_structural_build_id,build_id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS pcap_posting_index_generations_staging
              ON pcap_posting_index_generations(state,created_at,build_id);
            CREATE INDEX IF NOT EXISTS pcap_posting_index_chunks_lookup
              ON pcap_posting_index_chunks(build_id,dimension,canonical_value,chunk_ordinal);
            CREATE INDEX IF NOT EXISTS objects_sensor_pcap_job_uploaded_id
              ON objects(
                json_extract(data, '$.analysis_job_id'),
                json_extract(data, '$.uploaded_at'),
                id
              ) WHERE kind='sensor_pcap';
        """)
        self._migrate_stage10_offset_index_schema()
        self._migrate_stage11_posting_owner_schema()
        candidate_columns = {
            str(row[1]) for row in self.connection.execute("PRAGMA table_info(candidate_records)")
        }
        for column, definition in {
            "score": "INTEGER NOT NULL DEFAULT 0",
            "severity": "TEXT NOT NULL DEFAULT ''",
            "excluded": "INTEGER NOT NULL DEFAULT 0",
        }.items():
            if column not in candidate_columns:
                self.connection.execute(
                    f"ALTER TABLE candidate_records ADD COLUMN {column} {definition}"
                )
        self.connection.execute(
            "UPDATE candidate_records SET "
            "score=CAST(COALESCE(json_extract(data,'$.score'),0) AS INTEGER),"
            "severity=COALESCE(json_extract(data,'$.severity'),''),"
            "excluded=CAST(COALESCE(json_extract(data,'$.excluded'),0) AS INTEGER)"
        )
        self.connection.commit()
        self._migrate_embedded_job_flows()
        self._migrate_embedded_job_signatures()
        self._migrate_legacy_candidates()
        self.connection.commit()

    def _migrate_stage11_posting_owner_schema(self) -> None:
        """Bind each posting owner to one exact source/parent generation identity."""
        owner_row = self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='pcap_posting_index_owners'"
        ).fetchone()
        normalized = "" if owner_row is None else "".join(str(owner_row[0]).split()).lower()
        composite = (
            "foreignkey(source_kind,source_id,parent_structural_build_id,build_id)"
            "referencespcap_posting_index_generations("
            "source_kind,source_id,parent_structural_build_id,build_id)"
        )
        if composite in normalized:
            return
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS pcap_posting_index_generations_identity "
            "ON pcap_posting_index_generations("
            "source_kind,source_id,parent_structural_build_id,build_id)"
        )
        self.connection.commit()
        self.connection.execute("PRAGMA foreign_keys=OFF")
        try:
            self.connection.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE pcap_posting_index_owners_stage11 (
                  source_kind TEXT NOT NULL
                    CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                  source_id TEXT NOT NULL,
                  parent_structural_build_id TEXT NOT NULL
                    REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
                  build_id TEXT NOT NULL UNIQUE,
                  PRIMARY KEY(source_kind,source_id,parent_structural_build_id),
                  FOREIGN KEY(source_kind,source_id,parent_structural_build_id,build_id)
                    REFERENCES pcap_posting_index_generations(
                      source_kind,source_id,parent_structural_build_id,build_id
                    ) ON DELETE CASCADE
                );
                INSERT INTO pcap_posting_index_owners_stage11(
                  source_kind,source_id,parent_structural_build_id,build_id
                ) SELECT source_kind,source_id,parent_structural_build_id,build_id
                  FROM pcap_posting_index_owners;
                DROP TABLE pcap_posting_index_owners;
                ALTER TABLE pcap_posting_index_owners_stage11
                  RENAME TO pcap_posting_index_owners;
                COMMIT;
            """)
        except Exception:
            self.connection.rollback()
            raise
        finally:
            self.connection.execute("PRAGMA foreign_keys=ON")
        violations = self.connection.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise sqlite3.IntegrityError(
                f"Stage11 posting owner migration violated FKs: {violations}"
            )

    def _migrate_stage10_offset_index_schema(self) -> None:
        """Transactionally rebuild deployed Stage9 index tables exactly once."""

        def columns(table: str) -> set[str]:
            return {str(row[1]) for row in self.connection.execute(f"PRAGMA table_info({table})")}

        source_row = self.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='pcap_capture_source_versions'"
        ).fetchone()
        if (
            "source_kind" in columns("pcap_offset_index_owners")
            and "source_kind" in columns("pcap_offset_index_generations")
            and source_row is not None
            and "LIVE_SEGMENT" in str(source_row[0])
        ):
            return
        self.connection.commit()
        self.connection.execute("PRAGMA foreign_keys=OFF")
        try:
            self.connection.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE pcap_capture_source_versions_stage10 (
                  source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                  source_id TEXT NOT NULL, object_key TEXT NOT NULL,
                  source_version_id TEXT NOT NULL, source_size_bytes INTEGER NOT NULL
                    CHECK(source_size_bytes>=0), source_sha256 TEXT NOT NULL,
                  PRIMARY KEY(source_kind,source_id));
                INSERT INTO pcap_capture_source_versions_stage10
                  SELECT * FROM pcap_capture_source_versions;
                CREATE TABLE pcap_offset_index_generations_stage10 (
                  build_id TEXT PRIMARY KEY, source_kind TEXT NOT NULL DEFAULT 'PCAP_UPLOAD'
                    CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                  source_id TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('STAGING','READY')),
                  binding TEXT NOT NULL, created_at TEXT NOT NULL, packet_count INTEGER,
                  interface_count INTEGER, index_sha256 TEXT);
                INSERT INTO pcap_offset_index_generations_stage10
                  SELECT build_id,COALESCE(json_extract(binding,'$.source_kind'),'PCAP_UPLOAD'),
                         source_id,state,binding,created_at,packet_count,interface_count,index_sha256
                  FROM pcap_offset_index_generations;
                CREATE TABLE pcap_offset_index_interfaces_stage10 (
                  build_id TEXT NOT NULL REFERENCES pcap_offset_index_generations_stage10(build_id)
                    ON DELETE CASCADE, interface_ordinal INTEGER NOT NULL, data TEXT NOT NULL,
                  PRIMARY KEY(build_id,interface_ordinal));
                INSERT INTO pcap_offset_index_interfaces_stage10
                  SELECT * FROM pcap_offset_index_interfaces;
                CREATE TABLE pcap_offset_index_packets_stage10 (
                  build_id TEXT NOT NULL REFERENCES pcap_offset_index_generations_stage10(build_id)
                    ON DELETE CASCADE, packet_index INTEGER NOT NULL, data TEXT NOT NULL,
                  PRIMARY KEY(build_id,packet_index));
                INSERT INTO pcap_offset_index_packets_stage10
                  SELECT * FROM pcap_offset_index_packets;
                CREATE TABLE pcap_offset_index_owners_stage10 (
                  source_kind TEXT NOT NULL CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                  source_id TEXT NOT NULL, build_id TEXT NOT NULL UNIQUE
                    REFERENCES pcap_offset_index_generations_stage10(build_id) ON DELETE CASCADE,
                  PRIMARY KEY(source_kind,source_id));
                INSERT INTO pcap_offset_index_owners_stage10
                  SELECT COALESCE(json_extract(g.binding,'$.source_kind'),'PCAP_UPLOAD'),
                         o.source_id,o.build_id
                  FROM pcap_offset_index_owners o
                  JOIN pcap_offset_index_generations g ON g.build_id=o.build_id;
                DROP TABLE pcap_offset_index_owners;
                DROP TABLE pcap_offset_index_interfaces;
                DROP TABLE pcap_offset_index_packets;
                DROP TABLE pcap_offset_index_generations;
                DROP TABLE pcap_capture_source_versions;
                ALTER TABLE pcap_offset_index_generations_stage10
                  RENAME TO pcap_offset_index_generations;
                ALTER TABLE pcap_offset_index_interfaces_stage10
                  RENAME TO pcap_offset_index_interfaces;
                ALTER TABLE pcap_offset_index_packets_stage10
                  RENAME TO pcap_offset_index_packets;
                ALTER TABLE pcap_offset_index_owners_stage10 RENAME TO pcap_offset_index_owners;
                ALTER TABLE pcap_capture_source_versions_stage10
                  RENAME TO pcap_capture_source_versions;
                CREATE INDEX pcap_offset_index_packets_lookup
                  ON pcap_offset_index_packets(build_id,packet_index);
                CREATE INDEX pcap_offset_index_generations_staging
                  ON pcap_offset_index_generations(state,created_at,build_id);
                COMMIT;
            """)
        except Exception:
            self.connection.rollback()
            raise
        finally:
            self.connection.execute("PRAGMA foreign_keys=ON")

    @staticmethod
    def _serialize(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"), default=str)

    def _migrate_legacy_candidates(self) -> None:
        """Move legacy per-job candidate arrays into candidate-addressable rows exactly once."""
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                rows = self.connection.execute("SELECT job_id,data FROM candidates").fetchall()
                for job_id, raw_data in rows:
                    candidates = json.loads(raw_data)
                    for position, candidate in enumerate(candidates):
                        self.connection.execute(
                            "INSERT INTO candidate_records("
                            "candidate_id,job_id,position,score,severity,excluded,data"
                            ") VALUES(?,?,?,?,?,?,?) ON CONFLICT(candidate_id) DO NOTHING",
                            (
                                str(candidate["id"]),
                                str(job_id),
                                position,
                                int(candidate.get("score", 0)),
                                str(candidate.get("severity", "")),
                                int(bool(candidate.get("excluded", False))),
                                self._serialize(candidate),
                            ),
                        )
                self.connection.execute("DELETE FROM candidates")
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def _put(self, kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT INTO objects(kind,id,data) VALUES(?,?,?) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (kind, object_id, self._serialize(value)),
            )
            self.connection.commit()
        return deepcopy(value)

    def _get(self, kind: str, object_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT data FROM objects WHERE kind=? AND id=?", (kind, object_id)
            ).fetchone()
        return json.loads(row[0]) if row else None

    def _list(self, kind: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT data FROM objects WHERE kind=? ORDER BY rowid", (kind,)
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _migrate_embedded_job_flows(self) -> None:
        rows = self.connection.execute(
            "SELECT id,data FROM objects WHERE kind='job' "
            "AND json_type(data, '$.flow_records') IS NOT NULL"
        ).fetchall()
        for job_id, raw in rows:
            job = json.loads(raw)
            records = job.pop("flow_records", [])
            self.connection.execute(
                "INSERT INTO job_flow_records(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO NOTHING",
                (job_id, self._serialize(records)),
            )
            self.connection.execute(
                "UPDATE objects SET data=? WHERE kind='job' AND id=?",
                (self._serialize(job), job_id),
            )

    def _migrate_embedded_job_signatures(self) -> None:
        rows = self.connection.execute(
            "SELECT id,data FROM objects WHERE kind='job' "
            "AND json_type(data, '$.payload_signatures') IS NOT NULL"
        ).fetchall()
        for job_id, raw in rows:
            job = json.loads(raw)
            signatures = job.pop("payload_signatures", [])
            self.connection.execute(
                "INSERT INTO job_payload_signatures(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO NOTHING",
                (job_id, self._serialize(signatures)),
            )
            self.connection.execute(
                "UPDATE objects SET data=? WHERE kind='job' AND id=?",
                (self._serialize(job), job_id),
            )

    def _save_job_parts(self, job: dict[str, Any]) -> None:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        self._put("job", job["id"], metadata)
        if "flow_records" in job:
            self.connection.execute(
                "INSERT INTO job_flow_records(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job["id"], self._serialize(job["flow_records"])),
            )
            self.connection.commit()
        if "payload_signatures" in job:
            self.connection.execute(
                "INSERT INTO job_payload_signatures(job_id,data) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                (job["id"], self._serialize(job["payload_signatures"])),
            )
            self.connection.commit()

    def ready(self) -> bool:
        try:
            return bool(self.connection.execute("SELECT 1").fetchone() == (1,))
        except sqlite3.Error:
            return False

    def _posting_now(self) -> datetime:
        return self._lease_clock()

    def close(self) -> None:
        with self._lock:
            self.connection.close()

    def for_background_worker(self) -> SQLiteRepository:
        return SQLiteRepository(self._path, _lease_clock=self._lease_clock)

    def snapshot_pcap_export_source(
        self,
        job_id: str,
        canonical_request: dict[str, Any],
        effective_limits: dict[str, int],
    ) -> dict[str, Any] | None:
        with self._lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                snapshot = _pcap_export_snapshot(self, job_id, canonical_request, effective_limits)
                self.connection.commit()
                return snapshot
            except Exception:
                self.connection.rollback()
                raise

    def validate_pcap_export_admission(self, job: dict[str, Any]) -> bool:
        with self._lock:
            return _pcap_export_admission_matches(self, job)

    def _pcap_store(self) -> RepositoryQueueStore:
        return RepositoryQueueStore(self)

    def _pcap_storage_call(self, operation: Callable[[], _T]) -> _T:
        try:
            return operation()
        except ExportQueueStorageError:
            raise
        except sqlite3.Error as exc:
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    def enqueue_pcap_export_job(
        self, job: dict[str, Any], *, capacity: int, per_principal_limit: int
    ) -> tuple[dict[str, Any], bool]:
        return self._pcap_storage_call(
            lambda: self._pcap_store().enqueue(
                job, capacity=capacity, per_principal_limit=per_principal_limit
            )
        )

    def get_pcap_export_job(self, export_id: str) -> dict[str, Any] | None:
        return self._pcap_storage_call(lambda: self._pcap_store().get(export_id))

    def find_pcap_export_job(
        self, principal_scope: str, idempotency_key: str, request_fingerprint: str
    ) -> dict[str, Any] | None:
        def find() -> dict[str, Any] | None:
            with self._lock:
                row = self.connection.execute(
                    "SELECT data FROM pcap_export_jobs WHERE principal_scope=? "
                    "AND idempotency_key=?",
                    (principal_scope, idempotency_key),
                ).fetchone()
            found = json.loads(row[0]) if row is not None else None
            if found is not None and found.get("request_fingerprint") != request_fingerprint:
                raise ValueError("idempotency_conflict")
            return found

        return self._pcap_storage_call(find)

    def count_pcap_export_jobs_by_status(self) -> dict[str, int]:
        def count() -> dict[str, int]:
            with self._lock:
                rows = self.connection.execute(
                    "SELECT status,COUNT(*) FROM pcap_export_jobs "
                    "WHERE status IN ('QUEUED','RUNNING') GROUP BY status"
                ).fetchall()
            found = {str(status): int(value) for status, value in rows}
            return {status: found.get(status, 0) for status in ("QUEUED", "RUNNING")}

        return self._pcap_storage_call(count)

    def claim_pcap_export_job(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> dict[str, Any] | None:
        return self._pcap_storage_call(
            lambda: self._pcap_store().claim(now=now, lease_seconds=lease_seconds)
        )

    def heartbeat_pcap_export_job(
        self, export_id: str, *, attempt: int, lease_token: str, lease_seconds: int
    ) -> bool:
        return self._pcap_storage_call(
            lambda: self._pcap_store().heartbeat(
                export_id, attempt=attempt, lease_token=lease_token, lease_seconds=lease_seconds
            )
        )

    def progress_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        progress: dict[str, Any],
    ) -> bool:
        return self._pcap_storage_call(
            lambda: self._pcap_store().progress(
                export_id, attempt=attempt, lease_token=lease_token, progress=progress
            )
        )

    def complete_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> bool:
        return self._pcap_storage_call(
            lambda: self._pcap_store().complete(
                export_id, attempt=attempt, lease_token=lease_token, artifact=artifact
            )
        )

    def retry_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        error: str,
        retry_base_seconds: int = 5,
    ) -> bool:
        return self._pcap_storage_call(
            lambda: self._pcap_store().retry_or_fail(
                export_id,
                attempt=attempt,
                lease_token=lease_token,
                transient=transient,
                error_code=error_code,
                error=error,
                retry_base_seconds=retry_base_seconds,
            )
        )

    def cancel_pcap_export_job(
        self, export_id: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        return self._pcap_storage_call(lambda: self._pcap_store().cancel(export_id, reason=reason))

    def recover_pcap_export_jobs(self, *, now: datetime | None = None) -> int:
        return self._pcap_storage_call(lambda: self._pcap_store().recover_expired(now=now))

    def has_active_pcap_exports(self, job_id: str) -> bool:
        return bool(
            self._pcap_storage_call(
                lambda: self.connection.execute(
                    "SELECT 1 FROM pcap_export_jobs WHERE (json_extract(data,'$.job_id')=? "
                    "OR json_extract(data,'$.source_job_id')=? "
                    "OR EXISTS (SELECT 1 FROM json_each(data,'$.provenance_job_ids') "
                    "WHERE value=?)) "
                    "AND status IN ('QUEUED','RUNNING') LIMIT 1",
                    (job_id, job_id, job_id),
                ).fetchone()
            )
        )

    def validate_pcap_export_source(self, job: dict[str, Any]) -> bool:
        if "canonical_request" not in job:
            return True
        snapshot = self.snapshot_pcap_export_source(
            str(job["job_id"]),
            dict(job.get("canonical_request", {})),
            dict(job.get("effective_limits", {})),
        )
        return bool(
            snapshot is not None
            and snapshot["source_generation"] == job.get("source_generation")
            and snapshot["source_manifest"] == job.get("source_manifest", [])
        )

    def compensate_pcap_export_artifact(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> None:
        def compensate() -> None:
            with self._lock:
                self.connection.execute("BEGIN IMMEDIATE")
                object_key = artifact.get("object_key")
                lifecycle = self.connection.execute(
                    "SELECT data FROM pcap_export_jobs WHERE export_id=?",
                    (export_id,),
                ).fetchone()
                lifecycle_job = json.loads(lifecycle[0]) if lifecycle is not None else None
                published_winner = bool(
                    lifecycle_job is not None
                    and lifecycle_job.get("status") == "COMPLETED"
                    and int(lifecycle_job.get("attempt", 0)) == attempt
                    and isinstance(artifact.get("sha256"), str)
                    and isinstance(artifact.get("size_bytes"), int)
                    and lifecycle_job.get("sha256") == artifact.get("sha256")
                    and lifecycle_job.get("size_bytes") == artifact.get("size_bytes")
                )
                if published_winner or (
                    object_key
                    and lifecycle_job is not None
                    and lifecycle_job.get("object_key") == object_key
                ):
                    self.connection.commit()
                    return
                row = self.connection.execute(
                    "SELECT data FROM objects WHERE kind='export' AND id=?", (export_id,)
                ).fetchone()
                metadata = json.loads(row[0]) if row else None
                if (
                    metadata is not None
                    and metadata.get("attempt") == attempt
                    and metadata.get("lease_token") == lease_token
                    and metadata.get("object_key") == artifact.get("object_key")
                ):
                    self.connection.execute(
                        "DELETE FROM export_blobs WHERE export_id=?", (export_id,)
                    )
                    self.connection.execute(
                        "DELETE FROM objects WHERE kind='export' AND id=?", (export_id,)
                    )
                self.connection.commit()

        self._pcap_storage_call(compensate)

    def cleanup_pcap_export_orphans(
        self, *, now: datetime, max_age_seconds: int, limit: int
    ) -> list[str]:
        def cleanup() -> list[str]:
            cutoff = (now - timedelta(seconds=max_age_seconds)).isoformat()
            with self._lock:
                rows = self.connection.execute(
                    "SELECT id,data FROM objects WHERE kind='export' "
                    "AND json_extract(data,'$.published')=0 "
                    "AND json_extract(data,'$.created_at')<=? "
                    "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs "
                    "WHERE json_extract(pcap_export_jobs.data,'$.object_key')="
                    "json_extract(objects.data,'$.object_key')) "
                    "ORDER BY json_extract(data,'$.created_at'),id LIMIT ?",
                    (cutoff, limit),
                ).fetchall()
                selected = [(str(row[0]), json.loads(row[1])) for row in rows]
                for export_id, _metadata in selected:
                    self.connection.execute(
                        "DELETE FROM export_blobs WHERE export_id=?", (export_id,)
                    )
                    self.connection.execute(
                        "DELETE FROM objects WHERE kind='export' AND id=?", (export_id,)
                    )
                self.connection.commit()
                return [str(metadata["object_key"]) for _export_id, metadata in selected]

        return self._pcap_storage_call(cleanup)

    def retain_pcap_export_jobs(
        self,
        *,
        now: datetime,
        max_age_seconds: int,
        max_count: int,
        max_artifact_bytes: int,
    ) -> list[str]:
        return self._pcap_storage_call(
            lambda: self._pcap_store().retain_terminal(
                now=now,
                max_age_seconds=max_age_seconds,
                max_count=max_count,
                max_artifact_bytes=max_artifact_bytes,
            )
        )

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor", sensor["sensor_id"], sensor)

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor", sensor_id)

    def list_sensors(self) -> list[dict[str, Any]]:
        return self._list("sensor")

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return self._put("group", group["id"], group)

    def list_groups(self) -> list[dict[str, Any]]:
        return self._list("group")

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            row = self.connection.execute(
                "SELECT job_id FROM idempotency WHERE key=?", (job["idempotency_key"],)
            ).fetchone()
            if row:
                existing = self.get_job(row[0])
                if existing is None:
                    raise RuntimeError("idempotency ledger references missing job")
                return existing, False
            self._save_job_parts(job)
            self.connection.execute(
                "INSERT INTO idempotency(key,job_id) VALUES(?,?)",
                (job["idempotency_key"], job["id"]),
            )
            self.connection.commit()
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._save_job_parts(job)
            return deepcopy(job)

    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        return self._put("job", job["id"], metadata)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        job = self._get("job", job_id)
        if job is None:
            return None
        row = self.connection.execute(
            "SELECT data FROM job_flow_records WHERE job_id=?", (job_id,)
        ).fetchone()
        job["flow_records"] = json.loads(row[0]) if row else []
        row = self.connection.execute(
            "SELECT data FROM job_payload_signatures WHERE job_id=?", (job_id,)
        ).fetchone()
        job["payload_signatures"] = json.loads(row[0]) if row else []
        return job

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        return self._get("job", job_id)

    def get_job_summaries(self, job_ids: list[str]) -> dict[str, dict[str, Any]]:
        selected = list(dict.fromkeys(job_ids))
        if not selected:
            return {}
        placeholders = ",".join("?" for _ in selected)
        rows = self.connection.execute(
            f"SELECT id,data FROM objects WHERE kind='job' AND id IN ({placeholders})",  # noqa: S608 -- placeholders contain only generated question marks
            selected,
        ).fetchall()
        return {str(row[0]): json.loads(row[1]) for row in rows}

    def list_jobs(self) -> list[dict[str, Any]]:
        return self._list("job")

    def list_active_live_jobs(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM objects WHERE kind='job' "
            "AND json_extract(data, '$.mode')='LIVE' "
            "AND json_extract(data, '$.status') IN ('CAPTURING','UPLOADING') "
            "ORDER BY rowid"
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def delete_job(self, job_id: str) -> bool:
        with self._lock, self.connection:
            self.connection.execute("BEGIN IMMEDIATE")
            job = self.get_job(job_id)
            if job is None:
                return False
            active_export = self.connection.execute(
                "SELECT 1 FROM pcap_export_jobs "
                "WHERE (json_extract(data,'$.job_id')=? "
                "OR json_extract(data,'$.source_job_id')=? "
                "OR EXISTS (SELECT 1 FROM json_each(data,'$.provenance_job_ids') "
                "WHERE value=?)) "
                "AND status IN ('QUEUED','RUNNING') LIMIT 1",
                (job_id, job_id, job_id),
            ).fetchone()
            if active_export is not None:
                return False
            run_rows = self.connection.execute(
                "SELECT run_id,data FROM ai_analysis_runs WHERE analysis_job_id=?", (job_id,)
            ).fetchall()
            if any(
                json.loads(str(row[1])).get("status") not in _AI_TERMINAL_STATUSES
                for row in run_rows
            ):
                return False
            run_ids = [str(row[0]) for row in run_rows]
            assessment_ids: list[str] = []
            if run_ids:
                placeholders = ",".join("?" for _ in run_ids)
                assessment_rows = self.connection.execute(
                    f"SELECT assessment_id FROM ai_candidate_assessments "  # noqa: S608 -- generated placeholders only
                    f"WHERE ai_run_id IN ({placeholders})",
                    run_ids,
                ).fetchall()
                assessment_ids = [str(row[0]) for row in assessment_rows]
            if assessment_ids:
                placeholders = ",".join("?" for _ in assessment_ids)
                self.connection.execute(
                    f"DELETE FROM ai_feedback WHERE assessment_id IN ({placeholders})",  # noqa: S608 -- generated placeholders only
                    assessment_ids,
                )
                self.connection.execute(
                    f"DELETE FROM ai_generated_artifacts WHERE assessment_id IN ({placeholders})",  # noqa: S608 -- generated placeholders only
                    assessment_ids,
                )
            if run_ids:
                placeholders = ",".join("?" for _ in run_ids)
                self.connection.execute(
                    f"DELETE FROM ai_candidate_assessments WHERE ai_run_id IN ({placeholders})",  # noqa: S608 -- generated placeholders only
                    run_ids,
                )
            self.connection.execute(
                "DELETE FROM ai_analysis_runs WHERE analysis_job_id=?", (job_id,)
            )
            export_rows = self.connection.execute(
                "SELECT id FROM objects WHERE kind='export' AND json_extract(data, '$.job_id')=?",
                (job_id,),
            ).fetchall()
            export_ids = [str(row[0]) for row in export_rows]
            if export_ids:
                placeholders = ",".join("?" for _ in export_ids)
                self.connection.execute(
                    f"DELETE FROM export_blobs WHERE export_id IN ({placeholders})",  # noqa: S608 -- generated placeholders only
                    export_ids,
                )
                self.connection.execute(
                    f"DELETE FROM objects WHERE kind='export' AND id IN ({placeholders})",  # noqa: S608 -- generated placeholders only
                    export_ids,
                )
            self.connection.execute("DELETE FROM candidates WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM candidate_records WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM job_flow_records WHERE job_id=?", (job_id,))
            self.connection.execute("DELETE FROM job_payload_signatures WHERE job_id=?", (job_id,))
            live_segment_rows = self.connection.execute(
                "SELECT id FROM objects WHERE kind='sensor_pcap' "
                "AND json_extract(data,'$.analysis_job_id')=? ORDER BY id",
                (job_id,),
            ).fetchall()
            live_segment_ids = [str(row[0]) for row in live_segment_rows]
            for segment_id in live_segment_ids:
                self.connection.execute(
                    "DELETE FROM pcap_offset_index_jobs "
                    "WHERE source_kind='LIVE_SEGMENT' AND source_id=?",
                    (segment_id,),
                )
                self.connection.execute(
                    "DELETE FROM pcap_capture_source_versions "
                    "WHERE source_kind='LIVE_SEGMENT' AND source_id=?",
                    (segment_id,),
                )
                self.connection.execute(
                    "DELETE FROM pcap_offset_index_generations "
                    "WHERE source_kind='LIVE_SEGMENT' AND source_id=?",
                    (segment_id,),
                )
                self.connection.execute(
                    "DELETE FROM sensor_pcap_blobs WHERE segment_id=?", (segment_id,)
                )
                self.connection.execute(
                    "DELETE FROM objects WHERE kind='sensor_pcap' AND id=?", (segment_id,)
                )
            self.connection.execute(
                "DELETE FROM pcap_offset_index_generations WHERE source_kind='PCAP_UPLOAD' "
                "AND source_id=?",
                (job_id,),
            )
            self.connection.execute("DELETE FROM job_capture_blobs WHERE job_id=?", (job_id,))
            self.connection.execute(
                "DELETE FROM pcap_capture_source_versions WHERE source_kind='PCAP_UPLOAD' "
                "AND source_id=?",
                (job_id,),
            )
            self.connection.execute("DELETE FROM idempotency WHERE job_id=?", (job_id,))
            self.connection.execute(
                "DELETE FROM pcap_export_jobs WHERE json_extract(data,'$.job_id')=?", (job_id,)
            )
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='job' AND id=?", (job_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def delete_retained_source(self, job_id: str) -> bool:
        """Retention seam: metadata/index deletion shares the canonical job transaction."""
        return self.delete_job(job_id)

    def save_job_capture(self, job_id: str, content: bytes) -> None:
        with self._lock:
            digest = hashlib.sha256(content).hexdigest()
            self.connection.execute(
                "INSERT INTO job_capture_blobs(job_id,content) VALUES(?,?) "
                "ON CONFLICT(job_id) DO UPDATE SET content=excluded.content",
                (job_id, content),
            )
            self.connection.execute(
                "INSERT INTO pcap_capture_source_versions("
                "source_kind,source_id,object_key,source_version_id,source_size_bytes,source_sha256"
                ") VALUES('PCAP_UPLOAD',?,?,?,?,?) "
                "ON CONFLICT(source_kind,source_id) DO UPDATE SET "
                "object_key=excluded.object_key,source_version_id=excluded.source_version_id,"
                "source_size_bytes=excluded.source_size_bytes,source_sha256=excluded.source_sha256",
                (job_id, f"captures/{job_id}.pcap", f"sha256:{digest}", len(content), digest),
            )
            self.connection.commit()

    def get_capture_source_version(self, job_id: str) -> CaptureSourceVersion | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                "source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
                (job_id,),
            ).fetchone()
        return CaptureSourceVersion(*row) if row is not None else None

    def read_capture_range(
        self, source: CaptureSourceVersion, byte_range: CaptureByteRange
    ) -> bytes:
        byte_range.validate_for_source(source)
        blob_table, blob_id = (
            ("job_capture_blobs", "job_id")
            if source.source_kind == "PCAP_UPLOAD"
            else ("sensor_pcap_blobs", "segment_id")
        )
        try:
            with self._lock:
                self.connection.execute("BEGIN")
                row = self.connection.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,"
                    "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind=? AND source_id=?",
                    (source.source_kind, source.source_id),
                ).fetchone()
                if row is None:
                    self.connection.rollback()
                    raise CaptureRangeMissing("capture source row is missing")
                if CaptureSourceVersion(*row) != source:
                    self.connection.rollback()
                    raise CaptureRangeVersionDrift("capture source version changed")
                content_row = self.connection.execute(
                    f"SELECT substr(content, ?, ?) FROM {blob_table} WHERE {blob_id}=?",  # noqa: S608 -- table and identifier are selected from fixed internal constants
                    (byte_range.offset + 1, byte_range.length, source.source_id),
                ).fetchone()
                if content_row is None:
                    self.connection.rollback()
                    raise CaptureRangeMissing("capture object is missing")
                result = bytes(content_row[0])
                post = self.connection.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,"
                    "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind=? AND source_id=?",
                    (source.source_kind, source.source_id),
                ).fetchone()
                self.connection.commit()
        except (CaptureRangeMissing, CaptureRangeVersionDrift):
            raise
        except sqlite3.Error as exc:
            self.connection.rollback()
            raise CaptureRangeUnavailable("SQLite capture range read failed") from exc
        if post is None:
            raise CaptureRangeMissing("capture source disappeared during range read")
        if CaptureSourceVersion(*post) != source:
            raise CaptureRangeVersionDrift("capture source changed during range read")
        if len(result) != byte_range.length:
            raise CaptureRangeShortRead("capture range returned fewer bytes than requested")
        return result

    def get_job_capture(self, job_id: str) -> bytes | None:
        source = self.open_job_capture(job_id)
        if source is None:
            return None
        with source:
            return b"".join(source.iter_chunks())

    def open_job_capture(self, job_id: str) -> CaptureSource | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT content FROM job_capture_blobs WHERE job_id=?", (job_id,)
            ).fetchone()
            return _bytes_source(bytes(row[0])) if row else None

    def begin_structural_index(
        self, build_id: str, binding: SourceIndexBinding, created_at: datetime
    ) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "INSERT INTO pcap_offset_index_generations("
                "build_id,source_kind,source_id,state,binding,created_at) "
                "VALUES(?,?,?,'STAGING',?,?)",
                (
                    build_id,
                    binding.source_kind,
                    binding.source_id,
                    self._serialize(asdict(binding)),
                    created_at.isoformat(),
                ),
            )

    def stage_structural_index_packets(
        self, build_id: str, packets: tuple[StructuralPacketEntry, ...]
    ) -> None:
        if not packets:
            return
        with self._lock, self.connection:
            row = self.connection.execute(
                "SELECT COALESCE(MAX(packet_index)+1,0) FROM pcap_offset_index_packets "
                "WHERE build_id=?",
                (build_id,),
            ).fetchone()
            if row is None or int(row[0]) != packets[0].packet_index:
                raise ValueError("structural packet rows are not contiguous")
            self.connection.executemany(
                "INSERT INTO pcap_offset_index_packets(build_id,packet_index,data) VALUES(?,?,?)",
                [
                    (build_id, packet.packet_index, self._serialize(asdict(packet)))
                    for packet in packets
                ],
            )

    def _load_structural_snapshot(self, build_id: str) -> StructuralIndexSnapshot | None:
        row = self.connection.execute(
            "SELECT binding,created_at,index_sha256,packet_count,interface_count "
            "FROM pcap_offset_index_generations "
            "WHERE build_id=? AND state='READY'",
            (build_id,),
        ).fetchone()
        if row is None or row[2] is None:
            return None
        binding = SourceIndexBinding(**json.loads(row[0]))
        interfaces = tuple(
            StructuralInterfaceEntry(**json.loads(item[0]))
            for item in self.connection.execute(
                "SELECT data FROM pcap_offset_index_interfaces WHERE build_id=? "
                "ORDER BY interface_ordinal",
                (build_id,),
            ).fetchall()
        )
        packets = tuple(
            StructuralPacketEntry(**json.loads(item[0]))
            for item in self.connection.execute(
                "SELECT data FROM pcap_offset_index_packets WHERE build_id=? ORDER BY packet_index",
                (build_id,),
            ).fetchall()
        )
        if row[3] is None or row[4] is None:
            raise ValueError("ready structural index counts are missing")
        if int(row[3]) != len(packets) or int(row[4]) != len(interfaces):
            raise ValueError("ready structural index counts do not match child rows")
        return StructuralIndexSnapshot(
            build_id,
            binding,
            datetime.fromisoformat(str(row[1])),
            str(row[2]),
            interfaces,
            packets,
        )

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
    ) -> bool:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                generation = self.connection.execute(
                    "SELECT binding FROM pcap_offset_index_generations "
                    "WHERE build_id=? AND state='STAGING'",
                    (build_id,),
                ).fetchone()
                job = self.get_job_summary(binding.source_id)
                source_version = self.connection.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                    "source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
                    (binding.source_id,),
                ).fetchone()
                stored_count = int(
                    self.connection.execute(
                        "SELECT COUNT(*) FROM pcap_offset_index_packets WHERE build_id=?",
                        (build_id,),
                    ).fetchone()[0]
                )
                if (
                    generation is None
                    or SourceIndexBinding(**json.loads(generation[0])) != binding
                    or stored_count != packet_count
                    or not _job_matches_structural_binding(job, binding)
                    or source_version is None
                    or tuple(source_version)
                    != (
                        binding.source_kind,
                        binding.source_id,
                        f"captures/{binding.source_id}.pcap",
                        binding.source_version_id,
                        binding.source_size_bytes,
                        binding.source_sha256,
                    )
                ):
                    self.connection.rollback()
                    return False
                packets = tuple(
                    StructuralPacketEntry(**json.loads(item[0]))
                    for item in self.connection.execute(
                        "SELECT data FROM pcap_offset_index_packets WHERE build_id=? "
                        "ORDER BY packet_index",
                        (build_id,),
                    ).fetchall()
                )
                snapshot = StructuralIndexSnapshot(
                    build_id,
                    binding,
                    datetime.now().astimezone(),
                    structural_index_digest(binding, interfaces, packets),
                    interfaces,
                    packets,
                )
                if not validate_structural_index(snapshot):
                    self.connection.rollback()
                    return False
                previous = self.connection.execute(
                    "SELECT build_id FROM pcap_offset_index_owners "
                    "WHERE source_kind=? AND source_id=?",
                    (binding.source_kind, binding.source_id),
                ).fetchone()
                if previous is not None and str(previous[0]) != build_id:
                    active = self.connection.execute(
                        "SELECT 1 FROM pcap_posting_index_jobs WHERE source_kind=? "
                        "AND source_id=? AND parent_structural_build_id=? "
                        "AND status IN ('QUEUED','RUNNING') LIMIT 1",
                        (binding.source_kind, binding.source_id, str(previous[0])),
                    ).fetchone()
                    if active is not None:
                        self.connection.rollback()
                        return False
                self.connection.executemany(
                    "INSERT INTO pcap_offset_index_interfaces(build_id,interface_ordinal,data) "
                    "VALUES(?,?,?)",
                    [
                        (build_id, interface.interface_ordinal, self._serialize(asdict(interface)))
                        for interface in interfaces
                    ],
                )
                self.connection.execute(
                    "UPDATE pcap_offset_index_generations SET state='READY',packet_count=?,"
                    "interface_count=?,index_sha256=? WHERE build_id=?",
                    (packet_count, len(interfaces), snapshot.index_sha256, build_id),
                )
                self.connection.execute(
                    "INSERT INTO pcap_offset_index_owners(source_kind,source_id,build_id) "
                    "VALUES(?,?,?) ON CONFLICT(source_kind,source_id) "
                    "DO UPDATE SET build_id=excluded.build_id",
                    (binding.source_kind, binding.source_id, build_id),
                )
                if previous is not None and str(previous[0]) != build_id:
                    # A terminal task still references the old intent parent. Remove
                    # it before repointing the marker; active tasks were rejected above.
                    self.connection.execute(
                        "DELETE FROM pcap_posting_index_jobs WHERE source_kind=? "
                        "AND source_id=? AND parent_structural_build_id=?",
                        (binding.source_kind, binding.source_id, str(previous[0])),
                    )
                if request_postings:
                    source = CaptureSourceVersion(*source_version)
                    spec = replace(
                        PostingIndexTaskSpec.from_binding(source, snapshot),
                        posting_schema_version=posting_schema_version,
                        posting_parser_contract_version=posting_parser_contract_version,
                        filter_contract_version=filter_contract_version,
                    )
                    current = self.get_posting_index_intent(spec.source_kind, spec.source_id)
                    if current is None or current.spec.identity != spec.identity:
                        requested_at = self._posting_now()
                        put_posting_intent(
                            self,
                            PostingIndexIntent(
                                spec,
                                PostingIndexIntentStatus.PENDING,
                                requested_at,
                                requested_at,
                            ),
                        )
                if previous is not None and str(previous[0]) != build_id:
                    self.connection.execute(
                        "DELETE FROM pcap_offset_index_generations WHERE build_id=?",
                        (str(previous[0]),),
                    )
                self.connection.commit()
                return True
            except Exception:
                self.connection.rollback()
                raise

    def abort_structural_index(self, build_id: str) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "DELETE FROM pcap_offset_index_generations WHERE build_id=? AND state='STAGING'",
                (build_id,),
            )

    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup:
        with self._lock:
            row = self.connection.execute(
                "SELECT build_id FROM pcap_offset_index_owners WHERE source_kind=? AND source_id=?",
                (binding.source_kind, binding.source_id),
            ).fetchone()
            if row is None:
                return StructuralIndexLookup(IndexAvailability.MISSING)
            try:
                snapshot = self._load_structural_snapshot(str(row[0]))
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                return StructuralIndexLookup(IndexAvailability.CORRUPT)
            if snapshot is None:
                return StructuralIndexLookup(IndexAvailability.CORRUPT)
            if (
                snapshot.binding.schema_version != binding.schema_version
                or snapshot.binding.parser_contract_version != binding.parser_contract_version
            ):
                return StructuralIndexLookup(IndexAvailability.UNSUPPORTED_SCHEMA)
            if snapshot.binding != binding:
                return StructuralIndexLookup(IndexAvailability.STALE)
            if binding.source_kind == "LIVE_SEGMENT":
                segment = self._get("sensor_pcap", binding.source_id)
                job = (
                    self.get_job_summary(str(segment.get("analysis_job_id")))
                    if segment is not None
                    else None
                )
                object_key = (
                    str(segment.get("object_key"))
                    if segment and segment.get("object_key")
                    else f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
                    if segment
                    else ""
                )
                canonical_matches = bool(
                    segment
                    and eligible_live_segment(job, segment)
                    and segment.get("index_requested_at")
                    and int(segment.get("size_bytes", -1)) == binding.source_size_bytes
                    and segment.get("sha256") == binding.source_sha256
                )
            else:
                job = self.get_job_summary(binding.source_id)
                object_key = f"captures/{binding.source_id}.pcap"
                canonical_matches = _job_matches_structural_binding(job, binding)
            source_version = self.connection.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                "source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind=? AND source_id=?",
                (binding.source_kind, binding.source_id),
            ).fetchone()
            if (
                not canonical_matches
                or source_version is None
                or tuple(source_version)
                != (
                    binding.source_kind,
                    binding.source_id,
                    object_key,
                    binding.source_version_id,
                    binding.source_size_bytes,
                    binding.source_sha256,
                )
            ):
                return StructuralIndexLookup(IndexAvailability.STALE)
            if not validate_structural_index(snapshot):
                return StructuralIndexLookup(IndexAvailability.CORRUPT)
            return StructuralIndexLookup(IndexAvailability.READY, snapshot)

    def get_structural_index_identity(
        self, source: CaptureSourceVersion
    ) -> StructuralIndexIdentityLookup:
        with self._lock:
            row = self.connection.execute(
                "SELECT owner.build_id,generation.binding,generation.created_at,"
                "generation.index_sha256,generation.state,generation.packet_count,"
                "generation.interface_count FROM pcap_offset_index_owners AS owner "
                "LEFT JOIN pcap_offset_index_generations AS generation "
                "ON generation.build_id=owner.build_id WHERE owner.source_kind=? "
                "AND owner.source_id=? LIMIT 1",
                (source.source_kind, source.source_id),
            ).fetchone()
            if row is None:
                return StructuralIndexIdentityLookup(IndexAvailability.MISSING)
            if (
                row[1] is None
                or row[4] != "READY"
                or type(row[5]) is not int
                or type(row[6]) is not int
                or row[5] < 0
                or row[6] < 0
            ):
                return StructuralIndexIdentityLookup(IndexAvailability.CORRUPT)
            try:
                snapshot_binding = SourceIndexBinding(**json.loads(row[1]))
                identity = structural_index_identity(
                    StructuralIndexSnapshot(
                        str(row[0]),
                        snapshot_binding,
                        datetime.fromisoformat(str(row[2])),
                        str(row[3]),
                        (),
                        (),
                    )
                )
            except (TypeError, ValueError, KeyError, json.JSONDecodeError):
                return StructuralIndexIdentityLookup(IndexAvailability.CORRUPT)
            availability = structural_index_identity_availability(identity, source)
            if availability is IndexAvailability.READY:
                binding = identity.binding
                if binding.source_kind == "LIVE_SEGMENT":
                    segment = self._get("sensor_pcap", binding.source_id)
                    job = (
                        self.get_job_summary(str(segment.get("analysis_job_id")))
                        if segment is not None
                        else None
                    )
                    object_key = (
                        str(segment.get("object_key"))
                        if segment and segment.get("object_key")
                        else f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
                        if segment
                        else ""
                    )
                    canonical_matches = bool(
                        segment
                        and eligible_live_segment(job, segment)
                        and segment.get("index_requested_at")
                        and int(segment.get("size_bytes", -1)) == binding.source_size_bytes
                        and segment.get("sha256") == binding.source_sha256
                    )
                else:
                    object_key = f"captures/{binding.source_id}.pcap"
                    canonical_matches = _job_matches_structural_binding(
                        self.get_job_summary(binding.source_id), binding
                    )
                source_version = self.connection.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,"
                    "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind=? AND source_id=?",
                    (binding.source_kind, binding.source_id),
                ).fetchone()
                if (
                    not canonical_matches
                    or source_version is None
                    or tuple(source_version)
                    != (
                        binding.source_kind,
                        binding.source_id,
                        object_key,
                        binding.source_version_id,
                        binding.source_size_bytes,
                        binding.source_sha256,
                    )
                ):
                    availability = IndexAvailability.STALE
            return StructuralIndexIdentityLookup(
                availability,
                identity if availability is IndexAvailability.READY else None,
            )

    def delete_structural_indexes_for_source(
        self, source_id: str, *, source_kind: str = "PCAP_UPLOAD"
    ) -> None:
        with self._lock, self.connection:
            self.connection.execute(
                "DELETE FROM pcap_offset_index_generations WHERE source_kind=? AND source_id=?",
                (source_kind, source_id),
            )

    def cleanup_stale_structural_indexes(self, *, before: datetime, limit: int) -> int:
        with self._lock, self.connection:
            rows = self.connection.execute(
                "SELECT build_id FROM pcap_offset_index_generations "
                "WHERE state='STAGING' AND created_at<=? ORDER BY created_at,build_id LIMIT ?",
                (before.isoformat(), limit),
            ).fetchall()
            self.connection.executemany(
                "DELETE FROM pcap_offset_index_generations WHERE build_id=?",
                rows,
            )
            return len(rows)

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("DELETE FROM candidate_records WHERE job_id=?", (job_id,))
                self.connection.executemany(
                    "INSERT INTO candidate_records("
                    "candidate_id,job_id,position,score,severity,excluded,data"
                    ") VALUES(?,?,?,?,?,?,?)",
                    [
                        (
                            str(candidate["id"]),
                            job_id,
                            position,
                            int(candidate.get("score", 0)),
                            str(candidate.get("severity", "")),
                            int(bool(candidate.get("excluded", False))),
                            self._serialize(candidate),
                        )
                        for position, candidate in enumerate(candidates)
                    ],
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM candidate_records WHERE job_id=? ORDER BY position", (job_id,)
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None:
        row = self.connection.execute(
            "SELECT job_id,data FROM candidate_records WHERE candidate_id=?", (candidate_id,)
        ).fetchone()
        return (str(row[0]), json.loads(row[1])) if row else None

    def query_candidates(
        self,
        *,
        minimum_score: int = 0,
        severity: str | None = None,
        include_suppressed: bool = False,
    ) -> list[tuple[str, dict[str, Any]]]:
        clauses = ["CAST(json_extract(data,'$.score') AS INTEGER)>=?"]
        parameters: list[Any] = [minimum_score]
        if severity is not None:
            clauses.append("json_extract(data,'$.severity')=?")
            parameters.append(severity)
        if not include_suppressed:
            clauses.append("COALESCE(json_extract(data,'$.excluded'),0)=0")
        rows = self.connection.execute(
            "SELECT job_id,data FROM candidate_records WHERE "  # noqa: S608 -- clauses are code-owned and values are bound
            + " AND ".join(clauses),
            parameters,
        ).fetchall()
        return [(str(row[0]), json.loads(row[1])) for row in rows]

    @staticmethod
    def _candidate_query_parts(
        minimum_score: int, severity: str | None, include_suppressed: bool
    ) -> tuple[list[str], list[Any]]:
        clauses = ["score>=?"]
        parameters: list[Any] = [minimum_score]
        if severity is not None:
            clauses.append("severity=?")
            parameters.append(severity)
        if not include_suppressed:
            clauses.append("excluded=0")
        return clauses, parameters

    def query_candidate_page(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
        sort: str,
        page: int,
        page_size: int,
    ) -> tuple[list[tuple[str, dict[str, Any]]], int]:
        clauses, parameters = self._candidate_query_parts(
            minimum_score, severity, include_suppressed
        )
        field = sort.removeprefix("-")
        direction = "DESC" if sort.startswith("-") else "ASC"
        columns = {
            "score": "score",
            "severity": "severity",
            "candidate_ip": "json_extract(data,'$.candidate_ip')",
            "first_seen": "json_extract(data,'$.first_seen')",
            "last_seen": "json_extract(data,'$.last_seen')",
        }
        order_column = columns[field]
        where = " AND ".join(clauses)
        total = int(
            self.connection.execute(
                f"SELECT COUNT(*) FROM candidate_records WHERE {where}",  # noqa: S608 -- where is built from code-owned clauses
                parameters,
            ).fetchone()[0]
        )
        rows = self.connection.execute(
            f"SELECT job_id,data FROM candidate_records WHERE {where} "  # noqa: S608 -- columns/clauses are allowlisted
            f"ORDER BY {order_column} {direction},candidate_id ASC LIMIT ? OFFSET ?",
            [*parameters, page_size, (page - 1) * page_size],
        ).fetchall()
        return [(str(row[0]), json.loads(row[1])) for row in rows], total

    def query_candidate_refs(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> list[tuple[str, bool]]:
        clauses, parameters = self._candidate_query_parts(
            minimum_score, severity, include_suppressed
        )
        rows = self.connection.execute(
            "SELECT candidate_id,excluded FROM candidate_records WHERE "  # noqa: S608 -- clauses are code-owned and values are bound
            + " AND ".join(clauses),
            parameters,
        ).fetchall()
        return [(str(row[0]), bool(row[1])) for row in rows]

    def candidate_workflow_counts(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> dict[str, int]:
        candidate_ids = [
            candidate_id
            for candidate_id, _ in self.query_candidate_refs(
                minimum_score=minimum_score,
                severity=severity,
                include_suppressed=include_suppressed,
            )
        ]
        return _candidate_workflow_counts_from_records(
            candidate_ids,
            self.list_candidate_decisions(),
            self.list_candidate_actions(),
        )

    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._lock:
            existing = self.connection.execute(
                "SELECT data FROM ai_analysis_runs WHERE analysis_job_id=? AND idempotency_key=?",
                (run["analysis_job_id"], run["idempotency_key"]),
            ).fetchone()
            if existing is not None:
                return json.loads(existing[0]), False
            self.connection.execute(
                "INSERT INTO ai_analysis_runs"
                "(run_id,analysis_job_id,idempotency_key,created_at,data) VALUES(?,?,?,?,?)",
                (
                    run["id"],
                    run["analysis_job_id"],
                    run["idempotency_key"],
                    run["created_at"],
                    self._serialize(run),
                ),
            )
            self.connection.commit()
            return deepcopy(run), True

    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            row = self.connection.execute(
                "SELECT data FROM ai_analysis_runs WHERE run_id=?", (run["id"],)
            ).fetchone()
            if row is not None:
                existing = cast(dict[str, Any], json.loads(row[0]))
                if existing.get("status") in {"COMPLETED", "FAILED", "CANCELLED"}:
                    return existing
            self.connection.execute(
                "UPDATE ai_analysis_runs SET data=? WHERE run_id=?",
                (self._serialize(run), run["id"]),
            )
            self.connection.commit()
            return deepcopy(run)

    def get_ai_run(self, run_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM ai_analysis_runs WHERE run_id=?", (run_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_analysis_runs WHERE analysis_job_id=? ORDER BY created_at DESC",
            (job_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT OR IGNORE INTO ai_candidate_assessments"
                "(assessment_id,ai_run_id,created_at,data) VALUES(?,?,?,?)",
                (
                    assessment["id"],
                    assessment["ai_run_id"],
                    assessment["created_at"],
                    self._serialize(assessment),
                ),
            )
            self.connection.commit()
            stored = self.get_ai_assessment(assessment["id"])
            if stored is None:
                raise RuntimeError("AI assessment was not persisted")
            return stored

    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM ai_candidate_assessments WHERE assessment_id=?",
            (assessment_id,),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_candidate_assessments WHERE ai_run_id=? ORDER BY created_at",
            (run_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT INTO ai_generated_artifacts"
                "(artifact_id,assessment_id,created_at,data) VALUES(?,?,?,?) "
                "ON CONFLICT(artifact_id) DO UPDATE SET data=excluded.data",
                (
                    artifact["id"],
                    artifact["assessment_id"],
                    artifact["created_at"],
                    self._serialize(artifact),
                ),
            )
            self.connection.commit()
            return deepcopy(artifact)

    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT data FROM ai_generated_artifacts WHERE artifact_id=?", (artifact_id,)
        ).fetchone()
        return json.loads(row[0]) if row else None

    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_generated_artifacts "
            "WHERE assessment_id=? ORDER BY created_at,artifact_id",
            (assessment_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.connection.execute(
                "INSERT OR IGNORE INTO ai_feedback"
                "(feedback_id,assessment_id,created_at,data) VALUES(?,?,?,?)",
                (
                    feedback["id"],
                    feedback["assessment_id"],
                    feedback["created_at"],
                    self._serialize(feedback),
                ),
            )
            self.connection.commit()
        return deepcopy(feedback)

    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT data FROM ai_feedback WHERE assessment_id=? ORDER BY created_at,feedback_id",
            (assessment_id,),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None:
        with self._lock:
            self.connection.execute(
                "INSERT INTO audit_events(kind,object_id,occurred_at,data) VALUES(?,?,?,?)",
                (kind, object_id, datetime.now().astimezone().isoformat(), self._serialize(data)),
            )
            self.connection.commit()

    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]:
        rows = self.connection.execute(
            "SELECT job_id,data FROM candidate_records ORDER BY job_id,position"
        ).fetchall()
        result: dict[str, list[dict[str, Any]]] = {}
        for job_id, data in rows:
            result.setdefault(str(job_id), []).append(json.loads(data))
        return result

    def get_integration_settings(self) -> dict[str, Any] | None:
        return self._get("integration_settings", "global")

    def save_integration_settings(
        self, settings: dict[str, Any], expected_version: int
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                row = self.connection.execute(
                    "SELECT data FROM objects WHERE kind='integration_settings' AND id='global'"
                ).fetchone()
                current = json.loads(row[0]) if row else None
                if int((current or {}).get("version", 0)) != expected_version:
                    self.connection.commit()
                    return current, "CONFLICT"
                self.connection.execute(
                    "INSERT INTO objects(kind,id,data) VALUES('integration_settings','global',?) "
                    "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                    (self._serialize(settings),),
                )
                self.connection.commit()
                return deepcopy(settings), "OK"
            except Exception:
                self.connection.rollback()
                raise

    def save_candidate_decision(self, decision: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-decision", decision["id"], decision)

    def list_candidate_decisions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-decision")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-action", action["id"], action)

    def list_candidate_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-action")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_ti_lookup(self, lookup: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-ti-lookup", lookup["id"], lookup)

    def list_candidate_ti_lookups(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-ti-lookup")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def save_candidate_misp_action(self, action: dict[str, Any]) -> dict[str, Any]:
        return self._put("candidate-misp-action", action["id"], action)

    def claim_candidate_misp_action(self, action: dict[str, Any]) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "INSERT INTO objects(kind,id,data) VALUES('candidate-misp-action',?,?) "
                "ON CONFLICT(kind,id) DO NOTHING",
                (action["id"], self._serialize(action)),
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def list_candidate_misp_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-misp-action")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def list_candidate_workflow_records(
        self, candidate_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        selected = list(dict.fromkeys(candidate_ids))
        records: dict[str, list[dict[str, Any]]] = {
            "decisions": [],
            "actions": [],
            "lookups": [],
            "misp_actions": [],
        }
        if not selected:
            return records
        placeholders = ",".join("?" for _ in selected)
        for kind, key in {
            "candidate-decision": "decisions",
            "candidate-action": "actions",
            "candidate-ti-lookup": "lookups",
            "candidate-misp-action": "misp_actions",
        }.items():
            rows = self.connection.execute(
                "SELECT data FROM objects WHERE kind=? "  # noqa: S608 -- generated placeholders only
                f"AND json_extract(data,'$.candidate_id') IN ({placeholders})",
                [kind, *selected],
            ).fetchall()
            records[key] = [json.loads(row[0]) for row in rows]
        return records

    def update_candidate(self, candidate_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a candidate by ID across all jobs."""
        with self._lock:
            row = self.connection.execute(
                "SELECT data FROM candidate_records WHERE candidate_id=?", (candidate_id,)
            ).fetchone()
            if row is None:
                return None
            from datetime import UTC

            updated = json.loads(row[0])
            updates_copy = deepcopy(updates)
            if "score_adjustment" in updates_copy:
                old_score = updated.get("score", 0)
                adjustment = updates_copy.pop("score_adjustment")
                updated["score"] = max(0, min(100, old_score + adjustment))
            if "exclude_reason" in updates_copy:
                updated["excluded"] = True
                updated["exclude_reason"] = updates_copy.pop("exclude_reason")
            updated.update(deepcopy(updates_copy))
            updated["updated_at"] = datetime.now(UTC).isoformat()
            self.connection.execute(
                "UPDATE candidate_records SET score=?,severity=?,excluded=?,data=? "
                "WHERE candidate_id=?",
                (
                    int(updated.get("score", 0)),
                    str(updated.get("severity", "")),
                    int(bool(updated.get("excluded", False))),
                    self._serialize(updated),
                    candidate_id,
                ),
            )
            self.connection.commit()
            return cast(dict[str, Any], deepcopy(updated))

    def delete_candidate(self, candidate_id: str) -> bool:
        """Delete a candidate by ID across all jobs."""
        with self._lock:
            cursor = self.connection.execute(
                "DELETE FROM candidate_records WHERE candidate_id=?", (candidate_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]:
        return self._put("flow_label", label["id"], label)

    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]:
        labels = self._list("flow_label")
        if job_id is not None:
            labels = [label for label in labels if label.get("job_id") == job_id]
        return sorted(labels, key=lambda item: str(item["created_at"]))

    def save_payload_signature(self, signature: dict[str, Any]) -> dict[str, Any]:
        return self._put("payload_signature", signature["id"], signature)

    def get_payload_signature(self, signature_id: str) -> dict[str, Any] | None:
        return self._get("payload_signature", signature_id)

    def list_payload_signatures(self) -> list[dict[str, Any]]:
        return sorted(
            self._list("payload_signature"),
            key=lambda item: str(item["created_at"]),
        )

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        return self._put("allowlist", entry["id"], entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return self._list("allowlist")

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='allowlist' AND id=?", (entry_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any] | None:
        return self.save_export_stream(export, iter((content,)), size_hint=len(content))

    def save_export_stream(
        self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
    ) -> dict[str, Any] | None:
        if size_hint < 0:
            raise ArtifactProducerError("artifact size hint must be non-negative")
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                parent = self.connection.execute(
                    "SELECT 1 FROM objects WHERE kind='job' AND id=?",
                    (str(export["job_id"]),),
                ).fetchone()
                if parent is None:
                    self.connection.commit()
                    return None
                if (
                    self.connection.execute(
                        "SELECT 1 FROM objects WHERE kind='export' AND id=?", (export["id"],)
                    ).fetchone()
                    is not None
                ):
                    raise ArtifactAlreadyExistsError(f"export already exists: {export['id']}")
                self.connection.execute(
                    "INSERT INTO objects(kind,id,data) VALUES('export',?,?)",
                    (export["id"], self._serialize(export)),
                )
                self.connection.execute(
                    "INSERT INTO export_blobs(export_id,content) VALUES(?,zeroblob(?))",
                    (export["id"], size_hint),
                )
                row = self.connection.execute(
                    "SELECT rowid FROM export_blobs WHERE export_id=?", (export["id"],)
                ).fetchone()
                if row is None:
                    raise ArtifactStorageError("artifact blob row disappeared")
                digest = hashlib.sha256()
                size = 0
                blob = self.connection.blobopen(
                    "export_blobs", "content", int(row[0]), readonly=False
                )
                stream_error: Exception | None = None
                try:
                    iterator = iter(chunks)
                    while True:
                        try:
                            chunk = next(iterator)
                        except StopIteration:
                            break
                        except Exception as exc:
                            raise ArtifactProducerError("artifact producer failed") from exc
                        if type(chunk) is not bytes:
                            raise ArtifactProducerError(
                                "artifact chunks must be exact bytes values"
                            )
                        if not chunk:
                            continue
                        size += len(chunk)
                        if size > size_hint:
                            raise ArtifactProducerError(
                                "artifact producer yielded more than size hint"
                            )
                        try:
                            blob.write(chunk)
                        except Exception as exc:
                            raise ArtifactStorageError("SQLite artifact blob write failed") from exc
                        digest.update(chunk)
                except Exception as exc:
                    stream_error = exc
                try:
                    blob.close()
                except Exception as exc:
                    if stream_error is None:
                        raise ArtifactStorageError("SQLite artifact blob close failed") from exc
                if stream_error is not None:
                    raise stream_error
                if size != size_hint:
                    raise ArtifactProducerError("artifact producer ended before size hint")
                stored = {
                    **deepcopy(export),
                    "size_bytes": size,
                    "sha256": digest.hexdigest(),
                }
                self.connection.execute(
                    "UPDATE objects SET data=? WHERE kind='export' AND id=?",
                    (self._serialize(stored), export["id"]),
                )
                self.connection.commit()
                return deepcopy(stored)
            except (ArtifactProducerError, ArtifactAlreadyExistsError):
                self.connection.rollback()
                raise
            except Exception as exc:
                self.connection.rollback()
                if isinstance(exc, ArtifactStorageError):
                    raise
                raise ArtifactStorageError("SQLite artifact persistence failed") from exc

    def get_export_metadata(self, export_id: str) -> dict[str, Any] | None:
        try:
            metadata = self._get("export", export_id)
            return None if metadata is not None and metadata.get("published") is False else metadata
        except ArtifactStorageError:
            raise
        except Exception as exc:
            raise ArtifactStorageError("SQLite export metadata lookup failed") from exc

    def open_export_stream(
        self, export_id: str
    ) -> tuple[dict[str, Any], AbstractContextManager[Iterator[bytes]]] | None:
        try:
            with self._lock:
                metadata = self._get("export", export_id)
                if metadata is not None and metadata.get("published") is False:
                    return None
                if metadata is None:
                    return None
                row = self.connection.execute(
                    "SELECT rowid FROM export_blobs WHERE export_id=?", (export_id,)
                ).fetchone()
                if row is None:
                    raise ArtifactMissingError(f"artifact content is missing: {export_id}")
                rowid = int(row[0])
        except ArtifactMissingError:
            raise
        except ArtifactStorageError:
            raise
        except Exception as exc:
            raise ArtifactStorageError("SQLite export stream resolution failed") from exc

        @contextmanager
        def opened() -> Iterator[Iterator[bytes]]:
            self._lock.acquire()
            blob: Any = None
            lock_held = True
            closed = False

            def close() -> None:
                nonlocal closed, lock_held
                if closed:
                    return
                closed = True
                failure: Exception | None = None
                try:
                    if blob is not None:
                        blob.close()
                except Exception as exc:
                    failure = exc
                finally:
                    if lock_held:
                        lock_held = False
                        self._lock.release()
                if failure is not None:
                    raise ArtifactStorageError("SQLite artifact blob close failed") from failure

            class OwnedIterator(Iterator[bytes]):
                def __next__(self) -> bytes:
                    if closed:
                        raise StopIteration
                    try:
                        chunk = blob.read(_DEFAULT_ARTIFACT_CHUNK_SIZE)
                        if type(chunk) is not bytes:
                            raise ArtifactStorageError(
                                "SQLite artifact reader returned a non-bytes chunk"
                            )
                        if not chunk:
                            close()
                            raise StopIteration
                        return chunk
                    except StopIteration:
                        raise
                    except ArtifactStorageError:
                        try:
                            close()
                        except ArtifactStorageError:
                            pass
                        raise
                    except Exception as exc:
                        try:
                            close()
                        except ArtifactStorageError:
                            pass
                        raise ArtifactStorageError("SQLite artifact read failed") from exc

                def close(self) -> None:
                    close()

            try:
                blob = self.connection.blobopen("export_blobs", "content", rowid, readonly=True)
                owned = OwnedIterator()
                try:
                    yield owned
                except BaseException:
                    try:
                        owned.close()
                    except ArtifactStorageError:
                        pass
                    raise
                else:
                    owned.close()
            except ArtifactError:
                raise
            except Exception as exc:
                try:
                    close()
                except ArtifactStorageError:
                    pass
                raise ArtifactStorageError("SQLite artifact read failed") from exc
            finally:
                if not closed:
                    close()

        return metadata, opened()

    def get_export(self, export_id: str) -> tuple[dict[str, Any], bytes] | None:
        opened = self.open_export_stream(export_id)
        if opened is None:
            return None
        metadata, stream = opened
        with stream as chunks:
            return metadata, b"".join(chunks)

    def save_sensor_pcap(self, segment: dict[str, Any], content: bytes) -> dict[str, Any]:
        stored, status = self.save_sensor_pcap_limited(segment, content, None)
        if stored is None or status not in {"OK", "EXISTS"}:
            raise RuntimeError(f"sensor PCAP save failed: {status}")
        return stored

    def save_sensor_pcap_limited(
        self,
        segment: dict[str, Any],
        content: bytes,
        max_total_bytes: int | None,
        *,
        require_open_job: bool = False,
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                analysis_job_id = segment.get("analysis_job_id")
                job_row = (
                    self.connection.execute(
                        "SELECT data FROM objects WHERE kind='job' AND id=?",
                        (analysis_job_id,),
                    ).fetchone()
                    if analysis_job_id is not None
                    else None
                )
                job = json.loads(job_row[0]) if job_row is not None else None
                if require_open_job and analysis_job_id is not None:
                    if job is None or job.get("status") in _JOB_TERMINAL_STATUSES:
                        self.connection.commit()
                        return None, "JOB_CLOSED"
                row = self.connection.execute(
                    "SELECT data FROM objects WHERE kind='sensor_pcap' AND id=?",
                    (segment["id"],),
                ).fetchone()
                if row is not None:
                    existing = json.loads(row[0])
                    matches = all(
                        existing.get(field) == segment.get(field)
                        for field in ("sensor_id", "analysis_job_id", "sha256")
                    )
                    self.connection.commit()
                    return (existing, "EXISTS") if matches else (None, "CONFLICT")
                if max_total_bytes is not None and analysis_job_id is not None:
                    used_row = self.connection.execute(
                        "SELECT COALESCE("
                        "SUM(CAST(json_extract(data, '$.size_bytes') AS INTEGER)),0) "
                        "FROM objects WHERE kind='sensor_pcap' "
                        "AND json_extract(data, '$.analysis_job_id')=?",
                        (analysis_job_id,),
                    ).fetchone()
                    used = int(used_row[0] if used_row else 0)
                    if used + len(content) > max_total_bytes:
                        self.connection.commit()
                        return None, "LIMIT"
                stored = deepcopy(segment)
                if eligible_live_segment(job, stored):
                    stored["index_requested_at"] = datetime.now().astimezone().isoformat()
                    stored["index_intent_state"] = "PENDING"
                    stored["index_intent_schema_version"] = PCAP_OFFSET_INDEX_SCHEMA_VERSION
                    stored["index_intent_parser_contract_version"] = (
                        PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION
                    )
                self.connection.execute(
                    "INSERT INTO objects(kind,id,data) VALUES('sensor_pcap',?,?)",
                    (segment["id"], self._serialize(stored)),
                )
                self.connection.execute(
                    "INSERT INTO sensor_pcap_blobs(segment_id,content) VALUES(?,?)",
                    (segment["id"], content),
                )
                self.connection.commit()
                return deepcopy(stored), "OK"
            except Exception:
                self.connection.rollback()
                raise

    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None:
        opened = self.open_sensor_pcap(segment_id)
        if opened is None:
            return None
        metadata, source = opened
        with source:
            return metadata, b"".join(source.iter_chunks())

    def open_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], CaptureSource] | None:
        with self._lock:
            row = self.connection.execute(
                "SELECT objects.data,sensor_pcap_blobs.content FROM objects "
                "JOIN sensor_pcap_blobs ON sensor_pcap_blobs.segment_id=objects.id "
                "WHERE objects.kind='sensor_pcap' AND objects.id=?",
                (segment_id,),
            ).fetchone()
            if row is None:
                return None
            return json.loads(row[0]), _bytes_source(bytes(row[1]))

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        return self._list("sensor_pcap")

    def list_sensor_pcaps_for_job(self, job_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self.connection.execute(
                "SELECT data FROM objects WHERE kind='sensor_pcap' "
                "AND json_extract(data, '$.analysis_job_id')=? "
                "ORDER BY json_extract(data, '$.uploaded_at'),id",
                (job_id,),
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self._put("enrollment", enrollment["enrollment_id"], enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        return self._get("enrollment", enrollment_id)

    def list_enrollments(self) -> list[dict[str, Any]]:
        return self._list("enrollment")

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            row = self.connection.execute(
                "SELECT id,data FROM objects WHERE kind='enrollment' "
                "AND json_extract(data, '$.token_hash')=?",
                (token_hash,),
            ).fetchone()
            if row is None:
                return None, "NOT_FOUND"
            enrollment = json.loads(row[1])
            if enrollment.get("revoked_at") is not None:
                return enrollment, "REVOKED"
            if enrollment.get("claimed_at") is not None:
                return enrollment, "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                return enrollment, "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            self._put("enrollment", str(row[0]), enrollment)
            return enrollment, "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor_credential", credential["sensor_id"], credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor_credential", sensor_id)

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock:
            sensor = self.get_sensor(sensor_id)
            if sensor is None:
                return None, "NOT_FOUND"
            if sensor.get("config_version") != expected_version:
                return sensor, "CONFLICT"
            sensor.update(configuration)
            sensor["config_version"] = expected_version + 1
            return self.upsert_sensor(sensor), "OK"

    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None:
        with self._lock:
            sensor = self.get_sensor(sensor_id)
            if sensor is None:
                return None
            sensor.update(fields)
            return self.upsert_sensor(sensor)

    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            try:
                if preset.get("is_default"):
                    rows = self.connection.execute(
                        "SELECT id,data FROM objects WHERE kind='detector_weight_preset'"
                    ).fetchall()
                    for object_id, raw in rows:
                        item = json.loads(raw)
                        item["is_default"] = False
                        self.connection.execute(
                            "UPDATE objects SET data=? "
                            "WHERE kind='detector_weight_preset' AND id=?",
                            (self._serialize(item), object_id),
                        )
                self.connection.execute(
                    "INSERT INTO objects(kind,id,data) VALUES(?,?,?) "
                    "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                    ("detector_weight_preset", preset["id"], self._serialize(preset)),
                )
                self.connection.commit()
            except Exception:
                self.connection.rollback()
                raise
            return deepcopy(preset)

    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        return self._get("detector_weight_preset", preset_id)

    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None:
        with self._lock:
            try:
                preset = self.get_detector_weight_preset(preset_id)
                if preset is None:
                    return None
                preset.update(updates)
                if set_as_default:
                    rows = self.connection.execute(
                        "SELECT id,data FROM objects WHERE kind='detector_weight_preset'"
                    ).fetchall()
                    for object_id, raw in rows:
                        item = json.loads(raw)
                        item["is_default"] = object_id == preset_id
                        if object_id == preset_id:
                            item.update(updates)
                            preset = item
                        self.connection.execute(
                            "UPDATE objects SET data=? "
                            "WHERE kind='detector_weight_preset' AND id=?",
                            (self._serialize(item), object_id),
                        )
                else:
                    self.connection.execute(
                        "UPDATE objects SET data=? WHERE kind='detector_weight_preset' AND id=?",
                        (self._serialize(preset), preset_id),
                    )
                self.connection.commit()
                return deepcopy(preset)
            except Exception:
                self.connection.rollback()
                raise

    def list_detector_weight_presets(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._list("detector_weight_preset")

    def delete_detector_weight_preset(self, preset_id: str) -> bool:
        with self._lock:
            cursor = self.connection.execute(
                "DELETE FROM objects WHERE kind='detector_weight_preset' AND id=?", (preset_id,)
            )
            self.connection.commit()
            return cursor.rowcount > 0

    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        with self._lock:
            try:
                selected = self.get_detector_weight_preset(preset_id)
                if selected is None:
                    return None
                presets = self.list_detector_weight_presets()
                for preset in presets:
                    preset["is_default"] = preset["id"] == preset_id
                    self.connection.execute(
                        "UPDATE objects SET data=? WHERE kind='detector_weight_preset' AND id=?",
                        (self._serialize(preset), preset["id"]),
                    )
                self.connection.commit()
                return next(preset for preset in presets if preset["id"] == preset_id)
            except Exception:
                self.connection.rollback()
                raise
