from __future__ import annotations

import json
import re
import secrets
from copy import deepcopy
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Literal, TypeGuard

from c2hunter_analysis.pcap_index import (
    PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_OFFSET_INDEX_SCHEMA_VERSION,
)
from c2hunter_analysis.pcap_postings import (
    PCAP_FILTER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
    PCAP_POSTING_INDEX_SCHEMA_VERSION,
)

from .pcap_offset_index import (
    CaptureSourceVersion,
    StructuralIndexSnapshot,
    validate_structural_index,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CODE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class PostingIndexQueueError(RuntimeError):
    """Stable posting queue error containing no source or exception details."""

    def __init__(self, code: str) -> None:
        super().__init__(sanitize_error_code(code))
        self.code = sanitize_error_code(code)


class PostingIndexQueuePermanentError(PostingIndexQueueError):
    pass


class PostingIndexQueueTransientError(PostingIndexQueueError):
    pass


class PostingIndexAdmission(str, Enum):
    QUEUED = "QUEUED"
    COALESCED = "COALESCED"
    DEFERRED = "DEFERRED"
    INELIGIBLE = "INELIGIBLE"


class PostingIndexIntentStatus(str, Enum):
    PENDING = "PENDING"
    DEFERRED = "DEFERRED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class PostingIndexTaskStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


type PostingSourceKind = Literal["PCAP_UPLOAD", "LIVE_SEGMENT"]


def is_posting_source_kind(value: object) -> TypeGuard[PostingSourceKind]:
    return value in {"PCAP_UPLOAD", "LIVE_SEGMENT"}


@dataclass(frozen=True)
class PostingIndexTaskSpec:
    source_kind: PostingSourceKind
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
            or not _SHA256.fullmatch(self.source_sha256)
            or self.capture_format not in {"PCAP", "PCAPNG"}
            or self.source_kind == "LIVE_SEGMENT"
            and self.capture_format != "PCAP"
            or not self.parent_structural_build_id
            or not _SHA256.fullmatch(self.parent_structural_index_sha256)
            or min(
                self.structural_schema_version,
                self.structural_parser_contract_version,
                self.posting_schema_version,
                self.posting_parser_contract_version,
                self.filter_contract_version,
            )
            <= 0
        ):
            raise ValueError("invalid posting index task specification")

    @property
    def identity(self) -> tuple[str, str, str, str, int, int, int]:
        return (
            self.source_kind,
            self.source_id,
            self.source_version_id,
            self.parent_structural_build_id,
            self.posting_schema_version,
            self.posting_parser_contract_version,
            self.filter_contract_version,
        )

    @classmethod
    def from_binding(
        cls, source: CaptureSourceVersion, parent: StructuralIndexSnapshot
    ) -> PostingIndexTaskSpec:
        return cls(
            source.source_kind,
            source.source_id,
            source.source_version_id,
            source.source_size_bytes,
            source.source_sha256,
            parent.binding.capture_format,
            parent.build_id,
            parent.index_sha256,
            parent.binding.schema_version,
            parent.binding.parser_contract_version,
        )


@dataclass(frozen=True)
class PostingIndexIntent:
    spec: PostingIndexTaskSpec
    status: PostingIndexIntentStatus
    requested_at: datetime
    updated_at: datetime | None = None
    published_build_id: str | None = None
    error_code: str | None = None


@dataclass(frozen=True)
class PostingIndexTask:
    spec: PostingIndexTaskSpec
    status: PostingIndexTaskStatus
    attempt: int
    max_attempts: int
    lease_token: str | None
    lease_expires_at: datetime | None
    next_attempt_at: datetime
    queued_at: datetime
    updated_at: datetime
    error_code: str | None = None


_ELIGIBLE_INTENTS = {PostingIndexIntentStatus.PENDING, PostingIndexIntentStatus.DEFERRED}
_TERMINAL_INTENTS = {PostingIndexIntentStatus.COMPLETED, PostingIndexIntentStatus.FAILED}
_ACTIVE_TASKS = {PostingIndexTaskStatus.QUEUED, PostingIndexTaskStatus.RUNNING}
_TERMINAL_TASKS = {PostingIndexTaskStatus.COMPLETED, PostingIndexTaskStatus.FAILED}


def sanitize_error_code(value: object, *, fallback: str = "POSTING_BUILD_FAILED") -> str:
    candidate = str(value)
    return candidate if _ERROR_CODE.fullmatch(candidate) else fallback


def _posting_now(repository: Any) -> datetime:
    """Return the sole repository-owned clock for durable posting lifecycle state."""
    value: datetime = repository._posting_now()
    if value.utcoffset() is None:
        raise ValueError("posting lifecycle clock must be timezone-aware")
    return value.astimezone(UTC)


def _source_key(spec: PostingIndexTaskSpec) -> tuple[PostingSourceKind, str]:
    return spec.source_kind, spec.source_id


def _memory_source(repository: Any, spec: PostingIndexTaskSpec) -> CaptureSourceVersion | None:
    key = spec.source_id if spec.source_kind == "PCAP_UPLOAD" else f"LIVE_SEGMENT:{spec.source_id}"
    source: CaptureSourceVersion | None = repository.capture_source_versions.get(key)
    return source


def eligible_posting_index(
    repository: Any, source: CaptureSourceVersion, parent: StructuralIndexSnapshot
) -> bool:
    if source.source_kind not in {"PCAP_UPLOAD", "LIVE_SEGMENT"}:
        return False
    try:
        spec = PostingIndexTaskSpec.from_binding(source, parent)
    except ValueError:
        return False
    if not validate_structural_index(parent) or parent.binding.source_kind != source.source_kind:
        return False
    if (
        parent.binding.source_id != source.source_id
        or parent.binding.source_version_id != source.source_version_id
        or parent.binding.source_size_bytes != source.source_size_bytes
        or parent.binding.source_sha256 != source.source_sha256
    ):
        return False
    if hasattr(repository, "connection"):
        source_row = repository.connection.execute(
            "SELECT source_version_id,source_size_bytes,source_sha256 FROM "
            "pcap_capture_source_versions WHERE source_kind=? AND source_id=?",
            _source_key(spec),
        ).fetchone()
        owner = repository.connection.execute(
            "SELECT g.index_sha256,g.state FROM pcap_offset_index_owners o "
            "JOIN pcap_offset_index_generations g ON g.build_id=o.build_id "
            "WHERE o.source_kind=? AND o.source_id=? AND o.build_id=?",
            (*_source_key(spec), spec.parent_structural_build_id),
        ).fetchone()
        return bool(
            source_row
            == (
                spec.source_version_id,
                spec.source_size_bytes,
                spec.source_sha256,
            )
            and owner == (spec.parent_structural_index_sha256, "READY")
        )
    current_parent = repository.structural_index_generations.get(parent.build_id)
    return bool(
        _memory_source(repository, spec) == source
        and repository.structural_index_owners.get(_source_key(spec)) == parent.build_id
        and current_parent is not None
        and current_parent.binding == parent.binding
        and current_parent.index_sha256 == parent.index_sha256
        and current_parent.interfaces == parent.interfaces
        and current_parent.packets == parent.packets
    )


def _encode(value: PostingIndexIntent | PostingIndexTask) -> str:
    document = asdict(value)
    document["status"] = value.status.value
    for field in ("requested_at", "updated_at", "lease_expires_at", "next_attempt_at", "queued_at"):
        if field in document and document[field] is not None:
            document[field] = document[field].isoformat()
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _decode_spec(value: dict[str, Any]) -> PostingIndexTaskSpec:
    return PostingIndexTaskSpec(**value)


def decode_intent(raw: str) -> PostingIndexIntent:
    value = json.loads(raw)
    value["spec"] = _decode_spec(value["spec"])
    value["status"] = PostingIndexIntentStatus(value["status"])
    for field in ("requested_at", "updated_at"):
        if value.get(field) is not None:
            value[field] = datetime.fromisoformat(value[field])
    return PostingIndexIntent(**value)


def decode_task(raw: str) -> PostingIndexTask:
    value = json.loads(raw)
    value["spec"] = _decode_spec(value["spec"])
    value["status"] = PostingIndexTaskStatus(value["status"])
    for field in ("lease_expires_at", "next_attempt_at", "queued_at", "updated_at"):
        if value.get(field) is not None:
            value[field] = datetime.fromisoformat(value[field])
    return PostingIndexTask(**value)


def _get_intent(
    repository: Any, source_kind: PostingSourceKind, source_id: str
) -> PostingIndexIntent | None:
    if hasattr(repository, "connection"):
        row = repository.connection.execute(
            "SELECT data FROM pcap_posting_index_intents WHERE source_kind=? AND source_id=?",
            (source_kind, source_id),
        ).fetchone()
        return decode_intent(row[0]) if row else None
    intent: PostingIndexIntent | None = deepcopy(
        repository.posting_index_intents.get((source_kind, source_id))
    )
    return intent


def _put_intent(repository: Any, intent: PostingIndexIntent) -> None:
    key = _source_key(intent.spec)
    if hasattr(repository, "connection"):
        repository.connection.execute(
            "INSERT INTO pcap_posting_index_intents("
            "source_kind,source_id,parent_structural_build_id,status,requested_at,updated_at,data) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(source_kind,source_id) DO UPDATE SET "
            "parent_structural_build_id=excluded.parent_structural_build_id,status=excluded.status,"
            "requested_at=excluded.requested_at,updated_at=excluded.updated_at,data=excluded.data",
            (
                *key,
                intent.spec.parent_structural_build_id,
                intent.status.value,
                intent.requested_at.isoformat(),
                (intent.updated_at or intent.requested_at).isoformat(),
                _encode(intent),
            ),
        )
    else:
        repository.posting_index_intents[key] = intent


def _get_task(
    repository: Any, source_kind: PostingSourceKind, source_id: str
) -> PostingIndexTask | None:
    if hasattr(repository, "connection"):
        row = repository.connection.execute(
            "SELECT data FROM pcap_posting_index_jobs WHERE source_kind=? AND source_id=?",
            (source_kind, source_id),
        ).fetchone()
        return decode_task(row[0]) if row else None
    task: PostingIndexTask | None = deepcopy(
        repository.posting_index_tasks.get((source_kind, source_id))
    )
    return task


def _put_task(repository: Any, task: PostingIndexTask) -> None:
    key = _source_key(task.spec)
    if hasattr(repository, "connection"):
        repository.connection.execute(
            "INSERT INTO pcap_posting_index_jobs("
            "source_kind,source_id,parent_structural_build_id,status,attempt,lease_token,"
            "lease_expires_at,next_attempt_at,queued_at,updated_at,data) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(source_kind,source_id) DO UPDATE SET "
            "parent_structural_build_id=excluded.parent_structural_build_id,status=excluded.status,"
            "attempt=excluded.attempt,lease_token=excluded.lease_token,"
            "lease_expires_at=excluded.lease_expires_at,next_attempt_at=excluded.next_attempt_at,"
            "queued_at=excluded.queued_at,updated_at=excluded.updated_at,data=excluded.data",
            (
                *key,
                task.spec.parent_structural_build_id,
                task.status.value,
                task.attempt,
                task.lease_token,
                task.lease_expires_at.isoformat() if task.lease_expires_at else None,
                task.next_attempt_at.isoformat(),
                task.queued_at.isoformat(),
                task.updated_at.isoformat(),
                _encode(task),
            ),
        )
    else:
        repository.posting_index_tasks[key] = task


def _transaction(repository: Any) -> bool:
    if hasattr(repository, "connection"):
        repository.connection.execute("BEGIN IMMEDIATE")
        return True
    return False


def _finish(repository: Any, sqlite: bool, *, commit: bool) -> None:
    if sqlite:
        repository.connection.commit() if commit else repository.connection.rollback()


def request(
    repository: Any,
    source: CaptureSourceVersion,
    parent: StructuralIndexSnapshot,
    *,
    requested_at: datetime | None = None,
) -> PostingIndexIntent | None:
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            if not eligible_posting_index(repository, source, parent):
                _finish(repository, sqlite, commit=False)
                return None
            spec = PostingIndexTaskSpec.from_binding(source, parent)
            current = _get_intent(repository, spec.source_kind, spec.source_id)
            if current is not None and current.spec.identity == spec.identity:
                _finish(repository, sqlite, commit=True)
                return current
            # A new structural parent supersedes only its source's old lifecycle.
            if _get_task(repository, spec.source_kind, spec.source_id) is not None:
                if sqlite:
                    repository.connection.execute(
                        "DELETE FROM pcap_posting_index_jobs WHERE source_kind=? AND source_id=?",
                        _source_key(spec),
                    )
                else:
                    repository.posting_index_tasks.pop(_source_key(spec), None)
            # Compatibility timestamps are informational; persistence uses repository time.
            at = _posting_now(repository)
            intent = PostingIndexIntent(spec, PostingIndexIntentStatus.PENDING, at, at)
            _put_intent(repository, intent)
            _finish(repository, sqlite, commit=True)
            return intent
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


_SQLITE_POSTING_BACKFILL_SELECT = """
SELECT source.source_kind,
       source.source_id,
       source.source_version_id,
       source.source_size_bytes,
       source.source_sha256,
       generation.binding,
       owner.build_id,
       generation.index_sha256
FROM pcap_offset_index_owners AS owner
JOIN pcap_offset_index_generations AS generation
  ON generation.build_id=owner.build_id
JOIN pcap_capture_source_versions AS source
  ON source.source_kind=owner.source_kind
 AND source.source_id=owner.source_id
WHERE generation.state='READY'
  AND generation.source_kind=source.source_kind
  AND generation.source_id=source.source_id
  AND json_extract(generation.binding,'$.source_version_id')=source.source_version_id
  AND CAST(json_extract(generation.binding,'$.source_size_bytes') AS INTEGER)=
      source.source_size_bytes
  AND json_extract(generation.binding,'$.source_sha256')=source.source_sha256
  AND CAST(json_extract(generation.binding,'$.schema_version') AS INTEGER)=?
  AND CAST(json_extract(generation.binding,'$.parser_contract_version') AS INTEGER)=?
  AND (
    (
      source.source_kind='PCAP_UPLOAD'
      AND EXISTS (
        SELECT 1 FROM objects AS job
        WHERE job.kind='job'
          AND job.id=source.source_id
          AND json_extract(job.data,'$.mode')='PCAP_UPLOAD'
      )
    )
    OR
    (
      source.source_kind='LIVE_SEGMENT'
      AND EXISTS (
        SELECT 1
        FROM objects AS segment
        JOIN objects AS job
          ON job.kind='job'
         AND job.id=json_extract(segment.data,'$.analysis_job_id')
        WHERE segment.kind='sensor_pcap'
          AND segment.id=source.source_id
          AND json_extract(job.data,'$.mode')='LIVE'
      )
      AND EXISTS (
        SELECT 1 FROM pcap_offset_index_jobs AS live_task
        WHERE live_task.source_kind='LIVE_SEGMENT'
          AND live_task.source_id=source.source_id
          AND live_task.status='COMPLETED'
      )
    )
  )
  AND NOT EXISTS (
    SELECT 1 FROM pcap_posting_index_intents AS intent
    WHERE intent.source_kind=source.source_kind
      AND intent.source_id=source.source_id
      AND intent.parent_structural_build_id=owner.build_id
      AND json_extract(intent.data,'$.spec.source_version_id')=source.source_version_id
      AND CAST(
        json_extract(intent.data,'$.spec.posting_schema_version') AS INTEGER
      )=?
      AND CAST(
        json_extract(intent.data,'$.spec.posting_parser_contract_version') AS INTEGER
      )=?
      AND CAST(
        json_extract(intent.data,'$.spec.filter_contract_version') AS INTEGER
      )=?
  )
  AND NOT EXISTS (
    SELECT 1 FROM pcap_posting_index_jobs AS task
    WHERE task.source_kind=source.source_kind
      AND task.source_id=source.source_id
      AND task.parent_structural_build_id=owner.build_id
  )
  AND NOT EXISTS (
    SELECT 1
    FROM pcap_posting_index_owners AS posting_owner
    JOIN pcap_posting_index_generations AS posting_generation
      ON posting_generation.build_id=posting_owner.build_id
    WHERE posting_owner.source_kind=source.source_kind
      AND posting_owner.source_id=source.source_id
      AND posting_owner.parent_structural_build_id=owner.build_id
      AND posting_generation.state='READY'
      AND json_extract(
        posting_generation.binding,'$.source_version_id'
      )=source.source_version_id
      AND CAST(
        json_extract(posting_generation.binding,'$.posting_schema_version') AS INTEGER
      )=?
      AND CAST(
        json_extract(
          posting_generation.binding,'$.posting_parser_contract_version'
        ) AS INTEGER
      )=?
      AND CAST(
        json_extract(posting_generation.binding,'$.filter_contract_version') AS INTEGER
      )=?
  )
ORDER BY source.source_kind,source.source_id
LIMIT ?
"""


def request_backfill(repository: Any, *, limit: int) -> int:
    """Persist a bounded set of missing current posting intents, but no queue tasks."""

    if limit <= 0:
        raise ValueError("posting backfill limit must be positive")
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            candidates: list[PostingIndexTaskSpec]
            if hasattr(repository, "connection"):
                # Eligibility and every absence predicate precede deterministic LIMIT.
                rows = repository.connection.execute(
                    _SQLITE_POSTING_BACKFILL_SELECT,
                    (
                        PCAP_OFFSET_INDEX_SCHEMA_VERSION,
                        PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION,
                        PCAP_POSTING_INDEX_SCHEMA_VERSION,
                        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
                        PCAP_FILTER_CONTRACT_VERSION,
                        PCAP_POSTING_INDEX_SCHEMA_VERSION,
                        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
                        PCAP_FILTER_CONTRACT_VERSION,
                        limit,
                    ),
                ).fetchall()
                candidates = []
                for row in rows:
                    binding = json.loads(row[5])
                    candidates.append(
                        PostingIndexTaskSpec(
                            row[0],
                            row[1],
                            row[2],
                            int(row[3]),
                            row[4],
                            binding["capture_format"],
                            row[6],
                            row[7],
                            int(binding["schema_version"]),
                            int(binding["parser_contract_version"]),
                        )
                    )
            else:
                candidates = []
                for key, build_id in repository.structural_index_owners.items():
                    if (
                        not isinstance(key, tuple)
                        or len(key) != 2
                        or not is_posting_source_kind(key[0])
                    ):
                        continue
                    source_kind, source_id = key
                    parent = repository.structural_index_generations.get(build_id)
                    source_key = (
                        source_id if source_kind == "PCAP_UPLOAD" else f"LIVE_SEGMENT:{source_id}"
                    )
                    source = repository.capture_source_versions.get(source_key)
                    if (
                        source is None
                        or parent is None
                        or not eligible_posting_index(repository, source, parent)
                    ):
                        continue
                    if source_kind == "PCAP_UPLOAD":
                        if repository.jobs.get(source_id, {}).get("mode") != "PCAP_UPLOAD":
                            continue
                    else:
                        live_task = repository.live_segment_index_tasks.get(source_id)
                        segment = repository.sensor_pcaps.get(source_id)
                        live_job = (
                            repository.jobs.get(str(segment.get("analysis_job_id")))
                            if segment is not None
                            else None
                        )
                        if (
                            live_task is None
                            or live_task.status != "COMPLETED"
                            or live_job is None
                            or live_job.get("mode") != "LIVE"
                        ):
                            continue
                    spec = PostingIndexTaskSpec.from_binding(source, parent)
                    intent = repository.posting_index_intents.get((source_kind, source_id))
                    task = repository.posting_index_tasks.get((source_kind, source_id))
                    posting_build_id = repository.posting_index_owners.get(
                        (source_kind, source_id, parent.build_id)
                    )
                    ready = repository.posting_index_generations.get(posting_build_id)
                    ready_binding = getattr(ready, "binding", None)
                    if (
                        intent is not None
                        and intent.spec.identity == spec.identity
                        or task is not None
                        and task.spec.identity == spec.identity
                        or ready_binding is not None
                        and (
                            ready_binding.source_version_id,
                            ready_binding.parent_structural_build_id,
                            ready_binding.posting_schema_version,
                            ready_binding.posting_parser_contract_version,
                            ready_binding.filter_contract_version,
                        )
                        == (
                            spec.source_version_id,
                            spec.parent_structural_build_id,
                            spec.posting_schema_version,
                            spec.posting_parser_contract_version,
                            spec.filter_contract_version,
                        )
                    ):
                        continue
                    candidates.append(spec)
                candidates.sort(key=lambda item: (item.source_kind, item.source_id))
                candidates = candidates[:limit]
            at = _posting_now(repository)
            for spec in candidates:
                _put_intent(
                    repository,
                    PostingIndexIntent(spec, PostingIndexIntentStatus.PENDING, at, at),
                )
            _finish(repository, sqlite, commit=True)
            return len(candidates)
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


def admit(
    repository: Any,
    source_kind: PostingSourceKind,
    source_id: str,
    *,
    capacity: int,
    max_attempts: int,
    now: datetime | None = None,
) -> PostingIndexAdmission:
    if capacity <= 0 or max_attempts <= 0:
        raise ValueError("posting queue bounds must be positive")
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            intent = _get_intent(repository, source_kind, source_id)
            task = _get_task(repository, source_kind, source_id)
            # Coalescing and terminal idempotency always precede capacity.
            if task is not None or intent is not None and intent.status in _TERMINAL_INTENTS:
                _finish(repository, sqlite, commit=True)
                return PostingIndexAdmission.COALESCED
            if intent is None or intent.status not in _ELIGIBLE_INTENTS:
                _finish(repository, sqlite, commit=True)
                return PostingIndexAdmission.INELIGIBLE
            if hasattr(repository, "connection"):
                active = repository.connection.execute(
                    "SELECT COUNT(*) FROM pcap_posting_index_jobs "
                    "WHERE status IN ('QUEUED','RUNNING')"
                ).fetchone()[0]
            else:
                active = sum(
                    task.status in _ACTIVE_TASKS for task in repository.posting_index_tasks.values()
                )
            # Compatibility timestamps are informational; persistence uses repository time.
            at = _posting_now(repository)
            if int(active) >= capacity:
                _put_intent(
                    repository,
                    replace(intent, status=PostingIndexIntentStatus.DEFERRED, updated_at=at),
                )
                _finish(repository, sqlite, commit=True)
                return PostingIndexAdmission.DEFERRED
            _put_task(
                repository,
                PostingIndexTask(
                    intent.spec,
                    PostingIndexTaskStatus.QUEUED,
                    0,
                    max_attempts,
                    None,
                    None,
                    at,
                    at,
                    at,
                ),
            )
            _put_intent(
                repository, replace(intent, status=PostingIndexIntentStatus.PENDING, updated_at=at)
            )
            _finish(repository, sqlite, commit=True)
            return PostingIndexAdmission.QUEUED
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


def claim(
    repository: Any, *, now: datetime | None = None, lease_seconds: int
) -> PostingIndexTask | None:
    if lease_seconds <= 0:
        raise ValueError("posting lease must be positive")
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            authoritative_now = _posting_now(repository)
            if hasattr(repository, "connection"):
                row = repository.connection.execute(
                    "SELECT data FROM pcap_posting_index_jobs j WHERE j.status='QUEUED' "
                    "AND j.next_attempt_at<=? AND EXISTS (SELECT 1 FROM "
                    "pcap_posting_index_intents i "
                    "WHERE i.source_kind=j.source_kind AND i.source_id=j.source_id "
                    "AND i.parent_structural_build_id=j.parent_structural_build_id "
                    "AND i.status IN ('PENDING','DEFERRED')) "
                    "ORDER BY j.next_attempt_at,j.queued_at,j.source_kind,j.source_id LIMIT 1",
                    (authoritative_now.isoformat(),),
                ).fetchone()
                current = decode_task(row[0]) if row else None
            else:
                candidates = [
                    task
                    for task in repository.posting_index_tasks.values()
                    if task.status is PostingIndexTaskStatus.QUEUED
                    and task.next_attempt_at <= authoritative_now
                    and (intent := repository.posting_index_intents.get(_source_key(task.spec)))
                    is not None
                    and intent.spec.identity == task.spec.identity
                    and intent.status in _ELIGIBLE_INTENTS
                ]
                current = min(
                    candidates,
                    key=lambda item: (
                        item.next_attempt_at,
                        item.queued_at,
                        item.spec.source_kind,
                        item.spec.source_id,
                    ),
                    default=None,
                )
            if current is None:
                _finish(repository, sqlite, commit=True)
                return None
            claimed = replace(
                current,
                status=PostingIndexTaskStatus.RUNNING,
                attempt=current.attempt + 1,
                lease_token=secrets.token_hex(16),
                lease_expires_at=authoritative_now + timedelta(seconds=lease_seconds),
                updated_at=authoritative_now,
            )
            _put_task(repository, claimed)
            _finish(repository, sqlite, commit=True)
            return claimed
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


def heartbeat(
    repository: Any,
    source_kind: PostingSourceKind,
    source_id: str,
    *,
    attempt: int,
    lease_token: str,
    now: datetime | None = None,
    lease_seconds: int,
) -> bool:
    if lease_seconds <= 0:
        raise ValueError("posting lease must be positive")
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            authoritative_now = _posting_now(repository)
            task = _get_task(repository, source_kind, source_id)
            if not owns_unexpired(
                task,
                attempt=attempt,
                lease_token=lease_token,
                now=authoritative_now,
            ):
                _finish(repository, sqlite, commit=False)
                return False
            if task is None:
                _finish(repository, sqlite, commit=False)
                return False
            _put_task(
                repository,
                replace(
                    task,
                    lease_expires_at=authoritative_now + timedelta(seconds=lease_seconds),
                    updated_at=authoritative_now,
                ),
            )
            _finish(repository, sqlite, commit=True)
            return True
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


def owns_unexpired(
    task: PostingIndexTask | None, *, attempt: int, lease_token: str, now: datetime
) -> bool:
    return bool(
        task is not None
        and task.status is PostingIndexTaskStatus.RUNNING
        and task.attempt == attempt
        and task.lease_token == lease_token
        and task.lease_expires_at is not None
        and task.lease_expires_at > now
    )


def fail(
    repository: Any,
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
    if retry_base_seconds <= 0:
        raise ValueError("posting retry base must be positive")
    code = sanitize_error_code(error_code)
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            authoritative_now = _posting_now(repository)
            task = _get_task(repository, source_kind, source_id)
            if not owns_unexpired(
                task,
                attempt=attempt,
                lease_token=lease_token,
                now=authoritative_now,
            ):
                _finish(repository, sqlite, commit=False)
                return False
            if task is None:
                _finish(repository, sqlite, commit=False)
                return False
            retry = transient and task.attempt < task.max_attempts
            status = PostingIndexTaskStatus.QUEUED if retry else PostingIndexTaskStatus.FAILED
            _put_task(
                repository,
                replace(
                    task,
                    status=status,
                    lease_token=None,
                    lease_expires_at=None,
                    next_attempt_at=(
                        authoritative_now
                        + timedelta(seconds=retry_base_seconds * 2 ** max(task.attempt - 1, 0))
                        if retry
                        else task.next_attempt_at
                    ),
                    updated_at=authoritative_now,
                    error_code=code,
                ),
            )
            intent = _get_intent(repository, source_kind, source_id)
            if intent is not None and intent.spec.identity == task.spec.identity:
                _put_intent(
                    repository,
                    replace(
                        intent,
                        status=(
                            PostingIndexIntentStatus.PENDING
                            if retry
                            else PostingIndexIntentStatus.FAILED
                        ),
                        updated_at=authoritative_now,
                        error_code=code,
                    ),
                )
            _finish(repository, sqlite, commit=True)
            return True
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


def recover(repository: Any, *, now: datetime | None = None) -> int:
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            authoritative_now = _posting_now(repository)
            if hasattr(repository, "connection"):
                rows = repository.connection.execute(
                    "SELECT data FROM pcap_posting_index_jobs WHERE status='RUNNING' "
                    "AND lease_expires_at<=? ORDER BY lease_expires_at,source_kind,source_id",
                    (authoritative_now.isoformat(),),
                ).fetchall()
                tasks = [decode_task(row[0]) for row in rows]
            else:
                tasks = sorted(
                    (
                        task
                        for task in repository.posting_index_tasks.values()
                        if task.status is PostingIndexTaskStatus.RUNNING
                        and task.lease_expires_at is not None
                        and task.lease_expires_at <= authoritative_now
                    ),
                    key=lambda item: (
                        item.lease_expires_at,
                        item.spec.source_kind,
                        item.spec.source_id,
                    ),
                )
            for task in tasks:
                retry = task.attempt < task.max_attempts
                _put_task(
                    repository,
                    replace(
                        task,
                        status=(
                            PostingIndexTaskStatus.QUEUED
                            if retry
                            else PostingIndexTaskStatus.FAILED
                        ),
                        lease_token=None,
                        lease_expires_at=None,
                        next_attempt_at=authoritative_now,
                        updated_at=authoritative_now,
                        error_code=None if retry else "POSTING_LEASE_EXPIRED",
                    ),
                )
                intent = _get_intent(repository, *(_source_key(task.spec)))
                if intent is not None and intent.spec.identity == task.spec.identity:
                    _put_intent(
                        repository,
                        replace(
                            intent,
                            status=(
                                PostingIndexIntentStatus.PENDING
                                if retry
                                else PostingIndexIntentStatus.FAILED
                            ),
                            updated_at=authoritative_now,
                            error_code=None if retry else "POSTING_LEASE_EXPIRED",
                        ),
                    )
            _finish(repository, sqlite, commit=True)
            return len(tasks)
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise


def queue_depth(repository: Any) -> dict[str, int]:
    statuses = tuple(PostingIndexTaskStatus)
    with repository._lock:
        if hasattr(repository, "connection"):
            rows = repository.connection.execute(
                "SELECT status,COUNT(*) FROM pcap_posting_index_jobs GROUP BY status"
            ).fetchall()
            values = {PostingIndexTaskStatus(status): int(count) for status, count in rows}
        else:
            values = {
                status: sum(
                    task.status is status for task in repository.posting_index_tasks.values()
                )
                for status in statuses
            }
    return {status.value: values.get(status, 0) for status in statuses}


def reconcile(
    repository: Any,
    *,
    capacity: int,
    max_attempts: int,
    limit: int,
    now: datetime | None = None,
) -> int:
    if limit <= 0:
        raise ValueError("posting reconciliation limit must be positive")
    with repository._lock:
        if hasattr(repository, "connection"):
            # State and NOT EXISTS filtering happen before ordering and limiting.
            rows = repository.connection.execute(
                "SELECT i.source_kind,i.source_id FROM pcap_posting_index_intents i "
                "WHERE i.status IN ('PENDING','DEFERRED') AND NOT EXISTS ("
                "SELECT 1 FROM pcap_posting_index_jobs j WHERE j.source_kind=i.source_kind "
                "AND j.source_id=i.source_id) ORDER BY "
                "i.requested_at,i.source_kind,i.source_id LIMIT ?",
                (limit,),
            ).fetchall()
            selected = [
                (kind, str(source_id)) for kind, source_id in rows if is_posting_source_kind(kind)
            ]
        else:
            selected = [
                _source_key(intent.spec)
                for intent in sorted(
                    (
                        intent
                        for key, intent in repository.posting_index_intents.items()
                        if intent.status in _ELIGIBLE_INTENTS
                        and key not in repository.posting_index_tasks
                    ),
                    key=lambda item: (
                        item.requested_at,
                        item.spec.source_kind,
                        item.spec.source_id,
                    ),
                )[:limit]
            ]
    admitted = 0
    for source_kind, source_id in selected:
        if (
            admit(
                repository,
                source_kind,
                source_id,
                capacity=capacity,
                max_attempts=max_attempts,
            )
            is PostingIndexAdmission.QUEUED
        ):
            admitted += 1
    return admitted


def cleanup_terminal(repository: Any, *, max_age_seconds: int, limit: int) -> int:
    if limit <= 0 or max_age_seconds <= 0:
        raise ValueError("posting terminal cleanup bounds must be positive")
    with repository._lock:
        sqlite = _transaction(repository)
        try:
            before = _posting_now(repository) - timedelta(seconds=max_age_seconds)
            if hasattr(repository, "connection"):
                rows = repository.connection.execute(
                    "SELECT source_kind,source_id FROM pcap_posting_index_jobs "
                    "WHERE status IN ('COMPLETED','FAILED') AND updated_at<=? "
                    "ORDER BY updated_at,source_kind,source_id LIMIT ?",
                    (before.isoformat(), limit),
                ).fetchall()
                repository.connection.executemany(
                    "DELETE FROM pcap_posting_index_jobs WHERE source_kind=? AND source_id=? "
                    "AND status IN ('COMPLETED','FAILED')",
                    rows,
                )
                count = len(rows)
            else:
                selected = sorted(
                    (
                        (key, task)
                        for key, task in repository.posting_index_tasks.items()
                        if task.status in _TERMINAL_TASKS and task.updated_at <= before
                    ),
                    key=lambda item: (item[1].updated_at, *item[0]),
                )[:limit]
                for key, _task in selected:
                    repository.posting_index_tasks.pop(key, None)
                count = len(selected)
            _finish(repository, sqlite, commit=True)
            return count
        except Exception:
            _finish(repository, sqlite, commit=False)
            raise
