from __future__ import annotations

import hashlib
import io
import json
import logging
import secrets
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import AbstractContextManager, contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, BinaryIO, cast
from uuid import uuid4

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

from c2hunter_controller.pcap_export_store import (
    TERMINAL_EXPORT_STATES,
    ExportPrincipalLimitError,
    ExportQueueFullError,
    ExportQueueStorageError,
    ExportSourceChangedError,
)
from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexLookup,
    StructuralIndexSnapshot,
    structural_index_digest,
    validate_structural_index,
)
from c2hunter_controller.pcap_offset_index_queue import (
    IndexAdmission,
    LiveIndexTask,
    LiveIndexTaskSpec,
    eligible_live_segment,
    live_index_task_status,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexBinding,
    PostingIndexIdentity,
    PostingIndexIdentityLookup,
    PostingIndexLookup,
    PostingIndexSnapshot,
    posting_index_identity_availability,
    validate_posting_index,
)
from c2hunter_controller.pcap_posting_index_queue import (
    PostingIndexAdmission,
    PostingIndexIntent,
    PostingIndexIntentStatus,
    PostingIndexTask,
    PostingIndexTaskSpec,
    PostingIndexTaskStatus,
    PostingSourceKind,
    sanitize_error_code,
)
from c2hunter_controller.repositories import (
    ArtifactAlreadyExistsError,
    ArtifactMissingError,
    ArtifactProducerError,
    ArtifactStorageError,
    ArtifactWriteResult,
    CaptureSource,
    Repository,
    _job_matches_structural_binding,
    _pcap_export_snapshot,
)

_AI_TERMINAL_STATUSES = {"COMPLETED", "FAILED", "CANCELLED"}
_JOB_TERMINAL_STATUSES = {"COMPLETED", "PARTIALLY_COMPLETED", "FAILED", "CANCELLED"}
logger = logging.getLogger(__name__)

_MISSING_OBJECT_CODES = {"NoSuchKey", "NoSuchObject", "NoSuchVersion"}


def _serialize_shared_connection[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    """Keep commit/rollback inside one facade-wide shared-connection critical section."""

    @wraps(method)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        repository = cast(Any, args[0])
        with repository._lock:
            return method(*args, **kwargs)

    return wrapped


def _is_missing_object_error(exc: Exception) -> bool:
    return isinstance(exc, FileNotFoundError | KeyError) or getattr(exc, "code", None) in (
        _MISSING_OBJECT_CODES
    )


class MinioBlobStore:
    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket: str,
    ) -> None:
        from minio import Minio

        secure = endpoint.startswith("https://")
        address = endpoint.removeprefix("https://").removeprefix("http://")
        self.client = Minio(address, access_key=access_key, secret_key=secret_key, secure=secure)
        self.bucket = bucket

    def ready(self) -> bool:
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
            return bool(self.client.bucket_exists(self.bucket))
        except Exception:
            return False

    def put(self, key: str, content: bytes) -> None:
        if not self.client.bucket_exists(self.bucket):
            self.client.make_bucket(self.bucket)
        self.client.put_object(
            self.bucket,
            key,
            io.BytesIO(content),
            len(content),
            content_type="application/vnd.tcpdump.pcap",
        )

    def put_stream(
        self,
        key: str,
        chunks: Iterable[bytes],
        *,
        size_hint: int,
        content_type: str,
    ) -> ArtifactWriteResult:
        if size_hint < 0:
            raise ArtifactProducerError("artifact size hint must be non-negative")

        class BoundedReader(io.RawIOBase):
            def __init__(self) -> None:
                self.iterator = iter(chunks)
                self.buffer = b""
                self.size = 0
                self.digest = hashlib.sha256()
                self.ended = False
                self.validated = False

            def _next(self) -> bytes:
                try:
                    chunk = next(self.iterator)
                except StopIteration:
                    self.ended = True
                    return b""
                except Exception as exc:
                    raise ArtifactProducerError("artifact producer failed") from exc
                if type(chunk) is not bytes:
                    raise ArtifactProducerError("artifact chunks must be exact bytes values")
                return chunk

            def read(self, size: int = -1) -> bytes:
                if size < 0:
                    size = max(1, size_hint - self.size)
                wanted = min(size, size_hint - self.size)
                while len(self.buffer) < wanted and not self.ended:
                    chunk = self._next()
                    if chunk:
                        self.buffer += chunk
                data, self.buffer = self.buffer[:wanted], self.buffer[wanted:]
                self.size += len(data)
                self.digest.update(data)
                return data

            def readable(self) -> bool:
                return True

            def readinto(self, buffer: Any) -> int:
                data = self.read(len(buffer))
                buffer[: len(data)] = data
                return len(data)

            def finish(self) -> ArtifactWriteResult:
                if self.size != size_hint:
                    raise ArtifactProducerError("artifact producer ended before size hint")
                if self.buffer:
                    raise ArtifactProducerError("artifact producer yielded more than size hint")
                while not self.ended:
                    chunk = self._next()
                    if chunk:
                        raise ArtifactProducerError("artifact producer yielded more than size hint")
                self.validated = True
                return ArtifactWriteResult(self.size, self.digest.hexdigest())

        bounded_reader = BoundedReader()
        reader: BinaryIO = io.BufferedReader(bounded_reader, buffer_size=1024 * 1024)
        upload_attempted = False
        try:
            if not self.client.bucket_exists(self.bucket):
                self.client.make_bucket(self.bucket)
            upload_attempted = True
            self.client.put_object(
                self.bucket,
                key,
                reader,
                size_hint,
                content_type=content_type,
                part_size=5 * 1024 * 1024,
            )
            result = bounded_reader.finish()
            try:
                remote = self.client.stat_object(self.bucket, key)
                if remote.size is None:
                    raise ArtifactStorageError("MinIO artifact size unavailable")
                remote_size = int(remote.size)
            except Exception as exc:
                try:
                    self.client.remove_object(self.bucket, key)
                except Exception:
                    logger.warning("Failed to clean up unverifiable artifact object %s", key)
                raise ArtifactStorageError("MinIO artifact verification failed") from exc
            if remote_size != result.size_bytes:
                try:
                    self.client.remove_object(self.bucket, key)
                except Exception:
                    logger.warning("Failed to clean up mismatched artifact object %s", key)
                raise ArtifactStorageError("MinIO artifact remote size mismatch")
            return result
        except ArtifactProducerError:
            raise
        except Exception as exc:
            raise ArtifactStorageError("MinIO artifact upload failed") from exc
        finally:
            if upload_attempted and not bounded_reader.validated:
                try:
                    self.client.remove_object(self.bucket, key)
                except Exception:
                    logger.warning("Failed to clean up incomplete artifact object %s", key)

    @contextmanager
    def open_stream(self, key: str, *, chunk_size: int) -> Iterator[Iterator[bytes]]:
        if chunk_size <= 0:
            raise ValueError("artifact read chunk size must be positive")
        try:
            response = self.client.get_object(self.bucket, key)
        except Exception as exc:
            if _is_missing_object_error(exc):
                raise ArtifactMissingError(f"artifact object is missing: {key}") from exc
            raise ArtifactStorageError("MinIO artifact open failed") from exc
        closed = False

        def close() -> None:
            nonlocal closed
            if closed:
                return
            closed = True
            failure: Exception | None = None
            try:
                response.close()
            except Exception as exc:
                failure = exc
            try:
                response.release_conn()
            except Exception as exc:
                if failure is None:
                    failure = exc
            if failure is not None:
                raise ArtifactStorageError("MinIO artifact stream close failed") from failure

        class OwnedIterator(Iterator[bytes]):
            def __next__(self) -> bytes:
                if closed:
                    raise StopIteration
                try:
                    chunk = response.read(chunk_size)
                    if type(chunk) is not bytes:
                        raise ArtifactStorageError(
                            "MinIO artifact reader returned a non-bytes chunk"
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
                    raise ArtifactStorageError("MinIO artifact read failed") from exc

            def close(self) -> None:
                close()

        owned = OwnedIterator()
        try:
            yield owned
        except BaseException:
            try:
                owned.close()
            except ArtifactStorageError:
                logger.debug("Artifact response cleanup failed", exc_info=True)
            raise
        else:
            owned.close()

    def get(self, key: str) -> bytes:
        source = self.open(key)
        with source:
            return b"".join(source.iter_chunks())

    def open(self, key: str) -> CaptureSource:
        response = self.client.get_object(self.bucket, key)
        try:
            headers = getattr(response, "headers", {})
            normalized_headers = {str(name).lower(): str(value) for name, value in headers.items()}
            object_version = normalized_headers.get("x-amz-version-id", "").strip()
            version_id = (
                f"s3-version:{object_version}"
                if object_version and object_version.lower() != "null"
                else None
            )
            if version_id is None:
                etag = normalized_headers.get("etag", "").strip().strip('"').strip()
                version_id = f"etag:{etag}" if etag else None
            if version_id is None:
                raise ValueError("object response lacks immutable version identity")
            release_conn = response.release_conn
            return CaptureSource(response, version_id, release_conn=release_conn)
        except Exception:
            try:
                response.close()
            except Exception:
                logger.debug(
                    "Capture response close failed during cleanup; preserving primary open error",
                    exc_info=True,
                )
            try:
                response.release_conn()
            except Exception:
                logger.debug(
                    "Capture response connection release failed during cleanup; "
                    "preserving primary open error",
                    exc_info=True,
                )
            raise

    def delete(self, key: str) -> None:
        self.client.remove_object(self.bucket, key)


class PostgresRepository(Repository):
    """PostgreSQL JSONB control-plane repository with MinIO export blobs and audit rows."""

    _DETECTOR_PRESET_ADVISORY_LOCK = 112737
    _FLOW_RECORD_CHUNK_TARGET_BYTES = 8 * 1024 * 1024
    _LIVE_TASK_COLUMNS = (
        "source_kind,source_id,sensor_id,analysis_job_id,object_key,source_size_bytes,"
        "source_sha256,capture_format,schema_version,parser_contract_version,status,attempt,"
        "max_attempts,lease_token,lease_expires_at,next_attempt_at,queued_at,updated_at,error_code"
    )

    def __init__(self, database_url: str, blob_store: MinioBlobStore) -> None:
        self.database_url = database_url
        self._connection: Any = None
        self.blob_store = blob_store
        self._lock = threading.RLock()

    @_serialize_shared_connection
    def snapshot_pcap_export_source(
        self,
        job_id: str,
        canonical_request: dict[str, Any],
        effective_limits: dict[str, int],
    ) -> dict[str, Any] | None:
        connection = self.connection
        with self._lock, self._rollback_on_error(), connection.cursor() as cursor:
            cursor.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")

            class AtomicSnapshotView:
                def get_job_summary(self, value: str) -> dict[str, Any] | None:
                    cursor.execute(
                        "SELECT data FROM controller_objects WHERE kind='job' AND id=%s",
                        (value,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        return None
                    data = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                    return {key: item for key, item in data.items() if key != "flow_records"}

                def list_sensor_pcaps_for_job(self, value: str) -> list[dict[str, Any]]:
                    cursor.execute(
                        "SELECT data FROM controller_objects WHERE kind='sensor_pcap' "
                        "AND data->>'analysis_job_id'=%s ORDER BY data->>'uploaded_at',id",
                        (value,),
                    )
                    return [
                        row[0] if isinstance(row[0], dict) else json.loads(row[0])
                        for row in cursor.fetchall()
                    ]

            snapshot = _pcap_export_snapshot(
                AtomicSnapshotView(), job_id, canonical_request, effective_limits
            )
            connection.commit()
            return snapshot

    def validate_pcap_export_admission(self, job: dict[str, Any]) -> bool:
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

    @staticmethod
    def _queue_row(row: Any) -> dict[str, Any]:
        value = row[-1]
        return value if isinstance(value, dict) else json.loads(value)

    @staticmethod
    def _rollback_pcap_queue(connection: Any) -> None:
        try:
            connection.rollback()
        except Exception:
            logger.debug(
                "PCAP export queue rollback failed; preserving primary error", exc_info=True
            )

    @_serialize_shared_connection
    def enqueue_pcap_export_job(
        self, job: dict[str, Any], *, capacity: int, per_principal_limit: int
    ) -> tuple[dict[str, Any], bool]:
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                # One transaction-scoped lock serializes replay/conflict/coalescing,
                # both capacity counters, and insertion across all API processes.
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                    ("pcap-export-admission",),
                )
                key = job.get("idempotency_key")
                if key is not None:
                    cursor.execute(
                        "SELECT data FROM pcap_export_jobs "
                        "WHERE principal_scope=%s AND idempotency_key=%s FOR UPDATE",
                        (job["principal_scope"], key),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        existing = self._queue_row(row)
                        if existing["request_fingerprint"] != job["request_fingerprint"]:
                            raise ValueError("idempotency_conflict")
                        connection.commit()
                        return existing, False
                cursor.execute(
                    "SELECT data FROM pcap_export_jobs "
                    "WHERE principal_scope=%s AND coalesce_fingerprint=%s "
                    "AND status IN ('QUEUED','RUNNING','COMPLETED') FOR UPDATE",
                    (job["principal_scope"], job["coalesce_fingerprint"]),
                )
                row = cursor.fetchone()
                if row is not None:
                    connection.commit()
                    return self._queue_row(row), False
                cursor.execute(
                    "SELECT COUNT(*),COUNT(*) FILTER (WHERE principal_scope=%s) "
                    "FROM pcap_export_jobs WHERE status IN ('QUEUED','RUNNING')",
                    (job["principal_scope"],),
                )
                counts = cursor.fetchone() or (0, 0)
                if int(counts[0]) >= capacity:
                    raise ExportQueueFullError("pcap export queue is full")
                if int(counts[1]) >= per_principal_limit:
                    raise ExportPrincipalLimitError("principal PCAP export limit reached")
                if "canonical_request" in job:

                    class AdmissionSnapshotView:
                        def get_job_summary(self, value: str) -> dict[str, Any] | None:
                            cursor.execute(
                                "SELECT data FROM controller_objects "
                                "WHERE kind='job' AND id=%s FOR UPDATE",
                                (value,),
                            )
                            row = cursor.fetchone()
                            if row is None:
                                return None
                            data = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                            return {
                                key: item for key, item in data.items() if key != "flow_records"
                            }

                        def list_sensor_pcaps_for_job(self, value: str) -> list[dict[str, Any]]:
                            cursor.execute(
                                "SELECT data FROM controller_objects "
                                "WHERE kind='sensor_pcap' "
                                "AND data->>'analysis_job_id'=%s "
                                "ORDER BY data->>'uploaded_at',id FOR SHARE",
                                (value,),
                            )
                            return [
                                row[0] if isinstance(row[0], dict) else json.loads(row[0])
                                for row in cursor.fetchall()
                            ]

                    current_snapshot = _pcap_export_snapshot(
                        AdmissionSnapshotView(),
                        str(job["job_id"]),
                        dict(job.get("canonical_request", {})),
                        dict(job.get("effective_limits", {})),
                    )
                    if (
                        current_snapshot is None
                        or current_snapshot["source_generation"] != job.get("source_generation")
                        or current_snapshot["source_manifest"] != job.get("source_manifest", [])
                    ):
                        raise ExportSourceChangedError(
                            "PCAP export source changed before admission"
                        )
                cursor.execute(
                    "INSERT INTO pcap_export_jobs("
                    "export_id,principal_scope,idempotency_key,request_fingerprint,"
                    "coalesce_fingerprint,parent_job_id,source_job_id,source_generation,status,"
                    "attempt,lease_token,lease_expires_at,next_attempt_at,queued_at,data) VALUES("
                    "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)",
                    (
                        job["id"],
                        job["principal_scope"],
                        key,
                        job["request_fingerprint"],
                        job["coalesce_fingerprint"],
                        job["job_id"],
                        job["source_job_id"],
                        job["source_generation"],
                        job["status"],
                        job.get("attempt", 0),
                        job.get("lease_token"),
                        job.get("lease_expires_at"),
                        job.get("next_attempt_at"),
                        job["queued_at"],
                        self._json(job),
                    ),
                )
                connection.commit()
                return deepcopy(job), True
        except (
            ValueError,
            ExportQueueFullError,
            ExportPrincipalLimitError,
            ExportSourceChangedError,
        ):
            self._rollback_pcap_queue(connection)
            raise
        except Exception as exc:
            self._rollback_pcap_queue(connection)
            # A uniqueness race can still be observed during rolling upgrades or
            # if an older writer does not take the admission lock. Reconcile by
            # rereading the winner and applying the same exact replay semantics.
            try:
                with self._lock, connection.cursor() as cursor:
                    key = job.get("idempotency_key")
                    if key is not None:
                        cursor.execute(
                            "SELECT data FROM pcap_export_jobs WHERE principal_scope=%s "
                            "AND idempotency_key=%s",
                            (job["principal_scope"], key),
                        )
                        row = cursor.fetchone()
                        if row is not None:
                            existing = self._queue_row(row)
                            connection.commit()
                            if existing["request_fingerprint"] != job["request_fingerprint"]:
                                raise ValueError("idempotency_conflict") from exc
                            return existing, False
                    cursor.execute(
                        "SELECT data FROM pcap_export_jobs WHERE principal_scope=%s "
                        "AND coalesce_fingerprint=%s "
                        "AND status IN ('QUEUED','RUNNING','COMPLETED')",
                        (job["principal_scope"], job["coalesce_fingerprint"]),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        connection.commit()
                        return self._queue_row(row), False
                    connection.rollback()
            except ValueError:
                raise
            except Exception:
                self._rollback_pcap_queue(connection)
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def get_pcap_export_job(self, export_id: str) -> dict[str, Any] | None:
        try:
            with self._lock, self.connection.cursor() as cursor:
                cursor.execute("SELECT data FROM pcap_export_jobs WHERE export_id=%s", (export_id,))
                row = cursor.fetchone()
                self.connection.commit()
            return self._queue_row(row) if row is not None else None
        except Exception as exc:
            self._rollback_pcap_queue(self.connection)
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def find_pcap_export_job(
        self, principal_scope: str, idempotency_key: str, request_fingerprint: str
    ) -> dict[str, Any] | None:
        try:
            with self._lock, self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM pcap_export_jobs WHERE principal_scope=%s "
                    "AND idempotency_key=%s",
                    (principal_scope, idempotency_key),
                )
                row = cursor.fetchone()
                self.connection.commit()
            found = self._queue_row(row) if row is not None else None
            if found is not None and found.get("request_fingerprint") != request_fingerprint:
                raise ValueError("idempotency_conflict")
            return found
        except ValueError:
            raise
        except Exception as exc:
            self._rollback_pcap_queue(self.connection)
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def count_pcap_export_jobs_by_status(self) -> dict[str, int]:
        try:
            with self._lock, self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT status,COUNT(*) FROM pcap_export_jobs "
                    "WHERE status IN ('QUEUED','RUNNING') GROUP BY status"
                )
                found = {str(status): int(value) for status, value in cursor.fetchall()}
                self.connection.commit()
            return {status: found.get(status, 0) for status in ("QUEUED", "RUNNING")}
        except Exception as exc:
            self._rollback_pcap_queue(self.connection)
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def claim_pcap_export_job(
        self, *, now: datetime | None = None, lease_seconds: int = 120
    ) -> dict[str, Any] | None:
        connection = self.connection
        current = now or datetime.now(UTC)
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT export_id,data FROM pcap_export_jobs "
                    "WHERE status='QUEUED' AND (next_attempt_at IS NULL OR next_attempt_at<=%s) "
                    "ORDER BY queued_at,export_id FOR UPDATE SKIP LOCKED LIMIT 1",
                    (current,),
                )
                row = cursor.fetchone()
                if row is None:
                    connection.commit()
                    return None
                job = self._queue_row(row)
                token = secrets.token_urlsafe(32)
                job.update(
                    status="RUNNING",
                    attempt=int(job.get("attempt", 0)) + 1,
                    lease_token=token,
                    lease_expires_at=(current + timedelta(seconds=lease_seconds)).isoformat(),
                    started_at=job.get("started_at") or current.isoformat(),
                    updated_at=current.isoformat(),
                )
                job["progress"] = {**job.get("progress", {}), "phase": "SNAPSHOT_VALIDATION"}
                cursor.execute(
                    "UPDATE pcap_export_jobs SET status='RUNNING',attempt=%s,lease_token=%s,"
                    "lease_expires_at=%s,data=%s::jsonb WHERE export_id=%s AND status='QUEUED'",
                    (
                        job["attempt"],
                        token,
                        current + timedelta(seconds=lease_seconds),
                        self._json(job),
                        job["id"],
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return None
                connection.commit()
                return job
        except Exception as exc:
            connection.rollback()
            if isinstance(exc, ExportQueueStorageError):
                raise
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def _guarded_pcap_update(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        mutate: Callable[[dict[str, Any]], bool],
    ) -> bool:
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM pcap_export_jobs WHERE export_id=%s FOR UPDATE",
                    (export_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    connection.commit()
                    return False
                job = self._queue_row(row)
                if (
                    job.get("status") != "RUNNING"
                    or int(job.get("attempt", 0)) != attempt
                    or not secrets.compare_digest(str(job.get("lease_token", "")), lease_token)
                    or not mutate(job)
                ):
                    connection.commit()
                    return False
                job["updated_at"] = datetime.now(UTC).isoformat()
                cursor.execute(
                    "UPDATE pcap_export_jobs SET status=%s,lease_token=%s,lease_expires_at=%s,"
                    "next_attempt_at=%s,completed_at=%s,artifact_size_bytes=%s,data=%s::jsonb "
                    "WHERE export_id=%s AND status='RUNNING' AND attempt=%s AND lease_token=%s",
                    (
                        job["status"],
                        job.get("lease_token"),
                        job.get("lease_expires_at"),
                        job.get("next_attempt_at"),
                        job.get("completed_at"),
                        job.get("size_bytes"),
                        self._json(job),
                        export_id,
                        attempt,
                        lease_token,
                    ),
                )
                won = bool(cursor.rowcount == 1)
                connection.commit()
                return won
        except Exception as exc:
            connection.rollback()
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    def heartbeat_pcap_export_job(
        self, export_id: str, *, attempt: int, lease_token: str, lease_seconds: int
    ) -> bool:
        def mutate(job: dict[str, Any]) -> bool:
            job["lease_expires_at"] = (
                datetime.now(UTC) + timedelta(seconds=lease_seconds)
            ).isoformat()
            return True

        return self._guarded_pcap_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )

    def progress_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        progress: dict[str, Any],
    ) -> bool:
        def mutate(job: dict[str, Any]) -> bool:
            current = dict(job.get("progress", {}))
            for key, value in progress.items():
                if key == "phase":
                    current[key] = str(value)
                elif key in {
                    "percent",
                    "scanned_source_bytes",
                    "scanned_packet_count",
                    "matched_packet_count",
                    "exported_packet_count",
                }:
                    limit = 99 if key == "percent" else int(value)
                    current[key] = max(int(current.get(key, 0)), min(limit, int(value)))
            job["progress"] = current
            return True

        return self._guarded_pcap_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )

    def complete_pcap_export_job(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> bool:
        artifact_accepted = False

        def mutate(job: dict[str, Any]) -> bool:
            nonlocal artifact_accepted
            now = datetime.now(UTC).isoformat()
            artifact_status = str(artifact.get("status", "COMPLETED"))
            if artifact_status not in {"COMPLETED", "FAILED"}:
                return False
            if job.get("cancellation_requested"):
                job.update(
                    status="CANCELLED",
                    completed_at=now,
                    error_code="PCAP_EXPORT_CANCELLED",
                    error="PCAP export was cancelled",
                )
            elif artifact_status == "COMPLETED":
                with self.connection.cursor() as publication_cursor:
                    publication_cursor.execute(
                        "SELECT 1 FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                        (str(job["job_id"]),),
                    )
                    if publication_cursor.fetchone() is None:
                        return False

                    class CompletionSnapshotView:
                        def get_job_summary(self, value: str) -> dict[str, Any] | None:
                            publication_cursor.execute(
                                "SELECT data FROM controller_objects "
                                "WHERE kind='job' AND id=%s FOR UPDATE",
                                (value,),
                            )
                            row = publication_cursor.fetchone()
                            if row is None:
                                return None
                            data = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                            return {
                                key: item for key, item in data.items() if key != "flow_records"
                            }

                        def list_sensor_pcaps_for_job(self, value: str) -> list[dict[str, Any]]:
                            publication_cursor.execute(
                                "SELECT data FROM controller_objects WHERE kind='sensor_pcap' "
                                "AND data->>'analysis_job_id'=%s "
                                "ORDER BY data->>'uploaded_at',id FOR SHARE",
                                (value,),
                            )
                            return [
                                row[0] if isinstance(row[0], dict) else json.loads(row[0])
                                for row in publication_cursor.fetchall()
                            ]

                    current_snapshot = _pcap_export_snapshot(
                        CompletionSnapshotView(),
                        str(job["job_id"]),
                        dict(job.get("canonical_request", {})),
                        dict(job.get("effective_limits", {})),
                    )
                    if (
                        current_snapshot is None
                        or current_snapshot["source_generation"] != job.get("source_generation")
                        or current_snapshot["source_manifest"] != job.get("source_manifest", [])
                    ):
                        return False
                if artifact.get("published") is False:
                    with self.connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT data FROM controller_objects "
                            "WHERE kind='export' AND id=%s FOR UPDATE",
                            (export_id,),
                        )
                        row = cursor.fetchone()
                        value = row[0] if row is not None else None
                        stored = (
                            value
                            if isinstance(value, dict)
                            else json.loads(value)
                            if value
                            else None
                        )
                        if (
                            stored is None
                            or stored.get("attempt") != attempt
                            or stored.get("lease_token") != lease_token
                            or stored.get("object_key") != artifact.get("object_key")
                        ):
                            return False
                        object_key = str(artifact.get("object_key", ""))
                        cleanup_id = self._pcap_cleanup_id(f"publication:{export_id}", object_key)
                        cursor.execute(
                            "SELECT id,data FROM controller_objects "
                            "WHERE kind='pcap_export_cleanup' "
                            "AND data->>'object_key'=%s FOR UPDATE",
                            (object_key,),
                        )
                        cleanup_rows = cursor.fetchall()
                        cleanup_row = cleanup_rows[0] if len(cleanup_rows) == 1 else None
                        cleanup_row_id = cleanup_row[0] if cleanup_row is not None else None
                        cleanup_value = cleanup_row[1] if cleanup_row is not None else None
                        cleanup = (
                            cleanup_value
                            if isinstance(cleanup_value, dict)
                            else json.loads(cleanup_value)
                            if cleanup_value
                            else None
                        )
                        if (
                            cleanup is None
                            or cleanup_row_id != cleanup_id
                            or cleanup.get("object_key") != object_key
                            or cleanup.get("state") != "STAGED"
                        ):
                            return False
                        stored["published"] = True
                        cursor.execute(
                            "UPDATE controller_objects SET data=%s::jsonb "
                            "WHERE kind='export' AND id=%s",
                            (self._json(stored), export_id),
                        )
                        cursor.execute(
                            "DELETE FROM controller_objects "
                            "WHERE kind='pcap_export_cleanup' AND id=%s "
                            "AND data->>'object_key'=%s AND data->>'state'='STAGED'",
                            (cleanup_id, object_key),
                        )
                        if cursor.rowcount != 1:
                            raise ExportQueueStorageError(
                                "PCAP export cleanup publication CAS failed"
                            )
                    artifact["published"] = True
                job.update(artifact)
                job.update(status="COMPLETED", completed_at=now, error_code=None, error=None)
                job["progress"] = {
                    **job.get("progress", {}),
                    "phase": "TERMINAL",
                    "percent": 100,
                }
            else:
                job.update(artifact)
                job.update(status="FAILED", completed_at=now)
                job["progress"] = {
                    **job.get("progress", {}),
                    "phase": "TERMINAL",
                    "percent": min(99, int(job.get("progress", {}).get("percent", 0))),
                }
            artifact_accepted = not job.get("cancellation_requested")
            job.update(lease_token=None, lease_expires_at=None)
            return True

        updated = self._guarded_pcap_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )
        return updated and artifact_accepted

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
        def mutate(job: dict[str, Any]) -> bool:
            now = datetime.now(UTC)
            if job.get("cancellation_requested"):
                job.update(
                    status="CANCELLED",
                    completed_at=now.isoformat(),
                    error_code="PCAP_EXPORT_CANCELLED",
                    error="PCAP export was cancelled",
                )
            elif transient and attempt < int(job.get("max_attempts", 3)):
                job.update(
                    status="QUEUED",
                    next_attempt_at=(
                        now + timedelta(seconds=retry_base_seconds * 2 ** (attempt - 1))
                    ).isoformat(),
                )
            else:
                job.update(
                    status="FAILED",
                    completed_at=now.isoformat(),
                    error_code="PCAP_EXPORT_RETRY_EXHAUSTED" if transient else error_code,
                    error=error,
                )
            job.update(lease_token=None, lease_expires_at=None)
            return True

        return self._guarded_pcap_update(
            export_id, attempt=attempt, lease_token=lease_token, mutate=mutate
        )

    @_serialize_shared_connection
    def cancel_pcap_export_job(
        self, export_id: str, *, reason: str | None = None
    ) -> dict[str, Any]:
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM pcap_export_jobs WHERE export_id=%s FOR UPDATE",
                    (export_id,),
                )
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(export_id)
                job = self._queue_row(row)
                if job["status"] not in TERMINAL_EXPORT_STATES:
                    now = datetime.now(UTC).isoformat()
                    job.update(
                        cancellation_requested=True,
                        cancellation_requested_at=now,
                        cancellation_reason=reason,
                        updated_at=now,
                    )
                    if job["status"] == "QUEUED":
                        job.update(
                            status="CANCELLED",
                            completed_at=now,
                            error_code="PCAP_EXPORT_CANCELLED",
                            error="PCAP export was cancelled",
                        )
                    cursor.execute(
                        "UPDATE pcap_export_jobs SET status=%s,completed_at=%s,data=%s::jsonb "
                        "WHERE export_id=%s AND status IN ('QUEUED','RUNNING')",
                        (job["status"], job.get("completed_at"), self._json(job), export_id),
                    )
                connection.commit()
                return job
        except KeyError:
            connection.rollback()
            raise
        except Exception as exc:
            connection.rollback()
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def recover_pcap_export_jobs(self, *, now: datetime | None = None) -> int:
        current = now or datetime.now(UTC)
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT export_id,data FROM pcap_export_jobs WHERE status='RUNNING' "
                    "AND lease_expires_at<=%s FOR UPDATE SKIP LOCKED",
                    (current,),
                )
                rows = cursor.fetchall()
                for row in rows:
                    job = self._queue_row(row)
                    if job.get("cancellation_requested"):
                        job.update(
                            status="CANCELLED",
                            completed_at=current.isoformat(),
                            error_code="PCAP_EXPORT_CANCELLED",
                            error="PCAP export was cancelled",
                        )
                    elif int(job.get("attempt", 0)) >= int(job.get("max_attempts", 3)):
                        job.update(
                            status="FAILED",
                            completed_at=current.isoformat(),
                            error_code="PCAP_EXPORT_RETRY_EXHAUSTED",
                            error="PCAP export retry attempts were exhausted",
                        )
                    else:
                        job.update(status="QUEUED", next_attempt_at=current.isoformat())
                    job.update(
                        lease_token=None,
                        lease_expires_at=None,
                        updated_at=current.isoformat(),
                    )
                    cursor.execute(
                        "UPDATE pcap_export_jobs SET status=%s,lease_token=NULL,"
                        "lease_expires_at=NULL,next_attempt_at=%s,completed_at=%s,data=%s::jsonb "
                        "WHERE export_id=%s AND status='RUNNING'",
                        (
                            job["status"],
                            job.get("next_attempt_at"),
                            job.get("completed_at"),
                            self._json(job),
                            job["id"],
                        ),
                    )
                connection.commit()
                return len(rows)
        except Exception as exc:
            connection.rollback()
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @_serialize_shared_connection
    def has_active_pcap_exports(self, job_id: str) -> bool:
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM pcap_export_jobs WHERE (parent_job_id=%s "
                    "OR source_job_id=%s OR data->'provenance_job_ids' ? %s) "
                    "AND status IN ('QUEUED','RUNNING') LIMIT 1",
                    (job_id, job_id, job_id),
                )
                active = cursor.fetchone() is not None
            connection.commit()
            return active
        except Exception as exc:
            connection.rollback()
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

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

    @staticmethod
    def _pcap_cleanup_id(scope: str, object_key: str) -> str:
        digest = hashlib.sha256(object_key.encode()).hexdigest()[:16]
        return f"{scope}:{digest}"

    def compensate_pcap_export_artifact(
        self,
        export_id: str,
        *,
        attempt: int,
        lease_token: str,
        artifact: dict[str, Any],
    ) -> None:
        object_key = artifact.get("object_key")
        if not object_key:
            return
        cleanup_id = self._pcap_cleanup_id(f"publication:{export_id}", str(object_key))
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data->>'object_key' FROM pcap_export_jobs "
                    "WHERE export_id=%s FOR UPDATE",
                    (export_id,),
                )
                row = cursor.fetchone()
                cursor.execute(
                    "SELECT id FROM controller_objects "
                    "WHERE kind='pcap_export_cleanup' AND data->>'object_key'=%s FOR UPDATE",
                    (object_key,),
                )
                cleanup_exists = bool(cursor.fetchall())
                if row is not None and row[0] == object_key:
                    cursor.execute(
                        "DELETE FROM controller_objects "
                        "WHERE kind='pcap_export_cleanup' AND data->>'object_key'=%s",
                        (object_key,),
                    )
                    connection.commit()
                    return
                cursor.execute(
                    "DELETE FROM controller_objects WHERE kind='export' AND id=%s "
                    "AND data->>'object_key'=%s AND data->>'attempt'=%s "
                    "AND data->>'lease_token'=%s",
                    (export_id, object_key, str(attempt), lease_token),
                )
                if cursor.rowcount != 1 and not cleanup_exists:
                    connection.commit()
                    return
                cursor.execute(
                    "DELETE FROM controller_objects "
                    "WHERE kind='pcap_export_cleanup' AND data->>'object_key'=%s AND id<>%s",
                    (object_key, cleanup_id),
                )
                cursor.execute(
                    "INSERT INTO controller_objects(kind,id,data) "
                    "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
                    "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                    (
                        cleanup_id,
                        self._json(
                            {
                                "object_key": object_key,
                                "created_at": datetime.now(UTC).isoformat(),
                                "state": "READY",
                                "export_id": export_id,
                                "attempt": attempt,
                                "lease_token": lease_token,
                            }
                        ),
                    ),
                )
                connection.commit()
            self.blob_store.delete(str(object_key))
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM controller_objects WHERE kind='pcap_export_cleanup' AND id=%s "
                    "AND data->>'object_key'=%s",
                    (cleanup_id, str(object_key)),
                )
                connection.commit()
        except Exception as exc:
            connection.rollback()
            raise ExportQueueStorageError("PCAP export artifact compensation failed") from exc

    def cleanup_pcap_export_orphans(
        self, *, now: datetime, max_age_seconds: int, limit: int
    ) -> list[str]:
        """Delete a bounded batch via the durable cleanup outbox without locking across MinIO."""
        connection = self.connection
        cutoff = now - timedelta(seconds=max_age_seconds)
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT id,data->>'object_key' FROM controller_objects "
                    "WHERE kind='pcap_export_cleanup' "
                    "AND (COALESCE(data->>'state','READY') IN ('READY','DELETING') "
                    "OR (data->>'state'='UPLOADING' "
                    "AND (data->>'created_at')::timestamptz<=%s "
                    "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs AS active "
                    "WHERE active.export_id=(controller_objects.data->>'export_id') "
                    "AND active.status='RUNNING' "
                    "AND active.attempt=COALESCE("
                    "(controller_objects.data->>'attempt')::integer,-1) "
                    "AND active.lease_token=(controller_objects.data->>'lease_token'))) "
                    "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs AS published "
                    "WHERE published.status='COMPLETED' "
                    "AND published.data->>'object_key'=controller_objects.data->>'object_key') "
                    "AND NOT EXISTS (SELECT 1 FROM pcap_capture_source_versions AS capture "
                    "WHERE capture.object_key=controller_objects.data->>'object_key') "
                    "ORDER BY id "
                    "FOR UPDATE SKIP LOCKED LIMIT %s",
                    (cutoff, limit),
                )
                candidates = [(str(item[0]), str(item[1])) for item in cursor.fetchall() if item[1]]
                pending: list[tuple[str, str]] = []
                for cleanup_id, object_key in candidates:
                    cursor.execute(
                        "UPDATE controller_objects "
                        "SET data=jsonb_set(data,'{state}','\"DELETING\"'::jsonb) "
                        "WHERE kind='pcap_export_cleanup' AND id=%s "
                        "AND data->>'object_key'=%s "
                        "AND (COALESCE(data->>'state','READY') IN ('READY','DELETING') "
                        "OR (data->>'state'='UPLOADING' "
                        "AND (data->>'created_at')::timestamptz<=%s "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs AS active "
                        "WHERE active.export_id=(controller_objects.data->>'export_id') "
                        "AND active.status='RUNNING' "
                        "AND active.attempt=COALESCE("
                        "(controller_objects.data->>'attempt')::integer,-1) "
                        "AND active.lease_token=(controller_objects.data->>'lease_token'))) "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs AS published "
                        "WHERE published.status='COMPLETED' "
                        "AND published.data->>'object_key'=controller_objects.data->>'object_key') "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_capture_source_versions AS capture "
                        "WHERE capture.object_key=controller_objects.data->>'object_key')",
                        (cleanup_id, object_key, cutoff),
                    )
                    if cursor.rowcount == 1:
                        pending.append((cleanup_id, object_key))
                remaining = max(0, limit - len(pending))
                if remaining:
                    cursor.execute(
                        "SELECT id,data->>'object_key' FROM controller_objects AS artifact "
                        "WHERE kind='export' AND data->>'published'='false' "
                        "AND (data->>'created_at')::timestamptz<=%s "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs AS job "
                        "WHERE job.data->>'object_key'=artifact.data->>'object_key') "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_export_jobs AS active "
                        "WHERE active.export_id=artifact.id AND active.status='RUNNING' "
                        "AND active.attempt=COALESCE((artifact.data->>'attempt')::integer,-1) "
                        "AND active.lease_token=artifact.data->>'lease_token') "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_capture_source_versions AS capture "
                        "WHERE capture.object_key=artifact.data->>'object_key') "
                        "ORDER BY (data->>'created_at')::timestamptz,id "
                        "FOR UPDATE SKIP LOCKED LIMIT %s",
                        (cutoff, remaining),
                    )
                    fresh_artifacts = [
                        (str(item[0]), str(item[1])) for item in cursor.fetchall() if item[1]
                    ]
                    fresh: list[tuple[str, str]] = []
                    for artifact_id, object_key in fresh_artifacts:
                        cleanup_id = self._pcap_cleanup_id(f"orphan:{artifact_id}", object_key)
                        cursor.execute(
                            "INSERT INTO controller_objects(kind,id,data) "
                            "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
                            "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                            (
                                cleanup_id,
                                self._json(
                                    {
                                        "object_key": object_key,
                                        "created_at": now.isoformat(),
                                        "state": "DELETING",
                                    }
                                ),
                            ),
                        )
                        cursor.execute(
                            "DELETE FROM controller_objects WHERE kind='export' AND id=%s "
                            "AND data->>'published'='false' AND data->>'object_key'=%s",
                            (artifact_id, object_key),
                        )
                        fresh.append((cleanup_id, object_key))
                    pending.extend(fresh)
                connection.commit()
            removed: list[str] = []
            for cleanup_id, object_key in pending:
                try:
                    self.blob_store.delete(object_key)
                    with self._lock, connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM controller_objects "
                            "WHERE kind='pcap_export_cleanup' AND id=%s "
                            "AND data->>'object_key'=%s",
                            (cleanup_id, object_key),
                        )
                        connection.commit()
                    removed.append(object_key)
                except Exception:
                    with self._lock:
                        connection.rollback()
                    logger.warning("Deferred PCAP orphan cleanup failed", exc_info=True)
            return removed
        except Exception as exc:
            with self._lock:
                self._rollback_pcap_queue(connection)
            raise ExportQueueStorageError("PCAP export orphan cleanup failed") from exc

    def retain_pcap_export_jobs(
        self,
        *,
        now: datetime,
        max_age_seconds: int,
        max_count: int,
        max_artifact_bytes: int,
    ) -> list[str]:
        connection = self.connection
        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT export_id,data FROM pcap_export_jobs "
                    "WHERE status IN ('COMPLETED','FAILED','CANCELLED') "
                    "ORDER BY completed_at,export_id FOR UPDATE",
                )
                rows = cursor.fetchall()
                jobs = [self._queue_row(row) for row in rows]
                selected: set[str] = {
                    str(job["id"])
                    for job in jobs
                    if job.get("completed_at")
                    and datetime.fromisoformat(str(job["completed_at"]))
                    < now - timedelta(seconds=max_age_seconds)
                }
                survivors = [job for job in jobs if str(job["id"]) not in selected]
                while len(survivors) > max_count:
                    selected.add(str(survivors.pop(0)["id"]))
                retained_bytes = sum(int(job.get("size_bytes", 0) or 0) for job in survivors)
                while survivors and retained_bytes > max_artifact_bytes:
                    removed = survivors.pop(0)
                    retained_bytes -= int(removed.get("size_bytes", 0) or 0)
                    selected.add(str(removed["id"]))
                ordered = [str(job["id"]) for job in jobs if str(job["id"]) in selected]
                cleanup: list[tuple[str, str]] = []
                if ordered:
                    cleanup = [
                        (
                            self._pcap_cleanup_id(f"retention:{job['id']}", str(job["object_key"])),
                            str(job["object_key"]),
                        )
                        for job in jobs
                        if str(job["id"]) in selected and job.get("object_key")
                    ]
                    for cleanup_id, object_key in cleanup:
                        cursor.execute(
                            "INSERT INTO controller_objects(kind,id,data) "
                            "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
                            "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                            (
                                cleanup_id,
                                self._json(
                                    {
                                        "object_key": object_key,
                                        "created_at": now.isoformat(),
                                    }
                                ),
                            ),
                        )
                    cursor.execute(
                        "DELETE FROM controller_objects WHERE kind='export' AND id=ANY(%s)",
                        (ordered,),
                    )
                    cursor.execute(
                        "DELETE FROM pcap_export_jobs WHERE export_id=ANY(%s)", (ordered,)
                    )
                connection.commit()
            # Public references are gone before any irreversible object delete.
            # Failed deletes remain in the durable cleanup outbox for maintenance.
            for cleanup_id, object_key in cleanup:
                try:
                    self.blob_store.delete(object_key)
                    with self._lock, connection.cursor() as cursor:
                        cursor.execute(
                            "DELETE FROM controller_objects "
                            "WHERE kind='pcap_export_cleanup' AND id=%s "
                            "AND data->>'object_key'=%s",
                            (cleanup_id, object_key),
                        )
                        connection.commit()
                except Exception:
                    with self._lock:
                        connection.rollback()
                    logger.warning("Deferred PCAP artifact cleanup failed", exc_info=True)
            return ordered
        except Exception as exc:
            with self._lock:
                self._rollback_pcap_queue(connection)
            raise ExportQueueStorageError("PCAP export lifecycle storage unavailable") from exc

    @contextmanager
    def _rollback_on_error(self) -> Iterator[None]:
        try:
            yield
        except Exception:
            self.connection.rollback()
            raise

    @property
    def connection(self) -> Any:
        with self._lock:
            if self._connection is not None and not self._connection.closed:
                return self._connection
            import psycopg

            connection = psycopg.connect(self.database_url, autocommit=False)
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS controller_objects (
                          kind text NOT NULL, id text NOT NULL, data jsonb NOT NULL,
                          PRIMARY KEY(kind,id)
                        );
                        CREATE TABLE IF NOT EXISTS job_idempotency (
                          idempotency_key text PRIMARY KEY, job_id text NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS job_candidates (
                          job_id text PRIMARY KEY, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS candidate_records (
                          candidate_id text PRIMARY KEY,
                          job_id text NOT NULL,
                          position integer NOT NULL,
                          score integer NOT NULL DEFAULT 0,
                          severity text NOT NULL DEFAULT '',
                          excluded boolean NOT NULL DEFAULT false,
                          data jsonb NOT NULL,
                          UNIQUE(job_id,position)
                        );
                        CREATE INDEX IF NOT EXISTS candidate_records_job_position
                          ON candidate_records(job_id,position);
                        CREATE INDEX IF NOT EXISTS candidate_records_triage
                          ON candidate_records(excluded,severity,score DESC,candidate_id);
                        CREATE TABLE IF NOT EXISTS ai_analysis_runs (
                          run_id text PRIMARY KEY,
                          analysis_job_id text NOT NULL,
                          idempotency_key text NOT NULL,
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL,
                          UNIQUE(analysis_job_id,idempotency_key)
                        );
                        CREATE INDEX IF NOT EXISTS ai_analysis_runs_job_created
                          ON ai_analysis_runs(analysis_job_id,created_at DESC);
                        CREATE TABLE IF NOT EXISTS ai_candidate_assessments (
                          assessment_id text PRIMARY KEY,
                          ai_run_id text NOT NULL REFERENCES ai_analysis_runs(run_id),
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ai_candidate_assessments_run_created
                          ON ai_candidate_assessments(ai_run_id,created_at);
                        CREATE TABLE IF NOT EXISTS ai_generated_artifacts (
                          artifact_id text PRIMARY KEY,
                          assessment_id text NOT NULL
                            REFERENCES ai_candidate_assessments(assessment_id),
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ai_generated_artifacts_assessment_created
                          ON ai_generated_artifacts(assessment_id,created_at);
                        CREATE TABLE IF NOT EXISTS ai_feedback (
                          feedback_id text PRIMARY KEY,
                          assessment_id text NOT NULL
                            REFERENCES ai_candidate_assessments(assessment_id),
                          created_at timestamptz NOT NULL,
                          data jsonb NOT NULL
                        );
                        CREATE INDEX IF NOT EXISTS ai_feedback_assessment_created
                          ON ai_feedback(assessment_id,created_at);
                        CREATE TABLE IF NOT EXISTS job_flow_records (
                          job_id text PRIMARY KEY, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS job_flow_record_chunks (
                          job_id text NOT NULL, chunk_no integer NOT NULL,
                          data jsonb NOT NULL,
                          PRIMARY KEY(job_id,chunk_no)
                        );
                        CREATE TABLE IF NOT EXISTS job_payload_signatures (
                          job_id text PRIMARY KEY, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS audit_events (
                          sequence bigserial PRIMARY KEY, kind text NOT NULL,
                          object_id text NOT NULL,
                          occurred_at timestamptz NOT NULL, data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS pcap_export_jobs (
                          export_id text PRIMARY KEY,
                          principal_scope text NOT NULL,
                          idempotency_key text,
                          request_fingerprint text NOT NULL,
                          coalesce_fingerprint text NOT NULL,
                          parent_job_id text NOT NULL,
                          source_job_id text NOT NULL,
                          source_generation text NOT NULL,
                          status text NOT NULL,
                          attempt integer NOT NULL DEFAULT 0,
                          lease_token text,
                          lease_expires_at timestamptz,
                          next_attempt_at timestamptz,
                          queued_at timestamptz NOT NULL,
                          completed_at timestamptz,
                          artifact_size_bytes bigint,
                          data jsonb NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS pcap_capture_source_versions (
                          source_kind text NOT NULL
                            CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                          source_id text NOT NULL,
                          object_key text NOT NULL,
                          source_version_id text NOT NULL,
                          source_size_bytes bigint NOT NULL CHECK(source_size_bytes>=0),
                          source_sha256 text NOT NULL,
                          updated_at timestamptz NOT NULL,
                          PRIMARY KEY(source_kind,source_id)
                        );
                        CREATE TABLE IF NOT EXISTS pcap_offset_index_generations (
                          build_id text PRIMARY KEY,
                          source_kind text NOT NULL
                            CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                          source_id text NOT NULL,
                          source_version_id text NOT NULL,
                          source_size_bytes bigint NOT NULL CHECK(source_size_bytes>=0),
                          source_sha256 text NOT NULL,
                          capture_format text NOT NULL CHECK(capture_format IN ('PCAP','PCAPNG')),
                          schema_version integer NOT NULL,
                          parser_contract_version integer NOT NULL,
                          state text NOT NULL CHECK(state IN ('STAGING','READY')),
                          created_at timestamptz NOT NULL,
                          packet_count bigint,
                          interface_count integer,
                          index_sha256 text
                        );
                        CREATE TABLE IF NOT EXISTS pcap_offset_index_interfaces (
                          build_id text NOT NULL
                            REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
                          interface_ordinal integer NOT NULL,
                          section_index integer NOT NULL,
                          interface_id integer NOT NULL,
                          link_type integer NOT NULL,
                          snaplen bigint NOT NULL,
                          timestamp_resolution_numerator bigint NOT NULL,
                          timestamp_resolution_denominator bigint NOT NULL,
                          timestamp_offset_seconds bigint NOT NULL,
                          PRIMARY KEY(build_id,interface_ordinal)
                        );
                        CREATE TABLE IF NOT EXISTS pcap_offset_index_packets (
                          build_id text NOT NULL
                            REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
                          packet_index bigint NOT NULL,
                          record_offset bigint NOT NULL,
                          data_offset bigint NOT NULL,
                          captured_length bigint NOT NULL,
                          original_length bigint NOT NULL,
                          framed_length bigint NOT NULL,
                          section_index integer NOT NULL,
                          interface_id integer NOT NULL,
                          interface_ordinal integer NOT NULL,
                          raw_timestamp_ticks numeric(20,0) NOT NULL,
                          PRIMARY KEY(build_id,packet_index)
                        );
                        CREATE TABLE IF NOT EXISTS pcap_offset_index_owners (
                          source_kind text NOT NULL,
                          source_id text NOT NULL,
                          build_id text NOT NULL UNIQUE
                            REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
                          PRIMARY KEY(source_kind,source_id)
                        );
                        CREATE TABLE IF NOT EXISTS pcap_offset_index_jobs (
                          source_kind text NOT NULL CHECK(source_kind='LIVE_SEGMENT'),
                          source_id text NOT NULL, sensor_id text NOT NULL,
                          analysis_job_id text NOT NULL, object_key text NOT NULL,
                          source_size_bytes bigint NOT NULL CHECK(source_size_bytes>=0),
                          source_sha256 text NOT NULL,
                          capture_format text NOT NULL CHECK(capture_format='PCAP'),
                          schema_version integer NOT NULL, parser_contract_version integer NOT NULL,
                          status text NOT NULL
                            CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
                          attempt integer NOT NULL DEFAULT 0,
                          max_attempts integer NOT NULL CHECK(max_attempts>0),
                          lease_token text, lease_expires_at timestamptz,
                          next_attempt_at timestamptz NOT NULL, queued_at timestamptz NOT NULL,
                          updated_at timestamptz NOT NULL, completed_at timestamptz,
                          error_code text, published_build_id text,
                          published_source_version_id text,
                          PRIMARY KEY(source_kind,source_id)
                        );
                        CREATE TABLE IF NOT EXISTS pcap_posting_index_intents (
                          source_kind text NOT NULL
                            CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                          source_id text NOT NULL,
                          source_version_id text NOT NULL,
                          source_size_bytes bigint NOT NULL CHECK(source_size_bytes>=0),
                          source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
                          capture_format text NOT NULL CHECK(capture_format IN ('PCAP','PCAPNG')),
                          parent_structural_build_id text NOT NULL
                            REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
                          parent_structural_index_sha256 text NOT NULL
                            CHECK(parent_structural_index_sha256 ~ '^[0-9a-f]{64}$'),
                          structural_schema_version integer NOT NULL
                            CHECK(structural_schema_version>0),
                          structural_parser_contract_version integer NOT NULL
                            CHECK(structural_parser_contract_version>0),
                          posting_schema_version integer NOT NULL CHECK(posting_schema_version>0),
                          posting_parser_contract_version integer NOT NULL
                            CHECK(posting_parser_contract_version>0),
                          filter_contract_version integer NOT NULL CHECK(filter_contract_version>0),
                          status text NOT NULL
                            CHECK(status IN ('PENDING','DEFERRED','COMPLETED','FAILED')),
                          requested_at timestamptz NOT NULL,
                          updated_at timestamptz NOT NULL,
                          published_build_id text,
                          terminal_attempt integer
                            CHECK(terminal_attempt IS NULL OR terminal_attempt>=0),
                          terminal_max_attempts integer
                            CHECK(terminal_max_attempts IS NULL OR terminal_max_attempts>0),
                          error_code text
                            CHECK(error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
                          PRIMARY KEY(source_kind,source_id),
                          CONSTRAINT pcap_posting_index_intents_source_parent_key
                            UNIQUE(source_kind,source_id,parent_structural_build_id),
                          FOREIGN KEY(source_kind,source_id)
                            REFERENCES pcap_capture_source_versions(source_kind,source_id)
                            ON DELETE CASCADE
                        );
                        CREATE TABLE IF NOT EXISTS pcap_posting_index_jobs (
                          source_kind text NOT NULL
                            CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                          source_id text NOT NULL,
                          parent_structural_build_id text NOT NULL,
                          status text NOT NULL
                            CHECK(status IN ('QUEUED','RUNNING','COMPLETED','FAILED')),
                          attempt integer NOT NULL DEFAULT 0 CHECK(attempt>=0),
                          max_attempts integer NOT NULL CHECK(max_attempts>0),
                          lease_token text,
                          lease_expires_at timestamptz,
                          next_attempt_at timestamptz NOT NULL,
                          queued_at timestamptz NOT NULL,
                          updated_at timestamptz NOT NULL,
                          error_code text
                            CHECK(error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
                          PRIMARY KEY(source_kind,source_id),
                          CONSTRAINT pcap_posting_index_jobs_intent_parent_fkey
                            FOREIGN KEY(source_kind,source_id,parent_structural_build_id)
                            REFERENCES pcap_posting_index_intents(
                              source_kind,source_id,parent_structural_build_id
                            ) ON DELETE CASCADE
                        );
                        CREATE TABLE IF NOT EXISTS pcap_posting_index_generations (
                          build_id text PRIMARY KEY,
                          source_kind text NOT NULL
                            CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                          source_id text NOT NULL,
                          source_version_id text NOT NULL,
                          source_size_bytes bigint NOT NULL CHECK(source_size_bytes>=0),
                          source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[0-9a-f]{64}$'),
                          capture_format text NOT NULL CHECK(capture_format IN ('PCAP','PCAPNG')),
                          parent_structural_build_id text NOT NULL
                            REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE,
                          parent_structural_index_sha256 text NOT NULL
                            CHECK(parent_structural_index_sha256 ~ '^[0-9a-f]{64}$'),
                          structural_schema_version integer NOT NULL
                            CHECK(structural_schema_version>0),
                          structural_parser_contract_version integer NOT NULL
                            CHECK(structural_parser_contract_version>0),
                          posting_schema_version integer NOT NULL CHECK(posting_schema_version>0),
                          posting_parser_contract_version integer NOT NULL
                            CHECK(posting_parser_contract_version>0),
                          filter_contract_version integer NOT NULL CHECK(filter_contract_version>0),
                          state text NOT NULL CHECK(state IN ('STAGING','READY')),
                          created_at timestamptz NOT NULL,
                          packet_count bigint NOT NULL CHECK(packet_count>=0),
                          supported_count bigint NOT NULL CHECK(supported_count>=0),
                          membership_count bigint NOT NULL CHECK(membership_count>=0),
                          distinct_key_count bigint NOT NULL CHECK(distinct_key_count>=0),
                          chunk_count bigint NOT NULL CHECK(chunk_count>=0),
                          encoded_byte_count bigint NOT NULL CHECK(encoded_byte_count>=0),
                          complete_dimensions text[] NOT NULL,
                          posting_index_sha256 text NOT NULL
                            CHECK(posting_index_sha256 ~ '^[0-9a-f]{64}$'),
                          binding_document bytea NOT NULL,
                          builder_attempt integer NOT NULL CHECK(builder_attempt>0),
                          lease_token text NOT NULL,
                          expected_owner_build_id text,
                          UNIQUE(source_kind,source_id,parent_structural_build_id,build_id),
                          FOREIGN KEY(source_kind,source_id)
                            REFERENCES pcap_capture_source_versions(source_kind,source_id)
                            ON DELETE CASCADE
                        );
                        CREATE TABLE IF NOT EXISTS pcap_posting_index_chunks (
                          build_id text NOT NULL
                            REFERENCES pcap_posting_index_generations(build_id) ON DELETE CASCADE,
                          dimension text NOT NULL CHECK(dimension IN (
                            'ALL_PACKET','SUPPORTED','SRC_ADDRESS','DST_ADDRESS','SRC_PORT',
                            'DST_PORT','PROTOCOL','HAS_PAYLOAD'
                          )),
                          canonical_value bytea NOT NULL,
                          chunk_ordinal bigint NOT NULL CHECK(chunk_ordinal>=0),
                          first_packet_index bigint NOT NULL CHECK(first_packet_index>=0),
                          last_packet_index bigint NOT NULL
                            CHECK(last_packet_index>=first_packet_index),
                          membership_count bigint NOT NULL CHECK(membership_count>0),
                          encoded_ordinals bytea NOT NULL,
                          PRIMARY KEY(build_id,dimension,canonical_value,chunk_ordinal)
                        );
                        CREATE TABLE IF NOT EXISTS pcap_posting_index_owners (
                          source_kind text NOT NULL
                            CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT')),
                          source_id text NOT NULL,
                          parent_structural_build_id text NOT NULL,
                          build_id text NOT NULL UNIQUE,
                          PRIMARY KEY(source_kind,source_id,parent_structural_build_id),
                          FOREIGN KEY(source_kind,source_id,parent_structural_build_id,build_id)
                            REFERENCES pcap_posting_index_generations(
                              source_kind,source_id,parent_structural_build_id,build_id
                            ) ON DELETE CASCADE
                        );
                        DO $stage11$
                        BEGIN
                          IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint AS con
                            JOIN pg_class AS rel ON rel.oid=con.conrelid
                            JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                            WHERE nsp.nspname=current_schema()
                              AND rel.relname='pcap_posting_index_intents'
                              AND con.conname='pcap_posting_index_intents_source_parent_key'
                          ) THEN
                            ALTER TABLE pcap_posting_index_intents ADD CONSTRAINT
                              pcap_posting_index_intents_source_parent_key
                              UNIQUE(source_kind,source_id,parent_structural_build_id);
                          END IF;
                          IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint AS con
                            JOIN pg_class AS rel ON rel.oid=con.conrelid
                            JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                            WHERE nsp.nspname=current_schema()
                              AND rel.relname='pcap_posting_index_jobs'
                              AND con.conname='pcap_posting_index_jobs_intent_parent_fkey'
                          ) THEN
                            ALTER TABLE pcap_posting_index_jobs ADD CONSTRAINT
                              pcap_posting_index_jobs_intent_parent_fkey
                              FOREIGN KEY(source_kind,source_id,parent_structural_build_id)
                              REFERENCES pcap_posting_index_intents(
                                source_kind,source_id,parent_structural_build_id
                              ) ON DELETE CASCADE;
                          END IF;
                          ALTER TABLE pcap_posting_index_jobs DROP CONSTRAINT IF EXISTS
                            pcap_posting_index_jobs_source_kind_source_id_fkey;
                          ALTER TABLE pcap_posting_index_jobs DROP CONSTRAINT IF EXISTS
                            pcap_posting_index_jobs_parent_structural_build_id_fkey;
                        END $stage11$;
                        CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_claim
                          ON pcap_posting_index_jobs(
                            status,next_attempt_at,queued_at,source_kind,source_id
                          );
                        CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_lease
                          ON pcap_posting_index_jobs(status,lease_expires_at,source_kind,source_id);
                        CREATE INDEX IF NOT EXISTS pcap_posting_index_jobs_terminal
                          ON pcap_posting_index_jobs(status,updated_at,source_kind,source_id);
                        CREATE INDEX IF NOT EXISTS pcap_posting_index_intents_reconcile
                          ON pcap_posting_index_intents(status,requested_at,source_kind,source_id);
                        CREATE INDEX IF NOT EXISTS pcap_posting_index_generations_staging
                          ON pcap_posting_index_generations(state,created_at,build_id);
                        CREATE INDEX IF NOT EXISTS pcap_posting_index_chunks_read
                          ON pcap_posting_index_chunks(
                            build_id,dimension,canonical_value,chunk_ordinal
                          );
                        DO $stage10$
                        DECLARE
                          target_table text;
                          constraint_row record;
                        BEGIN
                          FOREACH target_table IN ARRAY ARRAY[
                            'pcap_capture_source_versions',
                            'pcap_offset_index_generations'
                          ] LOOP
                            FOR constraint_row IN
                              SELECT con.conname
                              FROM pg_constraint AS con
                              JOIN pg_class AS rel ON rel.oid=con.conrelid
                              JOIN pg_namespace AS nsp ON nsp.oid=rel.relnamespace
                              WHERE nsp.nspname=current_schema()
                                AND rel.relname=target_table
                                AND con.contype='c'
                                AND pg_get_constraintdef(con.oid) LIKE '%source_kind%'
                                AND pg_get_constraintdef(con.oid) LIKE '%PCAP_UPLOAD%'
                                AND pg_get_constraintdef(con.oid) NOT LIKE '%LIVE_SEGMENT%'
                            LOOP
                              EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I',
                                             target_table,constraint_row.conname);
                            END LOOP;
                          END LOOP;
                          IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint con
                            JOIN pg_class rel ON rel.oid=con.conrelid
                            WHERE rel.relname='pcap_capture_source_versions'
                              AND con.contype='c'
                              AND pg_get_constraintdef(con.oid) LIKE '%LIVE_SEGMENT%'
                          ) THEN
                            ALTER TABLE pcap_capture_source_versions ADD CONSTRAINT
                              pcap_capture_source_versions_source_kind_check
                              CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT'));
                          END IF;
                          IF NOT EXISTS (
                            SELECT 1 FROM pg_constraint con
                            JOIN pg_class rel ON rel.oid=con.conrelid
                            WHERE rel.relname='pcap_offset_index_generations'
                              AND con.contype='c'
                              AND pg_get_constraintdef(con.oid) LIKE '%LIVE_SEGMENT%'
                          ) THEN
                            ALTER TABLE pcap_offset_index_generations ADD CONSTRAINT
                              pcap_offset_index_generations_source_kind_check
                              CHECK(source_kind IN ('PCAP_UPLOAD','LIVE_SEGMENT'));
                          END IF;
                        END $stage10$;
                        CREATE INDEX IF NOT EXISTS pcap_offset_index_generations_staging
                          ON pcap_offset_index_generations(state,created_at,build_id);
                        CREATE INDEX IF NOT EXISTS pcap_offset_index_packets_lookup
                          ON pcap_offset_index_packets(build_id,packet_index);
                        CREATE INDEX IF NOT EXISTS pcap_offset_index_jobs_claim
                          ON pcap_offset_index_jobs(status,next_attempt_at,queued_at,source_id);
                        CREATE INDEX IF NOT EXISTS pcap_offset_index_jobs_lease
                          ON pcap_offset_index_jobs(status,lease_expires_at);
                        CREATE UNIQUE INDEX IF NOT EXISTS pcap_export_jobs_principal_idempotency
                          ON pcap_export_jobs(principal_scope,idempotency_key)
                          WHERE idempotency_key IS NOT NULL;
                        CREATE UNIQUE INDEX IF NOT EXISTS pcap_export_jobs_reusable_coalesce
                          ON pcap_export_jobs(principal_scope,coalesce_fingerprint)
                          WHERE status IN ('QUEUED','RUNNING','COMPLETED');
                        CREATE INDEX IF NOT EXISTS pcap_export_jobs_claim
                          ON pcap_export_jobs(status,next_attempt_at,queued_at);
                        CREATE INDEX IF NOT EXISTS pcap_export_jobs_lease
                          ON pcap_export_jobs(status,lease_expires_at);
                        CREATE INDEX IF NOT EXISTS pcap_export_jobs_parent
                          ON pcap_export_jobs(parent_job_id,status);
                        CREATE INDEX IF NOT EXISTS controller_objects_active_live_jobs
                          ON controller_objects ((data->>'status'))
                          WHERE kind='job' AND data->>'mode'='LIVE';
                        CREATE INDEX IF NOT EXISTS controller_objects_sensor_pcap_job_uploaded_id
                          ON controller_objects (
                            (data->>'analysis_job_id'),(data->>'uploaded_at'),id
                          ) WHERE kind='sensor_pcap';

                        INSERT INTO job_flow_records(job_id,data)
                          SELECT id,data->'flow_records'
                          FROM controller_objects
                          WHERE kind='job' AND data ? 'flow_records'
                          ON CONFLICT(job_id) DO NOTHING;
                        UPDATE controller_objects
                          SET data=data-'flow_records'
                          WHERE kind='job' AND data ? 'flow_records';
                        INSERT INTO job_flow_record_chunks(job_id,chunk_no,data)
                          SELECT job_id,0,data
                          FROM job_flow_records
                          ON CONFLICT(job_id,chunk_no) DO NOTHING;
                        DELETE FROM job_flow_records AS legacy
                          WHERE EXISTS (
                            SELECT 1
                            FROM job_flow_record_chunks AS chunk
                            WHERE chunk.job_id=legacy.job_id
                          );
                        CREATE INDEX IF NOT EXISTS job_flow_record_chunks_job_id
                          ON job_flow_record_chunks(job_id,chunk_no);
                        INSERT INTO job_payload_signatures(job_id,data)
                          SELECT id,data->'payload_signatures'
                          FROM controller_objects
                          WHERE kind='job' AND data ? 'payload_signatures'
                          ON CONFLICT(job_id) DO NOTHING;
                        UPDATE controller_objects
                          SET data=data-'payload_signatures'
                          WHERE kind='job' AND data ? 'payload_signatures';
                        INSERT INTO candidate_records(
                          candidate_id,job_id,position,score,severity,excluded,data
                        )
                          SELECT candidate->>'id',legacy.job_id,entry.ordinality-1,
                                 COALESCE((candidate->>'score')::integer,0),
                                 COALESCE(candidate->>'severity',''),
                                 COALESCE((candidate->>'excluded')::boolean,false),candidate
                          FROM job_candidates AS legacy
                          CROSS JOIN LATERAL jsonb_array_elements(legacy.data)
                            WITH ORDINALITY AS entry(candidate,ordinality)
                          WHERE candidate ? 'id'
                          ON CONFLICT(candidate_id) DO NOTHING;
                        DELETE FROM job_candidates AS legacy
                          WHERE jsonb_array_length(legacy.data)=(
                            SELECT COUNT(*)
                            FROM candidate_records AS record
                            WHERE record.job_id=legacy.job_id
                          );
                        """
                    )
                connection.commit()
                self._ensure_candidate_query_indexes(connection)
            except Exception:
                connection.close()
                raise
            self._connection = connection
            return connection

    @staticmethod
    def _ensure_candidate_query_indexes(connection: Any) -> None:
        indexes = (
            (
                "candidate_records_score",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_score "
                "ON candidate_records (score DESC,candidate_id) WHERE excluded=false",
            ),
            (
                "candidate_records_last_seen",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_last_seen "
                "ON candidate_records ((data->>'last_seen') DESC,candidate_id) "
                "WHERE excluded=false",
            ),
            (
                "candidate_records_first_seen",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_first_seen "
                "ON candidate_records ((data->>'first_seen') DESC,candidate_id) "
                "WHERE excluded=false",
            ),
            (
                "candidate_records_ip",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS candidate_records_ip "
                "ON candidate_records ((data->>'candidate_ip'),candidate_id) "
                "WHERE excluded=false",
            ),
            (
                "controller_objects_candidate_workflow",
                "CREATE INDEX CONCURRENTLY IF NOT EXISTS controller_objects_candidate_workflow "
                "ON controller_objects "
                "(kind,(data->>'candidate_id'),(data->>'created_at') DESC) "
                "WHERE kind IN "
                "('candidate-decision','candidate-action','candidate-ti-lookup',"
                "'candidate-misp-action')",
            ),
        )
        index_names = tuple(name for name, _ in indexes)
        connection.autocommit = True
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_advisory_lock(2026081301)")
                try:
                    cursor.execute(
                        "SELECT indexrelid::regclass::text FROM pg_index "
                        "WHERE NOT indisvalid AND indexrelid::regclass::text=ANY(%s)",
                        (list(index_names),),
                    )
                    invalid_indexes = {str(row[0]) for row in cursor.fetchall()}
                    for index_name in index_names:
                        if index_name in invalid_indexes:
                            cursor.execute(f"DROP INDEX CONCURRENTLY IF EXISTS {index_name}")
                    for _, statement in indexes:
                        cursor.execute(statement)
                finally:
                    cursor.execute("SELECT pg_advisory_unlock(2026081301)")
        finally:
            connection.autocommit = False

    def close(self) -> None:
        with self._lock:
            if self._connection is not None and not self._connection.closed:
                self._connection.close()
            self._connection = None

    def for_background_worker(self) -> PostgresRepository:
        return PostgresRepository(self.database_url, self.blob_store)

    @staticmethod
    def _sanitize_json_value(value: Any) -> Any:
        """Make arbitrary control-plane values safe for PostgreSQL text/jsonb."""
        if isinstance(value, str):
            # PostgreSQL text/jsonb cannot represent U+0000. Preserve its
            # presence as a visible escaped marker instead of dropping data.
            return value.replace("\x00", "\\x00")
        if isinstance(value, dict):
            return {
                key: PostgresRepository._sanitize_json_value(item) for key, item in value.items()
            }
        if isinstance(value, list | tuple):
            return [PostgresRepository._sanitize_json_value(item) for item in value]
        return value

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(
            PostgresRepository._sanitize_json_value(value),
            separators=(",", ":"),
            default=str,
            ensure_ascii=False,
        )

    @classmethod
    def _json_array_chunks(cls, values: list[Any]) -> list[str]:
        """Serialize a JSON array into independently storable bounded chunks."""
        target = cls._FLOW_RECORD_CHUNK_TARGET_BYTES
        chunks: list[str] = []
        current: list[str] = []
        current_size = 2  # opening and closing brackets

        for value in values:
            serialized = cls._json(value)
            serialized_size = len(serialized.encode("utf-8"))
            separator_size = 1 if current else 0
            if current and current_size + separator_size + serialized_size > target:
                chunks.append(",".join(current))
                current = []
                current_size = 2
                separator_size = 0
            current.append(serialized)
            current_size += separator_size + serialized_size

        if current:
            chunks.append(",".join(current))
        return chunks

    @classmethod
    def _replace_job_flow_records(cls, cursor: Any, job_id: str, records: list[Any]) -> None:
        try:
            cursor.execute("DELETE FROM job_flow_record_chunks WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_flow_records WHERE job_id=%s", (job_id,))
            for chunk_no, chunk in enumerate(cls._json_array_chunks(records)):
                cursor.execute(
                    "INSERT INTO job_flow_record_chunks(job_id,chunk_no,data) "
                    "VALUES(%s,%s,('[' || %s || ']')::jsonb)",
                    (job_id, chunk_no, chunk),
                )
        except Exception:
            # A failed statement leaves a PostgreSQL transaction aborted until rollback.
            # Roll back here because both create_job() and save_job() call this helper.
            cursor.connection.rollback()
            raise

    @staticmethod
    def _load_job_flow_records(cursor: Any, job_id: str) -> list[Any]:
        cursor.execute(
            "SELECT data FROM job_flow_record_chunks WHERE job_id=%s ORDER BY chunk_no",
            (job_id,),
        )
        rows = cursor.fetchall()
        if rows:
            records: list[Any] = []
            for row in rows:
                value = row[0]
                chunk = value if isinstance(value, list) else json.loads(value)
                if not isinstance(chunk, list):
                    raise RuntimeError("stored flow-record chunk is not a JSON array")
                records.extend(chunk)
            return records

        # Compatibility fallback for a database that has not yet been migrated.
        cursor.execute("SELECT data FROM job_flow_records WHERE job_id=%s", (job_id,))
        row = cursor.fetchone()
        if row is None:
            return []
        value = row[0]
        records = value if isinstance(value, list) else json.loads(value)
        if not isinstance(records, list):
            raise RuntimeError("stored flow records are not a JSON array")
        return records

    def ready(self) -> bool:
        return self.database_ready() and self.blob_store.ready()

    _POSTING_SPEC_COLUMNS = (
        "source_kind,source_id,source_version_id,source_size_bytes,source_sha256,"
        "capture_format,parent_structural_build_id,parent_structural_index_sha256,"
        "structural_schema_version,structural_parser_contract_version,"
        "posting_schema_version,posting_parser_contract_version,filter_contract_version"
    )
    _POSTING_INTENT_COLUMNS = (
        _POSTING_SPEC_COLUMNS + ",status,requested_at,updated_at,published_build_id,error_code"
    )
    _POSTING_TASK_COLUMNS = (
        _POSTING_SPEC_COLUMNS
        + ",status,attempt,max_attempts,lease_token,lease_expires_at,next_attempt_at,"
        "queued_at,updated_at,error_code"
    )
    _POSTING_TASK_PROJECTION = (
        "intent."
        + _POSTING_SPEC_COLUMNS.replace(",", ",intent.")
        + ",task.status,task.attempt,task.max_attempts,task.lease_token,"
        "task.lease_expires_at,task.next_attempt_at,task.queued_at,task.updated_at,"
        "task.error_code"
    )

    @staticmethod
    def _posting_spec(row: tuple[Any, ...]) -> PostingIndexTaskSpec:
        return PostingIndexTaskSpec(
            source_kind=cast(PostingSourceKind, str(row[0])),
            source_id=str(row[1]),
            source_version_id=str(row[2]),
            source_size_bytes=int(row[3]),
            source_sha256=str(row[4]),
            capture_format=cast(Any, str(row[5])),
            parent_structural_build_id=str(row[6]),
            parent_structural_index_sha256=str(row[7]),
            structural_schema_version=int(row[8]),
            structural_parser_contract_version=int(row[9]),
            posting_schema_version=int(row[10]),
            posting_parser_contract_version=int(row[11]),
            filter_contract_version=int(row[12]),
        )

    @classmethod
    def _posting_intent(cls, row: tuple[Any, ...]) -> PostingIndexIntent:
        return PostingIndexIntent(
            cls._posting_spec(row),
            PostingIndexIntentStatus(str(row[13])),
            cast(datetime, row[14]),
            cast(datetime, row[15]),
            str(row[16]) if row[16] is not None else None,
            str(row[17]) if row[17] is not None else None,
        )

    @classmethod
    def _posting_task(cls, row: tuple[Any, ...]) -> PostingIndexTask:
        return PostingIndexTask(
            cls._posting_spec(row),
            PostingIndexTaskStatus(str(row[13])),
            int(row[14]),
            int(row[15]),
            str(row[16]) if row[16] is not None else None,
            cast(datetime | None, row[17]),
            cast(datetime, row[18]),
            cast(datetime, row[19]),
            cast(datetime, row[20]),
            str(row[21]) if row[21] is not None else None,
        )

    @staticmethod
    def _posting_spec_values(spec: PostingIndexTaskSpec) -> tuple[Any, ...]:
        return (
            spec.source_kind,
            spec.source_id,
            spec.source_version_id,
            spec.source_size_bytes,
            spec.source_sha256,
            spec.capture_format,
            spec.parent_structural_build_id,
            spec.parent_structural_index_sha256,
            spec.structural_schema_version,
            spec.structural_parser_contract_version,
            spec.posting_schema_version,
            spec.posting_parser_contract_version,
            spec.filter_contract_version,
        )

    @staticmethod
    def _lock_posting_lifecycle_for_sources(
        cursor: Any, source_kind: PostingSourceKind, source_ids: Iterable[str]
    ) -> None:
        """Lock exact posting rows in the one global PostgreSQL posting order.

        Every request, publication, abort, cleanup, structural replacement, and
        source deletion follows: canonical source/version -> structural
        owner/generation -> intent -> task -> posting generation -> posting owner.
        Object-store calls must happen only after the surrounding transaction commits.
        """
        selected_ids = sorted(set(source_ids))
        if not selected_ids:
            return
        params = (source_kind, selected_ids)
        cursor.execute(
            "SELECT source_id FROM pcap_capture_source_versions WHERE source_kind=%s "
            "AND source_id=ANY(%s) ORDER BY source_id FOR UPDATE",
            params,
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT owner.source_id,owner.build_id FROM pcap_offset_index_owners AS owner "
            "JOIN pcap_offset_index_generations AS generation ON generation.build_id="
            "owner.build_id WHERE owner.source_kind=%s AND owner.source_id=ANY(%s) "
            "ORDER BY owner.source_id,owner.build_id FOR UPDATE OF owner,generation",
            params,
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT source_id,build_id FROM pcap_offset_index_generations WHERE "
            "source_kind=%s AND source_id=ANY(%s) ORDER BY source_id,build_id FOR UPDATE",
            params,
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT source_id,parent_structural_build_id FROM pcap_posting_index_intents "
            "WHERE source_kind=%s AND source_id=ANY(%s) ORDER BY source_id FOR UPDATE",
            params,
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT source_id,parent_structural_build_id FROM pcap_posting_index_jobs "
            "WHERE source_kind=%s AND source_id=ANY(%s) ORDER BY source_id FOR UPDATE",
            params,
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT source_id,parent_structural_build_id,build_id FROM "
            "pcap_posting_index_generations WHERE source_kind=%s AND source_id=ANY(%s) "
            "ORDER BY source_id,parent_structural_build_id,build_id FOR UPDATE",
            params,
        )
        cursor.fetchall()
        cursor.execute(
            "SELECT source_id,parent_structural_build_id,build_id FROM "
            "pcap_posting_index_owners WHERE source_kind=%s AND source_id=ANY(%s) "
            "ORDER BY source_id,parent_structural_build_id FOR UPDATE",
            params,
        )
        cursor.fetchall()

    @_serialize_shared_connection
    def request_posting_index_backfill(self, *, limit: int) -> int:
        if limit <= 0:
            raise ValueError("posting backfill limit must be positive")
        query = f"""
WITH eligible_posting_parents AS (
  SELECT source.source_kind,
         source.source_id,
         source.source_version_id,
         source.source_size_bytes,
         source.source_sha256,
         generation.capture_format,
         owner.build_id AS parent_structural_build_id,
         generation.index_sha256 AS parent_structural_index_sha256,
         generation.schema_version AS structural_schema_version,
         generation.parser_contract_version AS structural_parser_contract_version
  FROM pcap_offset_index_owners AS owner
  JOIN pcap_offset_index_generations AS generation
    ON generation.build_id=owner.build_id
  JOIN pcap_capture_source_versions AS source
    ON source.source_kind=owner.source_kind
   AND source.source_id=owner.source_id
  WHERE generation.state='READY'
    AND generation.source_kind=source.source_kind
    AND generation.source_id=source.source_id
    AND generation.source_version_id=source.source_version_id
    AND generation.source_size_bytes=source.source_size_bytes
    AND generation.source_sha256=source.source_sha256
    AND generation.schema_version=%s
    AND generation.parser_contract_version=%s
    AND (
      (
        source.source_kind='PCAP_UPLOAD'
        AND EXISTS (
          SELECT 1 FROM controller_objects AS job
          WHERE job.kind='job'
            AND job.id=source.source_id
            AND job.data->>'mode'='PCAP_UPLOAD'
        )
      )
      OR
      (
        source.source_kind='LIVE_SEGMENT'
        AND EXISTS (
          SELECT 1
          FROM controller_objects AS segment
          JOIN controller_objects AS job
            ON job.kind='job'
           AND job.id=segment.data->>'analysis_job_id'
          WHERE segment.kind='sensor_pcap'
            AND segment.id=source.source_id
            AND job.data->>'mode'='LIVE'
            AND segment.data->>'sha256'=source.source_sha256
            AND (segment.data->>'size_bytes')::bigint=source.source_size_bytes
        )
        AND EXISTS (
          SELECT 1 FROM pcap_offset_index_jobs AS live_task
          WHERE live_task.source_kind='LIVE_SEGMENT'
            AND live_task.source_id=source.source_id
            AND live_task.status='COMPLETED'
            AND live_task.source_size_bytes=source.source_size_bytes
            AND live_task.source_sha256=source.source_sha256
            AND live_task.published_source_version_id=source.source_version_id
        )
      )
    )
    AND NOT EXISTS (
      SELECT 1 FROM pcap_posting_index_intents AS intent
      WHERE intent.source_kind=source.source_kind
        AND intent.source_id=source.source_id
        AND intent.source_version_id=source.source_version_id
        AND intent.parent_structural_build_id=owner.build_id
        AND intent.posting_schema_version=%s
        AND intent.posting_parser_contract_version=%s
        AND intent.filter_contract_version=%s
    )
    AND NOT EXISTS (
      SELECT 1
      FROM pcap_posting_index_jobs AS task
      JOIN pcap_posting_index_intents AS task_intent USING(source_kind,source_id)
      WHERE task.source_kind=source.source_kind
        AND task.source_id=source.source_id
        AND task.parent_structural_build_id=owner.build_id
        AND task_intent.source_version_id=source.source_version_id
        AND task_intent.posting_schema_version=%s
        AND task_intent.posting_parser_contract_version=%s
        AND task_intent.filter_contract_version=%s
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
        AND posting_generation.source_version_id=source.source_version_id
        AND posting_generation.posting_schema_version={PCAP_POSTING_INDEX_SCHEMA_VERSION}
        AND posting_generation.posting_parser_contract_version=
            {PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION}
        AND posting_generation.filter_contract_version={PCAP_FILTER_CONTRACT_VERSION}
    )
  ORDER BY source.source_kind,source.source_id
  LIMIT %s
  FOR UPDATE OF owner SKIP LOCKED
), inserted_posting_intents AS (
  INSERT INTO pcap_posting_index_intents(
    {self._POSTING_SPEC_COLUMNS},status,requested_at,updated_at,
    published_build_id,error_code
  )
  SELECT source_kind,source_id,source_version_id,source_size_bytes,source_sha256,
         capture_format,parent_structural_build_id,parent_structural_index_sha256,
         structural_schema_version,structural_parser_contract_version,
         {PCAP_POSTING_INDEX_SCHEMA_VERSION},
         {PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION},
         {PCAP_FILTER_CONTRACT_VERSION},
         'PENDING',clock_timestamp(),clock_timestamp(),NULL,NULL
  FROM eligible_posting_parents
  ON CONFLICT(source_kind,source_id) DO NOTHING
  RETURNING source_kind,source_id
)
SELECT source_kind,source_id
FROM inserted_posting_intents
ORDER BY source_kind,source_id
"""  # noqa: S608 -- interpolation uses fixed internal columns/contracts only
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    query,
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
                )
                inserted = cursor.fetchall()
            connection.commit()
            return len(inserted)
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def request_posting_index(
        self, source_version: CaptureSourceVersion, parent: StructuralIndexSnapshot
    ) -> PostingIndexIntent | None:
        if (
            source_version.source_kind not in {"PCAP_UPLOAD", "LIVE_SEGMENT"}
            or not validate_structural_index(parent)
            or parent.binding.source_kind != source_version.source_kind
            or parent.binding.source_id != source_version.source_id
            or parent.binding.source_version_id != source_version.source_version_id
            or parent.binding.source_size_bytes != source_version.source_size_bytes
            or parent.binding.source_sha256 != source_version.source_sha256
        ):
            return None
        spec = PostingIndexTaskSpec.from_binding(source_version, parent)
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,"
                    "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                    (spec.source_kind, spec.source_id),
                )
                source_row = cursor.fetchone()
                if source_row != (
                    source_version.source_kind,
                    source_version.source_id,
                    source_version.object_key,
                    source_version.source_version_id,
                    source_version.source_size_bytes,
                    source_version.source_sha256,
                ):
                    connection.rollback()
                    return None
                cursor.execute(
                    "SELECT owner.build_id,generation.index_sha256,generation.state "
                    "FROM pcap_offset_index_owners AS owner JOIN "
                    "pcap_offset_index_generations AS generation "
                    "ON generation.build_id=owner.build_id WHERE owner.source_kind=%s "
                    "AND owner.source_id=%s AND owner.build_id=%s AND generation.state='READY' "
                    "FOR UPDATE OF owner,generation",
                    (spec.source_kind, spec.source_id, spec.parent_structural_build_id),
                )
                if cursor.fetchone() != (
                    parent.build_id,
                    parent.index_sha256,
                    "READY",
                ):
                    connection.rollback()
                    return None
                cursor.execute(
                    f"SELECT {self._POSTING_INTENT_COLUMNS} "  # noqa: S608 -- fixed internal columns
                    "FROM pcap_posting_index_intents WHERE source_kind=%s AND source_id=%s "
                    "FOR UPDATE",
                    (spec.source_kind, spec.source_id),
                )
                row = cursor.fetchone()
                if row is not None:
                    current = self._posting_intent(row)
                    if current.spec.identity == spec.identity:
                        connection.commit()
                        return current
                values = self._posting_spec_values(spec)
                cursor.execute(
                    "INSERT INTO pcap_posting_index_intents("
                    + self._POSTING_SPEC_COLUMNS
                    + ",status,requested_at,updated_at,published_build_id,error_code) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',"
                    "clock_timestamp(),clock_timestamp(),NULL,NULL) "
                    "ON CONFLICT(source_kind,source_id) DO UPDATE SET "
                    "source_version_id=excluded.source_version_id,"
                    "source_size_bytes=excluded.source_size_bytes,"
                    "source_sha256=excluded.source_sha256,capture_format=excluded.capture_format,"
                    "parent_structural_build_id=excluded.parent_structural_build_id,"
                    "parent_structural_index_sha256=excluded.parent_structural_index_sha256,"
                    "structural_schema_version=excluded.structural_schema_version,"
                    "structural_parser_contract_version=excluded.structural_parser_contract_version,"
                    "posting_schema_version=excluded.posting_schema_version,"
                    "posting_parser_contract_version=excluded.posting_parser_contract_version,"
                    "filter_contract_version=excluded.filter_contract_version,status='PENDING',"
                    "requested_at=clock_timestamp(),updated_at=clock_timestamp(),"
                    "published_build_id=NULL,error_code=NULL RETURNING "
                    + self._POSTING_INTENT_COLUMNS,
                    values,
                )
                stored = cursor.fetchone()
                if stored is None or cursor.rowcount != 1:
                    connection.rollback()
                    return None
            connection.commit()
            return self._posting_intent(stored)
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def get_posting_index_intent(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexIntent | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {self._POSTING_INTENT_COLUMNS} FROM pcap_posting_index_intents "  # noqa: S608 -- fixed internal columns
                "WHERE source_kind=%s AND source_id=%s",
                (source_kind, source_id),
            )
            row = cursor.fetchone()
        self.connection.commit()
        return self._posting_intent(row) if row is not None else None

    @_serialize_shared_connection
    def admit_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        capacity: int,
        max_attempts: int,
    ) -> PostingIndexAdmission:
        if capacity <= 0 or max_attempts <= 0:
            raise ValueError("posting queue bounds must be positive")
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT {self._POSTING_INTENT_COLUMNS} FROM pcap_posting_index_intents "  # noqa: S608 -- fixed internal columns
                    "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                    (source_kind, source_id),
                )
                intent_row = cursor.fetchone()
                if intent_row is None:
                    connection.commit()
                    return PostingIndexAdmission.INELIGIBLE
                intent = self._posting_intent(intent_row)
                cursor.execute(
                    "SELECT status FROM pcap_posting_index_jobs WHERE source_kind=%s "
                    "AND source_id=%s FOR UPDATE",
                    (source_kind, source_id),
                )
                if cursor.fetchone() is not None or intent.status in {
                    PostingIndexIntentStatus.COMPLETED,
                    PostingIndexIntentStatus.FAILED,
                }:
                    connection.commit()
                    return PostingIndexAdmission.COALESCED
                if intent.status not in {
                    PostingIndexIntentStatus.PENDING,
                    PostingIndexIntentStatus.DEFERRED,
                }:
                    connection.commit()
                    return PostingIndexAdmission.INELIGIBLE
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                    ("pcap-posting-index-admission",),
                )
                cursor.execute(
                    "SELECT COUNT(*) FROM pcap_posting_index_jobs "
                    "WHERE status IN ('QUEUED','RUNNING')"
                )
                active_row = cursor.fetchone()
                active = int(active_row[0]) if active_row else 0
                if active >= capacity:
                    cursor.execute(
                        "UPDATE pcap_posting_index_intents SET status='DEFERRED',"
                        "updated_at=clock_timestamp() WHERE source_kind=%s AND source_id=%s "
                        "AND status IN ('PENDING','DEFERRED')",
                        (source_kind, source_id),
                    )
                    if cursor.rowcount != 1:
                        connection.rollback()
                        return PostingIndexAdmission.INELIGIBLE
                    connection.commit()
                    return PostingIndexAdmission.DEFERRED
                cursor.execute(
                    "INSERT INTO pcap_posting_index_jobs(source_kind,source_id,"
                    "parent_structural_build_id,status,attempt,max_attempts,lease_token,"
                    "lease_expires_at,next_attempt_at,queued_at,updated_at,error_code) "
                    "VALUES(%s,%s,%s,'QUEUED',0,%s,NULL,NULL,clock_timestamp(),"
                    "clock_timestamp(),clock_timestamp(),NULL) ON CONFLICT DO NOTHING",
                    (source_kind, source_id, intent.spec.parent_structural_build_id, max_attempts),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    return PostingIndexAdmission.COALESCED
            connection.commit()
            return PostingIndexAdmission.QUEUED
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def get_posting_index_task(
        self, source_kind: PostingSourceKind, source_id: str
    ) -> PostingIndexTask | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {self._POSTING_TASK_PROJECTION} "  # noqa: S608 -- fixed internal projection
                "FROM pcap_posting_index_jobs AS task "
                "JOIN pcap_posting_index_intents AS intent USING(source_kind,source_id) "
                "WHERE task.source_kind=%s AND task.source_id=%s",
                (source_kind, source_id),
            )
            row = cursor.fetchone()
        self.connection.commit()
        return self._posting_task(row) if row is not None else None

    @_serialize_shared_connection
    def claim_posting_index(self, *, lease_seconds: int) -> PostingIndexTask | None:
        if lease_seconds <= 0:
            raise ValueError("posting lease must be positive")
        token = secrets.token_hex(16)
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "WITH selected AS (SELECT task.source_kind,task.source_id FROM "  # noqa: S608 -- fixed internal projection appended below
                    "pcap_posting_index_jobs AS task WHERE task.status='QUEUED' "
                    "AND task.next_attempt_at<=clock_timestamp() AND EXISTS (SELECT 1 FROM "
                    "pcap_posting_index_intents AS intent WHERE "
                    "intent.source_kind=task.source_kind AND intent.source_id=task.source_id "
                    "AND intent.parent_structural_build_id=task.parent_structural_build_id "
                    "AND intent.status IN ('PENDING','DEFERRED')) "
                    "ORDER BY task.next_attempt_at,task.queued_at,task.source_kind,task.source_id "
                    "FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE pcap_posting_index_jobs AS task "
                    "SET status='RUNNING',attempt=task.attempt+1,lease_token=%s,"
                    "lease_expires_at=clock_timestamp()+make_interval(secs=>%s),"
                    "updated_at=clock_timestamp(),error_code=NULL FROM selected,"
                    "pcap_posting_index_intents AS intent WHERE "
                    "task.source_kind=selected.source_kind "
                    "AND task.source_id=selected.source_id AND intent.source_kind=task.source_kind "
                    "AND intent.source_id=task.source_id RETURNING "
                    + self._POSTING_TASK_PROJECTION,
                    (token, lease_seconds),
                )
                row = cursor.fetchone()
                if row is not None and cursor.rowcount != 1:
                    connection.rollback()
                    return None
            connection.commit()
            return self._posting_task(row) if row is not None else None
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def heartbeat_posting_index(
        self,
        source_kind: PostingSourceKind,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        lease_seconds: int,
    ) -> bool:
        if lease_seconds <= 0 or attempt <= 0 or not lease_token:
            return False
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE pcap_posting_index_jobs SET "
                    "lease_expires_at=clock_timestamp()+make_interval(secs=>%s),"
                    "updated_at=clock_timestamp() WHERE source_kind=%s AND source_id=%s "
                    "AND status='RUNNING' AND attempt=%s AND lease_token=%s "
                    "AND lease_expires_at>clock_timestamp()",
                    (lease_seconds, source_kind, source_id, attempt, lease_token),
                )
                updated = bool(cursor.rowcount == 1)
                if not updated:
                    connection.rollback()
                    return False
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
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
    ) -> bool:
        if attempt <= 0 or not lease_token or retry_base_seconds <= 0:
            return False
        code = sanitize_error_code(error_code)
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT parent_structural_build_id FROM pcap_posting_index_intents "
                    "WHERE source_kind=%s AND source_id=%s "
                    "AND status IN ('PENDING','DEFERRED') FOR UPDATE",
                    (source_kind, source_id),
                )
                intent_row = cursor.fetchone()
                if intent_row is None:
                    connection.rollback()
                    return False
                parent_id = str(intent_row[0])
                cursor.execute(
                    "SELECT task.max_attempts FROM pcap_posting_index_jobs AS task "
                    "WHERE task.source_kind=%s AND task.source_id=%s "
                    "AND task.parent_structural_build_id=%s AND task.status='RUNNING' "
                    "AND task.attempt=%s AND task.lease_token=%s "
                    "AND task.lease_expires_at>clock_timestamp() FOR UPDATE",
                    (source_kind, source_id, parent_id, attempt, lease_token),
                )
                task_row = cursor.fetchone()
                if task_row is None:
                    connection.rollback()
                    return False
                max_attempts = int(task_row[0])
                retry = transient and attempt < max_attempts
                task_status = "QUEUED" if retry else "FAILED"
                intent_status = "PENDING" if retry else "FAILED"
                cursor.execute(
                    "UPDATE pcap_posting_index_jobs SET status=%s,lease_token=NULL,"
                    "lease_expires_at=NULL,next_attempt_at=CASE WHEN %s THEN "
                    "clock_timestamp()+make_interval(secs=>LEAST(%s::bigint*"
                    "(1::bigint << LEAST(attempt-1,20)),2147483647)::integer) "
                    "ELSE next_attempt_at END,updated_at=clock_timestamp(),error_code=%s "
                    "WHERE source_kind=%s AND source_id=%s AND parent_structural_build_id=%s "
                    "AND status='RUNNING' AND attempt=%s AND lease_token=%s "
                    "AND lease_expires_at>clock_timestamp()",
                    (
                        task_status,
                        retry,
                        retry_base_seconds,
                        code,
                        source_kind,
                        source_id,
                        parent_id,
                        attempt,
                        lease_token,
                    ),
                )
                task_count = cursor.rowcount
                cursor.execute(
                    "UPDATE pcap_posting_index_intents SET status=%s,"
                    "updated_at=clock_timestamp(),error_code=%s,terminal_attempt=%s,"
                    "terminal_max_attempts=%s WHERE source_kind=%s AND source_id=%s "
                    "AND parent_structural_build_id=%s AND status IN ('PENDING','DEFERRED')",
                    (
                        intent_status,
                        code,
                        attempt,
                        max_attempts,
                        source_kind,
                        source_id,
                        parent_id,
                    ),
                )
                if task_count != 1 or cursor.rowcount != 1:
                    connection.rollback()
                    return False
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def recover_posting_indexes(self) -> int:
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT intent.source_kind,intent.source_id,"
                    "intent.parent_structural_build_id FROM pcap_posting_index_intents AS intent "
                    "WHERE intent.status IN ('PENDING','DEFERRED') AND EXISTS (SELECT 1 FROM "
                    "pcap_posting_index_jobs AS task WHERE task.source_kind=intent.source_kind "
                    "AND task.source_id=intent.source_id AND task.parent_structural_build_id="
                    "intent.parent_structural_build_id AND task.status='RUNNING' "
                    "AND task.lease_expires_at<=clock_timestamp()) "
                    "ORDER BY intent.updated_at,intent.source_kind,intent.source_id "
                    "FOR UPDATE OF intent SKIP LOCKED LIMIT %s",
                    (100,),
                )
                intents = cursor.fetchall()
                recovered = 0
                for kind, selected_id, parent_id in intents:
                    cursor.execute(
                        "SELECT task.max_attempts,task.attempt FROM "
                        "pcap_posting_index_jobs AS task WHERE task.source_kind=%s "
                        "AND task.source_id=%s AND task.parent_structural_build_id=%s "
                        "AND task.status='RUNNING' AND "
                        "task.lease_expires_at<=clock_timestamp() FOR UPDATE SKIP LOCKED",
                        (kind, selected_id, parent_id),
                    )
                    task_row = cursor.fetchone()
                    if task_row is None:
                        continue
                    maximum, task_attempt = int(task_row[0]), int(task_row[1])
                    retry = task_attempt < maximum
                    status = "QUEUED" if retry else "FAILED"
                    code = None if retry else "POSTING_LEASE_EXPIRED"
                    cursor.execute(
                        "UPDATE pcap_posting_index_jobs SET status=%s,lease_token=NULL,"
                        "lease_expires_at=NULL,next_attempt_at=clock_timestamp(),"
                        "updated_at=clock_timestamp(),error_code=%s WHERE source_kind=%s "
                        "AND source_id=%s AND parent_structural_build_id=%s "
                        "AND status='RUNNING' AND attempt=%s "
                        "AND lease_expires_at<=clock_timestamp()",
                        (status, code, kind, selected_id, parent_id, task_attempt),
                    )
                    task_count = cursor.rowcount
                    cursor.execute(
                        "UPDATE pcap_posting_index_intents SET status=%s,"
                        "updated_at=clock_timestamp(),error_code=%s,terminal_attempt=%s,"
                        "terminal_max_attempts=%s WHERE source_kind=%s AND source_id=%s "
                        "AND parent_structural_build_id=%s AND status IN ('PENDING','DEFERRED')",
                        (
                            "PENDING" if status == "QUEUED" else "FAILED",
                            code,
                            task_attempt,
                            maximum,
                            kind,
                            selected_id,
                            parent_id,
                        ),
                    )
                    if task_count != 1 or cursor.rowcount != 1:
                        connection.rollback()
                        return 0
                    recovered += 1
            connection.commit()
            return recovered
        except Exception:
            connection.rollback()
            raise

    def reconcile_posting_indexes(
        self,
        *,
        capacity: int,
        max_attempts: int,
        limit: int,
    ) -> int:
        if limit <= 0:
            raise ValueError("posting reconciliation limit must be positive")
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT intent.source_kind,intent.source_id FROM "
                "pcap_posting_index_intents AS intent WHERE "
                "intent.status IN ('PENDING','DEFERRED') AND NOT EXISTS (SELECT 1 FROM "
                "pcap_posting_index_jobs AS task WHERE task.source_kind=intent.source_kind "
                "AND task.source_id=intent.source_id) ORDER BY intent.requested_at,"
                "intent.source_kind,intent.source_id LIMIT %s",
                (limit,),
            )
            rows = [
                (cast(PostingSourceKind, str(row[0])), str(row[1])) for row in cursor.fetchall()
            ]
            self.connection.commit()
        admitted = 0
        for kind, selected_id in rows:
            if (
                self.admit_posting_index(
                    kind,
                    selected_id,
                    capacity=capacity,
                    max_attempts=max_attempts,
                )
                is PostingIndexAdmission.QUEUED
            ):
                admitted += 1
        return admitted

    @_serialize_shared_connection
    def get_posting_index_queue_depth(self) -> dict[str, int]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT status,COUNT(*) FROM pcap_posting_index_jobs GROUP BY status")
            rows = cursor.fetchall()
        self.connection.commit()
        counts = {str(status): int(count) for status, count in rows}
        return {status.value: counts.get(status.value, 0) for status in PostingIndexTaskStatus}

    @_serialize_shared_connection
    def cleanup_terminal_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int:
        if max_age_seconds <= 0 or limit <= 0:
            raise ValueError("posting terminal cleanup bounds must be positive")
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT source_kind,source_id FROM pcap_posting_index_jobs "
                    "WHERE status IN ('COMPLETED','FAILED') "
                    "AND updated_at<=clock_timestamp()-make_interval(secs=>%s) "
                    "ORDER BY updated_at,source_kind,source_id LIMIT %s",
                    (max_age_seconds, limit),
                )
                selected = [
                    (cast(PostingSourceKind, str(row[0])), str(row[1])) for row in cursor.fetchall()
                ]
                grouped: dict[PostingSourceKind, list[str]] = {}
                for source_kind, source_id in selected:
                    grouped.setdefault(source_kind, []).append(source_id)
                deleted = 0
                for source_kind in sorted(grouped):
                    source_ids = grouped[source_kind]
                    self._lock_posting_lifecycle_for_sources(cursor, source_kind, source_ids)
                    cursor.execute(
                        "DELETE FROM pcap_posting_index_jobs WHERE source_kind=%s "
                        "AND source_id=ANY(%s) AND status IN ('COMPLETED','FAILED') "
                        "AND updated_at<=clock_timestamp()-make_interval(secs=>%s) "
                        "RETURNING source_id",
                        (source_kind, source_ids, max_age_seconds),
                    )
                    deleted += len(cursor.fetchall())
            connection.commit()
            return deleted
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def cleanup_stale_posting_indexes(self, *, max_age_seconds: int, limit: int) -> int:
        if max_age_seconds <= 0 or limit <= 0:
            raise ValueError("posting staging cleanup bounds must be positive")
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT generation.source_kind,generation.source_id,generation.build_id FROM "
                    "pcap_posting_index_generations AS generation WHERE "
                    "generation.state='STAGING' AND generation.created_at<"
                    "clock_timestamp()-make_interval(secs=>%s) AND NOT EXISTS (SELECT 1 "
                    "FROM pcap_posting_index_owners AS owner WHERE "
                    "owner.build_id=generation.build_id) AND NOT EXISTS (SELECT 1 FROM "
                    "pcap_posting_index_jobs AS task WHERE "
                    "task.source_kind=generation.source_kind AND "
                    "task.source_id=generation.source_id AND task.parent_structural_build_id="
                    "generation.parent_structural_build_id AND task.status='RUNNING' "
                    "AND task.attempt=generation.builder_attempt AND "
                    "task.lease_token=generation.lease_token AND "
                    "task.lease_expires_at>clock_timestamp()) ORDER BY generation.created_at,"
                    "generation.build_id LIMIT %s",
                    (max_age_seconds, limit),
                )
                selected = [
                    (cast(PostingSourceKind, str(row[0])), str(row[1]), str(row[2]))
                    for row in cursor.fetchall()
                ]
                grouped: dict[PostingSourceKind, list[str]] = {}
                for source_kind, source_id, _build_id in selected:
                    grouped.setdefault(source_kind, []).append(source_id)
                for source_kind in sorted(grouped):
                    self._lock_posting_lifecycle_for_sources(
                        cursor, source_kind, grouped[source_kind]
                    )
                build_ids = [build_id for _kind, _source_id, build_id in selected]
                rows: list[tuple[Any, ...]] = []
                if build_ids:
                    cursor.execute(
                        "DELETE FROM pcap_posting_index_generations AS generation WHERE "
                        "generation.build_id=ANY(%s) AND generation.state='STAGING' AND "
                        "generation.created_at<clock_timestamp()-make_interval(secs=>%s) "
                        "AND NOT EXISTS (SELECT 1 FROM pcap_posting_index_owners AS owner "
                        "WHERE owner.build_id=generation.build_id) AND NOT EXISTS (SELECT 1 "
                        "FROM pcap_posting_index_jobs AS task WHERE task.source_kind="
                        "generation.source_kind AND task.source_id=generation.source_id AND "
                        "task.parent_structural_build_id=generation.parent_structural_build_id "
                        "AND task.status='RUNNING' AND task.attempt=generation.builder_attempt "
                        "AND task.lease_token=generation.lease_token AND "
                        "task.lease_expires_at>clock_timestamp()) RETURNING generation.build_id",
                        (build_ids, max_age_seconds),
                    )
                    rows = cursor.fetchall()
            connection.commit()
            return len(rows)
        except Exception:
            connection.rollback()
            raise

    @staticmethod
    def _posting_chunks(rows: Iterable[tuple[Any, ...]]) -> tuple[PostingChunk, ...]:
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

    @classmethod
    def _posting_snapshot_from_generation(
        cls, row: tuple[Any, ...], chunks: tuple[PostingChunk, ...]
    ) -> PostingIndexSnapshot:
        binding = PostingIndexBinding(
            cast(Any, str(row[1])),
            str(row[2]),
            str(row[3]),
            int(row[4]),
            str(row[5]),
            cast(Any, str(row[6])),
            str(row[7]),
            str(row[8]),
            int(row[9]),
            int(row[10]),
            int(row[11]),
            int(row[12]),
            int(row[13]),
        )
        generation = PostingGeneration(
            int(row[11]),
            int(row[12]),
            int(row[13]),
            int(row[16]),
            int(row[17]),
            int(row[18]),
            int(row[19]),
            int(row[21]),
            frozenset(PostingDimension(str(value)) for value in row[22]),
            chunks,
            str(row[23]),
            bytes(row[24]),
        )
        return PostingIndexSnapshot(str(row[0]), binding, cast(datetime, row[15]), generation)

    @_serialize_shared_connection
    def begin_posting_index(
        self,
        snapshot: PostingIndexSnapshot,
        *,
        attempt: int,
        lease_token: str,
    ) -> None:
        if attempt <= 0 or not lease_token:
            raise ValueError("posting task lease is required")
        spec = PostingIndexTaskSpec(**snapshot.binding.__dict__)
        generation = snapshot.generation
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"SELECT {self._POSTING_TASK_PROJECTION} FROM "  # noqa: S608 -- fixed internal projection
                    "pcap_posting_index_intents AS intent JOIN pcap_posting_index_jobs AS task "
                    "USING(source_kind,source_id) WHERE task.source_kind=%s "
                    "AND task.source_id=%s AND task.parent_structural_build_id=%s "
                    "AND task.status='RUNNING' AND task.attempt=%s AND task.lease_token=%s "
                    "AND task.lease_expires_at>clock_timestamp() FOR UPDATE OF intent,task",
                    (
                        spec.source_kind,
                        spec.source_id,
                        spec.parent_structural_build_id,
                        attempt,
                        lease_token,
                    ),
                )
                task_row = cursor.fetchone()
                if task_row is None or self._posting_task(task_row).spec != spec:
                    connection.rollback()
                    raise ValueError("posting task lease is not current")
                cursor.execute(
                    "SELECT build_id FROM pcap_posting_index_owners WHERE source_kind=%s "
                    "AND source_id=%s AND parent_structural_build_id=%s FOR UPDATE",
                    (spec.source_kind, spec.source_id, spec.parent_structural_build_id),
                )
                owner = cursor.fetchone()
                cursor.execute(
                    "INSERT INTO pcap_posting_index_generations(build_id,"
                    + self._POSTING_SPEC_COLUMNS
                    + ",state,created_at,packet_count,supported_count,membership_count,"
                    "distinct_key_count,chunk_count,encoded_byte_count,complete_dimensions,"
                    "posting_index_sha256,binding_document,builder_attempt,lease_token,"
                    "expected_owner_build_id) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,"
                    "%s,%s,'STAGING',clock_timestamp(),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        snapshot.build_id,
                        *self._posting_spec_values(spec),
                        generation.packet_count,
                        generation.supported_count,
                        generation.membership_count,
                        generation.distinct_key_count,
                        len(generation.chunks),
                        generation.encoded_byte_count,
                        [value.value for value in sorted(generation.complete_dimensions, key=str)],
                        generation.digest,
                        generation.binding_document,
                        attempt,
                        lease_token,
                        str(owner[0]) if owner else None,
                    ),
                )
                if cursor.rowcount != 1:
                    connection.rollback()
                    raise ValueError("posting generation was not created")
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
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
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT task.parent_structural_build_id FROM pcap_posting_index_jobs AS task "
                    "JOIN pcap_posting_index_intents AS intent USING(source_kind,source_id) "
                    "WHERE task.source_kind=%s AND task.source_id=%s AND task.status='RUNNING' "
                    "AND task.attempt=%s AND task.lease_token=%s "
                    "AND task.lease_expires_at>clock_timestamp() AND intent.status IN "
                    "('PENDING','DEFERRED') AND intent.parent_structural_build_id="
                    "task.parent_structural_build_id FOR UPDATE OF intent,task",
                    (source_kind, source_id, attempt, lease_token),
                )
                task_row = cursor.fetchone()
                if task_row is None:
                    connection.rollback()
                    raise ValueError("posting task lease is not current")
                cursor.execute(
                    "SELECT build_id FROM pcap_posting_index_generations WHERE build_id=%s "
                    "AND source_kind=%s AND source_id=%s AND parent_structural_build_id=%s "
                    "AND state='STAGING' AND builder_attempt=%s AND lease_token=%s FOR UPDATE",
                    (
                        build_id,
                        source_kind,
                        source_id,
                        str(task_row[0]),
                        attempt,
                        lease_token,
                    ),
                )
                if cursor.fetchone() is None:
                    connection.rollback()
                    raise ValueError("posting generation is not current")
                if chunks:
                    cursor.executemany(
                        "INSERT INTO pcap_posting_index_chunks(build_id,dimension,"
                        "canonical_value,chunk_ordinal,first_packet_index,last_packet_index,"
                        "membership_count,encoded_ordinals) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",
                        [
                            (
                                build_id,
                                chunk.dimension.value,
                                chunk.value,
                                chunk.chunk_ordinal,
                                chunk.first_packet_index,
                                chunk.last_packet_index,
                                chunk.count,
                                chunk.encoded_ordinals,
                            )
                            for chunk in chunks
                        ],
                    )
            connection.commit()
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def publish_posting_index(
        self,
        build_id: str,
        *,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        attempt: int,
        lease_token: str,
    ) -> bool:
        if source_version.source_kind not in {"PCAP_UPLOAD", "LIVE_SEGMENT"}:
            return False
        key = (source_version.source_kind, source_version.source_id, parent.build_id)
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                # Deterministic lock order: source -> structural owner/parent -> intent ->
                # exact task -> staging generation -> current posting owner.
                cursor.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,"
                    "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                    key[:2],
                )
                source_row = cursor.fetchone()
                if source_row != (
                    source_version.source_kind,
                    source_version.source_id,
                    source_version.object_key,
                    source_version.source_version_id,
                    source_version.source_size_bytes,
                    source_version.source_sha256,
                ):
                    connection.rollback()
                    return False
                cursor.execute(
                    "SELECT owner.build_id,generation.index_sha256,generation.state "
                    "FROM pcap_offset_index_owners AS owner JOIN "
                    "pcap_offset_index_generations AS generation "
                    "ON generation.build_id=owner.build_id WHERE owner.source_kind=%s "
                    "AND owner.source_id=%s AND owner.build_id=%s "
                    "AND generation.state='READY' FOR UPDATE OF owner,generation",
                    key,
                )
                if cursor.fetchone() != (parent.build_id, parent.index_sha256, "READY"):
                    connection.rollback()
                    return False
                cursor.execute(
                    f"SELECT {self._POSTING_INTENT_COLUMNS} FROM "  # noqa: S608 -- fixed internal columns
                    "pcap_posting_index_intents WHERE source_kind=%s AND source_id=%s "
                    "AND parent_structural_build_id=%s AND status IN ('PENDING','DEFERRED') "
                    "FOR UPDATE",
                    key,
                )
                intent_row = cursor.fetchone()
                if intent_row is None:
                    connection.rollback()
                    return False
                intent = self._posting_intent(intent_row)
                cursor.execute(
                    f"SELECT {self._POSTING_TASK_PROJECTION} FROM "  # noqa: S608 -- fixed internal projection
                    "pcap_posting_index_intents AS intent JOIN pcap_posting_index_jobs AS task "
                    "USING(source_kind,source_id) WHERE task.source_kind=%s "
                    "AND task.source_id=%s AND task.parent_structural_build_id=%s "
                    "AND task.status='RUNNING' AND task.attempt=%s AND task.lease_token=%s "
                    "AND task.lease_expires_at>clock_timestamp() FOR UPDATE OF task",
                    (*key, attempt, lease_token),
                )
                task_row = cursor.fetchone()
                if task_row is None:
                    connection.rollback()
                    return False
                task = self._posting_task(task_row)
                cursor.execute(
                    "SELECT build_id,source_kind,source_id,source_version_id,"
                    "source_size_bytes,source_sha256,capture_format,parent_structural_build_id,"
                    "parent_structural_index_sha256,structural_schema_version,"
                    "structural_parser_contract_version,posting_schema_version,"
                    "posting_parser_contract_version,filter_contract_version,state,created_at,"
                    "packet_count,supported_count,membership_count,distinct_key_count,chunk_count,"
                    "encoded_byte_count,complete_dimensions,posting_index_sha256,binding_document,"
                    "builder_attempt,lease_token,expected_owner_build_id FROM "
                    "pcap_posting_index_generations WHERE build_id=%s AND source_kind=%s "
                    "AND source_id=%s AND parent_structural_build_id=%s AND state='STAGING' "
                    "FOR UPDATE",
                    (build_id, *key),
                )
                generation_row = cursor.fetchone()
                if generation_row is None:
                    connection.rollback()
                    return False
                cursor.execute(
                    "SELECT build_id FROM pcap_posting_index_owners WHERE source_kind=%s "
                    "AND source_id=%s AND parent_structural_build_id=%s FOR UPDATE",
                    key,
                )
                owner_row = cursor.fetchone()
                current_owner = str(owner_row[0]) if owner_row else None
                if (
                    intent.spec != task.spec
                    or task.spec != PostingIndexTaskSpec.from_binding(source_version, parent)
                    or int(generation_row[25]) != attempt
                    or str(generation_row[26]) != lease_token
                    or generation_row[27] != current_owner
                ):
                    connection.rollback()
                    return False
                cursor.execute(
                    "SELECT dimension,canonical_value,chunk_ordinal,first_packet_index,"
                    "last_packet_index,membership_count,encoded_ordinals FROM "
                    "pcap_posting_index_chunks WHERE build_id=%s ORDER BY "
                    "dimension,canonical_value,chunk_ordinal",
                    (build_id,),
                )
                chunk_rows: list[tuple[Any, ...]] = []
                while batch := cursor.fetchmany(1_000):
                    chunk_rows.extend(batch)
                snapshot = self._posting_snapshot_from_generation(
                    generation_row, self._posting_chunks(chunk_rows)
                )
                if len(chunk_rows) != int(generation_row[20]) or not validate_posting_index(
                    snapshot, source_version=source_version, parent=parent
                ):
                    connection.rollback()
                    return False
                cursor.execute(
                    "UPDATE pcap_posting_index_generations SET state='READY' WHERE "
                    "build_id=%s AND state='STAGING' AND builder_attempt=%s AND lease_token=%s",
                    (build_id, attempt, lease_token),
                )
                generation_count = cursor.rowcount
                if current_owner is None:
                    cursor.execute(
                        "INSERT INTO pcap_posting_index_owners(source_kind,source_id,"
                        "parent_structural_build_id,build_id) VALUES(%s,%s,%s,%s) "
                        "ON CONFLICT DO NOTHING",
                        (*key, build_id),
                    )
                else:
                    cursor.execute(
                        "INSERT INTO pcap_posting_index_owners(source_kind,source_id,"
                        "parent_structural_build_id,build_id) VALUES(%s,%s,%s,%s) ON CONFLICT("
                        "source_kind,source_id,parent_structural_build_id) DO UPDATE SET "
                        "build_id=excluded.build_id WHERE "
                        "pcap_posting_index_owners.build_id=%s",
                        (*key, build_id, current_owner),
                    )
                owner_count = cursor.rowcount
                cursor.execute(
                    "UPDATE pcap_posting_index_jobs SET status='COMPLETED',lease_token=NULL,"
                    "lease_expires_at=NULL,updated_at=clock_timestamp(),error_code=NULL WHERE "
                    "source_kind=%s AND source_id=%s AND parent_structural_build_id=%s "
                    "AND status='RUNNING' AND attempt=%s AND lease_token=%s "
                    "AND lease_expires_at>clock_timestamp()",
                    (*key, attempt, lease_token),
                )
                task_count = cursor.rowcount
                cursor.execute(
                    "UPDATE pcap_posting_index_intents SET status='COMPLETED',"
                    "updated_at=clock_timestamp(),published_build_id=%s,error_code=NULL,"
                    "terminal_attempt=%s,terminal_max_attempts=%s WHERE source_kind=%s "
                    "AND source_id=%s AND parent_structural_build_id=%s "
                    "AND status IN ('PENDING','DEFERRED')",
                    (build_id, task.attempt, task.max_attempts, *key),
                )
                intent_count = cursor.rowcount
                if (generation_count, owner_count, task_count, intent_count) != (1, 1, 1, 1):
                    connection.rollback()
                    return False
                if current_owner is not None and current_owner != build_id:
                    cursor.execute(
                        "DELETE FROM pcap_posting_index_generations WHERE build_id=%s",
                        (current_owner,),
                    )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def get_posting_index_identity(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
    ) -> PostingIndexIdentityLookup:
        key = (source_version.source_kind, source_version.source_id, parent.build_id)
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT owner.build_id,generation.source_kind,generation.source_id,"
                    "generation.source_version_id,generation.source_size_bytes,"
                    "generation.source_sha256,generation.capture_format,"
                    "generation.parent_structural_build_id,"
                    "generation.parent_structural_index_sha256,"
                    "generation.structural_schema_version,"
                    "generation.structural_parser_contract_version,"
                    "generation.posting_schema_version,"
                    "generation.posting_parser_contract_version,"
                    "generation.filter_contract_version,generation.state,"
                    "generation.created_at,generation.packet_count,"
                    "generation.supported_count,generation.membership_count,"
                    "generation.distinct_key_count,generation.chunk_count,"
                    "generation.encoded_byte_count,generation.complete_dimensions,"
                    "generation.posting_index_sha256,generation.binding_document FROM "
                    "pcap_posting_index_owners AS owner LEFT JOIN "
                    "pcap_posting_index_generations AS generation ON "
                    "generation.build_id=owner.build_id WHERE owner.source_kind=%s AND "
                    "owner.source_id=%s AND owner.parent_structural_build_id=%s LIMIT 1",
                    key,
                )
                row = cursor.fetchone()
            connection.commit()
            if row is None:
                return PostingIndexIdentityLookup(PostingIndexAvailability.MISSING)
            if row[1] is None or row[14] != "READY":
                return PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT)
            numeric_indexes = tuple(range(9, 14)) + tuple(range(16, 22))
            if (
                any(type(row[index]) is not int for index in numeric_indexes)
                or not isinstance(row[15], datetime)
                or not isinstance(row[22], list | tuple)
                or not all(isinstance(item, str) for item in row[22])
                or not isinstance(row[23], str)
                or not isinstance(row[24], bytes | bytearray | memoryview)
            ):
                return PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT)
            identity = PostingIndexIdentity(
                str(row[0]),
                PostingIndexBinding(
                    cast(Any, row[1]),
                    str(row[2]),
                    str(row[3]),
                    row[4],
                    str(row[5]),
                    cast(Any, row[6]),
                    str(row[7]),
                    str(row[8]),
                    row[9],
                    row[10],
                    row[11],
                    row[12],
                    row[13],
                ),
                row[15],
                row[11],
                row[12],
                row[13],
                row[16],
                row[17],
                row[18],
                row[19],
                row[20],
                row[21],
                tuple(sorted(row[22])),
                row[23],
                bytes(row[24]),
            )
            availability = posting_index_identity_availability(
                identity, source_version=source_version, parent=parent
            )
            return PostingIndexIdentityLookup(
                availability,
                identity if availability is PostingIndexAvailability.READY else None,
            )
        except (KeyError, TypeError, ValueError, OverflowError):
            connection.rollback()
            return PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT)
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
    def get_posting_index(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        limits: PostingQueryLimits | None = None,
    ) -> PostingIndexLookup:
        key = (source_version.source_kind, source_version.source_id, parent.build_id)
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT build_id FROM pcap_posting_index_owners WHERE source_kind=%s "
                    "AND source_id=%s AND parent_structural_build_id=%s",
                    key,
                )
                owner = cursor.fetchone()
                if owner is None:
                    connection.commit()
                    return PostingIndexLookup(PostingIndexAvailability.MISSING)
                cursor.execute(
                    "SELECT source_kind,source_id,object_key,source_version_id,"
                    "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                    "WHERE source_kind=%s AND source_id=%s",
                    key[:2],
                )
                source_row = cursor.fetchone()
                if source_row != (
                    source_version.source_kind,
                    source_version.source_id,
                    source_version.object_key,
                    source_version.source_version_id,
                    source_version.source_size_bytes,
                    source_version.source_sha256,
                ):
                    connection.commit()
                    return PostingIndexLookup(PostingIndexAvailability.STALE)
                cursor.execute(
                    "SELECT owner.build_id,generation.index_sha256,generation.state FROM "
                    "pcap_offset_index_owners AS owner JOIN pcap_offset_index_generations AS "
                    "generation ON generation.build_id=owner.build_id WHERE "
                    "owner.source_kind=%s AND owner.source_id=%s AND owner.build_id=%s",
                    key,
                )
                if cursor.fetchone() != (parent.build_id, parent.index_sha256, "READY"):
                    connection.commit()
                    return PostingIndexLookup(PostingIndexAvailability.STALE)
                cursor.execute(
                    "SELECT build_id,source_kind,source_id,source_version_id,source_size_bytes,"
                    "source_sha256,capture_format,parent_structural_build_id,"
                    "parent_structural_index_sha256,structural_schema_version,"
                    "structural_parser_contract_version,posting_schema_version,"
                    "posting_parser_contract_version,filter_contract_version,state,created_at,"
                    "packet_count,supported_count,membership_count,distinct_key_count,chunk_count,"
                    "encoded_byte_count,complete_dimensions,posting_index_sha256,binding_document,"
                    "builder_attempt,lease_token,expected_owner_build_id FROM "
                    "pcap_posting_index_generations WHERE build_id=%s AND state='READY'",
                    (owner[0],),
                )
                generation_row = cursor.fetchone()
                if generation_row is None:
                    connection.commit()
                    return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
                chunk_count = int(generation_row[20])
                if limits is not None and chunk_count > limits.max_directory_chunks:
                    connection.commit()
                    return PostingIndexLookup(PostingIndexAvailability.RESOURCE_LIMIT)
                chunk_limit = (
                    limits.max_directory_chunks + 1 if limits is not None else chunk_count + 1
                )
                cursor.execute(
                    "SELECT dimension,canonical_value,chunk_ordinal,first_packet_index,"
                    "last_packet_index,membership_count,encoded_ordinals FROM "
                    "pcap_posting_index_chunks WHERE build_id=%s ORDER BY "
                    "dimension,canonical_value,chunk_ordinal LIMIT %s",
                    (owner[0], chunk_limit),
                )
                chunk_rows: list[tuple[Any, ...]] = []
                while batch := cursor.fetchmany(1_000):
                    chunk_rows.extend(batch)
                if len(chunk_rows) > chunk_count or (
                    limits is not None and len(chunk_rows) > limits.max_directory_chunks
                ):
                    connection.commit()
                    return PostingIndexLookup(PostingIndexAvailability.RESOURCE_LIMIT)
                snapshot = self._posting_snapshot_from_generation(
                    generation_row, self._posting_chunks(chunk_rows)
                )
            connection.commit()
            if len(chunk_rows) != int(generation_row[20]) or not validate_posting_index(
                snapshot, source_version=source_version, parent=parent
            ):
                return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
            return PostingIndexLookup(PostingIndexAvailability.READY, snapshot)
        except (KeyError, TypeError, ValueError, OverflowError):
            connection.rollback()
            return PostingIndexLookup(PostingIndexAvailability.CORRUPT)
        except Exception:
            connection.rollback()
            raise

    @_serialize_shared_connection
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
        if attempt <= 0 or not lease_token:
            return False
        connection = self.connection
        try:
            with connection.cursor() as cursor:
                self._lock_posting_lifecycle_for_sources(cursor, source_kind, [source_id])
                cursor.execute(
                    "DELETE FROM pcap_posting_index_generations AS generation USING "
                    "pcap_posting_index_jobs AS task,pcap_posting_index_intents AS intent "
                    "WHERE generation.build_id=%s AND generation.source_kind=%s "
                    "AND generation.source_id=%s AND generation.parent_structural_build_id=%s "
                    "AND generation.state='STAGING' AND generation.builder_attempt=%s "
                    "AND generation.lease_token=%s AND task.source_kind=generation.source_kind "
                    "AND task.source_id=generation.source_id AND task.parent_structural_build_id="
                    "generation.parent_structural_build_id AND task.status='RUNNING' "
                    "AND task.attempt=generation.builder_attempt AND task.lease_token="
                    "generation.lease_token AND task.lease_expires_at>clock_timestamp() "
                    "AND intent.source_kind=task.source_kind AND intent.source_id=task.source_id "
                    "AND intent.parent_structural_build_id=task.parent_structural_build_id "
                    "AND intent.status IN ('PENDING','DEFERRED')",
                    (
                        build_id,
                        source_kind,
                        source_id,
                        parent_structural_build_id,
                        attempt,
                        lease_token,
                    ),
                )
                deleted = cursor.rowcount == 1
                if not deleted:
                    connection.rollback()
                    return False
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise

    def database_ready(self) -> bool:
        try:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                return bool(cursor.fetchone() == (1,))
        except Exception:
            return False

    def _audit(self, kind: str, object_id: str, value: Any) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                "VALUES(%s,%s,%s,%s::jsonb)",
                (kind, object_id, datetime.now(UTC), self._json(value)),
            )
            self.connection.commit()

    def _put(self, kind: str, object_id: str, value: dict[str, Any]) -> dict[str, Any]:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES(%s,%s,%s::jsonb) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (kind, object_id, self._json(value)),
            )
            self._audit(kind, object_id, value)
            self.connection.commit()
        return deepcopy(value)

    def _get(self, kind: str, object_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind=%s AND id=%s", (kind, object_id)
            )
            row = cursor.fetchone()
            self.connection.commit()
        if not row:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def _list(self, kind: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM controller_objects WHERE kind=%s ORDER BY id", (kind,))
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def upsert_sensor(self, sensor: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor", sensor["sensor_id"], sensor)

    def update_sensor_heartbeat(
        self, sensor_id: str, fields: dict[str, Any]
    ) -> dict[str, Any] | None:
        with self._lock:
            connection = self.connection
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM controller_objects "
                        "WHERE kind='sensor' AND id=%s FOR UPDATE",
                        (sensor_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        connection.commit()
                        return None
                    value = row[0]
                    sensor = value if isinstance(value, dict) else json.loads(value)
                    sensor.update(fields)
                    cursor.execute(
                        "UPDATE controller_objects SET data=%s::jsonb "
                        "WHERE kind='sensor' AND id=%s",
                        (self._json(sensor), sensor_id),
                    )
                self._audit("sensor-heartbeat", sensor_id, fields)
                connection.commit()
                return deepcopy(sensor)
            except Exception:
                connection.rollback()
                raise

    def get_sensor(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor", sensor_id)

    def save_detector_weight_preset(self, preset: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    if preset.get("is_default"):
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(%s)",
                            (self._DETECTOR_PRESET_ADVISORY_LOCK,),
                        )
                        cursor.execute(
                            "SELECT id,data FROM controller_objects "
                            "WHERE kind='detector-weight-preset' FOR UPDATE"
                        )
                        for object_id, value in cursor.fetchall():
                            item = value if isinstance(value, dict) else json.loads(value)
                            item["is_default"] = False
                            cursor.execute(
                                "UPDATE controller_objects SET data=%s::jsonb "
                                "WHERE kind='detector-weight-preset' AND id=%s",
                                (self._json(item), object_id),
                            )
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) VALUES(%s,%s,%s::jsonb) "
                        "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                        ("detector-weight-preset", preset["id"], self._json(preset)),
                    )
                self._audit("detector-weight-preset", preset["id"], preset)
                connection.commit()
            except Exception:
                connection.rollback()
                raise
        return deepcopy(preset)

    def get_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        return self._get("detector-weight-preset", preset_id)

    def update_detector_weight_preset(
        self, preset_id: str, updates: dict[str, Any], *, set_as_default: bool = False
    ) -> dict[str, Any] | None:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    if set_as_default:
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(%s)",
                            (self._DETECTOR_PRESET_ADVISORY_LOCK,),
                        )
                    cursor.execute(
                        "SELECT id,data FROM controller_objects "
                        "WHERE kind='detector-weight-preset' FOR UPDATE"
                    )
                    rows = cursor.fetchall()
                    if not any(str(object_id) == preset_id for object_id, _ in rows):
                        connection.commit()
                        return None
                    selected: dict[str, Any] | None = None
                    for object_id, value in rows:
                        preset = value if isinstance(value, dict) else json.loads(value)
                        if str(object_id) == preset_id:
                            preset.update(updates)
                            selected = preset
                        if set_as_default:
                            preset["is_default"] = str(object_id) == preset_id
                        cursor.execute(
                            "UPDATE controller_objects SET data=%s::jsonb "
                            "WHERE kind='detector-weight-preset' AND id=%s",
                            (self._json(preset), object_id),
                        )
                if selected is None:
                    raise RuntimeError("locked preset disappeared during update")
                self._audit("detector-weight-preset", preset_id, selected)
                connection.commit()
                return deepcopy(selected)
            except Exception:
                connection.rollback()
                raise

    def list_detector_weight_presets(self) -> list[dict[str, Any]]:
        with self._lock:
            return self._list("detector-weight-preset")

    def delete_detector_weight_preset(self, preset_id: str) -> bool:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM controller_objects "
                        "WHERE kind='detector-weight-preset' AND id=%s",
                        (preset_id,),
                    )
                    deleted = bool(cursor.rowcount > 0)
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise

    def set_default_detector_weight_preset(self, preset_id: str) -> dict[str, Any] | None:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(%s)",
                        (self._DETECTOR_PRESET_ADVISORY_LOCK,),
                    )
                    cursor.execute(
                        "SELECT id,data FROM controller_objects "
                        "WHERE kind='detector-weight-preset' FOR UPDATE"
                    )
                    rows = cursor.fetchall()
                    if not any(str(object_id) == preset_id for object_id, _ in rows):
                        connection.commit()
                        return None
                    presets: list[dict[str, Any]] = []
                    for object_id, value in rows:
                        preset = value if isinstance(value, dict) else json.loads(value)
                        preset["is_default"] = str(object_id) == preset_id
                        presets.append(preset)
                        cursor.execute(
                            "UPDATE controller_objects SET data=%s::jsonb "
                            "WHERE kind='detector-weight-preset' AND id=%s",
                            (self._json(preset), object_id),
                        )
                selected = next((preset for preset in presets if preset["id"] == preset_id), None)
                connection.commit()
                return deepcopy(selected) if selected is not None else None
            except Exception:
                connection.rollback()
                raise

    def list_sensors(self) -> list[dict[str, Any]]:
        return self._list("sensor")

    def create_group(self, group: dict[str, Any]) -> dict[str, Any]:
        return self._put("group", group["id"], group)

    def list_groups(self) -> list[dict[str, Any]]:
        return self._list("group")

    def create_job(self, job: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO job_idempotency(idempotency_key,job_id) VALUES(%s,%s) "
                "ON CONFLICT(idempotency_key) DO NOTHING RETURNING job_id",
                (job["idempotency_key"], job["id"]),
            )
            created = cursor.fetchone() is not None
            if not created:
                cursor.execute(
                    "SELECT job_id FROM job_idempotency WHERE idempotency_key=%s",
                    (job["idempotency_key"],),
                )
                row = cursor.fetchone()
                self.connection.commit()
                if row is None:
                    raise RuntimeError("idempotency ledger row disappeared")
                existing = self.get_job(str(row[0]))
                if existing is None:
                    raise RuntimeError("idempotency ledger references missing job")
                return existing, False
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES('job',%s,%s::jsonb)",
                (job["id"], self._json(metadata)),
            )
            self._replace_job_flow_records(cursor, job["id"], list(job.get("flow_records", [])))
            cursor.execute(
                "INSERT INTO job_payload_signatures(job_id,data) VALUES(%s,%s::jsonb)",
                (job["id"], self._json(job.get("payload_signatures", []))),
            )
            self._audit("job", job["id"], metadata)
            self.connection.commit()
            return deepcopy(job), True

    def save_job(self, job: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES('job',%s,%s::jsonb) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (job["id"], self._json(metadata)),
            )
            if "flow_records" in job:
                self._replace_job_flow_records(cursor, job["id"], list(job["flow_records"]))
            if "payload_signatures" in job:
                cursor.execute(
                    "INSERT INTO job_payload_signatures(job_id,data) VALUES(%s,%s::jsonb) "
                    "ON CONFLICT(job_id) DO UPDATE SET data=excluded.data",
                    (job["id"], self._json(job["payload_signatures"])),
                )
            self._audit("job", job["id"], metadata)
            self.connection.commit()
        return deepcopy(job)

    def save_job_metadata(self, job: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            key: value
            for key, value in job.items()
            if key not in {"flow_records", "payload_signatures"}
        }
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO controller_objects(kind,id,data) VALUES('job',%s,%s::jsonb) "
                "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                (job["id"], self._json(metadata)),
            )
            self._audit("job", job["id"], metadata)
            self.connection.commit()
        return deepcopy(metadata)

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        job = self.get_job_summary(job_id)
        if job is None:
            return None
        with self.connection.cursor() as cursor:
            job["flow_records"] = self._load_job_flow_records(cursor, job_id)
            self.connection.commit()
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM job_payload_signatures WHERE job_id=%s", (job_id,))
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            job["payload_signatures"] = []
        else:
            value = row[0]
            job["payload_signatures"] = value if isinstance(value, list) else json.loads(value)
        return job

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        return self._get("job", job_id)

    def get_job_summaries(self, job_ids: list[str]) -> dict[str, dict[str, Any]]:
        selected = list(dict.fromkeys(job_ids))
        if not selected:
            return {}
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,data FROM controller_objects WHERE kind='job' AND id=ANY(%s)",
                (selected,),
            )
            rows = cursor.fetchall()
        return {
            str(row[0]): row[1] if isinstance(row[1], dict) else json.loads(row[1]) for row in rows
        }

    def list_jobs(self) -> list[dict[str, Any]]:
        return self._list("job")

    def list_active_live_jobs(self) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects "
                "WHERE kind='job' AND data->>'mode'='LIVE' "
                "AND data->>'status' IN ('CAPTURING','UPLOADING') ORDER BY id"
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def delete_job(self, job_id: str) -> bool:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                ("pcap-export-admission",),
            )
            cursor.execute(
                "SELECT 1 FROM pcap_export_jobs WHERE (parent_job_id=%s "
                "OR source_job_id=%s OR data->'provenance_job_ids' ? %s) "
                "AND status IN ('QUEUED','RUNNING') FOR UPDATE",
                (job_id, job_id, job_id),
            )
            if cursor.fetchone() is not None:
                self.connection.commit()
                return False
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (job_id,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return False
            cursor.execute(
                "SELECT data->>'status' FROM ai_analysis_runs WHERE analysis_job_id=%s FOR UPDATE",
                (job_id,),
            )
            if any(str(item[0]) not in _AI_TERMINAL_STATUSES for item in cursor.fetchall()):
                self.connection.commit()
                return False
            cursor.execute(
                "SELECT id,data->>'object_key' FROM controller_objects "
                "WHERE kind='export' AND data->>'job_id'=%s",
                (job_id,),
            )
            export_objects = [(str(item[0]), str(item[1])) for item in cursor.fetchall() if item[1]]
            job_data = row[0] if isinstance(row[0], dict) else json.loads(row[0])
            live_segment_rows: list[tuple[str, str | None]] = []
            if job_data.get("mode") == "LIVE":
                cursor.execute(
                    "SELECT id,data->>'object_key' FROM controller_objects "
                    "WHERE kind='sensor_pcap' AND data->>'analysis_job_id'=%s "
                    "ORDER BY data->>'uploaded_at',id FOR UPDATE",
                    (job_id,),
                )
                live_segment_rows = [
                    (str(item[0]), str(item[1]) if item[1] else None) for item in cursor.fetchall()
                ]
            if job_data.get("mode") == "LIVE":
                cleanup_objects = [
                    (f"job-delete:{job_id}:sensor-pcap:{segment_id}", object_key)
                    for segment_id, object_key in live_segment_rows
                    if object_key is not None
                ]
            else:
                cleanup_objects = [
                    (f"job-delete:{job_id}:{export_id}", object_key)
                    for export_id, object_key in export_objects
                ]
                cursor.execute(
                    "SELECT object_key FROM pcap_capture_source_versions "
                    "WHERE source_kind='PCAP_UPLOAD' AND source_id=%s",
                    (job_id,),
                )
                capture_row = cursor.fetchone()
                capture_key = (
                    str(capture_row[0]) if capture_row is not None else self._capture_key(job_id)
                )
                cleanup_objects.append((f"job-delete:{job_id}:capture", capture_key))
            unique_cleanup_objects: dict[str, str] = {}
            for cleanup_source, object_key in cleanup_objects:
                unique_cleanup_objects.setdefault(object_key, cleanup_source)
            cleanup_objects = [
                (cleanup_source, object_key)
                for object_key, cleanup_source in unique_cleanup_objects.items()
            ]
            cleanup: list[tuple[str, str]] = []
            for cleanup_source, object_key in cleanup_objects:
                cleanup_id = self._pcap_cleanup_id(cleanup_source, object_key)
                cleanup.append((cleanup_id, object_key))
                cursor.execute(
                    "INSERT INTO controller_objects(kind,id,data) "
                    "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
                    "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                    (
                        cleanup_id,
                        self._json(
                            {
                                "object_key": object_key,
                                "created_at": datetime.now(UTC).isoformat(),
                            }
                        ),
                    ),
                )
            cursor.execute(
                "DELETE FROM ai_feedback WHERE assessment_id IN "
                "(SELECT assessment_id FROM ai_candidate_assessments "
                "WHERE ai_run_id IN "
                "(SELECT run_id FROM ai_analysis_runs WHERE analysis_job_id=%s))",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM ai_generated_artifacts WHERE assessment_id IN "
                "(SELECT assessment_id FROM ai_candidate_assessments "
                "WHERE ai_run_id IN "
                "(SELECT run_id FROM ai_analysis_runs WHERE analysis_job_id=%s))",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM ai_candidate_assessments WHERE ai_run_id IN "
                "(SELECT run_id FROM ai_analysis_runs WHERE analysis_job_id=%s)",
                (job_id,),
            )
            cursor.execute("DELETE FROM ai_analysis_runs WHERE analysis_job_id=%s", (job_id,))
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='export' AND data->>'job_id'=%s",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM pcap_export_jobs WHERE parent_job_id=%s",
                (job_id,),
            )
            cursor.execute("DELETE FROM job_candidates WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM candidate_records WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_flow_record_chunks WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_flow_records WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM job_payload_signatures WHERE job_id=%s", (job_id,))
            self._lock_posting_lifecycle_for_sources(cursor, "PCAP_UPLOAD", [job_id])
            cursor.execute(
                "DELETE FROM pcap_posting_index_intents WHERE source_kind='PCAP_UPLOAD' "
                "AND source_id=%s",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM pcap_posting_index_generations WHERE source_kind='PCAP_UPLOAD' "
                "AND source_id=%s",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM pcap_offset_index_generations WHERE source_kind='PCAP_UPLOAD' "
                "AND source_id=%s",
                (job_id,),
            )
            cursor.execute(
                "DELETE FROM pcap_capture_source_versions WHERE source_kind='PCAP_UPLOAD' "
                "AND source_id=%s",
                (job_id,),
            )
            if live_segment_rows:
                segment_ids = [segment_id for segment_id, _object_key in live_segment_rows]
                self._lock_posting_lifecycle_for_sources(cursor, "LIVE_SEGMENT", segment_ids)
                cursor.execute(
                    "DELETE FROM pcap_posting_index_intents WHERE source_kind='LIVE_SEGMENT' "
                    "AND source_id=ANY(%s)",
                    (segment_ids,),
                )
                cursor.execute(
                    "DELETE FROM pcap_posting_index_generations "
                    "WHERE source_kind='LIVE_SEGMENT' AND source_id=ANY(%s)",
                    (segment_ids,),
                )
                cursor.execute(
                    "DELETE FROM pcap_offset_index_jobs WHERE source_kind='LIVE_SEGMENT' "
                    "AND source_id=ANY(%s)",
                    (segment_ids,),
                )
                cursor.execute(
                    "DELETE FROM pcap_offset_index_owners WHERE source_kind='LIVE_SEGMENT' "
                    "AND source_id=ANY(%s)",
                    (segment_ids,),
                )
                cursor.execute(
                    "DELETE FROM pcap_offset_index_generations WHERE source_kind='LIVE_SEGMENT' "
                    "AND source_id=ANY(%s)",
                    (segment_ids,),
                )
                cursor.execute(
                    "DELETE FROM pcap_capture_source_versions WHERE source_kind='LIVE_SEGMENT' "
                    "AND source_id=ANY(%s)",
                    (segment_ids,),
                )
                cursor.execute(
                    "DELETE FROM controller_objects WHERE kind='sensor_pcap' AND id=ANY(%s)",
                    (segment_ids,),
                )
            cursor.execute("DELETE FROM job_idempotency WHERE job_id=%s", (job_id,))
            cursor.execute("DELETE FROM controller_objects WHERE kind='job' AND id=%s", (job_id,))
            self._audit("job-delete", job_id, {"id": job_id})
            self.connection.commit()
        for cleanup_id, object_key in cleanup:
            try:
                self.blob_store.delete(object_key)
            except Exception:
                logger.warning(
                    "Failed to delete blob %s after job deletion; cleanup remains queued",
                    object_key,
                )
                continue
            try:
                with self._lock, self.connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM controller_objects WHERE kind='pcap_export_cleanup' AND id=%s "
                        "AND data->>'object_key'=%s",
                        (cleanup_id, object_key),
                    )
                    self.connection.commit()
            except Exception:
                with self._lock:
                    self.connection.rollback()
                logger.warning(
                    "Failed to acknowledge blob cleanup %s after job deletion",
                    object_key,
                    exc_info=True,
                )
        return True

    @staticmethod
    def _capture_key(job_id: str) -> str:
        """Return the historical deterministic key used by legacy stored rows."""
        return f"captures/{job_id}.pcap"

    @staticmethod
    def _capture_generation_key(job_id: str) -> str:
        return f"captures/{job_id}/{uuid4().hex}.pcap"

    def _queue_capture_cleanup(self, cursor: Any, scope: str, object_key: str) -> str:
        cleanup_id = self._pcap_cleanup_id(scope, object_key)
        cursor.execute(
            "INSERT INTO controller_objects(kind,id,data) "
            "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
            "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
            (
                cleanup_id,
                self._json(
                    {
                        "object_key": object_key,
                        "created_at": datetime.now(UTC).isoformat(),
                        "state": "READY",
                    }
                ),
            ),
        )
        return cleanup_id

    def _perform_capture_cleanup(self, cleanup_id: str, object_key: str) -> None:
        try:
            self.blob_store.delete(object_key)
        except Exception:
            logger.warning(
                "Failed to delete obsolete capture object %s; cleanup remains queued",
                object_key,
                exc_info=True,
            )
            return
        try:
            with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
                cursor.execute(
                    "DELETE FROM controller_objects WHERE kind='pcap_export_cleanup' AND id=%s "
                    "AND data->>'object_key'=%s",
                    (cleanup_id, object_key),
                )
                self.connection.commit()
        except Exception:
            logger.warning(
                "Failed to acknowledge capture object cleanup %s",
                object_key,
                exc_info=True,
            )

    def _cleanup_failed_capture_upload(self, job_id: str, object_key: str) -> None:
        cleanup_id = self._pcap_cleanup_id(f"capture-upload:{job_id}", object_key)
        try:
            with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT object_key FROM pcap_capture_source_versions "
                    "WHERE source_kind='PCAP_UPLOAD' AND source_id=%s FOR UPDATE",
                    (job_id,),
                )
                current = cursor.fetchone()
                if current is not None and str(current[0]) == object_key:
                    cursor.execute(
                        "DELETE FROM controller_objects WHERE kind='pcap_export_cleanup' "
                        "AND data->>'object_key'=%s",
                        (object_key,),
                    )
                    self.connection.commit()
                    return
                self._queue_capture_cleanup(cursor, f"capture-upload:{job_id}", object_key)
                self.connection.commit()
        except Exception as exc:
            raise ArtifactStorageError("capture cleanup intent unavailable") from exc
        self._perform_capture_cleanup(cleanup_id, object_key)

    def save_job_capture(self, job_id: str, content: bytes) -> None:
        object_key = self._capture_generation_key(job_id)
        expected_size = len(content)
        expected_sha256 = hashlib.sha256(content).hexdigest()
        upload_attempted = False
        try:
            upload_attempted = True
            self.blob_store.put(object_key, content)
            source = self.blob_store.open(object_key)
            with source:
                digest = hashlib.sha256()
                actual_size = 0
                for chunk in source.iter_chunks():
                    actual_size += len(chunk)
                    digest.update(chunk)
                source_version_id = source.version_id
        except Exception as exc:
            if upload_attempted:
                self._cleanup_failed_capture_upload(job_id, object_key)
            if isinstance(exc, ArtifactStorageError):
                raise
            raise ArtifactStorageError("MinIO capture upload verification failed") from exc
        if actual_size != expected_size or digest.hexdigest() != expected_sha256:
            self._cleanup_failed_capture_upload(job_id, object_key)
            raise ArtifactStorageError("MinIO capture upload verification mismatch")

        prior_cleanup: tuple[str, str] | None = None
        try:
            with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                    (job_id,),
                )
                row = cursor.fetchone()
                job = None
                if row is not None:
                    job = row[0] if isinstance(row[0], dict) else json.loads(row[0])
                source_metadata = job.get("source") if isinstance(job, dict) else None
                if (
                    not isinstance(job, dict)
                    or job.get("id") != job_id
                    or job.get("mode") != "PCAP_UPLOAD"
                    or not isinstance(source_metadata, dict)
                    or source_metadata.get("packet_bytes_retained") is not True
                    or int(source_metadata.get("size_bytes", -1)) != expected_size
                    or source_metadata.get("sha256") != expected_sha256
                ):
                    self.connection.rollback()
                    raise ArtifactStorageError("canonical capture metadata does not match upload")
                cursor.execute(
                    "SELECT object_key FROM pcap_capture_source_versions "
                    "WHERE source_kind='PCAP_UPLOAD' AND source_id=%s FOR UPDATE",
                    (job_id,),
                )
                prior_row = cursor.fetchone()
                prior_key = str(prior_row[0]) if prior_row is not None else None
                cursor.execute(
                    "INSERT INTO pcap_capture_source_versions("
                    "source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                    "source_sha256,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s) "
                    "ON CONFLICT(source_kind,source_id) DO UPDATE SET "
                    "object_key=excluded.object_key,source_version_id=excluded.source_version_id,"
                    "source_size_bytes=excluded.source_size_bytes,source_sha256=excluded.source_sha256,"
                    "updated_at=excluded.updated_at RETURNING object_key",
                    (
                        "PCAP_UPLOAD",
                        job_id,
                        object_key,
                        source_version_id,
                        expected_size,
                        expected_sha256,
                        datetime.now(UTC),
                    ),
                )
                stored = cursor.fetchone()
                if cursor.rowcount != 1 or stored != (object_key,):
                    self.connection.rollback()
                    raise ArtifactStorageError("capture version persistence rowcount mismatch")
                if prior_key is not None and prior_key != object_key:
                    prior_cleanup = (
                        self._queue_capture_cleanup(
                            cursor, f"capture-replacement:{job_id}", prior_key
                        ),
                        prior_key,
                    )
                self.connection.commit()
        except Exception as exc:
            self._cleanup_failed_capture_upload(job_id, object_key)
            raise ArtifactStorageError("capture version persistence failed") from exc
        if prior_cleanup is not None:
            self._perform_capture_cleanup(*prior_cleanup)

    def get_job_capture(self, job_id: str) -> bytes | None:
        source = self.open_job_capture(job_id)
        if source is None:
            return None
        with source:
            return b"".join(source.iter_chunks())

    def open_job_capture(self, job_id: str) -> CaptureSource | None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT object_key,source_version_id FROM pcap_capture_source_versions "
                "WHERE source_kind='PCAP_UPLOAD' AND source_id=%s",
                (job_id,),
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        object_key, expected_version_id = str(row[0]), str(row[1])
        try:
            source = self.blob_store.open(object_key)
        except Exception as exc:
            if _is_missing_object_error(exc):
                return None
            raise
        if source.version_id != expected_version_id:
            source.close()
            raise ArtifactStorageError(
                "capture object version does not match authoritative metadata"
            )
        return source

    def get_capture_source_version(self, job_id: str) -> CaptureSourceVersion | None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,"
                "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind='PCAP_UPLOAD' AND source_id=%s",
                (job_id,),
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        return CaptureSourceVersion(
            source_kind=row[0],
            source_id=str(row[1]),
            object_key=str(row[2]),
            source_version_id=str(row[3]),
            source_size_bytes=int(row[4]),
            source_sha256=str(row[5]),
        )

    @classmethod
    def _live_task_from_row(cls, row: tuple[Any, ...] | None) -> LiveIndexTask | None:
        if row is None:
            return None
        spec = LiveIndexTaskSpec(
            source_kind="LIVE_SEGMENT",
            source_id=str(row[1]),
            sensor_id=str(row[2]),
            analysis_job_id=str(row[3]),
            object_key=str(row[4]),
            source_size_bytes=int(row[5]),
            source_sha256=str(row[6]),
            capture_format="PCAP",
            schema_version=int(row[8]),
            parser_contract_version=int(row[9]),
        )
        return LiveIndexTask(
            spec=spec,
            status=live_index_task_status(row[10]),
            attempt=int(row[11]),
            max_attempts=int(row[12]),
            lease_token=str(row[13]) if row[13] is not None else None,
            lease_expires_at=row[14],
            next_attempt_at=row[15],
            queued_at=row[16],
            updated_at=row[17],
            error_code=str(row[18]) if row[18] is not None else None,
        )

    def _mark_live_index_intent(self, cursor: Any, source_id: str, state: str) -> None:
        cursor.execute(
            "UPDATE controller_objects SET data=data || %s::jsonb "
            "WHERE kind='sensor_pcap' AND id=%s",
            (
                self._json(
                    {
                        "index_intent_state": state,
                        "index_intent_schema_version": PCAP_OFFSET_INDEX_SCHEMA_VERSION,
                        "index_intent_parser_contract_version": (
                            PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION
                        ),
                    }
                ),
                source_id,
            ),
        )

    def get_live_segment_index_metadata(self, source_id: str) -> dict[str, Any] | None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor_pcap' AND id=%s",
                (source_id,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return None
            segment = row[0] if isinstance(row[0], dict) else json.loads(row[0])
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s",
                (str(segment.get("analysis_job_id", "")),),
            )
            job_row = cursor.fetchone()
            job = (
                job_row[0]
                if job_row is not None and isinstance(job_row[0], dict)
                else json.loads(job_row[0])
                if job_row is not None
                else None
            )
            self.connection.commit()
        return (
            deepcopy(segment)
            if segment.get("index_requested_at") and eligible_live_segment(job, segment)
            else None
        )

    def admit_live_segment_index(
        self, source_id: str, *, capacity: int, max_attempts: int
    ) -> IndexAdmission:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                ("live-offset-index-admission",),
            )
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor' AND id=("
                "SELECT data->>'sensor_id' FROM controller_objects "
                "WHERE kind='sensor_pcap' AND id=%s) FOR UPDATE",
                (source_id,),
            )
            sensor_row = cursor.fetchone()
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=("
                "SELECT data->>'analysis_job_id' FROM controller_objects "
                "WHERE kind='sensor_pcap' AND id=%s) FOR UPDATE",
                (source_id,),
            )
            job_row = cursor.fetchone()
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor_pcap' AND id=%s FOR UPDATE",
                (source_id,),
            )
            segment_row = cursor.fetchone()
            if sensor_row is None or job_row is None or segment_row is None:
                self.connection.commit()
                return IndexAdmission.DEFERRED
            segment = (
                segment_row[0] if isinstance(segment_row[0], dict) else json.loads(segment_row[0])
            )
            job = job_row[0] if isinstance(job_row[0], dict) else json.loads(job_row[0])
            cursor.execute(
                f"SELECT {self._LIVE_TASK_COLUMNS} FROM pcap_offset_index_jobs "  # noqa: S608 -- fixed internal column list
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s FOR UPDATE",
                (source_id,),
            )
            if cursor.fetchone() is not None:
                self.connection.commit()
                return IndexAdmission.COALESCED
            if not segment.get("index_requested_at") or not eligible_live_segment(job, segment):
                self.connection.commit()
                return IndexAdmission.DEFERRED
            if segment.get("index_intent_state") in {"COMPLETED", "FAILED"}:
                self.connection.commit()
                return IndexAdmission.COALESCED
            cursor.execute(
                "SELECT COUNT(*) FROM pcap_offset_index_jobs WHERE status IN ('QUEUED','RUNNING')"
            )
            count_row = cursor.fetchone()
            if int(count_row[0] if count_row else 0) >= capacity:
                self._mark_live_index_intent(cursor, source_id, "DEFERRED")
                self.connection.commit()
                return IndexAdmission.DEFERRED
            spec = LiveIndexTaskSpec.from_segment(segment)
            cursor.execute(
                "INSERT INTO pcap_offset_index_jobs("
                "source_kind,source_id,sensor_id,analysis_job_id,object_key,source_size_bytes,"
                "source_sha256,capture_format,schema_version,parser_contract_version,status,attempt,"
                "max_attempts,next_attempt_at,queued_at,updated_at) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'QUEUED',0,%s,"
                "clock_timestamp(),clock_timestamp(),clock_timestamp()) "
                "ON CONFLICT(source_kind,source_id) DO NOTHING",
                (
                    spec.source_kind,
                    spec.source_id,
                    spec.sensor_id,
                    spec.analysis_job_id,
                    spec.object_key,
                    spec.source_size_bytes,
                    spec.source_sha256,
                    spec.capture_format,
                    spec.schema_version,
                    spec.parser_contract_version,
                    max_attempts,
                ),
            )
            queued = cursor.rowcount == 1
            if queued:
                self._mark_live_index_intent(cursor, source_id, "PENDING")
            self.connection.commit()
            return IndexAdmission.QUEUED if queued else IndexAdmission.COALESCED

    def get_live_segment_index_task(self, source_id: str) -> LiveIndexTask | None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {self._LIVE_TASK_COLUMNS} FROM pcap_offset_index_jobs "  # noqa: S608 -- fixed internal column list
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s",
                (source_id,),
            )
            task = self._live_task_from_row(cursor.fetchone())
            self.connection.commit()
            return task

    def claim_live_segment_index(
        self, *, now: datetime | None = None, lease_seconds: int
    ) -> LiveIndexTask | None:
        token = secrets.token_hex(16)
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "WITH selected AS (SELECT source_kind,source_id FROM pcap_offset_index_jobs "  # noqa: S608 -- fixed internal RETURNING columns
                "WHERE status='QUEUED' AND next_attempt_at<=clock_timestamp() "
                "ORDER BY next_attempt_at,queued_at,source_id FOR UPDATE SKIP LOCKED LIMIT 1) "
                "UPDATE pcap_offset_index_jobs AS task SET status='RUNNING',attempt=task.attempt+1,"
                "lease_token=%s,lease_expires_at=clock_timestamp()+make_interval(secs => %s),"
                "updated_at=clock_timestamp() FROM selected "
                "WHERE task.source_kind=selected.source_kind AND task.source_id=selected.source_id "
                f"RETURNING {self._LIVE_TASK_COLUMNS}",
                (token, lease_seconds),
            )
            task = self._live_task_from_row(cursor.fetchone())
            self.connection.commit()
            return task

    def heartbeat_live_segment_index(
        self,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        now: datetime | None = None,
        lease_seconds: int,
    ) -> bool:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE pcap_offset_index_jobs SET "
                "lease_expires_at=clock_timestamp()+make_interval(secs => %s),"
                "updated_at=clock_timestamp() "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s AND status='RUNNING' "
                "AND attempt=%s AND lease_token=%s AND lease_expires_at>clock_timestamp()",
                (lease_seconds, source_id, attempt, lease_token),
            )
            updated = bool(cursor.rowcount == 1)
            self.connection.commit()
            return updated

    def complete_live_segment_index(
        self, source_id: str, *, attempt: int, lease_token: str
    ) -> bool:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE pcap_offset_index_jobs SET status='COMPLETED',lease_token=NULL,"
                "lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp() "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s AND status='RUNNING' "
                "AND attempt=%s AND lease_token=%s AND lease_expires_at>clock_timestamp()",
                (source_id, attempt, lease_token),
            )
            updated = bool(cursor.rowcount == 1)
            if updated:
                self._mark_live_index_intent(cursor, source_id, "COMPLETED")
            self.connection.commit()
            return updated

    def fail_live_segment_index(
        self,
        source_id: str,
        *,
        attempt: int,
        lease_token: str,
        transient: bool,
        error_code: str,
        now: datetime | None = None,
        retry_base_seconds: int,
    ) -> bool:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT {self._LIVE_TASK_COLUMNS} FROM pcap_offset_index_jobs "  # noqa: S608 -- fixed internal column list
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s AND status='RUNNING' "
                "AND attempt=%s AND lease_token=%s "
                "AND lease_expires_at>clock_timestamp() FOR UPDATE",
                (source_id, attempt, lease_token),
            )
            task = self._live_task_from_row(cursor.fetchone())
            if task is None:
                self.connection.commit()
                return False
            retry = transient and task.attempt < task.max_attempts
            retry_delay = retry_base_seconds * 2 ** max(task.attempt - 1, 0)
            cursor.execute(
                "UPDATE pcap_offset_index_jobs SET "
                "status=%s,lease_token=NULL,lease_expires_at=NULL,"
                "next_attempt_at=CASE WHEN %s THEN "
                "clock_timestamp()+make_interval(secs => %s) ELSE next_attempt_at END,"
                "updated_at=clock_timestamp(),error_code=%s WHERE source_kind='LIVE_SEGMENT' "
                "AND source_id=%s AND status='RUNNING' AND attempt=%s AND lease_token=%s",
                (
                    "QUEUED" if retry else "FAILED",
                    retry,
                    retry_delay,
                    error_code[:64],
                    source_id,
                    attempt,
                    lease_token,
                ),
            )
            updated = bool(cursor.rowcount == 1)
            if updated:
                self._mark_live_index_intent(cursor, source_id, "PENDING" if retry else "FAILED")
            self.connection.commit()
            return updated

    def recover_live_segment_indexes(self, *, now: datetime | None = None) -> int:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "WITH selected AS (SELECT source_kind,source_id FROM pcap_offset_index_jobs "
                "WHERE status='RUNNING' AND lease_expires_at<=clock_timestamp() "
                "ORDER BY lease_expires_at,source_id "
                "FOR UPDATE SKIP LOCKED) UPDATE pcap_offset_index_jobs AS task SET "
                "status=CASE WHEN task.attempt<task.max_attempts THEN 'QUEUED' ELSE 'FAILED' END,"
                "lease_token=NULL,lease_expires_at=NULL,next_attempt_at=clock_timestamp(),"
                "updated_at=clock_timestamp(),"
                "error_code=CASE WHEN task.attempt<task.max_attempts "
                "THEN NULL ELSE 'LEASE_EXPIRED' END "
                "FROM selected WHERE task.source_kind=selected.source_kind "
                "AND task.source_id=selected.source_id RETURNING source_id,status"
            )
            recovered_rows = cursor.fetchall()
            for source_id, status in recovered_rows:
                self._mark_live_index_intent(
                    cursor, str(source_id), "PENDING" if status == "QUEUED" else "FAILED"
                )
            recovered = len(recovered_rows)
            self.connection.commit()
            return recovered

    def get_live_segment_index_queue_depth(self) -> dict[str, int]:
        depths = {status: 0 for status in ("QUEUED", "RUNNING", "COMPLETED", "FAILED")}
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT status,COUNT(*) FROM pcap_offset_index_jobs "
                "WHERE source_kind='LIVE_SEGMENT' GROUP BY status"
            )
            for status, count in cursor.fetchall():
                depths[str(status)] = int(count)
            self.connection.commit()
        return depths

    def cleanup_terminal_live_segment_indexes(self, *, before: datetime, limit: int) -> int:
        if limit <= 0:
            raise ValueError("terminal cleanup limit must be positive")
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "WITH selected AS (SELECT source_kind,source_id FROM pcap_offset_index_jobs "
                "WHERE source_kind='LIVE_SEGMENT' AND status IN ('COMPLETED','FAILED') "
                "AND updated_at<=%s ORDER BY updated_at,source_id "
                "FOR UPDATE SKIP LOCKED LIMIT %s) "
                "DELETE FROM pcap_offset_index_jobs AS task USING selected "
                "WHERE task.source_kind=selected.source_kind "
                "AND task.source_id=selected.source_id RETURNING task.source_id",
                (before, limit),
            )
            deleted = len(cursor.fetchall())
            self.connection.commit()
            return deleted

    def reconcile_live_segment_indexes(
        self, *, capacity: int, max_attempts: int, limit: int
    ) -> int:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT source.id FROM controller_objects AS source "
                "WHERE source.kind='sensor_pcap' "
                "AND source.data ? 'index_requested_at' "
                "AND source.data->>'index_requested_at'<>'' "
                "AND COALESCE(source.data->>'index_intent_state','PENDING') "
                "IN ('PENDING','DEFERRED') "
                "AND NOT EXISTS (SELECT 1 FROM pcap_offset_index_jobs AS task "
                "WHERE task.source_kind='LIVE_SEGMENT' AND task.source_id=source.id) "
                "ORDER BY source.data->>'index_requested_at',source.id LIMIT %s",
                (limit,),
            )
            source_ids = [str(row[0]) for row in cursor.fetchall()]
            self.connection.commit()
        admitted = 0
        for source_id in source_ids:
            if (
                self.admit_live_segment_index(
                    source_id, capacity=capacity, max_attempts=max_attempts
                )
                is IndexAdmission.QUEUED
            ):
                admitted += 1
        return admitted

    def get_live_capture_source_version(self, source_id: str) -> CaptureSourceVersion | None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                "source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s",
                (source_id,),
            )
            row = cursor.fetchone()
            self.connection.commit()
        return CaptureSourceVersion(*row) if row is not None else None

    def begin_structural_index(
        self, build_id: str, binding: SourceIndexBinding, created_at: datetime
    ) -> None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO pcap_offset_index_generations("
                "build_id,source_kind,source_id,source_version_id,source_size_bytes,"
                "source_sha256,capture_format,schema_version,parser_contract_version,"
                "state,created_at) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,'STAGING',%s)",
                (
                    build_id,
                    binding.source_kind,
                    binding.source_id,
                    binding.source_version_id,
                    binding.source_size_bytes,
                    binding.source_sha256,
                    binding.capture_format,
                    binding.schema_version,
                    binding.parser_contract_version,
                    created_at,
                ),
            )
            self.connection.commit()

    def stage_structural_index_packets(
        self, build_id: str, packets: tuple[StructuralPacketEntry, ...]
    ) -> None:
        if not packets:
            return
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT build_id FROM pcap_offset_index_generations "
                "WHERE build_id=%s AND state='STAGING' FOR UPDATE",
                (build_id,),
            )
            generation = cursor.fetchone()
            if generation is None or str(generation[0]) != build_id:
                raise ValueError("structural index build is not staging")
            cursor.execute(
                "SELECT COALESCE(MAX(packet_index)+1,0) FROM pcap_offset_index_packets "
                "WHERE build_id=%s",
                (build_id,),
            )
            row = cursor.fetchone()
            if row is None or int(row[0]) != packets[0].packet_index:
                raise ValueError("structural packet rows are not contiguous")
            cursor.executemany(
                "INSERT INTO pcap_offset_index_packets("
                "build_id,packet_index,record_offset,data_offset,captured_length,original_length,"
                "framed_length,section_index,interface_id,interface_ordinal,raw_timestamp_ticks) "
                "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [
                    (
                        build_id,
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
                    for packet in packets
                ],
            )
            self.connection.commit()

    @staticmethod
    def _structural_binding_from_row(row: tuple[Any, ...]) -> SourceIndexBinding:
        return SourceIndexBinding(
            source_kind=row[0],
            source_id=str(row[1]),
            source_version_id=str(row[2]),
            source_size_bytes=int(row[3]),
            source_sha256=str(row[4]),
            capture_format=row[5],
            schema_version=int(row[6]),
            parser_contract_version=int(row[7]),
        )

    @classmethod
    def _load_structural_snapshot(
        cls, cursor: Any, build_id: str
    ) -> StructuralIndexSnapshot | None:
        cursor.execute(
            "SELECT source_kind,source_id,source_version_id,source_size_bytes,source_sha256,"
            "capture_format,schema_version,parser_contract_version,created_at,index_sha256,"
            "packet_count,interface_count "
            "FROM pcap_offset_index_generations WHERE build_id=%s AND state='READY'",
            (build_id,),
        )
        generation = cursor.fetchone()
        if generation is None or generation[9] is None:
            return None
        cursor.execute(
            "SELECT section_index,interface_id,interface_ordinal,link_type,snaplen,"
            "timestamp_resolution_numerator,timestamp_resolution_denominator,"
            "timestamp_offset_seconds FROM pcap_offset_index_interfaces "
            "WHERE build_id=%s ORDER BY interface_ordinal",
            (build_id,),
        )
        interfaces = tuple(StructuralInterfaceEntry(*row) for row in cursor.fetchall())
        cursor.execute(
            "SELECT packet_index,record_offset,data_offset,captured_length,original_length,"
            "framed_length,section_index,interface_id,interface_ordinal,raw_timestamp_ticks "
            "FROM pcap_offset_index_packets WHERE build_id=%s ORDER BY packet_index",
            (build_id,),
        )
        packets = tuple(
            StructuralPacketEntry(
                int(row[0]),
                int(row[1]),
                int(row[2]),
                int(row[3]),
                int(row[4]),
                int(row[5]),
                int(row[6]),
                int(row[7]),
                int(row[8]),
                int(row[9]),
            )
            for row in cursor.fetchall()
        )
        if generation[10] is None or generation[11] is None:
            raise ValueError("ready structural index counts are missing")
        if int(generation[10]) != len(packets) or int(generation[11]) != len(interfaces):
            raise ValueError("ready structural index counts do not match child rows")
        return StructuralIndexSnapshot(
            build_id,
            cls._structural_binding_from_row(generation[:8]),
            generation[8],
            str(generation[9]),
            interfaces,
            packets,
        )

    @classmethod
    def _capture_source_row_matches(
        cls,
        row: tuple[Any, ...] | None,
        binding: SourceIndexBinding,
        *,
        object_key: str | None = None,
    ) -> bool:
        if row is None or not str(row[2]):
            return False
        expected = (
            binding.source_kind,
            binding.source_id,
            binding.source_version_id,
            binding.source_size_bytes,
            binding.source_sha256,
        )
        actual = (
            str(row[0]),
            str(row[1]),
            str(row[3]),
            int(row[4]),
            str(row[5]),
        )
        return actual == expected and (object_key is None or str(row[2]) == object_key)

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
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                (binding.source_id,),
            )
            job_row = cursor.fetchone()
            job = None
            if job_row is not None:
                job = job_row[0] if isinstance(job_row[0], dict) else json.loads(job_row[0])
            cursor.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,"
                "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                (binding.source_kind, binding.source_id),
            )
            source_version_row = cursor.fetchone()
            if not _job_matches_structural_binding(
                job, binding
            ) or not self._capture_source_row_matches(source_version_row, binding):
                self.connection.rollback()
                return False
            self._lock_posting_lifecycle_for_sources(
                cursor, binding.source_kind, [binding.source_id]
            )
            cursor.execute(
                "SELECT source_kind,source_id,source_version_id,source_size_bytes,source_sha256,"
                "capture_format,schema_version,parser_contract_version,created_at "
                "FROM pcap_offset_index_generations "
                "WHERE build_id=%s AND state='STAGING'",
                (build_id,),
            )
            generation = cursor.fetchone()
            cursor.execute(
                "SELECT COUNT(*) FROM pcap_offset_index_packets WHERE build_id=%s", (build_id,)
            )
            count_row = cursor.fetchone()
            if (
                generation is None
                or self._structural_binding_from_row(generation[:8]) != binding
                or count_row is None
                or int(count_row[0]) != packet_count
                or not _job_matches_structural_binding(job, binding)
            ):
                self.connection.rollback()
                return False
            cursor.execute(
                "SELECT packet_index,record_offset,data_offset,captured_length,original_length,"
                "framed_length,section_index,interface_id,interface_ordinal,raw_timestamp_ticks "
                "FROM pcap_offset_index_packets WHERE build_id=%s ORDER BY packet_index",
                (build_id,),
            )
            packets = tuple(StructuralPacketEntry(*row) for row in cursor.fetchall())
            snapshot = StructuralIndexSnapshot(
                build_id,
                binding,
                generation[8],
                structural_index_digest(binding, interfaces, packets),
                interfaces,
                packets,
            )
            if not validate_structural_index(snapshot):
                self.connection.rollback()
                return False
            cursor.executemany(
                "INSERT INTO pcap_offset_index_interfaces("
                "build_id,interface_ordinal,section_index,interface_id,link_type,snaplen,"
                "timestamp_resolution_numerator,timestamp_resolution_denominator,"
                "timestamp_offset_seconds) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [
                    (
                        build_id,
                        interface.interface_ordinal,
                        interface.section_index,
                        interface.interface_id,
                        interface.link_type,
                        interface.snaplen,
                        interface.timestamp_resolution_numerator,
                        interface.timestamp_resolution_denominator,
                        interface.timestamp_offset_seconds,
                    )
                    for interface in interfaces
                ],
            )
            cursor.execute(
                "SELECT build_id FROM pcap_offset_index_owners "
                "WHERE source_kind=%s AND source_id=%s",
                (binding.source_kind, binding.source_id),
            )
            owner = cursor.fetchone()
            if owner is not None and str(owner[0]) != build_id:
                cursor.execute(
                    "SELECT 1 FROM pcap_posting_index_jobs WHERE source_kind=%s "
                    "AND source_id=%s AND parent_structural_build_id=%s "
                    "AND status IN ('QUEUED','RUNNING')",
                    (binding.source_kind, binding.source_id, str(owner[0])),
                )
                if cursor.fetchone() is not None:
                    self.connection.rollback()
                    return False
            cursor.execute(
                "UPDATE pcap_offset_index_generations SET state='READY',packet_count=%s,"
                "interface_count=%s,index_sha256=%s WHERE build_id=%s AND state='STAGING'",
                (packet_count, len(interfaces), snapshot.index_sha256, build_id),
            )
            cursor.execute(
                "INSERT INTO pcap_offset_index_owners(source_kind,source_id,build_id) "
                "VALUES(%s,%s,%s) ON CONFLICT(source_kind,source_id) "
                "DO UPDATE SET build_id=excluded.build_id",
                (binding.source_kind, binding.source_id, build_id),
            )
            if owner is not None and str(owner[0]) != build_id:
                cursor.execute(
                    "DELETE FROM pcap_offset_index_generations WHERE build_id=%s", (owner[0],)
                )
            if request_postings:
                source_version = CaptureSourceVersion(*source_version_row)
                spec = replace(
                    PostingIndexTaskSpec.from_binding(source_version, snapshot),
                    posting_schema_version=posting_schema_version,
                    posting_parser_contract_version=posting_parser_contract_version,
                    filter_contract_version=filter_contract_version,
                )
                cursor.execute(
                    "INSERT INTO pcap_posting_index_intents("
                    + self._POSTING_SPEC_COLUMNS
                    + ",status,requested_at,updated_at,published_build_id,error_code) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',"
                    "clock_timestamp(),clock_timestamp(),NULL,NULL) "
                    "ON CONFLICT(source_kind,source_id) DO UPDATE SET "
                    "source_version_id=excluded.source_version_id,"
                    "source_size_bytes=excluded.source_size_bytes,"
                    "source_sha256=excluded.source_sha256,capture_format=excluded.capture_format,"
                    "parent_structural_build_id=excluded.parent_structural_build_id,"
                    "parent_structural_index_sha256=excluded.parent_structural_index_sha256,"
                    "structural_schema_version=excluded.structural_schema_version,"
                    "structural_parser_contract_version="
                    "excluded.structural_parser_contract_version,"
                    "posting_schema_version=excluded.posting_schema_version,"
                    "posting_parser_contract_version=excluded.posting_parser_contract_version,"
                    "filter_contract_version=excluded.filter_contract_version,status='PENDING',"
                    "requested_at=clock_timestamp(),updated_at=clock_timestamp(),"
                    "published_build_id=NULL,error_code=NULL "
                    "WHERE (pcap_posting_index_intents.source_version_id,"
                    "pcap_posting_index_intents.parent_structural_build_id,"
                    "pcap_posting_index_intents.parent_structural_index_sha256,"
                    "pcap_posting_index_intents.posting_schema_version,"
                    "pcap_posting_index_intents.posting_parser_contract_version,"
                    "pcap_posting_index_intents.filter_contract_version) IS DISTINCT FROM "
                    "(excluded.source_version_id,excluded.parent_structural_build_id,"
                    "excluded.parent_structural_index_sha256,excluded.posting_schema_version,"
                    "excluded.posting_parser_contract_version,excluded.filter_contract_version)",
                    self._posting_spec_values(spec),
                )
                if cursor.rowcount != 1:
                    cursor.execute(
                        "SELECT " + self._POSTING_INTENT_COLUMNS + " "
                        "FROM pcap_posting_index_intents "
                        "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                        (spec.source_kind, spec.source_id),
                    )
                    marker = cursor.fetchone()
                    if (
                        marker is None
                        or self._posting_intent(marker).spec.identity != spec.identity
                    ):
                        self.connection.rollback()
                        return False
            self.connection.commit()
            return True

    def publish_live_structural_index(
        self,
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
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            # Lock the canonical ownership chain before any derived row can become visible.
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor' AND id=("
                "SELECT data->>'sensor_id' FROM controller_objects "
                "WHERE kind='sensor_pcap' AND id=%s) FOR UPDATE",
                (binding.source_id,),
            )
            sensor_row = cursor.fetchone()
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='job' AND id=("
                "SELECT data->>'analysis_job_id' FROM controller_objects "
                "WHERE kind='sensor_pcap' AND id=%s) FOR UPDATE",
                (binding.source_id,),
            )
            job_row = cursor.fetchone()
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor_pcap' AND id=%s FOR UPDATE",
                (binding.source_id,),
            )
            segment_row = cursor.fetchone()
            if sensor_row is None or job_row is None or segment_row is None:
                self.connection.rollback()
                return False
            sensor = sensor_row[0] if isinstance(sensor_row[0], dict) else json.loads(sensor_row[0])
            job = job_row[0] if isinstance(job_row[0], dict) else json.loads(job_row[0])
            segment = (
                segment_row[0] if isinstance(segment_row[0], dict) else json.loads(segment_row[0])
            )
            expected_key = str(
                segment.get("object_key")
                or f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
            )
            cursor.execute(
                f"SELECT {self._LIVE_TASK_COLUMNS} FROM pcap_offset_index_jobs "  # noqa: S608 -- fixed internal column list
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s FOR UPDATE",
                (binding.source_id,),
            )
            task = self._live_task_from_row(cursor.fetchone())
            expected_version = CaptureSourceVersion(
                "LIVE_SEGMENT",
                binding.source_id,
                expected_key,
                binding.source_version_id,
                binding.source_size_bytes,
                binding.source_sha256,
            )
            if (
                str(sensor.get("sensor_id", "")) != str(segment.get("sensor_id", ""))
                or not segment.get("index_requested_at")
                or not eligible_live_segment(job, segment)
                or int(segment.get("size_bytes", -1)) != binding.source_size_bytes
                or str(segment.get("sha256", "")) != binding.source_sha256
                or source_version != expected_version
                or task is None
                or task.spec != LiveIndexTaskSpec.from_segment(segment)
                or task.status != "RUNNING"
                or task.attempt != attempt
                or task.lease_token != lease_token
                or task.lease_expires_at is None
            ):
                self.connection.rollback()
                return False
            cursor.execute(
                "INSERT INTO pcap_capture_source_versions("
                "source_kind,source_id,object_key,source_version_id,"
                "source_size_bytes,source_sha256,updated_at) "
                "VALUES(%s,%s,%s,%s,%s,%s,clock_timestamp()) "
                "ON CONFLICT(source_kind,source_id) DO NOTHING",
                (
                    source_version.source_kind,
                    source_version.source_id,
                    source_version.object_key,
                    source_version.source_version_id,
                    source_version.source_size_bytes,
                    source_version.source_sha256,
                ),
            )
            cursor.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,source_size_bytes,"
                "source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s FOR UPDATE",
                (binding.source_id,),
            )
            persisted = cursor.fetchone()
            if persisted is None or CaptureSourceVersion(*persisted) != source_version:
                self.connection.rollback()
                return False
            self._lock_posting_lifecycle_for_sources(cursor, "LIVE_SEGMENT", [binding.source_id])
            cursor.execute(
                "SELECT source_kind,source_id,source_version_id,source_size_bytes,source_sha256,"
                "capture_format,schema_version,parser_contract_version,created_at "
                "FROM pcap_offset_index_generations "
                "WHERE build_id=%s AND state='STAGING'",
                (build_id,),
            )
            generation = cursor.fetchone()
            if generation is None or self._structural_binding_from_row(generation[:8]) != binding:
                self.connection.rollback()
                return False
            cursor.execute(
                "SELECT COUNT(*) FROM pcap_offset_index_packets WHERE build_id=%s",
                (build_id,),
            )
            count_row = cursor.fetchone()
            cursor.execute(
                "SELECT packet_index,record_offset,data_offset,captured_length,original_length,"
                "framed_length,section_index,interface_id,interface_ordinal,raw_timestamp_ticks "
                "FROM pcap_offset_index_packets WHERE build_id=%s ORDER BY packet_index",
                (build_id,),
            )
            packets = tuple(
                StructuralPacketEntry(*(int(value) for value in row)) for row in cursor.fetchall()
            )
            snapshot = StructuralIndexSnapshot(
                build_id,
                binding,
                generation[8],
                structural_index_digest(binding, interfaces, packets),
                interfaces,
                packets,
            )
            if (
                count_row is None
                or int(count_row[0]) != packet_count
                or len(packets) != packet_count
                or not validate_structural_index(snapshot)
            ):
                self.connection.rollback()
                return False
            cursor.execute(
                "SELECT build_id FROM pcap_offset_index_owners "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s",
                (binding.source_id,),
            )
            previous = cursor.fetchone()
            if previous is not None and str(previous[0]) != build_id:
                cursor.execute(
                    "SELECT 1 FROM pcap_posting_index_jobs WHERE source_kind='LIVE_SEGMENT' "
                    "AND source_id=%s AND parent_structural_build_id=%s "
                    "AND status IN ('QUEUED','RUNNING')",
                    (binding.source_id, str(previous[0])),
                )
                if cursor.fetchone() is not None:
                    self.connection.rollback()
                    return False
            cursor.executemany(
                "INSERT INTO pcap_offset_index_interfaces("
                "build_id,interface_ordinal,section_index,interface_id,link_type,snaplen,"
                "timestamp_resolution_numerator,timestamp_resolution_denominator,"
                "timestamp_offset_seconds) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                [
                    (
                        build_id,
                        item.interface_ordinal,
                        item.section_index,
                        item.interface_id,
                        item.link_type,
                        item.snaplen,
                        item.timestamp_resolution_numerator,
                        item.timestamp_resolution_denominator,
                        item.timestamp_offset_seconds,
                    )
                    for item in interfaces
                ],
            )
            cursor.execute(
                "UPDATE pcap_offset_index_generations SET state='READY',packet_count=%s,"
                "interface_count=%s,index_sha256=%s WHERE build_id=%s AND state='STAGING'",
                (packet_count, len(interfaces), snapshot.index_sha256, build_id),
            )
            if cursor.rowcount != 1:
                self.connection.rollback()
                return False
            cursor.execute(
                "INSERT INTO pcap_offset_index_owners(source_kind,source_id,build_id) "
                "VALUES('LIVE_SEGMENT',%s,%s) ON CONFLICT(source_kind,source_id) "
                "DO UPDATE SET build_id=excluded.build_id",
                (binding.source_id, build_id),
            )
            if previous is not None and str(previous[0]) != build_id:
                cursor.execute(
                    "DELETE FROM pcap_offset_index_generations WHERE build_id=%s", (previous[0],)
                )
            if request_postings:
                spec = replace(
                    PostingIndexTaskSpec.from_binding(source_version, snapshot),
                    posting_schema_version=posting_schema_version,
                    posting_parser_contract_version=posting_parser_contract_version,
                    filter_contract_version=filter_contract_version,
                )
                cursor.execute(
                    "INSERT INTO pcap_posting_index_intents("
                    + self._POSTING_SPEC_COLUMNS
                    + ",status,requested_at,updated_at,published_build_id,error_code) "
                    "VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',"
                    "clock_timestamp(),clock_timestamp(),NULL,NULL) "
                    "ON CONFLICT(source_kind,source_id) DO UPDATE SET "
                    "source_version_id=excluded.source_version_id,"
                    "source_size_bytes=excluded.source_size_bytes,"
                    "source_sha256=excluded.source_sha256,capture_format=excluded.capture_format,"
                    "parent_structural_build_id=excluded.parent_structural_build_id,"
                    "parent_structural_index_sha256=excluded.parent_structural_index_sha256,"
                    "structural_schema_version=excluded.structural_schema_version,"
                    "structural_parser_contract_version="
                    "excluded.structural_parser_contract_version,"
                    "posting_schema_version=excluded.posting_schema_version,"
                    "posting_parser_contract_version=excluded.posting_parser_contract_version,"
                    "filter_contract_version=excluded.filter_contract_version,status='PENDING',"
                    "requested_at=clock_timestamp(),updated_at=clock_timestamp(),"
                    "published_build_id=NULL,error_code=NULL "
                    "WHERE (pcap_posting_index_intents.source_version_id,"
                    "pcap_posting_index_intents.parent_structural_build_id,"
                    "pcap_posting_index_intents.parent_structural_index_sha256,"
                    "pcap_posting_index_intents.posting_schema_version,"
                    "pcap_posting_index_intents.posting_parser_contract_version,"
                    "pcap_posting_index_intents.filter_contract_version) IS DISTINCT FROM "
                    "(excluded.source_version_id,excluded.parent_structural_build_id,"
                    "excluded.parent_structural_index_sha256,excluded.posting_schema_version,"
                    "excluded.posting_parser_contract_version,excluded.filter_contract_version)",
                    self._posting_spec_values(spec),
                )
                if cursor.rowcount != 1:
                    cursor.execute(
                        "SELECT " + self._POSTING_INTENT_COLUMNS + " "
                        "FROM pcap_posting_index_intents "
                        "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                        (spec.source_kind, spec.source_id),
                    )
                    marker = cursor.fetchone()
                    if (
                        marker is None
                        or self._posting_intent(marker).spec.identity != spec.identity
                    ):
                        self.connection.rollback()
                        return False
            cursor.execute(
                "UPDATE pcap_offset_index_jobs SET status='COMPLETED',lease_token=NULL,"
                "lease_expires_at=NULL,completed_at=clock_timestamp(),"
                "updated_at=clock_timestamp(),published_build_id=%s,"
                "published_source_version_id=%s WHERE source_kind='LIVE_SEGMENT' AND source_id=%s "
                "AND status='RUNNING' AND attempt=%s AND lease_token=%s "
                "AND lease_expires_at>clock_timestamp()",
                (
                    build_id,
                    binding.source_version_id,
                    binding.source_id,
                    attempt,
                    lease_token,
                ),
            )
            if cursor.rowcount != 1:
                self.connection.rollback()
                return False
            self._mark_live_index_intent(cursor, binding.source_id, "COMPLETED")
            self.connection.commit()
            return True

    def abort_structural_index(self, build_id: str) -> None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM pcap_offset_index_generations WHERE build_id=%s AND state='STAGING'",
                (build_id,),
            )
            self.connection.commit()

    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT build_id FROM pcap_offset_index_owners "
                "WHERE source_kind=%s AND source_id=%s",
                (binding.source_kind, binding.source_id),
            )
            owner = cursor.fetchone()
            if owner is None:
                self.connection.commit()
                return StructuralIndexLookup(IndexAvailability.MISSING)
            try:
                snapshot = self._load_structural_snapshot(cursor, str(owner[0]))
            except (TypeError, ValueError, KeyError):
                self.connection.rollback()
                return StructuralIndexLookup(IndexAvailability.CORRUPT)
            canonical_matches = False
            canonical_object_key: str | None = None
            if binding.source_kind == "LIVE_SEGMENT":
                cursor.execute(
                    "SELECT data FROM controller_objects WHERE kind='sensor_pcap' AND id=%s",
                    (binding.source_id,),
                )
                segment_row = cursor.fetchone()
                segment = None
                if segment_row is not None:
                    segment = (
                        segment_row[0]
                        if isinstance(segment_row[0], dict)
                        else json.loads(segment_row[0])
                    )
                job = None
                if segment is not None and segment.get("analysis_job_id"):
                    cursor.execute(
                        "SELECT data FROM controller_objects WHERE kind='job' AND id=%s",
                        (str(segment["analysis_job_id"]),),
                    )
                    parent_row = cursor.fetchone()
                    if parent_row is not None:
                        job = (
                            parent_row[0]
                            if isinstance(parent_row[0], dict)
                            else json.loads(parent_row[0])
                        )
                canonical_matches = bool(
                    segment is not None
                    and segment.get("id") == binding.source_id
                    and segment.get("index_requested_at")
                    and segment.get("size_bytes") == binding.source_size_bytes
                    and segment.get("sha256") == binding.source_sha256
                    and eligible_live_segment(job, segment)
                )
                if segment is not None:
                    canonical_object_key = str(
                        segment.get("object_key")
                        or f"sensor-pcaps/{segment.get('sensor_id')}/{binding.source_id}.pcap"
                    )
            else:
                cursor.execute(
                    "SELECT data FROM controller_objects WHERE kind='job' AND id=%s",
                    (binding.source_id,),
                )
                job_row = cursor.fetchone()
                job = None
                if job_row is not None:
                    job = job_row[0] if isinstance(job_row[0], dict) else json.loads(job_row[0])
                canonical_matches = _job_matches_structural_binding(job, binding)
            cursor.execute(
                "SELECT source_kind,source_id,object_key,source_version_id,"
                "source_size_bytes,source_sha256 FROM pcap_capture_source_versions "
                "WHERE source_kind=%s AND source_id=%s",
                (binding.source_kind, binding.source_id),
            )
            source_version_row = cursor.fetchone()
            self.connection.commit()
        if snapshot is None:
            return StructuralIndexLookup(IndexAvailability.CORRUPT)
        if (
            snapshot.binding.schema_version != binding.schema_version
            or snapshot.binding.parser_contract_version != binding.parser_contract_version
        ):
            return StructuralIndexLookup(IndexAvailability.UNSUPPORTED_SCHEMA)
        if snapshot.binding != binding:
            return StructuralIndexLookup(IndexAvailability.STALE)
        if not canonical_matches or not self._capture_source_row_matches(
            source_version_row, binding, object_key=canonical_object_key
        ):
            return StructuralIndexLookup(IndexAvailability.STALE)
        if not validate_structural_index(snapshot):
            return StructuralIndexLookup(IndexAvailability.CORRUPT)
        return StructuralIndexLookup(IndexAvailability.READY, snapshot)

    def delete_structural_indexes_for_source(
        self, source_id: str, *, source_kind: str = "PCAP_UPLOAD"
    ) -> None:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            self._lock_posting_lifecycle_for_sources(
                cursor, cast(PostingSourceKind, source_kind), [source_id]
            )
            cursor.execute(
                "DELETE FROM pcap_offset_index_generations WHERE source_kind=%s AND source_id=%s",
                (source_kind, source_id),
            )
            self.connection.commit()

    def cleanup_stale_structural_indexes(self, *, before: datetime, limit: int) -> int:
        with self._lock, self._rollback_on_error(), self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT source_kind,source_id,build_id FROM pcap_offset_index_generations "
                "WHERE state='STAGING' AND created_at<=%s ORDER BY created_at,build_id LIMIT %s",
                (before, limit),
            )
            selected = [
                (cast(PostingSourceKind, str(row[0])), str(row[1]), str(row[2]))
                for row in cursor.fetchall()
            ]
            grouped: dict[PostingSourceKind, list[str]] = {}
            for source_kind, source_id, _build_id in selected:
                grouped.setdefault(source_kind, []).append(source_id)
            for source_kind in sorted(grouped):
                self._lock_posting_lifecycle_for_sources(cursor, source_kind, grouped[source_kind])
            build_ids = [build_id for _kind, _source_id, build_id in selected]
            deleted = 0
            if build_ids:
                cursor.execute(
                    "DELETE FROM pcap_offset_index_generations WHERE build_id=ANY(%s) "
                    "AND state='STAGING' AND created_at<=%s RETURNING build_id",
                    (build_ids, before),
                )
                deleted = len(cursor.fetchall())
            self.connection.commit()
            return deleted

    def delete_retained_source(self, job_id: str) -> bool:
        return self.delete_job(job_id)

    def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute("DELETE FROM candidate_records WHERE job_id=%s", (job_id,))
                    cursor.executemany(
                        "INSERT INTO candidate_records("
                        "candidate_id,job_id,position,score,severity,excluded,data"
                        ") VALUES(%s,%s,%s,%s,%s,%s,%s::jsonb)",
                        [
                            (
                                str(candidate["id"]),
                                job_id,
                                position,
                                int(candidate.get("score", 0)),
                                str(candidate.get("severity", "")),
                                bool(candidate.get("excluded", False)),
                                self._json(candidate),
                            )
                            for position, candidate in enumerate(candidates)
                        ],
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('candidates',%s,%s,%s::jsonb)",
                        (job_id, datetime.now(UTC), self._json(candidates)),
                    )
                connection.commit()
            except Exception:
                connection.rollback()
                raise

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM candidate_records WHERE job_id=%s ORDER BY position", (job_id,)
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT job_id,data FROM candidate_records WHERE candidate_id=%s", (candidate_id,)
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        data = row[1] if isinstance(row[1], dict) else json.loads(row[1])
        return str(row[0]), data

    def query_candidates(
        self,
        *,
        minimum_score: int = 0,
        severity: str | None = None,
        include_suppressed: bool = False,
    ) -> list[tuple[str, dict[str, Any]]]:
        clauses = ["score >= %s"]
        parameters: list[Any] = [minimum_score]
        if severity is not None:
            clauses.append("severity = %s")
            parameters.append(severity)
        if not include_suppressed:
            clauses.append("excluded = false")
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT job_id,data FROM candidate_records WHERE "  # noqa: S608 -- clauses are code-owned and values are bound
                + " AND ".join(clauses),
                parameters,
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [
            (str(row[0]), row[1] if isinstance(row[1], dict) else json.loads(row[1]))
            for row in rows
        ]

    @staticmethod
    def _candidate_query_parts(
        minimum_score: int, severity: str | None, include_suppressed: bool
    ) -> tuple[list[str], list[Any]]:
        clauses = ["score >= %s"]
        parameters: list[Any] = [minimum_score]
        if severity is not None:
            clauses.append("severity = %s")
            parameters.append(severity)
        if not include_suppressed:
            clauses.append("excluded = false")
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
            "candidate_ip": "data->>'candidate_ip'",
            "first_seen": "data->>'first_seen'",
            "last_seen": "data->>'last_seen'",
        }
        order_column = columns[field]
        where = " AND ".join(clauses)
        with self.connection.cursor() as cursor:
            cursor.execute(
                f"SELECT COUNT(*) FROM candidate_records WHERE {where}",  # noqa: S608 -- code-owned clauses
                parameters,
            )
            total_row = cursor.fetchone()
            page_query = f"SELECT job_id,data FROM candidate_records WHERE {where} "  # noqa: S608 -- internal clauses
            page_query += f"ORDER BY {order_column} {direction},candidate_id ASC LIMIT %s OFFSET %s"  # noqa: S608 -- allowlisted columns
            cursor.execute(
                page_query,
                [*parameters, page_size, (page - 1) * page_size],
            )
            rows = cursor.fetchall()
            self.connection.commit()
        total = int(total_row[0]) if total_row is not None else 0
        return [
            (str(row[0]), row[1] if isinstance(row[1], dict) else json.loads(row[1]))
            for row in rows
        ], total

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
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT candidate_id,excluded FROM candidate_records WHERE "  # noqa: S608 -- code-owned clauses
                + " AND ".join(clauses),
                parameters,
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [(str(row[0]), bool(row[1])) for row in rows]

    def candidate_workflow_counts(
        self,
        *,
        minimum_score: int,
        severity: str | None,
        include_suppressed: bool,
    ) -> dict[str, int]:
        clauses, parameters = self._candidate_query_parts(
            minimum_score, severity, include_suppressed
        )
        where = " AND ".join(f"c.{clause}" for clause in clauses)
        query = f"""
            WITH selected AS (
              SELECT c.candidate_id FROM candidate_records c WHERE {where}
            ), current_decision AS (
              SELECT DISTINCT ON (o.data->>'candidate_id')
                o.data->>'candidate_id' AS candidate_id,
                o.data->>'id' AS verdict_id,
                o.data->>'verdict' AS verdict
              FROM controller_objects o JOIN selected s
                ON s.candidate_id=o.data->>'candidate_id'
              WHERE o.kind='candidate-decision'
                AND o.data->>'verdict' IN ('CONFIRMED_C2','FALSE_POSITIVE','UNDER_REVIEW')
                AND o.data->>'confidence' IN ('CONFIRMED','HIGH','MEDIUM','LOW')
                AND COALESCE(o.data->>'id','')<>''
                AND COALESCE(o.data->>'candidate_id','')<>''
                AND COALESCE(o.data->>'note','')<>''
                AND COALESCE(o.data->>'created_by','')<>''
                AND o.data->>'created_at' ~
                  '^\\d{{4}}-\\d{{2}}-\\d{{2}}T\\d{{2}}:\\d{{2}}:\\d{{2}}.*(Z|[+-]\\d{{2}}:\\d{{2}})$'
              ORDER BY o.data->>'candidate_id',o.data->>'created_at' DESC
            ), current_action AS (
              SELECT DISTINCT ON (o.data->>'candidate_id')
                o.data->>'candidate_id' AS candidate_id,o.data->>'status' AS status
              FROM controller_objects o JOIN current_decision d
                ON d.candidate_id=o.data->>'candidate_id'
                AND d.verdict_id=o.data->>'verdict_id'
              WHERE o.kind='candidate-action'
              ORDER BY o.data->>'candidate_id',o.data->>'created_at' DESC
            )
            SELECT
              COUNT(*) FILTER (WHERE d.verdict IS NULL),
              COUNT(*) FILTER (WHERE d.verdict='UNDER_REVIEW'),
              COUNT(*) FILTER (WHERE d.verdict='CONFIRMED_C2'
                AND COALESCE(a.status,'PENDING') NOT IN ('IN_PROGRESS','COMPLETED')),
              COUNT(*) FILTER (WHERE d.verdict='CONFIRMED_C2' AND a.status='IN_PROGRESS'),
              COUNT(*) FILTER (WHERE d.verdict='CONFIRMED_C2' AND a.status='COMPLETED'),
              COUNT(*) FILTER (WHERE d.verdict='FALSE_POSITIVE'),
              COUNT(*) FILTER (WHERE d.verdict='FALSE_POSITIVE'
                OR (d.verdict='CONFIRMED_C2' AND a.status='COMPLETED'))
            FROM selected s
            LEFT JOIN current_decision d USING(candidate_id)
            LEFT JOIN current_action a USING(candidate_id)
        """  # noqa: S608 -- where is assembled from code-owned clauses
        with self.connection.cursor() as cursor:
            cursor.execute(query, parameters)
            row = cursor.fetchone()
            self.connection.commit()
        values = row or (0, 0, 0, 0, 0, 0, 0)
        return dict(
            zip(
                (
                    "needs_review",
                    "in_review",
                    "action_required",
                    "action_in_progress",
                    "action_completed",
                    "false_positive",
                    "done",
                ),
                (int(value) for value in values),
                strict=True,
            )
        )

    def create_ai_run(self, run: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_analysis_runs"
                        "(run_id,analysis_job_id,idempotency_key,created_at,data) "
                        "VALUES(%s,%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(analysis_job_id,idempotency_key) DO NOTHING "
                        "RETURNING data",
                        (
                            run["id"],
                            run["analysis_job_id"],
                            run["idempotency_key"],
                            run["created_at"],
                            self._json(run),
                        ),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        cursor.execute(
                            "SELECT data FROM ai_analysis_runs "
                            "WHERE analysis_job_id=%s AND idempotency_key=%s",
                            (run["analysis_job_id"], run["idempotency_key"]),
                        )
                        existing_row = cursor.fetchone()
                        if existing_row is None:
                            raise RuntimeError("AI run idempotency conflict could not be read")
                        connection.commit()
                        value = existing_row[0]
                        return (value if isinstance(value, dict) else json.loads(value)), False
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('ai-run',%s,%s,%s::jsonb)",
                        (run["id"], datetime.now(UTC), self._json(run)),
                    )
                connection.commit()
                return deepcopy(run), True
            except Exception:
                connection.rollback()
                raise

    def save_ai_run(self, run: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM ai_analysis_runs WHERE run_id=%s FOR UPDATE",
                        (run["id"],),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        connection.commit()
                        raise KeyError(f"AI run not found: {run['id']}")
                    value = row[0]
                    existing = value if isinstance(value, dict) else json.loads(value)
                    if existing.get("status") in {"COMPLETED", "FAILED", "CANCELLED"}:
                        connection.commit()
                        return existing
                    cursor.execute(
                        "UPDATE ai_analysis_runs SET data=%s::jsonb WHERE run_id=%s",
                        (self._json(run), run["id"]),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('ai-run',%s,%s,%s::jsonb)",
                        (run["id"], datetime.now(UTC), self._json(run)),
                    )
                connection.commit()
                return deepcopy(run)
            except Exception:
                connection.rollback()
                raise

    def get_ai_run(self, run_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT data FROM ai_analysis_runs WHERE run_id=%s", (run_id,))
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def list_ai_runs(self, job_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_analysis_runs "
                "WHERE analysis_job_id=%s ORDER BY created_at DESC",
                (job_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def save_ai_assessment(self, assessment: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_candidate_assessments"
                        "(assessment_id,ai_run_id,created_at,data) VALUES(%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(assessment_id) DO NOTHING",
                        (
                            assessment["id"],
                            assessment["ai_run_id"],
                            assessment["created_at"],
                            self._json(assessment),
                        ),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('ai-assessment',%s,%s,%s::jsonb)",
                        (assessment["id"], datetime.now(UTC), self._json(assessment)),
                    )
                connection.commit()
                return deepcopy(assessment)
            except Exception:
                connection.rollback()
                raise

    def get_ai_assessment(self, assessment_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_candidate_assessments WHERE assessment_id=%s",
                (assessment_id,),
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        value = row[0]
        return value if isinstance(value, dict) else json.loads(value)

    def list_ai_assessments(self, run_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_candidate_assessments WHERE ai_run_id=%s ORDER BY created_at",
                (run_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def save_ai_artifact(self, artifact: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_generated_artifacts"
                        "(artifact_id,assessment_id,created_at,data) VALUES(%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(artifact_id) DO UPDATE SET data=excluded.data",
                        (
                            artifact["id"],
                            artifact["assessment_id"],
                            artifact["created_at"],
                            self._json(artifact),
                        ),
                    )
                connection.commit()
                return deepcopy(artifact)
            except Exception:
                connection.rollback()
                raise

    def get_ai_artifact(self, artifact_id: str) -> dict[str, Any] | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_generated_artifacts WHERE artifact_id=%s", (artifact_id,)
            )
            row = cursor.fetchone()
            self.connection.commit()
        if row is None:
            return None
        return row[0] if isinstance(row[0], dict) else json.loads(row[0])

    def list_ai_artifacts(self, assessment_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_generated_artifacts "
                "WHERE assessment_id=%s ORDER BY created_at,artifact_id",
                (assessment_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def save_ai_feedback(self, feedback: dict[str, Any]) -> dict[str, Any]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO ai_feedback"
                        "(feedback_id,assessment_id,created_at,data) VALUES(%s,%s,%s,%s::jsonb) "
                        "ON CONFLICT(feedback_id) DO NOTHING",
                        (
                            feedback["id"],
                            feedback["assessment_id"],
                            feedback["created_at"],
                            self._json(feedback),
                        ),
                    )
                connection.commit()
                return deepcopy(feedback)
            except Exception:
                connection.rollback()
                raise

    def list_ai_feedback(self, assessment_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM ai_feedback "
                "WHERE assessment_id=%s ORDER BY created_at,feedback_id",
                (assessment_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def append_audit_event(self, kind: str, object_id: str, data: dict[str, Any]) -> None:
        self._audit(kind, object_id, data)

    def list_candidate_sets(self) -> dict[str, list[dict[str, Any]]]:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT job_id,data FROM candidate_records ORDER BY job_id,position")
            rows = cursor.fetchall()
            self.connection.commit()
        result: dict[str, list[dict[str, Any]]] = {}
        for job_id, data in rows:
            result.setdefault(str(job_id), []).append(
                data if isinstance(data, dict) else json.loads(data)
            )
        return result

    def get_integration_settings(self) -> dict[str, Any] | None:
        return self._get("integration_settings", "global")

    def save_integration_settings(
        self, settings: dict[str, Any], expected_version: int
    ) -> tuple[dict[str, Any] | None, str]:
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM controller_objects "
                        "WHERE kind='integration_settings' AND id='global' FOR UPDATE"
                    )
                    row = cursor.fetchone()
                    value = row[0] if row else None
                    current = (
                        value if isinstance(value, dict) else json.loads(value) if value else None
                    )
                    if int((current or {}).get("version", 0)) != expected_version:
                        connection.commit()
                        return current, "CONFLICT"
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('integration_settings','global',%s::jsonb) "
                        "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                        (self._json(settings),),
                    )
                connection.commit()
                return deepcopy(settings), "OK"
            except Exception:
                connection.rollback()
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
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('candidate-misp-action',%s,%s::jsonb) "
                        "ON CONFLICT(kind,id) DO NOTHING",
                        (action["id"], self._json(action)),
                    )
                    claimed = bool(cursor.rowcount > 0)
                connection.commit()
                return claimed
            except Exception:
                connection.rollback()
                raise

    def list_candidate_misp_actions(self, candidate_id: str | None = None) -> list[dict[str, Any]]:
        values = self._list("candidate-misp-action")
        return [
            item for item in values if candidate_id is None or item["candidate_id"] == candidate_id
        ]

    def list_candidate_workflow_records(
        self, candidate_ids: list[str]
    ) -> dict[str, list[dict[str, Any]]]:
        records: dict[str, list[dict[str, Any]]] = {
            "decisions": [],
            "actions": [],
            "lookups": [],
            "misp_actions": [],
        }
        selected = list(dict.fromkeys(candidate_ids))
        if not selected:
            return records
        kinds = {
            "candidate-decision": "decisions",
            "candidate-action": "actions",
            "candidate-ti-lookup": "lookups",
            "candidate-misp-action": "misp_actions",
        }
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT kind,data FROM controller_objects "
                "WHERE kind=ANY(%s) AND data->>'candidate_id'=ANY(%s)",
                (list(kinds), selected),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        for kind, value in rows:
            records[kinds[str(kind)]].append(
                value if isinstance(value, dict) else json.loads(value)
            )
        return records

    def update_candidate(self, candidate_id: str, updates: dict[str, Any]) -> dict[str, Any] | None:
        """Update a candidate by ID across all jobs."""
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT data FROM candidate_records WHERE candidate_id=%s FOR UPDATE",
                        (candidate_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        connection.commit()
                        return None
                    value = row[0]
                    updated = value if isinstance(value, dict) else json.loads(value)
                    updated = deepcopy(updated)
                    updates_copy = deepcopy(updates)
                    if "score_adjustment" in updates_copy:
                        adjustment = updates_copy.pop("score_adjustment")
                        updated["score"] = max(
                            0, min(100, int(updated.get("score", 0)) + int(adjustment))
                        )
                    if "exclude_reason" in updates_copy:
                        updated["excluded"] = True
                        updated["exclude_reason"] = updates_copy.pop("exclude_reason")
                    updated.update(updates_copy)
                    updated["updated_at"] = datetime.now(UTC).isoformat()
                    cursor.execute(
                        "UPDATE candidate_records SET "
                        "score=%s,severity=%s,excluded=%s,data=%s::jsonb "
                        "WHERE candidate_id=%s",
                        (
                            int(updated.get("score", 0)),
                            str(updated.get("severity", "")),
                            bool(updated.get("excluded", False)),
                            self._json(updated),
                            candidate_id,
                        ),
                    )
                connection.commit()
                return deepcopy(updated)
            except Exception:
                connection.rollback()
                raise

    def delete_candidate(self, candidate_id: str) -> bool:
        """Delete a candidate by ID across all jobs."""
        connection = self.connection
        with self._lock:
            try:
                with connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM candidate_records WHERE candidate_id=%s "
                        "RETURNING candidate_id",
                        (candidate_id,),
                    )
                    deleted = cursor.fetchone() is not None
                connection.commit()
                return deleted
            except Exception:
                connection.rollback()
                raise

    def save_flow_label(self, label: dict[str, Any]) -> dict[str, Any]:
        return self._put("flow_label", label["id"], label)

    def list_flow_labels(self, job_id: str | None = None) -> list[dict[str, Any]]:
        if job_id is None:
            labels = self._list("flow_label")
        else:
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM controller_objects "
                    "WHERE kind='flow_label' AND data->>'job_id'=%s ORDER BY id",
                    (job_id,),
                )
                rows = cursor.fetchall()
                self.connection.commit()
            labels = [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]
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

    def delete_payload_signature(self, signature_id: str) -> bool:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='payload_signature' AND id=%s",
                (signature_id,),
            )
            deleted = bool(cursor.rowcount > 0)
            if deleted:
                self._audit("payload_signature-delete", signature_id, {"id": signature_id})
                self.connection.commit()
        return deleted

    def save_allowlist(self, entry: dict[str, Any]) -> dict[str, Any]:
        return self._put("allowlist", entry["id"], entry)

    def list_allowlist(self) -> list[dict[str, Any]]:
        return self._list("allowlist")

    def delete_allowlist(self, entry_id: str) -> bool:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM controller_objects WHERE kind='allowlist' AND id=%s", (entry_id,)
            )
            deleted = cursor.rowcount > 0
            if deleted:
                self._audit("allowlist-delete", entry_id, {"id": entry_id})
            self.connection.commit()
            return bool(deleted)

    def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any] | None:
        return self.save_export_stream(export, iter((content,)), size_hint=len(content))

    def save_export_stream(
        self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
    ) -> dict[str, Any] | None:
        extension = "pcapng" if export.get("capture_format") == "PCAPNG" else "pcap"
        key = f"exports/{export['id']}/{uuid4().hex}.{extension}"
        content_type = (
            "application/x-pcapng"
            if export.get("capture_format") == "PCAPNG"
            else "application/vnd.tcpdump.pcap"
        )
        cleanup_id = self._pcap_cleanup_id(f"publication:{export['id']}", key)
        connection = self.connection

        def rollback_quietly() -> None:
            try:
                connection.rollback()
            except Exception:
                logger.warning("Failed to roll back export publication for %s", export["id"])

        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "SELECT data FROM controller_objects WHERE kind='export' AND id=%s FOR UPDATE",
                    (str(export["id"]),),
                )
                existing_row = cursor.fetchone()
                existing_value = existing_row[0] if existing_row is not None else None
                existing = (
                    existing_value
                    if isinstance(existing_value, dict)
                    else json.loads(existing_value)
                    if existing_value
                    else None
                )
                if existing is not None and existing.get("published") is not False:
                    raise ArtifactAlreadyExistsError(f"export already exists: {export['id']}")
                if existing is not None and existing.get("object_key"):
                    stale_key = str(existing["object_key"])
                    stale_cleanup_id = self._pcap_cleanup_id(
                        f"publication:{export['id']}", stale_key
                    )
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
                        "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                        (
                            stale_cleanup_id,
                            self._json(
                                {
                                    "object_key": stale_key,
                                    "created_at": datetime.now(UTC).isoformat(),
                                    "state": "READY",
                                }
                            ),
                        ),
                    )
                    cursor.execute(
                        "DELETE FROM controller_objects "
                        "WHERE kind='export' AND id=%s "
                        "AND data->>'published'='false' AND data->>'object_key'=%s",
                        (str(export["id"]), stale_key),
                    )
                cursor.execute(
                    "INSERT INTO controller_objects(kind,id,data) "
                    "VALUES('pcap_export_cleanup',%s,%s::jsonb) "
                    "ON CONFLICT(kind,id) DO UPDATE SET data=excluded.data",
                    (
                        cleanup_id,
                        self._json(
                            {
                                "object_key": key,
                                "created_at": datetime.now(UTC).isoformat(),
                                "state": "UPLOADING",
                                "export_id": str(export["id"]),
                                "attempt": int(export.get("attempt", -1)),
                                "lease_token": str(export.get("lease_token", "")),
                            }
                        ),
                    ),
                )
                connection.commit()
        except ArtifactAlreadyExistsError:
            rollback_quietly()
            raise
        except Exception as exc:
            rollback_quietly()
            raise ArtifactStorageError("PostgreSQL cleanup intent unavailable") from exc
        try:
            result = self.blob_store.put_stream(
                key, chunks, size_hint=size_hint, content_type=content_type
            )
        except Exception:
            try:
                with self._lock, connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE controller_objects "
                        "SET data=jsonb_set(data,'{state}','\"READY\"'::jsonb) "
                        "WHERE kind='pcap_export_cleanup' AND id=%s "
                        "AND data->>'object_key'=%s "
                        "AND data->>'state' IN ('UPLOADING','STAGED')",
                        (cleanup_id, key),
                    )
                    connection.commit()
            except Exception:
                rollback_quietly()
                logger.warning("Failed to ready cleanup intent after export upload failure")
            raise
        stored = {
            **export,
            "object_key": key,
            "size_bytes": result.size_bytes,
            "sha256": result.sha256,
        }
        primary: Exception | None = None
        parent_missing = False

        try:
            with self._lock, self.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT 1 FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                    (str(export["job_id"]),),
                )
                if cursor.fetchone() is None:
                    rollback_quietly()
                    parent_missing = True
                else:
                    cursor.execute(
                        "SELECT 1 FROM controller_objects WHERE kind='export' AND id=%s FOR UPDATE",
                        (str(export["id"]),),
                    )
                    if cursor.fetchone() is not None:
                        raise ArtifactAlreadyExistsError(f"export already exists: {export['id']}")
                    cursor.execute(
                        "INSERT INTO controller_objects(kind,id,data) "
                        "VALUES('export',%s,%s::jsonb)",
                        (export["id"], self._json(stored)),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                        "VALUES('export',%s,%s,%s::jsonb)",
                        (export["id"], datetime.now(UTC), self._json(stored)),
                    )
                    cursor.execute(
                        "UPDATE controller_objects "
                        "SET data=jsonb_set(data,'{state}','\"STAGED\"'::jsonb) "
                        "WHERE kind='pcap_export_cleanup' AND id=%s "
                        "AND data->>'object_key'=%s AND data->>'state'='UPLOADING'",
                        (cleanup_id, key),
                    )
                    if cursor.rowcount != 1:
                        raise ArtifactStorageError("PCAP export cleanup intent was lost")
                    connection.commit()
                    return deepcopy(stored)
        except ArtifactAlreadyExistsError as exc:
            rollback_quietly()
            primary = exc
        except Exception as exc:
            rollback_quietly()
            primary = ArtifactStorageError("PostgreSQL artifact publication failed")
            primary.__cause__ = exc

        try:
            with self._lock, connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE controller_objects "
                    "SET data=jsonb_set(data,'{state}','\"READY\"'::jsonb) "
                    "WHERE kind='pcap_export_cleanup' AND id=%s "
                    "AND data->>'object_key'=%s "
                    "AND data->>'state' IN ('UPLOADING','STAGED')",
                    (cleanup_id, key),
                )
                connection.commit()
        except Exception:
            rollback_quietly()
            logger.warning("Failed to ready cleanup intent after export publication failure")
        try:
            self.blob_store.delete(key)
        except Exception:
            logger.warning("Failed to delete orphaned export blob %s", key)
        else:
            try:
                with self._lock, connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM controller_objects "
                        "WHERE kind='pcap_export_cleanup' AND id=%s "
                        "AND data->>'object_key'=%s",
                        (cleanup_id, key),
                    )
                    connection.commit()
            except Exception:
                rollback_quietly()
                logger.warning("Failed to acknowledge orphaned export cleanup", exc_info=True)
        if primary is not None:
            raise primary
        if parent_missing:
            return None
        raise ArtifactStorageError("PostgreSQL artifact publication failed")

    def get_export_metadata(self, export_id: str) -> dict[str, Any] | None:
        try:
            metadata = self._get("export", export_id)
            return None if metadata is not None and metadata.get("published") is False else metadata
        except ArtifactStorageError:
            raise
        except Exception as exc:
            raise ArtifactStorageError("PostgreSQL export metadata lookup failed") from exc

    def open_export_stream(
        self, export_id: str
    ) -> tuple[dict[str, Any], AbstractContextManager[Iterator[bytes]]] | None:
        metadata = self.get_export_metadata(export_id)
        if metadata is None:
            return None
        return deepcopy(metadata), self.blob_store.open_stream(
            str(metadata["object_key"]), chunk_size=1024 * 1024
        )

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
        """Publish a sensor capture without retaining DB locks across object I/O."""
        connection = self.connection
        analysis_job_id = segment.get("analysis_job_id")
        source_id = str(segment["id"])
        lock_key = f"sensor-pcap:{analysis_job_id or source_id}"

        # Cheap duplicate/conflict check avoids an unnecessary upload in the common replay case.
        with self._lock, self._rollback_on_error(), connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor_pcap' AND id=%s",
                (source_id,),
            )
            row = cursor.fetchone()
            if row is not None:
                value = row[0]
                existing = value if isinstance(value, dict) else json.loads(value)
                matches = all(
                    existing.get(field) == segment.get(field)
                    for field in ("sensor_id", "analysis_job_id", "sha256")
                )
                connection.commit()
                return (deepcopy(existing), "EXISTS") if matches else (None, "CONFLICT")
            connection.commit()

        # Every accepted attempt owns a non-reused key, so compensation can never delete a winner.
        object_key = f"sensor-pcaps/{segment['sensor_id']}/{source_id}/{uuid4().hex}.pcap"
        self.blob_store.put(object_key, content)
        stored: dict[str, Any] | None = None
        status = "ERROR"
        try:
            with self._lock, self._rollback_on_error(), connection.cursor() as cursor:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s,0))",
                    (lock_key,),
                )
                locked_job: dict[str, Any] | None = None
                if analysis_job_id is not None:
                    cursor.execute(
                        "SELECT data FROM controller_objects WHERE kind='job' AND id=%s FOR UPDATE",
                        (analysis_job_id,),
                    )
                    job_row = cursor.fetchone()
                    value = job_row[0] if job_row is not None else None
                    locked_job = (
                        value if isinstance(value, dict) else json.loads(value) if value else None
                    )
                    if require_open_job and (
                        locked_job is None or locked_job.get("status") in _JOB_TERMINAL_STATUSES
                    ):
                        connection.commit()
                        status = "JOB_CLOSED"
                    else:
                        status = "CONTINUE"
                else:
                    status = "CONTINUE"
                if status == "CONTINUE":
                    cursor.execute(
                        "SELECT data FROM controller_objects "
                        "WHERE kind='sensor_pcap' AND id=%s FOR UPDATE",
                        (source_id,),
                    )
                    row = cursor.fetchone()
                    if row is not None:
                        value = row[0]
                        existing = value if isinstance(value, dict) else json.loads(value)
                        matches = all(
                            existing.get(field) == segment.get(field)
                            for field in ("sensor_id", "analysis_job_id", "sha256")
                        )
                        connection.commit()
                        stored = deepcopy(existing) if matches else None
                        status = "EXISTS" if matches else "CONFLICT"
                    else:
                        if max_total_bytes is not None and analysis_job_id is not None:
                            cursor.execute(
                                "SELECT COALESCE(SUM((data->>'size_bytes')::bigint),0) "
                                "FROM controller_objects WHERE kind='sensor_pcap' "
                                "AND data->>'analysis_job_id'=%s",
                                (analysis_job_id,),
                            )
                            used_row = cursor.fetchone()
                            used = int(used_row[0] if used_row else 0)
                            if used + len(content) > max_total_bytes:
                                connection.commit()
                                status = "LIMIT"
                        if status == "CONTINUE":
                            stored = {**segment, "object_key": object_key}
                            if eligible_live_segment(locked_job, stored):
                                stored.update(
                                    index_requested_at=datetime.now(UTC).isoformat(),
                                    index_intent_state="PENDING",
                                    index_intent_schema_version=PCAP_OFFSET_INDEX_SCHEMA_VERSION,
                                    index_intent_parser_contract_version=(
                                        PCAP_OFFSET_INDEX_PARSER_CONTRACT_VERSION
                                    ),
                                )
                            cursor.execute(
                                "INSERT INTO controller_objects(kind,id,data) "
                                "VALUES('sensor_pcap',%s,%s::jsonb)",
                                (source_id, self._json(stored)),
                            )
                            cursor.execute(
                                "INSERT INTO audit_events(kind,object_id,occurred_at,data) "
                                "VALUES('sensor_pcap',%s,%s,%s::jsonb)",
                                (source_id, datetime.now(UTC), self._json(stored)),
                            )
                            connection.commit()
                            status = "OK"
        except Exception:
            connection.rollback()
            # A commit can fail ambiguously. Retain the candidate if metadata names it;
            # otherwise it is provably unowned and safe to compensate by exact key.
            authoritative: dict[str, Any] | None = None
            try:
                authoritative = self._get("sensor_pcap", source_id)
            except Exception:
                logger.warning("Could not resolve ambiguous sensor PCAP commit", exc_info=True)
            if authoritative is None or authoritative.get("object_key") != object_key:
                try:
                    self.blob_store.delete(object_key)
                except Exception:
                    logger.warning("Failed to delete unowned sensor PCAP %s", object_key)
            raise

        if status != "OK":
            try:
                self.blob_store.delete(object_key)
            except Exception:
                logger.warning("Failed to delete race-losing sensor PCAP %s", object_key)
        return deepcopy(stored) if stored is not None else None, status

    def get_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], bytes] | None:
        opened = self.open_sensor_pcap(segment_id)
        if opened is None:
            return None
        metadata, source = opened
        with source:
            return metadata, b"".join(source.iter_chunks())

    def open_sensor_pcap(self, segment_id: str) -> tuple[dict[str, Any], CaptureSource] | None:
        metadata = self._get("sensor_pcap", segment_id)
        if metadata is None:
            return None
        try:
            source = self.blob_store.open(str(metadata["object_key"]))
        except Exception as exc:
            if _is_missing_object_error(exc):
                return None
            raise
        return deepcopy(metadata), source

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        return self._list("sensor_pcap")

    def list_sensor_pcaps_for_job(self, job_id: str) -> list[dict[str, Any]]:
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor_pcap' "
                "AND data->>'analysis_job_id'=%s ORDER BY data->>'uploaded_at',id",
                (job_id,),
            )
            rows = cursor.fetchall()
            self.connection.commit()
        return [row[0] if isinstance(row[0], dict) else json.loads(row[0]) for row in rows]

    def create_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self._put("enrollment", enrollment["enrollment_id"], enrollment)

    def get_enrollment(self, enrollment_id: str) -> dict[str, Any] | None:
        return self._get("enrollment", enrollment_id)

    def list_enrollments(self) -> list[dict[str, Any]]:
        return self._list("enrollment")

    def save_enrollment(self, enrollment: dict[str, Any]) -> dict[str, Any]:
        return self.create_enrollment(enrollment)

    def claim_enrollment(self, token_hash: str, now: datetime) -> tuple[dict[str, Any] | None, str]:
        """Claim inside one row lock/transaction so a token can succeed only once."""
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT id,data FROM controller_objects "
                "WHERE kind='enrollment' AND data->>'token_hash'=%s FOR UPDATE",
                (token_hash,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return None, "NOT_FOUND"
            value = row[1]
            enrollment = value if isinstance(value, dict) else json.loads(value)
            if enrollment.get("revoked_at") is not None:
                self.connection.commit()
                return enrollment, "REVOKED"
            if enrollment.get("claimed_at") is not None:
                self.connection.commit()
                return enrollment, "CLAIMED"
            if datetime.fromisoformat(enrollment["expires_at"]) <= now:
                self.connection.commit()
                return enrollment, "EXPIRED"
            enrollment["claimed_at"] = now.isoformat()
            cursor.execute(
                "UPDATE controller_objects SET data=%s::jsonb WHERE kind='enrollment' AND id=%s",
                (self._json(enrollment), row[0]),
            )
            self._audit("enrollment-claim", str(row[0]), {"claimed_at": now.isoformat()})
            self.connection.commit()
            return deepcopy(enrollment), "OK"

    def save_sensor_credential(self, credential: dict[str, Any]) -> dict[str, Any]:
        return self._put("sensor_credential", credential["sensor_id"], credential)

    def get_sensor_credential(self, sensor_id: str) -> dict[str, Any] | None:
        return self._get("sensor_credential", sensor_id)

    def update_sensor_configuration(
        self, sensor_id: str, expected_version: int, configuration: dict[str, Any]
    ) -> tuple[dict[str, Any] | None, str]:
        with self._lock, self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT data FROM controller_objects WHERE kind='sensor' AND id=%s FOR UPDATE",
                (sensor_id,),
            )
            row = cursor.fetchone()
            if row is None:
                self.connection.commit()
                return None, "NOT_FOUND"
            value = row[0]
            sensor = value if isinstance(value, dict) else json.loads(value)
            if sensor.get("config_version") != expected_version:
                self.connection.commit()
                return sensor, "CONFLICT"
            sensor.update(configuration)
            sensor["config_version"] = expected_version + 1
            cursor.execute(
                "UPDATE controller_objects SET data=%s::jsonb WHERE kind='sensor' AND id=%s",
                (self._json(sensor), sensor_id),
            )
            self._audit("sensor-configuration", sensor_id, configuration)
            self.connection.commit()
            return deepcopy(sensor), "OK"
