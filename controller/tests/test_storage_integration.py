from __future__ import annotations

import hashlib
import os
import struct
import sys
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import CancelledError, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from minio.error import S3Error
from psycopg.errors import ForeignKeyViolation

from c2hunter_controller.pcap_export_queue import (
    ExportPrincipalLimitError,
    ExportQueueFullError,
    ExportSourceChangedError,
)
from c2hunter_controller.pcap_offset_index import (
    IndexAvailability,
    SourceIndexBinding,
    build_live_segment_index,
    build_offline_upload_index,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    build_source_posting_index,
)
from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.queueing import RedisControllerQueue
from c2hunter_controller.storage import ClickHouseFlowStore

pytestmark = pytest.mark.skipif(
    os.getenv("C2HUNTER_RUN_STORAGE_INTEGRATION") != "1",
    reason="set C2HUNTER_RUN_STORAGE_INTEGRATION=1 with dependency URLs",
)

sys.path.insert(0, str(Path(__file__).parents[2] / "sensor" / "worker" / "src"))
from c2hunter_worker.queue import RedisQueue  # noqa: E402

_postgres_integration = pytest.mark.skipif(
    os.getenv("C2HUNTER_RUN_STORAGE_INTEGRATION") != "1" or not os.getenv("C2HUNTER_DATABASE_URL"),
    reason=(
        "set C2HUNTER_RUN_STORAGE_INTEGRATION=1 and C2HUNTER_DATABASE_URL "
        "for real PostgreSQL integration tests"
    ),
)

_postgres_minio_integration = pytest.mark.skipif(
    os.getenv("C2HUNTER_RUN_STORAGE_INTEGRATION") != "1"
    or not all(
        os.getenv(name)
        for name in (
            "C2HUNTER_DATABASE_URL",
            "C2HUNTER_S3_ENDPOINT",
            "C2HUNTER_S3_ACCESS_KEY",
            "C2HUNTER_S3_SECRET_KEY",
        )
    ),
    reason=(
        "set C2HUNTER_RUN_STORAGE_INTEGRATION=1 with PostgreSQL and MinIO "
        "connection variables for the live structural-index integration test"
    ),
)


def _release_and_drain_publication_probe(
    *,
    release: Callable[[], None],
    interrupt: Callable[[], None],
    publication: Any,
    executor: Any,
    result_timeout: float,
) -> None:
    """Release the source lock before bounded future/executor cleanup."""
    release_error: BaseException | None = None
    try:
        release()
    except BaseException as exc:
        release_error = exc

    completed = True
    if publication is not None:
        publication.cancel()
        try:
            publication.result(timeout=result_timeout)
        except CancelledError:
            pass
        except FutureTimeoutError:
            interrupt()
            try:
                publication.result(timeout=result_timeout)
            except CancelledError:
                pass
            except FutureTimeoutError:
                completed = False
            except Exception:
                pass
        except Exception:
            pass
    executor.shutdown(wait=completed, cancel_futures=True)
    if not completed:
        raise AssertionError("publication worker did not stop after connection cancellation")
    if release_error is not None:
        raise release_error


def _assert_minio_object_missing(blob: MinioBlobStore, object_key: str) -> None:
    """Require authoritative provider not-found from both read and metadata paths."""
    operations = (
        ("read", lambda: blob.get(object_key)),
        ("stat", lambda: blob.client.stat_object(blob.bucket, object_key)),
    )
    for operation_name, operation in operations:
        try:
            operation()
        except S3Error as exc:
            assert exc.code in {"NoSuchKey", "NoSuchObject", "NoSuchVersion"}, (
                f"MinIO {operation_name} failed for {object_key} with non-missing code {exc.code}"
            )
        else:
            pytest.fail(f"MinIO {operation_name} unexpectedly found deleted object {object_key}")


def _stage9_capture() -> bytes:
    payload = b"stage9-live"
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
        + struct.pack("<IIII", 1_700_000_000, 123, len(payload), len(payload))
        + payload
    )


def _pcap_export_job(
    export_id: str,
    *,
    principal: str,
    key: str,
    fingerprint: str,
) -> dict[str, Any]:
    queued_at = datetime.now(UTC).isoformat()
    return {
        "id": export_id,
        "principal_scope": principal,
        "idempotency_key": key,
        "request_fingerprint": fingerprint,
        "coalesce_fingerprint": fingerprint,
        "job_id": f"analysis-{export_id}",
        "source_job_id": f"source-{export_id}",
        "source_generation": "a" * 64,
        "status": "QUEUED",
        "attempt": 0,
        "max_attempts": 3,
        "queued_at": queued_at,
        "next_attempt_at": queued_at,
        "progress": {"phase": "QUEUED", "percent": 0},
    }


def _postgres_repositories(count: int) -> list[PostgresRepository]:
    repositories: list[PostgresRepository] = []
    try:
        for _ in range(count):
            repository = PostgresRepository(
                os.environ["C2HUNTER_DATABASE_URL"],
                cast(MinioBlobStore, SimpleNamespace(delete=lambda _key: None)),
            )
            repositories.append(repository)
            assert repository.ready()
            with repository.connection.cursor() as cursor:
                cursor.execute("SELECT set_config('statement_timeout', %s, false)", ("15s",))
                cursor.execute("SELECT set_config('lock_timeout', %s, false)", ("15s",))
            repository.connection.commit()
        return repositories
    except Exception:
        for repository in repositories:
            repository.close()
        raise


def _race_enqueue(
    repositories: list[PostgresRepository],
    jobs: list[dict[str, Any]],
    *,
    capacity: int,
    per_principal_limit: int,
) -> list[tuple[dict[str, Any], bool] | Exception]:
    barrier = threading.Barrier(len(jobs), timeout=10)

    def enqueue(
        repository: PostgresRepository, job: dict[str, Any]
    ) -> tuple[dict[str, Any], bool] | Exception:
        try:
            barrier.wait()
            return repository.enqueue_pcap_export_job(
                job, capacity=capacity, per_principal_limit=per_principal_limit
            )
        except Exception as exc:
            return exc

    with ThreadPoolExecutor(max_workers=len(jobs)) as executor:
        futures = [
            executor.submit(enqueue, repository, job)
            for repository, job in zip(repositories, jobs, strict=True)
        ]
        return [future.result(timeout=20) for future in futures]


def _delete_pcap_export_jobs(repository: PostgresRepository, export_ids: list[str]) -> None:
    try:
        with repository.connection.cursor() as cursor:
            cursor.execute("DELETE FROM pcap_export_jobs WHERE export_id=ANY(%s)", (export_ids,))
        repository.connection.commit()
    except Exception:
        repository.connection.rollback()
        raise


def _cleanup_pcap_export_case(
    repositories: list[PostgresRepository], export_ids: list[str]
) -> None:
    try:
        _delete_pcap_export_jobs(repositories[0], export_ids)
    finally:
        for repository in repositories:
            repository.close()


def test_postgres_minio_clickhouse_and_redis_durable_vertical_path() -> None:
    suffix = uuid.uuid4().hex
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", f"c2hunter-{suffix}"),
    )
    blob.put(f"probe/{suffix}", b"pcap")
    repository = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    assert repository.ready()
    repository.upsert_sensor({"sensor_id": suffix, "name": "integration"})
    assert repository.get_sensor(suffix) == {"sensor_id": suffix, "name": "integration"}

    flow_store = ClickHouseFlowStore(
        os.environ["C2HUNTER_CLICKHOUSE_URL"],
        database=os.getenv("C2HUNTER_CLICKHOUSE_DATABASE", "c2hunter"),
        username=os.getenv("C2HUNTER_CLICKHOUSE_USER", "default"),
        password=os.getenv("C2HUNTER_CLICKHOUSE_PASSWORD", ""),
    )
    record = {
        "sensor_id": suffix,
        "timestamp": "2026-07-20T00:00:00+00:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.1",
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "packet_count": 1,
        "total_bytes": 60,
    }
    assert flow_store.ingest_batch(suffix, "batch-1", [record]) == (True, 1)
    assert flow_store.ingest_batch(suffix, "batch-1", [record]) == (False, 1)
    from datetime import datetime

    snapshot = flow_store.snapshot(
        [suffix],
        datetime.fromisoformat("2026-07-20T00:00:00+00:00"),
        datetime.fromisoformat("2026-07-20T00:01:00+00:00"),
    )
    assert snapshot.records == (record,)

    jobs_key = f"c2hunter:test:{suffix}:jobs"
    results_key = f"c2hunter:test:{suffix}:results"
    controller = RedisControllerQueue(
        os.environ["C2HUNTER_REDIS_URL"], jobs_key=jobs_key, results_key=results_key
    )
    worker = RedisQueue(
        os.environ["C2HUNTER_REDIS_URL"], jobs_key=jobs_key, results_key=results_key
    )
    assert controller.ready()
    controller.enqueue({"id": suffix, "payload": {"flow_records": list(snapshot.records)}})
    claimed = worker.receive(timeout=1)
    assert claimed is not None
    worker.complete(
        claimed["receipt"],
        {"job_id": suffix, "status": "COMPLETED", "result": {"candidates": []}},
    )
    result = controller.claim_result(timeout=1)
    assert result is not None and result["job_id"] == suffix
    controller.ack_result(result["receipt"])
    assert controller.client.llen(controller.processing_key) == 0
    assert worker.client.llen(worker.processing_key) == 0
    worker.close()
    controller.client.close()


@_postgres_integration
@pytest.mark.parametrize(
    ("limit_kind", "expected_error"),
    [
        ("global", ExportQueueFullError),
        ("principal", ExportPrincipalLimitError),
    ],
)
def test_real_postgres_simultaneous_first_inserts_never_exceed_capacity(
    limit_kind: str, expected_error: type[Exception]
) -> None:
    admitted_limit = 3
    worker_count = admitted_limit + 1
    scope = f"stage8-capacity-{limit_kind}-{uuid.uuid4().hex}"
    jobs = [
        _pcap_export_job(
            f"{scope}-export-{index}",
            principal=scope if limit_kind == "principal" else f"{scope}-principal-{index}",
            key=f"{scope}-key-{index}",
            fingerprint=f"{scope}-fingerprint-{index}",
        )
        for index in range(worker_count)
    ]
    repositories = _postgres_repositories(worker_count)
    try:
        baseline = sum(repositories[0].count_pcap_export_jobs_by_status().values())
        outcomes = _race_enqueue(
            repositories,
            jobs,
            capacity=baseline + (admitted_limit if limit_kind == "global" else worker_count),
            per_principal_limit=(worker_count if limit_kind == "global" else admitted_limit),
        )

        created = [outcome for outcome in outcomes if isinstance(outcome, tuple)]
        rejected = [outcome for outcome in outcomes if isinstance(outcome, Exception)]
        assert len(created) == admitted_limit
        assert all(was_created for _stored, was_created in created)
        assert len(rejected) == 1
        assert isinstance(rejected[0], expected_error)
    finally:
        _cleanup_pcap_export_case(repositories, [job["id"] for job in jobs])


@_postgres_integration
def test_real_postgres_simultaneous_same_key_replays_one_created_winner() -> None:
    worker_count = 6
    scope = f"stage8-replay-{uuid.uuid4().hex}"
    jobs = [
        _pcap_export_job(
            f"{scope}-export-{index}",
            principal=scope,
            key=f"{scope}-key",
            fingerprint=f"{scope}-fingerprint",
        )
        for index in range(worker_count)
    ]
    repositories = _postgres_repositories(worker_count)
    try:
        baseline = sum(repositories[0].count_pcap_export_jobs_by_status().values())
        outcomes = _race_enqueue(
            repositories,
            jobs,
            capacity=baseline + 1,
            per_principal_limit=1,
        )

        assert all(isinstance(outcome, tuple) for outcome in outcomes), outcomes
        stored = [outcome for outcome in outcomes if isinstance(outcome, tuple)]
        assert sum(created for _job, created in stored) == 1
        assert len({job["id"] for job, _created in stored}) == 1
    finally:
        _cleanup_pcap_export_case(repositories, [job["id"] for job in jobs])


@_postgres_integration
def test_real_postgres_simultaneous_same_key_different_fingerprints_conflict() -> None:
    worker_count = 6
    scope = f"stage8-conflict-{uuid.uuid4().hex}"
    jobs = [
        _pcap_export_job(
            f"{scope}-export-{index}",
            principal=scope,
            key=f"{scope}-key",
            fingerprint=f"{scope}-fingerprint-{index}",
        )
        for index in range(worker_count)
    ]
    repositories = _postgres_repositories(worker_count)
    try:
        baseline = sum(repositories[0].count_pcap_export_jobs_by_status().values())
        outcomes = _race_enqueue(
            repositories,
            jobs,
            capacity=baseline + 1,
            per_principal_limit=1,
        )

        winners = [outcome for outcome in outcomes if isinstance(outcome, tuple)]
        conflicts = [outcome for outcome in outcomes if isinstance(outcome, ValueError)]
        assert len(winners) == 1 and winners[0][1] is True
        assert len(conflicts) == worker_count - 1
        assert all(str(conflict) == "idempotency_conflict" for conflict in conflicts)
        assert len(winners) + len(conflicts) == worker_count
    finally:
        _cleanup_pcap_export_case(repositories, [job["id"] for job in jobs])


@_postgres_integration
def test_real_postgres_source_delete_and_enqueue_are_atomic() -> None:
    suffix = uuid.uuid4().hex
    repositories = _postgres_repositories(2)
    parent_id = f"stage8-admission-parent-{suffix}"
    export_id = f"stage8-admission-export-{suffix}"
    try:
        repositories[0].create_job(
            {
                "id": parent_id,
                "status": "COMPLETED",
                "mode": "PCAP_UPLOAD",
                "sensor_ids": ["uploaded"],
                "source": {
                    "packet_bytes_retained": True,
                    "size_bytes": 0,
                    "sha256": "0" * 64,
                    "packet_count": 0,
                },
            }
        )
        canonical_request = {"job_id": parent_id}
        limits: dict[str, int] = {}
        snapshot = repositories[0].snapshot_pcap_export_source(parent_id, canonical_request, limits)
        assert snapshot is not None
        queued = _pcap_export_job(
            export_id,
            principal=f"stage8-admission-{suffix}",
            key=f"stage8-admission-key-{suffix}",
            fingerprint=f"stage8-admission-fingerprint-{suffix}",
        )
        queued.update(
            job_id=parent_id,
            source_job_id=snapshot["source_job_id"],
            provenance_job_ids=snapshot["provenance_job_ids"],
            source_generation=snapshot["source_generation"],
            source_manifest=snapshot["source_manifest"],
            canonical_request=canonical_request,
            effective_limits=limits,
        )
        barrier = threading.Barrier(2, timeout=10)

        def admit() -> tuple[dict[str, Any], bool] | Exception:
            try:
                baseline = sum(repositories[0].count_pcap_export_jobs_by_status().values())
                barrier.wait()
                return repositories[0].enqueue_pcap_export_job(
                    queued, capacity=baseline + 1, per_principal_limit=1
                )
            except Exception as exc:
                return exc

        def delete() -> bool:
            barrier.wait()
            return repositories[1].delete_job(parent_id)

        with ThreadPoolExecutor(max_workers=2) as executor:
            admission_future = executor.submit(admit)
            deletion_future = executor.submit(delete)
            admitted = admission_future.result(timeout=20)
            deleted = deletion_future.result(timeout=20)

        if deleted:
            assert isinstance(admitted, ExportSourceChangedError)
        else:
            assert isinstance(admitted, tuple) and admitted[1] is True
    finally:
        try:
            _delete_pcap_export_jobs(repositories[0], [export_id])
            repositories[0].delete_job(parent_id)
        finally:
            for repository in repositories:
                repository.close()


@_postgres_minio_integration
def test_real_postgres_minio_structural_index_publication_read_and_source_delete() -> None:
    suffix = uuid.uuid4().hex
    job_id = f"stage9-structural-index-{suffix}"
    capture = _stage9_capture()
    capture_sha256 = hashlib.sha256(capture).hexdigest()
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", "c2hunter"),
    )
    assert blob.ready()
    repository = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    created = False
    try:
        stored, was_created = repository.create_job(
            {
                "id": job_id,
                "idempotency_key": f"stage9-structural-index-{suffix}",
                "status": "COMPLETED",
                "mode": "PCAP_UPLOAD",
                "sensor_ids": ["uploaded"],
                "source": {
                    "packet_bytes_retained": True,
                    "size_bytes": len(capture),
                    "sha256": capture_sha256,
                    "packet_count": 1,
                    "capture_format": "PCAP",
                },
            }
        )
        assert was_created and stored["id"] == job_id
        created = True
        repository.save_job_capture(job_id, capture)
        durable_version = repository.get_capture_source_version(job_id)
        assert durable_version is not None
        assert durable_version.object_key.startswith(f"captures/{job_id}/")
        assert durable_version.object_key.endswith(".pcap")
        assert blob.get(durable_version.object_key) == capture
        assert durable_version.source_size_bytes == len(capture)
        assert durable_version.source_sha256 == capture_sha256
        binding = SourceIndexBinding(
            source_kind="PCAP_UPLOAD",
            source_id=job_id,
            source_version_id=durable_version.source_version_id,
            source_size_bytes=len(capture),
            source_sha256=capture_sha256,
            capture_format="PCAP",
        )

        assert build_offline_upload_index(
            repository,
            job_id,
            max_packets=10,
            max_interfaces=4,
            batch_size=2,
        )
        lookup = repository.get_structural_index(binding)
        assert lookup.availability is IndexAvailability.READY
        assert lookup.snapshot is not None
        assert lookup.snapshot.binding == binding
        assert len(lookup.snapshot.interfaces) == 1
        assert len(lookup.snapshot.packets) == 1

        assert repository.delete_retained_source(job_id)
        created = False
        assert repository.get_job_summary(job_id) is None
        assert repository.open_job_capture(job_id) is None
        assert repository.get_capture_source_version(job_id) is None
        assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING
    finally:
        if created:
            repository.delete_retained_source(job_id)
        repository.close()


@_postgres_minio_integration
def test_real_postgres_minio_live_segment_index_lease_recovery_publication_and_job_delete() -> None:
    suffix = uuid.uuid4().hex
    sensor_id = f"stage10-live-sensor-{suffix}"
    job_id = f"stage10-live-job-{suffix}"
    segment_id = f"stage10-live-segment-{suffix}"
    capture = _stage9_capture()
    capture_sha256 = hashlib.sha256(capture).hexdigest()
    object_key: str | None = None
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", "c2hunter"),
    )
    assert blob.ready()
    repository = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    created = False
    try:
        repository.upsert_sensor({"sensor_id": sensor_id, "name": "stage10-live"})
        stored_job, was_created = repository.create_job(
            {
                "id": job_id,
                "idempotency_key": f"stage10-live-{suffix}",
                "status": "CAPTURING",
                "mode": "LIVE",
                "sensor_ids": [sensor_id],
                "capture": {"store_pcap": True},
            }
        )
        assert was_created and stored_job["id"] == job_id
        created = True
        marker = datetime.now(UTC).isoformat()
        stored, status = repository.save_sensor_pcap_limited(
            {
                "id": segment_id,
                "sensor_id": sensor_id,
                "analysis_job_id": job_id,
                "filename": f"{segment_id}.pcap",
                "size_bytes": len(capture),
                "sha256": capture_sha256,
                "uploaded_at": marker,
                "index_requested_at": marker,
            },
            capture,
            None,
            require_open_job=True,
        )
        assert status == "OK" and stored is not None
        object_key = str(stored["object_key"])
        assert object_key.startswith(f"sensor-pcaps/{sensor_id}/{segment_id}/")
        assert object_key.endswith(".pcap")
        assert object_key != f"sensor-pcaps/{sensor_id}/{segment_id}.pcap"
        assert stored["index_intent_state"] == "PENDING"
        assert blob.get(object_key) == capture

        admission = repository.admit_live_segment_index(segment_id, capacity=1, max_attempts=3)
        assert admission.value == "QUEUED"
        first_now = datetime.now(UTC) + timedelta(seconds=1)
        abandoned = repository.claim_live_segment_index(now=first_now, lease_seconds=1)
        assert abandoned is not None and abandoned.attempt == 1 and abandoned.lease_token
        assert repository.recover_live_segment_indexes(now=first_now + timedelta(seconds=2)) == 1
        claimed = repository.claim_live_segment_index(
            now=first_now + timedelta(seconds=2), lease_seconds=120
        )
        assert claimed is not None and claimed.attempt == 2 and claimed.lease_token
        assert claimed.lease_token != abandoned.lease_token

        assert build_live_segment_index(
            repository,
            segment_id,
            max_packets=10,
            max_interfaces=4,
            batch_size=2,
            attempt=claimed.attempt,
            lease_token=claimed.lease_token,
        )
        version = repository.get_live_capture_source_version(segment_id)
        assert version is not None
        assert version.object_key == object_key
        assert version.source_size_bytes == len(capture)
        assert version.source_sha256 == capture_sha256
        binding = SourceIndexBinding(
            "LIVE_SEGMENT",
            segment_id,
            version.source_version_id,
            len(capture),
            capture_sha256,
            "PCAP",
        )
        lookup = repository.get_structural_index(binding)
        assert lookup.availability is IndexAvailability.READY
        assert lookup.snapshot is not None and lookup.snapshot.binding == binding
        assert len(lookup.snapshot.interfaces) == 1
        assert len(lookup.snapshot.packets) == 1
        task = repository.get_live_segment_index_task(segment_id)
        assert task is not None and task.status == "COMPLETED" and task.attempt == 2
        with repository.connection.cursor() as cursor:
            cursor.execute(
                "SELECT o.build_id,g.state,g.source_kind,g.source_id "
                "FROM pcap_offset_index_owners o JOIN pcap_offset_index_generations g "
                "ON g.build_id=o.build_id WHERE o.source_kind='LIVE_SEGMENT' AND o.source_id=%s",
                (segment_id,),
            )
            owner = cursor.fetchone()
        repository.connection.commit()
        assert owner is not None and owner[1:] == ("READY", "LIVE_SEGMENT", segment_id)

        assert repository.delete_job(job_id)
        created = False
        assert repository.get_job_summary(job_id) is None
        assert repository.get_sensor_pcap(segment_id) is None
        assert repository.get_live_segment_index_task(segment_id) is None
        assert repository.get_live_capture_source_version(segment_id) is None
        assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING
        with repository.connection.cursor() as cursor:
            cursor.execute(
                "SELECT "
                "(SELECT COUNT(*) FROM pcap_offset_index_jobs "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s),"
                "(SELECT COUNT(*) FROM pcap_capture_source_versions "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s),"
                "(SELECT COUNT(*) FROM pcap_offset_index_owners "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s),"
                "(SELECT COUNT(*) FROM pcap_offset_index_generations "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id=%s)",
                (segment_id, segment_id, segment_id, segment_id),
            )
            assert cursor.fetchone() == (0, 0, 0, 0)
        repository.connection.commit()
        with pytest.raises(S3Error):
            blob.get(object_key)
    finally:
        if created:
            repository.delete_job(job_id)
        repository.close()


@_postgres_minio_integration
def test_real_stage11_postgres_minio_posting_lifecycle_is_fenced_and_cascading() -> None:
    """Opt-in only: migration twice, upload/LIVE posting, reclaim, readback, and cascade."""
    suffix = uuid.uuid4().hex
    upload_id = f"stage11-upload-{suffix}"
    live_job_id = f"stage11-live-job-{suffix}"
    sensor_id = f"stage11-live-sensor-{suffix}"
    segment_id = f"stage11-live-segment-{suffix}"
    capture = _stage9_capture()
    digest = hashlib.sha256(capture).hexdigest()
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", "c2hunter"),
    )
    assert blob.ready()
    # Each facade runs the additive schema migration, proving a second application is safe.
    first = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    second = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    created_upload = False
    created_live = False
    build_ids: list[str] = []
    object_keys: list[str] = []

    def build_posting(
        repository: PostgresRepository, source: Any, parent: Any, stream: Any, name: str
    ):
        with stream:
            return build_source_posting_index(
                stream,
                source_version=source,
                parent=parent,
                internal_networks=["10.0.0.0/8"],
                build_id=name,
            )

    def publish_posting(
        repository: PostgresRepository, source: Any, parent: Any, posting: Any
    ) -> Any:
        assert repository.request_posting_index(source, parent) is not None
        assert repository.admit_posting_index(
            source.source_kind, source.source_id, capacity=8, max_attempts=3
        ).value in {"QUEUED", "COALESCED"}
        claim = repository.claim_posting_index(lease_seconds=120)
        assert claim is not None and claim.lease_token
        repository.begin_posting_index(
            posting, attempt=claim.attempt, lease_token=claim.lease_token
        )
        repository.stage_posting_index_chunks(
            posting.build_id,
            posting.generation.chunks,
            source_kind=source.source_kind,
            source_id=source.source_id,
            attempt=claim.attempt,
            lease_token=claim.lease_token,
        )
        assert repository.publish_posting_index(
            posting.build_id,
            source_version=source,
            parent=parent,
            attempt=claim.attempt,
            lease_token=claim.lease_token,
        )
        return claim

    try:
        with first.connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM pg_constraint WHERE conrelid="
                "'pcap_posting_index_jobs'::regclass AND "
                "conname='pcap_posting_index_jobs_intent_parent_fkey'"
            )
            assert cursor.fetchone() == (1,)
        first.connection.commit()

        stored, was_created = first.create_job(
            {
                "id": upload_id,
                "idempotency_key": f"stage11-upload-{suffix}",
                "status": "COMPLETED",
                "mode": "PCAP_UPLOAD",
                "sensor_ids": ["uploaded"],
                "source": {
                    "packet_bytes_retained": True,
                    "size_bytes": len(capture),
                    "sha256": digest,
                    "packet_count": 1,
                    "capture_format": "PCAP",
                },
            }
        )
        assert was_created and stored["id"] == upload_id
        created_upload = True
        first.save_job_capture(upload_id, capture)
        assert build_offline_upload_index(
            first, upload_id, max_packets=10, max_interfaces=4, batch_size=2
        )
        upload_source = first.get_capture_source_version(upload_id)
        assert upload_source is not None
        upload_object_key = upload_source.object_key
        assert upload_object_key.startswith(f"captures/{upload_id}/")
        assert upload_object_key.endswith(".pcap")
        assert blob.get(upload_object_key) == capture
        object_keys.append(upload_object_key)
        upload_binding = SourceIndexBinding(
            upload_source.source_kind,
            upload_source.source_id,
            upload_source.source_version_id,
            upload_source.source_size_bytes,
            upload_source.source_sha256,
            "PCAP",
        )
        upload_parent_lookup = first.get_structural_index(upload_binding)
        assert upload_parent_lookup.snapshot is not None
        upload_parent = upload_parent_lookup.snapshot
        upload_stream = first.open_job_capture(upload_id)
        assert upload_stream is not None
        upload_posting = build_posting(
            first, upload_source, upload_parent, upload_stream, f"stage11-upload-posting-{suffix}"
        )
        build_ids.append(upload_posting.build_id)

        # Abandon attempt one, recover through the second facade, and publish attempt two.
        assert first.request_posting_index(upload_source, upload_parent) is not None
        with first.connection.cursor() as cursor:
            cursor.execute("SAVEPOINT stage11_composite_fk_mismatch")
            with pytest.raises(ForeignKeyViolation) as rejected:
                now = datetime.now(UTC)
                cursor.execute(
                    "INSERT INTO pcap_posting_index_jobs("
                    "source_kind,source_id,parent_structural_build_id,status,attempt,max_attempts,"
                    "next_attempt_at,queued_at,updated_at) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    (
                        upload_source.source_kind,
                        upload_source.source_id,
                        f"{upload_parent.build_id}-mismatch",
                        "QUEUED",
                        0,
                        3,
                        now,
                        now,
                        now,
                    ),
                )
            assert rejected.value.sqlstate == "23503"
            cursor.execute("ROLLBACK TO SAVEPOINT stage11_composite_fk_mismatch")
            cursor.execute("RELEASE SAVEPOINT stage11_composite_fk_mismatch")
        first.connection.commit()
        assert (
            first.admit_posting_index(
                upload_source.source_kind, upload_source.source_id, capacity=8, max_attempts=3
            ).value
            == "QUEUED"
        )
        abandoned = first.claim_posting_index(lease_seconds=120)
        assert abandoned is not None and abandoned.lease_token
        with first.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE pcap_posting_index_jobs SET lease_expires_at=clock_timestamp()-"
                "make_interval(secs=>1) WHERE source_kind=%s AND source_id=%s",
                (upload_source.source_kind, upload_source.source_id),
            )
        first.connection.commit()
        assert second.recover_posting_indexes() == 1
        winner = second.claim_posting_index(lease_seconds=120)
        assert winner is not None and winner.attempt == 2 and winner.lease_token
        winner_lease_token = winner.lease_token
        assert winner_lease_token is not None
        assert winner_lease_token != abandoned.lease_token
        second.begin_posting_index(
            upload_posting, attempt=winner.attempt, lease_token=winner_lease_token
        )
        second.stage_posting_index_chunks(
            upload_posting.build_id,
            upload_posting.generation.chunks,
            source_kind=upload_source.source_kind,
            source_id=upload_source.source_id,
            attempt=winner.attempt,
            lease_token=winner_lease_token,
        )
        assert second.publish_posting_index(
            upload_posting.build_id,
            source_version=upload_source,
            parent=upload_parent,
            attempt=winner.attempt,
            lease_token=winner_lease_token,
        )
        upload_lookup = first.get_posting_index(upload_source, upload_parent)
        assert upload_lookup.availability is PostingIndexAvailability.READY
        assert upload_lookup.snapshot is not None

        first.upsert_sensor({"sensor_id": sensor_id, "name": "stage11-live"})
        live_job, was_created = first.create_job(
            {
                "id": live_job_id,
                "idempotency_key": f"stage11-live-{suffix}",
                "status": "CAPTURING",
                "mode": "LIVE",
                "sensor_ids": [sensor_id],
                "capture": {"store_pcap": True},
            }
        )
        assert was_created
        created_live = True
        marker = datetime.now(UTC).isoformat()
        live_segment, status = first.save_sensor_pcap_limited(
            {
                "id": segment_id,
                "sensor_id": sensor_id,
                "analysis_job_id": live_job_id,
                "filename": f"{segment_id}.pcap",
                "size_bytes": len(capture),
                "sha256": digest,
                "uploaded_at": marker,
                "index_requested_at": marker,
            },
            capture,
            None,
            require_open_job=True,
        )
        assert status == "OK" and live_segment is not None
        live_object_key = str(live_segment["object_key"])
        assert live_object_key.startswith(f"sensor-pcaps/{sensor_id}/{segment_id}/")
        assert live_object_key.endswith(".pcap")
        assert blob.get(live_object_key) == capture
        object_keys.append(live_object_key)
        assert (
            first.admit_live_segment_index(segment_id, capacity=8, max_attempts=3).value == "QUEUED"
        )
        structural_claim = first.claim_live_segment_index(now=datetime.now(UTC), lease_seconds=120)
        assert structural_claim is not None and structural_claim.lease_token
        assert build_live_segment_index(
            first,
            segment_id,
            max_packets=10,
            max_interfaces=4,
            batch_size=2,
            attempt=structural_claim.attempt,
            lease_token=structural_claim.lease_token,
        )
        live_source = first.get_live_capture_source_version(segment_id)
        assert live_source is not None
        assert live_source.object_key == live_object_key
        live_binding = SourceIndexBinding(
            live_source.source_kind,
            live_source.source_id,
            live_source.source_version_id,
            live_source.source_size_bytes,
            live_source.source_sha256,
            "PCAP",
        )
        live_parent_lookup = first.get_structural_index(live_binding)
        assert live_parent_lookup.snapshot is not None
        live_parent = live_parent_lookup.snapshot
        first.save_job_metadata({**live_job, "status": "COMPLETED"})
        live_opened = first.open_sensor_pcap(segment_id)
        assert live_opened is not None
        _version, live_stream = live_opened
        live_posting = build_posting(
            first, live_source, live_parent, live_stream, f"stage11-live-posting-{suffix}"
        )
        build_ids.append(live_posting.build_id)
        publish_posting(first, live_source, live_parent, live_posting)
        live_lookup = second.get_posting_index(live_source, live_parent)
        assert live_lookup.availability is PostingIndexAvailability.READY
        assert live_lookup.snapshot is not None

        failed_deletes = set(object_keys)

        def fail_first_delete(object_key: str) -> None:
            if object_key in failed_deletes:
                failed_deletes.remove(object_key)
                raise RuntimeError(f"forced first cleanup attempt for {object_key}")
            blob.delete(object_key)

        cleanup_blob = cast(MinioBlobStore, SimpleNamespace(delete=fail_first_delete))
        first.blob_store = cleanup_blob
        second.blob_store = cleanup_blob

        with second.connection.cursor() as cursor:
            cursor.execute("SET LOCAL lock_timeout TO '5s'")
            cursor.execute("SET LOCAL statement_timeout TO '10s'")
            cursor.execute("SELECT pg_backend_pid()")
            second_backend_pid = int(cursor.fetchone()[0])
        publication_started = threading.Event()

        def publish_while_deleting() -> bool:
            publication_started.set()
            return second.publish_posting_index(
                upload_posting.build_id,
                source_version=upload_source,
                parent=upload_parent,
                attempt=winner.attempt,
                lease_token=winner_lease_token,
            )

        executor = ThreadPoolExecutor(max_workers=1)
        publication = None
        source_lock_acquired = False
        try:
            with first.connection.cursor() as cursor:
                cursor.execute(
                    "SELECT source_id FROM pcap_capture_source_versions "
                    "WHERE source_kind=%s AND source_id=%s FOR UPDATE",
                    (upload_source.source_kind, upload_source.source_id),
                )
                assert cursor.fetchone() == (upload_id,)
            source_lock_acquired = True
            assert source_lock_acquired
            publication = executor.submit(publish_while_deleting)
            assert publication_started.wait(timeout=5)
            deadline = time.monotonic() + 5
            blocked_on_lock = False
            while time.monotonic() < deadline:
                with first.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s",
                        (second_backend_pid,),
                    )
                    activity = cursor.fetchone()
                if activity == ("Lock",):
                    blocked_on_lock = True
                    break
                time.sleep(0.02)
            assert blocked_on_lock, "publication never blocked behind the canonical source lock"
            assert first.delete_retained_source(upload_id)
            created_upload = False
            assert publication.result(timeout=10) is False
        finally:
            _release_and_drain_publication_probe(
                release=first.connection.rollback,
                interrupt=second.connection.cancel,
                publication=publication,
                executor=executor,
                result_timeout=12,
            )

        assert second.delete_job(live_job_id)
        created_live = False
        with first.connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM controller_objects WHERE kind='pcap_export_cleanup' "
                "AND data->>'object_key'=ANY(%s)",
                (object_keys,),
            )
            assert cursor.fetchone() == (2,)
        first.connection.commit()

        acknowledged = first.cleanup_pcap_export_orphans(
            now=datetime.now(UTC), max_age_seconds=0, limit=100
        )
        assert set(object_keys).issubset(acknowledged)
        source_predicate = (
            "((source_kind=%s AND source_id=%s) OR (source_kind=%s AND source_id=%s))"
        )
        source_params = (
            upload_source.source_kind,
            upload_source.source_id,
            live_source.source_kind,
            live_source.source_id,
        )
        with first.connection.cursor() as cursor:
            cursor.execute(
                "SELECT "
                f"(SELECT COUNT(*) FROM pcap_posting_index_intents WHERE {source_predicate}),"
                f"(SELECT COUNT(*) FROM pcap_posting_index_jobs WHERE {source_predicate}),"
                f"(SELECT COUNT(*) FROM pcap_posting_index_generations WHERE {source_predicate}),"
                f"(SELECT COUNT(*) FROM pcap_posting_index_owners WHERE {source_predicate}),"
                "(SELECT COUNT(*) FROM pcap_posting_index_chunks WHERE build_id=ANY(%s)),"
                f"(SELECT COUNT(*) FROM pcap_capture_source_versions WHERE {source_predicate}),"
                "(SELECT COUNT(*) FROM controller_objects WHERE "
                "(kind='job' AND id=ANY(%s)) OR (kind='sensor_pcap' AND id=%s)),"
                "(SELECT COUNT(*) FROM controller_objects WHERE kind='pcap_export_cleanup' "
                "AND data->>'object_key'=ANY(%s))",
                (
                    *source_params,
                    *source_params,
                    *source_params,
                    *source_params,
                    build_ids,
                    *source_params,
                    [upload_id, live_job_id],
                    segment_id,
                    object_keys,
                ),
            )
            assert cursor.fetchone() == (0, 0, 0, 0, 0, 0, 0, 0)
        first.connection.commit()
        assert failed_deletes == set()
        for object_key in object_keys:
            _assert_minio_object_missing(blob, object_key)
    finally:
        if created_upload:
            first.delete_retained_source(upload_id)
        if created_live:
            first.delete_job(live_job_id)
        second.close()
        first.close()
