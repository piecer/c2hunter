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

from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_export_queue import (
    ExportPrincipalLimitError,
    ExportQueueFullError,
    ExportSourceChangedError,
)
from c2hunter_controller.pcap_export_service import (
    PcapExportDependencies,
    PcapExportExecutor,
)
from c2hunter_controller.pcap_indexed_export import (
    CaptureByteRange,
    CaptureRangeMissing,
    CaptureRangeShortRead,
    CaptureRangeUnavailable,
    CaptureRangeVersionDrift,
    create_indexed_match_factory_from_settings,
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
from c2hunter_controller.schemas import PcapExportCreate
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


def _stage12_capture(*, port_base: int = 40_000, packet_count: int = 6) -> bytes:
    """Build parseable deterministic Ethernet/IPv4/UDP packets for sparse reads."""
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1))
    for index in range(packet_count):
        payload = bytes([index + 1]) * (24 + index)
        udp = struct.pack("!HHHH", port_base + index, 443, 8 + len(payload), 0) + payload
        source = bytes((10, 0, 0, index + 1))
        destination = bytes((203, 0, 113, 77))
        ip = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), index, 0, 64, 17, 0, source, destination
        )
        packet = bytes.fromhex("0200000000020200000000010800") + ip + udp
        capture.extend(struct.pack("<IIII", 1_700_000_000 + index, index, len(packet), len(packet)))
        capture.extend(packet)
    return bytes(capture)


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


@_postgres_minio_integration
def test_real_stage12_postgres_minio_immutable_upload_and_live_exact_ranges() -> None:
    """Opt-in only: exact immutable range identity and typed failure distinctions."""
    suffix = uuid.uuid4().hex
    upload_id = f"stage12-range-upload-{suffix}"
    sensor_id = f"stage12-range-sensor-{suffix}"
    live_job_id = f"stage12-range-live-job-{suffix}"
    segment_id = f"stage12-range-segment-{suffix}"
    capture = _stage9_capture()
    digest = hashlib.sha256(capture).hexdigest()
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", "c2hunter"),
    )
    assert blob.ready()
    repository = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    upload_created = False
    live_created = False
    try:
        _stored, upload_created = repository.create_job(
            {
                "id": upload_id,
                "idempotency_key": upload_id,
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
        assert upload_created
        repository.save_job_capture(upload_id, capture)
        upload = repository.get_capture_source_version(upload_id)
        assert upload is not None
        assert upload.object_key.startswith(f"captures/{upload_id}/")
        assert upload.object_key.endswith(".pcap")
        assert upload.object_key != f"captures/{upload_id}.pcap"

        repository.upsert_sensor({"sensor_id": sensor_id, "name": "stage12-range"})
        _stored, live_created = repository.create_job(
            {
                "id": live_job_id,
                "idempotency_key": live_job_id,
                "status": "CAPTURING",
                "mode": "LIVE",
                "sensor_ids": [sensor_id],
                "capture": {"store_pcap": True},
            }
        )
        assert live_created
        segment, status = repository.save_sensor_pcap_limited(
            {
                "id": segment_id,
                "sensor_id": sensor_id,
                "analysis_job_id": live_job_id,
                "filename": f"{segment_id}.pcap",
                "size_bytes": len(capture),
                "sha256": digest,
                "uploaded_at": datetime.now(UTC).isoformat(),
            },
            capture,
            None,
            require_open_job=True,
        )
        assert status == "OK" and segment is not None
        live = repository.get_live_capture_source_version(segment_id)
        assert live is not None
        assert live.object_key.startswith(f"sensor-pcaps/{sensor_id}/{segment_id}/")
        assert live.object_key.endswith(".pcap")
        assert live.object_key != f"sensor-pcaps/{sensor_id}/{segment_id}.pcap"

        for source in (upload, live):
            assert repository.read_capture_range(source, CaptureByteRange(0, 2)) == capture[:2]
            middle = len(capture) // 2
            assert (
                repository.read_capture_range(source, CaptureByteRange(middle, 3))
                == capture[middle : middle + 3]
            )
            assert (
                repository.read_capture_range(source, CaptureByteRange(len(capture) - 1, 1))
                == capture[-1:]
            )

        # Same immutable bytes still publish under a fresh generation key/version.
        repository.save_job_capture(upload_id, capture)
        replacement = repository.get_capture_source_version(upload_id)
        assert replacement is not None
        assert replacement.object_key != upload.object_key
        with pytest.raises(CaptureRangeVersionDrift):
            repository.read_capture_range(upload, CaptureByteRange(0, 1))

        real_blob = repository.blob_store
        repository.blob_store = cast(
            MinioBlobStore,
            SimpleNamespace(read_range=lambda *_args, **_kwargs: b""),
        )
        with pytest.raises(CaptureRangeShortRead):
            repository.read_capture_range(replacement, CaptureByteRange(0, 1))

        def unavailable(*_args: Any, **_kwargs: Any) -> bytes:
            raise CaptureRangeUnavailable("injected provider outage")

        repository.blob_store = cast(MinioBlobStore, SimpleNamespace(read_range=unavailable))
        with pytest.raises(CaptureRangeUnavailable, match="injected provider outage"):
            repository.read_capture_range(replacement, CaptureByteRange(0, 1))
        repository.blob_store = real_blob

        blob.delete(live.object_key)
        with pytest.raises(CaptureRangeMissing):
            repository.read_capture_range(live, CaptureByteRange(0, 1))
        assert repository.delete_job(live_job_id)
        live_created = False
        with pytest.raises(CaptureRangeMissing):
            repository.read_capture_range(live, CaptureByteRange(0, 1))
    finally:
        repository.blob_store = blob
        if upload_created:
            repository.delete_retained_source(upload_id)
        if live_created:
            repository.delete_job(live_job_id)
        repository.close()


@_postgres_minio_integration
def test_real_stage12_postgres_minio_active_factory_executor_parity_and_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Opt-in only: production active sparse path and bounded all-source fallbacks."""
    suffix = uuid.uuid4().hex
    upload_id = f"stage12-active-upload-{suffix}"
    live_job_id = f"stage12-active-live-{suffix}"
    sensors = (f"stage12-sensor-a-{suffix}", f"stage12-sensor-b-{suffix}")
    segments = (f"stage12-segment-a-{suffix}", f"stage12-segment-b-{suffix}")
    upload_capture = _stage12_capture(port_base=41_000)
    captures = (_stage12_capture(), _stage12_capture())
    blob = MinioBlobStore(
        os.environ["C2HUNTER_S3_ENDPOINT"],
        os.environ["C2HUNTER_S3_ACCESS_KEY"],
        os.environ["C2HUNTER_S3_SECRET_KEY"],
        os.getenv("C2HUNTER_S3_BUCKET", "c2hunter"),
    )
    assert blob.ready()
    repository = PostgresRepository(os.environ["C2HUNTER_DATABASE_URL"], blob)
    upload_created = live_created = False
    source_keys: set[str] = set()
    export_ids: list[str] = []

    def publish_next() -> None:
        claim = repository.claim_posting_index(lease_seconds=120)
        assert claim is not None and claim.lease_token
        source = (
            repository.get_capture_source_version(claim.source_id)
            if claim.source_kind == "PCAP_UPLOAD"
            else repository.get_live_capture_source_version(claim.source_id)
        )
        assert source is not None
        binding = SourceIndexBinding(
            source.source_kind,
            source.source_id,
            source.source_version_id,
            source.source_size_bytes,
            source.source_sha256,
            "PCAP",
        )
        lookup = repository.get_structural_index(binding)
        assert lookup.availability is IndexAvailability.READY and lookup.snapshot is not None
        opened = (
            repository.open_job_capture(source.source_id)
            if source.source_kind == "PCAP_UPLOAD"
            else repository.open_sensor_pcap(source.source_id)
        )
        assert opened is not None
        stream = opened if source.source_kind == "PCAP_UPLOAD" else opened[1]
        with stream:
            posting = build_source_posting_index(
                stream,
                source_version=source,
                parent=lookup.snapshot,
                internal_networks=["10.0.0.0/8"],
                build_id=f"stage12-posting-{source.source_id}-{suffix}",
            )
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
            parent=lookup.snapshot,
            attempt=claim.attempt,
            lease_token=claim.lease_token,
        )
        assert (
            repository.get_posting_index(source, lookup.snapshot).availability
            is PostingIndexAvailability.READY
        )

    base_settings = Settings(
        environment="test",
        pcap_export_pipeline="streaming",
        pcap_export_max_bytes=1 << 20,
        pcap_export_scan_max_bytes=1 << 20,
        pcap_export_scan_max_packets=1_000,
    )

    def active_settings(max_gap: int = 1) -> Settings:
        return Settings(
            **{
                **base_settings.model_dump(),
                "pcap_posting_index_enabled": True,
                "pcap_indexed_export_mode": "active",
                "pcap_indexed_export_max_gap_bytes": max_gap,
                "pcap_indexed_export_max_source_fraction_numerator": 9,
                "pcap_indexed_export_max_source_fraction_denominator": 10,
            }
        )

    def execute(
        payload: PcapExportCreate,
        snapshot: dict[str, Any],
        export_id: str,
        *,
        active: bool,
        gap: int = 1,
    ) -> tuple[dict[str, Any], bytes]:
        settings = active_settings(gap) if active else base_settings
        dependencies = PcapExportDependencies(
            indexed_match_factory=create_indexed_match_factory_from_settings(repository, settings)
            if active
            else None
        )
        export_ids.append(export_id)
        result = PcapExportExecutor(repository, settings, dependencies).execute(
            payload, {}, export_id=export_id, source_snapshot=snapshot
        )
        stored = repository.get_export(export_id)
        assert stored is not None
        metadata, content = stored
        assert metadata["sha256"] == hashlib.sha256(content).hexdigest()
        assert metadata["size_bytes"] == len(content)
        assert result["sha256"] == metadata["sha256"]
        return result, content

    try:
        _stored, upload_created = repository.create_job(
            {
                "id": upload_id,
                "idempotency_key": upload_id,
                "status": "COMPLETED",
                "mode": "PCAP_UPLOAD",
                "sensor_ids": ["uploaded"],
                "internal_networks": ["10.0.0.0/8"],
                "source": {
                    "packet_bytes_retained": True,
                    "size_bytes": len(upload_capture),
                    "sha256": hashlib.sha256(upload_capture).hexdigest(),
                    "packet_count": 6,
                    "capture_format": "PCAP",
                },
            }
        )
        assert upload_created
        repository.save_job_capture(upload_id, upload_capture)
        upload_source = repository.get_capture_source_version(upload_id)
        assert upload_source is not None
        source_keys.add(upload_source.object_key)
        assert build_offline_upload_index(
            repository,
            upload_id,
            max_packets=100,
            max_interfaces=4,
            batch_size=8,
            request_postings=True,
            posting_queue_capacity=8,
            posting_max_attempts=3,
        )

        for sensor in sensors:
            repository.upsert_sensor({"sensor_id": sensor, "name": sensor})
        live_job, live_created = repository.create_job(
            {
                "id": live_job_id,
                "idempotency_key": live_job_id,
                "status": "CAPTURING",
                "mode": "LIVE",
                "sensor_ids": list(sensors),
                "internal_networks": ["10.0.0.0/8"],
                "capture": {"store_pcap": True},
            }
        )
        assert live_created
        for order, (segment_id, sensor, capture) in enumerate(
            zip(segments, sensors, captures, strict=True)
        ):
            marker = (datetime.now(UTC) + timedelta(microseconds=order)).isoformat()
            stored, status = repository.save_sensor_pcap_limited(
                {
                    "id": segment_id,
                    "sensor_id": sensor,
                    "analysis_job_id": live_job_id,
                    "filename": f"{segment_id}.pcap",
                    "size_bytes": len(capture),
                    "sha256": hashlib.sha256(capture).hexdigest(),
                    "uploaded_at": marker,
                    "index_requested_at": marker,
                },
                capture,
                None,
                require_open_job=True,
            )
            assert status == "OK" and stored is not None
            source_keys.add(str(stored["object_key"]))
            assert (
                repository.admit_live_segment_index(segment_id, capacity=8, max_attempts=3).value
                == "QUEUED"
            )
            claim = repository.claim_live_segment_index(now=datetime.now(UTC), lease_seconds=120)
            assert claim is not None and claim.lease_token
            assert build_live_segment_index(
                repository,
                segment_id,
                max_packets=100,
                max_interfaces=4,
                batch_size=8,
                attempt=claim.attempt,
                lease_token=claim.lease_token,
                request_postings=True,
                posting_queue_capacity=8,
                posting_max_attempts=3,
            )
        repository.save_job_metadata({**live_job, "status": "COMPLETED"})
        for _ in range(3):
            publish_next()

        for name, filters, gap in (
            ("sparse", [{"source_port": 40_000}, {"source_port": 40_005}], 1),
            ("coalesced", [{"source_port": 40_000}, {"source_port": 40_001}], 1 << 16),
        ):
            payload = PcapExportCreate(job_id=live_job_id, include_filters=filters)
            snapshot = repository.snapshot_pcap_export_source(
                live_job_id, payload.model_dump(mode="json", exclude_none=True), {}
            )
            assert snapshot is not None and len(snapshot["source_manifest"]) == 2
            sequential, sequential_bytes = execute(
                payload, snapshot, f"stage12-{name}-sequential-{suffix}", active=False
            )
            forbidden = (
                "open_job_capture",
                "open_sensor_pcap",
                "get_job_capture",
                "get_sensor_pcap",
            )
            originals = {item: getattr(repository, item) for item in forbidden}
            original_get, original_open = blob.get, blob.open
            original_range = repository.read_capture_range
            ranges: list[tuple[str, int, int]] = []

            def reject_full(*_args: Any, **_kwargs: Any) -> Any:
                raise AssertionError("successful indexed path performed a full source read")

            def bounded(
                source: Any,
                byte_range: CaptureByteRange,
                _ranges: list[tuple[str, int, int]] = ranges,
                _read: Callable[[Any, CaptureByteRange], bytes] = original_range,
            ) -> bytes:
                assert byte_range.offset >= 0 and 0 < byte_range.length < source.source_size_bytes
                _ranges.append((source.source_id, byte_range.offset, byte_range.length))
                return _read(source, byte_range)

            for item in forbidden:
                monkeypatch.setattr(repository, item, reject_full)
            monkeypatch.setattr(blob, "get", reject_full)
            monkeypatch.setattr(blob, "open", reject_full)
            monkeypatch.setattr(repository, "read_capture_range", bounded)
            settings = active_settings(gap)
            indexed_export_id = f"stage12-{name}-indexed-{suffix}"
            export_ids.append(indexed_export_id)
            indexed = PcapExportExecutor(
                repository,
                settings,
                PcapExportDependencies(
                    indexed_match_factory=create_indexed_match_factory_from_settings(
                        repository, settings
                    )
                ),
            ).execute(payload, {}, export_id=indexed_export_id, source_snapshot=snapshot)
            for item, original in originals.items():
                monkeypatch.setattr(repository, item, original)
            monkeypatch.setattr(blob, "get", original_get)
            monkeypatch.setattr(blob, "open", original_open)
            monkeypatch.setattr(repository, "read_capture_range", original_range)
            stored_indexed = repository.get_export(indexed_export_id)
            assert stored_indexed is not None
            metadata, indexed_bytes = stored_indexed
            assert ranges and {item[0] for item in ranges} == set(segments)
            assert indexed_bytes == sequential_bytes
            assert metadata["sha256"] == hashlib.sha256(sequential_bytes).hexdigest()
            for field in (
                "matched_packet_count",
                "exported_packet_count",
                "source_manifest",
                "source_capture_count",
            ):
                assert indexed[field] == sequential[field]

        payload = PcapExportCreate(job_id=live_job_id, include_filters=[{"source_port": 40_000}])
        snapshot = repository.snapshot_pcap_export_source(
            live_job_id, payload.model_dump(mode="json", exclude_none=True), {}
        )
        assert snapshot is not None
        baseline, baseline_bytes = execute(
            payload, snapshot, f"stage12-fallback-base-{suffix}", active=False
        )
        original_range = repository.read_capture_range
        for reason in ("short", "version", "outage"):
            attempts: list[CaptureByteRange] = []

            def fault(
                source: Any,
                byte_range: CaptureByteRange,
                *,
                _reason: str = reason,
                _attempts: list[CaptureByteRange] = attempts,
                _read: Callable[[Any, CaptureByteRange], bytes] = original_range,
            ) -> bytes:
                assert 0 < byte_range.length < source.source_size_bytes
                _attempts.append(byte_range)
                if _reason == "short":
                    return _read(source, byte_range)[:-1]
                if _reason == "version":
                    raise CaptureRangeVersionDrift("injected")
                raise CaptureRangeUnavailable("injected")

            monkeypatch.setattr(repository, "read_capture_range", fault)
            result, content = execute(
                payload, snapshot, f"stage12-fallback-{reason}-{suffix}", active=True
            )
            assert attempts and content == baseline_bytes
            assert result["source_manifest"] == baseline["source_manifest"]
        monkeypatch.setattr(repository, "read_capture_range", original_range)

        upload_payload = PcapExportCreate(
            job_id=upload_id, include_filters=[{"source_port": 41_000}]
        )
        stale = repository.snapshot_pcap_export_source(
            upload_id, upload_payload.model_dump(mode="json", exclude_none=True), {}
        )
        assert stale is not None
        repository.save_job_capture(upload_id, upload_capture)
        replacement = repository.get_capture_source_version(upload_id)
        assert replacement is not None and replacement.object_key not in source_keys
        source_keys.add(replacement.object_key)
        replaced, replaced_bytes = execute(
            upload_payload, stale, f"stage12-replaced-{suffix}", active=True
        )
        fresh = repository.snapshot_pcap_export_source(
            upload_id, upload_payload.model_dump(mode="json", exclude_none=True), {}
        )
        assert fresh is not None
        sequential, sequential_bytes = execute(
            upload_payload, fresh, f"stage12-replaced-sequential-{suffix}", active=False
        )
        assert replaced_bytes == sequential_bytes
        assert replaced["source_manifest"] == sequential["source_manifest"]

        assert repository.delete_job(live_job_id)
        live_created = False
        for key in source_keys:
            if key.startswith("sensor-pcaps/"):
                _assert_minio_object_missing(blob, key)
    finally:
        repository.blob_store = blob
        try:
            _delete_pcap_export_jobs(repository, export_ids)
        finally:
            if upload_created:
                repository.delete_retained_source(upload_id)
            if live_created:
                repository.delete_job(live_job_id)
            repository.cleanup_pcap_export_orphans(
                now=datetime.now(UTC),
                max_age_seconds=0,
                limit=max(100, len(export_ids) * 2),
            )
            repository.close()
