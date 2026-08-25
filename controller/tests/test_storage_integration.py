from __future__ import annotations

import hashlib
import os
import struct
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from c2hunter_controller.pcap_export_queue import (
    ExportPrincipalLimitError,
    ExportQueueFullError,
    ExportSourceChangedError,
)
from c2hunter_controller.pcap_offset_index import (
    IndexAvailability,
    SourceIndexBinding,
    build_offline_upload_index,
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
        assert durable_version.object_key == f"captures/{job_id}.pcap"
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
