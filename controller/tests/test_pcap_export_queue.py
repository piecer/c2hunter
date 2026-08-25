from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from prometheus_client import CollectorRegistry, generate_latest

from c2hunter_controller.pcap_export_metrics import PcapExportMetrics
from c2hunter_controller.pcap_export_queue import ExportQueueStorageError, PcapExportQueue
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _job(job_id: str = "e1", *, key: str | None = "key", fingerprint: str = "fp") -> dict:
    now = datetime.now(UTC).isoformat()
    return {
        "id": job_id,
        "principal_scope": "local",
        "idempotency_key": key,
        "request_fingerprint": fingerprint,
        "coalesce_fingerprint": fingerprint,
        "job_id": "analysis-1",
        "source_job_id": "analysis-1",
        "source_generation": "a" * 64,
        "status": "QUEUED",
        "execution_mode": "ASYNC",
        "attempt": 0,
        "max_attempts": 3,
        "queued_at": now,
        "created_at": now,
        "updated_at": now,
        "next_attempt_at": now,
        "progress": {
            "phase": "QUEUED",
            "percent": 0,
            "scanned_source_bytes": 0,
            "scanned_packet_count": 0,
            "matched_packet_count": 0,
            "exported_packet_count": 0,
        },
    }


def test_memory_queue_replays_before_capacity_and_rejects_key_conflict() -> None:
    queue = PcapExportQueue(MemoryRepository())
    first, created = queue.enqueue(_job(), capacity=1, per_principal_limit=1)
    assert created is True
    replay, created = queue.enqueue(_job("other"), capacity=1, per_principal_limit=1)
    assert created is False
    assert replay["id"] == first["id"]
    conflict = _job("conflict", fingerprint="different")
    try:
        queue.enqueue(conflict, capacity=1, per_principal_limit=1)
    except ValueError as exc:
        assert str(exc) == "idempotency_conflict"
    else:
        raise AssertionError("conflicting idempotency key accepted")


def test_claim_lease_guards_monotonic_progress_and_stale_completion() -> None:
    queue = PcapExportQueue(MemoryRepository())
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    now = datetime.now(UTC)
    claimed = queue.claim(now=now, lease_seconds=120)
    assert claimed is not None and claimed["status"] == "RUNNING" and claimed["attempt"] == 1
    token = claimed["lease_token"]
    assert queue.progress(
        "e1",
        attempt=1,
        lease_token=token,
        progress={"phase": "SOURCE_SCAN", "percent": 30, "scanned_source_bytes": 30},
    )
    assert queue.progress(
        "e1",
        attempt=1,
        lease_token=token,
        progress={"phase": "FILTER", "percent": 10, "scanned_source_bytes": 4},
    )
    current = queue.get("e1")
    assert current is not None
    assert current["progress"]["percent"] == 30
    assert current["progress"]["scanned_source_bytes"] == 30
    assert not queue.complete("e1", attempt=1, lease_token="stale", artifact={"id": "e1"})
    assert queue.complete(
        "e1",
        attempt=1,
        lease_token=token,
        artifact={"id": "e1", "sha256": "b" * 64, "size_bytes": 1},
    )
    assert queue.get("e1")["status"] == "COMPLETED"  # type: ignore[index]


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_unsuccessful_artifact_completion_preserves_failed_terminal_state(
    repository_kind: str, tmp_path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / f"{repository_kind}.db")
    )
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    claimed = queue.claim()
    assert claimed is not None
    assert queue.complete(
        claimed["id"],
        attempt=claimed["attempt"],
        lease_token=claimed["lease_token"],
        artifact={
            "status": "FAILED",
            "error_code": "PCAP_NO_MATCH",
            "error": "No packets matched",
            "matched_packet_count": 0,
            "published": True,
        },
    )
    terminal = queue.get(claimed["id"])
    assert terminal is not None
    assert terminal["status"] == "FAILED"
    assert terminal["error_code"] == "PCAP_NO_MATCH"
    assert terminal["error"] == "No packets matched"
    assert terminal["progress"]["phase"] == "TERMINAL"
    assert terminal["progress"]["percent"] < 100


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
@pytest.mark.parametrize("with_object_key", [False, True])
def test_compensation_never_deletes_lifecycle_referenced_winner(
    repository_kind: str, with_object_key: bool, tmp_path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / f"winner-{repository_kind}.db")
    )
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    claimed = queue.claim()
    assert claimed is not None
    artifact_metadata = {
        "id": claimed["id"],
        "job_id": "analysis-1",
        "status": "COMPLETED",
        "published": False,
        "attempt": claimed["attempt"],
        "lease_token": claimed["lease_token"],
    }
    if with_object_key:
        artifact_metadata["object_key"] = "published-winner"
    artifact = repository.save_export(artifact_metadata, b"pcap")
    assert artifact is not None
    assert queue.complete(
        claimed["id"],
        attempt=claimed["attempt"],
        lease_token=claimed["lease_token"],
        artifact=artifact,
    )

    queue.compensate_artifact(
        claimed["id"],
        attempt=claimed["attempt"],
        lease_token=claimed["lease_token"],
        artifact=artifact,
    )

    retained = repository.get_export_metadata(claimed["id"])
    assert retained is not None
    assert retained.get("object_key") == ("published-winner" if with_object_key else None)


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_active_export_protects_resolved_provenance_source(repository_kind: str, tmp_path) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / f"provenance-{repository_kind}.db")
    )
    repository.save_job(
        {
            "id": "source-parent",
            "status": "COMPLETED",
            "sensor_ids": ["uploaded"],
            "source": {
                "packet_bytes_retained": True,
                "size_bytes": 4,
                "sha256": "a" * 64,
                "packet_count": 1,
            },
        }
    )
    repository.save_job(
        {"id": "analysis-child", "status": "COMPLETED", "parent_job_id": "source-parent"}
    )
    canonical_request = {"job_id": "analysis-child"}
    snapshot = repository.snapshot_pcap_export_source("analysis-child", canonical_request, {})
    assert snapshot is not None and snapshot["source_job_id"] == "source-parent"
    queued = {
        **_job(),
        "job_id": "analysis-child",
        "source_job_id": snapshot["source_job_id"],
        "source_generation": snapshot["source_generation"],
        "source_manifest": snapshot["source_manifest"],
        "canonical_request": canonical_request,
        "effective_limits": {},
    }
    PcapExportQueue(repository).enqueue(queued, capacity=2, per_principal_limit=2)

    assert repository.delete_job("source-parent") is False


def test_sqlite_queue_recovers_expired_lease_and_cancel_is_sticky(tmp_path) -> None:
    queue = PcapExportQueue(SQLiteRepository(tmp_path / "controller.db"))
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    now = datetime.now(UTC)
    claimed = queue.claim(now=now, lease_seconds=1)
    assert claimed is not None
    assert queue.recover_expired(now=now + timedelta(seconds=2)) == 1
    reclaimed = queue.claim(now=now + timedelta(seconds=2), lease_seconds=10)
    assert reclaimed is not None and reclaimed["attempt"] == 2
    result = queue.cancel("e1", reason="operator")
    assert result["cancellation_requested"] is True
    assert result["status"] == "RUNNING"
    assert not queue.complete(
        "e1", attempt=2, lease_token=reclaimed["lease_token"], artifact={"id": "e1"}
    )
    terminal = queue.get("e1")
    assert terminal is not None and terminal["status"] == "CANCELLED"
    assert "sha256" not in terminal


def test_queue_storage_outage_is_typed_after_sqlite_close(tmp_path) -> None:
    repository = SQLiteRepository(tmp_path / "closed.db")
    queue = PcapExportQueue(repository)
    repository.close()

    with pytest.raises(ExportQueueStorageError):
        queue.get("missing")


def test_repository_owns_queue_lifecycle_api() -> None:
    repository = MemoryRepository()
    required = {
        "enqueue_pcap_export_job",
        "get_pcap_export_job",
        "claim_pcap_export_job",
        "heartbeat_pcap_export_job",
        "progress_pcap_export_job",
        "complete_pcap_export_job",
        "retry_pcap_export_job",
        "cancel_pcap_export_job",
        "recover_pcap_export_jobs",
    }
    assert required <= set(dir(repository))


def test_metrics_registry_has_exact_low_cardinality_names_and_transition_values() -> None:
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)
    queue = PcapExportQueue(MemoryRepository(), metrics=metrics)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    claimed = queue.claim(lease_seconds=1)
    assert claimed is not None
    assert not queue.progress("e1", attempt=1, lease_token="stale", progress={"percent": 10})
    assert queue.retry_or_fail(
        "e1",
        attempt=1,
        lease_token=claimed["lease_token"],
        transient=True,
        error_code="PCAP_EXPORT_STORAGE_ERROR",
        error="temporary",
    )

    text = generate_latest(registry).decode()
    expected = {
        "c2hunter_pcap_export_queue_depth",
        "c2hunter_pcap_export_enqueue_total",
        "c2hunter_pcap_export_duration_seconds",
        "c2hunter_pcap_export_retries_total",
        "c2hunter_pcap_export_lease_expirations_total",
        "c2hunter_pcap_export_progress_stale_total",
        "c2hunter_pcap_export_artifact_bytes",
        "c2hunter_pcap_export_orphan_cleanup_total",
    }
    assert all(name in text for name in expected)
    assert 'c2hunter_pcap_export_enqueue_total{result="created"} 1.0' in text
    assert 'c2hunter_pcap_export_retries_total{reason="storage"} 1.0' in text
    assert "c2hunter_pcap_export_progress_stale_total 1.0" in text
    assert "export_id" not in text and "principal_scope" not in text


def test_queue_depth_reconciles_from_durable_storage_across_facades() -> None:
    repository = MemoryRepository()
    first_registry = CollectorRegistry()
    first = PcapExportQueue(repository, metrics=PcapExportMetrics(first_registry))
    first.enqueue(_job("queued"), capacity=3, per_principal_limit=3)
    second_registry = CollectorRegistry()
    second = PcapExportQueue(repository, metrics=PcapExportMetrics(second_registry))
    second.reconcile_metrics()
    text = generate_latest(second_registry).decode()
    assert 'c2hunter_pcap_export_queue_depth{status="QUEUED"} 1.0' in text
    assert 'c2hunter_pcap_export_queue_depth{status="RUNNING"} 0.0' in text
    claimed = first.claim()
    assert claimed is not None
    second.reconcile_metrics()
    text = generate_latest(second_registry).decode()
    assert 'c2hunter_pcap_export_queue_depth{status="QUEUED"} 0.0' in text
    assert 'c2hunter_pcap_export_queue_depth{status="RUNNING"} 1.0' in text


def test_retention_bounds_age_count_and_bytes_independently() -> None:
    now = datetime.now(UTC)

    def completed(job_id: str, seconds_old: int, size: int) -> dict:
        value = _job(job_id, key=job_id, fingerprint=job_id)
        value.update(
            status="COMPLETED",
            completed_at=(now - timedelta(seconds=seconds_old)).isoformat(),
            size_bytes=size,
        )
        return value

    for expected, limits in [
        (["old"], dict(max_age_seconds=10, max_count=10, max_artifact_bytes=1000)),
        (["first"], dict(max_age_seconds=1000, max_count=1, max_artifact_bytes=1000)),
        (["first"], dict(max_age_seconds=1000, max_count=10, max_artifact_bytes=6)),
    ]:
        repository = MemoryRepository()
        repository.pcap_export_jobs = {
            "first": completed("first", 2, 5),
            "old" if expected == ["old"] else "second": completed(
                "old" if expected == ["old"] else "second", 1 if expected != ["old"] else 20, 5
            ),
        }
        if expected == ["first"]:
            repository.pcap_export_jobs["first"]["completed_at"] = (
                now - timedelta(seconds=2)
            ).isoformat()
        removed = PcapExportQueue(repository).retain_terminal(now=now, **limits)
        assert removed == expected
        assert all(export_id not in repository.exports for export_id in removed)
        assert all(export_id not in repository.export_content for export_id in removed)


def test_orphan_cleanup_is_bounded_and_never_removes_referenced_or_published_artifact() -> None:
    now = datetime.now(UTC)
    repository = MemoryRepository()
    old = (now - timedelta(hours=1)).isoformat()
    repository.exports = {
        "loser-a": {
            "id": "loser-a",
            "object_key": "exports/loser-a.pcap",
            "published": False,
            "created_at": old,
        },
        "loser-b": {
            "id": "loser-b",
            "object_key": "exports/loser-b.pcap",
            "published": False,
            "created_at": old,
        },
        "winner": {
            "id": "winner",
            "object_key": "exports/winner.pcap",
            "published": False,
            "created_at": old,
        },
        "visible": {
            "id": "visible",
            "object_key": "exports/visible.pcap",
            "published": True,
            "created_at": old,
        },
    }
    repository.export_content = {key: b"pcap" for key in repository.exports}
    repository.pcap_export_jobs = {
        "winner": {"id": "winner", "object_key": "exports/winner.pcap", "status": "COMPLETED"}
    }

    removed = repository.cleanup_pcap_export_orphans(now=now, max_age_seconds=60, limit=1)

    assert removed == ["exports/loser-a.pcap"]
    assert "loser-a" not in repository.exports
    assert "loser-b" in repository.exports
    assert "winner" in repository.exports
    assert "visible" in repository.exports


def test_orphan_cleanup_metrics_have_only_bounded_success_and_failure_labels() -> None:
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)
    metrics.orphan_cleanup("success")
    metrics.orphan_cleanup("failure")

    text = generate_latest(registry).decode()
    assert 'c2hunter_pcap_export_orphan_cleanup_total{result="success"} 1.0' in text
    assert 'c2hunter_pcap_export_orphan_cleanup_total{result="failure"} 1.0' in text
    assert "export_id" not in text and "object_key" not in text
