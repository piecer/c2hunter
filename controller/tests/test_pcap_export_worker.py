from __future__ import annotations

from datetime import UTC, datetime
from threading import Event

from prometheus_client import CollectorRegistry, generate_latest

from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_export_metrics import PcapExportMetrics
from c2hunter_controller.pcap_export_queue import ExportQueueStorageError, PcapExportQueue
from c2hunter_controller.pcap_export_service import build_async_job
from c2hunter_controller.pcap_export_worker import (
    PcapExportWorker,
    TransientExportError,
    create_pcap_export_worker,
    parse_worker_command,
    worker_ready,
)
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import PcapExportCreate


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


def test_worker_publishes_only_after_executor_returns_verified_artifact() -> None:
    queue = PcapExportQueue(MemoryRepository())
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    worker = PcapExportWorker(
        queue,
        lambda job, checkpoint: {
            "id": job["id"],
            "sha256": "c" * 64,
            "size_bytes": 4,
            "capture_format": "PCAP",
            "filename": "x.pcap",
        },
    )
    assert worker.run_once() is True
    completed = queue.get("e1")
    assert completed is not None and completed["status"] == "COMPLETED"
    assert completed["progress"]["percent"] == 100


def test_worker_retries_only_typed_transient_failures() -> None:
    queue = PcapExportQueue(MemoryRepository())
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)
    worker = PcapExportWorker(
        queue, lambda _job, _checkpoint: (_ for _ in ()).throw(TransientExportError("store"))
    )
    assert worker.run_once() is True
    assert queue.get("e1")["status"] == "QUEUED"  # type: ignore[index]

    other = _job("e2", key="key2", fingerprint="fp2")
    queue.enqueue(other, capacity=2, per_principal_limit=2)
    broken = PcapExportWorker(
        queue, lambda _job, _checkpoint: (_ for _ in ()).throw(ValueError("secret path"))
    )
    assert broken.run_once() is True
    failed = queue.get("e2")
    assert failed is not None and failed["status"] == "FAILED"
    assert "secret path" not in failed["error"]


def test_transient_completion_outage_compensates_staged_artifact_before_retry(monkeypatch) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(
        repository, metrics=PcapExportMetrics(CollectorRegistry(auto_describe=True))
    )
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        stored = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
                "object_key": "attempt-owned",
            },
            b"pcap",
        )
        assert stored is not None
        return stored

    compensation_calls = 0
    original_compensate = queue.compensate_artifact
    original_count = repository.count_pcap_export_jobs_by_status

    def compensate(*args, **kwargs):
        nonlocal compensation_calls
        compensation_calls += 1
        return original_compensate(*args, **kwargs)

    def count():
        lifecycle = repository.pcap_export_jobs["e1"]
        if lifecycle.get("status") == "QUEUED" and lifecycle.get("attempt") == 1:
            raise ExportQueueStorageError("metrics outage")
        return original_count()

    monkeypatch.setattr(
        repository,
        "complete_pcap_export_job",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ExportQueueStorageError("outage")),
    )
    monkeypatch.setattr(repository, "count_pcap_export_jobs_by_status", count)
    monkeypatch.setattr(queue, "compensate_artifact", compensate)
    assert PcapExportWorker(queue, stage).run_once() is True
    assert compensation_calls == 1
    assert queue.get("e1")["status"] == "QUEUED"  # type: ignore[index]
    assert "e1" not in repository.exports


def test_post_commit_outage_preserves_object_keyless_published_winner() -> None:
    class CommittedThenOutageRepository(MemoryRepository):
        def complete_pcap_export_job(self, export_id: str, **kwargs) -> bool:
            assert super().complete_pcap_export_job(export_id, **kwargs) is True
            raise ExportQueueStorageError("ambiguous post-commit outage")

    repository = CommittedThenOutageRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        stored = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
            },
            b"pcap",
        )
        assert stored is not None
        return stored

    assert PcapExportWorker(queue, stage).run_once() is True
    lifecycle = queue.get("e1")
    assert lifecycle is not None and lifecycle["status"] == "COMPLETED"
    artifact = repository.get_export_metadata("e1")
    assert artifact is not None and artifact["published"] is True
    retained = repository.get_export("e1")
    assert retained is not None and retained[1] == b"pcap"


def test_successful_completion_is_not_compensated_when_followup_read_fails(monkeypatch) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(
        repository, metrics=PcapExportMetrics(CollectorRegistry(auto_describe=True))
    )
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        stored = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
                "object_key": "published-winner",
            },
            b"pcap",
        )
        assert stored is not None
        return stored

    original_get = repository.get_pcap_export_job

    def get(export_id):
        lifecycle = repository.pcap_export_jobs.get(export_id)
        if lifecycle is not None and lifecycle.get("status") == "COMPLETED":
            raise ExportQueueStorageError("post-completion read outage")
        return original_get(export_id)

    compensation_calls = 0
    original_compensate = queue.compensate_artifact

    def compensate(*args, **kwargs):
        nonlocal compensation_calls
        compensation_calls += 1
        return original_compensate(*args, **kwargs)

    monkeypatch.setattr(repository, "get_pcap_export_job", get)
    monkeypatch.setattr(queue, "compensate_artifact", compensate)

    assert PcapExportWorker(queue, stage).run_once() is True
    assert compensation_calls == 0
    assert repository.pcap_export_jobs["e1"]["status"] == "COMPLETED"
    assert repository.exports["e1"]["published"] is True
    assert repository.export_content["e1"] == b"pcap"


def test_unexpected_completion_failure_compensates_staged_artifact(monkeypatch) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        stored = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
                "object_key": "unexpected-failure",
            },
            b"pcap",
        )
        assert stored is not None
        return stored

    compensation_calls = 0
    original_compensate = queue.compensate_artifact

    def compensate(*args, **kwargs):
        nonlocal compensation_calls
        compensation_calls += 1
        return original_compensate(*args, **kwargs)

    monkeypatch.setattr(
        queue,
        "complete",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(ValueError("unexpected")),
    )
    monkeypatch.setattr(queue, "compensate_artifact", compensate)

    assert PcapExportWorker(queue, stage).run_once() is True
    assert compensation_calls == 1
    assert queue.get("e1")["status"] == "FAILED"  # type: ignore[index]
    assert "e1" not in repository.exports


def test_worker_factory_executes_stored_canonical_request_with_shared_executor(monkeypatch) -> None:
    repository = MemoryRepository()
    queue = PcapExportQueue(repository)
    queued = _job()
    queued.update(
        canonical_request={"job_id": "analysis-1", "port": 443},
        effective_limits={},
        source_manifest=[],
    )
    monkeypatch.setattr(repository, "validate_pcap_export_admission", lambda _job: True)
    queue.enqueue(queued, capacity=2, per_principal_limit=2)
    seen: dict = {}

    def execute(self, payload, stage_seconds, **kwargs):
        seen.update(payload=payload, kwargs=kwargs, stage_seconds=stage_seconds)
        return {"id": "e1", "sha256": "c" * 64, "size_bytes": 4}

    monkeypatch.setattr(
        "c2hunter_controller.pcap_export_worker.PcapExportExecutor.execute", execute
    )
    monkeypatch.setattr(repository, "validate_pcap_export_source", lambda _job: True)

    worker = create_pcap_export_worker(repository, Settings(environment="test"))
    assert worker.run_once() is True
    assert seen["payload"] == PcapExportCreate(job_id="analysis-1", port=443)
    assert seen["kwargs"]["export_id"] == "e1"
    assert seen["kwargs"]["source_snapshot"]["lease_token"]


def test_attempt_artifact_is_hidden_until_cas_and_removed_after_cas_loss(monkeypatch) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        artifact = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
                "object_key": "attempt-owned",
            },
            b"pcap",
        )
        assert artifact is not None
        assert repository.get_export_metadata(job["id"]) is None
        return artifact

    worker = PcapExportWorker(queue, stage)
    monkeypatch.setattr(queue, "complete", lambda *args, **kwargs: False)
    assert worker.run_once() is True
    assert repository.get_export_metadata("e1") is None
    assert "e1" not in repository.exports


def test_cancellation_after_staging_compensates_exact_attempt_artifact() -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        artifact = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
                "object_key": "cancelled-attempt",
            },
            b"pcap",
        )
        assert artifact is not None
        queue.cancel(job["id"], reason="operator")
        return artifact

    assert PcapExportWorker(queue, stage).run_once() is True
    assert queue.get("e1")["status"] == "CANCELLED"  # type: ignore[index]
    assert "e1" not in repository.exports


def test_cancellation_winning_inside_completion_compensates_staged_artifact(
    monkeypatch,
) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "analysis-1", "status": "COMPLETED"})
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        artifact = repository.save_export(
            {
                "id": job["id"],
                "job_id": "analysis-1",
                "status": "COMPLETED",
                "published": False,
                "attempt": job["attempt"],
                "lease_token": job["lease_token"],
                "object_key": "completion-race",
            },
            b"sensitive-pcap",
        )
        assert artifact is not None
        return artifact

    original_complete = queue.complete

    def cancel_then_complete(export_id, **kwargs):
        queue.cancel(export_id, reason="operator")
        return original_complete(export_id, **kwargs)

    monkeypatch.setattr(queue, "complete", cancel_then_complete)

    assert PcapExportWorker(queue, stage).run_once() is True
    lifecycle = queue.get("e1")
    assert lifecycle is not None and lifecycle["status"] == "CANCELLED"
    assert "e1" not in repository.exports
    assert "e1" not in repository.export_content


def test_cleanup_failure_does_not_replace_cancellation_as_primary_outcome(monkeypatch) -> None:
    repository = MemoryRepository()
    queue = PcapExportQueue(repository)
    queue.enqueue(_job(), capacity=2, per_principal_limit=2)

    def stage(job, _checkpoint):
        queue.cancel(job["id"], reason="operator")
        return {"id": job["id"], "object_key": "exports/staged.pcap", "published": False}

    monkeypatch.setattr(
        queue,
        "compensate_artifact",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("private cleanup failure")),
    )

    assert PcapExportWorker(queue, stage).run_once() is True
    terminal = queue.get("e1")
    assert terminal is not None and terminal["status"] == "CANCELLED"
    assert terminal["error_code"] == "PCAP_EXPORT_CANCELLED"


def test_worker_run_recovers_before_readiness_and_stops_gracefully(monkeypatch) -> None:
    queue = PcapExportQueue(MemoryRepository())
    calls: list[str] = []
    monkeypatch.setattr(queue, "recover_expired", lambda: calls.append("recover") or 0)
    monkeypatch.setattr(queue, "claim", lambda **_kwargs: calls.append("claim") or None)
    stopped = Event()
    stopped.set()

    worker = PcapExportWorker(queue, lambda _job, _checkpoint: {})
    worker.run(stopped)
    assert calls == ["recover"]


def test_real_worker_executes_shared_executor_and_publishes_after_cas() -> None:
    repository = MemoryRepository()
    timestamp = datetime.now(UTC).isoformat()
    repository.create_job(
        {
            "id": "analysis-1",
            "idempotency_key": "analysis-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": [
                {
                    "timestamp": timestamp,
                    "source_ip": "10.0.0.1",
                    "destination_ip": "203.0.113.1",
                    "source_port": 50000,
                    "destination_port": 443,
                    "protocol": "UDP",
                    "direction": "OUTBOUND",
                    "sensor_id": "sensor-a",
                    "raw_packet_hex": "00" * 14,
                    "raw_packet_index": 0,
                    "raw_packet_interface_id": 0,
                    "raw_packet_link_type": 1,
                    "raw_packet_captured_length": 14,
                    "raw_packet_original_length": 14,
                }
            ],
            "created_at": timestamp,
        }
    )
    settings = Settings(environment="test")
    request = {"job_id": "analysis-1"}
    limits = {
        "source_scan_max_bytes": int(settings.pcap_export_scan_max_bytes or 0),
        "source_scan_max_packets": int(settings.pcap_export_scan_max_packets or 0),
        "output_max_bytes": int(settings.pcap_export_max_bytes or 0),
    }
    snapshot = repository.snapshot_pcap_export_source("analysis-1", request, limits)
    assert snapshot is not None
    queued = build_async_job(
        settings=settings,
        principal_scope="local",
        requested_job_id="analysis-1",
        snapshot=snapshot,
        candidate_id=None,
        idempotency_key="worker-integration",
    )
    PcapExportQueue(repository).enqueue(queued, capacity=2, per_principal_limit=2)

    assert create_pcap_export_worker(repository, settings).run_once() is True

    lifecycle = repository.get_pcap_export_job(queued["id"])
    assert lifecycle is not None and lifecycle["status"] == "COMPLETED"
    artifact = repository.get_export_metadata(queued["id"])
    assert artifact is not None and artifact["published"] is True
    assert isinstance(artifact["lease_token"], str) and lifecycle["lease_token"] is None


def test_worker_readiness_is_fail_closed() -> None:
    repository = MemoryRepository()
    assert worker_ready(repository) is True
    repository.ready = lambda: (_ for _ in ()).throw(RuntimeError("database unavailable"))  # type: ignore[method-assign]
    assert worker_ready(repository) is False


def test_worker_cli_supports_run_readiness_and_health() -> None:
    assert parse_worker_command([]) == "run"
    assert parse_worker_command(["run"]) == "run"
    assert parse_worker_command(["readiness"]) == "readiness"
    assert parse_worker_command(["healthcheck"]) == "healthcheck"


def test_worker_maintenance_retains_terminal_jobs_and_cleans_orphans_fail_open() -> None:
    repository = MemoryRepository()
    registry = CollectorRegistry()
    metrics = PcapExportMetrics(registry)
    queue = PcapExportQueue(repository, metrics=metrics)
    calls: list[str] = []
    repository.retain_pcap_export_jobs = (  # type: ignore[method-assign]
        lambda **_kwargs: calls.append("retention") or []
    )
    repository.cleanup_pcap_export_orphans = (  # type: ignore[method-assign]
        lambda **_kwargs: calls.append("cleanup") or ["exports/orphan.pcap"]
    )
    worker = PcapExportWorker(queue, lambda _job, _checkpoint: {})

    assert worker.run_once() is False
    assert calls == ["retention", "cleanup"]
    assert (
        'c2hunter_pcap_export_orphan_cleanup_total{result="success"} 1.0'
        in generate_latest(registry).decode()
    )

    repository.cleanup_pcap_export_orphans = (  # type: ignore[method-assign]
        lambda **_kwargs: (_ for _ in ()).throw(RuntimeError("private cleanup failure"))
    )
    assert worker.run_once() is False
    assert (
        'c2hunter_pcap_export_orphan_cleanup_total{result="failure"} 1.0'
        in generate_latest(registry).decode()
    )
