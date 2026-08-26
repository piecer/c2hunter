from __future__ import annotations

import hashlib
import io
import threading
from collections.abc import Callable
from dataclasses import replace
from datetime import timedelta
from typing import Any

import pytest
from c2hunter_analysis.pcap_export import open_export_capture
from fastapi.testclient import TestClient
from test_pcap_posting_selection import _capture, _udp_packet

from c2hunter_controller.api_errors import ApiError
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap import build_capture_to_sink
from c2hunter_controller.pcap_export_queue import PcapExportQueue
from c2hunter_controller.pcap_export_service import (
    PcapExportDependencies,
    PcapExportExecutor,
    build_async_job,
)
from c2hunter_controller.pcap_export_worker import (
    ExportCancelled,
    ExportTimedOut,
    create_pcap_export_worker,
)
from c2hunter_controller.pcap_indexed_export import (
    IndexedFallback,
    IndexedFallbackReason,
    IndexedMatchBatch,
)
from c2hunter_controller.pcap_stream import MatchedPacketRecord
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import PcapExportCreate


def _setup_live_repository() -> tuple[MemoryRepository, dict[str, Any], tuple[bytes, bytes]]:
    repository = MemoryRepository()
    job = {
        "id": "atomic-live",
        "mode": "LIVE",
        "status": "CAPTURING",
        "capture": {"store_pcap": True},
        "internal_networks": ["10.0.0.0/8"],
        "sensor_ids": ["sensor-a", "sensor-b"],
    }
    repository.save_job(job)
    captures = (
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
        _capture(_udp_packet("10.0.0.2", "203.0.113.9", 50_001, 443)),
    )
    for order, capture in enumerate(captures):
        digest = hashlib.sha256(capture).hexdigest()
        stored, status = repository.save_sensor_pcap_limited(
            {
                "id": f"segment-{order}",
                "sensor_id": f"sensor-{'a' if order == 0 else 'b'}",
                "analysis_job_id": job["id"],
                "filename": f"segment-{order}.pcap",
                "size_bytes": len(capture),
                "sha256": digest,
                "uploaded_at": f"2026-08-26T00:00:0{order}+00:00",
            },
            capture,
            None,
            require_open_job=True,
        )
        assert status == "OK" and stored is not None
    completed = {**job, "status": "COMPLETED"}
    repository.save_job(completed)
    snapshot = repository.snapshot_pcap_export_source(
        job["id"],
        {"job_id": job["id"], "port": 443},
        {},
    )
    assert snapshot is not None
    return repository, snapshot, captures


def _indexed_records(captures: tuple[bytes, bytes]) -> tuple[MatchedPacketRecord, ...]:
    records: list[MatchedPacketRecord] = []
    for source_order, capture in enumerate(captures):
        decoder = open_export_capture(
            io.BytesIO(capture),
            source_id=f"segment-{source_order}",
            source_order=source_order,
            internal_networks=["10.0.0.0/8"],
        )
        packet = next(iter(decoder.iter_packets()))
        records.append(
            MatchedPacketRecord.from_export_packet(
                packet,
                sensor_id=f"sensor-{'a' if source_order == 0 else 'b'}",
            )
        )
    return tuple(records)


def _run_executor(
    repository: MemoryRepository,
    snapshot: dict[str, Any],
    dependencies: PcapExportDependencies,
    *,
    check_cancelled: Callable[[], None] | None = None,
    check_deadline: Callable[[], None] | None = None,
    settings: Settings | None = None,
) -> dict[str, Any]:
    return PcapExportExecutor(
        repository,
        settings
        or Settings(
            environment="test",
            pcap_export_max_bytes=4096,
            pcap_export_spool_max_memory_bytes=128,
        ),
        dependencies,
    ).execute(
        PcapExportCreate(job_id="atomic-live", port=443),
        {},
        source_snapshot=snapshot,
        check_cancelled=check_cancelled,
        check_deadline=check_deadline,
    )


def test_mode_off_with_corrupt_postings_performs_zero_stage11_12_lookups_and_is_sequential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, snapshot, captures = _setup_live_repository()
    indexed_calls = 0

    def reject(*_args: object, **_kwargs: object) -> IndexedMatchBatch:
        nonlocal indexed_calls
        indexed_calls += 1
        raise AssertionError("rollback-off touched Stage 11/12")

    for name in (
        "get_posting_index",
        "get_posting_index_identity",
        "get_structural_index",
        "read_capture_range",
    ):
        monkeypatch.setattr(repository, name, reject)
    result = _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(),
        settings=Settings(environment="test", pcap_indexed_export_mode="off"),
    )

    assert indexed_calls == 0
    assert result["matched_packet_count"] == len(captures)
    assert result["exported_packet_count"] == len(captures)


def test_indexed_fallback_runs_whole_manifest_sequentially_once_and_writes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, snapshot, _captures = _setup_live_repository()
    opened: list[str] = []
    writer_calls: list[dict[str, Any]] = []
    save_calls = 0
    observations: list[dict[str, Any]] = []
    original_open = repository.open_sensor_pcap
    original_save = repository.save_export_stream

    def open_source(source_id: str) -> Any:
        opened.append(source_id)
        return original_open(source_id)

    def writer(records: Any, **kwargs: Any) -> Any:
        writer_calls.append(kwargs)
        return build_capture_to_sink(records, **kwargs)

    def save(*args: Any, **kwargs: Any) -> Any:
        nonlocal save_calls
        save_calls += 1
        return original_save(*args, **kwargs)

    def unavailable(**_kwargs: Any) -> IndexedMatchBatch:
        raise IndexedFallback(IndexedFallbackReason.RANGE_MISSING)

    monkeypatch.setattr(repository, "open_sensor_pcap", open_source)
    monkeypatch.setattr(repository, "save_export_stream", save)
    result = _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(
            indexed_match_factory=unavailable,
            capture_writer=writer,
            rollout_observer=lambda **values: observations.append(values),
        ),
    )

    assert opened == ["segment-0", "segment-1"]
    assert len(writer_calls) == 1
    assert writer_calls[0] == {
        "max_output_bytes": 4096,
        "spool_max_memory_bytes": 128,
        "spool_directory": None,
    }
    assert save_calls == 1
    assert result["source_capture_count"] == 2
    assert result["scanned_source_capture_count"] == 2
    assert result["scanned_packet_count"] == 2
    assert result["matched_packet_count"] == 2
    assert observations[0]["path"] == "fallback"
    assert observations[0]["fallback_reason"] == "range_missing"
    assert observations[0]["shadow_parity"] == "not_applicable"


def test_complete_indexed_batch_has_no_sequential_reads_and_writes_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, snapshot, captures = _setup_live_repository()
    writer_calls = 0
    save_calls = 0
    observations: list[dict[str, Any]] = []
    original_save = repository.save_export_stream

    def reject_open(_source_id: str) -> Any:
        raise AssertionError("sequential source read")

    def writer(records: Any, **kwargs: Any) -> Any:
        nonlocal writer_calls
        writer_calls += 1
        return build_capture_to_sink(records, **kwargs)

    def save(*args: Any, **kwargs: Any) -> Any:
        nonlocal save_calls
        save_calls += 1
        return original_save(*args, **kwargs)

    def complete(**_kwargs: Any) -> IndexedMatchBatch:
        records = _indexed_records(captures)
        return IndexedMatchBatch(
            records=records,
            source_capture_count=2,
            scanned_source_capture_count=2,
            source_total_bytes=sum(map(len, captures)),
            scanned_source_bytes=sum(map(len, captures)),
            scanned_packet_count=2,
            source_manifest=tuple(
                (f"segment-{order}", hashlib.sha256(capture).hexdigest())
                for order, capture in enumerate(captures)
            ),
            truncation_reasons=(),
            range_count=2,
            selected_payload_bytes=sum(record.captured_length for record in records),
            fetched_bytes=sum(record.captured_length for record in records),
            identity_proof=(),
        )

    monkeypatch.setattr(repository, "open_sensor_pcap", reject_open)
    monkeypatch.setattr(repository, "save_export_stream", save)
    result = _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(
            indexed_match_factory=complete,
            capture_writer=writer,
            rollout_observer=lambda **values: observations.append(values),
        ),
    )

    assert writer_calls == 1
    assert save_calls == 1
    assert result["matched_packet_count"] == 2
    assert result["exported_packet_count"] == 2
    assert result["scanned_packet_count"] == 2
    assert observations == [
        {
            "path": "indexed",
            "fallback_reason": "none",
            "shadow_parity": "not_applicable",
            "requested_range_count": 0,
            "coalesced_range_count": 2,
            "selected_payload_bytes": sum(
                record.captured_length for record in _indexed_records(captures)
            ),
            "fetched_bytes": sum(record.captured_length for record in _indexed_records(captures)),
            "source_total_bytes": sum(map(len, captures)),
        }
    ]


@pytest.mark.parametrize("check_name", ["cancelled", "deadline"])
def test_indexed_check_exceptions_propagate_without_sequential_fallback(
    monkeypatch: pytest.MonkeyPatch,
    check_name: str,
) -> None:
    repository, snapshot, _captures = _setup_live_repository()
    opened = 0

    class StopExport(RuntimeError):
        pass

    def reject_open(_source_id: str) -> Any:
        nonlocal opened
        opened += 1
        raise AssertionError("sequential fallback")

    def factory(**kwargs: Any) -> IndexedMatchBatch:
        kwargs[f"check_{check_name}"]()
        raise AssertionError("check did not raise")

    monkeypatch.setattr(repository, "open_sensor_pcap", reject_open)

    def check() -> None:
        raise StopExport(check_name)

    with pytest.raises(StopExport, match=check_name):
        _run_executor(
            repository,
            snapshot,
            PcapExportDependencies(indexed_match_factory=factory),
            check_cancelled=check if check_name == "cancelled" else None,
            check_deadline=check if check_name == "deadline" else None,
        )

    assert opened == 0
    assert repository.exports == {}


def test_candidate_ownership_rejection_happens_before_indexed_factory() -> None:
    repository, snapshot, _captures = _setup_live_repository()
    calls = 0

    def factory(**_kwargs: Any) -> IndexedMatchBatch:
        nonlocal calls
        calls += 1
        raise AssertionError("factory called before candidate authorization")

    with pytest.raises(ApiError) as caught:
        PcapExportExecutor(
            repository,
            Settings(environment="test"),
            PcapExportDependencies(indexed_match_factory=factory),
        ).execute(
            PcapExportCreate(job_id="atomic-live", candidate_id="foreign"),
            {},
            source_snapshot=snapshot,
        )

    assert (caught.value.status, caught.value.code) == (404, "CANDIDATE_NOT_FOUND")
    assert calls == 0


def test_sync_route_passes_exact_admitted_snapshot_to_injected_factory() -> None:
    repository, snapshot, _captures = _setup_live_repository()
    observed: list[tuple[str, tuple[str, ...]]] = []

    def factory(**kwargs: Any) -> IndexedMatchBatch:
        supplied = kwargs["source_snapshot"]
        observed.append(
            (
                supplied["source_generation"],
                tuple(item["id"] for item in supplied["source_manifest"]),
            )
        )
        raise IndexedFallback(IndexedFallbackReason.INDEX_UNAVAILABLE)

    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_execution_mode="sync_only"),
            repository,
            pcap_export_dependencies=PcapExportDependencies(indexed_match_factory=factory),
        )
    )
    response = client.post("/api/v1/pcap-exports", json={"job_id": "atomic-live", "port": 443})

    assert response.status_code == 201
    assert observed == [
        (
            snapshot["source_generation"],
            tuple(item["id"] for item in snapshot["source_manifest"]),
        )
    ]


def test_durable_worker_uses_same_factory_between_pre_and_post_generation_fences(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, snapshot, _captures = _setup_live_repository()
    settings = Settings(environment="test")
    queued = build_async_job(
        settings=settings,
        principal_scope="local",
        requested_job_id="atomic-live",
        snapshot={
            **snapshot,
            "canonical_request": {"job_id": "atomic-live", "port": 443},
            "effective_limits": {},
            "policy_version": "pcap-export-v8",
        },
        candidate_id=None,
        idempotency_key="indexed-durable",
    )
    PcapExportQueue(repository).enqueue(queued, capacity=2, per_principal_limit=2)
    events: list[tuple[str, str]] = []
    original_validate = repository.validate_pcap_export_source

    def validate(job: dict[str, Any]) -> bool:
        events.append(("fence", str(job["source_generation"])))
        return original_validate(job)

    def factory(**kwargs: Any) -> IndexedMatchBatch:
        supplied = kwargs["source_snapshot"]
        events.append(("factory", str(supplied["source_generation"])))
        assert supplied["source_manifest"] == snapshot["source_manifest"]
        raise IndexedFallback(IndexedFallbackReason.INDEX_UNAVAILABLE)

    monkeypatch.setattr(repository, "validate_pcap_export_source", validate)
    worker = create_pcap_export_worker(
        repository,
        settings,
        dependencies=PcapExportDependencies(indexed_match_factory=factory),
    )

    assert worker.run_once()
    assert events == [
        ("fence", snapshot["source_generation"]),
        ("factory", snapshot["source_generation"]),
        ("fence", snapshot["source_generation"]),
    ]


@pytest.mark.parametrize(
    "indexed_stage",
    ["posting_selection", "locator_before_range", "predicate_loop", "final_identity_fence"],
)
@pytest.mark.parametrize("loss", ["cancellation", "deadline", "lease"])
def test_durable_indexed_guard_loss_never_falls_back_writes_or_publishes(
    monkeypatch: pytest.MonkeyPatch,
    indexed_stage: str,
    loss: str,
) -> None:
    repository, snapshot, _captures = _setup_live_repository()
    settings = Settings(environment="test", pcap_export_job_timeout_seconds=121)
    queued = build_async_job(
        settings=settings,
        principal_scope="local",
        requested_job_id="atomic-live",
        snapshot={
            **snapshot,
            "canonical_request": {"job_id": "atomic-live", "port": 443},
            "effective_limits": {},
            "policy_version": "pcap-export-v8",
        },
        candidate_id=None,
        idempotency_key=f"guard-{indexed_stage}-{loss}",
    )
    PcapExportQueue(repository).enqueue(queued, capacity=2, per_principal_limit=2)
    clock = [0.0]
    observed: list[tuple[str, type[BaseException]]] = []
    opened = writer_calls = save_calls = completion_calls = 0
    original_save = repository.save_export_stream
    original_complete = repository.complete_pcap_export_job
    original_retry = repository.retry_pcap_export_job
    retry_codes: list[str] = []

    def reject_open(_source_id: str) -> Any:
        nonlocal opened
        opened += 1
        raise AssertionError("IndexedFallback triggered a sequential full read")

    def writer(_records: Any, **_kwargs: Any) -> Any:
        nonlocal writer_calls
        writer_calls += 1
        raise AssertionError("writer called after durable guard loss")

    def save(*args: Any, **kwargs: Any) -> Any:
        nonlocal save_calls
        save_calls += 1
        return original_save(*args, **kwargs)

    def complete(*args: Any, **kwargs: Any) -> bool:
        nonlocal completion_calls
        completion_calls += 1
        return original_complete(*args, **kwargs)

    def retry(*args: Any, **kwargs: Any) -> bool:
        retry_codes.append(str(kwargs["error_code"]))
        return original_retry(*args, **kwargs)

    def factory(**kwargs: Any) -> IndexedMatchBatch:
        guard = kwargs["check_cancelled"]
        assert guard is kwargs["check_deadline"]
        if loss == "cancellation":
            PcapExportQueue(repository).cancel(str(kwargs["source_snapshot"]["id"]))
        elif loss == "deadline":
            clock[0] = 121.0
        else:
            repository.pcap_export_jobs[queued["id"]]["lease_token"] = "replacement-owner"
        try:
            guard()
        except (ExportCancelled, ExportTimedOut) as exc:
            observed.append((indexed_stage, type(exc)))
            raise
        raise AssertionError("durable guard accepted lost ownership")

    monkeypatch.setattr(repository, "open_sensor_pcap", reject_open)
    monkeypatch.setattr(repository, "save_export_stream", save)
    monkeypatch.setattr(repository, "complete_pcap_export_job", complete)
    monkeypatch.setattr(repository, "retry_pcap_export_job", retry)
    worker = create_pcap_export_worker(
        repository,
        settings,
        dependencies=PcapExportDependencies(
            indexed_match_factory=factory,
            capture_writer=writer,
        ),
    )
    worker.monotonic_clock = lambda: clock[0]

    assert worker.run_once() is True

    expected_exception = ExportTimedOut if loss == "deadline" else ExportCancelled
    assert observed == [(indexed_stage, expected_exception)]
    expected_retry_code = "PCAP_EXPORT_TIMEOUT" if loss == "deadline" else "PCAP_EXPORT_CANCELLED"
    assert retry_codes == [expected_retry_code]
    assert (opened, writer_calls, save_calls, completion_calls) == (0, 0, 0, 0)
    assert repository.exports == {}
    lifecycle = repository.get_pcap_export_job(queued["id"])
    assert lifecycle is not None
    if loss == "cancellation":
        assert (lifecycle["status"], lifecycle["error_code"]) == (
            "CANCELLED",
            "PCAP_EXPORT_CANCELLED",
        )
        assert lifecycle["lease_token"] is None
    elif loss == "deadline":
        assert lifecycle["status"] == "QUEUED"
        assert lifecycle.get("error_code") is None
        assert lifecycle["attempt"] == 1
        assert lifecycle["next_attempt_at"] > lifecycle["updated_at"]
        assert lifecycle["lease_token"] is None
    else:
        assert lifecycle["status"] == "RUNNING"
        assert lifecycle["lease_token"] == "replacement-owner"
        assert lifecycle.get("error_code") is None
    assert not any(
        thread.name == f"pcap-export-heartbeat-{queued['id']}" and thread.is_alive()
        for thread in threading.enumerate()
    )


@pytest.mark.parametrize(
    ("outcome", "expected_parity", "expected_writes"),
    [("match", "match", 2), ("mismatch", "mismatch", 2), ("error", "error", 1)],
)
def test_shadow_is_authoritative_sequential_and_never_persists_provisional_artifact(
    monkeypatch: pytest.MonkeyPatch,
    outcome: str,
    expected_parity: str,
    expected_writes: int,
) -> None:
    repository, snapshot, captures = _setup_live_repository()
    records = _indexed_records(captures)
    writes = saves = 0
    observations: list[dict[str, Any]] = []
    original_save = repository.save_export_stream

    def writer(items: Any, **kwargs: Any) -> Any:
        nonlocal writes
        writes += 1
        return build_capture_to_sink(items, **kwargs)

    def save(*args: Any, **kwargs: Any) -> Any:
        nonlocal saves
        saves += 1
        return original_save(*args, **kwargs)

    def factory(**_kwargs: Any) -> IndexedMatchBatch:
        if outcome == "error":
            raise RuntimeError("shadow-only failure")
        selected = records
        if outcome == "mismatch":
            selected = (
                replace(records[0], timestamp=records[0].timestamp + timedelta(seconds=1)),
                *records[1:],
            )
        return IndexedMatchBatch(
            records=tuple(selected),
            source_capture_count=2,
            scanned_source_capture_count=2,
            source_total_bytes=sum(map(len, captures)),
            scanned_source_bytes=sum(map(len, captures)),
            scanned_packet_count=2,
            source_manifest=tuple(
                (f"segment-{order}", hashlib.sha256(capture).hexdigest())
                for order, capture in enumerate(captures)
            ),
            truncation_reasons=(),
            range_count=2,
            selected_payload_bytes=sum(record.captured_length for record in records),
            fetched_bytes=sum(record.captured_length for record in records),
            identity_proof=(),
            requested_range_count=2,
        )

    monkeypatch.setattr(repository, "save_export_stream", save)
    result = _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(
            indexed_match_factory=factory,
            capture_writer=writer,
            rollout_observer=lambda **values: observations.append(values),
        ),
        settings=Settings(
            environment="test",
            pcap_posting_index_enabled=True,
            pcap_indexed_export_mode="shadow",
            pcap_indexed_export_canary_basis_points=10_000,
            pcap_export_max_bytes=4096,
            pcap_export_spool_max_memory_bytes=128,
        ),
    )

    assert result["matched_packet_count"] == 2
    assert (writes, saves, len(repository.exports)) == (expected_writes, 1, 1)
    assert observations[-1]["path"] == "shadow"
    assert observations[-1]["shadow_parity"] == expected_parity


def test_shadow_not_sampled_does_no_index_work_and_records_bounded_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, snapshot, _captures = _setup_live_repository()
    calls = 0
    observations: list[dict[str, Any]] = []

    def factory(**_kwargs: Any) -> IndexedMatchBatch:
        nonlocal calls
        calls += 1
        raise AssertionError("unsampled shadow factory")

    monkeypatch.setattr(
        "c2hunter_controller.pcap_export_service.deterministic_shadow_sample",
        lambda *_args: False,
    )
    _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(
            indexed_match_factory=factory,
            rollout_observer=lambda **values: observations.append(values),
        ),
        settings=Settings(
            environment="test",
            pcap_posting_index_enabled=True,
            pcap_indexed_export_mode="shadow",
            pcap_indexed_export_canary_basis_points=1,
        ),
    )

    assert calls == 0
    assert observations[-1] == {
        "path": "sequential",
        "fallback_reason": "none",
        "shadow_parity": "not_sampled",
        "requested_range_count": 0,
        "coalesced_range_count": 0,
        "selected_payload_bytes": 0,
        "fetched_bytes": 0,
        "source_total_bytes": sum(item["size_bytes"] for item in snapshot["source_manifest"]),
    }


def test_shadow_factory_cancellation_propagates_without_sequential_write_or_observation() -> None:
    repository, snapshot, _captures = _setup_live_repository()
    writes = 0
    observations: list[dict[str, Any]] = []

    class Cancelled(RuntimeError):
        pass

    def check() -> None:
        raise Cancelled("cancelled")

    def factory(**kwargs: Any) -> IndexedMatchBatch:
        kwargs["check_cancelled"]()
        raise AssertionError("cancellation did not propagate")

    def writer(_records: Any, **_kwargs: Any) -> Any:
        nonlocal writes
        writes += 1
        raise AssertionError("writer ran after cancellation")

    with pytest.raises(Cancelled, match="cancelled"):
        _run_executor(
            repository,
            snapshot,
            PcapExportDependencies(
                indexed_match_factory=factory,
                capture_writer=writer,
                rollout_observer=lambda **values: observations.append(values),
            ),
            check_cancelled=check,
            settings=Settings(
                environment="test",
                pcap_posting_index_enabled=True,
                pcap_indexed_export_mode="shadow",
                pcap_indexed_export_canary_basis_points=10_000,
            ),
        )

    assert writes == 0
    assert observations == []
    assert repository.exports == {}


def test_shadow_writer_comparison_failure_closes_provisional_artifact() -> None:
    repository, snapshot, captures = _setup_live_repository()
    records = _indexed_records(captures)
    writes = 0
    closed: list[bool] = []
    observations: list[dict[str, Any]] = []

    def factory(**_kwargs: Any) -> IndexedMatchBatch:
        return IndexedMatchBatch(
            records=records,
            source_capture_count=2,
            scanned_source_capture_count=2,
            source_total_bytes=sum(map(len, captures)),
            scanned_source_bytes=sum(map(len, captures)),
            scanned_packet_count=2,
            source_manifest=tuple(
                (f"segment-{order}", hashlib.sha256(capture).hexdigest())
                for order, capture in enumerate(captures)
            ),
            truncation_reasons=(),
            range_count=2,
            selected_payload_bytes=sum(record.captured_length for record in records),
            fetched_bytes=sum(record.captured_length for record in records),
            identity_proof=(),
            requested_range_count=2,
        )

    class BrokenShadowArtifact:
        def __init__(self, artifact: Any) -> None:
            self.artifact = artifact
            self.size_bytes = artifact.size_bytes
            self.exported_packet_count = artifact.exported_packet_count

        @property
        def sha256(self) -> str:
            raise RuntimeError("shadow comparison failed")

        def __enter__(self) -> BrokenShadowArtifact:
            return self

        def __exit__(self, *_args: object) -> None:
            self.artifact.close()
            closed.append(True)

    def writer(items: Any, **kwargs: Any) -> Any:
        nonlocal writes
        writes += 1
        artifact = build_capture_to_sink(items, **kwargs)
        return artifact if writes == 1 else BrokenShadowArtifact(artifact)

    result = _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(
            indexed_match_factory=factory,
            capture_writer=writer,
            rollout_observer=lambda **values: observations.append(values),
        ),
        settings=Settings(
            environment="test",
            pcap_posting_index_enabled=True,
            pcap_indexed_export_mode="shadow",
            pcap_indexed_export_canary_basis_points=10_000,
        ),
    )

    assert result["status"] == "COMPLETED"
    assert writes == 2
    assert closed == [True]
    assert observations[-1]["shadow_parity"] == "error"
    assert len(repository.exports) == 1


def test_rollout_observer_base_exception_is_metrics_only() -> None:
    repository, snapshot, _captures = _setup_live_repository()

    class BrokenObserver(BaseException):
        pass

    def observer(**_values: Any) -> None:
        raise BrokenObserver("metrics callback failed")

    result = _run_executor(
        repository,
        snapshot,
        PcapExportDependencies(rollout_observer=observer),
    )

    assert result["status"] == "COMPLETED"
    assert len(repository.exports) == 1
