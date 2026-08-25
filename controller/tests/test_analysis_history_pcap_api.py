from __future__ import annotations

import asyncio
import hashlib
import io
import ipaddress
import struct
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from c2hunter_analysis.pcap import parse_pcap
from fastapi.testclient import TestClient
from test_analysis_job_api import api, payload, synthetic_flows

import c2hunter_controller.app as controller_app
import c2hunter_controller.capture_sink as controller_capture_sink
import c2hunter_controller.pcap as controller_pcap
from c2hunter_controller.app import create_app
from c2hunter_controller.capture_sink import CaptureStorageError
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap import build_capture_result, filter_records
from c2hunter_controller.pcap_export_store import ExportQueueStorageError
from c2hunter_controller.pcap_export_worker import create_pcap_export_worker
from c2hunter_controller.repositories import (
    ArtifactStorageError,
    CaptureSource,
    MemoryRepository,
    SQLiteRepository,
)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _udp_packet(source: str, destination: str, source_port: int, ident: int) -> bytes:
    payload = b"uploaded-beacon"
    udp = struct.pack("!HHHH", source_port, 443, 8 + len(payload), 0) + payload
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        ident,
        0,
        64,
        17,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return bytes.fromhex("0200000000020200000000010800") + header + udp


def _pcap() -> bytes:
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    epoch = int(datetime(2026, 7, 20, tzinfo=UTC).timestamp())
    for sample in range(6):
        for host in range(1, 4):
            packet = _udp_packet(f"10.0.0.{host}", "203.0.113.77", 50000 + host, sample * 10 + host)
            content.extend(
                struct.pack("<IIII", epoch + sample * 30, host * 1000, len(packet), len(packet))
            )
            content.extend(packet)
    return bytes(content)


def _pcap_for_packets(packets: list[bytes]) -> bytes:
    content = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        content.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
        content.extend(packet)
    return bytes(content)


def _legacy_packet_record(packet: bytes, index: int) -> dict[str, Any]:
    timestamp = datetime(2026, 7, 20, 12, 0, index, tzinfo=UTC).isoformat()
    return {
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.77",
        "source_port": 50001,
        "destination_port": 443,
        "protocol": "UDP",
        "raw_packet_hex": packet.hex(),
        "timestamp": timestamp,
        "raw_packet_timestamp": timestamp,
        "raw_packet_index": index,
        "raw_packet_interface_id": 0,
        "raw_packet_link_type": 1,
        "raw_packet_original_length": len(packet),
    }


def test_streaming_export_uses_open_source_without_materializing(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        controller_capture_sink.CaptureArtifact,
        "read_bytes",
        lambda _self: (_ for _ in ()).throw(AssertionError("streaming artifact materialized")),
    )
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "streamed", "filename": "streamed.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert upload.status_code == 201
    opened = 0
    original_open = repository.open_job_capture

    def counted_open(job_id: str):
        nonlocal opened
        opened += 1
        return original_open(job_id)

    monkeypatch.setattr(repository, "open_job_capture", counted_open)
    monkeypatch.setattr(
        repository,
        "get_job_capture",
        lambda _job_id: (_ for _ in ()).throw(AssertionError("materialized source read")),
    )
    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})
    assert response.status_code == 201
    assert response.json()["matched_packet_count"] == 18
    assert opened == 1


def test_streaming_and_legacy_rollout_paths_are_byte_for_byte_differential() -> None:
    repository = MemoryRepository()
    streaming = TestClient(create_app(Settings(environment="test"), repository))
    upload = streaming.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "rollout", "filename": "rollout.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    legacy = TestClient(
        create_app(
            Settings(
                environment="test",
                pcap_export_pipeline="legacy",
                pcap_artifact_io="legacy",
            ),
            repository,
        )
    )

    streamed = streaming.post(
        "/api/v1/pcap-exports",
        json={"job_id": upload["id"], "include_filters": [{"source_port": 50002}]},
    ).json()
    materialized = legacy.post(
        "/api/v1/pcap-exports",
        json={"job_id": upload["id"], "include_filters": [{"source_port": 50002}]},
    ).json()

    assert (
        streaming.get(f"/api/v1/pcap-exports/{streamed['id']}/download").content
        == legacy.get(f"/api/v1/pcap-exports/{materialized['id']}/download").content
    )
    for field in (
        "status",
        "matched_packet_count",
        "exported_packet_count",
        "omitted_packet_count",
        "scanned_source_bytes",
        "scanned_packet_count",
        "capture_format",
        "sha256",
        "truncation_reasons",
    ):
        assert streamed[field] == materialized[field]


def test_streaming_read_fault_does_not_publish_or_retry_legacy() -> None:
    class FailsAtEof(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            chunk = super().read(size)
            if not chunk:
                raise OSError("drain fault")
            return chunk

    class FaultingRepository(MemoryRepository):
        fault_reads = False

        def open_job_capture(self, job_id: str) -> CaptureSource | None:
            content = self.job_captures.get(job_id)
            if content is None:
                return None
            if self.fault_reads:
                return CaptureSource(FailsAtEof(content), "faulting-source-v1")
            return super().open_job_capture(job_id)

        def get_job_capture(self, job_id: str) -> bytes | None:
            if self.fault_reads:
                raise AssertionError(f"legacy retry attempted for {job_id}")
            return super().get_job_capture(job_id)

    repository = FaultingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "fault", "filename": "fault.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    repository.fault_reads = True

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"
    assert repository.exports == {}
    assert repository.export_content == {}


def test_analysis_history_can_update_metadata_and_delete_terminal_job() -> None:
    client = api(settings=Settings(environment="test", pcap_export_execution_mode="sync_only"))
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="history-completed"),
    ).json()
    assert "flow_records" not in job
    original_dataset_id = job["dataset_id"]
    original_analysis = job["analysis"]
    export = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]}).json()

    updated = client.patch(
        f"/api/v1/analysis-jobs/{job['id']}",
        json={"name": "Renamed investigation", "description": "Reviewed by analyst"},
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "Renamed investigation"
    assert updated.json()["description"] == "Reviewed by analyst"
    assert updated.json()["dataset_id"] == original_dataset_id
    assert updated.json()["analysis"] == original_analysis
    assert "flow_records" not in updated.json()
    assert updated.json()["metadata_updates"][-1]["changes"]["name"]["from"] == "historical"

    history = client.get(
        "/api/v1/analysis-jobs",
        params={"search": "reviewed", "source_type": "SENSOR_CAPTURE"},
    ).json()
    assert history["total"] == 1
    assert "flow_records" not in history["items"][0]
    assert history["items"][0]["candidate_count"] == 1

    assert client.delete(f"/api/v1/analysis-jobs/{job['id']}").status_code == 204
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}").status_code == 404
    assert client.get(f"/api/v1/pcap-exports/{export['id']}").status_code == 404


def test_hybrid_queued_export_blocks_parent_delete_until_cancelled() -> None:
    repository = MemoryRepository()
    client = api(repository)
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="history-async-delete"),
    ).json()

    export = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]})
    assert export.status_code == 202
    blocked = client.delete(f"/api/v1/analysis-jobs/{job['id']}")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "JOB_HAS_ACTIVE_PCAP_EXPORT"

    cancelled = client.post(f"/api/v1/pcap-exports/{export.json()['id']}/cancel", json={})
    assert cancelled.status_code == 200
    assert client.delete(f"/api/v1/analysis-jobs/{job['id']}").status_code == 204
    assert client.get(f"/api/v1/pcap-exports/{export.json()['id']}").status_code == 404


def test_async_export_contract_headers_idempotency_alias_and_active_fields() -> None:
    repository = MemoryRepository()
    settings = Settings(environment="test")
    client = api(repository, settings=settings)
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="async-contract"),
    ).json()
    repository.jobs[job["id"]]["flow_records"] = [
        _legacy_packet_record(_udp_packet("10.0.0.1", "203.0.113.77", 50001, 1), 0)
    ]

    conflict = client.post(
        "/api/v1/pcap-exports",
        headers={"Idempotency-Key": "header-key"},
        json={"job_id": job["id"], "idempotency_key": "body-key"},
    )
    assert conflict.status_code == 422
    assert conflict.json()["error"]["code"] == "PCAP_EXPORT_IDEMPOTENCY_KEY_CONFLICT"

    accepted = client.post(
        "/api/v1/pcap-exports",
        headers={"Idempotency-Key": "same-key"},
        json={"job_id": job["id"], "idempotency_key": "same-key"},
    )
    body = accepted.json()
    assert accepted.status_code == 202
    assert accepted.headers["location"] == f"/api/v1/pcap-exports/{body['id']}"
    assert accepted.headers["retry-after"] == "1"
    assert body["status"] == "QUEUED"
    assert body["execution_mode"] == "ASYNC"
    assert body["status_url"] == accepted.headers["location"]
    assert body["download_url"] is None
    for field in ("sha256", "size_bytes", "capture_format", "filename"):
        assert body[field] is None

    status = client.get(accepted.headers["location"])
    assert status.status_code == 200
    assert status.json() == body

    assert create_pcap_export_worker(repository, settings).run_once() is True
    completed = client.get(accepted.headers["location"])
    assert completed.status_code == 200
    assert completed.json()["status"] == "COMPLETED"
    assert completed.json()["download_url"] == f"{accepted.headers['location']}/download"
    download = client.get(completed.json()["download_url"])
    assert download.status_code == 200
    assert download.content


def test_queue_full_rejects_only_new_work_after_replay_lookup() -> None:
    client = api(
        MemoryRepository(),
        settings=Settings(
            environment="test",
            pcap_export_queue_capacity=1,
            pcap_export_async_worker_concurrency=1,
            pcap_export_per_principal_active_limit=2,
        ),
    )
    first_job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="queue-first"),
    ).json()
    second_job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="queue-second"),
    ).json()
    first = client.post(
        "/api/v1/pcap-exports",
        headers={"Idempotency-Key": "replay-key"},
        json={"job_id": first_job["id"]},
    )
    replay = client.post(
        "/api/v1/pcap-exports",
        headers={"Idempotency-Key": "replay-key"},
        json={"job_id": first_job["id"]},
    )
    rejected = client.post("/api/v1/pcap-exports", json={"job_id": second_job["id"]})

    assert first.status_code == 202
    assert replay.status_code == 202
    assert replay.json()["id"] == first.json()["id"]
    assert replay.headers["location"] == first.headers["location"]
    assert rejected.status_code == 429
    assert rejected.headers["retry-after"] == "1"
    assert rejected.json()["error"]["code"] == "PCAP_EXPORT_QUEUE_FULL"


def test_async_idempotent_replay_bypasses_source_snapshot_outage() -> None:
    class SnapshotOutageAfterAdmissionRepository(MemoryRepository):
        def __init__(self) -> None:
            super().__init__()
            self.snapshot_calls = 0

        def snapshot_pcap_export_source(
            self,
            job_id: str,
            canonical_request: dict[str, Any],
            effective_limits: dict[str, int],
        ) -> dict[str, Any] | None:
            self.snapshot_calls += 1
            if self.snapshot_calls > 1:
                raise ExportQueueStorageError("snapshot unavailable")
            return super().snapshot_pcap_export_source(job_id, canonical_request, effective_limits)

    repository = SnapshotOutageAfterAdmissionRepository()
    client = api(repository)
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="async-replay-snapshot-outage"),
    ).json()
    request = {"job_id": job["id"], "idempotency_key": "async-replay-snapshot-outage"}

    accepted = client.post("/api/v1/pcap-exports", json=request)
    replay = client.post("/api/v1/pcap-exports", json=request)

    assert accepted.status_code == 202
    assert replay.status_code == 202
    assert replay.json()["id"] == accepted.json()["id"]
    assert replay.headers["location"] == accepted.headers["location"]
    assert replay.headers["retry-after"] == "1"
    assert repository.snapshot_calls == 1

    cancelled = client.post(f"{accepted.headers['location']}/cancel", json={})
    assert cancelled.status_code == 200
    terminal_replay = client.post("/api/v1/pcap-exports", json=request)

    assert terminal_replay.status_code == 200
    assert terminal_replay.json()["id"] == accepted.json()["id"]
    assert terminal_replay.json()["status"] == "CANCELLED"
    assert terminal_replay.headers["location"] == accepted.headers["location"]
    assert "retry-after" not in terminal_replay.headers
    assert repository.snapshot_calls == 1


def test_async_idempotent_replay_survives_source_deletion() -> None:
    repository = MemoryRepository()
    client = api(repository)
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="async-replay-source-deleted"),
    ).json()
    request = {"job_id": job["id"], "idempotency_key": "async-replay-source-deleted"}
    accepted = client.post("/api/v1/pcap-exports", json=request)
    repository.jobs.pop(job["id"])

    replay = client.post("/api/v1/pcap-exports", json=request)

    assert replay.status_code == 202
    assert replay.json()["id"] == accepted.json()["id"]
    assert replay.headers["location"] == accepted.headers["location"]
    assert replay.headers["retry-after"] == "1"


def test_async_idempotent_lookup_storage_outage_is_sanitized() -> None:
    class LookupOutageRepository(MemoryRepository):
        fail_lookup = False

        def find_pcap_export_job(
            self,
            principal_scope: str,
            idempotency_key: str,
            request_fingerprint: str,
        ) -> dict[str, Any] | None:
            if self.fail_lookup:
                raise ExportQueueStorageError("private lifecycle storage failure")
            return super().find_pcap_export_job(
                principal_scope, idempotency_key, request_fingerprint
            )

    repository = LookupOutageRepository()
    client = api(repository)
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="async-replay-lookup-outage"),
    ).json()
    request = {"job_id": job["id"], "idempotency_key": "async-replay-lookup-outage"}
    assert client.post("/api/v1/pcap-exports", json=request).status_code == 202
    repository.fail_lookup = True

    replay = client.post("/api/v1/pcap-exports", json=request)

    assert replay.status_code == 503
    assert replay.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"
    assert "private" not in replay.text


def test_sync_idempotency_replays_completed_artifact_without_second_execution() -> None:
    class CountingRepository(MemoryRepository):
        def __init__(self) -> None:
            super().__init__()
            self.saves = 0
            self.reads = 0

        def save_export_stream(
            self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
        ) -> dict[str, Any] | None:
            self.saves += 1
            return super().save_export_stream(export, chunks, size_hint=size_hint)

        def open_export_stream(self, *args: Any, **kwargs: Any) -> Any:
            self.reads += 1
            return super().open_export_stream(*args, **kwargs)

    repository = CountingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Sync idem", "filename": "sync-idem.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    request = {"job_id": upload["id"], "idempotency_key": "sync-idem"}

    first = client.post("/api/v1/pcap-exports", json=request)
    replay = client.post("/api/v1/pcap-exports", json=request)
    conflict = client.post(
        "/api/v1/pcap-exports",
        json={**request, "protocol": "UDP"},
    )

    assert first.status_code == replay.status_code == 201
    assert replay.json()["id"] == first.json()["id"]
    assert replay.json()["sha256"] == first.json()["sha256"]
    assert repository.saves == 1
    assert repository.reads == 0
    assert conflict.status_code == 422
    assert conflict.json()["error"]["code"] == "PCAP_EXPORT_IDEMPOTENCY_CONFLICT"


def test_sync_storage_failure_terminalizes_lifecycle_and_keyed_replay_is_immediate() -> None:
    class FailingRepository(MemoryRepository):
        def save_export_stream(
            self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
        ) -> dict[str, Any] | None:
            raise ArtifactStorageError("private storage outage")

    repository = FailingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Sync failure", "filename": "sync-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    request = {"job_id": upload["id"], "idempotency_key": "sync-failure"}

    failed = client.post("/api/v1/pcap-exports", json=request)
    assert failed.status_code == 503
    assert failed.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"
    assert repository.count_pcap_export_jobs_by_status() == {"QUEUED": 0, "RUNNING": 0}
    lifecycle = next(iter(repository.pcap_export_jobs.values()))
    assert lifecycle["status"] == "FAILED"
    assert lifecycle["lease_token"] is None
    assert lifecycle["lease_expires_at"] is None
    assert repository.exports == {}

    replay = client.post("/api/v1/pcap-exports", json=request)
    assert replay.status_code == 201
    assert replay.json()["status"] == "FAILED"
    assert replay.json()["error_code"] == "PCAP_EXPORT_STORAGE_ERROR"


def test_sync_cancellation_winning_completion_compensates_staged_artifact() -> None:
    class CancellationRaceRepository(MemoryRepository):
        def complete_pcap_export_job(self, export_id: str, **kwargs: Any) -> bool:
            with self._lock:
                self.pcap_export_jobs[export_id]["cancellation_requested"] = True
            return super().complete_pcap_export_job(export_id, **kwargs)

    repository = CancellationRaceRepository()
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_execution_mode="sync_only"), repository)
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Sync cancellation race", "filename": "sync-cancel.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_EXPORT_CANCELLED"
    lifecycle = next(iter(repository.pcap_export_jobs.values()))
    assert lifecycle["status"] == "CANCELLED"
    assert repository.exports == {}
    assert repository.export_content == {}


def test_sync_unexpected_completion_failure_compensates_staged_artifact() -> None:
    class CompletionFailureRepository(MemoryRepository):
        def complete_pcap_export_job(self, _export_id: str, **_kwargs: Any) -> bool:
            raise RuntimeError("unexpected completion failure")

    repository = CompletionFailureRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_execution_mode="sync_only"), repository
        ),
        raise_server_exceptions=False,
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Sync completion failure", "filename": "sync-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})

    assert response.status_code == 500
    lifecycle = next(iter(repository.pcap_export_jobs.values()))
    assert lifecycle["status"] == "FAILED"
    assert repository.exports == {}
    assert repository.export_content == {}


def test_sync_admission_maps_source_deleted_after_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    original_enqueue = repository.enqueue_pcap_export_job

    def delete_then_enqueue(job: dict[str, Any], **kwargs: Any):
        assert repository.delete_job(str(job["job_id"])) is True
        return original_enqueue(job, **kwargs)

    monkeypatch.setattr(repository, "enqueue_pcap_export_job", delete_then_enqueue)
    client = api(repository)
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Sync admission race", "filename": "sync-admission.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_GENERATION_CHANGED"
    assert repository.pcap_export_jobs == {}
    assert repository.exports == {}


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_async_admission_rejects_source_deleted_after_snapshot(
    repository_kind: str, tmp_path, monkeypatch
) -> None:
    repository: Any = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "admission-race.db")
    )
    original_enqueue = repository.enqueue_pcap_export_job

    def delete_then_enqueue(job: dict[str, Any], **kwargs: Any):
        assert repository.delete_job(str(job["job_id"])) is True
        return original_enqueue(job, **kwargs)

    monkeypatch.setattr(repository, "enqueue_pcap_export_job", delete_then_enqueue)
    client = api(repository)  # type: ignore[arg-type]
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key=f"admission-race-{repository_kind}"),
    ).json()

    response = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_GENERATION_CHANGED"
    assert repository.get_pcap_export_job(response.json().get("id", "missing")) is None
    assert repository.count_pcap_export_jobs_by_status() == {"QUEUED": 0, "RUNNING": 0}


def test_concurrent_keyed_sync_requests_execute_once() -> None:
    class BlockingRepository(MemoryRepository):
        def __init__(self) -> None:
            super().__init__()
            self.saves = 0
            self.entered = threading.Event()
            self.release = threading.Event()

        def save_export_stream(
            self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
        ) -> dict[str, Any] | None:
            self.saves += 1
            self.entered.set()
            assert self.release.wait(5)
            return super().save_export_stream(export, chunks, size_hint=size_hint)

    repository = BlockingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Concurrent sync", "filename": "concurrent-sync.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    request = {"job_id": upload["id"], "idempotency_key": "concurrent-sync"}

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.post, "/api/v1/pcap-exports", json=request)
        assert repository.entered.wait(5)
        second = pool.submit(client.post, "/api/v1/pcap-exports", json=request)
        repository.release.set()
        responses = [first.result(timeout=5), second.result(timeout=5)]

    assert [item.status_code for item in responses] == [201, 201]
    assert responses[0].json()["id"] == responses[1].json()["id"]
    assert repository.saves == 1


def test_unkeyed_sync_busy_rejection_allocates_nothing_and_does_not_open_source() -> None:
    class BlockingRepository(MemoryRepository):
        def __init__(self) -> None:
            super().__init__()
            self.opens = 0
            self.entered = threading.Event()
            self.release = threading.Event()

        def open_job_capture(self, job_id: str) -> CaptureSource | None:
            self.opens += 1
            return super().open_job_capture(job_id)

        def save_export_stream(
            self, export: dict[str, Any], chunks: Iterable[bytes], *, size_hint: int
        ) -> dict[str, Any] | None:
            self.entered.set()
            assert self.release.wait(5)
            return super().save_export_stream(export, chunks, size_hint=size_hint)

    repository = BlockingRepository()
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_max_concurrent=1), repository)
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Busy sync", "filename": "busy-sync.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    repository.opens = 0

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.post, "/api/v1/pcap-exports", json={"job_id": upload["id"]})
        assert repository.entered.wait(5)
        rejected = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})
        assert rejected.status_code == 429
        assert rejected.json()["error"]["code"] == "PCAP_EXPORT_BUSY"
        assert len(repository.pcap_export_jobs) == 1
        assert repository.opens == 1
        repository.release.set()
        assert first.result(timeout=5).status_code == 201


def test_async_cancel_and_download_are_state_conditional() -> None:
    client = api(MemoryRepository())
    job = client.post(
        "/api/v1/analysis-jobs",
        json=payload(flows=synthetic_flows(), key="async-cancel-download"),
    ).json()
    accepted = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]})
    export_id = accepted.json()["id"]

    pending_download = client.get(f"/api/v1/pcap-exports/{export_id}/download")
    assert pending_download.status_code == 409
    pending_error = pending_download.json()["error"]
    assert pending_error["code"] == "PCAP_EXPORT_NOT_READY"
    assert pending_error["message"] == "PCAP export is not ready"
    assert pending_error["details"] == {"status": "QUEUED"}

    cancelled = client.post(
        f"/api/v1/pcap-exports/{export_id}/cancel",
        json={"reason": "no longer needed"},
    )
    assert cancelled.status_code == 200
    assert cancelled.json() == {
        "cancelled": True,
        "cancellation_requested": True,
        "status": "CANCELLED",
    }
    repeated = client.post(f"/api/v1/pcap-exports/{export_id}/cancel", json={})
    assert repeated.status_code == 200
    assert repeated.json() == cancelled.json()
    cancelled_download = client.get(f"/api/v1/pcap-exports/{export_id}/download")
    assert cancelled_download.status_code == 409
    assert cancelled_download.json()["error"]["code"] == "PCAP_EXPORT_CANCELLED"


def test_analysis_history_rejects_immutable_updates_and_active_deletion() -> None:
    client = api()
    job = client.post("/api/v1/analysis-jobs", json=payload(key="active-history")).json()

    immutable = client.patch(f"/api/v1/analysis-jobs/{job['id']}", json={"status": "COMPLETED"})
    assert immutable.status_code == 422
    deletion = client.delete(f"/api/v1/analysis-jobs/{job['id']}")
    assert deletion.status_code == 409
    assert deletion.json()["error"]["code"] == "JOB_NOT_TERMINAL"


def test_pcap_upload_runs_existing_detectors_and_appears_in_history() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    capture = _pcap()
    response = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={
            "name": "Uploaded investigation",
            "filename": "../../capture.pcap",
            "internal_networks": "10.0.0.0/8",
            "minimum_candidate_score": 0,
            "minimum_distinct_clients": 3,
            "detector_weights": '{"common_destination":0.25}',
        },
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )

    assert response.status_code == 201
    job = response.json()
    assert "flow_records" not in job
    assert job["status"] == "COMPLETED"
    assert job["mode"] == "PCAP_UPLOAD"
    assert job["source_type"] == "PCAP_UPLOAD"
    assert job["source"]["filename"] == "capture.pcap"
    assert job["source"]["capture_format"] == "PCAP"
    assert job["source"]["captured_packet_count"] == 18
    assert job["source"]["parsed_packet_count"] == 18
    assert job["flow_count"] == 18
    assert job["packet_count"] == 18
    assert job["analysis"]["detector_weights"]["common_destination"] == 0.25
    stored = repository.get_job(job["id"])
    assert stored is not None
    assert all("raw_packet_hex" not in record for record in stored["flow_records"])
    assert repository.get_job_capture(job["id"]) == capture

    candidates = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()
    assert candidates["total"] == 1
    assert candidates["items"][0]["candidate_ip"] == "203.0.113.77"
    history = client.get("/api/v1/analysis-jobs", params={"source_type": "PCAP_UPLOAD"}).json()
    assert history["items"][0]["source"]["sha256"] == job["source"]["sha256"]
    exported = client.post("/api/v1/pcap-exports", json={"job_id": job["id"]}).json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 18

    rerun = client.post(
        f"/api/v1/analysis-jobs/{job['id']}/reanalyze",
        json={"idempotency_key": "uploaded-rerun"},
    )
    assert rerun.status_code == 201
    assert rerun.json()["source_type"] == "PCAP_UPLOAD"
    assert rerun.json()["source"]["sha256"] == job["source"]["sha256"]


def test_pcap_export_returns_valid_packet_prefix_at_output_limit(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    output_limit = 24 + 16 + len(first_packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_max_bytes=output_limit),
            repository,
        )
    )
    capture = _pcap()
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Partial export", "filename": "partial.pcap"},
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert upload.status_code == 201

    monkeypatch.setattr(
        repository,
        "save_export",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("streaming save used compatibility wrapper")
        ),
    )
    monkeypatch.setattr(
        repository,
        "get_export",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("streaming read used compatibility wrapper")
        ),
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": upload.json()["id"]},
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 18
    assert exported["exported_packet_count"] == 1
    assert exported["omitted_packet_count"] == 17
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["OUTPUT_BYTE_LIMIT"]
    assert exported["output_byte_limit"] == output_limit
    assert exported["size_bytes"] == output_limit
    assert "-partial-" in exported["filename"]
    original_open = repository.open_export_stream
    monkeypatch.setattr(
        repository,
        "open_export_stream",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("metadata GET opened artifact content")
        ),
    )
    metadata_response = client.get(f"/api/v1/pcap-exports/{exported['id']}")
    assert metadata_response.status_code == 200
    monkeypatch.setattr(repository, "open_export_stream", original_open)
    download = client.get(
        f"/api/v1/pcap-exports/{exported['id']}/download",
        headers={"Range": "bytes=1-2"},
    )
    assert download.status_code == 200
    assert len(download.content) == output_limit
    assert download.headers["content-length"] == str(output_limit)
    assert download.headers["x-content-type-options"] == "nosniff"
    assert "accept-ranges" not in download.headers
    assert "content-range" not in download.headers
    assert download.headers["content-disposition"] == (
        f'attachment; filename="{exported["filename"]}"'
    )
    assert exported["sha256"] == hashlib.sha256(download.content).hexdigest()
    reparsed = parse_pcap(
        download.content,
        sensor_id="download",
        internal_networks=["10.0.0.0/8"],
        max_packets=10,
    )
    assert reparsed.captured_packet_count == 1

    repository.export_content[exported["id"]] = b"corrupt"
    corrupted = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert corrupted.status_code == 409
    assert corrupted.json()["error"]["code"] == "PCAP_EXPORT_INTEGRITY_ERROR"

    repository.export_content.pop(exported["id"])
    missing = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert missing.status_code == 409
    assert missing.json()["error"]["code"] == "PCAP_EXPORT_INTEGRITY_ERROR"


def test_download_integrity_error_precedes_staging_spool_close_failure(
    monkeypatch: Any,
) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    stored = repository.save_export_stream(
        {
            "id": "export-close-fault",
            "job_id": "job-1",
            "status": "COMPLETED",
            "capture_format": "PCAP",
            "filename": "safe.pcap",
        },
        iter((b"expected",)),
        size_hint=8,
    )
    assert stored is not None
    repository.export_content["export-close-fault"] = b"corrupt!"

    class CloseFaultSpool(io.BytesIO):
        def close(self) -> None:
            super().close()
            raise OSError("private spool close fault")

    monkeypatch.setattr(
        controller_app.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: CloseFaultSpool(),
    )
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get("/api/v1/pcap-exports/export-close-fault/download")

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_EXPORT_INTEGRITY_ERROR"
    assert "private" not in response.text


def test_download_seek_failure_is_sanitized_as_storage_error(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {
            "id": "export-seek-fault",
            "job_id": "job-1",
            "status": "COMPLETED",
            "capture_format": "PCAP",
            "filename": "safe.pcap",
        },
        iter((b"valid",)),
        size_hint=5,
    )

    class SeekFaultSpool(io.BytesIO):
        def seek(self, *_args: object, **_kwargs: object) -> int:
            raise RuntimeError("private seek fault")

    monkeypatch.setattr(
        controller_app.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: SeekFaultSpool(),
    )
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get("/api/v1/pcap-exports/export-seek-fault/download")

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"
    assert "private" not in response.text


def test_download_rejects_short_spool_write_before_response(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {
            "id": "export-short-write",
            "job_id": "job-1",
            "status": "COMPLETED",
            "capture_format": "PCAP",
            "filename": "safe.pcap",
        },
        iter((b"valid",)),
        size_hint=5,
    )

    class ShortWriteSpool(io.BytesIO):
        def write(self, data: bytes) -> int:
            return super().write(data[:-1])

    monkeypatch.setattr(
        controller_app.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: ShortWriteSpool(),
    )
    response = TestClient(create_app(Settings(environment="test"), repository)).get(
        "/api/v1/pcap-exports/export-short-write/download"
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"


def test_download_flushes_validated_spool_before_rewind(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {
            "id": "export-flush",
            "job_id": "job-1",
            "status": "COMPLETED",
            "capture_format": "PCAP",
            "filename": "safe.pcap",
        },
        iter((b"valid",)),
        size_hint=5,
    )

    class FlushRequiredSpool(io.BytesIO):
        flushed = False

        def flush(self) -> None:
            self.flushed = True
            super().flush()

        def seek(self, *args: object, **kwargs: object) -> int:
            if not self.flushed:
                raise OSError("rewound before flush")
            return super().seek(*args, **kwargs)

    monkeypatch.setattr(
        controller_app.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: FlushRequiredSpool(),
    )
    response = TestClient(create_app(Settings(environment="test"), repository)).get(
        "/api/v1/pcap-exports/export-flush/download"
    )

    assert response.status_code == 200
    assert response.content == b"valid"


def test_download_second_pass_read_fault_fails_before_success_response(monkeypatch: Any) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {
            "id": "export-second-read-fault",
            "job_id": "job-1",
            "status": "COMPLETED",
            "capture_format": "PCAP",
            "filename": "safe.pcap",
        },
        iter((b"valid",)),
        size_hint=5,
    )

    class SecondPassFaultSpool(io.BytesIO):
        rewinds = 0

        def seek(self, offset: int, whence: int = 0) -> int:
            result = super().seek(offset, whence)
            if offset == 0 and whence == 0:
                self.rewinds += 1
            return result

        def read(self, size: int | None = -1) -> bytes:
            effective_size = -1 if size is None else size
            if self.rewinds == 1 and self.tell() >= 3:
                raise OSError("private second-pass read fault")
            if self.rewinds == 1:
                return super().read(min(effective_size, 3))
            return super().read(effective_size)

    monkeypatch.setattr(
        controller_app.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: SecondPassFaultSpool(),
    )
    response = TestClient(create_app(Settings(environment="test"), repository)).get(
        "/api/v1/pcap-exports/export-second-read-fault/download"
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"
    assert "private" not in response.text

    messages: list[dict[str, Any]] = []
    request_sent = False

    async def receive() -> dict[str, Any]:
        nonlocal request_sent
        if not request_sent:
            request_sent = True
            return {"type": "http.request", "body": b"", "more_body": False}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        messages.append(message)

    application = create_app(Settings(environment="test"), repository)
    asyncio.run(
        application(
            {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": "/api/v1/pcap-exports/export-second-read-fault/download",
                "raw_path": b"/api/v1/pcap-exports/export-second-read-fault/download",
                "query_string": b"",
                "headers": [],
                "client": ("127.0.0.1", 1234),
                "server": ("testserver", 80),
            },
            receive,
            send,
        )
    )
    starts = [message for message in messages if message["type"] == "http.response.start"]
    bodies = [message for message in messages if message["type"] == "http.response.body"]
    assert [message["status"] for message in starts] == [503]
    assert not any(message.get("body") == b"val" for message in bodies)


@pytest.mark.parametrize("fault", ["short", "extra", "corrupt"])
def test_download_rejects_second_pass_spool_integrity_faults(monkeypatch: Any, fault: str) -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {
            "id": "export-local-integrity",
            "job_id": "job-1",
            "status": "COMPLETED",
            "capture_format": "PCAP",
            "filename": "safe.pcap",
        },
        iter((b"valid",)),
        size_hint=5,
    )

    class IntegrityFaultSpool(io.BytesIO):
        rewinds = 0
        fault_emitted = False

        def seek(self, offset: int, whence: int = 0) -> int:
            result = super().seek(offset, whence)
            if offset == 0 and whence == 0:
                self.rewinds += 1
            return result

        def read(self, size: int | None = -1) -> bytes:
            effective_size = -1 if size is None else size
            data = super().read(effective_size)
            if self.rewinds != 1:
                return data
            if fault == "short":
                return data[:3]
            if self.fault_emitted:
                return data
            self.fault_emitted = True
            if fault == "extra":
                return data + b"x"
            return b"X" + data[1:]

    monkeypatch.setattr(
        controller_app.tempfile,
        "SpooledTemporaryFile",
        lambda **_kwargs: IntegrityFaultSpool(),
    )
    response = TestClient(create_app(Settings(environment="test"), repository)).get(
        "/api/v1/pcap-exports/export-local-integrity/download"
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_EXPORT_INTEGRITY_ERROR"


def test_sqlite_metadata_database_faults_are_sanitized_for_get_and_download(tmp_path: Any) -> None:
    repository = SQLiteRepository(tmp_path / "closed-download.db")
    client = TestClient(create_app(Settings(environment="test"), repository))  # type: ignore[arg-type]
    repository.connection.close()

    for path in (
        "/api/v1/pcap-exports/export-1",
        "/api/v1/pcap-exports/export-1/download",
    ):
        response = client.get(path)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"


def test_pcap_export_preserves_packet_prefix_at_scan_packet_limit() -> None:
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_packets=2),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Packet bounded export", "filename": "packets.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 2
    assert exported["exported_packet_count"] == 2
    assert exported["scanned_packet_count"] == 2
    assert exported["source_scan_packet_limit"] == 2
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_PACKET_LIMIT"]


def test_partial_source_scan_without_a_prefix_match_is_not_reported_as_no_match() -> None:
    repository = MemoryRepository()
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_scan_max_packets=1), repository)
    )
    packets = [
        _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1),
        _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2),
    ]
    capture = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, packet in enumerate(packets):
        capture.extend(struct.pack("<IIII", 1_700_000_000 + index, 0, len(packet), len(packet)))
        capture.extend(packet)
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Partial no-match", "filename": "partial-no-match.pcap"},
        content=bytes(capture),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": upload.json()["id"],
            "include_filters": [{"candidate_ip": "203.0.113.88"}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["error_code"] == "PCAP_SOURCE_SCAN_INCOMPLETE"
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_PACKET_LIMIT"]


def test_pcap_export_rejects_retained_segment_size_mismatch() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    capture = _pcap()
    repository.create_job(
        {
            "id": "size-mismatch-export",
            "idempotency_key": "size-mismatch-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    repository.save_sensor_pcap(
        {
            "id": "size-mismatch-segment",
            "sensor_id": "sensor-a",
            "analysis_job_id": "size-mismatch-export",
            "filename": "segment.pcap",
            "size_bytes": len(capture),
            "sha256": hashlib.sha256(capture).hexdigest(),
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )
    repository.sensor_pcaps["size-mismatch-segment"]["size_bytes"] = len(capture) - 1

    response = client.post("/api/v1/pcap-exports", json={"job_id": "size-mismatch-export"})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"


def test_pcap_export_rejects_canonical_capture_without_a_trusted_digest() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Missing digest", "filename": "missing-digest.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert upload.status_code == 201
    job_id = upload.json()["id"]
    job = repository.get_job(job_id)
    assert job is not None
    job["source"].pop("sha256")
    repository.save_job(job)

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": job_id},
    )

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"


def test_streaming_export_rejects_invalid_canonical_digest_without_leaking_source() -> None:
    class TrackingRepository(MemoryRepository):
        opened_source: CaptureSource | None = None

        def open_job_capture(self, job_id: str):
            self.opened_source = super().open_job_capture(job_id)
            return self.opened_source

    repository = TrackingRepository()
    client = TestClient(
        create_app(Settings(environment="test"), repository), raise_server_exceptions=False
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Invalid digest", "filename": "invalid-digest.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]
    job = repository.get_job(job_id)
    assert job is not None
    job["source"]["sha256"] = "short"
    repository.save_job(job)

    response = client.post("/api/v1/pcap-exports", json={"job_id": job_id})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"
    assert repository.opened_source is None or repository.opened_source.closed
    assert repository.exports == {}


def test_streaming_factory_failure_closes_once_without_masking_primary(
    monkeypatch: Any,
) -> None:
    class CloseFails(io.BytesIO):
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            raise OSError("close failure")

    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Factory failure", "filename": "factory-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]
    stream = CloseFails(repository.job_captures[job_id])
    source = CaptureSource(stream, "factory-failure-v1")
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: source)

    def fail_factory(*args: Any, **kwargs: Any) -> Any:
        raise controller_app.ApiError(
            409, "PCAP_SOURCE_INTEGRITY_ERROR", "factory validation failed"
        )

    monkeypatch.setattr(controller_app, "open_bounded_verified_capture", fail_factory)

    response = client.post("/api/v1/pcap-exports", json={"job_id": job_id})

    assert response.status_code == 409
    assert response.json()["error"]["message"] == "factory validation failed"
    assert source.closed
    assert stream.close_calls == 1
    assert repository.exports == {}


def test_streaming_decoder_factory_failure_closes_source_once_without_publication(
    monkeypatch: Any,
) -> None:
    class CountedClose(io.BytesIO):
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            super().close()

    repository = MemoryRepository()
    upload_client = TestClient(create_app(Settings(environment="test"), repository))
    upload = upload_client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Decoder failure", "filename": "decoder-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]
    stream = CountedClose(repository.job_captures[job_id])
    source = CaptureSource(stream, "decoder-failure-v1")
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: source)
    monkeypatch.setattr(
        controller_app,
        "open_export_capture",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("decoder dependency failed")),
    )
    client = TestClient(
        create_app(Settings(environment="test"), repository), raise_server_exceptions=False
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": job_id})

    assert response.status_code == 500
    assert source.closed
    assert stream.close_calls == 1
    assert repository.exports == {}
    assert repository.export_content == {}


def test_streaming_predicate_failure_closes_source_once_without_publication(
    monkeypatch: Any,
) -> None:
    class CountedClose(io.BytesIO):
        close_calls = 0

        def close(self) -> None:
            self.close_calls += 1
            super().close()

    repository = MemoryRepository()
    upload_client = TestClient(create_app(Settings(environment="test"), repository))
    upload = upload_client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Predicate failure", "filename": "predicate-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]
    stream = CountedClose(repository.job_captures[job_id])
    source = CaptureSource(stream, "predicate-failure-v1")
    monkeypatch.setattr(repository, "open_job_capture", lambda _job_id: source)
    original_compile = controller_app.compile_packet_predicate

    def failing_compile(*args: Any, **kwargs: Any) -> Any:
        predicate = original_compile(*args, **kwargs)

        def fail_matches(*match_args: Any, **match_kwargs: Any) -> bool:
            raise RuntimeError("predicate evaluation failed")

        object.__setattr__(predicate, "matches", fail_matches)
        return predicate

    monkeypatch.setattr(controller_app, "compile_packet_predicate", failing_compile)
    client = TestClient(
        create_app(Settings(environment="test"), repository), raise_server_exceptions=False
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": job_id})

    assert response.status_code == 500
    assert source.closed
    assert stream.close_calls == 1
    assert repository.exports == {}
    assert repository.export_content == {}


def test_streaming_export_rejects_invalid_opened_sensor_digest_and_closes_source() -> None:
    capture = _pcap()
    digest = hashlib.sha256(capture).hexdigest()

    class InvalidOpenedMetadataRepository(MemoryRepository):
        opened_source: CaptureSource | None = None

        def open_sensor_pcap(self, segment_id: str):
            opened = super().open_sensor_pcap(segment_id)
            assert opened is not None
            metadata, source = opened
            metadata["sha256"] = "short"
            self.opened_source = source
            return metadata, source

    repository = InvalidOpenedMetadataRepository()
    repository.create_job(
        {
            "id": "invalid-opened-digest",
            "idempotency_key": "invalid-opened-digest-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    repository.save_sensor_pcap(
        {
            "id": "invalid-opened-digest-segment",
            "sensor_id": "sensor-a",
            "analysis_job_id": "invalid-opened-digest",
            "filename": "segment.pcap",
            "size_bytes": len(capture),
            "sha256": digest,
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.post("/api/v1/pcap-exports", json={"job_id": "invalid-opened-digest"})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"
    assert repository.opened_source is not None and repository.opened_source.closed
    assert repository.exports == {}


def test_pcap_export_rejects_concurrent_memory_intensive_requests() -> None:
    entered = threading.Event()
    release = threading.Event()

    class BlockingRepository(MemoryRepository):
        def open_job_capture(self, job_id: str) -> CaptureSource | None:
            source = super().open_job_capture(job_id)
            entered.set()
            release.wait(timeout=5)
            return source

    repository = BlockingRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_max_concurrent=1),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Admission", "filename": "admission.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    entered.clear()

    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(
            client.post,
            "/api/v1/pcap-exports",
            json={"job_id": upload.json()["id"]},
        )
        assert entered.wait(timeout=2)
        second = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})
        release.set()
        assert first.result(timeout=5).status_code == 201

    assert second.status_code == 429
    assert second.json()["error"]["code"] == "PCAP_EXPORT_BUSY"


def test_legacy_pcap_export_preserves_packet_prefix_at_scan_byte_limit() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 2)
    client = TestClient(
        create_app(
            Settings(
                environment="test",
                pcap_export_execution_mode="sync_only",
                pcap_export_scan_max_bytes=len(first_packet),
            ),
            repository,
        )
    )
    repository.create_job(
        {
            "id": "legacy-byte-bounded-export",
            "idempotency_key": "legacy-byte-bounded-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": [
                _legacy_packet_record(first_packet, 0),
                _legacy_packet_record(second_packet, 1),
            ],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "legacy-byte-bounded-export"})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 1
    assert exported["exported_packet_count"] == 1
    assert exported["source_total_bytes"] == len(first_packet) + len(second_packet)
    assert exported["scanned_source_bytes"] == len(first_packet)
    assert exported["scanned_packet_count"] == 1
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_legacy_fallback_calls_compiled_predicate_once_per_admitted_packet(
    monkeypatch: Any,
) -> None:
    repository = MemoryRepository()
    packets = [
        _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1),
        _udp_packet("10.0.0.2", "203.0.113.77", 50002, 2),
    ]
    repository.create_job(
        {
            "id": "legacy-predicate-count",
            "idempotency_key": "legacy-predicate-count-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": [
                _legacy_packet_record(packet, index) for index, packet in enumerate(packets)
            ],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    original_compile = controller_app.compile_packet_predicate
    predicate_calls = 0

    def counted_compile(*args: Any, **kwargs: Any) -> Any:
        predicate = original_compile(*args, **kwargs)
        original_matches = predicate.matches

        def counted_matches(*match_args: Any, **match_kwargs: Any) -> bool:
            nonlocal predicate_calls
            predicate_calls += 1
            return original_matches(*match_args, **match_kwargs)

        object.__setattr__(predicate, "matches", counted_matches)
        return predicate

    monkeypatch.setattr(controller_app, "compile_packet_predicate", counted_compile)
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_execution_mode="sync_only"), repository)
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "legacy-predicate-count"})

    assert response.status_code == 201
    assert response.json()["matched_packet_count"] == 2
    assert predicate_calls == 2


def test_legacy_fallback_matches_materialized_filter_bytes_for_nested_candidate() -> None:
    repository = MemoryRepository()
    packets = [
        _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1),
        _udp_packet("10.0.0.2", "203.0.113.77", 50002, 2),
    ]
    records = [_legacy_packet_record(packet, index) for index, packet in enumerate(packets)]
    records[1]["source_ip"] = "10.0.0.2"
    records[1]["source_port"] = 50002
    repository.create_job(
        {
            "id": "legacy-filter-differential",
            "idempotency_key": "legacy-filter-differential-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": records,
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    repository.save_candidates(
        "legacy-filter-differential",
        [{"id": "legacy-candidate", "candidate_ip": "203.0.113.77"}],
    )
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_execution_mode="sync_only"), repository)
    )
    request_filter = {
        "job_id": "legacy-filter-differential",
        "candidate_id": "legacy-candidate",
        "include_filters": [{"candidate_ip": "10.0.0.0/8", "destination_port": 443}],
        "exclude_filters": [{"source_port": 50001}],
    }

    response = client.post("/api/v1/pcap-exports", json=request_filter)

    assert response.status_code == 201
    exported = response.json()
    expected_records = filter_records(
        records,
        {
            "candidate_ip": "203.0.113.77",
            "include_filters": request_filter["include_filters"],
            "exclude_filters": request_filter["exclude_filters"],
        },
        internal_networks=["10.0.0.0/8"],
    )
    expected = build_capture_result(expected_records).content
    download = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert download.content == expected
    assert exported["matched_packet_count"] == len(expected_records) == 1


def test_legacy_fallback_preserves_invalid_raw_hex_integrity_error() -> None:
    repository = MemoryRepository()
    record = _legacy_packet_record(b"valid", 0)
    record["raw_packet_hex"] = "not-hex"
    repository.create_job(
        {
            "id": "legacy-invalid-hex",
            "idempotency_key": "legacy-invalid-hex-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": [record],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_execution_mode="sync_only"), repository)
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "legacy-invalid-hex"})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_INTEGRITY_ERROR"
    assert response.json()["error"]["message"] == (
        "retained raw packet is not valid hexadecimal data"
    )
    assert repository.exports == {}


def test_pcap_export_reports_when_output_limit_cannot_fit_a_packet() -> None:
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_max_bytes=24),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Header only export", "filename": "header-only.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["matched_packet_count"] == 18
    assert exported["exported_packet_count"] == 0
    assert exported["error_code"] == "PCAP_OUTPUT_LIMIT_TOO_SMALL"
    assert exported["truncation_reasons"] == ["OUTPUT_BYTE_LIMIT"]


def test_completed_live_job_exports_associated_sensor_pcaps_with_nested_filters() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    capture = _pcap()
    repository.create_job(
        {
            "id": "live-export-job",
            "idempotency_key": "live-export-job-key",
            "name": "Live export",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    digest = hashlib.sha256(capture).hexdigest()
    repository.save_sensor_pcap(
        {
            "id": "segment-a",
            "sensor_id": "sensor-a",
            "analysis_job_id": "live-export-job",
            "filename": "segment-a.pcap",
            "size_bytes": len(capture),
            "sha256": digest,
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )
    repository.save_sensor_pcap(
        {
            "id": "unrelated",
            "sensor_id": "sensor-a",
            "analysis_job_id": "other-job",
            "filename": "other.pcap",
            "size_bytes": len(capture),
            "sha256": digest,
            "uploaded_at": "2026-08-21T09:02:00+00:00",
        },
        capture,
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "live-export-job",
            "include_filters": [{"candidate_ip": "203.0.113.0/24", "port": 443}],
            "exclude_filters": [{"source_port": 50001}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 12
    assert exported["source_capture_count"] == 1
    download = client.get(f"/api/v1/pcap-exports/{exported['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-disposition"].endswith('.pcap"')

    no_match = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "live-export-job",
            "include_filters": [{"candidate_ip": "192.0.2.0/24"}],
        },
    )
    assert no_match.status_code == 201
    assert no_match.json()["status"] == "FAILED"
    assert no_match.json()["error_code"] == "PCAP_NO_MATCH"

    invalid = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": "live-export-job", "include_filters": [{}]},
    )
    assert invalid.status_code == 422


def test_live_export_preserves_scanned_prefix_when_source_byte_limit_is_reached() -> None:
    repository = MemoryRepository()
    capture = _pcap()
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=len(capture)),
            repository,
        )
    )
    repository.create_job(
        {
            "id": "bounded-live-export",
            "idempotency_key": "bounded-live-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    digest = hashlib.sha256(capture).hexdigest()
    for index in range(2):
        repository.save_sensor_pcap(
            {
                "id": f"bounded-segment-{index}",
                "sensor_id": "sensor-a",
                "analysis_job_id": "bounded-live-export",
                "filename": f"bounded-{index}.pcap",
                "size_bytes": len(capture),
                "sha256": digest,
                "uploaded_at": f"2026-08-21T09:0{index}:00+00:00",
            },
            capture,
        )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "bounded-live-export"})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 18
    assert exported["exported_packet_count"] == 18
    assert exported["source_capture_count"] == 2
    assert exported["scanned_source_capture_count"] == 1
    assert exported["omitted_source_capture_count"] == 1
    assert exported["source_total_bytes"] == 2 * len(capture)
    assert exported["scanned_source_bytes"] == len(capture)
    assert exported["source_scan_byte_limit"] == len(capture)
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_live_export_scans_packet_prefix_from_oversized_first_segment() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2)
    capture = _pcap_for_packets([first_packet, second_packet])
    first_packet_boundary = 24 + 16 + len(first_packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=first_packet_boundary),
            repository,
        )
    )
    repository.create_job(
        {
            "id": "oversized-first-live-segment",
            "idempotency_key": "oversized-first-live-segment-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )
    repository.save_sensor_pcap(
        {
            "id": "oversized-first-segment",
            "sensor_id": "sensor-a",
            "analysis_job_id": "oversized-first-live-segment",
            "filename": "oversized-first.pcap",
            "size_bytes": len(capture),
            "sha256": hashlib.sha256(capture).hexdigest(),
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "oversized-first-live-segment",
            "include_filters": [{"candidate_ip": "203.0.113.77"}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 1
    assert exported["scanned_source_bytes"] == first_packet_boundary
    assert exported["scanned_packet_count"] == 1
    assert exported["scanned_source_capture_count"] == 1
    assert exported["omitted_source_capture_count"] == 0
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_pcap_upload_validates_media_format_size_and_packet_limit() -> None:
    assert Settings(environment="test").pcap_upload_max_bytes == 500 * 1024 * 1024
    client = api()
    params = {"name": "bad", "filename": "capture.pcap"}
    default_too_large = client.post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={
            "content-type": "application/octet-stream",
            "content-length": str(500 * 1024 * 1024 + 1),
        },
    )
    assert default_too_large.status_code == 413
    assert default_too_large.json()["error"]["code"] == "PCAP_TOO_LARGE"

    unsupported_media = client.post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={"content-type": "text/plain"},
    )
    assert unsupported_media.status_code == 415

    malformed = client.post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=b"not-a-pcap",
        headers={"content-type": "application/octet-stream"},
    )
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "INVALID_PCAP"

    invalid_weights = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={**params, "detector_weights": "not-json"},
        content=_pcap(),
        headers={"content-type": "application/octet-stream"},
    )
    assert invalid_weights.status_code == 422
    assert invalid_weights.json()["error"]["code"] == "INVALID_DETECTOR_WEIGHTS"

    too_large = TestClient(
        create_app(Settings(environment="test", pcap_upload_max_bytes=16), MemoryRepository())
    ).post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={"content-type": "application/octet-stream"},
    )
    assert too_large.status_code == 413
    assert too_large.json()["error"]["code"] == "PCAP_TOO_LARGE"

    too_many_packets = TestClient(
        create_app(Settings(environment="test", pcap_upload_max_packets=1), MemoryRepository())
    ).post(
        "/api/v1/pcap-analysis-jobs",
        params=params,
        content=_pcap(),
        headers={"content-type": "application/octet-stream"},
    )
    assert too_many_packets.status_code == 413
    assert too_many_packets.json()["error"]["code"] == "PCAP_PACKET_LIMIT_EXCEEDED"


def test_sqlite_job_delete_cascades_candidates_and_exports(tmp_path: Any) -> None:
    repository = SQLiteRepository(tmp_path / "history.sqlite")
    job = {
        "id": "job-1",
        "idempotency_key": "delete-me",
        "status": "COMPLETED",
        "mode": "PCAP_UPLOAD",
        "flow_records": [{"source_ip": "10.0.0.1"}],
        "payload_signatures": [{"id": "signature-1", "version": 1}],
    }
    repository.create_job(job)
    repository.save_job_capture("job-1", b"source-pcap")
    repository.save_candidates("job-1", [{"id": "candidate-1"}])
    repository.save_export({"id": "export-1", "job_id": "job-1"}, b"pcap")

    assert "flow_records" not in repository.get_job_summary("job-1")  # type: ignore[operator]
    assert "payload_signatures" not in repository.get_job_summary("job-1")  # type: ignore[operator]
    assert "flow_records" not in repository.list_jobs()[0]
    assert "payload_signatures" not in repository.list_jobs()[0]
    assert repository.get_job("job-1")["flow_records"] == [  # type: ignore[index]
        {"source_ip": "10.0.0.1"}
    ]
    assert repository.get_job("job-1")["payload_signatures"] == [  # type: ignore[index]
        {"id": "signature-1", "version": 1}
    ]
    repository.save_job_metadata({**repository.get_job_summary("job-1"), "name": "renamed"})  # type: ignore[arg-type]
    assert repository.get_job("job-1")["flow_records"] == [  # type: ignore[index]
        {"source_ip": "10.0.0.1"}
    ]
    assert repository.get_job("job-1")["payload_signatures"] == [  # type: ignore[index]
        {"id": "signature-1", "version": 1}
    ]
    assert repository.delete_job("job-1") is True
    assert repository.get_job("job-1") is None
    assert repository.get_candidates("job-1") == []
    assert repository.get_export("export-1") is None
    assert repository.get_job_capture("job-1") is None
    assert repository.delete_job("job-1") is False


def test_canonical_filtered_export_scans_complete_packet_prefix_within_byte_limit() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2)
    capture = _pcap_for_packets([first_packet, second_packet])
    first_packet_boundary = 24 + 16 + len(first_packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=first_packet_boundary),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Bounded canonical", "filename": "bounded.pcap"},
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert upload.status_code == 201

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": upload.json()["id"],
            "include_filters": [{"candidate_ip": "203.0.113.77"}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["matched_packet_count"] == 1
    assert exported["exported_packet_count"] == 1
    assert exported["omitted_packet_count"] == 0
    assert exported["source_total_bytes"] == len(capture)
    assert exported["scanned_source_bytes"] == first_packet_boundary
    assert exported["scanned_packet_count"] == 1
    assert exported["scanned_source_capture_count"] == 1
    assert exported["omitted_source_capture_count"] == 0
    assert exported["truncated"] is True
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_canonical_candidate_export_matches_within_source_byte_prefix() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2)
    capture = _pcap_for_packets([first_packet, second_packet])
    first_packet_boundary = 24 + 16 + len(first_packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=first_packet_boundary),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Candidate prefix", "filename": "candidate-prefix.pcap"},
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]
    repository.save_candidates(
        job_id,
        [{"id": "candidate-prefix", "candidate_ip": "203.0.113.77"}],
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": job_id, "candidate_id": "candidate-prefix"},
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "COMPLETED"
    assert exported["candidate_id"] == "candidate-prefix"
    assert exported["matched_packet_count"] == 1
    assert exported["scanned_source_bytes"] == first_packet_boundary
    assert exported["scanned_packet_count"] == 1
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_candidate_after_source_byte_prefix_reports_incomplete_scan() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2)
    capture = _pcap_for_packets([first_packet, second_packet])
    first_packet_boundary = 24 + 16 + len(first_packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=first_packet_boundary),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Late candidate", "filename": "late-candidate.pcap"},
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]
    repository.save_candidates(
        job_id,
        [{"id": "candidate-after-prefix", "candidate_ip": "203.0.113.88"}],
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": job_id, "candidate_id": "candidate-after-prefix"},
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["error_code"] == "PCAP_SOURCE_SCAN_INCOMPLETE"
    assert exported["matched_packet_count"] == 0
    assert exported["exported_packet_count"] == 0
    assert exported["scanned_source_bytes"] == first_packet_boundary
    assert exported["scanned_packet_count"] == 1
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_source_byte_limit_below_first_packet_reports_limit_too_small() -> None:
    repository = MemoryRepository()
    packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    capture = _pcap_for_packets([packet])
    first_packet_boundary = 24 + 16 + len(packet)
    client = TestClient(
        create_app(
            Settings(environment="test", pcap_export_scan_max_bytes=first_packet_boundary - 1),
            repository,
        )
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Too small prefix", "filename": "too-small.pcap"},
        content=capture,
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["error_code"] == "PCAP_SOURCE_SCAN_LIMIT_TOO_SMALL"
    assert exported["error"] == "source scan byte limit cannot fit the first complete packet"
    assert exported["scanned_source_bytes"] == 24
    assert exported["scanned_packet_count"] == 0
    assert exported["truncation_reasons"] == ["SOURCE_BYTE_LIMIT"]


def test_export_is_not_saved_after_its_parent_job_is_deleted() -> None:
    class DeletingRepository(MemoryRepository):
        def save_export_stream(
            self,
            export: dict[str, Any],
            chunks: Iterable[bytes],
            *,
            size_hint: int,
        ) -> dict[str, Any] | None:
            job_id = str(export["job_id"])
            with self._lock:
                # Simulate an external source-generation deletion that bypasses
                # the API's active-export guard after execution has started.
                assert self.jobs.pop(job_id, None) is not None
                self.job_captures.pop(job_id, None)
            return super().save_export_stream(export, chunks, size_hint=size_hint)

    repository = DeletingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Delete race", "filename": "delete-race.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    job_id = upload.json()["id"]

    response = client.post("/api/v1/pcap-exports", json={"job_id": job_id})

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PCAP_SOURCE_UNAVAILABLE"
    assert repository.get_job(job_id) is None
    assert repository.exports == {}
    assert repository.export_content == {}


def test_spool_storage_failure_is_sanitized_and_never_saved(monkeypatch: Any) -> None:
    class SaveTrackingRepository(MemoryRepository):
        save_calls = 0

        def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any] | None:
            self.save_calls += 1
            return super().save_export(export, content)

    repository = SaveTrackingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Spool failure", "filename": "spool-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )

    def fail_writer(*args: Any, **kwargs: Any) -> Any:
        raise CaptureStorageError("private host path")

    monkeypatch.setattr(controller_app, "build_capture_to_sink", fail_writer)
    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "PCAP_EXPORT_STORAGE_ERROR"
    assert response.json()["error"]["message"] == "temporary PCAP export storage failed"
    assert "private" not in response.text
    assert repository.save_calls == 0
    assert repository.exports == {}


def test_neutral_payload_read_fault_is_sanitized_and_never_published(monkeypatch: Any) -> None:
    class SaveTrackingRepository(MemoryRepository):
        save_calls = 0

        def save_export(self, export: dict[str, Any], content: bytes) -> dict[str, Any] | None:
            self.save_calls += 1
            return super().save_export(export, content)

    class TrackingSpool(io.BytesIO):
        def __init__(self, *, fail_payload_read: bool = False, fail_close: bool = False) -> None:
            super().__init__()
            self.fail_payload_read = fail_payload_read
            self.fail_close = fail_close
            self.close_calls = 0

        def read(self, size: int | None = -1) -> bytes:
            if (
                self.fail_payload_read
                and size is not None
                and size > len(controller_pcap._SPOOL_MAGIC)
            ):
                raise OSError(5, "/private/neutral-spool")
            return super().read(size)

        def close(self) -> None:
            self.close_calls += 1
            super().close()
            if self.fail_close:
                raise OSError(5, "/private/close")

    repository = SaveTrackingRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Neutral fault", "filename": "neutral-fault.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    output = TrackingSpool(fail_close=True)
    neutral = TrackingSpool(fail_payload_read=True, fail_close=True)
    created = iter((output, neutral))
    monkeypatch.setattr(
        controller_capture_sink.tempfile, "SpooledTemporaryFile", lambda **_: next(created)
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload.json()["id"]})

    assert response.status_code == 500
    error = response.json()["error"]
    assert error["code"] == "PCAP_EXPORT_STORAGE_ERROR"
    assert error["message"] == "temporary PCAP export storage failed"
    assert "private" not in response.text
    assert output.close_calls == neutral.close_calls == 1
    assert repository.save_calls == 0
    assert repository.exports == {}
    assert repository.export_content == {}


def test_legacy_partial_scan_without_match_reports_incomplete_prefix() -> None:
    repository = MemoryRepository()
    first_packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    second_packet = _udp_packet("10.0.0.1", "203.0.113.88", 50001, 2)
    client = TestClient(
        create_app(
            Settings(
                environment="test",
                pcap_export_execution_mode="sync_only",
                pcap_export_scan_max_packets=1,
            ),
            repository,
        )
    )
    repository.create_job(
        {
            "id": "legacy-partial-no-match",
            "idempotency_key": "legacy-partial-no-match-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": False},
            "flow_records": [
                _legacy_packet_record(first_packet, 0),
                _legacy_packet_record(second_packet, 1),
            ],
            "created_at": "2026-08-21T09:00:00+00:00",
        }
    )

    response = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "legacy-partial-no-match",
            "include_filters": [{"candidate_ip": "203.0.113.88"}],
        },
    )

    assert response.status_code == 201
    exported = response.json()
    assert exported["status"] == "FAILED"
    assert exported["scanned_packet_count"] == 1
    assert exported["error_code"] == "PCAP_SOURCE_SCAN_INCOMPLETE"


def test_sqlite_export_save_rejects_a_missing_parent_and_blob(tmp_path: Any) -> None:
    repository = SQLiteRepository(tmp_path / "missing-parent.db")

    stored = repository.save_export(
        {"id": "orphan-export", "job_id": "deleted-job", "capture_format": "PCAP"},
        b"capture",
    )

    assert stored is None
    assert repository.get_export("orphan-export") is None


def test_pcap_export_emits_bounded_stage_and_volume_metrics_without_ids() -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Metrics", "filename": "metrics.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()

    exported = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]}).json()
    metrics = client.get("/api/v1/metrics").text

    for stage in ("source_read", "hash", "frame", "decode", "filter", "write", "save", "total"):
        assert (
            f'c2hunter_pcap_export_stage_duration_seconds_count{{stage="{stage}"}} 1.0' in metrics
        )
    assert 'c2hunter_pcap_export_packets_total{kind="scanned"} 18.0' in metrics
    assert 'c2hunter_pcap_export_packets_total{kind="matched"} 18.0' in metrics
    assert 'c2hunter_pcap_export_packets_total{kind="exported"} 18.0' in metrics
    assert f'c2hunter_pcap_export_bytes_total{{kind="source"}} {float(len(_pcap()))}' in metrics
    assert (
        f'c2hunter_pcap_export_bytes_total{{kind="output"}} {float(exported["size_bytes"])}'
        in metrics
    )
    assert upload["id"] not in metrics
    assert exported["id"] not in metrics


def test_missing_job_export_records_only_total_stage_metric() -> None:
    client = TestClient(create_app(Settings(environment="test"), MemoryRepository()))
    before = client.get("/api/v1/metrics").text

    response = client.post("/api/v1/pcap-exports", json={"job_id": "missing-job"})
    after = client.get("/api/v1/metrics").text

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "JOB_NOT_FOUND"
    for stage in ("source_read", "hash", "frame", "decode", "filter", "write", "save"):
        sample = f'c2hunter_pcap_export_stage_duration_seconds_count{{stage="{stage}"}}'
        assert sample not in before
        assert sample not in after
    total = 'c2hunter_pcap_export_stage_duration_seconds_count{stage="total"}'
    assert total not in before
    assert f"{total} 1.0" in after


def test_export_records_an_entered_stage_when_the_stage_raises() -> None:
    class FailingSourceRepository(MemoryRepository):
        def open_job_capture(self, job_id: str) -> CaptureSource | None:
            raise RuntimeError(f"source read failed for {job_id}")

    repository = FailingSourceRepository()
    client = TestClient(
        create_app(Settings(environment="test"), repository), raise_server_exceptions=False
    )
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Stage failure", "filename": "stage-failure.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()

    response = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})
    metrics = client.get("/api/v1/metrics").text

    assert response.status_code == 500
    for stage in ("source_read", "total"):
        assert (
            f'c2hunter_pcap_export_stage_duration_seconds_count{{stage="{stage}"}} 1.0' in metrics
        )
    for stage in ("hash", "frame", "decode", "filter", "write", "save"):
        assert (
            f'c2hunter_pcap_export_stage_duration_seconds_count{{stage="{stage}"}}' not in metrics
        )


def test_metric_failures_preserve_successful_artifact_and_original_early_error(
    monkeypatch: Any,
) -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = client.post(
        "/api/v1/pcap-analysis-jobs",
        params={"name": "Metric faults", "filename": "metric-faults.pcap"},
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    ).json()
    original_observe = controller_app.Histogram.observe
    original_inc = controller_app.Counter.inc
    injected_failures = {"observe": 0, "inc": 0}

    def fail_export_observe(metric: Any, amount: float) -> None:
        if metric._name == "c2hunter_pcap_export_stage_duration_seconds":
            injected_failures["observe"] += 1
            raise RuntimeError("stage metric unavailable")
        original_observe(metric, amount)

    def fail_export_inc(metric: Any, amount: int = 1) -> None:
        if metric._name in {
            "c2hunter_pcap_export_packets",
            "c2hunter_pcap_export_bytes",
        }:
            injected_failures["inc"] += 1
            raise RuntimeError("volume metric unavailable")
        original_inc(metric, amount)

    monkeypatch.setattr(controller_app.Histogram, "observe", fail_export_observe)
    monkeypatch.setattr(controller_app.Counter, "inc", fail_export_inc)

    successful = client.post("/api/v1/pcap-exports", json={"job_id": upload["id"]})
    missing = client.post("/api/v1/pcap-exports", json={"job_id": "missing-job"})

    assert successful.status_code == 201
    assert injected_failures["observe"] > 0
    assert injected_failures["inc"] > 0
    stored = repository.get_export(successful.json()["id"])
    assert stored is not None
    assert (
        stored[1] == client.get(f"/api/v1/pcap-exports/{successful.json()['id']}/download").content
    )
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "JOB_NOT_FOUND"


class _NarrowExportRepository(MemoryRepository):
    def __init__(self) -> None:
        super().__init__()
        self.full_job_reads: list[str] = []
        self.segment_job_reads: list[str] = []

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        self.full_job_reads.append(job_id)
        return super().get_job(job_id)

    def get_candidates(self, job_id: str) -> list[dict[str, Any]]:
        raise AssertionError(f"candidate export scanned all candidates for {job_id}")

    def list_sensor_pcaps(self) -> list[dict[str, Any]]:
        raise AssertionError("PCAP export scanned every retained segment")

    def list_sensor_pcaps_for_job(self, job_id: str) -> list[dict[str, Any]]:
        self.segment_job_reads.append(job_id)
        return super().list_sensor_pcaps_for_job(job_id)


def test_retained_segment_candidate_export_uses_only_narrow_metadata_reads() -> None:
    repository = _NarrowExportRepository()
    capture = _pcap()
    repository.create_job(
        {
            "id": "narrow-live-source",
            "idempotency_key": "narrow-live-source-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "source_type": "SENSOR_CAPTURE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "capture": {"store_pcap": True},
            "flow_records": [{"large": "must not hydrate"}],
            "payload_signatures": [{"id": "must-not-hydrate"}],
        }
    )
    repository.create_job(
        {
            "id": "narrow-live-export",
            "idempotency_key": "narrow-live-export-key",
            "status": "COMPLETED",
            "mode": "REANALYSIS",
            "parent_job_id": "narrow-live-source",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "flow_records": [{"large": "also must not hydrate"}],
        }
    )
    repository.save_candidates(
        "narrow-live-export",
        [{"id": "narrow-candidate", "candidate_ip": "203.0.113.77"}],
    )
    repository.save_sensor_pcap(
        {
            "id": "narrow-segment",
            "sensor_id": "sensor-a",
            "analysis_job_id": "narrow-live-source",
            "filename": "narrow.pcap",
            "size_bytes": len(capture),
            "sha256": hashlib.sha256(capture).hexdigest(),
            "uploaded_at": "2026-08-21T09:01:00+00:00",
        },
        capture,
    )
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": "narrow-live-export", "candidate_id": "narrow-candidate"},
    )

    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"
    assert repository.full_job_reads == []
    # Snapshotting uses the lock-safe narrow storage view directly.
    assert repository.segment_job_reads == []


def test_candidate_export_rejects_candidate_owned_by_another_job() -> None:
    repository = MemoryRepository()
    for job_id in ("requested-job", "owner-job"):
        repository.create_job(
            {
                "id": job_id,
                "idempotency_key": f"{job_id}-key",
                "status": "COMPLETED",
                "mode": "LIVE",
                "internal_networks": ["10.0.0.0/8"],
            }
        )
    repository.save_candidates(
        "owner-job", [{"id": "foreign-candidate", "candidate_ip": "203.0.113.77"}]
    )
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": "requested-job", "candidate_id": "foreign-candidate"},
    )

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "CANDIDATE_NOT_FOUND"


def test_legacy_export_hydrates_full_job_only_after_sources_are_absent() -> None:
    repository = _NarrowExportRepository()
    packet = _udp_packet("10.0.0.1", "203.0.113.77", 50001, 1)
    repository.create_job(
        {
            "id": "legacy-lazy-export",
            "idempotency_key": "legacy-lazy-export-key",
            "status": "COMPLETED",
            "mode": "LIVE",
            "sensor_ids": ["sensor-a"],
            "internal_networks": ["10.0.0.0/8"],
            "flow_records": [_legacy_packet_record(packet, 0)],
        }
    )
    client = TestClient(
        create_app(Settings(environment="test", pcap_export_execution_mode="sync_only"), repository)
    )

    response = client.post("/api/v1/pcap-exports", json={"job_id": "legacy-lazy-export"})

    assert response.status_code == 201
    assert response.json()["status"] == "COMPLETED"
    assert repository.segment_job_reads == []
    assert repository.full_job_reads == ["legacy-lazy-export"]
