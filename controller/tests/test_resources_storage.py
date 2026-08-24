import hashlib
import struct
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import (
    ArtifactAlreadyExistsError,
    ArtifactProducerError,
    ArtifactStorageError,
    MemoryRepository,
    SQLiteRepository,
)
from c2hunter_controller.retention import RetentionPolicy

START = datetime(2026, 7, 20, tzinfo=UTC)


def configured_client() -> TestClient:
    repository = MemoryRepository()
    repository.upsert_sensor({"sensor_id": "s1", "name": "sensor", "derived_status": "ONLINE"})
    return TestClient(create_app(Settings(environment="test"), repository))


def test_artifact_streaming_settings_have_separate_download_spool() -> None:
    settings = Settings(environment="test")

    assert settings.pcap_artifact_io == "streaming"
    assert settings.pcap_download_spool_max_memory_bytes == 8 * 1024 * 1024
    assert settings.pcap_download_spool_directory is None
    with pytest.raises(ValueError):
        Settings(environment="test", pcap_download_spool_max_memory_bytes=0)


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_export_stream_is_authoritative_atomic_and_immutable(
    repository_kind: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "artifact-stream.db")
    )
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    metadata = {
        "id": "export-1",
        "job_id": "job-1",
        "capture_format": "PCAP",
        "size_bytes": 999,
        "sha256": "caller-is-not-authoritative",
    }

    stored = repository.save_export_stream(metadata, iter((b"ab", b"", b"cd")), size_hint=4)

    assert stored is not None
    assert stored["size_bytes"] == 4
    assert stored["sha256"] == hashlib.sha256(b"abcd").hexdigest()
    assert repository.get_export_metadata("export-1") == stored
    opened = repository.open_export_stream("export-1")
    assert opened is not None
    opened_metadata, stream = opened
    with stream as chunks:
        assert b"".join(chunks) == b"abcd"
    assert opened_metadata == stored
    with pytest.raises(ArtifactAlreadyExistsError):
        repository.save_export_stream(metadata, iter((b"xxxx",)), size_hint=4)
    assert repository.get_export("export-1") == (stored, b"abcd")


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
@pytest.mark.parametrize(
    ("chunks", "size_hint"),
    [((b"abc",), 4), ((b"abc", b"d"), 3), ((bytearray(b"abc"),), 3)],
)
def test_export_stream_rejects_invalid_producer_without_publication(
    repository_kind: str, chunks: tuple[object, ...], size_hint: int, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / f"invalid-{size_hint}-{len(chunks)}.db")
    )
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    metadata = {"id": "bad", "job_id": "job-1", "capture_format": "PCAP"}

    with pytest.raises(ArtifactProducerError):
        repository.save_export_stream(metadata, iter(chunks), size_hint=size_hint)  # type: ignore[arg-type]

    assert repository.get_export_metadata("bad") is None
    assert repository.open_export_stream("bad") is None


def test_memory_export_stream_returns_none_if_parent_disappears_before_publication() -> None:
    repository = MemoryRepository()
    repository.save_job({"id": "job-1", "idempotency_key": "job-1", "status": "COMPLETED"})

    def chunks() -> Iterator[bytes]:
        yield b"abc"
        repository.delete_job("job-1")

    result = repository.save_export_stream(
        {"id": "raced", "job_id": "job-1", "capture_format": "PCAP"},
        chunks(),
        size_hint=3,
    )

    assert result is None
    assert repository.get_export_metadata("raced") is None


def test_sqlite_export_stream_preserves_producer_error_over_blob_close_failure(
    tmp_path: Path,
) -> None:
    repository = SQLiteRepository(tmp_path / "close-precedence.db")
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    real_connection = repository.connection

    class FailingCloseBlob:
        def __init__(self, wrapped: object) -> None:
            self.wrapped = wrapped

        def write(self, content: bytes) -> object:
            return self.wrapped.write(content)  # type: ignore[attr-defined,no-any-return]

        def close(self) -> None:
            self.wrapped.close()  # type: ignore[attr-defined]
            raise OSError("blob close failed")

    class ConnectionWrapper:
        def __getattr__(self, name: str) -> object:
            return getattr(real_connection, name)

        def blobopen(self, *args: object, **kwargs: object) -> FailingCloseBlob:
            return FailingCloseBlob(real_connection.blobopen(*args, **kwargs))  # type: ignore[arg-type]

    repository.connection = ConnectionWrapper()  # type: ignore[assignment]

    with pytest.raises(ArtifactProducerError, match="exact bytes"):
        repository.save_export_stream(
            {"id": "bad-close", "job_id": "job-1", "capture_format": "PCAP"},
            iter((bytearray(b"x"),)),  # type: ignore[arg-type]
            size_hint=1,
        )

    assert repository.get_export_metadata("bad-close") is None


def test_sqlite_export_stream_preserves_read_error_over_blob_close_failure(
    tmp_path: Path,
) -> None:
    repository = SQLiteRepository(tmp_path / "read-close-precedence.db")
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {"id": "read-fault", "job_id": "job-1", "capture_format": "PCAP"},
        iter((b"abc",)),
        size_hint=3,
    )
    real_connection = repository.connection

    class FailingReadBlob:
        def read(self, _size: int) -> bytes:
            raise OSError("blob read failed")

        def close(self) -> None:
            raise OSError("blob close failed")

    class ConnectionWrapper:
        def __getattr__(self, name: str) -> object:
            return getattr(real_connection, name)

        def blobopen(self, *_args: object, **_kwargs: object) -> FailingReadBlob:
            return FailingReadBlob()

    repository.connection = ConnectionWrapper()  # type: ignore[assignment]
    opened = repository.open_export_stream("read-fault")
    assert opened is not None
    _, stream = opened

    with pytest.raises(ArtifactStorageError, match="read failed"):
        with stream as chunks:
            list(chunks)


def test_sqlite_export_stream_releases_lock_at_eof_before_context_exit(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "eof-release.db")
    repository.save_job({"id": "job-1", "status": "COMPLETED"})
    repository.save_export_stream(
        {"id": "eof", "job_id": "job-1", "capture_format": "PCAP"},
        iter((b"abc",)),
        size_hint=3,
    )
    opened = repository.open_export_stream("eof")
    assert opened is not None
    _, stream = opened

    with stream as chunks:
        assert list(chunks) == [b"abc"]
        acquired: list[bool] = []

        def acquire_from_other_thread() -> None:
            locked = repository._lock.acquire(timeout=0.2)
            acquired.append(locked)
            if locked:
                repository._lock.release()

        worker = __import__("threading").Thread(target=acquire_from_other_thread)
        worker.start()
        worker.join()
        assert acquired == [True]


def test_sqlite_export_metadata_and_open_faults_are_typed(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "typed-read-fault.db")
    repository.connection.close()

    with pytest.raises(ArtifactStorageError, match="metadata lookup"):
        repository.get_export_metadata("missing")
    with pytest.raises(ArtifactStorageError, match="stream resolution"):
        repository.open_export_stream("missing")


def test_sqlite_export_stream_returns_none_for_missing_parent(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "missing-parent.db")

    result = repository.save_export_stream(
        {"id": "missing", "job_id": "gone", "capture_format": "PCAP"},
        iter((b"abc",)),
        size_hint=3,
    )

    assert result is None
    assert repository.get_export_metadata("missing") is None


def job_payload(key: str = "job") -> dict[str, object]:
    raw = "00112233445566778899aabb08004500001400000000400600000a000001cb007109"
    flows = [
        {
            "sensor_id": "s1",
            "timestamp": (START + timedelta(seconds=tick * 30)).isoformat(),
            "source_ip": f"10.0.0.{host}",
            "destination_ip": "203.0.113.9",
            "source_port": 50000,
            "destination_port": 4444,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "packet_count": 1,
            "total_bytes": 60,
            "payload_hash": "sig",
            "raw_packet_hex": raw,
        }
        for tick in range(6)
        for host in range(1, 5)
    ]
    return {
        "name": "pcap job",
        "idempotency_key": key,
        "sensor_ids": ["s1"],
        "mode": "HISTORICAL",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(minutes=5)).isoformat(),
        "capture": {"directions": ["OUTBOUND"], "store_pcap": True},
        "analysis": {
            "minimum_distinct_clients": 3,
            "minimum_candidate_score": 0,
            "periodicity_min_samples": 5,
        },
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": flows,
    }


def test_allowlist_crud_normalizes_and_suppresses_calculated_candidate() -> None:
    client = configured_client()
    entry = client.post(
        "/api/v1/allowlist",
        json={
            "type": "CIDR",
            "value": "203.0.113.9/24",
            "description": "lab",
            "enabled": True,
        },
    )
    assert entry.status_code == 201
    assert entry.json()["value"] == "203.0.113.0/24"
    assert client.get("/api/v1/allowlist?type=CIDR&sort=value").json()["total"] == 1
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["total"] == 0
    assert client.delete(f"/api/v1/allowlist/{entry.json()['id']}").status_code == 204


def test_allowlist_expiration_requires_timezone_and_is_stored_as_utc() -> None:
    client = configured_client()
    future = datetime.now(UTC) + timedelta(days=1)
    offset_expiration = future.astimezone(tz=timezone(timedelta(hours=9))).isoformat()

    missing_timezone = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.10",
            "description": "timezone required",
            "expires_at": future.replace(tzinfo=None).isoformat(),
        },
    )
    created = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.11",
            "description": "normalized expiration",
            "expires_at": offset_expiration,
        },
    )

    assert missing_timezone.status_code == 422
    assert created.status_code == 201
    stored_expiration = datetime.fromisoformat(created.json()["expires_at"])
    assert stored_expiration.tzinfo == UTC
    assert stored_expiration == future


def test_allowlist_accepts_utc_z_and_null_expirations() -> None:
    client = configured_client()
    future = (datetime.now(UTC) + timedelta(days=1)).replace(microsecond=0)

    utc_expiration = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.14",
            "description": "UTC expiration",
            "expires_at": future.isoformat().replace("+00:00", "Z"),
        },
    )
    no_expiration = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.15",
            "description": "no expiration",
            "expires_at": None,
        },
    )

    assert utc_expiration.status_code == 201
    assert utc_expiration.json()["expires_at"] == future.isoformat().replace("+00:00", "Z")
    assert no_expiration.status_code == 201
    assert no_expiration.json()["expires_at"] is None


def test_sqlite_allowlist_expiration_survives_reopen_as_utc(tmp_path: Path) -> None:
    path = tmp_path / "allowlist.sqlite3"
    repository = SQLiteRepository(path)
    expiration = "2099-08-13T00:30:00Z"
    repository.save_allowlist(
        {
            "id": "allowlist-utc",
            "type": "IP",
            "value": "203.0.113.16",
            "description": "persistent expiration",
            "expires_at": expiration,
            "enabled": True,
        }
    )
    repository.connection.close()

    reopened = SQLiteRepository(path)
    try:
        stored = reopened.list_allowlist()
    finally:
        reopened.connection.close()

    assert stored[0]["expires_at"] == expiration


@pytest.mark.parametrize(
    "expires_at",
    [
        "2099-08-13T09:30",
        "2099-08-13",
        "4089758200",
        4_089_758_200,
    ],
)
def test_allowlist_rejects_expiration_without_iso_timezone(expires_at: object) -> None:
    client = configured_client()

    response = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.13",
            "description": "invalid expiration format",
            "expires_at": expires_at,
        },
    )

    assert response.status_code == 422


def test_allowlist_rejects_expiration_that_is_not_in_the_future() -> None:
    client = configured_client()

    response = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.12",
            "description": "already expired",
            "expires_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat(),
        },
    )

    assert response.status_code == 422


def test_allowlist_suppresses_existing_candidate_but_preserves_audit_record() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    endpoint = f"/api/v1/analysis-jobs/{job['id']}/candidates"
    assert client.get(endpoint).json()["total"] == 1

    entry = client.post(
        "/api/v1/allowlist",
        json={
            "type": "IP",
            "value": "203.0.113.9",
            "description": "trusted infrastructure",
        },
    ).json()

    assert client.get(endpoint).json()["total"] == 0
    suppressed = client.get(endpoint, params={"include_suppressed": True}).json()
    assert suppressed["total"] == 1
    assert suppressed["items"][0]["excluded"] is True
    assert suppressed["items"][0]["suppressed_by_allowlist_id"] == entry["id"]
    assert suppressed["items"][0]["suppressed_at"]
    assert "trusted infrastructure" in suppressed["items"][0]["exclude_reason"]
    assert client.get(f"/api/v1/analysis-jobs/{job['id']}").json()["candidate_count"] == 0


def test_trusted_dns_policy_only_discounts_matching_udp_dns_traffic() -> None:
    client = configured_client()
    response = client.post(
        "/api/v1/allowlist",
        json={
            "type": "TRUSTED_DNS",
            "value": "203.0.113.9",
            "description": "corporate resolver",
        },
    )
    assert response.status_code == 201

    request = job_payload()
    flows = request["flow_records"]
    assert isinstance(flows, list)
    for flow in flows:
        assert isinstance(flow, dict)
        flow["protocol"] = "UDP"
        flow["destination_port"] = 53
    job = client.post("/api/v1/analysis-jobs", json=request).json()
    candidate = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["items"][0]

    assert candidate["candidate_ip"] == "203.0.113.9"
    assert any(item["kind"] == "PUBLIC_DNS_NTP" for item in candidate["adjustments"])

    tcp_request = job_payload()
    tcp_request["idempotency_key"] = "storage-test-tcp-dns"
    tcp_flows = tcp_request["flow_records"]
    assert isinstance(tcp_flows, list)
    for flow in tcp_flows:
        assert isinstance(flow, dict)
        flow["protocol"] = "TCP"
        flow["destination_port"] = 53
    tcp_job = client.post("/api/v1/analysis-jobs", json=tcp_request).json()
    tcp_candidate = client.get(f"/api/v1/analysis-jobs/{tcp_job['id']}/candidates").json()["items"][
        0
    ]
    assert not any(item["kind"] == "PUBLIC_DNS_NTP" for item in tcp_candidate["adjustments"])


def test_flow_review_filters_endpoints_by_ip_or_cidr() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    endpoint = f"/api/v1/analysis-jobs/{job['id']}/flows"

    assert client.get(endpoint, params={"candidate_ip": "203.0.113.9"}).json()["total"] == 24
    assert client.get(endpoint, params={"candidate_ip": "203.0.113.0/24"}).json()["total"] == 24
    assert client.get(endpoint, params={"candidate_ip": "10.0.0.0/30"}).json()["total"] == 18
    assert client.get(endpoint, params={"candidate_ip": "not-a-cidr"}).status_code == 422


def test_flow_review_filters_external_source_and_destination_ports_independently() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    endpoint = f"/api/v1/analysis-jobs/{job['id']}/flows"

    assert client.get(endpoint, params={"port": 4444}).json()["total"] == 24
    assert client.get(endpoint, params={"source_port": 50000}).json()["total"] == 24
    assert client.get(endpoint, params={"destination_port": 4444}).json()["total"] == 24
    assert client.get(endpoint, params={"source_port": 4444}).json()["total"] == 0
    assert (
        client.get(
            endpoint,
            params={"port": 4444, "source_port": 50000, "destination_port": 4444},
        ).json()["total"]
        == 24
    )


def test_pcap_export_applies_all_filters_and_streams_pcap() -> None:
    client = configured_client()
    job = client.post("/api/v1/analysis-jobs", json=job_payload()).json()
    candidate = client.get(f"/api/v1/analysis-jobs/{job['id']}/candidates").json()["items"][0]
    export = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": job["id"],
            "candidate_id": candidate["id"],
            "internal_host_ip": "10.0.0.1",
            "start_time": START.isoformat(),
            "end_time": (START + timedelta(minutes=4)).isoformat(),
            "port": 4444,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "sensor_id": "s1",
        },
    )
    assert export.status_code == 201
    body = export.json()
    assert body["status"] == "COMPLETED"
    assert body["matched_packet_count"] == 6
    fetched = client.get(f"/api/v1/pcap-exports/{body['id']}")
    assert fetched.json()["filter"]["candidate_ip"] == "203.0.113.9"
    download = client.get(f"/api/v1/pcap-exports/{body['id']}/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/vnd.tcpdump.pcap")
    assert struct.unpack("<I", download.content[:4])[0] == 0xA1B2C3D4


def test_export_validation_rejects_inverted_time_range_and_unknown_job() -> None:
    client = configured_client()
    invalid = client.post(
        "/api/v1/pcap-exports",
        json={
            "job_id": "missing",
            "start_time": (START + timedelta(seconds=1)).isoformat(),
            "end_time": START.isoformat(),
        },
    )
    assert invalid.status_code == 422
    missing = client.post("/api/v1/pcap-exports", json={"job_id": "missing"})
    assert missing.status_code == 404


def test_retention_defaults_and_expiration_cutoffs() -> None:
    policy = RetentionPolicy()
    assert policy.days == {
        "pcap": 7,
        "flow": 30,
        "result": 180,
        "audit": 365,
        "heartbeat": 30,
    }
    now = datetime(2026, 7, 20, tzinfo=UTC)
    assert policy.is_expired("pcap", now - timedelta(days=8), now)
    assert not policy.is_expired("result", now - timedelta(days=179), now)


def test_sqlite_adapter_persists_repository_contract(tmp_path: Path) -> None:
    path = tmp_path / "controller.db"
    first = SQLiteRepository(path)
    first.upsert_sensor({"sensor_id": "s1", "name": "durable"})
    first.create_group({"id": "g1", "name": "group", "sensor_ids": ["s1"]})
    first.close()
    reopened = SQLiteRepository(path)
    assert reopened.ready()
    assert reopened.get_sensor("s1")["name"] == "durable"  # type: ignore[index]
    assert reopened.list_groups()[0]["id"] == "g1"
    reopened.close()


@pytest.mark.parametrize("operation", ["update", "set-default"])
def test_sqlite_preset_default_switch_rolls_back_on_serialization_failure(
    tmp_path: Path, operation: str
) -> None:
    repository = SQLiteRepository(tmp_path / f"preset-{operation}.sqlite")
    repository.save_detector_weight_preset({"id": "first", "name": "First", "is_default": True})
    repository.save_detector_weight_preset({"id": "second", "name": "Second", "is_default": False})
    serialize = repository._serialize
    calls = 0

    def fail_second_serialization(value: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("serialization failed")
        return serialize(value)

    repository._serialize = fail_second_serialization  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="serialization failed"):
        if operation == "update":
            repository.update_detector_weight_preset(
                "second", {"name": "Updated"}, set_as_default=True
            )
        else:
            repository.set_default_detector_weight_preset("second")

    assert not repository.connection.in_transaction
    defaults = [
        preset["id"] for preset in repository.list_detector_weight_presets() if preset["is_default"]
    ]
    assert defaults == ["first"]
    repository.close()
