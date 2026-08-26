from __future__ import annotations

import ast
import hashlib
import io
import ipaddress
import struct
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis.pcap_index import scan_structural_packet_index

from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    SourceIndexBinding,
    StructuralIndexSnapshot,
    structural_index_digest,
)


def _capture() -> bytes:
    payload = b"stage11"
    udp = struct.pack("!HHHH", 50000, 443, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        7,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("10.0.0.8").packed,
        ipaddress.ip_address("203.0.113.8").packed,
    )
    packet = bytes.fromhex("0200000000020200000000010800") + ipv4 + udp
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, len(packet), len(packet))
        + packet
    )


class SequentialSource(io.BytesIO):
    def __init__(self, value: bytes, version_id: str) -> None:
        super().__init__(value)
        self.version_id = version_id
        self.close_count = 0
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        assert size > 0
        self.read_sizes.append(size)
        return super().read(size)

    def seek(self, *args, **kwargs):
        raise AssertionError("posting builder must not seek")

    def close(self) -> None:
        if not self.closed:
            self.close_count += 1
        super().close()


class ShortReadSequentialSource(SequentialSource):
    def __init__(self, value: bytes, version_id: str) -> None:
        super().__init__(value, version_id)
        self.offset_calls = 0

    def read(self, size: int = -1) -> bytes:
        return super().read(min(size, 3))

    def read_at(self, *_args: object, **_kwargs: object) -> bytes:
        self.offset_calls += 1
        raise AssertionError("posting builder must not use offset reads")

    def read_range(self, *_args: object, **_kwargs: object) -> bytes:
        self.offset_calls += 1
        raise AssertionError("posting builder must not use range reads")

    def range_read(self, *_args: object, **_kwargs: object) -> bytes:
        self.offset_calls += 1
        raise AssertionError("posting builder must not use range reads")


def _parent(capture: bytes) -> tuple[CaptureSourceVersion, StructuralIndexSnapshot]:
    digest = hashlib.sha256(capture).hexdigest()
    source = CaptureSourceVersion(
        "PCAP_UPLOAD", "job-1", "captures/job-1.pcap", "version-1", len(capture), digest
    )
    scan = scan_structural_packet_index(io.BytesIO(capture), max_packets=10, max_interfaces=2)
    binding = SourceIndexBinding("PCAP_UPLOAD", "job-1", "version-1", len(capture), digest, "PCAP")
    parent = StructuralIndexSnapshot(
        "structural-1",
        binding,
        datetime.now(UTC),
        structural_index_digest(binding, scan.interfaces, scan.packets),
        scan.interfaces,
        scan.packets,
    )
    return source, parent


def test_controller_builder_binds_exact_parent_and_reads_source_once() -> None:
    from c2hunter_controller.pcap_posting_index import (
        PostingIndexBinding,
        build_source_posting_index,
        validate_posting_index,
    )

    capture = _capture()
    source_version, parent = _parent(capture)
    source = SequentialSource(capture, "version-1")

    snapshot = build_source_posting_index(
        source,
        source_version=source_version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id="posting-1",
    )

    assert isinstance(snapshot.binding, PostingIndexBinding)
    assert snapshot.binding.parent_structural_build_id == "structural-1"
    assert snapshot.binding.parent_structural_index_sha256 == parent.index_sha256
    assert snapshot.binding.source_sha256 == hashlib.sha256(capture).hexdigest()
    assert snapshot.generation.packet_count == 1
    assert validate_posting_index(snapshot, source_version=source_version, parent=parent)
    assert source.closed and source.close_count == 1
    assert source.read_sizes and all(size > 0 for size in source.read_sizes)


def test_controller_builder_handles_short_reads_without_seek_or_range_and_closes_once() -> None:
    from c2hunter_controller.pcap_posting_index import build_source_posting_index

    capture = _capture()
    source_version, parent = _parent(capture)
    source = ShortReadSequentialSource(capture, "version-1")

    snapshot = build_source_posting_index(
        source,
        source_version=source_version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id="posting-short-read",
    )

    assert snapshot.generation.packet_count == 1
    assert len(source.read_sizes) > 10
    assert source.offset_calls == 0
    assert source.closed and source.close_count == 1


def test_controller_builder_source_and_parent_mismatch_have_stable_permanent_codes() -> None:
    from dataclasses import replace

    from c2hunter_controller.pcap_posting_index import (
        PostingIndexPermanentError,
        build_source_posting_index,
    )

    capture = _capture()
    source_version, parent = _parent(capture)
    wrong_parent = replace(
        parent,
        binding=replace(parent.binding, source_sha256="0" * 64),
    )
    source = SequentialSource(capture, "version-1")
    with pytest.raises(PostingIndexPermanentError) as raised:
        build_source_posting_index(
            source,
            source_version=source_version,
            parent=wrong_parent,
            internal_networks=["10.0.0.0/8"],
            build_id="posting-bad-parent",
        )
    assert raised.value.code == "POSTING_PARENT_INVALID"
    assert source.close_count == 1

    truncated = SequentialSource(capture[:-1], "version-1")
    with pytest.raises(PostingIndexPermanentError) as raised:
        build_source_posting_index(
            truncated,
            source_version=source_version,
            parent=parent,
            internal_networks=["10.0.0.0/8"],
            build_id="posting-truncated",
        )
    assert raised.value.code == "POSTING_SOURCE_FRAMING_INVALID"
    assert truncated.close_count == 1


def test_controller_orchestrator_stages_bounded_chunks_only_after_source_close() -> None:
    from c2hunter_controller.pcap_posting_index import (
        PostingIndexPermanentError,
        build_and_publish_source_posting_index,
    )

    capture = _capture()
    source_version, parent = _parent(capture)
    source = SequentialSource(capture, "version-1")

    class Repository:
        def __init__(self) -> None:
            self.snapshot = None
            self.batch_sizes: list[int] = []

        def begin_posting_index(self, snapshot, *, attempt: int, lease_token: str) -> None:
            assert source.closed
            assert (attempt, lease_token) == (2, "lease")
            assert snapshot.created_at == staged_at
            self.snapshot = snapshot

        def stage_posting_index_chunks(
            self,
            build_id: str,
            chunks,
            *,
            source_kind: str,
            source_id: str,
            attempt: int,
            lease_token: str,
        ) -> None:
            assert build_id == "posting-staged"
            assert (source_kind, source_id, attempt, lease_token) == (
                "PCAP_UPLOAD",
                "job-1",
                2,
                "lease",
            )
            self.batch_sizes.append(len(chunks))

        def publish_posting_index(
            self,
            build_id: str,
            *,
            source_version: CaptureSourceVersion,
            parent: StructuralIndexSnapshot,
            attempt: int,
            lease_token: str,
        ) -> bool:
            assert build_id == "posting-staged"
            assert source_version.source_id == "job-1"
            assert parent.build_id == "structural-1"
            assert (attempt, lease_token) == (2, "lease")
            return True

        def abort_posting_index(self, build_id: str, **ownership) -> bool:
            raise AssertionError("successful publication must not abort")

    repository = Repository()
    staged_at = datetime(2026, 8, 26, tzinfo=UTC)
    completed = []

    def completion(snapshot) -> None:
        completed.append(snapshot)
        raise RuntimeError("metrics callback must not undo publication")

    assert build_and_publish_source_posting_index(
        repository,
        source,
        source_version=source_version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id="posting-staged",
        attempt=2,
        lease_token="lease",
        now=staged_at,
        stage_batch_size=2,
        on_published=completion,
    )
    assert repository.snapshot is not None
    assert completed == [repository.snapshot]
    assert repository.batch_sizes and max(repository.batch_sizes) <= 2

    rejected_source = SequentialSource(capture, "version-1")
    repository.publish_posting_index = lambda *_args, **_kwargs: False
    with pytest.raises(PostingIndexPermanentError) as rejected:
        build_and_publish_source_posting_index(
            repository,
            rejected_source,
            source_version=source_version,
            parent=parent,
            internal_networks=["10.0.0.0/8"],
            build_id="posting-staged",
            attempt=2,
            lease_token="lease",
            now=staged_at,
            stage_batch_size=2,
            on_published=completion,
        )
    assert rejected.value.code == "POSTING_PUBLICATION_REJECTED"
    assert completed == [repository.snapshot]


_POSTING_FOUNDATION_METHODS = (
    "begin_posting_index",
    "stage_posting_index_chunks",
    "publish_posting_index",
    "get_posting_index",
    "abort_posting_index",
)


def _make_posting_methods_raise(monkeypatch: Any, repository: Any) -> dict[str, int]:
    calls = dict.fromkeys(_POSTING_FOUNDATION_METHODS, 0)

    def reject(method_name: str):
        def rejected(*_args: object, **_kwargs: object) -> None:
            calls[method_name] += 1
            raise AssertionError(f"Stage11 posting method called: {method_name}")

        return rejected

    for method_name in _POSTING_FOUNDATION_METHODS:
        monkeypatch.setattr(repository, method_name, reject(method_name))
    return calls


@pytest.mark.parametrize(
    ("settings_kwargs", "expected_status"),
    [
        ({"pcap_export_execution_mode": "sync_only"}, 201),
        (
            {
                "pcap_export_sync_max_source_bytes": 1,
                "pcap_export_sync_max_packets": 1,
            },
            202,
        ),
    ],
)
def test_sync_and_claimed_async_artifact_publication_and_download_ignore_postings(
    monkeypatch: Any,
    settings_kwargs: dict[str, object],
    expected_status: int,
) -> None:
    from fastapi.testclient import TestClient
    from test_pcap_offset_index_upload import _upload

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.pcap_export_worker import create_pcap_export_worker
    from c2hunter_controller.repositories import MemoryRepository

    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test", **settings_kwargs), repository))
    uploaded = _upload(client, key=f"posting-isolation-{expected_status}")
    assert uploaded.status_code == 201
    calls = _make_posting_methods_raise(monkeypatch, repository)

    exported = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": uploaded.json()["id"]},
    )
    assert exported.status_code == expected_status
    if expected_status == 202:
        assert create_pcap_export_worker(
            repository, Settings(environment="test", **settings_kwargs)
        ).run_once()
        exported = client.get(f"/api/v1/pcap-exports/{exported.json()['id']}")
        assert exported.status_code == 200
        assert exported.json()["status"] == "COMPLETED"

    download = client.get(f"/api/v1/pcap-exports/{exported.json()['id']}/download")
    assert download.status_code == 200
    assert download.content.startswith(b"\xd4\xc3\xb2\xa1")
    assert calls == dict.fromkeys(_POSTING_FOUNDATION_METHODS, 0)


def test_upload_and_finalized_live_acceptance_ignore_unavailable_postings(
    monkeypatch: Any,
) -> None:
    from fastapi.testclient import TestClient
    from test_pcap_offset_index_upload import _upload
    from test_sensor_gateway_api import enroll_and_claim

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import MemoryRepository

    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    calls = _make_posting_methods_raise(monkeypatch, repository)

    uploaded = _upload(client, key="posting-unavailable-upload")
    assert uploaded.status_code == 201

    sensor_id, token = enroll_and_claim(client)
    repository.save_job(
        {
            "id": "posting-unavailable-live",
            "mode": "LIVE",
            "status": "CAPTURING",
            "sensor_ids": [sensor_id],
            "capture": {"store_pcap": True},
        }
    )
    filename = "posting-unavailable-live.pcap"
    segment_id = hashlib.sha256(f"{sensor_id}\0{filename}".encode()).hexdigest()
    capture = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")
    accepted = client.put(
        f"/api/v1/sensors/{sensor_id}/pcap-segments/{segment_id}",
        params={"filename": filename, "analysis_job_id": "posting-unavailable-live"},
        content=capture,
        headers={
            "X-Sensor-Token": token,
            "content-type": "application/vnd.tcpdump.pcap",
        },
    )
    assert accepted.status_code == 201
    assert calls == dict.fromkeys(_POSTING_FOUNDATION_METHODS, 0)


def _walk_mapping_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {key for child in value.values() for key in _walk_mapping_keys(child)}
    if isinstance(value, list):
        return {key for child in value for key in _walk_mapping_keys(child)}
    return set()


def test_openapi_and_public_sensor_export_responses_hide_posting_internals() -> None:
    from fastapi.testclient import TestClient
    from test_pcap_offset_index_upload import _upload
    from test_sensor_gateway_api import enroll_and_claim

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import MemoryRepository

    internal_fields = {
        "posting_index",
        "posting_index_state",
        "posting_build_id",
        "posting_generation_id",
        "posting_schema_version",
        "posting_parser_contract_version",
        "posting_filter_contract_version",
        "index_requested_at",
        "index_intent_state",
        "index_intent_schema_version",
        "index_intent_parser_contract_version",
    }
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    upload = _upload(client, key="posting-public-upload")
    export = client.post(
        "/api/v1/pcap-exports",
        json={"job_id": upload.json()["id"]},
    )
    sensor_id, token = enroll_and_claim(client)
    repository.save_job(
        {
            "id": "posting-public-live",
            "mode": "LIVE",
            "status": "CAPTURING",
            "sensor_ids": [sensor_id],
            "capture": {"store_pcap": True},
        }
    )
    filename = "posting-public-live.pcap"
    segment_id = hashlib.sha256(f"{sensor_id}\0{filename}".encode()).hexdigest()
    sensor = client.put(
        f"/api/v1/sensors/{sensor_id}/pcap-segments/{segment_id}",
        params={"filename": filename, "analysis_job_id": "posting-public-live"},
        content=bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000"),
        headers={
            "X-Sensor-Token": token,
            "content-type": "application/vnd.tcpdump.pcap",
        },
    )
    assert upload.status_code == export.status_code == sensor.status_code == 201

    for public_document in (
        client.get("/openapi.json").json(),
        upload.json(),
        export.json(),
        sensor.json(),
        client.get("/api/v1/sensor-pcaps").json(),
    ):
        assert internal_fields.isdisjoint(_walk_mapping_keys(public_document))


def test_all_tracked_production_export_modules_have_no_direct_posting_storage_dependency() -> None:
    repository_root = Path(__file__).parents[2]
    tracked = (
        subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=repository_root,
            check=True,
            capture_output=True,
        )
        .stdout.decode()
        .split("\0")
    )
    export_modules = [
        repository_root / name
        for name in tracked
        if name
        and name.startswith(("controller/src/", "analysis/src/"))
        and Path(name).name.startswith("pcap_export")
        and name.endswith(".py")
    ]
    assert export_modules

    forbidden_modules = {
        "c2hunter_analysis.pcap_postings",
        "c2hunter_controller.pcap_offset_index",
        "c2hunter_controller.pcap_posting_index",
    }
    forbidden_symbols = {
        "get_structural_index",
        "get_posting_index",
        "lookup_structural_index",
        "lookup_posting_index",
        "read_range",
        "range_read",
        "seek",
        "coalesce_ranges",
        "selected_offsets",
        "selected_packet_offsets",
        "structural_packet_range",
    }
    violations: list[str] = []
    for path in export_modules:
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in forbidden_modules:
                        violations.append(
                            f"{path.relative_to(repository_root)}:{node.lineno}:import"
                        )
            elif isinstance(node, ast.ImportFrom) and node.module in forbidden_modules:
                violations.append(f"{path.relative_to(repository_root)}:{node.lineno}:import-from")
            elif isinstance(node, ast.Call):
                called = (
                    node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else (node.func.id if isinstance(node.func, ast.Name) else None)
                )
                if called in forbidden_symbols:
                    violations.append(
                        f"{path.relative_to(repository_root)}:{node.lineno}:call:{called}"
                    )
                if any(
                    keyword.arg in {"offset", "byte_range", "packet_range"}
                    for keyword in node.keywords
                ):
                    violations.append(
                        f"{path.relative_to(repository_root)}:{node.lineno}:range-keyword"
                    )
            elif isinstance(node, ast.Attribute | ast.Name):
                symbol = node.attr if isinstance(node, ast.Attribute) else node.id
                if symbol in forbidden_symbols - {"seek"}:
                    violations.append(
                        f"{path.relative_to(repository_root)}:{node.lineno}:symbol:{symbol}"
                    )
            elif isinstance(node, ast.Subscript):
                key = node.slice
                if isinstance(key, ast.Constant) and key.value == "Range":
                    violations.append(
                        f"{path.relative_to(repository_root)}:{node.lineno}:range-header"
                    )
            elif isinstance(node, ast.Dict):
                if any(isinstance(key, ast.Constant) and key.value == "Range" for key in node.keys):
                    violations.append(
                        f"{path.relative_to(repository_root)}:{node.lineno}:range-header"
                    )

    assert violations == []
