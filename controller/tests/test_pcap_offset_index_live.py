from __future__ import annotations

import hashlib
import io
import struct
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event, Thread

import pytest
from c2hunter_analysis.pcap_index import StructuralInterfaceEntry, StructuralPacketEntry

from c2hunter_controller import repositories as repositories_module
from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    LiveIndexPermanentError,
    LiveIndexTransientError,
    SourceIndexBinding,
    build_live_segment_index,
)
from c2hunter_controller.pcap_offset_index_queue import encode_task
from c2hunter_controller.repositories import CaptureSource, MemoryRepository, SQLiteRepository


def _pcap(*, packet: bytes = b"abc") -> bytes:
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, len(packet), len(packet))
        + packet
    )


def _pcap_packets(count: int) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(
        struct.pack("<IIII", index + 1, 2, 1, 1) + bytes([index]) for index in range(count)
    )


class _CloseCountingStream(io.BytesIO):
    close_calls = 0

    def close(self) -> None:
        self.close_calls += 1
        super().close()


def _repository(kind: str, tmp_path: Path) -> MemoryRepository | SQLiteRepository:
    return MemoryRepository() if kind == "memory" else SQLiteRepository(str(tmp_path / "db.sqlite"))


def _save(repository: MemoryRepository | SQLiteRepository, content: bytes) -> None:
    repository.save_job(
        {"id": "live-1", "mode": "LIVE", "status": "CAPTURING", "capture": {"store_pcap": True}}
    )
    digest = hashlib.sha256(content).hexdigest()
    stored, status = repository.save_sensor_pcap_limited(
        {
            "id": "segment-1",
            "sensor_id": "sensor-1",
            "analysis_job_id": "live-1",
            "filename": "segment-1.pcap",
            "size_bytes": len(content),
            "sha256": digest,
            "uploaded_at": "2026-08-25T00:00:00+00:00",
        },
        content,
        None,
        require_open_job=True,
    )
    assert status == "OK" and stored is not None


def _build(
    repository: MemoryRepository | SQLiteRepository, *, request_postings: bool = False
) -> bool:
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    task = repository.claim_live_segment_index(
        now=datetime.now(UTC) + timedelta(seconds=1), lease_seconds=120
    )
    assert task is not None and task.lease_token is not None
    return build_live_segment_index(
        repository,
        "segment-1",
        max_packets=10,
        max_interfaces=10,
        batch_size=1,
        attempt=task.attempt,
        lease_token=task.lease_token,
        request_postings=request_postings,
        posting_queue_capacity=1,
        posting_max_attempts=3,
    )


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_builder_binds_observed_version_and_publishes_segment_local_index(
    kind: str, tmp_path: Path
) -> None:
    repository = _repository(kind, tmp_path)
    content = _pcap()
    _save(repository, content)

    assert _build(repository)
    version = repository.get_live_capture_source_version("segment-1")
    assert version is not None
    binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        "segment-1",
        version.source_version_id,
        len(content),
        hashlib.sha256(content).hexdigest(),
        "PCAP",
    )
    lookup = repository.get_structural_index(binding)
    assert lookup.availability is IndexAvailability.READY
    assert lookup.snapshot is not None and [
        packet.packet_index for packet in lookup.snapshot.packets
    ] == [0]


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_publication_atomically_requests_and_admits_exact_posting(
    kind: str, tmp_path: Path
) -> None:
    repository = _repository(kind, tmp_path)
    _save(repository, _pcap())

    assert _build(repository, request_postings=True)

    intent = repository.get_posting_index_intent("LIVE_SEGMENT", "segment-1")
    task = repository.get_posting_index_task("LIVE_SEGMENT", "segment-1")
    owner = (
        repository.structural_index_owners[("LIVE_SEGMENT", "segment-1")]
        if kind == "memory"
        else repository.connection.execute(
            "SELECT build_id FROM pcap_offset_index_owners "
            "WHERE source_kind='LIVE_SEGMENT' AND source_id='segment-1'"
        ).fetchone()[0]
    )
    assert intent is not None and intent.spec.parent_structural_build_id == owner
    assert task is not None and task.spec.identity == intent.spec.identity


def test_live_postcommit_admission_failure_keeps_source_ack_and_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    _save(repository, _pcap())
    monkeypatch.setattr(
        repository,
        "admit_posting_index",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("queue unavailable")),
    )

    assert _build(repository, request_postings=True)
    assert repository.get_sensor_pcap("segment-1") is not None
    assert repository.get_live_segment_index_task("segment-1").status == "COMPLETED"
    assert repository.get_posting_index_intent("LIVE_SEGMENT", "segment-1") is not None
    assert repository.get_posting_index_task("LIVE_SEGMENT", "segment-1") is None


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_marker_exception_rolls_back_ready_owner_and_ack(kind: str, tmp_path: Path) -> None:
    repository = _repository(kind, tmp_path)
    _save(repository, _pcap())
    if kind == "memory":

        class FailingMarkers(dict):
            def __setitem__(self, key: object, value: object) -> None:
                raise RuntimeError("marker write failed")

        repository.posting_index_intents = FailingMarkers()
    else:
        repository.connection.execute(
            "CREATE TRIGGER fail_posting_marker BEFORE INSERT ON pcap_posting_index_intents "
            "BEGIN SELECT RAISE(ABORT, 'marker write failed'); END"
        )
        repository.connection.commit()

    with pytest.raises(LiveIndexTransientError) as raised:
        _build(repository, request_postings=True)
    assert raised.value.code == "INDEX_PUBLICATION_UNAVAILABLE"
    assert repository.get_live_segment_index_task("segment-1").status == "RUNNING"
    if kind == "memory":
        assert repository.structural_index_owners.get(("LIVE_SEGMENT", "segment-1")) is None
    else:
        assert (
            repository.connection.execute(
                "SELECT build_id FROM pcap_offset_index_owners "
                "WHERE source_kind='LIVE_SEGMENT' AND source_id='segment-1'"
            ).fetchone()
            is None
        )
        assert not repository.connection.in_transaction


@pytest.mark.parametrize("content", [_pcap(packet=b"")[:24], _pcap()[:-1]])
def test_live_builder_rejects_header_only_and_truncated_but_retains_source(content: bytes) -> None:
    repository = MemoryRepository()
    _save(repository, content)
    with pytest.raises(LiveIndexPermanentError) as raised:
        _build(repository)
    assert raised.value.code == "INDEX_SOURCE_FRAMING_INVALID"
    assert repository.get_sensor_pcap("segment-1")[1] == content
    assert repository.get_live_capture_source_version("segment-1") is None
    task = repository.get_live_segment_index_task("segment-1")
    assert task is not None and task.status == "RUNNING"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_publication_loses_to_source_deletion(kind: str, tmp_path: Path) -> None:
    repository = _repository(kind, tmp_path)
    content = _pcap()
    _save(repository, content)

    original = repository.publish_live_structural_index

    def delete_then_publish(*args: object, **kwargs: object) -> bool:
        assert repository.delete_job("live-1")
        return original(*args, **kwargs)

    repository.publish_live_structural_index = delete_then_publish  # type: ignore[method-assign]

    with pytest.raises(LiveIndexPermanentError) as raised:
        _build(repository)
    assert raised.value.code == "INDEX_PUBLICATION_REJECTED"
    assert repository.get_sensor_pcap("segment-1") is None
    assert repository.get_live_segment_index_task("segment-1") is None
    assert repository.get_live_capture_source_version("segment-1") is None


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_job_deletion_removes_segment_task_version_owner_and_generations(
    kind: str, tmp_path: Path
) -> None:
    repository = _repository(kind, tmp_path)
    content = _pcap()
    _save(repository, content)
    assert _build(repository)
    version = repository.get_live_capture_source_version("segment-1")
    assert version is not None
    binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        "segment-1",
        version.source_version_id,
        len(content),
        hashlib.sha256(content).hexdigest(),
        "PCAP",
    )

    assert repository.delete_job("live-1")
    assert repository.get_sensor_pcap("segment-1") is None
    assert repository.get_live_segment_index_task("segment-1") is None
    assert repository.get_live_capture_source_version("segment-1") is None
    assert repository.get_structural_index(binding).availability is IndexAvailability.MISSING


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize(
    "content,max_packets,max_interfaces",
    [
        (b"", 10, 10),
        (_pcap()[:28], 10, 10),
        (_pcap()[:-1], 10, 10),
        (b"BAD!" + _pcap()[4:], 10, 10),
        (_pcap_packets(2), 1, 10),
        (_pcap(), 10, 0),
    ],
    ids=[
        "empty",
        "truncated-record-header",
        "truncated-payload",
        "bad-magic",
        "packet-limit",
        "interface-limit",
    ],
)
def test_live_builder_failure_matrix_is_atomic_and_leaves_running_task(
    kind: str, tmp_path: Path, content: bytes, max_packets: int, max_interfaces: int
) -> None:
    repository = _repository(kind, tmp_path)
    _save(repository, content)
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    task = repository.claim_live_segment_index(
        now=datetime.now(UTC) + timedelta(seconds=1), lease_seconds=120
    )
    assert task is not None and task.lease_token is not None
    stream = _CloseCountingStream(content)
    source = CaptureSource(stream, f"sha256:{hashlib.sha256(content).hexdigest()}")
    metadata = repository.get_live_segment_index_metadata("segment-1")
    assert metadata is not None
    original_open = repository.open_sensor_pcap
    repository.open_sensor_pcap = lambda _source_id: (metadata, source)  # type: ignore[method-assign]

    with pytest.raises(LiveIndexPermanentError) as raised:
        build_live_segment_index(
            repository,
            "segment-1",
            max_packets=max_packets,
            max_interfaces=max_interfaces,
            batch_size=1,
            attempt=task.attempt,
            lease_token=task.lease_token,
        )
    expected_code = "INDEX_RESOURCE_LIMIT" if max_packets == 1 else "INDEX_SOURCE_FRAMING_INVALID"
    assert raised.value.code == expected_code
    repository.open_sensor_pcap = original_open  # type: ignore[method-assign]
    assert stream.close_calls == 1
    assert repository.get_sensor_pcap("segment-1")[1] == content
    assert repository.get_live_capture_source_version("segment-1") is None
    assert repository.get_live_segment_index_task("segment-1").status == "RUNNING"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize("failure", ["first-stage", "middle-stage", "final-stage", "publication"])
def test_live_builder_staging_and_publication_failures_leave_no_ready_partial(
    kind: str, tmp_path: Path, failure: str
) -> None:
    repository = _repository(kind, tmp_path)
    content = _pcap_packets(3)
    _save(repository, content)
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    task = repository.claim_live_segment_index(
        now=datetime.now(UTC) + timedelta(seconds=1), lease_seconds=120
    )
    assert task is not None and task.lease_token is not None
    stream = _CloseCountingStream(content)
    source = CaptureSource(stream, f"sha256:{hashlib.sha256(content).hexdigest()}")
    metadata = repository.get_live_segment_index_metadata("segment-1")
    assert metadata is not None
    original_open = repository.open_sensor_pcap
    repository.open_sensor_pcap = lambda _source_id: (metadata, source)  # type: ignore[method-assign]
    original_stage = repository.stage_structural_index_packets
    calls = 0

    def stage(build_id: str, packets: object) -> None:
        nonlocal calls
        calls += 1
        if failure == "first-stage" and calls == 1:
            raise RuntimeError("first")
        if failure == "middle-stage" and calls == 2:
            raise RuntimeError("middle")
        if failure == "final-stage" and calls == 3:
            raise RuntimeError("final")
        original_stage(build_id, packets)  # type: ignore[arg-type]

    repository.stage_structural_index_packets = stage  # type: ignore[method-assign]
    if failure == "publication":
        repository.publish_live_structural_index = lambda *_args, **_kwargs: False  # type: ignore[method-assign]

    error_type = LiveIndexPermanentError if failure == "publication" else LiveIndexTransientError
    expected_code = (
        "INDEX_PUBLICATION_REJECTED" if failure == "publication" else "INDEX_STAGING_UNAVAILABLE"
    )
    with pytest.raises(error_type) as raised:
        build_live_segment_index(
            repository,
            "segment-1",
            max_packets=10,
            max_interfaces=10,
            batch_size=1,
            attempt=task.attempt,
            lease_token=task.lease_token,
        )
    assert raised.value.code == expected_code
    repository.open_sensor_pcap = original_open  # type: ignore[method-assign]
    assert stream.close_calls == 1
    assert repository.get_sensor_pcap("segment-1")[1] == content
    assert repository.get_live_capture_source_version("segment-1") is None
    assert repository.get_live_segment_index_task("segment-1").status == "RUNNING"
    if kind == "memory":
        assert repository.structural_index_staging == {}
        assert repository.structural_index_owners.get(("LIVE_SEGMENT", "segment-1")) is None
    else:
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM pcap_offset_index_generations WHERE source_kind='LIVE_SEGMENT'"
        ).fetchone() == (0,)


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_job_deletion_removes_all_linked_exact_segments_but_preserves_unlinked_and_jobless(
    kind: str, tmp_path: Path
) -> None:
    repository = _repository(kind, tmp_path)
    content = _pcap()
    for job_id in ("live-1", "live-2"):
        repository.save_job(
            {
                "id": job_id,
                "mode": "LIVE",
                "status": "CAPTURING",
                "capture": {"store_pcap": True},
            }
        )
    for segment_id, job_id in (
        ("linked-1", "live-1"),
        ("linked-2", "live-1"),
        ("unlinked", "live-2"),
        ("jobless", None),
    ):
        stored, status = repository.save_sensor_pcap_limited(
            {
                "id": segment_id,
                "sensor_id": "sensor-1",
                "analysis_job_id": job_id,
                "filename": f"{segment_id}.pcap",
                "size_bytes": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "uploaded_at": "2026-08-25T00:00:00+00:00",
            },
            content,
            None,
            require_open_job=job_id is not None,
        )
        assert status == "OK" and stored is not None

    assert repository.delete_job("live-1")
    assert repository.get_sensor_pcap("linked-1") is None
    assert repository.get_sensor_pcap("linked-2") is None
    assert repository.get_sensor_pcap("unlinked") is not None
    assert repository.get_sensor_pcap("jobless") is not None


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
@pytest.mark.parametrize("mismatch", ["size", "sha256", "version"])
def test_live_builder_rejects_observed_identity_mismatch_without_publication(
    kind: str, tmp_path: Path, mismatch: str
) -> None:
    repository = _repository(kind, tmp_path)
    content = _pcap()
    _save(repository, content)
    repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    task = repository.claim_live_segment_index(
        now=datetime.now(UTC) + timedelta(seconds=1), lease_seconds=120
    )
    assert task is not None and task.lease_token is not None
    metadata = repository.get_live_segment_index_metadata("segment-1")
    assert metadata is not None
    if mismatch == "size":
        metadata["size_bytes"] = len(content) + 1
    elif mismatch == "sha256":
        metadata["sha256"] = "b" * 64
    stream = _CloseCountingStream(content)
    source = CaptureSource(stream, "etag:v1")
    original_open = repository.open_sensor_pcap
    repository.open_sensor_pcap = lambda _source_id: (metadata, source)  # type: ignore[method-assign]
    original_stage = repository.stage_structural_index_packets

    def stage(build_id: str, packets: object) -> None:
        original_stage(build_id, packets)  # type: ignore[arg-type]
        if mismatch == "version":
            source._version_id = "etag:v2"

    repository.stage_structural_index_packets = stage  # type: ignore[method-assign]
    with pytest.raises(LiveIndexPermanentError) as raised:
        build_live_segment_index(
            repository,
            "segment-1",
            max_packets=10,
            max_interfaces=10,
            batch_size=1,
            attempt=task.attempt,
            lease_token=task.lease_token,
        )
    expected_code = (
        "INDEX_SOURCE_DIGEST_MISMATCH"
        if mismatch == "version"
        else "INDEX_SOURCE_OWNERSHIP_MISMATCH"
    )
    assert raised.value.code == expected_code
    repository.open_sensor_pcap = original_open  # type: ignore[method-assign]
    assert stream.close_calls == 1
    assert repository.get_sensor_pcap("segment-1")[1] == content
    assert repository.get_live_capture_source_version("segment-1") is None
    assert repository.get_live_segment_index_task("segment-1").status == "RUNNING"


def test_sqlite_live_job_deletion_metadata_failure_rolls_back_whole_transaction(
    tmp_path: Path,
) -> None:
    repository = SQLiteRepository(str(tmp_path / "rollback.sqlite"))
    content = _pcap()
    _save(repository, content)
    assert _build(repository)
    repository.connection.execute(
        "CREATE TRIGGER fail_live_index_delete BEFORE DELETE ON pcap_offset_index_jobs "
        "BEGIN SELECT RAISE(ABORT,'forced metadata failure'); END"
    )
    repository.connection.commit()

    with pytest.raises(Exception, match="forced metadata failure"):
        repository.delete_job("live-1")
    assert repository.get_job("live-1") is not None
    stored = repository.get_sensor_pcap("segment-1")
    assert stored is not None and stored[1] == content
    assert repository.get_live_segment_index_task("segment-1") is not None
    assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_sqlite_live_publication_revalidates_expired_lease_inside_writer_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "publication-cas.sqlite"
    stale_repository = SQLiteRepository(str(path))
    recovering_repository = SQLiteRepository(str(path))
    content = _pcap()
    digest = hashlib.sha256(content).hexdigest()
    _save(stale_repository, content)
    assert stale_repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    claimed_at = datetime.now(UTC) + timedelta(seconds=1)
    stale = stale_repository.claim_live_segment_index(now=claimed_at, lease_seconds=30)
    assert stale is not None and stale.lease_token is not None
    expired_at = claimed_at + timedelta(seconds=31)
    stale_repository.connection.execute(
        "UPDATE pcap_offset_index_jobs SET data=? WHERE source_id='segment-1'",
        (encode_task(replace(stale, lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))),),
    )
    stale_repository.connection.commit()
    binding = SourceIndexBinding(
        "LIVE_SEGMENT", "segment-1", f"sha256:{digest}", len(content), digest, "PCAP"
    )
    source_version = CaptureSourceVersion(
        "LIVE_SEGMENT",
        "segment-1",
        "sensor-pcaps/sensor-1/segment-1.pcap",
        binding.source_version_id,
        len(content),
        digest,
    )
    staged_packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)
    staged_interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    stale_repository.begin_structural_index("stale-build", binding, claimed_at)
    stale_repository.stage_structural_index_packets("stale-build", (staged_packet,))

    pretransaction_task_read = Event()
    release_stale = Event()

    original_get_task = repositories_module.get_live_index_task

    def stale_precheck(repository: object, source_id: str) -> object:
        if (
            repository is stale_repository
            and source_id == "segment-1"
            and not stale_repository.connection.in_transaction
        ):
            pretransaction_task_read.set()
            assert release_stale.wait(2), "stale publication precheck was not released"
            return stale
        return original_get_task(repository, source_id)

    monkeypatch.setattr(repositories_module, "get_live_index_task", stale_precheck)

    def signal_transaction(statement: str) -> None:
        if statement == "BEGIN IMMEDIATE":
            pretransaction_task_read.set()

    stale_repository.connection.set_trace_callback(signal_transaction)
    publication: list[bool] = []
    publish_thread = Thread(
        target=lambda: publication.append(
            stale_repository.publish_live_structural_index(
                "stale-build",
                binding,
                (staged_interface,),
                1,
                source_version,
                attempt=stale.attempt,
                lease_token=stale.lease_token or "",
            )
        ),
        daemon=True,
    )
    publish_thread.start()
    assert pretransaction_task_read.wait(1)
    assert recovering_repository.recover_live_segment_indexes(now=expired_at) == 1
    newer = recovering_repository.claim_live_segment_index(now=expired_at, lease_seconds=30)
    assert newer is not None and newer.attempt == 2 and newer.lease_token != stale.lease_token
    release_stale.set()
    publish_thread.join(2)

    assert not publish_thread.is_alive()
    assert publication == [False]
    current = recovering_repository.get_live_segment_index_task("segment-1")
    assert current is not None and current.status == "RUNNING" and current.attempt == 2
    assert (
        recovering_repository.get_structural_index(binding).availability
        is IndexAvailability.MISSING
    )
    assert recovering_repository.connection.execute(
        "SELECT state FROM pcap_offset_index_generations WHERE build_id='stale-build'"
    ).fetchone() == ("STAGING",)
    assert recovering_repository.connection.execute(
        "SELECT COUNT(*) FROM pcap_offset_index_owners WHERE source_kind='LIVE_SEGMENT'"
    ).fetchone() == (0,)
    stale_repository.close()
    recovering_repository.close()
