from __future__ import annotations

import hashlib
import sqlite3
import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from c2hunter_analysis.pcap_index import StructuralInterfaceEntry, StructuralPacketEntry

from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    structural_index_digest,
)
from c2hunter_controller.pcap_offset_index_queue import (
    IndexAdmission,
    LiveIndexTaskSpec,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _job(job_id: str = "live-1") -> dict[str, object]:
    return {
        "id": job_id,
        "mode": "LIVE",
        "status": "CAPTURING",
        "capture": {"store_pcap": True},
    }


def _pcap() -> bytes:
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, 3, 3)
        + b"abc"
    )


def _segment(segment_id: str = "segment-1", job_id: str | None = "live-1") -> dict[str, object]:
    content = _pcap()
    return {
        "id": segment_id,
        "sensor_id": "sensor-1",
        "analysis_job_id": job_id,
        "filename": f"{segment_id}.pcap",
        "size_bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
        "uploaded_at": "2026-08-25T00:00:00+00:00",
    }


def _save_eligible(
    repository: MemoryRepository | SQLiteRepository, segment_id: str = "segment-1"
) -> None:
    repository.save_job(_job())
    stored, status = repository.save_sensor_pcap_limited(
        _segment(segment_id), _pcap(), None, require_open_job=True
    )
    assert status == "OK"
    assert stored is not None and stored["index_requested_at"]


def test_source_identity_accepts_live_segment() -> None:
    version = CaptureSourceVersion(
        "LIVE_SEGMENT", "segment-1", "sensor-pcaps/sensor-1/segment-1.pcap", "etag:v1", 43, "a" * 64
    )
    binding = SourceIndexBinding("LIVE_SEGMENT", "segment-1", "etag:v1", 43, "a" * 64, "PCAP")
    assert version.source_kind == binding.source_kind == "LIVE_SEGMENT"


def test_sqlite_migrates_stage9_source_kind_constraints_and_owner_keys(tmp_path: Path) -> None:
    path = tmp_path / "controller.db"
    repository = SQLiteRepository(str(path))
    repository.save_job(
        {
            "id": "upload-1",
            "mode": "PCAP_UPLOAD",
            "status": "COMPLETED",
            "source": {
                "packet_bytes_retained": True,
                "size_bytes": 3,
                "sha256": hashlib.sha256(b"abc").hexdigest(),
                "capture_format": "PCAP",
            },
        }
    )
    repository.save_job_capture("upload-1", b"abc")
    repository.close()

    reopened = SQLiteRepository(str(path))
    sql = " ".join(
        row[0]
        for row in reopened.connection.execute(
            "SELECT sql FROM sqlite_master WHERE name IN "
            "('pcap_capture_source_versions','pcap_offset_index_owners')"
        )
        if row[0]
    )
    assert "LIVE_SEGMENT" in sql
    assert "PRIMARYKEY(source_kind,source_id)" in sql.replace(" ", "")
    assert reopened.get_capture_source_version("upload-1") is not None
    reopened.close()


def test_sqlite_upgrades_deployed_stage9_tables_with_ready_owner_idempotently(
    tmp_path: Path,
) -> None:
    path = tmp_path / "stage9.db"
    binding = SourceIndexBinding(
        "PCAP_UPLOAD", "upload-1", "sha256:" + "a" * 64, 43, "a" * 64, "PCAP"
    )
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    packet = StructuralPacketEntry(0, 24, 40, 3, 3, 19, 0, 0, 0, 1_000_002)
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE pcap_capture_source_versions (
          source_kind TEXT NOT NULL CHECK(source_kind='PCAP_UPLOAD'), source_id TEXT NOT NULL,
          object_key TEXT NOT NULL, source_version_id TEXT NOT NULL,
          source_size_bytes INTEGER NOT NULL CHECK(source_size_bytes>=0),
          source_sha256 TEXT NOT NULL,
          PRIMARY KEY(source_kind,source_id));
        CREATE TABLE pcap_offset_index_generations (
          build_id TEXT PRIMARY KEY, source_id TEXT NOT NULL,
          state TEXT NOT NULL CHECK(state IN ('STAGING','READY')), binding TEXT NOT NULL,
          created_at TEXT NOT NULL, packet_count INTEGER,
          interface_count INTEGER, index_sha256 TEXT);
        CREATE TABLE pcap_offset_index_interfaces (
          build_id TEXT NOT NULL REFERENCES pcap_offset_index_generations(build_id)
          ON DELETE CASCADE, interface_ordinal INTEGER NOT NULL, data TEXT NOT NULL,
          PRIMARY KEY(build_id,interface_ordinal));
        CREATE TABLE pcap_offset_index_packets (
          build_id TEXT NOT NULL REFERENCES pcap_offset_index_generations(build_id)
          ON DELETE CASCADE,
          packet_index INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(build_id,packet_index));
        CREATE TABLE pcap_offset_index_owners (
          source_id TEXT PRIMARY KEY, build_id TEXT NOT NULL UNIQUE
          REFERENCES pcap_offset_index_generations(build_id) ON DELETE CASCADE);
        """
    )
    connection.execute(
        "INSERT INTO pcap_capture_source_versions VALUES(?,?,?,?,?,?)",
        (
            "PCAP_UPLOAD",
            "upload-1",
            "captures/upload-1.pcap",
            binding.source_version_id,
            43,
            "a" * 64,
        ),
    )
    connection.execute(
        "INSERT INTO pcap_offset_index_generations VALUES(?,?,?,?,?,?,?,?)",
        (
            "ready",
            "upload-1",
            "READY",
            __import__("json").dumps(binding.__dict__),
            "2026-08-25T00:00:00+00:00",
            1,
            1,
            structural_index_digest(binding, (interface,), (packet,)),
        ),
    )
    connection.execute(
        "INSERT INTO pcap_offset_index_interfaces VALUES(?,?,?)",
        ("ready", 0, __import__("json").dumps(interface.__dict__)),
    )
    connection.execute(
        "INSERT INTO pcap_offset_index_packets VALUES(?,?,?)",
        ("ready", 0, __import__("json").dumps(packet.__dict__)),
    )
    connection.execute("INSERT INTO pcap_offset_index_owners VALUES('upload-1','ready')")
    connection.commit()
    connection.close()

    for _ in range(2):
        repository = SQLiteRepository(path)
        repository.save_job(
            {
                "id": "upload-1",
                "mode": "PCAP_UPLOAD",
                "status": "COMPLETED",
                "source": {
                    "packet_bytes_retained": True,
                    "size_bytes": 43,
                    "sha256": "a" * 64,
                    "capture_format": "PCAP",
                },
            }
        )
        assert repository.connection.execute(
            "SELECT source_kind,source_id,build_id FROM pcap_offset_index_owners"
        ).fetchone() == ("PCAP_UPLOAD", "upload-1", "ready")
        assert repository.connection.execute(
            "SELECT source_kind,source_id FROM pcap_offset_index_generations"
        ).fetchone() == ("PCAP_UPLOAD", "upload-1")
        assert repository.get_capture_source_version("upload-1") is not None
        lookup = repository.get_structural_index(binding)
        assert lookup.availability is IndexAvailability.READY
        assert lookup.snapshot is not None and lookup.snapshot.packets == (packet,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM pcap_offset_index_interfaces WHERE build_id='ready'"
        ).fetchone() == (1,)
        assert repository.connection.execute(
            "SELECT COUNT(*) FROM pcap_offset_index_packets WHERE build_id='ready'"
        ).fetchone() == (1,)
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        repository.close()


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_queue_coalesces_before_capacity_and_claims_oldest(
    repository_kind: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(str(tmp_path / "controller.db"))
    )
    _save_eligible(repository, "segment-1")
    first = repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    duplicate = repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
    _save_eligible(repository, "segment-2")
    deferred = repository.admit_live_segment_index("segment-2", capacity=1, max_attempts=3)

    assert first is IndexAdmission.QUEUED
    assert duplicate is IndexAdmission.COALESCED
    assert deferred is IndexAdmission.DEFERRED
    claim_now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = repository.claim_live_segment_index(now=claim_now, lease_seconds=120)
    assert claimed is not None
    assert claimed.spec.source_id == "segment-1"
    assert claimed.attempt == 1 and claimed.lease_token


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_queue_lease_cas_retry_recovery_and_bounded_reconciliation(
    repository_kind: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(str(tmp_path / "controller.db"))
    )
    _save_eligible(repository)
    assert (
        repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=2)
        is IndexAdmission.QUEUED
    )
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = repository.claim_live_segment_index(now=now, lease_seconds=10)
    assert claimed is not None
    assert not repository.heartbeat_live_segment_index(
        "segment-1", attempt=claimed.attempt, lease_token="stale", now=now, lease_seconds=10
    )
    assert not repository.heartbeat_live_segment_index(
        "segment-1",
        attempt=claimed.attempt + 1,
        lease_token=claimed.lease_token,
        now=now,
        lease_seconds=10,
    )
    assert repository.heartbeat_live_segment_index(
        "segment-1",
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=now,
        lease_seconds=10,
    )
    assert repository.recover_live_segment_indexes(now=now + timedelta(seconds=11)) == 1
    claimed2 = repository.claim_live_segment_index(
        now=now + timedelta(seconds=11), lease_seconds=10
    )
    assert (
        claimed2 is not None
        and claimed2.attempt == 2
        and claimed2.lease_token != claimed.lease_token
    )
    assert not repository.complete_live_segment_index(
        "segment-1", attempt=claimed.attempt, lease_token=claimed.lease_token
    )
    assert not repository.complete_live_segment_index(
        "segment-1", attempt=claimed2.attempt, lease_token="stale"
    )
    assert repository.fail_live_segment_index(
        "segment-1",
        attempt=claimed2.attempt,
        lease_token=claimed2.lease_token,
        transient=False,
        error_code="MALFORMED_CAPTURE",
        now=now + timedelta(seconds=11),
        retry_base_seconds=5,
    )
    assert repository.get_live_segment_index_task("segment-1").status == "FAILED"

    _save_eligible(repository, "segment-2")
    _save_eligible(repository, "segment-3")
    assert repository.reconcile_live_segment_indexes(capacity=10, max_attempts=3, limit=1) == 1
    assert repository.get_live_segment_index_task("segment-2") is not None
    assert repository.get_live_segment_index_task("segment-3") is None


def test_only_new_explicitly_marked_live_segments_are_reconciled() -> None:
    repository = MemoryRepository()
    repository.save_job(_job())
    historical = _segment("historical")
    repository.sensor_pcaps["historical"] = historical
    repository.sensor_pcap_content["historical"] = _pcap()
    repository.save_job({**_job("wrong-mode"), "mode": "PCAP_UPLOAD"})
    repository.save_sensor_pcap_limited(_segment("wrong-mode-segment", "wrong-mode"), _pcap(), None)
    repository.save_sensor_pcap_limited(_segment("jobless", None), _pcap(), None)
    _save_eligible(repository, "eligible")

    assert repository.reconcile_live_segment_indexes(capacity=10, max_attempts=3, limit=10) == 1
    assert repository.get_live_segment_index_task("eligible") is not None
    assert repository.get_live_segment_index_task("historical") is None
    assert repository.get_live_segment_index_task("wrong-mode-segment") is None
    assert repository.get_live_segment_index_task("jobless") is None


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_queue_depth_and_bounded_terminal_cleanup_parity(
    repository_kind: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(str(tmp_path / "controller.db"))
    )
    for source_id in ("segment-1", "segment-2", "segment-3"):
        _save_eligible(repository, source_id)
        assert (
            repository.admit_live_segment_index(source_id, capacity=10, max_attempts=1)
            is IndexAdmission.QUEUED
        )
    now = datetime.now(UTC) + timedelta(seconds=1)
    first = repository.claim_live_segment_index(now=now, lease_seconds=30)
    assert first is not None and first.lease_token is not None
    assert repository.complete_live_segment_index(
        first.spec.source_id, attempt=first.attempt, lease_token=first.lease_token
    )
    second = repository.claim_live_segment_index(now=now, lease_seconds=30)
    assert second is not None and second.lease_token is not None
    assert repository.fail_live_segment_index(
        second.spec.source_id,
        attempt=second.attempt,
        lease_token=second.lease_token,
        transient=False,
        error_code="PERMANENT",
        now=now,
        retry_base_seconds=1,
    )

    assert repository.get_live_segment_index_queue_depth() == {
        "QUEUED": 1,
        "RUNNING": 0,
        "COMPLETED": 1,
        "FAILED": 1,
    }
    assert (
        repository.cleanup_terminal_live_segment_indexes(before=now + timedelta(seconds=1), limit=1)
        == 1
    )
    assert repository.get_live_segment_index_task(first.spec.source_id) is None
    assert repository.get_live_segment_index_task(second.spec.source_id) is not None
    assert sum(repository.get_live_segment_index_queue_depth().values()) == 2
    assert (
        repository.cleanup_terminal_live_segment_indexes(before=now + timedelta(seconds=1), limit=1)
        == 1
    )
    assert (
        repository.cleanup_terminal_live_segment_indexes(before=now + timedelta(seconds=1), limit=1)
        == 0
    )
    assert repository.get_live_segment_index_queue_depth()["QUEUED"] == 1


def test_terminal_cleanup_rejects_unbounded_limits() -> None:
    repository = MemoryRepository()
    with pytest.raises(ValueError, match="positive"):
        repository.cleanup_terminal_live_segment_indexes(before=datetime.now(UTC), limit=0)


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_expired_lease_rejects_every_cas_then_reclaim_invalidates_old_token(
    repository_kind: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(str(tmp_path / "expired.db"))
    )
    _save_eligible(repository)
    assert (
        repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=3)
        is IndexAdmission.QUEUED
    )
    claimed_at = datetime.now(UTC) + timedelta(seconds=1)
    first = repository.claim_live_segment_index(now=claimed_at, lease_seconds=1)
    assert first is not None and first.lease_token is not None
    expired = claimed_at + timedelta(seconds=1, microseconds=1)

    assert not repository.heartbeat_live_segment_index(
        "segment-1",
        attempt=first.attempt,
        lease_token=first.lease_token,
        now=expired,
        lease_seconds=10,
    )
    assert not repository.complete_live_segment_index(
        "segment-1", attempt=first.attempt, lease_token=first.lease_token, now=expired
    )
    assert not repository.fail_live_segment_index(
        "segment-1",
        attempt=first.attempt,
        lease_token=first.lease_token,
        transient=True,
        error_code="LATE",
        now=expired,
        retry_base_seconds=1,
    )
    assert repository.recover_live_segment_indexes(now=expired) == 1
    second = repository.claim_live_segment_index(now=expired, lease_seconds=10)
    assert second is not None and second.attempt == 2 and second.lease_token != first.lease_token
    assert not repository.complete_live_segment_index(
        "segment-1", attempt=first.attempt, lease_token=first.lease_token, now=expired
    )


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
@pytest.mark.parametrize("terminal", ["COMPLETED", "FAILED"])
def test_terminal_intent_survives_queue_cleanup_and_prevents_reconciliation(
    repository_kind: str, terminal: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(str(tmp_path / f"terminal-{terminal}.db"))
    )
    _save_eligible(repository)
    assert (
        repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=1)
        is IndexAdmission.QUEUED
    )
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = repository.claim_live_segment_index(now=now, lease_seconds=30)
    assert claimed is not None and claimed.lease_token is not None
    if terminal == "COMPLETED":
        assert repository.complete_live_segment_index(
            "segment-1", attempt=claimed.attempt, lease_token=claimed.lease_token, now=now
        )
    else:
        assert repository.fail_live_segment_index(
            "segment-1",
            attempt=claimed.attempt,
            lease_token=claimed.lease_token,
            transient=False,
            error_code="PERMANENT",
            now=now,
            retry_base_seconds=1,
        )
    marker = repository.list_sensor_pcaps()[0]
    assert marker["index_intent_state"] == terminal
    assert marker["index_intent_schema_version"] == 1
    assert marker["index_intent_parser_contract_version"] == 1
    assert (
        repository.cleanup_terminal_live_segment_indexes(before=now + timedelta(seconds=1), limit=1)
        == 1
    )
    assert repository.reconcile_live_segment_indexes(capacity=1, max_attempts=1, limit=1) == 0
    assert (
        repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=1)
        is IndexAdmission.COALESCED
    )
    assert repository.get_live_segment_index_task("segment-1") is None


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_deferred_and_transient_intents_remain_reconcilable(
    repository_kind: str, tmp_path: Path
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "retry.db")
    )
    _save_eligible(repository, "segment-1")
    _save_eligible(repository, "segment-2")
    assert (
        repository.admit_live_segment_index("segment-1", capacity=1, max_attempts=2)
        is IndexAdmission.QUEUED
    )
    assert (
        repository.admit_live_segment_index("segment-2", capacity=1, max_attempts=2)
        is IndexAdmission.DEFERRED
    )
    states = {item["id"]: item["index_intent_state"] for item in repository.list_sensor_pcaps()}
    assert states["segment-2"] == "DEFERRED"
    now = datetime.now(UTC) + timedelta(seconds=1)
    claimed = repository.claim_live_segment_index(now=now, lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    assert repository.fail_live_segment_index(
        claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=True,
        error_code="TEMP",
        now=now,
        retry_base_seconds=1,
    )
    states = {item["id"]: item["index_intent_state"] for item in repository.list_sensor_pcaps()}
    assert states["segment-1"] == "PENDING"
    assert repository.get_live_segment_index_task("segment-1").status == "QUEUED"


def test_task_spec_rejects_sensor_temporary_filenames() -> None:
    segment = _segment()
    segment["filename"] = "segment-1.pcap.uploading"
    with pytest.raises(ValueError, match="finalized classic PCAP"):
        LiveIndexTaskSpec.from_segment(segment)
