from __future__ import annotations

import hashlib
import io
import ipaddress
import struct
from copy import deepcopy
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from c2hunter_analysis.pcap_index import scan_structural_packet_index
from c2hunter_analysis.pcap_postings import PostingQueryLimits

from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    SourceIndexBinding,
    StructuralIndexSnapshot,
    structural_index_digest,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    posting_index_identity,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


class _FaultOnceDict(dict):
    def __init__(self, values, *, key) -> None:
        super().__init__(values)
        self.key = key
        self.armed = True

    def __setitem__(self, key, value) -> None:
        if self.armed and key == self.key:
            self.armed = False
            raise RuntimeError("injected publication mutation fault")
        super().__setitem__(key, value)


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _capture() -> bytes:
    payload = b"repo"
    udp = struct.pack("!HHHH", 50000, 443, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        69,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("10.0.0.8").packed,
        ipaddress.ip_address("203.0.113.8").packed,
    )
    packet = bytes.fromhex("0200000000020200000000010800") + ip + udp
    return (
        struct.pack("<IHHIIII", 2712847316, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 2, len(packet), len(packet))
        + packet
    )


def _prepare(repository, *, source_id: str = "posting-job"):
    from c2hunter_controller.pcap_posting_index import build_source_posting_index

    capture = _capture()
    digest = hashlib.sha256(capture).hexdigest()
    build_prefix = source_id.replace("posting-job", "posting")
    binding = SourceIndexBinding(
        "PCAP_UPLOAD", source_id, f"sha256:{digest}", len(capture), digest, "PCAP"
    )
    repository.create_job(
        {
            "id": source_id,
            "idempotency_key": f"{source_id}-key",
            "mode": "PCAP_UPLOAD",
            "source": {
                "packet_bytes_retained": True,
                "size_bytes": len(capture),
                "sha256": digest,
                "capture_format": "PCAP",
            },
        }
    )
    repository.save_job_capture(source_id, capture)
    scan = scan_structural_packet_index(io.BytesIO(capture), max_packets=10, max_interfaces=2)
    parent_build_id = f"{build_prefix}-parent-ready"
    repository.begin_structural_index(parent_build_id, binding, datetime.now(UTC))
    repository.stage_structural_index_packets(parent_build_id, scan.packets)
    assert repository.publish_structural_index(
        parent_build_id, binding, scan.interfaces, scan.packet_count
    )
    parent = StructuralIndexSnapshot(
        parent_build_id,
        binding,
        datetime.now(UTC),
        structural_index_digest(binding, scan.interfaces, scan.packets),
        scan.interfaces,
        scan.packets,
    )
    source_version = CaptureSourceVersion(
        "PCAP_UPLOAD",
        source_id,
        f"captures/{source_id}.pcap",
        f"sha256:{digest}",
        len(capture),
        digest,
    )

    class Source(io.BytesIO):
        version_id = f"sha256:{digest}"

    first = build_source_posting_index(
        Source(capture),
        source_version=source_version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id=f"{build_prefix}-first",
    )
    second = build_source_posting_index(
        Source(capture),
        source_version=source_version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id=f"{build_prefix}-second",
    )
    return (source_version, parent, first, second)


def _claim(repository, source_version, parent, *, now: datetime | None = None):
    """Create the exact intent, admit it, and return its claimed lease plus time."""
    current = now or datetime.now(UTC)
    assert repository.request_posting_index(source_version, parent)
    assert repository.admit_posting_index(
        source_version.source_kind, source_version.source_id, capacity=10, max_attempts=3
    ).value in {"QUEUED", "COALESCED"}
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    return (claimed, current)


def _stage(repository, snapshot, claimed, now: datetime, *, chunks=None) -> None:
    repository.begin_posting_index(
        snapshot, attempt=claimed.attempt, lease_token=claimed.lease_token
    )
    repository.stage_posting_index_chunks(
        snapshot.build_id,
        snapshot.generation.chunks if chunks is None else chunks,
        source_kind=claimed.spec.source_kind,
        source_id=claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
    )


def _publish(repository, snapshot, source_version, parent, claimed, now: datetime) -> bool:
    return repository.publish_posting_index(
        snapshot.build_id,
        source_version=source_version,
        parent=parent,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
    )


@pytest.mark.parametrize("fault_target", ["generation", "owner", "task", "intent"])
def test_memory_posting_publication_rolls_back_every_mutation_with_prior_owner(
    fault_target: str,
) -> None:
    repository = MemoryRepository()
    source, parent, old_snapshot, replacement = _prepare(
        repository, source_id=f"publication-fault-{fault_target}"
    )
    owner_key = (source.source_kind, source.source_id, parent.build_id)
    lifecycle_key = owner_key[:2]
    repository.posting_index_generations[old_snapshot.build_id] = old_snapshot
    repository.posting_index_owners[owner_key] = old_snapshot.build_id
    claimed, now = _claim(repository, source, parent)
    _stage(repository, replacement, claimed, now)

    affected = {
        "generations": deepcopy(repository.posting_index_generations),
        "owners": deepcopy(repository.posting_index_owners),
        "tasks": deepcopy(repository.posting_index_tasks),
        "intents": deepcopy(repository.posting_index_intents),
        "staging": deepcopy(repository.posting_index_staging),
    }
    target_name, target_key = {
        "generation": ("posting_index_generations", replacement.build_id),
        "owner": ("posting_index_owners", owner_key),
        "task": ("posting_index_tasks", lifecycle_key),
        "intent": ("posting_index_intents", lifecycle_key),
    }[fault_target]
    setattr(
        repository,
        target_name,
        _FaultOnceDict(getattr(repository, target_name), key=target_key),
    )

    with pytest.raises(RuntimeError, match="injected publication mutation fault"):
        _publish(repository, replacement, source, parent, claimed, now)

    assert repository.posting_index_generations == affected["generations"]
    assert repository.posting_index_owners == affected["owners"]
    assert repository.posting_index_tasks == affected["tasks"]
    assert repository.posting_index_intents == affected["intents"]
    assert repository.posting_index_staging == affected["staging"]
    assert repository.posting_index_owners[owner_key] == old_snapshot.build_id
    assert replacement.build_id not in repository.posting_index_generations


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_posting_staging_invisible_atomic_publish_and_reopen(tmp_path, kind: str) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    path = tmp_path / "postings.sqlite"
    repository = MemoryRepository() if kind == "memory" else SQLiteRepository(path)
    source_version, parent, first, _ = _prepare(repository)
    assert repository.request_posting_index(source_version, parent)
    assert (
        repository.admit_posting_index(
            source_version.source_kind, source_version.source_id, capacity=1, max_attempts=3
        ).value
        == "QUEUED"
    )
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    repository.begin_posting_index(first, attempt=claimed.attempt, lease_token=claimed.lease_token)
    repository.stage_posting_index_chunks(
        first.build_id,
        first.generation.chunks,
        source_kind=claimed.spec.source_kind,
        source_id=claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
    )
    assert (
        repository.get_posting_index(source_version, parent).availability
        is PostingIndexAvailability.MISSING
    )
    assert not repository.publish_posting_index(
        first.build_id,
        source_version=source_version,
        parent=parent,
        attempt=claimed.attempt,
        lease_token="wrong",
    )
    assert repository.publish_posting_index(
        first.build_id,
        source_version=source_version,
        parent=parent,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
    )
    lookup = repository.get_posting_index(source_version, parent)
    assert lookup.availability is PostingIndexAvailability.READY
    assert lookup.snapshot == replace(first, created_at=lookup.snapshot.created_at)
    completed_task = repository.get_posting_index_task("PCAP_UPLOAD", source_version.source_id)
    completed_intent = repository.get_posting_index_intent("PCAP_UPLOAD", source_version.source_id)
    assert completed_task is not None and completed_task.status.value == "COMPLETED"
    assert completed_task.lease_token is None and completed_task.lease_expires_at is None
    assert completed_intent is not None and completed_intent.status.value == "COMPLETED"
    assert completed_intent.published_build_id == first.build_id
    if kind == "sqlite":
        repository.close()
        repository = SQLiteRepository(path)
        assert (
            repository.get_posting_index(source_version, parent).availability
            is PostingIndexAvailability.READY
        )
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_bounded_posting_lookup_rejects_oversized_directory_before_materialization(
    tmp_path, kind: str
) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "bounded-postings.sqlite")
    )
    source, parent, posting, _replacement = _prepare(repository, source_id=f"bounded-{kind}")
    claimed, now = _claim(repository, source, parent)
    _stage(repository, posting, claimed, now)
    assert _publish(repository, posting, source, parent, claimed, now)
    chunk_count = len(posting.generation.chunks)
    assert chunk_count > 1
    sql: list[str] = []
    if kind == "sqlite":
        repository.connection.set_trace_callback(sql.append)

    limited = repository.get_posting_index(
        source,
        parent,
        PostingQueryLimits(max_directory_chunks=chunk_count - 1),
    )

    assert limited.availability is PostingIndexAvailability.RESOURCE_LIMIT
    assert limited.snapshot is None
    if kind == "sqlite":
        assert not any("FROM pcap_posting_index_chunks" in query for query in sql)
        repository.connection.set_trace_callback(None)
    accepted = repository.get_posting_index(
        source,
        parent,
        PostingQueryLimits(max_directory_chunks=chunk_count),
    )
    assert accepted.availability is PostingIndexAvailability.READY
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_posting_identity_lookup_is_compact_exact_and_never_reads_chunks(
    tmp_path, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "posting-identity.sqlite")
    )
    source, parent, posting, _replacement = _prepare(repository, source_id=f"identity-{kind}")
    claimed, now = _claim(repository, source, parent)
    _stage(repository, posting, claimed, now)
    assert _publish(repository, posting, source, parent, claimed, now)
    full = repository.get_posting_index(source, parent)
    assert full.snapshot is not None
    sql: list[str] = []
    if kind == "sqlite":
        repository.connection.set_trace_callback(sql.append)

    compact = repository.get_posting_index_identity(source, parent)

    assert compact.availability is PostingIndexAvailability.READY
    assert compact.identity == posting_index_identity(full.snapshot)
    if kind == "sqlite":
        posting_sql = [query for query in sql if "pcap_posting_index" in query]
        assert len(posting_sql) == 1
        assert "pcap_posting_index_chunks" not in posting_sql[0]
        repository.connection.set_trace_callback(None)
    repository.close()


def test_sqlite_posting_owner_composite_fk_rejects_cross_source_and_is_idempotent(
    tmp_path,
) -> None:
    path = tmp_path / "posting-owner-composite.sqlite"
    repository = SQLiteRepository(path)
    source_a, parent_a, first_a, _ = _prepare(repository, source_id="owner-source-a")
    claim_a, now_a = _claim(repository, source_a, parent_a)
    _stage(repository, first_a, claim_a, now_a)
    assert _publish(repository, first_a, source_a, parent_a, claim_a, now_a)
    source_b, parent_b, first_b, _ = _prepare(repository, source_id="owner-source-b")
    claim_b, now_b = _claim(repository, source_b, parent_b)
    _stage(repository, first_b, claim_b, now_b)
    assert _publish(repository, first_b, source_b, parent_b, claim_b, now_b)
    repository.connection.execute(
        "DELETE FROM pcap_posting_index_owners WHERE source_kind=? AND source_id=?",
        (source_b.source_kind, source_b.source_id),
    )
    with pytest.raises(Exception, match="FOREIGN KEY constraint failed"):
        repository.connection.execute(
            "UPDATE pcap_posting_index_owners SET build_id=? "
            "WHERE source_kind=? AND source_id=? AND parent_structural_build_id=?",
            (first_b.build_id, source_a.source_kind, source_a.source_id, parent_a.build_id),
        )
    repository.connection.rollback()
    assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()

    for _ in range(2):
        reopened = SQLiteRepository(path)
        assert reopened.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        owner_sql = reopened.connection.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='pcap_posting_index_owners'"
        ).fetchone()[0]
        assert "FOREIGN KEY(source_kind,source_id,parent_structural_build_id,build_id)" in owner_sql
        reopened.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_same_build_request_preserves_terminal_lifecycle(tmp_path, kind: str) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "same-terminal.sqlite")
    )
    source, parent, _first, _second = _prepare(repository, source_id=f"same-terminal-{kind}")
    original = repository.request_posting_index(source, parent)
    assert original is not None
    repository.admit_posting_index("PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=1)
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=False,
        error_code="POSTING_TERMINAL",
        retry_base_seconds=1,
    )
    terminal_intent = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    terminal_task = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    assert terminal_intent is not None and terminal_intent.status.value == "FAILED"
    assert terminal_task is not None and terminal_task.status.value == "FAILED"

    assert repository.request_posting_index(source, parent) == terminal_intent
    assert repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id) == terminal_intent
    assert repository.get_posting_index_task("PCAP_UPLOAD", source.source_id) == terminal_task
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_replaced_parent_removes_old_lifecycle_before_marker_and_creates_no_task(
    tmp_path, kind: str
) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "replace-parent.sqlite")
    )
    source, parent, _first, _second = _prepare(repository, source_id=f"replace-parent-{kind}")
    assert repository.request_posting_index(source, parent)
    repository.admit_posting_index("PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=1)
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=False,
        error_code="POSTING_TERMINAL",
        retry_base_seconds=1,
    )

    replacement_id = f"{parent.build_id}-replacement"
    repository.begin_structural_index(replacement_id, parent.binding, datetime.now(UTC))
    repository.stage_structural_index_packets(replacement_id, parent.packets)
    assert repository.publish_structural_index(
        replacement_id,
        parent.binding,
        parent.interfaces,
        len(parent.packets),
        request_postings=True,
    )
    marker = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    assert marker is not None and marker.spec.parent_structural_build_id == replacement_id
    assert marker.status.value == "PENDING"
    assert repository.get_posting_index_task("PCAP_UPLOAD", source.source_id) is None
    if kind == "sqlite":
        assert repository.connection.execute(
            "SELECT build_id FROM pcap_offset_index_owners "
            "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
            (source.source_id,),
        ).fetchone() == (replacement_id,)
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_marker_exception_rolls_back_structural_ready_owner(tmp_path, kind: str) -> None:
    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "marker-rollback.sqlite")
    )
    source, parent, _first, _second = _prepare(repository, source_id=f"marker-rollback-{kind}")
    replacement_id = f"{parent.build_id}-replacement"
    repository.begin_structural_index(replacement_id, parent.binding, datetime.now(UTC))
    repository.stage_structural_index_packets(replacement_id, parent.packets)
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

    with pytest.raises(Exception, match="marker write failed"):
        repository.publish_structural_index(
            replacement_id,
            parent.binding,
            parent.interfaces,
            len(parent.packets),
            request_postings=True,
        )
    if kind == "memory":
        assert (
            repository.structural_index_owners[("PCAP_UPLOAD", source.source_id)] == parent.build_id
        )
        assert replacement_id in repository.structural_index_staging
    else:
        assert repository.connection.execute(
            "SELECT build_id FROM pcap_offset_index_owners "
            "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
            (source.source_id,),
        ).fetchone() == (parent.build_id,)
        assert repository.connection.execute(
            "SELECT state FROM pcap_offset_index_generations WHERE build_id=?",
            (replacement_id,),
        ).fetchone() == ("STAGING",)
        assert not repository.connection.in_transaction
    repository.close()


def test_sqlite_two_facade_stale_owner_cas_preserves_winner(tmp_path) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    path = tmp_path / "two-facade.sqlite"
    now = datetime.now(UTC)
    clock = MutableClock(now)
    first_facade = SQLiteRepository(path, _lease_clock=clock)
    source_version, parent, first, second = _prepare(first_facade)
    second_facade = SQLiteRepository(path, _lease_clock=clock)
    first_claim, _ = _claim(first_facade, source_version, parent, now=now)
    first_facade.connection.execute(
        "UPDATE pcap_posting_index_jobs SET lease_expires_at=?,"
        "data=json_set(data,'$.lease_expires_at',?) "
        "WHERE source_kind='PCAP_UPLOAD' AND source_id=?",
        (
            (now + timedelta(seconds=1)).isoformat(),
            (now + timedelta(seconds=1)).isoformat(),
            source_version.source_id,
        ),
    )
    first_facade.connection.commit()
    first_claim = first_facade.get_posting_index_task("PCAP_UPLOAD", source_version.source_id)
    assert first_claim is not None and first_claim.lease_token
    _stage(first_facade, first, first_claim, now)
    expired = now + timedelta(seconds=1, microseconds=1)
    clock.value = expired
    assert second_facade.recover_posting_indexes() == 1
    second_claim = second_facade.claim_posting_index(lease_seconds=30)
    assert second_claim is not None and second_claim.lease_token
    _stage(second_facade, second, second_claim, expired)
    assert _publish(second_facade, second, source_version, parent, second_claim, expired)
    assert not first_facade.publish_posting_index(
        first.build_id,
        source_version=source_version,
        parent=parent,
        attempt=first_claim.attempt,
        lease_token=first_claim.lease_token,
    )
    lookup = second_facade.get_posting_index(source_version, parent)
    assert lookup.availability is PostingIndexAvailability.READY
    assert lookup.snapshot is not None and lookup.snapshot.build_id == second.build_id
    assert second_facade.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    first_facade.close()
    second_facade.close()


@pytest.mark.parametrize(
    ("table", "operation", "trigger_name"),
    [
        ("pcap_posting_index_generations", "UPDATE", "ignore_generation_ready"),
        ("pcap_posting_index_owners", "INSERT", "ignore_owner_publish"),
        ("pcap_posting_index_jobs", "UPDATE", "ignore_task_completion"),
        ("pcap_posting_index_intents", "UPDATE", "ignore_intent_completion"),
    ],
)
def test_sqlite_publish_rowcount_mismatch_rolls_back_generation_owner_task_and_intent(
    tmp_path, table: str, operation: str, trigger_name: str
) -> None:
    repository = SQLiteRepository(tmp_path / f"{trigger_name}.sqlite")
    source, parent, posting, _ = _prepare(repository, source_id=f"posting-{trigger_name}")
    claimed, now = _claim(repository, source, parent)
    _stage(repository, posting, claimed, now)
    prior_build_id = f"{posting.build_id}-prior-owner"
    repository.connection.execute(
        "INSERT INTO pcap_posting_index_generations("
        "build_id,source_kind,source_id,parent_structural_build_id,state,binding,created_at,"
        "generation_metadata,builder_attempt,lease_token,expected_owner_build_id) "
        "SELECT ?,source_kind,source_id,parent_structural_build_id,'READY',binding,created_at,"
        "generation_metadata,builder_attempt,lease_token,NULL "
        "FROM pcap_posting_index_generations WHERE build_id=?",
        (prior_build_id, posting.build_id),
    )
    repository.connection.execute(
        "INSERT INTO pcap_posting_index_owners("
        "source_kind,source_id,parent_structural_build_id,build_id) VALUES(?,?,?,?)",
        (source.source_kind, source.source_id, parent.build_id, prior_build_id),
    )
    repository.connection.execute(
        "UPDATE pcap_posting_index_generations SET expected_owner_build_id=? WHERE build_id=?",
        (prior_build_id, posting.build_id),
    )
    when = (
        "NEW.state='READY'"
        if table == "pcap_posting_index_generations"
        else "1"
        if table == "pcap_posting_index_owners"
        else "NEW.status='COMPLETED'"
    )
    repository.connection.execute(
        f"CREATE TRIGGER {trigger_name} BEFORE {operation} ON {table} "
        f"WHEN {when} BEGIN SELECT RAISE(IGNORE); END"
    )
    repository.connection.commit()
    assert not _publish(repository, posting, source, parent, claimed, now)
    assert repository.connection.execute(
        "SELECT state FROM pcap_posting_index_generations WHERE build_id=?", (posting.build_id,)
    ).fetchone() == ("STAGING",)
    assert repository.connection.execute(
        "SELECT build_id FROM pcap_posting_index_owners "
        "WHERE source_kind=? AND source_id=? AND parent_structural_build_id=?",
        (source.source_kind, source.source_id, parent.build_id),
    ).fetchone() == (prior_build_id,)
    assert repository.connection.execute(
        "SELECT state FROM pcap_posting_index_generations WHERE build_id=?", (prior_build_id,)
    ).fetchone() == ("READY",)
    task = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    intent = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    assert task is not None and task.status.value == "RUNNING"
    assert intent is not None and intent.status.value == "PENDING"
    assert not repository.connection.in_transaction
    assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


def test_memory_corrupt_ready_generation_is_unavailable() -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    repository = MemoryRepository()
    source_version, parent, first, _ = _prepare(repository)
    claimed, now = _claim(repository, source_version, parent)
    _stage(repository, first, claimed, now)
    assert _publish(repository, first, source_version, parent, claimed, now)
    repository.posting_index_generations[first.build_id] = replace(
        first, generation=replace(first.generation, digest="0" * 64)
    )
    assert (
        repository.get_posting_index(source_version, parent).availability
        is PostingIndexAvailability.CORRUPT
    )


def test_posting_corruption_and_source_deletion_are_unavailable(tmp_path) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    repository = SQLiteRepository(tmp_path / "corrupt.sqlite")
    source_version, parent, first, _ = _prepare(repository)
    claimed, now = _claim(repository, source_version, parent)
    _stage(repository, first, claimed, now)
    assert _publish(repository, first, source_version, parent, claimed, now)
    repository.connection.execute(
        "UPDATE pcap_posting_index_chunks SET encoded_ordinals=? "
        "WHERE build_id=? AND chunk_ordinal=0",
        (b"\x00", first.build_id),
    )
    repository.connection.commit()
    assert (
        repository.get_posting_index(source_version, parent).availability
        is PostingIndexAvailability.CORRUPT
    )
    assert repository.delete_retained_source("posting-job")
    assert (
        repository.connection.execute(
            "SELECT COUNT(*) FROM pcap_posting_index_generations"
        ).fetchone()[0]
        == 0
    )
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_partial_replacement_fails_without_replacing_ready_owner(tmp_path, kind: str) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    now = datetime.now(UTC)
    clock = MutableClock(now)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "replacement.sqlite", _lease_clock=clock)
    )
    source_version, parent, first, second = _prepare(repository)
    first_claim, now = _claim(repository, source_version, parent, now=now)
    _stage(repository, first, first_claim, now)
    expired = now + timedelta(seconds=31)
    clock.value = expired
    assert repository.recover_posting_indexes() == 1
    second_claim = repository.claim_posting_index(lease_seconds=30)
    assert second_claim is not None and second_claim.lease_token
    _stage(repository, second, second_claim, expired, chunks=second.generation.chunks[:-1])
    assert not _publish(repository, second, source_version, parent, second_claim, expired)
    assert not _publish(repository, first, source_version, parent, first_claim, expired)
    lookup = repository.get_posting_index(source_version, parent)
    assert lookup.availability is PostingIndexAvailability.MISSING
    if kind == "sqlite":
        assert not repository.connection.in_transaction
        assert repository.connection.execute(
            "SELECT state FROM pcap_posting_index_generations WHERE build_id=?", (second.build_id,)
        ).fetchone() == ("STAGING",)
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_job_deletion_removes_exact_postings_and_preserves_unrelated_source(
    tmp_path, kind: str
) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "exact-delete.sqlite")
    )
    deleted_source, deleted_parent, deleted, _ = _prepare(repository)
    kept_source, kept_parent, kept, _ = _prepare(repository, source_id="posting-job-unrelated")
    for source_version, parent, snapshot in (
        (deleted_source, deleted_parent, deleted),
        (kept_source, kept_parent, kept),
    ):
        claimed, now = _claim(repository, source_version, parent)
        _stage(repository, snapshot, claimed, now)
        assert _publish(repository, snapshot, source_version, parent, claimed, now)
    assert repository.delete_retained_source(deleted_source.source_id)
    assert repository.get_posting_index_task("PCAP_UPLOAD", deleted_source.source_id) is None
    assert repository.get_posting_index_intent("PCAP_UPLOAD", deleted_source.source_id) is None
    assert (
        repository.get_posting_index(deleted_source, deleted_parent).availability
        is PostingIndexAvailability.MISSING
    )
    kept_lookup = repository.get_posting_index(kept_source, kept_parent)
    assert kept_lookup.availability is PostingIndexAvailability.READY
    assert kept_lookup.snapshot == replace(kept, created_at=kept_lookup.snapshot.created_at)
    assert repository.get_posting_index_task("PCAP_UPLOAD", kept_source.source_id) is not None
    assert repository.get_posting_index_intent("PCAP_UPLOAD", kept_source.source_id) is not None
    if kind == "sqlite":
        rows = repository.connection.execute(
            "SELECT source_id,build_id FROM pcap_posting_index_owners ORDER BY source_id"
        ).fetchall()
        assert rows == [(kept_source.source_id, kept.build_id)]
        assert not repository.connection.in_transaction
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


def test_sqlite_job_deletion_rolls_back_postings_with_the_source_on_failure(tmp_path) -> None:
    from c2hunter_controller.pcap_posting_index import PostingIndexAvailability

    repository = SQLiteRepository(tmp_path / "delete-transaction.sqlite")
    source_version, parent, first, _ = _prepare(repository)
    claimed, now = _claim(repository, source_version, parent)
    _stage(repository, first, claimed, now)
    assert _publish(repository, first, source_version, parent, claimed, now)
    repository.connection.execute(
        "CREATE TRIGGER fail_capture_delete BEFORE DELETE ON job_capture_blobs "
        "BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END"
    )
    repository.connection.commit()
    with pytest.raises(Exception, match="injected delete failure"):
        repository.delete_retained_source(source_version.source_id)
    assert not repository.connection.in_transaction
    assert repository.get_job(source_version.source_id) is not None
    assert (
        repository.get_posting_index(source_version, parent).availability
        is PostingIndexAvailability.READY
    )
    assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_live_job_deletion_removes_exact_postings_and_preserves_unrelated_source(
    tmp_path, kind: str
) -> None:
    from test_pcap_offset_index_live import _build, _pcap, _save

    from c2hunter_controller.pcap_posting_index import (
        PostingIndexAvailability,
        build_source_posting_index,
    )

    repository = (
        MemoryRepository()
        if kind == "memory"
        else SQLiteRepository(tmp_path / "live-delete.sqlite")
    )
    _save(repository, _pcap())
    assert _build(repository)
    live_source = repository.get_live_capture_source_version("segment-1")
    assert live_source is not None
    live_binding = SourceIndexBinding(
        "LIVE_SEGMENT",
        "segment-1",
        live_source.source_version_id,
        live_source.source_size_bytes,
        live_source.source_sha256,
        "PCAP",
    )
    live_parent_lookup = repository.get_structural_index(live_binding)
    assert live_parent_lookup.snapshot is not None
    live_parent = live_parent_lookup.snapshot
    opened = repository.open_sensor_pcap("segment-1")
    assert opened is not None
    _, live_stream = opened
    live_posting = build_source_posting_index(
        live_stream,
        source_version=live_source,
        parent=live_parent,
        internal_networks=["10.0.0.0/8"],
        build_id="live-posting",
    )
    live_claim, live_now = _claim(repository, live_source, live_parent)
    _stage(repository, live_posting, live_claim, live_now)
    assert _publish(repository, live_posting, live_source, live_parent, live_claim, live_now)
    kept_source, kept_parent, kept_posting, _ = _prepare(
        repository, source_id="posting-job-kept-after-live"
    )
    kept_claim, kept_now = _claim(repository, kept_source, kept_parent)
    _stage(repository, kept_posting, kept_claim, kept_now)
    assert _publish(repository, kept_posting, kept_source, kept_parent, kept_claim, kept_now)
    assert repository.delete_job("live-1")
    assert repository.get_posting_index_task("LIVE_SEGMENT", live_source.source_id) is None
    assert repository.get_posting_index_intent("LIVE_SEGMENT", live_source.source_id) is None
    assert (
        repository.get_posting_index(live_source, live_parent).availability
        is PostingIndexAvailability.MISSING
    )
    kept_lookup = repository.get_posting_index(kept_source, kept_parent)
    assert kept_lookup.availability is PostingIndexAvailability.READY
    assert kept_lookup.snapshot == replace(kept_posting, created_at=kept_lookup.snapshot.created_at)
    assert repository.get_posting_index_task("PCAP_UPLOAD", kept_source.source_id) is not None
    assert repository.get_posting_index_intent("PCAP_UPLOAD", kept_source.source_id) is not None
    if kind == "sqlite":
        assert not repository.connection.in_transaction
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_begin_requires_task_spec_to_match_the_exact_staged_snapshot(tmp_path, kind: str) -> None:
    repository = MemoryRepository() if kind == "memory" else SQLiteRepository(tmp_path / "exact.db")
    source, parent, posting, _ = _prepare(repository, source_id=f"posting-exact-{kind}")
    claimed, now = _claim(repository, source, parent)
    mismatched = replace(
        posting, binding=replace(posting.binding, parent_structural_index_sha256="f" * 64)
    )
    with pytest.raises(ValueError, match="posting task lease is not current"):
        repository.begin_posting_index(
            mismatched, attempt=claimed.attempt, lease_token=claimed.lease_token
        )
    assert repository.get_posting_index(source, parent).snapshot is None
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_staging_cleanup_is_bounded_and_excludes_an_active_unexpired_generation(
    tmp_path, kind: str
) -> None:
    now = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(now)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "cleanup.db", _lease_clock=clock)
    )
    stale_source, stale_parent, stale_posting, stale_replacement = _prepare(
        repository, source_id=f"posting-cleanup-stale-{kind}"
    )
    active_source, active_parent, active_posting, active_replacement = _prepare(
        repository, source_id=f"posting-cleanup-active-{kind}"
    )
    stale_claim, _ = _claim(repository, stale_source, stale_parent, now=now)
    _stage(repository, stale_posting, stale_claim, now)
    active_claim, _ = _claim(repository, active_source, active_parent, now=now)
    _stage(repository, active_posting, active_claim, now)
    clock.value = now + timedelta(seconds=1)
    assert repository.cleanup_stale_posting_indexes(max_age_seconds=1, limit=1) == 0
    expired = now + timedelta(seconds=31)
    clock.value = expired
    assert repository.recover_posting_indexes() == 2
    assert repository.cleanup_stale_posting_indexes(max_age_seconds=30, limit=1) == 1
    reclaimed = repository.claim_posting_index(lease_seconds=30)
    assert reclaimed is not None and reclaimed.lease_token
    if reclaimed.spec.source_id == stale_source.source_id:
        active_snapshot = stale_replacement
    else:
        active_snapshot = active_replacement
    _stage(repository, active_snapshot, reclaimed, expired)
    active_build_id = active_snapshot.build_id
    assert repository.cleanup_stale_posting_indexes(max_age_seconds=30, limit=1) == 1
    if kind == "memory":
        assert active_build_id in repository.posting_index_staging
        assert set(repository.posting_index_staging) == {active_build_id}
    else:
        rows = repository.connection.execute(
            "SELECT build_id FROM pcap_posting_index_generations WHERE state='STAGING'"
        ).fetchall()
        assert rows == [(active_build_id,)]
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_active_posting_task_blocks_structural_owner_replacement(tmp_path, kind: str) -> None:
    repository = (
        MemoryRepository() if kind == "memory" else SQLiteRepository(tmp_path / "parent-race.db")
    )
    source, parent, _posting, _ = _prepare(repository, source_id=f"posting-parent-race-{kind}")
    _claimed, _now = _claim(repository, source, parent)
    replacement_id = f"{parent.build_id}-replacement"
    repository.begin_structural_index(replacement_id, parent.binding, parent.created_at)
    repository.stage_structural_index_packets(replacement_id, parent.packets)
    assert not repository.publish_structural_index(
        replacement_id, parent.binding, parent.interfaces, len(parent.packets)
    )
    lookup = repository.get_structural_index(parent.binding)
    assert lookup.snapshot is not None and lookup.snapshot.build_id == parent.build_id
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_structural_owner_replacement_cascades_old_posting_lifecycle(tmp_path, kind: str) -> None:
    repository = (
        MemoryRepository() if kind == "memory" else SQLiteRepository(tmp_path / "parent-cascade.db")
    )
    source, parent, posting, _ = _prepare(repository, source_id=f"posting-parent-cascade-{kind}")
    claimed, now = _claim(repository, source, parent)
    _stage(repository, posting, claimed, now)
    assert _publish(repository, posting, source, parent, claimed, now)
    kept_source, kept_parent, kept_posting, _ = _prepare(
        repository, source_id=f"posting-parent-cascade-kept-{kind}"
    )
    kept_claim, kept_now = _claim(repository, kept_source, kept_parent)
    _stage(repository, kept_posting, kept_claim, kept_now)
    assert _publish(repository, kept_posting, kept_source, kept_parent, kept_claim, kept_now)
    replacement_id = f"{parent.build_id}-replacement"
    repository.begin_structural_index(replacement_id, parent.binding, now)
    repository.stage_structural_index_packets(replacement_id, parent.packets)
    assert repository.publish_structural_index(
        replacement_id, parent.binding, parent.interfaces, len(parent.packets)
    )
    assert repository.get_posting_index_task("PCAP_UPLOAD", source.source_id) is None
    assert repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id) is None
    assert repository.get_posting_index_task("PCAP_UPLOAD", kept_source.source_id) is not None
    assert repository.get_posting_index_intent("PCAP_UPLOAD", kept_source.source_id) is not None
    assert repository.get_posting_index(kept_source, kept_parent).snapshot == replace(
        kept_posting,
        created_at=repository.get_posting_index(kept_source, kept_parent).snapshot.created_at,
    )
    if kind == "memory":
        assert posting.build_id not in repository.posting_index_generations
        assert repository.posting_index_owners == {
            ("PCAP_UPLOAD", kept_source.source_id, kept_parent.build_id): kept_posting.build_id
        }
    else:
        assert repository.connection.execute(
            "SELECT source_id,build_id FROM pcap_posting_index_owners"
        ).fetchall() == [(kept_source.source_id, kept_posting.build_id)]
        assert repository.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_authoritative_lease_clock_rejects_backdated_and_future_dated_owner_calls(
    tmp_path, kind: str
) -> None:
    base = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(base)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "authoritative.db", _lease_clock=clock)
    )
    source, parent, posting, replacement = _prepare(repository, source_id=f"posting-clock-{kind}")
    claimed, _ = _claim(repository, source, parent, now=base)
    assert claimed.lease_token and claimed.lease_expires_at == base + timedelta(seconds=30)
    future = base + timedelta(days=365)
    repository.begin_posting_index(
        posting, attempt=claimed.attempt, lease_token=claimed.lease_token, now=future
    )
    repository.stage_posting_index_chunks(
        posting.build_id,
        posting.generation.chunks,
        source_kind=claimed.spec.source_kind,
        source_id=claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=future,
    )
    assert repository.heartbeat_posting_index(
        claimed.spec.source_kind,
        claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=future,
        lease_seconds=30,
    )
    clock.value = base + timedelta(seconds=30)
    backdated = base - timedelta(days=365)
    assert not repository.heartbeat_posting_index(
        claimed.spec.source_kind,
        claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=backdated,
        lease_seconds=30,
    )
    assert not repository.fail_posting_index(
        claimed.spec.source_kind,
        claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=True,
        error_code="POSTING_TIMEOUT",
        now=backdated,
        retry_base_seconds=1,
    )
    assert not repository.publish_posting_index(
        posting.build_id,
        source_version=source,
        parent=parent,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=backdated,
    )
    with pytest.raises(ValueError, match="posting task lease is not current"):
        repository.begin_posting_index(
            replacement, attempt=claimed.attempt, lease_token=claimed.lease_token, now=backdated
        )
    with pytest.raises(ValueError, match="posting task lease is not current"):
        repository.stage_posting_index_chunks(
            posting.build_id,
            (),
            source_kind=claimed.spec.source_kind,
            source_id=claimed.spec.source_id,
            attempt=claimed.attempt,
            lease_token=claimed.lease_token,
            now=backdated,
        )
    assert not repository.abort_posting_index(
        posting.build_id,
        source_kind=claimed.spec.source_kind,
        source_id=claimed.spec.source_id,
        parent_structural_build_id=parent.build_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
    )
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_fenced_abort_cannot_delete_new_attempt_or_published_or_deleted_build(
    tmp_path, kind: str
) -> None:
    base = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(base)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "abort.db", _lease_clock=clock)
    )
    source, parent, old_build, new_build = _prepare(repository, source_id=f"posting-abort-{kind}")
    old, _ = _claim(repository, source, parent, now=base)
    _stage(repository, old_build, old, base)
    clock.value = base + timedelta(seconds=30)
    assert repository.recover_posting_indexes() == 1
    new = repository.claim_posting_index(lease_seconds=30)
    assert new is not None and new.lease_token
    _stage(repository, new_build, new, base - timedelta(days=1))

    def abort(snapshot, claim) -> bool:
        return repository.abort_posting_index(
            snapshot.build_id,
            source_kind=claim.spec.source_kind,
            source_id=claim.spec.source_id,
            parent_structural_build_id=parent.build_id,
            attempt=claim.attempt,
            lease_token=claim.lease_token,
        )

    assert not abort(new_build, old)
    assert not abort(old_build, old)
    assert not abort(old_build, new)
    assert not repository.abort_posting_index(
        new_build.build_id,
        source_kind=new.spec.source_kind,
        source_id=f"{new.spec.source_id}-other",
        parent_structural_build_id=parent.build_id,
        attempt=new.attempt,
        lease_token=new.lease_token,
    )
    assert abort(new_build, new)
    _stage(repository, new_build, new, clock.value)
    assert _publish(repository, new_build, source, parent, new, clock.value)
    assert not abort(new_build, new)
    repository.delete_structural_indexes_for_source(source.source_id)
    assert not abort(new_build, new)
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_repository_clock_controls_staging_publication_and_exact_cleanup_boundaries(
    tmp_path, kind: str
) -> None:
    base = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(base)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "terminal-clock.db", _lease_clock=clock)
    )
    source, parent, posting, _replacement = _prepare(repository, source_id=f"terminal-clock-{kind}")
    claimed, _ = _claim(repository, source, parent, now=base)
    assert claimed.lease_token
    repository.begin_posting_index(
        posting,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=base + timedelta(days=365),
    )
    if kind == "memory":
        assert repository.posting_index_staging[posting.build_id][0].created_at == base
    else:
        assert repository.connection.execute(
            "SELECT created_at FROM pcap_posting_index_generations WHERE build_id=?",
            (posting.build_id,),
        ).fetchone() == (base.isoformat(),)
    repository.stage_posting_index_chunks(
        posting.build_id,
        posting.generation.chunks,
        source_kind=claimed.spec.source_kind,
        source_id=claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=base - timedelta(days=365),
    )
    terminal_at = base + timedelta(seconds=1)
    clock.value = terminal_at
    assert repository.publish_posting_index(
        posting.build_id,
        source_version=source,
        parent=parent,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        now=base - timedelta(days=365),
    )
    task = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    intent = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    assert task is not None and task.updated_at == terminal_at
    assert intent is not None and intent.updated_at == terminal_at
    retention = 60
    clock.value = terminal_at + timedelta(seconds=retention) - timedelta(microseconds=1)
    assert repository.cleanup_terminal_posting_indexes(max_age_seconds=retention, limit=1) == 0
    clock.value += timedelta(microseconds=1)
    assert repository.cleanup_terminal_posting_indexes(max_age_seconds=retention, limit=1) == 1
    repository.close()
