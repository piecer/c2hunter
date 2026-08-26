from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from test_pcap_posting_index_repository import _prepare

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def test_posting_queue_models_are_frozen_and_identity_is_exact() -> None:
    from c2hunter_controller.pcap_posting_index_queue import (
        PostingIndexIntent,
        PostingIndexIntentStatus,
        PostingIndexTaskSpec,
    )

    spec = PostingIndexTaskSpec(
        source_kind="PCAP_UPLOAD",
        source_id="source-1",
        source_version_id="version-1",
        source_size_bytes=42,
        source_sha256="a" * 64,
        capture_format="PCAP",
        parent_structural_build_id="structural-1",
        parent_structural_index_sha256="b" * 64,
        structural_schema_version=1,
        structural_parser_contract_version=1,
    )
    intent = PostingIndexIntent(
        spec, PostingIndexIntentStatus.PENDING, datetime(2026, 8, 26, tzinfo=UTC)
    )
    assert intent.spec.identity == (
        "PCAP_UPLOAD",
        "source-1",
        "version-1",
        "structural-1",
        1,
        1,
        1,
    )
    assert intent.status is PostingIndexIntentStatus.PENDING
    try:
        intent.status = PostingIndexIntentStatus.FAILED
    except Exception as exc:
        assert type(exc).__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("posting queue models must be frozen")


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_request_admit_coalesce_capacity_claim_and_terminal_cleanup(tmp_path, kind: str) -> None:
    from c2hunter_controller.pcap_posting_index_queue import (
        PostingIndexAdmission,
        PostingIndexIntentStatus,
        PostingIndexTaskStatus,
    )

    now = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(now)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "queue.db", _lease_clock=clock)
    )
    source1, parent1, _first, _second = _prepare(repository, source_id="posting-job-1")
    source2, parent2, _first2, _second2 = _prepare(repository, source_id="posting-job-2")
    assert repository.request_posting_index(source1, parent1) is not None
    assert repository.request_posting_index(source2, parent2)
    assert (
        repository.admit_posting_index("PCAP_UPLOAD", source1.source_id, capacity=1, max_attempts=1)
        is PostingIndexAdmission.QUEUED
    )
    assert (
        repository.admit_posting_index("PCAP_UPLOAD", source1.source_id, capacity=1, max_attempts=1)
        is PostingIndexAdmission.COALESCED
    )
    assert (
        repository.admit_posting_index("PCAP_UPLOAD", source2.source_id, capacity=1, max_attempts=1)
        is PostingIndexAdmission.DEFERRED
    )
    claimed = repository.claim_posting_index(lease_seconds=10)
    assert claimed is not None and claimed.spec.source_id == source1.source_id
    assert claimed.status is PostingIndexTaskStatus.RUNNING and claimed.lease_token
    clock.value = now + timedelta(seconds=1)
    assert repository.fail_posting_index(
        claimed.spec.source_kind,
        claimed.spec.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=False,
        error_code="raw unsafe error/value",
        retry_base_seconds=1,
    )
    failed = repository.get_posting_index_task("PCAP_UPLOAD", source1.source_id)
    assert failed is not None and failed.error_code == "POSTING_BUILD_FAILED"
    intent = repository.get_posting_index_intent("PCAP_UPLOAD", source1.source_id)
    assert intent is not None and intent.status is PostingIndexIntentStatus.FAILED
    clock.value = now + timedelta(seconds=2)
    assert repository.cleanup_terminal_posting_indexes(max_age_seconds=1, limit=1) == 1
    assert repository.get_posting_index_task("PCAP_UPLOAD", source1.source_id) is None
    assert repository.reconcile_posting_indexes(capacity=1, max_attempts=1, limit=1) == 1
    assert repository.get_posting_index_task("PCAP_UPLOAD", source2.source_id) is not None
    assert (
        repository.get_posting_index_intent("PCAP_UPLOAD", source1.source_id).status
        is PostingIndexIntentStatus.FAILED
    )
    repository.close()


def test_sqlite_two_facade_expiry_reclaim_rejects_every_stale_owner_operation(tmp_path) -> None:
    path = tmp_path / "leases.db"
    now = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(now)
    first = SQLiteRepository(path, _lease_clock=clock)
    source, parent, _posting, _replacement = _prepare(first)
    second = SQLiteRepository(path, _lease_clock=clock)
    assert first.request_posting_index(source, parent)
    first.admit_posting_index("PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=3)
    old = first.claim_posting_index(lease_seconds=1)
    assert old is not None and old.lease_token
    expired = now + timedelta(seconds=1, microseconds=1)
    clock.value = expired
    assert not second.heartbeat_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=old.attempt,
        lease_token=old.lease_token,
        lease_seconds=10,
    )
    assert not second.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=old.attempt,
        lease_token=old.lease_token,
        transient=True,
        error_code="POSTING_TIMEOUT",
        retry_base_seconds=1,
    )
    assert second.recover_posting_indexes() == 1
    new = second.claim_posting_index(lease_seconds=10)
    assert new is not None and new.attempt == 2 and (new.lease_token != old.lease_token)
    assert not first.heartbeat_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=old.attempt,
        lease_token=old.lease_token,
        lease_seconds=10,
    )
    assert not first.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=old.attempt,
        lease_token=old.lease_token,
        transient=False,
        error_code="POSTING_STALE_OWNER",
        retry_base_seconds=1,
    )
    assert first.get_posting_index_queue_depth() == {
        "QUEUED": 0,
        "RUNNING": 1,
        "COMPLETED": 0,
        "FAILED": 0,
    }
    assert first.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    first.close()
    second.close()


def test_sqlite_reopen_additive_queue_schema_and_bounded_reconciliation_not_starved(
    tmp_path,
) -> None:
    path = tmp_path / "reopen.db"
    repository = SQLiteRepository(path)
    sources = []
    for suffix in ("terminal", "eligible-a", "eligible-b"):
        source, parent, _one, _two = _prepare(repository, source_id=f"posting-job-{suffix}")
        sources.append((source, parent))
        assert repository.request_posting_index(source, parent)
    terminal_source = sources[0][0]
    repository.admit_posting_index(
        "PCAP_UPLOAD", terminal_source.source_id, capacity=3, max_attempts=1
    )
    terminal = repository.claim_posting_index(lease_seconds=10)
    assert terminal is not None and terminal.lease_token
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        terminal.spec.source_id,
        attempt=terminal.attempt,
        lease_token=terminal.lease_token,
        transient=False,
        error_code="POSTING_PERMANENT",
        retry_base_seconds=1,
    )
    repository.close()
    reopened = SQLiteRepository(path)
    assert reopened.reconcile_posting_indexes(capacity=3, max_attempts=1, limit=1) == 1
    assert reopened.get_posting_index_task("PCAP_UPLOAD", sources[1][0].source_id) is not None
    assert reopened.get_posting_index_task("PCAP_UPLOAD", sources[2][0].source_id) is None
    tables = {
        row[0]
        for row in reopened.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'pcap_posting_index_%'"
        )
    }
    assert {"pcap_posting_index_intents", "pcap_posting_index_jobs"} <= tables
    assert reopened.connection.execute("PRAGMA foreign_key_check").fetchall() == []
    reopened.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_exact_expiry_retry_backoff_attempt_exhaustion_and_depth(tmp_path, kind: str) -> None:
    from c2hunter_controller.pcap_posting_index_queue import (
        PostingIndexIntentStatus,
        PostingIndexTaskStatus,
    )

    now = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(now)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "retry.db", _lease_clock=clock)
    )
    source, parent, _one, _two = _prepare(repository, source_id=f"posting-retry-{kind}")
    assert repository.request_posting_index(source, parent)
    repository.admit_posting_index("PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=2)
    first = repository.claim_posting_index(lease_seconds=10)
    assert first is not None and first.lease_token and first.lease_expires_at
    clock.value = first.lease_expires_at
    assert not repository.heartbeat_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=first.attempt,
        lease_token=first.lease_token,
        lease_seconds=10,
    )
    assert repository.recover_posting_indexes() == 1
    second = repository.claim_posting_index(lease_seconds=10)
    assert second is not None and second.lease_token and (second.attempt == 2)
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=second.attempt,
        lease_token=second.lease_token,
        transient=True,
        error_code="POSTING_STORAGE_UNAVAILABLE",
        retry_base_seconds=7,
    )
    task = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    intent = repository.get_posting_index_intent("PCAP_UPLOAD", source.source_id)
    assert task is not None and task.status is PostingIndexTaskStatus.FAILED
    assert task.error_code == "POSTING_STORAGE_UNAVAILABLE"
    assert intent is not None and intent.status is PostingIndexIntentStatus.FAILED
    assert repository.get_posting_index_queue_depth() == {
        "QUEUED": 0,
        "RUNNING": 0,
        "COMPLETED": 0,
        "FAILED": 1,
    }
    repository.close()


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_transient_failure_uses_exponential_backoff_before_reclaim(tmp_path, kind: str) -> None:
    now = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(now)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "backoff.db", _lease_clock=clock)
    )
    source, parent, _one, _two = _prepare(repository, source_id=f"posting-backoff-{kind}")
    assert repository.request_posting_index(source, parent)
    repository.admit_posting_index("PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=3)
    claimed = repository.claim_posting_index(lease_seconds=30)
    assert claimed is not None and claimed.lease_token
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=True,
        error_code="POSTING_STORAGE_UNAVAILABLE",
        retry_base_seconds=7,
    )
    clock.value = now + timedelta(seconds=6)
    assert repository.claim_posting_index(lease_seconds=30) is None
    clock.value = now + timedelta(seconds=7)
    retried = repository.claim_posting_index(lease_seconds=30)
    assert retried is not None and retried.attempt == 2
    repository.close()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("SAFE_CODE", "SAFE_CODE"),
        ("lowercase", "POSTING_BUILD_FAILED"),
        ("X" * 65, "POSTING_BUILD_FAILED"),
        ("ADDRESS_203_0_113_8", "ADDRESS_203_0_113_8"),
        (None, "POSTING_BUILD_FAILED"),
    ],
)
def test_sanitize_error_code_has_a_bounded_stable_vocabulary_shape(raw, expected: str) -> None:
    from c2hunter_controller.pcap_posting_index_queue import sanitize_error_code

    assert sanitize_error_code(raw) == expected


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_repository_clock_controls_request_admission_retry_and_claim_eligibility(
    tmp_path, kind: str
) -> None:
    base = datetime(2026, 8, 26, tzinfo=UTC)
    clock = MutableClock(base)
    repository = (
        MemoryRepository(_lease_clock=clock)
        if kind == "memory"
        else SQLiteRepository(tmp_path / "lifecycle-clock.db", _lease_clock=clock)
    )
    source, parent, _one, _two = _prepare(repository, source_id=f"lifecycle-clock-{kind}")
    intent = repository.request_posting_index(
        source, parent, requested_at=base + timedelta(days=365)
    )
    assert intent is not None and intent.requested_at == base and (intent.updated_at == base)
    repository.admit_posting_index(
        "PCAP_UPLOAD", source.source_id, capacity=1, max_attempts=3, now=base - timedelta(days=365)
    )
    queued = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    assert queued is not None and queued.queued_at == base and (queued.updated_at == base)
    claimed = repository.claim_posting_index(now=base + timedelta(days=365), lease_seconds=30)
    assert claimed is not None and claimed.lease_token and (claimed.updated_at == base)
    clock.value = base + timedelta(seconds=1)
    assert repository.fail_posting_index(
        "PCAP_UPLOAD",
        source.source_id,
        attempt=claimed.attempt,
        lease_token=claimed.lease_token,
        transient=True,
        error_code="POSTING_STORAGE_UNAVAILABLE",
        now=base - timedelta(days=365),
        retry_base_seconds=7,
    )
    failed = repository.get_posting_index_task("PCAP_UPLOAD", source.source_id)
    assert failed is not None
    assert failed.next_attempt_at == base + timedelta(seconds=8)
    assert failed.updated_at == base + timedelta(seconds=1)
    clock.value = base + timedelta(seconds=7)
    assert repository.claim_posting_index(now=base + timedelta(days=365), lease_seconds=30) is None
    clock.value = base + timedelta(seconds=8)
    retried = repository.claim_posting_index(now=base - timedelta(days=365), lease_seconds=30)
    assert retried is not None and retried.attempt == 2 and (retried.updated_at == clock.value)
    repository.close()
