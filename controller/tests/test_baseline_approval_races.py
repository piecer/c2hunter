"""Deterministic winner schedules and real uniqueness constraints."""

from typing import Any
from uuid import UUID, uuid4

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_source import START, config

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


@pytest.mark.parametrize("failure", ["source-deleted", "ancestor-missing"])
def test_committed_winner_recovery(approval_repo: Any, monkeypatch: Any, failure: str) -> None:
    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory holds one facade lock; no independent-connection acquisition gap")
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    pg = isinstance(repo, PostgresRepository)
    peer = PostgresRepository(repo.database_url, None) if pg else SQLiteRepository(repo._path)
    winner = []
    original = bs._publication_transaction.__exit__

    def release(owner: Any, *args: Any) -> Any:
        value = original(owner, *args)
        if owner.connection is repo.connection and not owner.write and not winner:
            winner.append(
                peer.publish_baseline_source(config().scope_id, request, "reviewer", START)
            )
            if failure == "source-deleted":
                peer.delete_job(request.source_job_id)
            else:
                raw = peer.get_job(request.source_job_id)
                raw["parent_job_id"] = "missing-ancestor"
                peer.save_job(raw)
        return value

    monkeypatch.setattr(bs._publication_transaction, "__exit__", release)
    try:
        replay = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert not replay.created and replay.receipt == winner[0].receipt
        assert repo.get_baseline_scope(config().scope_id).control_revision == 1
    finally:
        peer.close()


def test_global_operation_unique_collision(approval_repo: Any, monkeypatch: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    first = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    other = h.ScopeConfig.from_mapping(dict(config().to_mapping(), scope_id=str(uuid4())))
    repo.create_baseline_scope(other, "admin", START)
    ids = [UUID(first.receipt.operation_id), uuid4()]
    calls = []

    def identity() -> UUID:
        calls.append(True)
        return ids[len(calls) - 1]

    monkeypatch.setattr("uuid.uuid4", identity)
    observed = []
    original = bs._PublicationSQL.operation

    def lookup(db: Any, *args: Any, **kw: Any) -> Any:
        observed.append(args[0])
        return original(db, *args, **kw)

    monkeypatch.setattr(bs._PublicationSQL, "operation", lookup)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.publish_baseline_source(other.scope_id, request, "reviewer", START)
    assert len(calls) == 2
    assert repo.get_baseline_scope(other.scope_id).control_revision == 0
    if not isinstance(repo, MemoryRepository):
        assert observed == [other.scope_id] * 3  # fast, final, one fresh recovery
