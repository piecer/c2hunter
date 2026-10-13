"""Real explicit-review publication; synthetic times are not LIVE history."""

from datetime import timedelta
from typing import Any

import pytest

import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import START, config, review, stored

pg_repo = pg_fixtures.pg_repo


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def approval_repo(request: Any, tmp_path: Any) -> Any:
    if request.param == "postgres":
        return request.getfixturevalue("pg_repo")
    repo = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "approval.sqlite")
    )
    request.addfinalizer(repo.close)
    return repo


def prepare(repo: Any, index: int = 0) -> g.ApprovalRequest:
    raw = stored()
    delta = timedelta(minutes=index * 2)
    raw.update(
        id=f"source-{index}",
        dataset_id=f"dataset-{index}",
        start_time=(START + delta).isoformat(),
        end_time=(START + delta + timedelta(seconds=60)).isoformat(),
    )
    for row in raw["flow_records"]:
        from datetime import datetime

        row["timestamp"] = (datetime.fromisoformat(row["timestamp"]) + delta).isoformat()
    repo.save_job(raw)
    preview = repo.preview_baseline_source(config().scope_id, raw["id"], index, "APPROVAL")
    assert preview.required_review == "EXPLICIT_NORMAL_AND_QUALITY_ASSERTION"
    return g.ApprovalRequest(
        expected_revision=index,
        idempotency_key=f"approval-{index}",
        source_job_id=raw["id"],
        source_binding_sha256=preview.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="Explicit synthetic fixture review",
    )


def test_public_approval_vertical(approval_repo: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    publish = getattr(repo, "publish_baseline_source", None)
    assert callable(publish), "publication repository operation missing"
    result = publish(config().scope_id, request, "reviewer", START)
    assert result.created is True
    assert result.scope.control_revision == result.receipt.revision == 1
    assert result.scope.active.generation_id == result.receipt.generation_id
    assert result.scope.accepted_event_end == START + timedelta(seconds=60)
    assert result.scope.previous is None
    assert result.receipt.actor == "reviewer" and result.receipt.occurred_at == START
    assert repo.get_baseline_scope(config().scope_id) == result.scope
    page = repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
    assert page.total == 1 and page.next_offset is None
    source = page.items[0]
    assert source.source_receipt_id == result.receipt.operation_id
    assert source.normality == "APPROVED_NORMAL" and source.quality_review == request.quality_review
    assert source.reason == request.reason
    replay = publish(config().scope_id, request, "reviewer", START + timedelta(days=1))
    assert (
        replay.created is False
        and replay.receipt == result.receipt
        and replay.scope == result.scope
    )
    if isinstance(repo, SQLiteRepository):
        with __import__("sqlite3").connect(repo._path) as observer:
            assert observer.execute("SELECT count(*) FROM baseline_operations").fetchone() == (1,)
        reopened = SQLiteRepository(repo._path)
        try:
            assert (
                reopened.page_baseline_sources(config().scope_id, result.receipt.generation_id)
                == page
            )
            assert (
                reopened.publish_baseline_source(config().scope_id, request, "reviewer", START)
                == replay
            )
        finally:
            reopened.close()


def test_sql_reopen_source_independent(approval_repo: Any, monkeypatch: Any) -> None:
    from c2hunter_controller import historical_read as reader
    from c2hunter_controller.production import PostgresRepository

    repo = approval_repo
    if isinstance(repo, MemoryRepository):
        pytest.skip("Memory has no durable reopen")
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    page = repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
    repo.delete_job(request.source_job_id)
    repo.close()
    reopened = (
        PostgresRepository(repo.database_url, None)
        if isinstance(repo, PostgresRepository)
        else SQLiteRepository(repo._path)
    )
    try:
        # Initialize before poisoning: inherited legacy source migrations are not
        # falsely counted as baseline reads.
        assert reopened.get_baseline_scope(config().scope_id) == result.scope

        def forbidden(*args: Any, **kw: Any) -> Any:
            raise AssertionError("retained read reacquired source")

        for name in ("_sqlite_acquire", "_postgres_acquire"):
            monkeypatch.setattr(reader, name, forbidden)
        monkeypatch.setattr(g, "produce_generation", forbidden)
        assert (
            reopened.page_baseline_sources(config().scope_id, result.receipt.generation_id) == page
        )
        replay = reopened.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert not replay.created and replay.receipt == result.receipt
    finally:
        reopened.close()
