"""Remaining input custody, seeded watermark and readback corruption controls."""

from datetime import datetime, timedelta
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_approval_admission_repair import poison
from tests.test_baseline_approval_contract import prepare
from tests.test_baseline_approval_lifecycle_repair import full_snapshot
from tests.test_baseline_approval_oracle_repair import repo as repo_fixture
from tests.test_baseline_approval_producer import request_for
from tests.test_baseline_approval_retention import publish
from tests.test_historical_source import START, config, stored

repo = repo_fixture


@pytest.mark.parametrize(
    "field",
    [
        "key",
        "source",
        "reason",
        "note",
        "wide",
        "normality",
        "review",
        "actor",
        "clock",
        "naive-time",
    ],
)
def test_precopy_full_argument_boundaries(repo: Any, monkeypatch: Any, field: str) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    request = prepare(repo)
    actor, now = "reviewer", START
    if field == "key":
        request = request.model_copy(update={"idempotency_key": "x" * 201})
    elif field == "source":
        request = request.model_copy(update={"source_job_id": "x" * 201})
    elif field == "reason":
        request = request.model_copy(update={"reason": "x" * 513})
    elif field == "note":
        request = request.model_copy(
            update={"quality_review": request.quality_review.model_copy(update={"note": "x" * 513})}
        )
    elif field == "wide":
        request = request.model_copy(update={f"unknown-{i}": object() for i in range(100)})
    elif field == "normality":
        request = request.model_copy(update={"normality": "AUTOMATIC"})
    elif field == "review":
        request = request.model_copy(update={"quality_review": None})
    elif field == "actor":
        actor = "x" * 201
    elif field == "clock":
        request = request.model_copy(
            update={
                "quality_review": request.quality_review.model_copy(
                    update={"clock_offset_bound_ms": True}
                )
            }
        )
    else:
        now = datetime(2026, 1, 1)
    monkeypatch.setattr(bs, "publication_connection", poison)
    monkeypatch.setattr(bs, "memory_publish", poison)
    if field not in {"actor", "naive-time"}:
        monkeypatch.setattr(g, "_unmodel", poison)
    with pytest.raises(ValueError) as caught:
        repo.publish_baseline_source(config().scope_id, request, actor, now)
    assert not isinstance(caught.value, bs.BaselineStorageError)


def test_request_mapping_custody(repo: Any) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    original = prepare(repo)
    raw = original.to_mapping()
    request = g.ApprovalRequest.from_mapping(raw)
    raw["reason"] = "changed"
    raw["quality_review"]["note"] = "changed"
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    page = repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
    assert (
        page.items[0].reason == original.reason
        and page.items[0].quality_review == original.quality_review
    )
    returned = page.to_mapping()
    returned["items"][0]["reason"] = "changed again"
    assert repo.page_baseline_sources(config().scope_id, result.receipt.generation_id) == page


def test_seeded_greatest_watermark_not_active_newest(repo: Any, monkeypatch: Any) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    _, first = publish(repo, 0)
    watermark = START + timedelta(days=1)
    if isinstance(repo, MemoryRepository):
        repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
            dict(first.scope.to_mapping(), accepted_event_end=watermark)
        )
    else:
        repo.connection.execute(
            "UPDATE baseline_scopes SET accepted_event_end=?",
            (watermark.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),),
        )
        repo.connection.commit()
        reopened = SQLiteRepository(repo._path)
        try:
            assert reopened.get_baseline_scope(config().scope_id).accepted_event_end == watermark
        finally:
            reopened.close()
    request = prepare(repo, 1)
    with monkeypatch.context() as patch:
        patch.setattr(bs.g.b, "build_behavior_windows_with_retained_keys", poison)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_EVENT_ORDER$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    raw = stored()
    raw.update(
        id="later",
        dataset_id="later",
        start_time=(watermark + timedelta(seconds=1)).isoformat(),
        end_time=(watermark + timedelta(seconds=61)).isoformat(),
    )
    for index, row in enumerate(raw["flow_records"]):
        row["timestamp"] = (watermark + timedelta(seconds=1 + index % 8)).isoformat()
    request = request_for(repo, raw, 1)
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert result.scope.accepted_event_end == watermark + timedelta(seconds=61)


@pytest.mark.parametrize(
    "mutation",
    [
        "scope-missing",
        "scope-corrupt",
        "operation-missing",
        "receipt-corrupt",
        "document-missing",
        "document-corrupt",
    ],
)
def test_actual_committed_readback_mutations(
    tmp_path: Any, monkeypatch: Any, mutation: str
) -> None:
    repo = SQLiteRepository(tmp_path / "readback.sqlite")
    try:
        repo.create_baseline_scope(config(), "admin", START)
        request = prepare(repo)
        original = bs._publication_transaction.__exit__
        committed, corrupted = [], []

        def boundary(owner: Any, kind: Any, error: Any, tb: Any) -> Any:
            value = original(owner, kind, error, tb)
            if owner.write and error is None:
                committed.append(full_snapshot(repo))
                import sqlite3

                con = sqlite3.connect(repo._path)
                try:
                    statement = {
                        "scope-missing": "DELETE FROM baseline_scopes",
                        "scope-corrupt": "UPDATE baseline_scopes SET config_content_sha256='"
                        + "0" * 64
                        + "'",
                        "operation-missing": "DELETE FROM baseline_operations",
                        "receipt-corrupt": "UPDATE baseline_operations SET receipt_sha256='"
                        + "0" * 64
                        + "'",
                        "document-missing": "DELETE FROM baseline_generations",
                        "document-corrupt": "UPDATE baseline_generations SET content_sha256='"
                        + "0" * 64
                        + "'",
                    }[mutation]
                    con.execute(statement)
                    con.commit()
                finally:
                    con.close()
                corrupted.append(full_snapshot(repo))
            return value

        monkeypatch.setattr(bs._publication_transaction, "__exit__", boundary)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert len(committed) == len(corrupted) == 1
        assert full_snapshot(repo) == corrupted[0] != committed[0]
        assert (
            not repo.connection.in_transaction and not repo._baseline_publication_connection.failed
        )
    finally:
        repo.close()
