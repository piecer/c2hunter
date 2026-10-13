"""Conservation, source-independent history, and public maximal witnesses."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_approval_admission_repair import poison
from tests.test_baseline_approval_oracle_repair import canonical
from tests.test_baseline_approval_oracle_repair import repo as repo_fixture
from tests.test_baseline_approval_producer import request_for
from tests.test_baseline_approval_retention import operations, publish
from tests.test_historical_generation_retained_admission import source
from tests.test_historical_source import START, config, review, stored

repo = repo_fixture


def documents(repo: Any) -> dict:
    if isinstance(repo, MemoryRepository):
        return dict(repo._baseline_generations)
    return {
        (row[0], row[1]): tuple(row[2:])
        for row in repo.connection.execute("SELECT * FROM baseline_generations").fetchall()
    }


def test_every_retained_byte_and_previous_conservation(repo: Any) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    history = {}
    previous_doc = None
    for index in range(65):
        request, result = publish(repo, index)
        if index == 0:
            first_request = request
        current = {row[1]: tuple(row) for row in operations(repo)}
        for revision, row in current.items():
            if revision in history:
                assert row == history[revision]
        history[index + 1] = current[index + 1]
        assert current == {rev: history[rev] for rev in range(max(1, index - 62), index + 2)}
        docs = documents(repo)
        assert len(docs) == min(index + 1, 2)
        if previous_doc is not None:
            key, value = previous_doc
            assert docs[key] == value
        key = (config().scope_id, result.receipt.generation_id)
        previous_doc = (key, docs[key])
        page = repo.page_baseline_sources(*key)
        assert page.total == min(index + 1, 16)
        assert [item.source_job_id for item in page.items] == [
            f"source-{i}" for i in range(max(0, index - 15), index + 1)
        ]
        assert result.scope.accepted_event_end == START + timedelta(minutes=2 * index, seconds=60)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_REVISION_CONFLICT$"):
        repo.publish_baseline_source(config().scope_id, first_request, "reviewer", START)
    assert documents(repo) == docs and {row[1]: tuple(row) for row in operations(repo)} == current


def test_each_ancestor_and_metadata_loss_read_independent(repo: Any, monkeypatch: Any) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    for index in range(4):
        raw = stored()
        raw.update(
            id=f"ancestor-{index}", parent_job_id=f"ancestor-{index + 1}" if index < 3 else None
        )
        repo.save_job(raw)
    request = request_for(repo, dict(raw, id="selected", parent_job_id="ancestor-0"), 0)
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    expected_page = repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
    before = documents(repo), operations(repo)
    for identifier in ("selected", "ancestor-0", "ancestor-1", "ancestor-2", "ancestor-3"):
        raw = repo.get_job(identifier)
        raw["analysis"] = {"module": "ddos_attack"}
        raw["allowlist"] = [
            {"type": "IP", "value": "203.0.113.9", "description": "changed", "enabled": True}
        ]
        repo.save_job(raw)
        repo.delete_job(identifier)
        with monkeypatch.context() as patch:
            for name in ("_memory_acquire", "_sqlite_acquire", "_postgres_acquire"):
                patch.setattr(r, name, poison)
            patch.setattr(g, "produce_generation", poison)
            patch.setattr("uuid.uuid4", poison)
            assert repo.get_baseline_scope(config().scope_id) == result.scope
            assert (
                repo.page_baseline_sources(config().scope_id, result.receipt.generation_id)
                == expected_page
            )
            replay = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
            assert not replay.created and replay.receipt == result.receipt
        assert (documents(repo), operations(repo)) == before


def test_sparse_pruned_keys_and_previous_bytes(repo: Any) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    first_request = request_for(repo, source(0, range(1000, 1128)), 0)
    first = repo.publish_baseline_source(config().scope_id, first_request, "reviewer", START)
    before = documents(repo)
    raw = source(1, (2000,))
    delta = timedelta(days=31)
    for name in ("start_time", "end_time"):
        raw[name] = (datetime.fromisoformat(raw[name]) + delta).isoformat()
    for row in raw["flow_records"]:
        row["timestamp"] = (datetime.fromisoformat(row["timestamp"]) + delta).isoformat()
    request = request_for(repo, raw, 1)
    result = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert result.scope.active.profile_count == 1 and result.scope.active.source_window_count == 1
    assert (
        documents(repo)[(config().scope_id, first.receipt.generation_id)]
        == before[(config().scope_id, first.receipt.generation_id)]
    )


def test_maximum_public_receipt_and_request(repo: Any, monkeypatch: Any) -> None:
    view, _ = repo.create_baseline_scope(config(), "admin", START)
    maximum = 2**63 - 1
    if isinstance(repo, MemoryRepository):
        repo._baseline_scopes[config().scope_id] = g.ScopeView.from_mapping(
            dict(view.to_mapping(), control_revision=maximum - 1)
        )
    else:
        repo.connection.execute("UPDATE baseline_scopes SET control_revision=?", (maximum - 1,))
        repo.connection.commit()
    raw = stored()
    raw["id"] = "😀" * 200
    quality = review().model_copy(update={"clock_offset_bound_ms": 2000})
    req = request_for(repo, raw, maximum - 1, quality)
    req = g.ApprovalRequest.from_mapping(dict(req.to_mapping(), idempotency_key="😀" * 200))
    result = repo.publish_baseline_source(
        config().scope_id, req, "😀" * 200, datetime(9999, 12, 31, 23, 59, 59, 999999, UTC)
    )
    assert len(canonical(result.receipt.to_mapping()).encode()) == 1925
    maximum_request = req.model_copy(
        update={
            "expected_revision": maximum,
            "idempotency_key": "😁" * 200,
            "reason": "😀" * 512,
            "quality_review": quality.model_copy(update={"note": "😀" * 512}),
        }
    )
    assert len(canonical(maximum_request.to_mapping()).encode()) == 6076
    with monkeypatch.context() as patch:
        patch.setattr(g, "produce_generation", poison)
        patch.setattr("uuid.uuid4", poison)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_CONTROL_LIMIT$"):
            repo.publish_baseline_source(config().scope_id, maximum_request, "😀" * 200, START)
    assert not repo.publish_baseline_source(config().scope_id, req, "😀" * 200, START).created


@pytest.mark.parametrize("offset,limit", [(0, 1), (1, 1), (2, 20), (3, 20), (16, 20)])
def test_exact_page_order_next_offset(repo: Any, offset: int, limit: int) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    results = [publish(repo, index)[1] for index in range(3)]
    for result, total in ((results[1], 2), (results[2], 3)):
        page = repo.page_baseline_sources(
            config().scope_id, result.receipt.generation_id, offset, limit
        )
        assert [item.source_receipt_id for item in page.items] == [
            item.receipt.operation_id for item in results[:total][offset : offset + limit]
        ]
        end = offset + len(page.items)
        assert page.next_offset == (end if end < total else None)
    assert g.SourcePage(items=(), total=0, offset=0, limit=20, next_offset=None).items == ()
