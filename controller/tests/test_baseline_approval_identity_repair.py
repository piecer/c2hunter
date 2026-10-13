"""Explicit duplicate and review-independence public controls."""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_baseline_approval_admission_repair import poison
from tests.test_baseline_approval_conservation_repair import documents
from tests.test_baseline_approval_oracle_repair import repo as repo_fixture
from tests.test_baseline_approval_producer import request_for
from tests.test_baseline_approval_retention import operations, publish
from tests.test_historical_source import START, config, stored

repo = repo_fixture


@pytest.mark.parametrize("axis", ["root", "feature", "quality-before-duplicate", "event-equality"])
def test_duplicate_different_source_identity_and_precedence(
    repo: Any, monkeypatch: Any, axis: str
) -> None:
    repo.create_baseline_scope(config(), "admin", START)
    _, result = publish(repo, 0)
    raw = stored()
    raw.update(
        id="different-selected",
        dataset_id="dataset-0"
        if axis in {"root", "quality-before-duplicate"}
        else "different-dataset",
        parent_job_id="source-0" if axis in {"root", "quality-before-duplicate"} else None,
    )
    if axis == "root":
        delta = timedelta(minutes=2)
    elif axis == "event-equality":
        delta = timedelta(seconds=60)
    else:
        delta = timedelta()
    for field in ("start_time", "end_time"):
        raw[field] = (datetime.fromisoformat(raw[field]) + delta).isoformat()
    for row in raw["flow_records"]:
        row["timestamp"] = (datetime.fromisoformat(row["timestamp"]) + delta).isoformat()
    if axis == "quality-before-duplicate":
        raw["capture_incomplete"] = True
    request = request_for(repo, raw, 1)
    before = documents(repo), operations(repo)
    monkeypatch.setattr(b, "build_behavior_windows_with_retained_keys", poison)
    code = (
        "SOURCE_QUALITY"
        if axis == "quality-before-duplicate"
        else "EVENT_ORDER"
        if axis == "event-equality"
        else "SOURCE_DUPLICATE"
    )
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_" + code + "$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert (documents(repo), operations(repo)) == before
    assert repo.get_baseline_scope(config().scope_id) == result.scope


def test_review_actor_change_binding_fixed_document_changes(
    repo: Any, tmp_path: Any, monkeypatch: Any
) -> None:
    peer = (
        MemoryRepository()
        if isinstance(repo, MemoryRepository)
        else SQLiteRepository(tmp_path / "peer.sqlite")
    )
    try:
        pairs = []
        for target, actor, note in ((repo, "one", "first"), (peer, "two", "second")):
            target.create_baseline_scope(config(), "admin", START)
            request = request_for(target, stored(), 0)
            request = request.model_copy(
                update={"quality_review": request.quality_review.model_copy(update={"note": note})}
            )
            ids = iter(
                [
                    UUID("00000000-0000-4000-8000-000000000001"),
                    UUID("00000000-0000-4000-8000-000000000002"),
                ]
            )
            with monkeypatch.context() as patch:
                patch.setattr("uuid.uuid4", lambda ids=ids: next(ids))
                result = target.publish_baseline_source(config().scope_id, request, actor, START)
            pairs.append((result, request, documents(target), operations(target)))
        assert pairs[0][1].source_binding_sha256 == pairs[1][1].source_binding_sha256
        assert pairs[0][0].scope.active.content_sha256 != pairs[1][0].scope.active.content_sha256
        assert pairs[0][3][0][3] != pairs[1][3][0][3]
    finally:
        peer.close()
