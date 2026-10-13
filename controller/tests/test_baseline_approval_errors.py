"""Phase/type/cause mapping through actual publication; not message parsing."""

from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as r
from c2hunter_controller import historical_source as s
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_source import START, config, review, stored

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def test_long_ancestry_actual_producer_limit(approval_repo: Any, monkeypatch: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    names = [(chr(0x1F600 + i) * 200) for i in range(16)]
    for i, name in enumerate(names):
        raw = stored()
        raw.update(id=name, parent_job_id=names[i - 1] if i else None)
        repo.save_job(raw)
    preview = repo.preview_baseline_source(config().scope_id, names[-1], 0, "APPROVAL")
    request = g.ApprovalRequest(
        expected_revision=0,
        idempotency_key="long",
        source_job_id=names[-1],
        source_binding_sha256=preview.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="explicit synthetic",
    )
    called = []
    original = g.produce_generation

    def actual(**kwargs: Any) -> Any:
        called.append(True)
        return original(**kwargs)

    monkeypatch.setattr(g, "produce_generation", actual)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_GENERATION_LIMIT$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert called == [True]
    assert repo.get_baseline_scope(config().scope_id).control_revision == 0


@pytest.mark.parametrize(
    "error",
    [
        r.HistoricalReadError("BASELINE_SOURCE_LIMIT"),
        s.SourceInputError("BASELINE_SOURCE_QUALITY"),
        b.BaselineInputError("BASELINE_PROFILE_LIMIT"),
    ],
)
def test_typed_codes(approval_repo: Any, monkeypatch: Any, error: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    fired = []

    def fail(**kw: Any) -> Any:
        fired.append(True)
        raise error

    monkeypatch.setattr(g, "produce_generation", fail)
    with pytest.raises(bs.BaselineStorageError) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert caught.value.code == error.code and fired == [True]
    assert repo.get_baseline_scope(config().scope_id).control_revision == 0


@pytest.mark.parametrize(
    "error",
    [
        TypeError("owned"),
        RuntimeError("owned"),
        ValueError("text BASELINE_GENERATION_LIMIT"),
        ValueError("UNKNOWN"),
    ],
)
def test_programmer_identity(approval_repo: Any, monkeypatch: Any, error: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)

    def fail(**kw: Any) -> Any:
        raise error

    monkeypatch.setattr(g, "produce_generation", fail)
    with pytest.raises(type(error)) as caught:
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert caught.value is error
    assert repo.get_baseline_scope(config().scope_id).control_revision == 0
