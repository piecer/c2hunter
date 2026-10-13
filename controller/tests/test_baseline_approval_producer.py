"""Actual retained-key producer, event pruning, and review/binding separation."""

from datetime import timedelta
from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_generation import source_job
from tests.test_historical_generation_retained_admission import source
from tests.test_historical_source import START, config, review

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


def request_for(repo: Any, raw: dict, revision: int, quality: Any = None) -> g.ApprovalRequest:
    repo.save_job(raw)
    preview = repo.preview_baseline_source(config().scope_id, raw["id"], revision, "APPROVAL")
    return g.ApprovalRequest(
        expected_revision=revision,
        idempotency_key=f"review-{revision}",
        source_job_id=raw["id"],
        source_binding_sha256=preview.source_binding_sha256,
        normality="APPROVED_NORMAL",
        quality_review=review() if quality is None else quality,
        reason="explicit synthetic normal assertion",
    )


def test_prospective_retained_129_before_features(approval_repo: Any, monkeypatch: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    first_request = request_for(repo, source(0, range(1000, 1128)), 0)
    first = repo.publish_baseline_source(config().scope_id, first_request, "reviewer", START)
    assert first.scope.active.profile_count == 128
    request = request_for(repo, source(1, (1128,)), 1)
    features = []
    original = b._dispersion

    def count(*args: Any, **kw: Any) -> Any:
        features.append(True)
        return original(*args, **kw)

    monkeypatch.setattr(b, "_dispersion", count)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_PROFILE_LIMIT$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert features == []
    assert repo.get_baseline_scope(config().scope_id) == first.scope


@pytest.mark.parametrize("extra", [0, 1])
def test_event_30_days(approval_repo: Any, extra: int) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    first_request = request_for(repo, source_job(0), 0)
    first = repo.publish_baseline_source(config().scope_id, first_request, "reviewer", START)
    old_page = repo.page_baseline_sources(config().scope_id, first.receipt.generation_id)
    raw = source_job(1, hours=30 * 24)
    if extra:
        for key in ("start_time", "end_time"):
            raw[key] = (h._utc(raw[key]) + timedelta(microseconds=1)).isoformat()
        for row in raw["flow_records"]:
            row["timestamp"] = (h._utc(row["timestamp"]) + timedelta(microseconds=1)).isoformat()
    request = request_for(repo, raw, 1)
    second = repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert second.scope.active.source_window_count == (1 if extra else 2)
    assert repo.page_baseline_sources(config().scope_id, first.receipt.generation_id) == old_page


def test_comparison_binding_is_not_approval(approval_repo: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    comparison = repo.preview_baseline_source(
        config().scope_id, request.source_job_id, 0, "COMPARISON"
    )
    assert comparison.source_binding_sha256 != request.source_binding_sha256
    changed = g.ApprovalRequest.from_mapping(
        dict(request.to_mapping(), source_binding_sha256=comparison.source_binding_sha256)
    )
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_CHANGED$"):
        repo.publish_baseline_source(config().scope_id, changed, "reviewer", START)
    assert repo.publish_baseline_source(config().scope_id, request, "reviewer", START).created


def test_evaluation_explicit_review(approval_repo: Any) -> None:
    repo = approval_repo
    cfg = h.ScopeConfig.from_mapping(
        dict(config().to_mapping(), kind="EVALUATION", stored_sensor_id=None)
    )
    repo.create_baseline_scope(cfg, "admin", START)
    quality = h.QualityReview.from_mapping(dict(review().to_mapping(), sensor_alias_asserted=True))
    request = request_for(repo, source_job(0), 0, quality)
    result = repo.publish_baseline_source(cfg.scope_id, request, "reviewer", START)
    page = repo.page_baseline_sources(cfg.scope_id, result.receipt.generation_id)
    assert page.items[0].quality_review.sensor_alias_asserted is True
    assert "EVALUATION_SENSOR_ALIAS" in page.items[0].limitations


def test_maximum_valid_request_and_receipt_witness() -> None:
    from datetime import UTC, datetime

    identifier = "😀" * 200
    reason = "😀" * 512
    quality = h.QualityReview(
        representative_window_asserted=True,
        stable_host_attribution_asserted=True,
        clock_offset_bound_ms=2000,
        sensor_alias_asserted=False,
        note=reason,
    )
    request = g.ApprovalRequest(
        expected_revision=2**63 - 1,
        idempotency_key=identifier,
        source_job_id=identifier,
        source_binding_sha256="a" * 64,
        normality="APPROVED_NORMAL",
        quality_review=quality,
        reason=reason,
    )
    assert len(h.canonical_json(request.to_mapping()).encode()) == 6076
    assert bs.approval_arguments(config().scope_id, request, identifier, START)[0] == request
    receipt = g.ApprovalReceipt(
        operation_id=config().scope_id,
        action="APPROVE",
        revision=2**63 - 1,
        actor=identifier,
        occurred_at=datetime(9999, 12, 31, 23, 59, 59, 999999, UTC),
        generation_id=config().scope_id,
        source_job_id=identifier,
        source_binding_sha256="a" * 64,
    )
    assert len(h.canonical_json(receipt.to_mapping()).encode()) == 1925
