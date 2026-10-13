"""Publication retention uses event time, not the synthetic approval clock."""

from datetime import timedelta
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from tests.test_historical_generation import (
    advance,
    empty_scope,
    generation_module,
    producer_args,
    publish,
    snapshot_for,
    source_job,
    uid,
)
from tests.test_historical_source import START


@pytest.mark.parametrize("mutation", ["root", "features", "reorder", "operation"])
def test_duplicate_before_event_order_or_builder(
    mutation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_analysis import behavior_baseline as b

    g = generation_module()
    args = producer_args()
    doc = g.produce_generation(**args)
    scope = advance(args["scope"], doc)
    raw = source_job(1)
    if mutation == "root":
        raw.update(id="root-0", dataset_id="dataset-0")
    elif mutation in {"features", "reorder"}:
        raw = source_job(0)
        raw.update(id="different-root", dataset_id="different-dataset")
        if mutation == "reorder":
            raw["flow_records"].reverse()
    snapshot = snapshot_for(raw)

    def forbidden(*a: Any, **kw: Any) -> Any:
        raise AssertionError("duplicate reached feature build")

    monkeypatch.setattr(b, "build_behavior_windows", forbidden)
    with pytest.raises(ValueError, match="BASELINE_SOURCE_DUPLICATE"):
        publish(snapshot, scope, doc, index=1 if mutation == "operation" else 2)


def test_seventeenth_source_evicts_global_oldest_and_empty_profile() -> None:
    g = generation_module()
    scope, doc = empty_scope(), None
    for index in range(17):
        raw = source_job(index)
        raw["flow_records"] = raw["flow_records"][:8]
        raw["flow_records"][0]["destination_port"] = 8443 if index == 0 else 443
        for row in raw["flow_records"]:
            row["destination_port"] = 8443 if index == 0 else 443
        doc = publish(snapshot_for(raw), scope, doc, index=index + 1)
        scope = advance(scope, doc)
    assert len(doc.sources) == len(doc.windows) == 16
    assert uid(1) not in {s.source_receipt_id for s in doc.sources}
    assert {w.key.service_port for w in doc.windows} == {443}
    assert g.generation_view(doc).profile_count == 1


@pytest.mark.parametrize("extra", [0, 1])
def test_thirty_event_day_exact_boundary(extra: int) -> None:
    scope = empty_scope()
    doc = publish(snapshot_for(source_job(0)), scope)
    scope = advance(scope, doc)
    raw = source_job(1, hours=720)
    for key in ("start_time", "end_time"):
        raw[key] = (h._utc(raw[key]) + timedelta(microseconds=extra)).isoformat()
    for row in raw["flow_records"]:
        row["timestamp"] = (h._utc(row["timestamp"]) + timedelta(microseconds=extra)).isoformat()
    result = publish(snapshot_for(raw), scope, doc, index=2)
    assert len(result.sources) == (2 if extra == 0 else 1)
    assert len(result.windows) == (8 if extra == 0 else 4)


@pytest.mark.parametrize("case", ["rollback", "revoke", "retire", "reset"])
def test_durable_watermark_not_inferred_from_active(case: str) -> None:
    g = generation_module()
    scope = empty_scope()
    doc = publish(snapshot_for(source_job(0)), scope)
    scope = advance(scope, doc)
    watermark = START + timedelta(days=5)
    values = dict(scope.to_mapping(), accepted_event_end=watermark.isoformat(), control_revision=8)
    if case in {"revoke", "retire"}:
        values.update(
            active=None, previous=None, state="REVOKED" if case == "revoke" else "RETIRED"
        )
        doc = None
    scope = g.ScopeView.from_mapping(values)
    if case == "reset":
        args = producer_args()
        args.update(
            scope=scope,
            current_generation=doc,
            accepted_event_end=None,
            request=g.ApprovalRequest.from_mapping(
                dict(args["request"].to_mapping(), expected_revision=8)
            ),
        )
        with pytest.raises(ValueError, match="BASELINE_EVENT_ORDER"):
            g.produce_generation(**args)
    else:
        with pytest.raises(ValueError, match="BASELINE_EVENT_ORDER"):
            publish(snapshot_for(source_job(1)), scope, doc, index=2)
