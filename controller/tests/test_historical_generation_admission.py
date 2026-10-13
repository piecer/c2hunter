"""Admission work, invalid heads and explicit source-scope revalidation."""

from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from tests.test_historical_generation import (
    advance,
    generation_module,
    producer_args,
    snapshot_for,
    source_job,
    uid,
)


@pytest.mark.parametrize("collection,limit", [("windows", 2048), ("sources", 16)])
def test_cardinality_before_member_decoding(
    collection: str, limit: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_analysis import behavior_baseline as b

    g = generation_module()
    doc = g.produce_generation(**producer_args())
    data = doc.to_mapping()
    data[collection] = [data[collection][0]] * (limit + 1)
    calls = []
    actual = b.behavior_window_from_mapping

    def observe(value: Any) -> Any:
        calls.append(value)
        return actual(value)

    monkeypatch.setattr(b, "behavior_window_from_mapping", observe)
    with pytest.raises(ValueError):
        g.GenerationDocument(**data)
    assert calls == []


@pytest.mark.parametrize(
    "case", ["same_heads", "reverse_extrema", "empty_watermark", "new_id_reuse"]
)
def test_invalid_scope_heads(case: str) -> None:
    g = generation_module()
    args = producer_args()
    doc = g.produce_generation(**args)
    scope = advance(args["scope"], doc)
    data = scope.to_mapping()
    if case == "same_heads":
        data["previous"] = data["active"]
    elif case == "reverse_extrema":
        data["active"]["oldest_event_start"] = data["active"]["newest_event_end"]
    elif case == "empty_watermark":
        data.update(state="EMPTY", active=None)
    else:
        args.update(
            scope=scope,
            current_generation=doc,
            accepted_event_end=scope.accepted_event_end,
            snapshot=snapshot_for(source_job(1)),
            operation_id=uid(2),
        )
        args["request"] = g.ApprovalRequest.from_mapping(
            dict(
                args["request"].to_mapping(),
                expected_revision=1,
                source_job_id=args["snapshot"].source.original.id,
                source_binding_sha256=args["snapshot"].source_binding_sha256,
            )
        )
        with pytest.raises(ValueError):
            g.produce_generation(**args)
        return
    with pytest.raises(ValueError):
        g.ScopeView(**data)


@pytest.mark.parametrize("kind", ["derived_digest", "strict_flow", "source_extra", "lineage_extra"])
def test_snapshot_forgery_never_reaches_builder(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    from dataclasses import replace

    from c2hunter_analysis import behavior_baseline as b

    args = producer_args()
    source = args["snapshot"].source
    if kind == "derived_digest":
        source = source.model_copy(update={"feature_observation_sha256": "f" * 64})
    elif kind == "strict_flow":
        source = source.model_copy(
            update={
                "strict_flows": (replace(source.strict_flows[0], total_bytes=999),)
                + source.strict_flows[1:]
            }
        )
    elif kind == "source_extra":
        source = source.model_copy(update={"unrecognized": 1})
    else:
        source = source.model_copy(
            update={"lineage": (source.lineage[0].model_copy(update={"unrecognized": 1}),)}
        )
    args["snapshot"] = args["snapshot"].model_copy(update={"source": source})

    def forbidden(*a: Any, **kw: Any) -> Any:
        raise AssertionError("forged source reached build")

    monkeypatch.setattr(b, "build_behavior_windows", forbidden)
    with pytest.raises(ValueError):
        generation_module().produce_generation(**args)


def test_receipt_cannot_hide_upload_marker() -> None:
    g = generation_module()
    value = g.produce_generation(**producer_args()).sources[0].to_mapping()
    value["dataset_id"] = "pcap:" + "a" * 64
    value["root_identity"] = h.canonical_json([value["root_job_id"], value["dataset_id"]])
    with pytest.raises(ValueError):
        g.SourceReceipt(**value)
