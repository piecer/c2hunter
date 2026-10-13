"""Closed approval receipt and explicit publication authority values."""

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
from tests.test_historical_source import START, config, review


def test_exact_operation_receipt_links_to_new_source() -> None:
    g = generation_module()
    assert hasattr(g, "approval_receipt"), "pure approval receipt derivation missing"
    args = producer_args()
    doc = g.produce_generation(**args)
    receipt = g.approval_receipt(doc, operation_id=args["operation_id"])
    assert receipt.to_mapping() == {
        "operation_id": args["operation_id"],
        "action": "APPROVE",
        "revision": 1,
        "actor": args["actor"],
        "occurred_at": h._utc(args["now"]).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "generation_id": args["generation_id"],
        "source_job_id": args["request"].source_job_id,
        "source_binding_sha256": args["request"].source_binding_sha256,
    }
    assert g.ApprovalReceipt.model_validate_json(h.canonical_json(receipt.to_mapping())) == receipt
    with pytest.raises(ValueError):
        g.approval_receipt(doc, operation_id=uid(99))
    with pytest.raises(ValueError):
        g.ApprovalReceipt(**dict(receipt.to_mapping(), unknown=1))


@pytest.mark.parametrize(
    "field,value",
    [
        ("operation_id", "bad"),
        ("generation_id", "bad"),
        ("actor", ""),
        ("actor", "a" * 201),
        ("now", START.replace(tzinfo=None)),
        ("accepted_event_end", True),
    ],
)
def test_authority_inputs_reject_before_build(
    field: str, value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_analysis import behavior_baseline as b

    args = producer_args()
    args[field] = value
    calls = []
    actual = b.build_behavior_windows

    def observe(request: Any) -> Any:
        calls.append(request)
        return actual(request)

    monkeypatch.setattr(b, "build_behavior_windows", observe)
    with pytest.raises(ValueError):
        generation_module().produce_generation(**args)
    assert calls == []


@pytest.mark.parametrize(
    "case",
    ["overlap", "horizon", "published_actor", "published_time", "source_count_revision", "records"],
)
def test_document_chronology_and_publication_links(case: str) -> None:
    g = generation_module()
    args = producer_args()
    first = g.produce_generation(**args)
    from tests.test_historical_generation import publish

    doc = publish(snapshot_for(source_job(1)), advance(args["scope"], first), first, index=2)
    data = doc.to_mapping()
    if case in {"overlap", "horizon"}:
        source = data["sources"][0]
        if case == "overlap":
            source["event_start"], source["event_end"] = (
                data["sources"][1]["event_start"],
                data["sources"][1]["event_end"],
            )
        else:
            source["event_start"] = "2025-01-01T00:00:00.000000Z"
            source["event_end"] = "2025-01-01T00:01:00.000000Z"
        for w in data["windows"]:
            if w["source_receipt_id"] == source["source_receipt_id"]:
                w.update(event_start=source["event_start"], event_end=source["event_end"])
    elif case == "published_actor":
        data["published_by"] = "foreign-admin"
    elif case == "published_time":
        data["published_at"] = START.isoformat()
    elif case == "source_count_revision":
        data["publication_revision"] = 1
    else:
        for w in data["windows"]:
            w["outbound_record_count"] = 8192
    with pytest.raises(ValueError):
        g.GenerationDocument(**data)


@pytest.mark.parametrize("kind", ["OPERATIONAL", "EVALUATION"])
@pytest.mark.parametrize("null_family", ["recurrence", "outbound_share"])
def test_reviewed_packet_aggregate_null_family_positive(kind: str, null_family: str) -> None:
    g = generation_module()
    args = producer_args()
    cfg = config()
    quality = review()
    raw = source_job(0, aggregate=null_family == "recurrence")
    if null_family == "outbound_share":
        for row in raw["flow_records"]:
            row["bidirectional"] = True
    if kind == "EVALUATION":
        cfg = h.ScopeConfig.from_mapping(dict(cfg.to_mapping(), kind=kind, stored_sensor_id=None))
        quality = h.QualityReview.from_mapping(
            dict(quality.to_mapping(), sensor_alias_asserted=True)
        )
        digest = "a" * 64
        raw.update(
            source_type="PCAP_UPLOAD",
            mode="PCAP_UPLOAD",
            source={"sha256": digest},
            dataset_id="pcap:" + digest,
            sensor_ids=["pcap-upload:fixture"],
        )
        for row in raw["flow_records"]:
            row["sensor_id"] = "pcap-upload:fixture"
    snap = snapshot_for(raw, cfg, quality)
    args["snapshot"] = snap
    args["scope"] = g.ScopeView.from_mapping(
        dict(
            args["scope"].to_mapping(),
            config=cfg.to_mapping(),
            config_sha256=h.scope_config_sha256(cfg),
        )
    )
    args["request"] = g.ApprovalRequest.from_mapping(
        dict(
            args["request"].to_mapping(),
            quality_review=quality.to_mapping(),
            source_binding_sha256=snap.source_binding_sha256,
        )
    )
    doc = g.produce_generation(**args)
    assert all(getattr(w, null_family) is None for w in doc.windows)
    ref = g.generation_reference(doc, scope=cfg)
    assert len(ref.windows) == 4
    assert doc.sources[0].actual_sensor_id == raw["sensor_ids"][0]
    assert doc.sources[0].approved_at > doc.sources[0].event_end


def test_no_json_or_python_strict_false_downgrade() -> None:
    g = generation_module()
    data = producer_args()["request"].to_mapping()
    data["expected_revision"] = False
    with pytest.raises(ValueError):
        g.ApprovalRequest.model_validate(data, strict=False)
    with pytest.raises(ValueError):
        g.ApprovalRequest.model_validate_json(h.canonical_json(data), strict=False)
