"""Intrinsic reference consistency must precede any downstream scoped use."""

from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from tests.test_historical_generation import (
    advance,
    generation_module,
    producer_args,
    publish,
    snapshot_for,
    source_job,
)
from tests.test_historical_generation_validation import admit


@pytest.mark.parametrize("route", ["constructor", "mapping", "json", "storage"])
@pytest.mark.parametrize("case", ["logical_sensor", "duration", "epoch"])
def test_cross_receipt_reference_consistency(case: str, route: str) -> None:
    g = generation_module()
    args = producer_args()
    first = g.produce_generation(**args)
    doc = publish(snapshot_for(source_job(1)), advance(args["scope"], first), first, index=2)
    data: dict[str, Any] = doc.to_mapping()
    source = data["sources"][-1]
    if case == "logical_sensor":
        source["sensor_key"] = "foreign-logical"
    if case == "duration":
        source["event_end"] = "2026-01-01T12:02:00.000000Z"
    for window in data["windows"]:
        if window["source_receipt_id"] == source["source_receipt_id"]:
            if case == "logical_sensor":
                window["key"]["sensor_key"] = source["sensor_key"]
            if case == "duration":
                window["event_end"] = source["event_end"]
            if case == "epoch":
                window["key"]["host_epoch"] = "different-epoch"
    data["windows"].sort(key=lambda w: h.canonical_json([w["key"], w["source_receipt_id"]]))
    with pytest.raises(ValueError):
        admit(data, route)
