"""Closed constructors, ordered inputs and deep output aliases."""

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import rule, world


@pytest.mark.parametrize(
    "axis", ["request_extra", "payload_extra", "input_extra", "candidate_order"]
)
def test_forged_or_reordered_input_is_not_lossily_normalized(axis, monkeypatch):
    value = dto.HistoricalAdmissionInput(
        **world(candidates=[rule(), rule("198.51.100.20", "second")])
    )
    if axis == "request_extra":
        value = value.model_copy(
            update={"request": value.request.model_copy(update={"unexpected": "value"})}
        )
    elif axis == "payload_extra":
        payload = value.request.payload.model_copy(update={"unexpected": "value"})
        value = value.model_copy(
            update={"request": value.request.model_copy(update={"payload": payload})}
        )
    elif axis == "input_extra":
        value = value.model_copy(update={"unexpected": "value"})
    else:
        value = value.model_copy(update={"candidates": tuple(reversed(value.candidates))})
    monkeypatch.setattr(
        ai_discovery,
        "select_shadow_candidates",
        lambda *a, **kw: pytest.fail("unadmitted selector"),
    )
    with pytest.raises(dto.HistoricalAIError, match="BASELINE_SOURCE_INVALID"):
        producer.build_historical_snapshot(value)


def test_snapshot_nested_comparison_is_revalidated_and_frozen_at_constructor():
    value = dto.HistoricalAdmissionInput(**world())
    result = producer.build_historical_snapshot(value)
    row = result.baseline_comparisons[0]
    mutable = row.features.model_dump(mode="json")
    forged = row.model_copy(update={"features": mutable})
    fields = {name: getattr(result, name) for name in dto.HistoricalRunSnapshot.model_fields}
    fields["baseline_comparisons"] = (forged,)
    reconstructed = dto.HistoricalRunSnapshot(**fields)
    mutable["recurrence"]["current"] = 99
    assert (
        reconstructed.baseline_comparisons[0].features.recurrence.current
        == row.features.recurrence.current
    )
    output = reconstructed.to_mapping()
    output["candidate_snapshots"][0]["evidence"][0]["metrics"]["reference"] = "foreign"
    assert reconstructed.to_mapping() != output
    with pytest.raises(ValueError):
        reconstructed.admitted_bundles[0].metadata.byte_size = 0


def test_original_object_array_kind_and_key_order_survive_input_serialization():
    candidate = rule()
    candidate["evidence"][0]["metrics"] = {
        "z": {},
        "a": [],
        "pairs": [["x", 1]],
        "nested": {"b": 2, "a": 1},
    }
    value = dto.HistoricalAdmissionInput(**world(candidates=[candidate]))
    # Unsorted original-object serialization is intentional; request fingerprint
    # and final model bytes have their separately specified canonical encoders.
    restored = dto.HistoricalAdmissionInput.model_validate_json(value.model_dump_json())
    assert restored.candidates == value.candidates
    assert h.thaw_original_json(restored.candidates[0].fields) == h.thaw_original_json(
        value.candidates[0].fields
    )
    assert producer.build_historical_snapshot(restored) == producer.build_historical_snapshot(value)
