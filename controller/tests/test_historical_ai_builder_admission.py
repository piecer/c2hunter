"""Input binding must reject before the real selector, not after outputs exist."""

from copy import deepcopy

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import decode_with_matching_commitment, uid, world


@pytest.mark.parametrize(
    "axis,code",
    [
        ("scope", "BASELINE_SCOPE_MISMATCH"),
        ("generation_none", "BASELINE_GENERATION_MISMATCH"),
        ("generation_foreign", "BASELINE_GENERATION_MISMATCH"),
        ("fingerprint", "BASELINE_SOURCE_INVALID"),
        ("source_hash", "BASELINE_SOURCE_INVALID"),
    ],
)
def test_reject_mismatched_admission_before_selector(axis, code, monkeypatch):
    value = dto.HistoricalAdmissionInput(**world())
    if axis == "scope":
        reference = value.request.payload.baseline_reference.model_copy(
            update={"scope_id": uid(998)}
        )
        payload = value.request.payload.model_copy(update={"baseline_reference": reference})
        request = value.request.model_copy(
            update={
                "payload": payload,
                "request_fingerprint": dto.request_fingerprint(
                    value.request.analysis_job_id, value.request.actor, payload
                ),
            }
        )
        value = value.model_copy(update={"request": request})
    elif axis == "generation_none":
        value = value.model_copy(update={"generation": None})
    elif axis == "generation_foreign":
        value = value.model_copy(
            update={"generation": value.generation.model_copy(update={"generation_id": uid(997)})}
        )
    elif axis == "fingerprint":
        value = value.model_copy(
            update={"request": value.request.model_copy(update={"request_fingerprint": "f" * 64})}
        )
    else:
        value = value.model_copy(
            update={
                "target": value.target.model_copy(update={"feature_observation_sha256": "f" * 64})
            }
        )
    called = []
    original = ai_discovery.select_shadow_candidates

    def observed(*args, **kwargs):
        called.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(ai_discovery, "select_shadow_candidates", observed)
    with pytest.raises(dto.HistoricalAIError) as caught:
        producer.build_historical_snapshot(value)
    assert caught.value.code == code
    assert str(caught.value) == code
    assert called == []


def test_frozen_caller_aliases_and_order_are_real_local_inputs():
    from c2hunter_controller import ai_analysis as ai
    from tests.historical_ai_fixtures import job, rule

    original, candidate = job(), rule()
    metrics = {f"k{i}": i for i in reversed(range(35))}
    metrics["nested"] = {"array": [], "object": {}, "pairs": [["a", 2]]}
    candidate["evidence"][0]["metrics"] = metrics
    original["flow_records"][0]["Raw_Payload"] = "not retained"
    raw = world(target=original, candidates=[candidate])
    value = dto.HistoricalAdmissionInput(**raw)
    frozen = deepcopy(value.request.to_mapping())
    raw["request"]["payload"]["language"] = "en"
    metrics.clear()
    original["flow_records"][0]["packet_count"] = 10
    assert value.request.to_mapping() == frozen
    expected = ai._candidate_snapshot(h.thaw_original_json(value.candidates[0].fields))
    result = producer.build_historical_snapshot(value)
    bundle = decode_with_matching_commitment(
        h.canonical_json(result.to_mapping()), request=value.request
    )[0]
    rule_evidence = next(e for e in bundle.evidence if e.evidence_type == "RULE")
    assert rule_evidence.metrics == expected["evidence"][0]["metrics"]
    assert bundle.data_quality.payload_fields_excluded == 1
    with pytest.raises(ValueError):
        value.request.payload.language = "en"
    with pytest.raises(ValueError):
        result.selection_summary.selected_count = 0
    assert type(result.candidate_snapshots[0]) is h.FrozenObject
    assert "not retained" not in h.canonical_json(value.target.to_mapping())
