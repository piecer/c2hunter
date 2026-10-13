"""Existing complete source/request fences remain actual preselector gates."""

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import uid, world


@pytest.mark.parametrize(
    "axis,code",
    [
        ("revision", "BASELINE_REVISION_CONFLICT"),
        ("generation_pointer", "BASELINE_GENERATION_MISMATCH"),
        ("target_id", "BASELINE_SOURCE_CHANGED"),
        ("target_binding", "BASELINE_SOURCE_CHANGED"),
        ("input_binding", "BASELINE_SOURCE_CHANGED"),
        ("approval_purpose", "BASELINE_SOURCE_CHANGED"),
    ],
)
def test_bound_target_and_request_refusal_before_selector(axis, code, monkeypatch):
    inputs = world()
    request = inputs["request"]
    reference = request["payload"]["baseline_reference"]
    if axis == "revision":
        reference["expected_revision"] += 1
    elif axis == "generation_pointer":
        reference["generation_id"] = uid(888)
    elif axis == "target_id":
        request["analysis_job_id"] = "different-target"
    elif axis == "target_binding":
        reference["target_source_binding_sha256"] = "f" * 64
    elif axis == "input_binding":
        inputs["target_source_binding_sha256"] = "f" * 64
    else:
        binding = h.source_binding_sha256(inputs["target"].source_binding(), purpose="APPROVAL")
        reference["target_source_binding_sha256"] = binding
        inputs["target_source_binding_sha256"] = binding
    payload = dto.FrozenAIAnalysisRunCreate.model_validate(request["payload"])
    request["request_fingerprint"] = dto.request_fingerprint(
        request["analysis_job_id"], request["actor"], payload
    )
    value = dto.HistoricalAdmissionInput(**inputs)
    monkeypatch.setattr(
        ai_discovery, "select_shadow_candidates", lambda *a, **kw: pytest.fail("unbound selector")
    )
    with pytest.raises(dto.HistoricalAIError) as caught:
        producer.build_historical_snapshot(value)
    assert caught.value.code == code
