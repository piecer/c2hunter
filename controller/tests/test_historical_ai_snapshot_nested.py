"""Constructor boundary revalidates caller-owned nested frozen-model aliases."""

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import decode_with_matching_commitment, rule, world


@pytest.mark.parametrize("axis", ["summary", "baseline_summary", "inventory", "bundle", "receipt"])
def test_snapshot_constructor_does_not_retain_mutable_nested_model_leaves(axis):
    result = producer.build_historical_snapshot(dto.HistoricalAdmissionInput(**world()))
    fields = {name: getattr(result, name) for name in dto.HistoricalRunSnapshot.model_fields}
    mutable = list(result.selection_summary.warnings)
    if axis == "summary":
        fields["selection_summary"] = result.selection_summary.model_copy(
            update={"warnings": mutable}
        )
    elif axis == "baseline_summary":
        mutable = list(result.baseline_summary.warnings)
        fields["baseline_summary"] = result.baseline_summary.model_copy(
            update={"warnings": mutable}
        )
    elif axis == "inventory":
        mutable = result.selection_inventory[0].model_dump()
        fields["selection_inventory"] = (mutable,)
    elif axis == "receipt":
        mutable = list(result.baseline_sources[0].ancestry_job_ids)
        fields["baseline_sources"] = (
            result.baseline_sources[0].model_copy(update={"ancestry_job_ids": mutable}),
            *result.baseline_sources[1:],
        )
    else:
        mutable = result.admitted_bundles[0].metadata.model_dump()
        fields["admitted_bundles"] = (
            result.admitted_bundles[0].model_copy(update={"metadata": mutable}),
        )
    reconstructed = dto.HistoricalRunSnapshot(**fields)
    before = reconstructed.to_mapping()
    if isinstance(mutable, list):
        mutable.append("foreign")
    else:
        mutable.clear()
    assert reconstructed.to_mapping() == before
    assert reconstructed.to_mapping() == result.to_mapping()


@pytest.mark.parametrize("limit", range(1, 6))
def test_candidate_limit_and_one_shared_reservation_survive_saved_decode(limit):
    candidates = [rule(f"198.51.100.{index}", f"rule-{index}") for index in range(1, 7)]
    inputs = world(candidates=candidates)
    request = inputs["request"]
    request["payload"]["candidate_limit"] = limit
    payload = dto.FrozenAIAnalysisRunCreate.model_validate(request["payload"])
    request["request_fingerprint"] = dto.request_fingerprint(
        request["analysis_job_id"], request["actor"], payload
    )
    value = dto.HistoricalAdmissionInput(**inputs)
    result = producer.build_historical_snapshot(value)
    assert len(result.candidate_ids) == limit
    assert result.selection_summary.reserved_discovery_slots == 1
    decoded = decode_with_matching_commitment(
        h.canonical_json(result.to_mapping()), request=value.request
    )
    assert tuple(bundle.candidate.candidate_id for bundle in decoded) == result.candidate_ids
