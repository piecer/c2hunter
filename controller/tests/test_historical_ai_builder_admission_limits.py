"""Typed pre-copy admission, not backend storage-transfer claims."""

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import decode_with_matching_commitment, job, rule, world


@pytest.mark.parametrize(
    "axis,code",
    [("candidate_bytes", "BASELINE_CANDIDATE_LIMIT"), ("flow_count", "BASELINE_SOURCE_LIMIT")],
)
def test_admitted_wrapper_cumulative_limits_before_selector(axis, code, monkeypatch):
    value = dto.HistoricalAdmissionInput(**world())
    if axis == "candidate_bytes":
        candidates = []
        for i in range(65):
            raw = rule(identifier=f"c{i}")
            raw["evidence"][0]["metrics"] = {"large": "x" * 64900}
            candidates.append(h.project_candidate(raw, position=i))
        binding = h.source_binding_sha256(
            value.target.source_binding(), purpose="COMPARISON", candidates=tuple(candidates)
        )
        reference = value.request.payload.baseline_reference.model_copy(
            update={"target_source_binding_sha256": binding}
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
        value = value.model_copy(
            update={
                "candidates": tuple(candidates),
                "request": request,
                "target_source_binding_sha256": binding,
            }
        )
    else:
        original = value.target.original.model_copy(
            update={"flow_records": (value.target.original.flow_records[0],) * 8193}
        )
        value = value.model_copy(
            update={"target": value.target.model_copy(update={"original": original})}
        )
    monkeypatch.setattr(
        ai_discovery,
        "select_shadow_candidates",
        lambda *a, **kw: pytest.fail("selector after raw overflow"),
    )
    with pytest.raises(dto.HistoricalAIError) as caught:
        producer.build_historical_snapshot(value)
    assert caught.value.code == code


@pytest.mark.parametrize("count", [128, 129])
def test_real_profile_count_boundary(count):
    target = job()
    target["flow_records"] = [
        {**row, "destination_port" if row["direction"] == "OUTBOUND" else "source_port": port}
        for port in range(443, 443 + count)
        for row in target["flow_records"]
    ]
    # The accepted source bridge itself enforces the profile limit; preserve its
    # refusal if it precedes the builder rather than pretending it was admitted.
    if count == 129:
        with pytest.raises(ValueError, match="BASELINE_PROFILE_LIMIT"):
            inputs = world(target=target, candidates=[rule()])
            producer.build_historical_snapshot(dto.HistoricalAdmissionInput(**inputs))
    else:
        value = dto.HistoricalAdmissionInput(**world(target=target, candidates=[rule()]))
        result = producer.build_historical_snapshot(value)
        assert len(result.baseline_comparisons) == 128
        assert sum(result.baseline_summary.profile_counts.to_mapping().values()) == 128
        assert decode_with_matching_commitment(
            h.canonical_json(result.to_mapping()), request=value.request
        )
