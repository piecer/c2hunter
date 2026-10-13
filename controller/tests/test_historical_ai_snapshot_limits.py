"""Protected real-output reduction and independently metered saved additions."""

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_evidence as e
from tests.historical_ai_fixtures import decode_with_matching_commitment, job, rule, world


def test_builder_reducer_keeps_all_positive_claims_and_final_snapshots():
    candidate = rule()
    candidate["evidence"] = [
        {"type": "RULE", "description": "측정" * 120, "contribution": 1, "metrics": {"i": i}}
        for i in range(50)
    ]
    value = dto.HistoricalAdmissionInput(**world(candidates=[candidate]))

    result = producer.build_historical_snapshot(value)
    bundles = decode_with_matching_commitment(
        h.canonical_json(result.to_mapping()), request=value.request
    )
    bundle = bundles[0]
    assert bundle.metadata.reduced is True
    assert bundle.metadata.byte_size <= 65536
    assert bundle.metadata.estimated_tokens <= 8192
    assert len(bundle.evidence) <= 50
    assert bundle.evidence[0].evidence_id == e.COVERAGE_ID
    assert len([item for item in bundle.evidence if item.evidence_type in e.FACTOR_TYPES]) == 3
    assert bundle.historical_reference.comparison.historical_anomaly_score == sum(
        item.contribution for item in bundle.evidence if item.evidence_type in e.FACTOR_TYPES
    )
    assert bundle.historical_reference.source_references
    assert len(candidate["evidence"]) == 50


def test_real_mandatory_flow_summaries_cannot_be_trimmed_to_fit():
    target = job()
    rows = []
    for index in range(128):
        for row in target["flow_records"]:
            rows.append({**row, "protocol": f"P{index:03d}" + "X" * 190})
    target["flow_records"] = rows
    value = dto.HistoricalAdmissionInput(**world(target=target, candidates=[rule()]))
    with pytest.raises(dto.HistoricalAIError) as caught:
        producer.build_historical_snapshot(value)
    assert caught.value.code == "BASELINE_RUN_SNAPSHOT_LIMIT"


@pytest.mark.parametrize(
    "part,budget", [("baseline_comparisons", 256 * 1024), ("private", 1024 * 1024)]
)
@pytest.mark.parametrize("extra", [0, 1])
def test_exact_serialized_addition_meter(part, budget, extra):
    # Encoding boundary control, not a claim this padding is a legal snapshot.
    check = getattr(dto, "validate_snapshot_sizes", None)
    assert callable(check), "owning saved comparison/private byte admission missing"
    raw = {
        "baseline_comparisons": [],
        "baseline_sources": [],
        "admitted_bundles": [],
        "baseline_summary": {},
        "baseline_request": {},
        "baseline_request_fingerprint": "a" * 64,
    }
    if part == "baseline_comparisons":
        raw[part] = ["x" * (budget - 4 + extra)]
        assert len(h.canonical_json(raw[part]).encode()) == budget + extra
    else:
        size = len(h.canonical_json(raw).encode())
        raw["baseline_summary"] = "x" * (budget - size + extra)
        assert len(h.canonical_json(raw).encode()) == budget + extra
    if extra:
        with pytest.raises(dto.HistoricalAIError, match="BASELINE_RUN_SNAPSHOT_LIMIT"):
            check(raw)
    else:
        check(raw)


@pytest.mark.parametrize(
    "field,count",
    [("baseline_comparisons", 129), ("baseline_sources", 17), ("admitted_bundles", 6)],
)
def test_raw_snapshot_counts_before_member_copy(field, count):
    check = getattr(dto, "validate_snapshot_sizes", None)
    assert callable(check), "snapshot collection admission missing"

    class Poison:
        def __iter__(self):
            pytest.fail("visited unadmitted member")

    raw = {"baseline_comparisons": [], "baseline_sources": [], "admitted_bundles": []}
    raw[field] = [Poison()] * count
    with pytest.raises(dto.HistoricalAIError, match="BASELINE_RUN_SNAPSHOT_LIMIT"):
        check(raw)
