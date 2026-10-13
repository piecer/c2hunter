"""R5: full saved receipt facts are checked independently of custody."""

import hashlib
import json

import pytest

from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_generation as g
from tests.historical_ai_fixtures import decode_with_matching_commitment, job, rule, world


@pytest.fixture(scope="module")
def positive():
    value = dto.HistoricalAdmissionInput(**world(candidates=[rule()]))
    result = producer.build_historical_snapshot(value)
    return value, result


def rehash_bundle_comparisons(raw):
    row = raw["baseline_comparisons"][0]
    for envelope in raw["admitted_bundles"]:
        model = json.loads(envelope["canonical_json"])
        if model["historical_reference"]["comparison"]:
            model["historical_reference"]["comparison"] = {
                key: value for key, value in row.items() if key != "selected"
            }
        text = h.canonical_json(model)
        envelope["canonical_json"] = text
        size = len(text.encode())
        envelope["metadata"].update(
            canonical_sha256=hashlib.sha256(text.encode()).hexdigest(),
            byte_size=size,
            estimated_tokens=(size + 2) // 3,
        )


@pytest.mark.parametrize(
    "axis",
    ["dataset", "target_ancestry", "future", "SOURCE_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN"],
)
def test_matching_commitment_does_not_justify_impossible_receipts(positive, axis):
    value, snapshot = positive
    raw = snapshot.to_mapping()
    source = raw["baseline_sources"][0]
    if axis == "dataset":
        source["dataset_id"] = raw["dataset_id"]
        source["root_identity"] = h.canonical_json([source["root_job_id"], source["dataset_id"]])
    elif axis == "target_ancestry":
        source["ancestry_job_ids"].append(raw["analysis_job_id"])
    elif axis == "future":
        for feature in raw["baseline_comparisons"][0]["features"].values():
            feature["excluded_future_count"] = 1
        rehash_bundle_comparisons(raw)
    else:
        source["limitations"] = sorted(set(source["limitations"]) | {axis})
    with pytest.raises(dto.HistoricalAIError, match="HISTORICAL_SNAPSHOT_INVALID"):
        decode_with_matching_commitment(h.canonical_json(raw), request=value.request)


@pytest.mark.parametrize("reason", ["SOURCE_PARTIAL_CAPTURE", "SOURCE_CLOCK_UNCERTAIN"])
def test_supplied_generation_negative_quality_refused_before_selector(reason, monkeypatch):
    raw = world()
    document = raw["generation"].to_mapping()
    document["sources"][0]["limitations"] = sorted({*document["sources"][0]["limitations"], reason})
    raw["generation"] = g.GenerationDocument.from_mapping(document)
    scope = raw["scope"].to_mapping()
    scope["active"] = g.generation_view(raw["generation"]).to_mapping()
    raw["scope"] = g.ScopeView.from_mapping(scope)
    value = dto.HistoricalAdmissionInput(**raw)
    calls = []
    actual = ai_discovery.select_shadow_candidates

    def observed(*args, **kwargs):
        calls.append(1)
        return actual(*args, **kwargs)

    monkeypatch.setattr(ai_discovery, "select_shadow_candidates", observed)
    with pytest.raises(dto.HistoricalAIError, match="BASELINE_SOURCE_INVALID"):
        producer.build_historical_snapshot(value)
    assert calls == []  # noqa: S101 - pytest assertion, not an authorization guard.


@pytest.mark.parametrize("axis", ["future", "dataset"])
def test_actual_excluded_receipts_are_retained_and_decode(axis):
    target = job()
    if axis == "dataset":
        target["dataset_id"] = "dataset-0"
    value = dto.HistoricalAdmissionInput(
        **world(target=target, sources=4 if axis == "future" else 3, candidates=[rule()])
    )
    snapshot = producer.build_historical_snapshot(value)
    row = snapshot.baseline_comparisons[0]
    if axis == "future":
        assert len(snapshot.baseline_sources) == 4  # noqa: S101 - pytest assertion, not an authorization guard.
        assert all(f.excluded_future_count == 1 for f in row.features.ordered())  # noqa: S101 - pytest assertion, not an authorization guard.
    else:
        assert len(snapshot.baseline_sources) == 3  # noqa: S101 - pytest assertion, not an authorization guard.
        assert row.status == "INSUFFICIENT" and row.historical_anomaly_score == 0  # noqa: S101 - pytest assertion, not an authorization guard.
        assert snapshot.baseline_sources[0].source_receipt_id not in row.source_window_ids  # noqa: S101 - pytest assertion, not an authorization guard.
    assert decode_with_matching_commitment(  # noqa: S101 - pytest assertion, not an authorization guard.
        h.canonical_json(snapshot.to_mapping()), request=value.request
    )


def test_original_commitment_remains_an_independent_gate(positive):
    value, snapshot = positive
    saved = h.canonical_json(snapshot.to_mapping())
    commitment = hashlib.sha256(saved.encode()).hexdigest()
    raw = snapshot.to_mapping()
    raw["baseline_sources"][0]["quality_review"]["note"] = "foreign but well formed"
    with pytest.raises(dto.HistoricalAIError, match="HISTORICAL_SNAPSHOT_INVALID"):
        dto.decode_historical_snapshot(
            h.canonical_json(raw), request=value.request, expected_snapshot_sha256=commitment
        )
