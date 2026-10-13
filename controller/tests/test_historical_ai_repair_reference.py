"""R2: protected provenance overflow is not a generic shape failure."""

from datetime import timedelta

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import decode_with_matching_commitment, job, rule, world


def long_reference_value(count):
    refs = []
    for index in range(count):
        raw = job(index, changed=False)
        shift = timedelta(hours=-9 * index)
        for name in ("start_time", "end_time"):
            raw[name] = (h._utc(raw[name]) + shift).isoformat()
        for row in raw["flow_records"]:
            row["timestamp"] = (h._utc(row["timestamp"]) + shift).isoformat()
        raw["id"] = f"reference-{index:02d}-" + "x" * 180
        refs.append(raw)
    return dto.HistoricalAdmissionInput(
        **world(target=job(5), sources=count, reference_jobs=refs, candidates=[rule()])
    )


def test_real_reference_8k_overflow_preserves_limit_taxonomy():
    value = long_reference_value(16)
    before = value.model_dump_json()
    with pytest.raises(dto.HistoricalAIError) as error:
        producer.build_historical_snapshot(value)
    assert error.value.code == "BASELINE_RUN_SNAPSHOT_LIMIT"  # noqa: S101 - pytest assertion, not an authorization guard.
    assert value.model_dump_json() == before  # noqa: S101 - pytest assertion, not an authorization guard.


def test_small_reference_keeps_all_support_and_exact_saved_bundle():
    value = long_reference_value(3)
    result = producer.build_historical_snapshot(value)
    saved = h.canonical_json(result.to_mapping())
    bundle = decode_with_matching_commitment(saved, request=value.request)[0]
    assert len(bundle.historical_reference.source_references) == 3  # noqa: S101 - pytest assertion, not an authorization guard.
    assert bundle.historical_reference.comparison.status == "INSUFFICIENT"  # noqa: S101 - pytest assertion, not an authorization guard.
    assert bundle.historical_reference.historical_factor_types == ()  # noqa: S101 - pytest assertion, not an authorization guard.


def test_ordinary_malformed_request_remains_source_invalid():
    value = long_reference_value(3)
    request = value.request.model_copy(update={"actor": []})
    with pytest.raises(dto.HistoricalAIError, match="BASELINE_SOURCE_INVALID"):
        producer.build_historical_snapshot(value.model_copy(update={"request": request}))
