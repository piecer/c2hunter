"""R1: supplied generation/receipt time is fenced before derived work."""

from datetime import timedelta

import pytest
from c2hunter_analysis import behavior_baseline as pure

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_generation as g
from tests.historical_ai_fixtures import decode_with_matching_commitment, world


@pytest.mark.parametrize("axis", ["publication", "older_receipt"])
def test_future_generation_is_a_fence_mismatch_before_derived_work(axis, monkeypatch):
    raw = world()
    if axis == "publication":
        raw["request"]["admitted_at"] = raw["generation"].published_at - timedelta(microseconds=1)
    else:
        document = raw["generation"].to_mapping()
        document["sources"][0]["approved_at"] = "2026-01-07T00:00:00.000000Z"
        raw["generation"] = g.GenerationDocument.from_mapping(document)
        scope = raw["scope"].to_mapping()
        scope["active"] = g.generation_view(raw["generation"]).to_mapping()
        raw["scope"] = g.ScopeView.from_mapping(scope)
    value = dto.HistoricalAdmissionInput(**raw)
    calls = []
    for module, name in (
        (pure, "compare_behavior_windows"),
        (ai, "_shadow_preselection"),
        (ai_discovery, "select_shadow_candidates"),
    ):
        actual = getattr(module, name)

        def observe(*args, _actual=actual, _name=name, **kwargs):
            calls.append(_name)
            return _actual(*args, **kwargs)

        monkeypatch.setattr(module, name, observe)
    with pytest.raises(dto.HistoricalAIError, match="BASELINE_GENERATION_MISMATCH"):
        producer.build_historical_snapshot(value)
    assert calls == []  # noqa: S101 - pytest assertion, not an authorization guard.


@pytest.mark.parametrize("microseconds", [0, 1])
def test_equal_or_earlier_generation_roundtrips_with_original_seed(microseconds):
    raw = world()
    raw["request"]["admitted_at"] = raw["generation"].published_at + timedelta(
        microseconds=microseconds
    )
    value = dto.HistoricalAdmissionInput(**raw)
    result = producer.build_historical_snapshot(value)
    from c2hunter_controller import historical_baseline as h

    assert decode_with_matching_commitment(  # noqa: S101 - pytest assertion, not an authorization guard.
        h.canonical_json(result.to_mapping()), request=value.request
    )


def test_publication_alone_cannot_bypass_generation_document_links():
    raw = world()
    document = raw["generation"].to_mapping()
    document["published_at"] = "2026-01-07T00:00:00.000000Z"
    with pytest.raises(ValueError):
        g.GenerationDocument.from_mapping(document)
