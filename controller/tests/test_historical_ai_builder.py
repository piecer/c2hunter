"""Production source -> comparison -> single selector -> finalized saved decoder."""

import hashlib
import importlib
import importlib.util

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_evidence as e
from tests.historical_ai_fixtures import PEER, decode_with_matching_commitment, world


def modules():
    for name in ("historical_ai", "historical_ai_builder"):
        assert importlib.util.find_spec("c2hunter_controller." + name) is not None, (
            "owning historical builder/snapshot API missing: " + name
        )
    return (
        importlib.import_module("c2hunter_controller.historical_ai"),
        importlib.import_module("c2hunter_controller.historical_ai_builder"),
    )


@pytest.mark.parametrize("kind", ["OPERATIONAL", "EVALUATION"])
def test_real_positive_end_to_end(kind, monkeypatch):
    inputs = world(kind=kind)
    before = h.canonical_json(inputs["target"].to_mapping())
    assert len(inputs["generation"].sources) == 3
    dto, producer = modules()
    request = dto.HistoricalAdmissionInput(**inputs)
    calls = []
    selector = ai_discovery.select_shadow_candidates

    def observed(*args, **kwargs):
        calls.append((args, kwargs))
        return selector(*args, **kwargs)

    monkeypatch.setattr(ai_discovery, "select_shadow_candidates", observed)
    monkeypatch.setattr(ai, "_now", lambda: pytest.fail("builder acquired clock"))
    monkeypatch.setattr(ai, "_finalize_bundle", lambda _: pytest.fail("off finalizer used"))
    result = producer.build_historical_snapshot(request)
    assert len(calls) == 1
    assert result.candidate_ids == tuple(b.candidate_id for b in result.admitted_bundles)
    assert len(result.candidate_ids) == 1
    assert result.baseline_summary.profile_counts.READY == 1
    assert result.baseline_summary.historical_candidate_count == 1
    assert result.baseline_summary.scope_kind == kind
    assert result.baseline_sources == inputs["generation"].sources
    assert result.selection_summary.reserved_discovery_slots <= 2
    assert result.baseline_comparisons[0].selected is True
    wire = h.canonical_json(result.to_mapping())
    decoded = decode_with_matching_commitment(wire, request=request.request)
    assert len(decoded) == 1
    bundle = decoded[0]
    assert bundle.candidate.external_ip == PEER
    assert bundle.historical_reference.availability == "USABLE"
    assert bundle.evidence[0].evidence_id == e.COVERAGE_ID
    assert len(bundle.historical_reference.historical_factor_types) >= 2
    assert ai.canonical_bundle_json(bundle) == result.admitted_bundles[0].canonical_json
    assert hashlib.sha256(ai.canonical_bundle_json(bundle).encode()).hexdigest() == (
        result.admitted_bundles[0].metadata.canonical_sha256
    )
    assert h.canonical_json(inputs["target"].to_mapping()) == before
    assert "strict_flows" not in result.to_mapping()
    assert "NO_HISTORICAL_BASELINE" not in result.selection_summary.warnings
