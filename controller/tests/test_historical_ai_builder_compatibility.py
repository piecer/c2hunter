"""Characterize actual off/shadow consumers before extracting their local seam."""

import hashlib
from copy import deepcopy

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import job, rule


def test_existing_shadow_and_off_bytes(capsys):
    original, candidates = job(), [rule()]
    before = deepcopy((original, candidates))
    selected, inventory, summary = ai._shadow_candidate_selection(original, candidates, 2)
    assert len(selected) == 1
    assert selected[0]["id"] == "rule"
    assert summary["warnings"][0] == "NO_HISTORICAL_BASELINE"
    assert summary["candidate_pool_count"] == 1
    assert inventory[0]["selected"] is True
    bundle = ai.build_evidence_bundle(selected[0], job=original)
    assert "historical_reference" not in bundle.model_dump(mode="json")
    assert "historical_reference" not in ai.canonical_bundle_json(bundle)
    assert (original, candidates) == before
    assert hashlib.sha256(
        h.canonical_json([selected, inventory, summary]).encode()
    ).hexdigest() == ("0dde30f3a114687ea94e77aca92e1e5b581a35cf062feddc1d1922b8251f3371")
    assert hashlib.sha256(ai.canonical_bundle_json(bundle).encode()).hexdigest() == (
        "4b82b5391232f198c61fd8ab34248fdf8e71bb4b31e3bc1e2ea45240821e369c"
    )


def test_local_preselection_preserves_real_shadow_inputs():
    prepare = getattr(ai, "_shadow_preselection", None)
    assert callable(prepare), "local preselection seam missing; historical must not select twice"
    original, candidates = job(), [rule()]
    legacy, behavior, result = prepare(original, candidates)
    from c2hunter_controller.ai_discovery import select_shadow_candidates

    selected, inventory, summary = select_shadow_candidates(legacy, behavior, limit=2)
    old_selected, old_inventory, old_summary = ai._shadow_candidate_selection(
        original, candidates, 2
    )
    assert inventory == old_inventory
    assert selected[0]["evidence"] == old_selected[0]["evidence"][1:]
    assert summary["selected_count"] == old_summary["selected_count"]
    assert result is not None
