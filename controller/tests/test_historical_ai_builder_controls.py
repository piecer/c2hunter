"""Actual source/generation controls; fixture event time is not LIVE history."""

from copy import deepcopy
from datetime import timedelta

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import PEER, decode_with_matching_commitment, job, rule, world


def build(**kwargs):
    value = dto.HistoricalAdmissionInput(**world(**kwargs))
    result = producer.build_historical_snapshot(value)
    return (
        value,
        result,
        decode_with_matching_commitment(
            h.canonical_json(result.to_mapping()), request=value.request
        ),
    )


@pytest.mark.parametrize(
    "case,status",
    [
        ("matching", "READY"),
        ("one_family", "READY"),
        ("no_reference", "MISSING"),
        ("insufficient", "INSUFFICIENT"),
        ("stale", "STALE"),
        ("aggregate", "MISSING"),
        ("partial", "INCOMPATIBLE"),
        ("clock", "INCOMPATIBLE"),
        ("no_review", "INCOMPATIBLE"),
    ],
)
def test_nonpositive_history_controls(case, status):
    target = job(changed=False)
    options = {}
    if case == "one_family":
        target["flow_records"][-1]["total_bytes"] = 20
    elif case == "no_reference":
        options["sources"] = 0
    elif case == "insufficient":
        options["sources"] = 2
    elif case == "stale":
        delta = timedelta(days=10)
        for key in ("start_time", "end_time"):
            target[key] = (h._utc(target[key]) + delta).isoformat()
        for row in target["flow_records"]:
            row["timestamp"] = (h._utc(row["timestamp"]) + delta).isoformat()
    elif case == "aggregate":
        for row in target["flow_records"]:
            row["packet_count"] = 2
            row["duration_seconds"] = 0.25
    elif case == "partial":
        target["capture_incomplete"] = True
    elif case == "clock":
        target["operations"] = {"sensors": {"sensor": {"clock_offset_ms": 2001}}}
    elif case == "no_review":
        options["reviewed"] = False
    value, result, bundles = build(target=target, candidates=[rule()], **options)
    row = result.baseline_comparisons[0]
    assert row.status == status
    assert row.historical_anomaly_score == 0
    assert result.baseline_summary.historical_candidate_count == 0
    assert bundles[0].historical_reference.historical_factor_types == ()
    assert all(not e.evidence_type.startswith("BEHAVIOR_HISTORICAL_") for e in bundles[0].evidence)
    for feature in row.features.ordered():
        if feature.status != "READY":
            assert feature.reference_median is feature.reference_scale is feature.robust_z is None
    if case == "one_family":
        assert sum(f.drifting for f in row.features.ordered()) == 1
    if case == "no_review":
        assert result.baseline_summary.quality_assurance == "UNREVIEWED"
        assert "HUMAN_ASSERTED_CLOCK_BOUND" not in result.baseline_summary.warnings
        assert "TARGET_REVIEW_REQUIRED" in result.baseline_summary.warnings


@pytest.mark.parametrize("state", ["EMPTY", "REVOKED", "RETIRED"])
def test_saved_no_active_generation_and_empty_selection(state):
    target = job()
    target["flow_records"] = []
    inputs = world(target=target, sources=0)
    inputs["scope"] = inputs["scope"].model_copy(
        update={"state": state, "frozen": state != "EMPTY"}
    )
    value = dto.HistoricalAdmissionInput(**inputs)
    result = producer.build_historical_snapshot(value)
    assert result.candidate_ids == result.admitted_bundles == result.baseline_sources == ()
    assert result.baseline_summary.scope_state == state
    assert (
        decode_with_matching_commitment(
            h.canonical_json(result.to_mapping()), request=value.request
        )
        == ()
    )


def test_evaluation_missing_review_remains_refused_u02_open():
    with pytest.raises(ValueError, match="BASELINE_SCOPE_MISMATCH"):
        world(kind="EVALUATION", reviewed=False)


@pytest.mark.parametrize("kind", ["C2", "COMMUNICATION_STATUS"])
def test_selected_no_profile_and_communication_have_no_historical_claims(kind):
    candidate = rule("198.51.100.40" if kind == "C2" else PEER)
    candidate["candidate_kind"] = kind
    _, result, bundles = build(candidates=[candidate])
    bundle = next(b for b in bundles if b.candidate.candidate_id == "rule")
    reference = bundle.historical_reference
    assert reference.availability == "UNUSABLE"
    assert reference.cause == ("NO_PROFILE" if kind == "C2" else "COMMUNICATION_STATUS")
    assert reference.comparison is None
    assert reference.source_references == reference.historical_factor_types == ()
    if kind == "COMMUNICATION_STATUS":
        assert not any(c.selected for c in result.baseline_comparisons)


def test_real_local_larger_score_keeps_other_historical_stream():
    refs = [job(i, changed=False) for i in range(3)]
    for reference in refs:
        start = h._utc(reference["start_time"])
        for i, row in enumerate(reference["flow_records"][:8]):
            row["timestamp"] = (
                start + timedelta(seconds=(0, 1, 2.5, 4.5, 7, 10, 13.5, 17.5)[i])
            ).isoformat()
            row["total_bytes"] = (80 if i < 4 else 120) + int(reference["id"].split("-")[-1])
    target = job(changed=False)
    primary = deepcopy(target["flow_records"])
    for row in primary:
        key = "destination_port" if row["direction"] == "OUTBOUND" else "source_port"
        row[key] = 8443
    # More outbound observations force phase1's primary stream to 8443.
    primary.extend(
        [
            {**row, "timestamp": (h._utc(row["timestamp"]) + timedelta(seconds=10)).isoformat()}
            for row in primary[:8]
        ]
    )
    target["flow_records"].extend(primary)
    for i in range(8):
        other = job()["flow_records"]
        for row in other:
            field = "destination_ip" if row["direction"] == "OUTBOUND" else "source_ip"
            row[field] = f"203.0.113.{30 + i}"
            port = "destination_port" if row["direction"] == "OUTBOUND" else "source_port"
            row[port] = 8443
        target["flow_records"].extend(other)
    legacy, local, _ = ai._shadow_preselection(target, [rule()])
    local_peer = next(c for c in local if c["candidate_ip"] == PEER)
    value, result, bundles = build(target=target, reference_jobs=refs, candidates=[rule()])
    bundle = next(b for b in bundles if b.candidate.external_ip == PEER)
    comparison = bundle.historical_reference.comparison
    assert local_peer["behavior_anomaly_score"] > comparison.historical_anomaly_score > 0
    assert local_peer["ports"] == [443, 8443]  # peer summary, not the historical identity
    assert comparison.key.service_port == 443
    selected = next(
        h.thaw_original_json(c)
        for c in result.candidate_snapshots
        if dict(c.entries)["candidate_ip"] == PEER
    )
    assert selected["behavior_anomaly_score"] == local_peer["behavior_anomaly_score"]
    assert selected["discovery_origin"] == "RULE_AND_BEHAVIOR"
    assert selected["score"] == 80
    assert result.selection_summary.reserved_discovery_slots <= 2
    assert (
        sum(
            e.contribution
            for e in bundle.evidence
            if e.evidence_type.startswith("BEHAVIOR_HISTORICAL_")
        )
        == comparison.historical_anomaly_score
    )
    assert (
        len([c for c in result.baseline_comparisons if c.selected and c.key.peer_ip == PEER]) == 1
    )


def test_snapshot_contains_final_selected_evidence_not_prefinal_input():
    _, result, bundles = build(candidates=[rule()])
    snapshot = h.thaw_original_json(result.candidate_snapshots[0])
    expected = [
        {
            "type": e.evidence_type,
            "description": e.description,
            "contribution": e.contribution,
            "metrics": e.metrics,
        }
        for e in bundles[0].evidence
    ]
    assert snapshot["evidence"] == expected
