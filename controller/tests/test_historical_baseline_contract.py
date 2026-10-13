"""No-I/O historical handoff contracts; legacy consumers remain the oracle."""

import importlib
import importlib.util
import json
from typing import Any

import pytest

from c2hunter_controller.ai_analysis import (
    SENSITIVE_EVIDENCE_KEYS,
    _candidate_snapshot,
    _data_quality,
    _safe_metrics,
    build_evidence_bundle,
    canonical_bundle_json,
)


def contract() -> Any:
    name = "c2hunter_controller.historical_baseline"
    assert importlib.util.find_spec(name) is not None, "lossless projection boundary missing"
    return importlib.import_module(name)


def test_original_object_order_and_json_kinds_survive_real_local_consumers() -> None:
    h = contract()
    collision = "x" * 100
    metrics: dict[str, Any] = {
        "Raw_Payload": "do not send",
        collision + "b": 1,
        collision + "a": 2,
        "nested": {"z": [], "a": {}, "pairs": [["a", 1]]},
        **{f"key{i:02}": i for i in reversed(range(35))},
    }
    candidate = {
        "id": "candidate-1",
        "candidate_ip": "203.0.113.2",
        "score": 12,
        "evidence": [{"type": "TEST", "metrics": metrics}],
    }
    frozen = h.freeze_original_json(candidate)
    restored = h.thaw_original_json(frozen)
    assert restored == candidate
    assert list(restored["evidence"][0]["metrics"]) == list(metrics)
    assert _safe_metrics(restored["evidence"][0]["metrics"]) == _safe_metrics(metrics)
    assert _candidate_snapshot(restored) == _candidate_snapshot(candidate)
    assert canonical_bundle_json(build_evidence_bundle(restored)) == canonical_bundle_json(
        build_evidence_bundle(candidate)
    )
    reordered = dict(
        candidate, evidence=[{"type": "TEST", "metrics": dict(reversed(list(metrics.items())))}]
    )
    assert _candidate_snapshot(reordered) != _candidate_snapshot(candidate)
    assert h.original_binding_sha256(frozen) != h.original_binding_sha256(
        h.freeze_original_json(reordered)
    )
    kinds = [{}, [], [["x", 1]], {"x": 1}]
    assert len({h.original_binding_sha256(h.freeze_original_json(v)) for v in kinds}) == 4
    for value in kinds:
        assert json.dumps(h.thaw_original_json(h.freeze_original_json(value))) == json.dumps(value)
    metrics["nested"]["z"].append("mutation")
    assert h.thaw_original_json(frozen) == restored


def test_original_json_rejects_malformed_and_checks_limits_before_copy() -> None:
    h = contract()
    for bad in [
        float("nan"),
        float("inf"),
        {1: "bad"},
        object(),
        {"bad": (1, 2)},
        "bad\x00",
        10**100,
    ]:
        with pytest.raises(ValueError):
            h.freeze_original_json(bad)
    value: Any = 0
    for _ in range(16):
        value = [value]
    h.freeze_original_json(value)
    with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
        h.freeze_original_json([value])
    h.freeze_original_json([0] * 262143)
    with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
        h.freeze_original_json([0] * 262144)
    assert h.freeze_original_json("é", max_bytes=4) == "é"
    with pytest.raises(ValueError, match="BASELINE_SOURCE_LIMIT"):
        h.freeze_original_json("é", max_bytes=3)
    with pytest.raises(ValueError):
        h.FrozenObject((("x", []),))
    with pytest.raises(ValueError):
        h.FrozenObject((("x", 1), ("x", 2)))
    assert h.thaw_original_json(h.decode_original_json('{"z":{},"a":[]}')) == {"z": {}, "a": []}
    for raw in ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}']:
        with pytest.raises(ValueError):
            h.decode_original_json(raw)


def test_quality_facts_use_qualified_paths_and_never_invent_measurements() -> None:
    h = contract()
    assert hasattr(h, "project_source_quality"), "stored quality boundary missing"
    raw: dict[str, Any] = {
        "source": {"skipped_packet_count": 3},
        "capture_quality": {"dropped_packet_count": 2, "clock_skew_detected": False},
        "capture_limit": {"discarded_packets": 4},
        "capture_incomplete": True,
        "error_code": None,
        "capture": {"requested_end_time": "2026-01-01T10:01:00+09:00"},
        "capture_stopped_at": "2026-01-01T01:00:50Z",
        "capture_completions": {
            "sensor-z": {"stop_reason": "MAX_BYTES", "reported_at": "2026-01-01T01:00:50Z"}
        },
        "operations": {
            "failed_sensors": ["sensor-z", "sensor-z"],
            "sensors": {"sensor-z": {"clock_offset_ms": -2001}, "sensor-a": {"status": "OK"}},
        },
        "skipped_packet_count": 999,
    }
    facts = h.project_source_quality(raw)
    mapped = facts.to_mapping()
    assert mapped["skipped_packet_count"] == {"present": True, "value": 3}
    assert mapped["error_code"] == {"present": True, "value": None}
    assert mapped["requested_end_time"]["value"] == "2026-01-01T01:01:00.000000Z"
    assert mapped["sensor_offsets"] == [{"sensor_id": "sensor-z", "clock_offset_ms": -2001}]
    assert mapped["failed_sensors"]["value"] == ["sensor-z"]
    raw["operations"]["sensors"]["sensor-z"]["clock_offset_ms"] = 0
    assert facts.to_mapping() == mapped
    assert h.SourceQualityFacts.from_mapping(mapped) == facts
    missing = h.project_source_quality({}).to_mapping()
    assert missing["skipped_packet_count"] == {"present": False}
    assert missing["sensor_offsets"] == []
    for changed in [
        dict(mapped, extra=1),
        dict(mapped, skipped_packet_count={"present": True, "value": True}),
        dict(mapped, error_code={"present": False, "value": None}),
    ]:
        with pytest.raises(ValueError):
            h.SourceQualityFacts.from_mapping(changed)
    for bad in [None, True, -1, float("nan"), "3"]:
        with pytest.raises(ValueError):
            h.project_source_quality({"source": {"skipped_packet_count": bad}})
    for raw_bad in [
        {"capture_incomplete": 0},
        {"capture_quality": {"clock_skew_detected": None}},
        {"capture": {"requested_end_time": "2026-01-01T01:01:00"}},
        {"operations": {"sensors": {"s": {"clock_offset_ms": True}}}},
    ]:
        with pytest.raises(ValueError):
            h.project_source_quality(raw_bad)


def test_quality_union_retains_ancestral_envelope_and_negative_evidence() -> None:
    h = contract()
    assert hasattr(h, "merge_source_quality"), "quality provenance union missing"
    root = h.project_source_quality(
        {
            "capture": {"requested_end_time": "2026-01-01T00:02:00Z"},
            "source": {"skipped_packet_count": 3},
            "operations": {"sensors": {"s": {"clock_offset_ms": -2100}}},
        }
    )
    args = dict(
        original_start="2026-01-01T00:00:00Z",
        original_end="2026-01-01T00:01:00Z",
        effective_start="2026-01-01T00:00:00Z",
        effective_end="2026-01-01T00:01:00Z",
    )
    first = h.merge_source_quality(**args, facts=(root,), inherited=(), partial_status=False)
    assert first.known_partial and first.clock_uncertain
    child = h.project_source_quality(
        {
            "source": {"skipped_packet_count": 1},
            "capture_incomplete": False,
            "operations": {"sensors": {"s": {"clock_offset_ms": 2100}}},
        }
    )
    args["effective_end"] = "2026-01-01T00:03:00Z"
    merged = h.merge_source_quality(
        **args,
        facts=(h.project_source_quality({}), child),
        inherited=(first,),
        partial_status=False,
    )
    mapped = merged.to_mapping()
    assert mapped["skipped_packet_count"] == {"present": True, "value": 3}
    assert mapped["dropped_packet_count"] == {"present": False}
    assert mapped["capture_incomplete"] == {"present": True, "value": False}
    assert mapped["sensor_offset_bounds"] == [
        {"sensor_id": "s", "minimum_ms": -2100, "maximum_ms": 2100}
    ]
    assert mapped["original_end"] == "2026-01-01T00:01:00.000000Z"
    assert mapped["effective_end"] == "2026-01-01T00:03:00.000000Z"
    assert merged.known_partial and merged.clock_uncertain
    assert h.stored_clock_offset_ms(merged) == -2100
    assert h.SourceObservationQuality.from_mapping(mapped) == merged
    empty = h.merge_source_quality(
        **args, facts=(h.project_source_quality({}),), inherited=(), partial_status=False
    )
    assert not empty.known_partial and not empty.clock_uncertain
    assert h.stored_clock_offset_ms(empty) is None
    assert empty.producer_completeness == "UNKNOWN"
    with pytest.raises(ValueError, match="BASELINE_SOURCE_LINEAGE_INVALID"):
        h.merge_source_quality(
            **dict(args, original_end="2026-01-01T00:04:00Z"),
            facts=(child,),
            inherited=(first,),
            partial_status=False,
        )
    with pytest.raises(ValueError):
        h.SourceObservationQuality.from_mapping(
            dict(
                mapped, sensor_offset_bounds=[{"sensor_id": "s", "minimum_ms": 4, "maximum_ms": 3}]
            )
        )


def test_original_projections_strip_values_not_presence_or_local_order() -> None:
    h = contract()
    assert hasattr(h, "project_original_flow"), "original flow projection missing"
    flow = {
        "sensor_id": "s",
        "timestamp": "2026-01-01T09:00:00+09:00",
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.2",
        "protocol": "tcp",
        "direction": "OUTBOUND",
        "packet_count": 1,
        "total_bytes": 9,
        "duration_seconds": 0,
        "Raw_Payload": "secret",
        "PAYLOAD": {"nested": "secret"},
        "ignored": "unused",
    }
    projected = h.project_original_flow(flow)
    assert projected.sensitive_keys_present == ("PAYLOAD", "Raw_Payload")
    assert set(h.SENSITIVE_ORIGINAL_KEYS) == SENSITIVE_EVIDENCE_KEYS
    assert "secret" not in repr(projected)
    assert list(h.thaw_original_json(projected.fields)) == [
        k for k in flow if k not in {"Raw_Payload", "PAYLOAD", "ignored"}
    ]
    assert (
        h.projected_payload_fields_excluded((projected,))
        == _data_quality({}, [flow]).payload_fields_excluded
        == 1
    )
    assert h.OriginalFlowProjection.from_mapping(projected.to_mapping()) == projected
    metrics = {"Raw_Payload": "secret", **{f"key{i}": i for i in reversed(range(35))}}
    raw = {
        "id": "c",
        "candidate_ip": "203.0.113.2",
        "score": 5,
        "excluded": True,
        "severity": None,
        "decision": "ignored",
        "evidence": [{"metrics": metrics, "unknown": "ignored"}],
    }
    candidate = h.project_candidate(raw, position=0)
    restored = h.thaw_original_json(candidate.fields)
    assert restored["severity"] is None and restored["excluded"] is True
    assert "decision" not in restored and "unknown" not in restored["evidence"][0]
    assert "secret" not in repr(candidate)
    assert _candidate_snapshot(restored) == _candidate_snapshot(raw)
    assert h.CandidateProjection.from_mapping(candidate.to_mapping()) == candidate
    for bad in [dict(raw, score=True), dict(raw, candidate_ip="not-ip"), dict(raw, evidence=None)]:
        with pytest.raises(ValueError):
            h.project_candidate(bad, position=0)
    for missing in ["timestamp", "packet_count", "duration_seconds"]:
        with pytest.raises(ValueError):
            h.project_original_flow({k: v for k, v in flow.items() if k != missing})
    with pytest.raises(ValueError):
        h.project_original_flow(dict(flow, packet_count=True))
    with pytest.raises(ValueError):
        h.project_candidate(dict(raw, unused="x" * 65536), position=0)


def scope_mapping() -> dict[str, Any]:
    return {
        "scope_id": "12345678-1234-1234-1234-123456789abc",
        "name": "scope",
        "kind": "OPERATIONAL",
        "sensor_key": "logical",
        "stored_sensor_id": "sensor-1",
        "internal_networks": ["10.0.0.0/8"],
        "window_seconds": 60,
        "hosts": [{"ip": "10.0.0.1", "epoch": "epoch-1"}],
        "identity_assertion": "STABLE_SINGLE_HOST_NO_SHARED_NAT",
        "reason": "reviewed",
    }


def review_mapping() -> dict[str, Any]:
    return {
        "representative_window_asserted": True,
        "stable_host_attribution_asserted": True,
        "clock_offset_bound_ms": 2000,
        "sensor_alias_asserted": False,
        "note": "human assertion not measurement",
    }


def test_scope_identity_is_immutable_canonical_and_assertion_tier_is_explicit() -> None:
    h = contract()
    assert hasattr(h, "ScopeConfig"), "scope identity DTO missing"
    raw = scope_mapping()
    config = h.ScopeConfig.from_mapping(raw)
    original_hash = h.scope_config_sha256(config)
    raw["hosts"][0]["epoch"] = "changed"
    assert config.hosts[0].epoch == "epoch-1"
    assert h.ScopeConfig.from_mapping(config.to_mapping()) == config
    assert (
        h.scope_config_sha256(
            h.ScopeConfig.from_mapping(dict(config.to_mapping(), name="display", reason="cosmetic"))
        )
        == original_hash
    )
    assert h.scope_config_sha256(h.ScopeConfig.from_mapping(raw)) != original_hash
    with pytest.raises(ValueError):
        config.hosts[0].epoch = "changed"
    for bad in [
        dict(scope_mapping(), stored_sensor_id=None),
        dict(scope_mapping(), kind="EVALUATION"),
        dict(scope_mapping(), window_seconds=True),
        dict(scope_mapping(), window_seconds=21601),
        dict(scope_mapping(), extra=True),
        dict(scope_mapping(), hosts=scope_mapping()["hosts"] * 2),
        dict(scope_mapping(), internal_networks=["10.0.0.0/8"] * 129),
    ]:
        with pytest.raises(ValueError):
            h.ScopeConfig.from_mapping(bad)
    review = h.QualityReview.from_mapping(review_mapping())
    assert h.QualityReview.from_mapping(review.to_mapping()) == review
    for bad in [
        dict(review_mapping(), representative_window_asserted=1),
        dict(review_mapping(), clock_offset_bound_ms=True),
        dict(review_mapping(), clock_offset_bound_ms=2001),
        dict(review_mapping(), stable_host_attribution_asserted=False),
    ]:
        with pytest.raises(ValueError):
            h.QualityReview.from_mapping(bad)
    h.validate_sensor_assertion(
        config, actual_sensor_id="sensor-1", review=review, origin="SENSOR_CAPTURE"
    )
    for actual, origin in [("other", "SENSOR_CAPTURE"), ("sensor-1", "PCAP_UPLOAD")]:
        with pytest.raises(ValueError):
            h.validate_sensor_assertion(
                config, actual_sensor_id=actual, review=review, origin=origin
            )
    evaluation = h.ScopeConfig.from_mapping(
        dict(scope_mapping(), kind="EVALUATION", stored_sensor_id=None)
    )
    with pytest.raises(ValueError):
        h.validate_sensor_assertion(
            evaluation, actual_sensor_id="pcap-upload:one", review=review, origin="PCAP_UPLOAD"
        )
    alias_review = h.QualityReview.from_mapping(dict(review_mapping(), sensor_alias_asserted=True))
    h.validate_sensor_assertion(
        evaluation, actual_sensor_id="pcap-upload:one", review=alias_review, origin="PCAP_UPLOAD"
    )


def job_mapping() -> dict[str, Any]:
    return {
        "id": "job-1",
        "dataset_id": "dataset-1",
        "parent_job_id": None,
        "source_type": "SENSOR_CAPTURE",
        "mode": "LIVE_CAPTURE",
        "status": "COMPLETED",
        "start_time": "2026-01-01T09:00:00+09:00",
        "end_time": "2026-01-01T09:01:00+09:00",
        "sensor_ids": ["sensor-1"],
        "internal_networks": ["10.0.0.0/8"],
        "analysis": {"periodicity_min_samples": 5, "module": "c2"},
        "flow_records": [],
    }


def test_job_projection_preserves_original_subset_and_bindings_are_purpose_exact() -> None:
    h = contract()
    assert hasattr(h, "project_original_job"), "original job projection missing"
    raw = job_mapping()
    raw["operations"] = {"sensors": {"sensor-1": {"status": "OK"}}, "warnings": []}
    raw["allowlist"] = [
        {
            "type": "IP",
            "value": "203.0.113.2",
            "description": "peer",
            "enabled": True,
            "unused": "ignored",
        }
    ]
    original = h.project_original_job(raw)
    restored = h.thaw_original_job(original)
    assert list(restored["analysis"]) == list(raw["analysis"])
    assert restored["start_time"] == raw["start_time"]
    assert "clock_offset_ms" not in restored["operations"]["sensors"]["sensor-1"]
    assert "unused" not in restored["allowlist"][0]
    assert h.OriginalJobProjection.from_mapping(original.to_mapping()) == original
    del raw["operations"]
    del raw["allowlist"]
    absent = h.project_original_job(raw)
    assert "operations" not in h.thaw_original_job(absent)
    assert absent.to_mapping()["allowlist"] == {"present": False}
    lineage = h.project_lineage_node(raw)
    quality = h.merge_source_quality(
        original_start=raw["start_time"],
        original_end=raw["end_time"],
        effective_start=raw["start_time"],
        effective_end=raw["end_time"],
        facts=(lineage.quality,),
        inherited=(),
        partial_status=False,
    )
    source = h.SourceBindingProjection(
        original=original,
        lineage=(lineage,),
        root_job_id="job-1",
        root_identity='["job-1","dataset-1"]',
        root_content_sha256=None,
        origin="SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        actual_sensor_id="sensor-1",
        event_start=raw["start_time"],
        event_end=raw["end_time"],
        internal_networks=("10.0.0.0/8",),
        quality=quality,
    )
    candidate_raw = {
        "id": "c",
        "candidate_ip": "203.0.113.2",
        "score": 4,
        "excluded": False,
        "evidence": [{"metrics": {"z": 1, "a": 2}}],
    }
    candidate = h.project_candidate(candidate_raw, position=0)
    approval = h.source_binding_sha256(source, purpose="APPROVAL")
    comparison = h.source_binding_sha256(source, purpose="COMPARISON", candidates=(candidate,))
    assert comparison != approval
    edited = h.project_candidate(dict(candidate_raw, score=5), position=0)
    assert h.source_binding_sha256(source, purpose="COMPARISON", candidates=(edited,)) != comparison
    workflow = h.project_candidate(
        dict(candidate_raw, decision="APPROVE", notes="cosmetic"), position=0
    )
    assert (
        h.source_binding_sha256(source, purpose="COMPARISON", candidates=(workflow,)) == comparison
    )
    with pytest.raises(ValueError):
        h.source_binding_sha256(source, purpose="APPROVAL", candidates=(candidate,))
    with pytest.raises(ValueError):
        h.source_binding_sha256(source, purpose="COMPARISON", candidates=(candidate, candidate))
    assert h.SourceBindingProjection.from_mapping(source.to_mapping()) == source
    for bad in [
        dict(source.to_mapping(), root_job_id="wrong"),
        dict(source.to_mapping(), origin="PCAP_UPLOAD"),
        dict(source.to_mapping(), lineage=[]),
        dict(source.to_mapping(), quality=dict(quality.to_mapping(), known_partial=True)),
    ]:
        with pytest.raises(ValueError):
            h.SourceBindingProjection.from_mapping(bad)
    binding = h.source_binding_value(source)
    assert binding["original"]["analysis"] == {
        "kind": "object",
        "entries": [
            ["periodicity_min_samples", {"kind": "scalar", "value": 5}],
            ["module", {"kind": "scalar", "value": "c2"}],
        ],
    }
    for field in ["analysis", "sensor_ids", "flow_records"]:
        with pytest.raises(ValueError):
            h.project_original_job({k: v for k, v in raw.items() if k != field})


def test_lineage_aggregation_retains_intermediate_cutoff_and_rejects_bad_edges() -> None:
    h = contract()
    assert hasattr(h, "aggregate_lineage_quality"), "retained lineage envelope fold missing"
    root_raw = job_mapping()
    child_raw = dict(
        root_raw,
        id="child",
        parent_job_id="job-1",
        end_time="2026-01-01T00:00:30Z",
        capture={"requested_end_time": "2026-01-01T00:01:00Z"},
    )
    grandchild_raw = dict(
        root_raw, id="grandchild", parent_job_id="child", end_time="2026-01-01T00:02:00Z"
    )
    nodes = tuple(h.project_lineage_node(v) for v in (root_raw, child_raw, grandchild_raw))
    quality = h.aggregate_lineage_quality(nodes, selected_job_id="grandchild")
    assert quality.known_partial
    assert quality.original_end.isoformat() == "2026-01-01T00:01:00+00:00"
    assert quality.effective_end.isoformat() == "2026-01-01T00:02:00+00:00"
    assert (
        h.aggregate_lineage_quality(tuple(reversed(nodes)), selected_job_id="grandchild") == quality
    )
    for bad_nodes in [
        nodes[1:],
        (nodes[0], nodes[0]),
        (h.project_lineage_node(dict(root_raw, parent_job_id="grandchild")), *nodes[1:]),
        (nodes[0], h.project_lineage_node(dict(child_raw, dataset_id="other")), nodes[2]),
    ]:
        with pytest.raises(ValueError, match="BASELINE_SOURCE_LINEAGE_INVALID"):
            h.aggregate_lineage_quality(bad_nodes, selected_job_id="grandchild")


@pytest.mark.parametrize("count", [128, 129])
def test_quality_context_limit_is_checked_before_deduplication(count: int) -> None:
    h = contract()
    raw = {"operations": {"failed_sensors": ["same"] * count}}
    if count == 128:
        assert h.project_source_quality(raw).failed_sensors.value == ("same",)
    else:
        with pytest.raises(ValueError):
            h.project_source_quality(raw)


def test_direct_dto_construction_cannot_retain_sensitive_metric_values() -> None:
    h = contract()
    with pytest.raises(ValueError):
        h.CandidateProjection(
            position=0,
            fields=h.freeze_original_json(
                {
                    "id": "c",
                    "candidate_ip": "203.0.113.2",
                    "score": 4,
                    "evidence": [{"metrics": {"Raw_Payload": "secret"}}],
                }
            ),
        )


def test_quality_mapping_validation_does_not_reserialize_the_whole_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h = contract()
    mapped = h.project_source_quality({}).to_mapping()
    original_dumps = json.dumps

    def bounded_dumps(value: object, *args: Any, **kwargs: Any) -> str:
        assert not isinstance(value, dict | list), "whole-document copy before field admission"
        return original_dumps(value, *args, **kwargs)

    monkeypatch.setattr(h.json, "dumps", bounded_dumps)
    assert h.SourceQualityFacts.from_mapping(mapped).to_mapping() == mapped


def test_direct_record_dto_byte_limit_matches_projection_limit() -> None:
    h = contract()
    raw: dict[str, Any] = {
        "id": "c",
        "candidate_ip": "203.0.113.2",
        "score": 4,
        "evidence": [{"description": ""}],
    }
    overhead = len(h.canonical_json(raw).encode())
    raw["evidence"][0]["description"] = "x" * (65536 - overhead)
    assert len(h.canonical_json(raw).encode()) == 65536
    admitted = h.project_candidate(raw, position=0)
    assert h.CandidateProjection.from_mapping(admitted.to_mapping()) == admitted
    raw["evidence"][0]["description"] += "x"
    with pytest.raises(ValueError):
        h.CandidateProjection.from_mapping({"position": 0, "fields": raw})


@pytest.mark.parametrize("count", [8192, 8193])
def test_original_flow_row_count_limit(count: int) -> None:
    h = contract()
    row = {
        "sensor_id": "sensor-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "source_ip": "10.0.0.1",
        "destination_ip": "203.0.113.2",
        "protocol": "TCP",
        "direction": "OUTBOUND",
        "packet_count": 1,
        "total_bytes": 1,
        "duration_seconds": 0,
    }
    job = dict(job_mapping(), flow_records=[row] * count)
    if count == 8192:
        assert len(h.project_original_job(job).flow_records) == count
    else:
        with pytest.raises(ValueError):
            h.project_original_job(job)
