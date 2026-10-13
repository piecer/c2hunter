"""Owning saved admission: exact seed and cross-record links precede consumption."""

import hashlib
import json

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import decode_with_matching_commitment, rule, uid, world


@pytest.fixture(scope="module")
def saved():
    value = dto.HistoricalAdmissionInput(
        **world(candidates=[rule(), rule("198.51.100.3", "other")])
    )
    result = producer.build_historical_snapshot(value)
    return value.request, h.canonical_json(result.to_mapping())


def test_roundtrip_without_source_or_generation(saved, monkeypatch):
    from c2hunter_controller import historical_generation as g
    from c2hunter_controller import historical_source as s

    request, wire = saved
    monkeypatch.setattr(
        g, "generation_reference", lambda *a, **kw: pytest.fail("current generation read")
    )
    monkeypatch.setattr(
        s, "source_build_input", lambda *a, **kw: pytest.fail("current source read")
    )
    bundles = decode_with_matching_commitment(wire, request=request)
    assert [ai.canonical_bundle_json(b) for b in bundles] == [
        b["canonical_json"] for b in json.loads(wire)["admitted_bundles"]
    ]


@pytest.mark.parametrize(
    "axis",
    [
        "run_id",
        "job_id",
        "actor",
        "created",
        "updated",
        "transition",
        "provider",
        "model",
        "prompt",
        "fingerprint",
        "request_fingerprint",
        "request",
        "limit",
        "language",
        "id_order",
        "snapshot_id",
        "snapshot_score",
        "bundle_order",
        "bytes",
        "hash",
        "comparison_selected",
        "comparison_missing",
        "summary_count",
        "summary_scope",
        "inventory_selected",
        "inventory_order",
        "selection_count",
        "selection_warning",
        "source_duplicate",
        "source_order",
        "source_review",
        "source_sensor",
        "source_ancestry",
        "source_known_partial",
        "source_compact",
        "extra",
        "progress_bool",
    ],
)
def test_mutated_owning_snapshot_rejected(saved, axis):
    request, wire = saved
    value = json.loads(wire)
    if axis == "run_id":
        value["id"] = uid(9999)
    elif axis == "job_id":
        value["analysis_job_id"] = "foreign-job"
    elif axis == "actor":
        value["created_by"] = "foreign-actor"
    elif axis == "created":
        value["created_at"] = "2026-01-07T00:00:00.000000Z"
    elif axis == "updated":
        value["updated_at"] = "2026-01-07T00:00:00.000000Z"
    elif axis == "transition":
        value["transitions"][0]["occurred_at"] = "2026-01-07T00:00:00.000000Z"
    elif axis == "provider":
        value["provider"] = "foreign"
    elif axis == "model":
        value["model_name"] = "foreign"
    elif axis == "prompt":
        value["prompt_hash"] = "f" * 64
    elif axis == "fingerprint":
        value["baseline_request_fingerprint"] = "f" * 64
    elif axis == "request_fingerprint":
        request = request.model_copy(update={"request_fingerprint": "f" * 64})
    elif axis == "request":
        value["baseline_request"]["allow_remote"] = True
    elif axis == "limit":
        value["candidate_limit"] = 1
    elif axis == "language":
        value["language"] = "en"
    elif axis == "id_order":
        value["candidate_ids"].reverse()
    elif axis == "snapshot_id":
        value["candidate_snapshots"][0]["id"] = "foreign"
    elif axis == "snapshot_score":
        value["candidate_snapshots"][0]["score"] = 99
    elif axis == "bundle_order":
        value["admitted_bundles"].reverse()
    elif axis == "bytes":
        value["admitted_bundles"][0]["canonical_json"] += " "
    elif axis == "hash":
        value["admitted_bundles"][0]["metadata"]["canonical_sha256"] = "f" * 64
    elif axis == "comparison_selected":
        value["baseline_comparisons"][0]["selected"] = False
    elif axis == "comparison_missing":
        value["baseline_comparisons"] = []
    elif axis == "summary_count":
        value["baseline_summary"]["historical_candidate_count"] = 0
    elif axis == "summary_scope":
        value["baseline_summary"]["scope_id"] = uid(444)
    elif axis == "inventory_selected":
        value["selection_inventory"][0]["selected"] = False
    elif axis == "inventory_order":
        value["selection_inventory"].reverse()
    elif axis == "selection_count":
        value["selection_summary"]["selected_count"] = 0
    elif axis == "selection_warning":
        value["selection_summary"]["warnings"].append("NO_HISTORICAL_BASELINE")
    elif axis == "source_duplicate":
        value["baseline_sources"].append(value["baseline_sources"][0])
    elif axis == "source_order":
        value["baseline_sources"].reverse()
    elif axis == "source_review":
        value["baseline_sources"][0]["quality_review"]["sensor_alias_asserted"] = True
    elif axis == "source_sensor":
        value["baseline_sources"][0]["sensor_key"] = "foreign"
    elif axis == "source_ancestry":
        value["baseline_sources"][0]["ancestry_job_ids"] = ["foreign"]
    elif axis == "source_known_partial":
        value["baseline_sources"][0]["known_partial"] = True
    elif axis == "source_compact":
        value["baseline_sources"][0]["source_binding_sha256"] = "f" * 64
    elif axis == "extra":
        value["target"] = {}
    elif axis == "progress_bool":
        value["progress_percent"] = False
    with pytest.raises(dto.HistoricalAIError) as caught:
        decode_with_matching_commitment(h.canonical_json(value), request=request)
    assert caught.value.code == "HISTORICAL_SNAPSHOT_INVALID"


def test_rehashed_foreign_candidate_bundle_rejected(saved):
    request, wire = saved
    value = json.loads(wire)
    envelope = value["admitted_bundles"][1]
    bundle = json.loads(envelope["canonical_json"])
    bundle["candidate"]["external_ip"] = "198.51.100.200"
    canonical = h.canonical_json(bundle)
    envelope["canonical_json"] = canonical
    envelope["metadata"].update(
        canonical_sha256=hashlib.sha256(canonical.encode()).hexdigest(),
        byte_size=len(canonical.encode()),
        estimated_tokens=(len(canonical.encode()) + 2) // 3,
    )
    with pytest.raises(dto.HistoricalAIError, match="HISTORICAL_SNAPSHOT_INVALID"):
        decode_with_matching_commitment(h.canonical_json(value), request=request)
