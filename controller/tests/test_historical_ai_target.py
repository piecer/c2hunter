"""Unreviewed evaluation targets stay comparable without approval authority."""

from dataclasses import replace
from pathlib import Path

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import ai_discovery
from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as builder
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as reader
from c2hunter_controller import historical_source as source
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.historical_ai_fixtures import decode_with_matching_commitment, job, rule, world


@pytest.fixture(params=["memory", "sqlite"])
def repository(request, tmp_path):
    repo = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "target.db")
    )
    yield repo
    repo.close()


def acquire_target(repo, raw, cfg, quality=None):
    with repo._lock:
        if isinstance(repo, MemoryRepository):
            return reader.memory_ai_target(repo.jobs, repo.candidates, raw["id"], cfg, quality)
        repo.connection.execute("BEGIN")
        try:
            value = reader.sqlite_ai_target(repo.connection, raw["id"], cfg, quality)
            assert repo.connection.in_transaction
            return value
        finally:
            repo.connection.rollback()


def unreviewed_request(inputs):
    request = inputs["request"]
    request["payload"]["baseline_reference"]["quality_review"] = None
    payload = dto.FrozenAIAnalysisRunCreate(**request["payload"])
    request["request_fingerprint"] = dto.request_fingerprint(
        request["analysis_job_id"], request["actor"], payload
    )
    return dto.HistoricalAdmissionRequest(**request)


def test_persisted_unreviewed_evaluation_reaches_saved_snapshot(repository, monkeypatch):
    inputs = world(kind="EVALUATION", candidates=[rule()])
    request = unreviewed_request(inputs)
    repo = repository
    raw = job()
    repo.save_job(raw)
    repo.save_candidates(raw["id"], [rule()])
    before = h.canonical_json(repo.get_job(raw["id"]))
    calls = []
    select = ai_discovery.select_shadow_candidates

    def selected(*args, **kwargs):
        calls.append(1)
        return select(*args, **kwargs)

    def forbidden(*args, **kwargs):
        pytest.fail("unreviewed target entered reviewed authority or generic source getter")

    for name in ("get_job", "get_candidates"):
        monkeypatch.setattr(repo, name, forbidden)
    monkeypatch.setattr(source, "source_build_input", forbidden)
    monkeypatch.setattr(source, "source_from_binding", forbidden)
    monkeypatch.setattr(ai_discovery, "select_shadow_candidates", selected)
    target = acquire_target(repo, raw, inputs["scope"].config)
    snapshot = builder.build_historical_target_snapshot(
        request, target, inputs["scope"], inputs["generation"]
    )
    assert calls == [1]
    assert snapshot.baseline_summary.quality_assurance == "UNREVIEWED"
    assert snapshot.baseline_summary.profile_counts.INCOMPATIBLE == 1
    assert snapshot.baseline_summary.historical_candidate_count == 0
    comparison = snapshot.baseline_comparisons[0]
    assert comparison.historical_anomaly_score == 0
    assert comparison.features.recurrence.current is not None
    assert comparison.source_window_ids == ()
    for feature in comparison.features.ordered():
        assert feature.status == "INCOMPATIBLE"
        assert feature.reference_median is None
        assert feature.eligible_window_ids == ()
        assert feature.drifting is False
    assert "TARGET_REVIEW_REQUIRED" in snapshot.baseline_summary.warnings
    assert "EVALUATION_SENSOR_ALIAS" not in snapshot.baseline_summary.warnings
    assert "HUMAN_ASSERTED_CLOCK_BOUND" not in snapshot.baseline_summary.warnings
    decoded = decode_with_matching_commitment(
        h.canonical_json(snapshot.to_mapping()), request=request
    )
    assert decoded[0].historical_reference.availability == "UNUSABLE"
    assert decoded[0].historical_reference.historical_factor_types == ()
    assert Path(source.__file__).resolve().is_relative_to(Path.cwd())
    assert ai.canonical_bundle_json(decoded[0]) == snapshot.admitted_bundles[0].canonical_json
    monkeypatch.undo()
    assert h.canonical_json(repo.get_job(raw["id"])) == before


@pytest.mark.parametrize(
    "kind,reviewed", [("OPERATIONAL", True), ("OPERATIONAL", False), ("EVALUATION", True)]
)
def test_reviewed_and_operational_targets_keep_exact_snapshot_bytes(repository, kind, reviewed):
    inputs = world(kind=kind, candidates=[rule()], reviewed=reviewed)
    original = dto.HistoricalAdmissionInput(**inputs)
    repository.save_job(job())
    repository.save_candidates(job()["id"], [rule()])
    target = acquire_target(
        repository,
        job(),
        inputs["scope"].config,
        original.request.payload.baseline_reference.quality_review,
    )
    actual = builder.build_historical_target_snapshot(
        original.request, target, inputs["scope"], inputs["generation"]
    )
    expected = builder.build_historical_snapshot(original)
    assert h.canonical_json(actual.to_mapping()) == h.canonical_json(expected.to_mapping())


@pytest.mark.parametrize(
    "field", ["feature_observation_sha256", "observation_sha256", "flows", "scope"]
)
def test_forged_unreviewed_target_refused_before_selector(repository, monkeypatch, field):
    inputs = world(kind="EVALUATION", candidates=[rule()])
    request = unreviewed_request(inputs)
    repository.save_job(job())
    repository.save_candidates(job()["id"], [rule()])
    target = acquire_target(repository, job(), inputs["scope"].config)
    value = target.source
    if field in {"feature_observation_sha256", "observation_sha256"}:
        value = replace(value, **{field: "0" * 64})
    elif field == "flows":
        value = replace(value, structural=replace(value.structural, strict_flows=()))
    else:
        cfg = value.structural.scope.model_copy(update={"sensor_key": "different"})
        value = replace(value, structural=replace(value.structural, scope=cfg))
    target = replace(target, source=value)
    monkeypatch.setattr(
        ai_discovery, "select_shadow_candidates", lambda *a, **k: pytest.fail("selector reached")
    )
    with pytest.raises(ValueError, match="BASELINE_(SOURCE_INVALID|SCOPE_MISMATCH)"):
        builder.build_historical_target_snapshot(
            request, target, inputs["scope"], inputs["generation"]
        )


def test_target_wrapper_does_not_grant_source_or_approval_authority(repository):
    inputs = world(kind="EVALUATION", candidates=[rule()])
    repository.save_job(job())
    target = acquire_target(repository, job(), inputs["scope"].config)
    cfg = inputs["scope"].config
    with pytest.raises(ValueError, match="BASELINE_SCOPE_MISMATCH"):
        repository.read_historical_source(
            job()["id"], purpose="COMPARISON", scope=cfg, quality_review=None
        )
    with pytest.raises(ValueError, match="BASELINE_SCOPE_MISMATCH"):
        source.source_from_binding(target.source.structural.source, scope=cfg, quality_review=None)
    with pytest.raises(ValueError, match="BASELINE_SOURCE_INVALID"):
        source.source_build_input(
            target.source, scope=cfg, quality_review=None, source_receipt_id=None
        )
    with pytest.raises(ValueError):
        dto.HistoricalAdmissionInput(**{**inputs, "target": target.source})


@pytest.mark.parametrize("variant", ["unprofiled", "communication", "empty_reference", "partial"])
def test_unreviewed_target_preserves_actual_coverage(repository, variant):
    raw = job()
    candidate = rule()
    if variant == "unprofiled":
        for flow in raw["flow_records"]:
            if flow["direction"] == "OUTBOUND":
                flow["destination_port"] = 53
            else:
                flow["source_port"] = 53
    elif variant == "communication":
        candidate["candidate_kind"] = "COMMUNICATION_STATUS"
    elif variant == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    inputs = world(
        kind="EVALUATION",
        candidates=[candidate],
        target=raw,
        sources=0 if variant == "empty_reference" else 3,
    )
    request = unreviewed_request(inputs)
    repository.save_job(raw)
    repository.save_candidates(raw["id"], [candidate])
    target = acquire_target(repository, raw, inputs["scope"].config)
    snapshot = builder.build_historical_target_snapshot(
        request, target, inputs["scope"], inputs["generation"]
    )
    assert snapshot.baseline_summary.historical_candidate_count == 0
    decoded = decode_with_matching_commitment(
        h.canonical_json(snapshot.to_mapping()), request=request
    )
    if variant == "unprofiled":
        assert snapshot.baseline_summary.unprofiled_count == 1
        assert snapshot.baseline_comparisons == ()
        assert decoded[0].historical_reference.cause == "NO_PROFILE"
    elif variant == "communication":
        assert decoded[0].historical_reference.comparison is None
        assert decoded[0].historical_reference.source_references == ()
        assert decoded[0].historical_reference.historical_factor_types == ()
    elif variant == "empty_reference":
        assert snapshot.baseline_sources == ()
        assert snapshot.baseline_summary.generation_id is None
        assert snapshot.baseline_comparisons[0].status == "INCOMPATIBLE"
    else:
        assert "TARGET_PARTIAL_CAPTURE" in snapshot.baseline_summary.warnings
