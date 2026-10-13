"""Repository custody exercises real builders; no model or external database."""

from pathlib import Path

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import repositories
from c2hunter_controller.historical_ai_builder import (
    build_historical_snapshot,
    build_historical_target_snapshot,
)
from tests.historical_ai_fixtures import world


def test_raw_real_historical_snapshot_requires_atomic_owner() -> None:
    assert Path(repositories.__file__).resolve().is_relative_to(Path.cwd())
    snapshot = build_historical_snapshot(dto.HistoricalAdmissionInput(**world()))
    repo = repositories.MemoryRepository()
    with pytest.raises(ValueError, match="^historical admission requires atomic owner$"):
        repo.create_ai_run(snapshot.to_mapping())
    assert repo.ai_runs == {}


def test_generic_off_create_cannot_overwrite_historical_id() -> None:
    repo = repositories.MemoryRepository()
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    with pytest.raises(ValueError):
        repo.create_ai_run(
            {
                "id": run["id"],
                "analysis_job_id": "different-job",
                "idempotency_key": "off",
                "status": "QUEUED",
            }
        )
    assert repo.get_ai_run(run["id"]) == run


def prepared(repo):
    from c2hunter_controller import historical_baseline as h
    from tests.historical_ai_fixtures import START, job, rule

    inputs = world(sources=0, candidates=[rule()])
    repo.create_baseline_scope(inputs["scope"].config, "fixture-admin", START)
    repo.save_job(job())
    repo.save_candidates(job()["id"], [rule()])
    return dto.HistoricalAdmissionRequest.model_validate(inputs["request"]), inputs, h


def test_memory_atomic_admission_owns_original_bytes_and_replays() -> None:
    import hashlib
    from copy import deepcopy

    repo = repositories.MemoryRepository()
    request, inputs, h = prepared(repo)
    original_source = deepcopy(repo.get_job(request.analysis_job_id))
    expected_snapshot = h.canonical_json(
        build_historical_snapshot(dto.HistoricalAdmissionInput(**inputs)).to_mapping()
    )
    run, created = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    assert created
    owner = run["_historical_admission"]
    assert owner == {
        "version": "historical-ai-owner-v1",
        "request_canonical_json": h.canonical_json(request.to_mapping()),
        "request_byte_size": len(h.canonical_json(request.to_mapping()).encode()),
        "snapshot_canonical_json": expected_snapshot,
        "snapshot_byte_size": len(expected_snapshot.encode()),
        "expected_snapshot_sha256": hashlib.sha256(expected_snapshot.encode()).hexdigest(),
    }
    assert set(run) == {
        "id",
        "analysis_job_id",
        "idempotency_key",
        "created_at",
        "baseline_mode",
        "status",
        "progress_percent",
        "updated_at",
        "transitions",
        "_historical_admission",
    }
    assert repo.get_job(request.analysis_job_id) == original_source
    assert repo.get_ai_run(run["id"]) == run
    assert repo.get_ai_run_by_request(request.analysis_job_id, "request-1") == run
    assert repo.list_ai_runs(request.analysis_job_id) == [run]
    repo.jobs.clear()  # Replay must precede current source/head reads.
    repo._baseline_scopes.clear()
    replay, created = repo.admit_historical_ai_run(
        request, lambda *_: pytest.fail("rebuilt replay")
    )
    assert not created and replay == run
    owner["snapshot_canonical_json"] = "caller edit"
    assert repo.get_ai_run(run["id"]) == replay


def test_memory_list_cannot_replace_map_identity_with_lifecycle_id() -> None:
    repo = repositories.MemoryRepository()
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    repo.ai_runs[run["id"]]["id"] = "00000000-0000-0000-0000-000000009999"
    with pytest.raises(ValueError, match="BASELINE_STORAGE_UNAVAILABLE"):
        repo.list_ai_runs(request.analysis_job_id)


def advance(run, status, progress):
    from copy import deepcopy
    from datetime import datetime, timedelta

    result = deepcopy(run)
    stamp = (
        datetime.fromisoformat(run["updated_at"].replace("Z", "+00:00")) + timedelta(seconds=1)
    ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    result.update(status=status, progress_percent=progress, updated_at=stamp)
    result["transitions"].append({"to_status": status, "occurred_at": stamp, "reason": "test"})
    if status in {"CANCELLED", "COMPLETED", "FAILED"}:
        result["completed_at"] = stamp
    return result


def test_memory_lifecycle_keeps_owner_and_materializes_separately() -> None:
    from copy import deepcopy

    from c2hunter_controller import historical_ai_storage as custody

    repo = repositories.MemoryRepository()
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    owner = deepcopy(run["_historical_admission"])
    view, bundles = custody.materialize_historical_run(run)
    assert bundles and view["candidate_ids"]
    assert "_historical_admission" not in view
    with pytest.raises(ValueError):
        repo.save_ai_run(view)
    for status, progress in (
        ("PREPARING", 10),
        ("ANALYZING", 40),
        ("VALIDATING", 80),
        ("ANALYZING", 40),
        ("VALIDATING", 80),
        ("COMPLETED", 100),
    ):
        run = repo.save_ai_run(advance(run, status, progress))
        assert run["_historical_admission"] == owner
    assert custody.materialize_historical_run(run)[0]["status"] == "COMPLETED"
    tampered = deepcopy(run)
    tampered["_historical_admission"]["expected_snapshot_sha256"] = "0" * 64
    with pytest.raises(ValueError):
        repo.save_ai_run(tampered)  # Validate input before terminal winner.
    stale = {**run, "extra": "not permitted"}
    with pytest.raises(ValueError):
        repo.save_ai_run(stale)
    assert repo.get_ai_run(run["id"]) == run


@pytest.mark.parametrize("corruption", ["snapshot", "request"])
def test_memory_semantic_failure_persists_same_literal_owner_only(corruption) -> None:
    from copy import deepcopy
    from datetime import UTC, datetime

    from c2hunter_controller import historical_ai_storage as custody

    repo = repositories.MemoryRepository()
    request, _, _ = prepared(repo)
    run, _ = repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    original_owner = deepcopy(run["_historical_admission"])
    retained = repo._historical_admissions[run["id"]]
    if corruption == "snapshot":
        assert '"dataset_id":"dataset-3"' in retained["snapshot_canonical_json"]
        retained["snapshot_canonical_json"] = retained["snapshot_canonical_json"].replace(
            '"dataset_id":"dataset-3"', '"dataset_id":"dataset-4"'
        )
    else:
        retained["request_canonical_json"] = retained["request_canonical_json"].replace(
            "fixture-analyst", "fixture-analysx"
        )
        assert retained["snapshot_canonical_json"] == original_owner["snapshot_canonical_json"]
    corrupt = repo.get_ai_run(run["id"])
    assert custody.historical_header(corrupt) == retained
    assert retained["expected_snapshot_sha256"] == original_owner["expected_snapshot_sha256"]
    with pytest.raises(dto.HistoricalAIError, match="HISTORICAL_SNAPSHOT_INVALID"):
        custody.materialize_historical_run(corrupt)
    with pytest.raises(ValueError):
        repo.save_ai_run(advance(corrupt, "CANCELLED", 0))
    failure = custody.safe_historical_failure(corrupt, datetime(2026, 1, 1, tzinfo=UTC))
    assert failure["updated_at"] == corrupt["updated_at"]
    saved = repo.save_ai_run(failure)
    assert saved["status"] == "FAILED" and saved["progress_percent"] == 0
    assert saved["transitions"] == corrupt["transitions"] + [
        {
            "to_status": "FAILED",
            "occurred_at": corrupt["updated_at"],
            "reason": "historical snapshot rejected",
        }
    ]
    assert saved["_historical_admission"] == retained
    assert repo.save_ai_run(failure) == saved
    with pytest.raises(dto.HistoricalAIError):
        custody.materialize_historical_run(saved)
    del repo.ai_runs[saved["id"]]
    with pytest.raises(ValueError):
        repo.save_ai_run(saved)  # No resurrection through generic save.
