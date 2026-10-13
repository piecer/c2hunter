"""Native metadata classification; no DTO/JSON-body authorization fallback."""

import json
from copy import deepcopy

import pytest

from c2hunter_controller import repositories
from c2hunter_controller.historical_ai_access import HistoricalAccessDenied, public_ai_access
from c2hunter_controller.historical_ai_storage import HistoricalStorageError
from tests.test_historical_ai_access import completed
from tests.test_historical_ai_access import repo as _repository_fixture
from tests.test_historical_ai_execution import admitted

repo = _repository_fixture


def inject(repo, kind, value, text=None):
    names = {
        "R": ("ai_runs", "ai_analysis_runs", "run_id", "analysis_job_id"),
        "A": ("ai_assessments", "ai_candidate_assessments", "assessment_id", "ai_run_id"),
        "T": ("ai_artifacts", "ai_generated_artifacts", "artifact_id", "assessment_id"),
        "F": ("ai_feedback", "ai_feedback", "feedback_id", "assessment_id"),
    }
    attr, table, pk, parent = names[kind]
    if isinstance(repo, repositories.MemoryRepository):
        getattr(repo, attr)[value["id"]] = deepcopy(value)
    else:
        cols = f"{pk},{parent},created_at,data"
        params = (
            value["id"],
            value.get(parent, "missing"),
            value["created_at"],
            text or json.dumps(value),
        )
        if kind == "R":
            cols += ",idempotency_key"
            params += (value.get("idempotency_key", "fixture"),)
        repo.connection.execute(
            f"INSERT OR REPLACE INTO {table}({cols}) VALUES({','.join('?' for _ in params)})",
            params,
        )
        repo.connection.commit()


@pytest.mark.parametrize(
    "marker",
    [
        {"baseline_mode": "historical"},
        {"baseline_summary": {"mode": "historical", "scope_kind": "EVALUATION"}},
        {"evidence_bundle": {"historical_reference": {}}},
    ],
)
def test_historical_orphan_denied_before_missing_owner(repo, marker):
    row = {"id": "orphan", "created_at": "2026-01-01", "ai_run_id": "missing", **marker}
    inject(repo, "A", row)
    with public_ai_access(None), pytest.raises(HistoricalAccessDenied) as caught:
        repo.get_ai_assessment("orphan")
    assert caught.value.code == "BASELINE_AUTH_REQUIRED"
    with public_ai_access(2), pytest.raises(HistoricalStorageError):
        repo.get_ai_assessment("orphan")


@pytest.mark.parametrize(
    "marker",
    [
        {"baseline_mode": None},
        {"baseline_mode": "unknown"},
        {"evidence_bundle": None},
        {"evidence_bundle": {"historical_reference": []}},
        {"baseline_mode": "off", "baseline_sources": []},
    ],
)
def test_malformed_or_contradictory_marker_is_not_auth_or_absence(repo, marker):
    row = {"id": "orphan", "created_at": "2026-01-01", "ai_run_id": "missing", **marker}
    inject(repo, "A", row)
    with public_ai_access(None), pytest.raises(HistoricalStorageError):
        repo.get_ai_assessment("orphan")


def test_off_orphans_and_null_reference_keep_legacy(repo):
    row = {
        "id": "orphan",
        "assessment_id": "gone",
        "created_at": "2026-01-01",
        "artifact_type": "SPLUNK_QUERY",
        "evidence_bundle": {"historical_reference": None},
        "candidate_snapshots": [{"x": "historical"}],
    }
    inject(repo, "T", row)
    with public_ai_access(None):
        assert repo.get_ai_artifact("orphan") == row
        assert repo.list_ai_artifacts("gone") == [row]
        assert repo.list_ai_feedback("gone") == []


@pytest.mark.parametrize("container", ["candidate_snapshots", "selection_inventory"])
def test_run_nested_reference_is_marker_not_container_existence(repo, container):
    row = {
        "id": "legacy",
        "analysis_job_id": "gone",
        "idempotency_key": "legacy",
        "created_at": "2026-01-01",
        container: [{"historical_reference": None}],
    }
    inject(repo, "R", row)
    with public_ai_access(None):
        assert repo.get_ai_run("legacy") == row
    row[container][0]["historical_reference"] = {}
    inject(repo, "R", row)
    with public_ai_access(None), pytest.raises(HistoricalAccessDenied):
        repo.get_ai_run("legacy")


def test_compact_flag_cannot_grant_mutation_or_private_lookup(repo):
    run = admitted(repo)
    with public_ai_access(1, compact_runs=True), pytest.raises(HistoricalAccessDenied):
        repo.save_ai_run(run)
    with public_ai_access(1, compact_runs=True), pytest.raises(HistoricalAccessDenied):
        repo.get_ai_run_by_request(run["analysis_job_id"], run["idempotency_key"])


def test_off_create_collision_does_not_bypass_historical_authority(repo):
    run = admitted(repo)
    proposed = {
        "id": "off-id",
        "analysis_job_id": run["analysis_job_id"],
        "idempotency_key": run["idempotency_key"],
        "created_at": run["created_at"],
        "status": "QUEUED",
    }
    with public_ai_access(None, compact_runs=True), pytest.raises(HistoricalAccessDenied):
        repo.create_ai_run(proposed)
    assert repo.get_ai_run(run["id"]) == run


def test_direct_admission_requires_analyst_even_with_compact_flag(repo):
    from c2hunter_controller.historical_ai_builder import build_historical_target_snapshot
    from tests.test_historical_ai_storage import prepared

    request, _, _ = prepared(repo)
    with public_ai_access(None, compact_runs=True), pytest.raises(HistoricalAccessDenied):
        repo.admit_historical_ai_run(request, build_historical_target_snapshot)
    assert repo.list_ai_runs(request.analysis_job_id) == []


def test_relation_contradiction_is_storage_error_before_private_transfer(repo):
    run, assessment, artifact = completed(repo)
    if isinstance(repo, repositories.MemoryRepository):
        repo.ai_artifacts[artifact["id"]]["analysis_job_id"] = "different-job"
    else:
        repo.connection.execute(
            "UPDATE ai_generated_artifacts "
            "SET data=json_set(data,'$.analysis_job_id','different-job') WHERE artifact_id=?",
            (artifact["id"],),
        )
        repo.connection.commit()
    with public_ai_access(None), pytest.raises(HistoricalStorageError):
        repo.get_ai_artifact(artifact["id"])


@pytest.mark.parametrize("kind", ["R", "A"])
def test_sqlite_list_does_not_transfer_unbounded_historical_identity(tmp_path, kind):
    repository = repositories.SQLiteRepository(tmp_path / "identity-transfer.db")
    try:
        raw = {
            "id": "x" * 5000,
            "created_at": "2026-01-01T00:00:00Z",
            "baseline_mode": "historical",
            "analysis_job_id": "missing",
            "ai_run_id": "missing",
            "idempotency_key": "orphan",
        }
        inject(repository, kind, raw)

        def bounded_metadata(cursor, row):
            assert not any(type(value) is str and raw["id"] in value for value in row), (
                "unbounded ID transfer"
            )
            return row

        repository.connection.row_factory = bounded_metadata
        with public_ai_access(None), pytest.raises(HistoricalAccessDenied):
            if kind == "R":
                repository.list_ai_runs("missing")
            else:
                repository.list_ai_assessments("missing")
    finally:
        repository.connection.close()


def test_sqlite_descendant_created_at_keeps_relational_identity(tmp_path):
    repository = repositories.SQLiteRepository(tmp_path / "identity.db")
    try:
        _, assessment, _ = completed(repository)
        repository.connection.execute(
            "UPDATE ai_candidate_assessments "
            "SET data=json_set(data,'$.created_at','2026-01-08T00:00:00+00:00') "
            "WHERE assessment_id=?",
            (assessment["id"],),
        )
        repository.connection.commit()
        with public_ai_access(2), pytest.raises(HistoricalStorageError):
            repository.get_ai_assessment(assessment["id"])
    finally:
        repository.connection.close()


def test_sqlite_authorized_private_decoder_failure_is_storage_error(tmp_path):
    repository = repositories.SQLiteRepository(tmp_path / "private-duplicate.db")
    try:
        _, assessment, _ = completed(repository)
        text = json.dumps(assessment)[:-1] + ',"assessment":{}}'
        repository.connection.execute(
            "UPDATE ai_candidate_assessments SET data=? WHERE assessment_id=?",
            (text, assessment["id"]),
        )
        repository.connection.commit()
        with public_ai_access(2), pytest.raises(HistoricalStorageError):
            repository.get_ai_assessment(assessment["id"])
    finally:
        repository.connection.close()


def test_duplicate_relevant_decoded_sqlite_key_fails_before_transfer(tmp_path):
    repo = repositories.SQLiteRepository(tmp_path / "duplicate.db")
    try:
        row = {"id": "orphan", "ai_run_id": "missing", "created_at": "2026-01-01"}
        text = json.dumps(row)[:-1] + ',"baseline_mode":"off","baseline_\\u006dode":"historical"}'
        inject(repo, "A", row, text)
        with public_ai_access(None), pytest.raises(HistoricalStorageError):
            repo.get_ai_assessment("orphan")
    finally:
        repo.connection.close()
