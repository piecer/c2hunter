from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.fixture(params=["memory", "sqlite"])
def repository(request: pytest.FixtureRequest, tmp_path: Path) -> Any:
    if request.param == "memory":
        return MemoryRepository()
    return SQLiteRepository(tmp_path / "retention.db")


def test_delete_job_cascades_all_ai_analysis_records(repository: Any) -> None:
    job = {"id": "job-1", "idempotency_key": "job-key"}
    run = {
        "id": "run-1",
        "analysis_job_id": "job-1",
        "idempotency_key": "run-key",
        "created_at": "2026-08-09T00:00:00+00:00",
        "status": "COMPLETED",
    }
    assessment = {
        "id": "assessment-1",
        "ai_run_id": "run-1",
        "created_at": "2026-08-09T00:01:00+00:00",
    }
    artifact = {
        "id": "artifact-1",
        "assessment_id": "assessment-1",
        "created_at": "2026-08-09T00:02:00+00:00",
    }
    feedback = {
        "id": "feedback-1",
        "assessment_id": "assessment-1",
        "created_at": "2026-08-09T00:03:00+00:00",
    }

    repository.create_job(job)
    repository.create_ai_run(run)
    repository.save_ai_assessment(assessment)
    repository.save_ai_artifact(artifact)
    repository.save_ai_feedback(feedback)

    assert repository.delete_job("job-1") is True
    assert repository.list_ai_runs("job-1") == []
    assert repository.get_ai_assessment("assessment-1") is None
    assert repository.get_ai_artifact("artifact-1") is None
    assert repository.list_ai_feedback("assessment-1") == []


def test_delete_job_refuses_active_ai_run(repository: Any) -> None:
    repository.create_job({"id": "job-active", "idempotency_key": "job-active-key"})
    repository.create_ai_run(
        {
            "id": "run-active",
            "analysis_job_id": "job-active",
            "idempotency_key": "run-active-key",
            "created_at": "2026-08-09T00:00:00+00:00",
            "status": "ANALYZING",
        }
    )

    assert repository.delete_job("job-active") is False
    assert repository.get_job("job-active") is not None
    assert repository.get_ai_run("run-active") is not None


def test_sqlite_delete_job_rolls_back_all_ai_ledgers_on_mid_transaction_failure(
    tmp_path: Path,
) -> None:
    repository = SQLiteRepository(tmp_path / "rollback.db")
    repository.create_job({"id": "job-1", "idempotency_key": "job-key"})
    repository.create_ai_run(
        {
            "id": "run-1",
            "analysis_job_id": "job-1",
            "idempotency_key": "run-key",
            "created_at": "2026-08-09T00:00:00+00:00",
            "status": "COMPLETED",
        }
    )
    repository.save_ai_assessment(
        {
            "id": "assessment-1",
            "ai_run_id": "run-1",
            "created_at": "2026-08-09T00:01:00+00:00",
        }
    )
    repository.save_ai_artifact(
        {
            "id": "artifact-1",
            "assessment_id": "assessment-1",
            "created_at": "2026-08-09T00:02:00+00:00",
        }
    )
    repository.save_ai_feedback(
        {
            "id": "feedback-1",
            "assessment_id": "assessment-1",
            "created_at": "2026-08-09T00:03:00+00:00",
        }
    )
    repository.connection.execute(
        "CREATE TRIGGER fail_artifact_delete BEFORE DELETE ON ai_generated_artifacts "
        "BEGIN SELECT RAISE(ABORT, 'forced retention failure'); END"
    )
    repository.connection.commit()

    with pytest.raises(sqlite3.IntegrityError, match="forced retention failure"):
        repository.delete_job("job-1")

    assert repository.get_job("job-1") is not None
    assert len(repository.list_ai_runs("job-1")) == 1
    assert len(repository.list_ai_assessments("run-1")) == 1
    assert len(repository.list_ai_artifacts("assessment-1")) == 1
    assert len(repository.list_ai_feedback("assessment-1")) == 1
