"""Vertical repository privacy tests: real Memory/SQLite, no HTTP preflight."""

import json

import pytest

from c2hunter_controller import repositories
from c2hunter_controller.historical_ai_access import public_ai_access as public
from tests.test_historical_ai_execution import admitted


@pytest.fixture(params=["memory", "sqlite"])
def repo(request, tmp_path):
    value = (
        repositories.MemoryRepository()
        if request.param == "memory"
        else repositories.SQLiteRepository(tmp_path / "access.db")
    )
    yield value
    if request.param == "sqlite":
        value.connection.close()


def test_private_run_lookup_requires_analyst_inside_repository(repo):
    run = admitted(repo)
    with public(1), pytest.raises(ValueError, match="ANALYST 역할이 필요합니다"):
        repo.get_ai_run_by_request(run["analysis_job_id"], run["idempotency_key"])
    with public(None), pytest.raises(ValueError, match="인증이 필요합니다"):
        repo.get_ai_run(run["id"])
    with public(None, compact_runs=True):
        assert repo.get_ai_run(run["id"]) == run
    with public(2):
        assert repo.get_ai_run(run["id"]) == run
    assert repo.get_ai_run(run["id"]) == run


def test_existing_role_enum_is_accepted(repo):
    from c2hunter_controller.security import Role

    run = admitted(repo)
    with public(Role.ANALYST):
        assert repo.get_ai_run_by_request(run["analysis_job_id"], run["idempotency_key"]) == run


def completed(repo):
    from c2hunter_controller.ai_analysis import AIAnalysisService, FakeGateway

    run = admitted(repo)
    AIAnalysisService(repo, FakeGateway()).execute(run["id"])
    assessment = repo.list_ai_assessments(run["id"])[0]
    artifact = repo.list_ai_artifacts(assessment["id"])[0]
    return run, assessment, artifact


class NoPrivateCopy:
    def __deepcopy__(self, memo):
        pytest.fail("private Memory body copied before authorization")


@pytest.mark.parametrize(
    "operation", ["assessment", "assessments", "artifact", "artifacts", "feedback"]
)
def test_descendant_authorization_precedes_private_transfer(repo, operation):
    run, assessment, artifact = completed(repo)
    if isinstance(repo, repositories.MemoryRepository):
        repo.ai_assessments[assessment["id"]]["private_probe"] = NoPrivateCopy()
        repo.ai_artifacts[artifact["id"]]["private_probe"] = NoPrivateCopy()
    else:
        for table, column, value in [
            ("ai_candidate_assessments", "assessment_id", assessment),
            ("ai_generated_artifacts", "artifact_id", artifact),
        ]:
            value = {**value, "private_probe": "SENTINEL-NARRATIVE"}
            repo.connection.execute(
                f"UPDATE {table} SET data=? WHERE {column}=?", (json.dumps(value), value["id"])
            )
        repo.connection.commit()

        def check_transfer(cursor, row):
            assert not any(isinstance(v, str) and "SENTINEL-NARRATIVE" in v for v in row), (
                "private SQL body transferred"
            )
            return row

        repo.connection.row_factory = check_transfer
    operations = {
        "assessment": lambda: repo.get_ai_assessment(assessment["id"]),
        "assessments": lambda: repo.list_ai_assessments(run["id"]),
        "artifact": lambda: repo.get_ai_artifact(artifact["id"]),
        "artifacts": lambda: repo.list_ai_artifacts(assessment["id"]),
        "feedback": lambda: repo.list_ai_feedback(assessment["id"]),
    }
    with public(1, compact_runs=True), pytest.raises(ValueError, match="ANALYST 역할이 필요합니다"):
        operations[operation]()
