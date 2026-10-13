"""Actual HTTP entrypoints carry metadata-first repository privacy authority."""

import pytest

from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_http_routes import headers
from tests.test_historical_ai_access import completed
from tests.test_historical_ai_api import api
from tests.test_historical_ai_api import repo as _repo

repo = _repo


def routes(run, assessment, artifact):
    return [
        ("GET", f"/api/v1/ai-runs/{run['id']}/selection", None),
        ("GET", f"/api/v1/ai-runs/{run['id']}/assessments", None),
        ("GET", f"/api/v1/ai-assessments/{assessment['id']}", None),
        ("GET", f"/api/v1/ai-assessments/{assessment['id']}/feedback", None),
        ("GET", f"/api/v1/ai-assessments/{assessment['id']}/evidence-bundle", None),
        ("GET", f"/api/v1/ai-assessments/{assessment['id']}/artifacts", None),
        ("GET", f"/api/v1/ai-artifacts/{artifact['id']}", None),
        (
            "POST",
            f"/api/v1/ai-assessments/{assessment['id']}/feedback",
            {
                "verdict": "NEED_MORE_DATA",
                "note": "check",
                "corrected_confidence": None,
            },
        ),
        ("POST", f"/api/v1/ai-assessments/{assessment['id']}/artifacts/regenerate", None),
        ("POST", f"/api/v1/ai-artifacts/{artifact['id']}/approve", {"note": "check"}),
        ("POST", f"/api/v1/ai-artifacts/{artifact['id']}/reject", {"note": "check"}),
        ("POST", f"/api/v1/ai-runs/{run['id']}/cancel", {"reason": "stop"}),
    ]


@pytest.mark.parametrize("role", [None, "viewer"])
def test_all_historical_private_routes_deny_before_transfer(repo, role):
    run, assessment, artifact = completed(repo)
    client, _ = api(repo, auth=role is not None)

    class NoCopy:
        def __deepcopy__(self, memo):
            pytest.fail("HTTP copied private stored body before authorization")

    if isinstance(repo, MemoryRepository):
        repo.ai_assessments[assessment["id"]]["private_probe"] = NoCopy()
        repo.ai_artifacts[artifact["id"]]["private_probe"] = NoCopy()
    else:

        def no_transfer(cursor, row):
            assert not any(isinstance(v, str) and '"evidence_bundle"' in v for v in row), (
                "private transfer"
            )
            return row

        repo.connection.row_factory = no_transfer
    for method, path, body in routes(run, assessment, artifact):
        response = client.request(method, path, json=body, headers=headers(role) if role else {})
        assert response.status_code == 403, (path, response.text)
        assert response.json()["error"]["code"] == (
            "INSUFFICIENT_ROLE" if role else "BASELINE_AUTH_REQUIRED"
        )
        assert response.json()["error"]["details"] is None


@pytest.mark.parametrize("role", [None, "viewer", "analyst"])
def test_only_compact_run_views_get_public_exception(repo, role):
    run, _, _ = completed(repo)
    client, _ = api(repo, auth=role is not None)
    for path in (
        f"/api/v1/ai-runs/{run['id']}",
        f"/api/v1/analysis-jobs/{run['analysis_job_id']}/ai-runs",
    ):
        response = client.get(path, headers=headers(role) if role else {})
        assert response.status_code == 200, response.text
        value = response.json().get("items", [response.json()])[0]
        assert value["baseline_mode"] == "historical"
        assert "baseline_summary" in value
        assert "_historical_admission" not in value
        assert "candidate_snapshots" not in value


def test_analyst_reads_saved_selection_not_empty_lifecycle(repo):
    from c2hunter_controller.historical_ai_storage import materialize_historical_run

    run, _, _ = completed(repo)
    view, _ = materialize_historical_run(repo.get_ai_run(run["id"]))
    client, _ = api(repo)
    response = client.get(f"/api/v1/ai-runs/{run['id']}/selection", headers=headers("analyst"))
    assert response.status_code == 200
    assert response.json()["items"] == view["selection_inventory"]
    assert response.json()["total"] == len(view["selection_inventory"]) == 1


def test_analyst_regenerates_from_validated_saved_bundle(repo):
    run, assessment, _ = completed(repo)
    client, _ = api(repo)
    before = repo.get_ai_run(run["id"])
    response = client.post(
        f"/api/v1/ai-assessments/{assessment['id']}/artifacts/regenerate",
        headers=headers("analyst"),
    )
    assert response.status_code == 201, response.text
    assert response.json()["total"] == 3
    for artifact in response.json()["items"]:
        assert artifact["baseline_mode"] == "historical"
        assert artifact["baseline_summary"] == assessment["baseline_summary"]
        assert repo.get_ai_artifact(artifact["id"]) == artifact
    assert len(repo.list_ai_artifacts(assessment["id"])) == 6
    assert repo.get_ai_run(run["id"]) == before


@pytest.mark.parametrize("field", ["actor", "note"])
def test_artifact_same_status_checks_incoming_mutation_before_shortcut(repo, field):
    from c2hunter_controller.ai_artifacts import AIArtifactService

    _, _, artifact = completed(repo)
    service = AIArtifactService(repo)
    approved = service.review(
        artifact["id"], status="APPROVED", reviewed_by="analyst", note="checked"
    )
    with pytest.raises(ValueError) as caught:
        service.review(
            artifact["id"],
            status="APPROVED",
            reviewed_by="x" * 201 if field == "actor" else "analyst",
            note="x" * 2001 if field == "note" else "checked",
        )
    assert getattr(caught.value, "code", None) == (
        "BASELINE_STORAGE_UNAVAILABLE" if field == "actor" else "VALIDATION_ERROR"
    )
    assert repo.get_ai_artifact(artifact["id"]) == approved


def test_feedback_input_validation_precedes_new_identifier(repo, monkeypatch):
    from c2hunter_controller import ai_feedback

    _, assessment, _ = completed(repo)
    monkeypatch.setattr(ai_feedback.uuid, "uuid4", lambda: pytest.fail("UUID before validation"))
    with pytest.raises(ValueError) as caught:
        ai_feedback.AIFeedbackService(repo).append(
            assessment_id=assessment["id"],
            verdict="NEED_MORE_DATA",
            corrected_confidence=None,
            note="x" * 5001,
            created_by="analyst",
        )
    assert getattr(caught.value, "code", None) == "VALIDATION_ERROR"
    assert repo.list_ai_feedback(assessment["id"]) == []
