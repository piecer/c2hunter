from __future__ import annotations

from copy import deepcopy

import pytest

from c2hunter_controller.ai_analysis import CandidateAssessment, FakeGateway, build_evidence_bundle
from c2hunter_controller.ai_artifacts import (
    AIArtifactError,
    AIArtifactService,
    build_ai_artifacts,
    validate_misp_draft,
    validate_splunk_draft,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def candidate() -> dict[str, object]:
    return {
        "id": "candidate-1",
        "candidate_ip": "203.0.113.9",
        "score": 82,
        "protocols": ["TCP"],
        "ports": [443],
        "first_seen": "2026-08-09T00:00:00+00:00",
        "last_seen": "2026-08-09T00:05:00+00:00",
        "evidence": [
            {
                "type": "PERIODIC_BEACON",
                "description": "Stable interval",
                "metrics": {"period_seconds": 30},
            }
        ],
    }


def artifact_inputs():
    bundle = build_evidence_bundle(candidate())
    assessment = CandidateAssessment.model_validate(FakeGateway().assess(bundle))
    return assessment, bundle


def test_builds_valid_read_only_splunk_and_unpublished_misp_artifacts() -> None:
    assessment, bundle = artifact_inputs()

    artifacts = build_ai_artifacts(
        assessment_id="assessment-1",
        ai_run_id="run-1",
        analysis_job_id="job-1",
        assessment=assessment,
        bundle=bundle,
    )

    assert [artifact["artifact_type"] for artifact in artifacts] == [
        "SPLUNK_HUNT",
        "SPLUNK_DETECTION",
        "MISP_DRAFT",
    ]
    assert all(artifact["validation_status"] == "VALID" for artifact in artifacts)
    assert all(artifact["approved_status"] == "PENDING" for artifact in artifacts)
    misp = next(item for item in artifacts if item["artifact_type"] == "MISP_DRAFT")
    assert misp["content"]["Event"]["published"] is False
    assert misp["content"]["Event"]["Attribute"][0]["to_ids"] is False


@pytest.mark.parametrize(
    "command", ["delete", "collect", "outputlookup", "sendemail", "script", "run"]
)
def test_splunk_validator_rejects_write_commands(command: str) -> None:
    assessment, bundle = artifact_inputs()
    artifacts = build_ai_artifacts(
        assessment_id="assessment-1",
        ai_run_id="run-1",
        analysis_job_id="job-1",
        assessment=assessment,
        bundle=bundle,
    )
    hunt = next(item["content"] for item in artifacts if item["artifact_type"] == "SPLUNK_HUNT")
    invalid = deepcopy(hunt)
    invalid["spl"] += f" | {command}"

    with pytest.raises(AIArtifactError, match="write command"):
        validate_splunk_draft(invalid, allowed_iocs={"203.0.113.9"})


def test_splunk_validator_rejects_unknown_fields_and_unbounded_index() -> None:
    assessment, bundle = artifact_inputs()
    hunt = next(
        item["content"]
        for item in build_ai_artifacts(
            assessment_id="assessment-1",
            ai_run_id="run-1",
            analysis_job_id="job-1",
            assessment=assessment,
            bundle=bundle,
        )
        if item["artifact_type"] == "SPLUNK_HUNT"
    )
    unknown = deepcopy(hunt)
    unknown["spl"] += " | table made_up_field"
    unknown["expected_fields"] = [*unknown["expected_fields"], "made_up_field"]
    with pytest.raises(AIArtifactError, match="unknown profile field"):
        validate_splunk_draft(unknown, allowed_iocs={"203.0.113.9"})

    wildcard = deepcopy(hunt)
    wildcard["spl"] = wildcard["spl"].replace("index=c2hunter", "index=*")
    with pytest.raises(AIArtifactError, match=r"index=\*"):
        validate_splunk_draft(wildcard, allowed_iocs={"203.0.113.9"})


def test_misp_validator_rejects_publish_unknown_ioc_and_internal_ip() -> None:
    assessment, bundle = artifact_inputs()
    draft = next(
        item["content"]
        for item in build_ai_artifacts(
            assessment_id="assessment-1",
            ai_run_id="run-1",
            analysis_job_id="job-1",
            assessment=assessment,
            bundle=bundle,
        )
        if item["artifact_type"] == "MISP_DRAFT"
    )

    published = deepcopy(draft)
    published["Event"]["published"] = True
    with pytest.raises(AIArtifactError, match="published=false"):
        validate_misp_draft(published, allowed_iocs={"203.0.113.9"})

    unknown = deepcopy(draft)
    unknown["Event"]["Attribute"][0]["value"] = "198.51.100.99"
    with pytest.raises(AIArtifactError, match="supplied evidence"):
        validate_misp_draft(unknown, allowed_iocs={"203.0.113.9"})

    internal = deepcopy(draft)
    internal["Event"]["Attribute"][0]["value"] = "10.0.0.8"
    with pytest.raises(AIArtifactError, match="internal IP"):
        validate_misp_draft(internal, allowed_iocs={"10.0.0.8"})


def test_artifact_review_is_idempotent_and_terminal() -> None:
    repository = MemoryRepository()
    assessment, bundle = artifact_inputs()
    service = AIArtifactService(repository)
    artifacts = service.generate(
        assessment_id="assessment-1",
        ai_run_id="run-1",
        analysis_job_id="job-1",
        assessment=assessment,
        bundle=bundle,
    )
    artifact_id = artifacts[0]["id"]

    approved = service.review(artifact_id, status="APPROVED", reviewed_by="analyst")
    repeated = service.review(artifact_id, status="APPROVED", reviewed_by="analyst")

    assert approved == repeated
    assert approved["approved_status"] == "APPROVED"
    with pytest.raises(AIArtifactError, match="terminal"):
        service.review(artifact_id, status="REJECTED", reviewed_by="other")


def test_sqlite_persists_artifact_content_and_review_status(tmp_path) -> None:
    path = tmp_path / "artifacts.sqlite3"
    repository = SQLiteRepository(path)
    assessment, bundle = artifact_inputs()
    artifact = build_ai_artifacts(
        assessment_id="assessment-1",
        ai_run_id="run-1",
        analysis_job_id="job-1",
        assessment=assessment,
        bundle=bundle,
    )[0]
    repository.save_ai_artifact(artifact)
    AIArtifactService(repository).review(
        artifact["id"],
        status="APPROVED",
        reviewed_by="alice",
        note="reviewed offline",
    )
    repository.connection.close()

    reopened = SQLiteRepository(path)
    stored = reopened.get_ai_artifact(artifact["id"])

    assert stored is not None
    assert stored["approved_status"] == "APPROVED"
    assert stored["review_note"] == "reviewed offline"
    assert reopened.list_ai_artifacts("assessment-1")[0]["content"] == artifact["content"]
