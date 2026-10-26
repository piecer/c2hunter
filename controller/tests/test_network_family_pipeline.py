"""Stored/public report identity and bounded AI projection; no model calls."""

import importlib.util
import json
from contextlib import closing
from pathlib import Path

from c2hunter_analysis.network_report import analyze_network_report
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.network_ai import build_network_input
from c2hunter_controller.repositories import SQLiteRepository

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "family_pipeline_fixture", ROOT / "web/tests/network_family_fixture.py"
)
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def test_real_worker_stored_get_and_ai_preserve_default_twenty():
    first = fixture._public_case("family-first", fixture.capture())
    second = fixture._public_case("family-second", fixture.capture())
    for field in ("report", "ai"):
        assert fixture.canonical(first[field]) == fixture.canonical(second[field])
    assert first["job"]["id"] != second["job"]["id"]
    assert first["job"]["network_anomaly"] == first["worker_result"]["network_anomaly"]
    assert first["public_response"]["status_code"] == 200
    assert {i["pattern"] for i in first["ai"]["issues"]} == {
        "udp_duplicate_candidates",
        "matched_resets",
    }
    assert first["ai"]["omitted_input_issues"] == 0
    assert first["ai"]["summary"]["omitted_issue_count"] == 1
    assert first["report"]["family_coverage"]["families"][-1]["omitted_groups"] == 1


def test_maximum_analyzer_does_not_claim_ai_family_preservation():
    report = analyze_network_report(
        fixture.records(fixture.capture(100, all_families=True)), max_issues=100
    )
    ai = build_network_input(report)
    assert len(report["issues"]) == 100
    assert len({i["pattern"] for i in report["issues"]}) == 6
    assert {i["pattern"] for i in ai["issues"]} == {"udp_duplicate_candidates"}
    assert ai["omitted_input_issues"] == 80
    assert [i["id"] for i in ai["issues"]] == [i["id"] for i in report["issues"][:20]]
    assert "family_coverage" not in ai
    assert len(fixture.canonical(ai).encode()) <= 24000


def test_old_saved_report_and_ai_references_are_not_reselected_on_read(tmp_path):
    legacy = json.loads((ROOT / "web/tests/fixtures/network-family-legacy.json").read_text())
    before = fixture.canonical(legacy)
    old_input = build_network_input(legacy)
    settings = Settings(
        _env_file=None,
        environment="test",
        database_url="memory://",
        redis_url="memory://",
        clickhouse_url="memory://",
        s3_endpoint="memory://",
        api_auth_required=False,
    )
    database = tmp_path / "family.sqlite3"
    with closing(SQLiteRepository(database)) as repo:
        repo.save_job(
            {
                "id": "stored-family-job",
                "status": "COMPLETED",
                "analysis": {"module": "network_anomaly"},
                "network_anomaly": legacy,
                "created_at": "2026-09-11T00:00:00Z",
            }
        )
        run = {
            "id": "stored-family-run",
            "idempotency_key": "stored-family-control",
            "analysis_job_id": "stored-family-job",
            "analysis_kind": "NETWORK_ANOMALY",
            "status": "COMPLETED",
            "created_at": "2026-09-11T00:00:00Z",
            "network_input": old_input,
            "network_interpretation": {
                "schema_version": "network-interpretation-v1",
                "kind": "MODEL_INTERPRETATION",
                "language": "en",
                "summary": "Synthetic historical reference control",
                "possible_causes": [
                    {
                        "hypothesis": "Capture duplication",
                        "issue_ids": ["pattern-20"],
                        "uncertainty": "Not verified",
                    }
                ],
                "prioritized_checks": [],
                "correlations": [],
                "limitations": [],
            },
        }
        repo.create_ai_run(run)
    with (
        closing(SQLiteRepository(database)) as repo,
        closing(TestClient(create_app(settings, repo))) as client,
    ):
        response = client.get("/api/v1/analysis-jobs/stored-family-job")
        assert response.status_code == 200, response.text
        stored = response.json()["network_anomaly"]
        assert fixture.canonical(stored) == before
        assert build_network_input(stored) == old_input
        saved = repo.get_ai_run("stored-family-run")
        assert saved["network_input"] == old_input
        assert saved["network_interpretation"] == run["network_interpretation"]
        assert stored["issues"][-1]["pattern"] == "udp_duplicate_candidates"
        assert "family_coverage" not in stored
    fresh = analyze_network_report(fixture.records(fixture.capture()))
    assert fresh["issues"][-1]["id"] == "pattern-20"
    assert fresh["issues"][-1]["pattern"] == "matched_resets"
    assert fixture.canonical(legacy) == before
