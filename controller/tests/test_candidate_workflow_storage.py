"""Candidate workflow resource persistence tests."""

from pathlib import Path

from c2hunter_controller.repositories import SQLiteRepository


def test_sqlite_candidate_workflow_resources_survive_reopen(tmp_path: Path) -> None:
    # The workflow records remain independent from detector-produced candidate JSON.
    path = tmp_path / "controller.db"
    repository = SQLiteRepository(path)
    repository.save_candidates("job-1", [{"id": "candidate-1", "candidate_ip": "203.0.113.44"}])
    repository.save_candidate_decision(
        {
            "id": "decision-1",
            "candidate_id": "candidate-1",
            "verdict": "CONFIRMED_C2",
            "created_at": "2026-08-08T00:00:00+00:00",
        }
    )
    repository.save_candidate_ti_lookup(
        {
            "id": "lookup-1",
            "candidate_id": "candidate-1",
            "fetched_at": "2026-08-08T00:01:00+00:00",
            "providers": {"virustotal": {"status": "OK"}},
        }
    )
    repository.save_candidate_misp_action(
        {
            "id": "action-1",
            "candidate_id": "candidate-1",
            "event_id": "42",
            "status": "EXPORTED",
            "created_at": "2026-08-08T00:02:00+00:00",
        }
    )
    repository.connection.close()

    reopened = SQLiteRepository(path)

    assert reopened.get_candidates("job-1") == [
        {"id": "candidate-1", "candidate_ip": "203.0.113.44"}
    ]
    assert reopened.list_candidate_decisions("candidate-1")[0]["id"] == "decision-1"
    assert reopened.list_candidate_ti_lookups("candidate-1")[0]["id"] == "lookup-1"
    assert reopened.list_candidate_misp_actions("candidate-1")[0]["id"] == "action-1"
