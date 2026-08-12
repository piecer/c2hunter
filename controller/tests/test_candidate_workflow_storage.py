"""Candidate workflow resource persistence tests."""

import threading
from pathlib import Path

import pytest

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_candidate_ti_lookup_supports_concurrent_reads_and_writes(
    tmp_path: Path, repository_kind: str
) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "concurrent.db")
    )
    errors: list[Exception] = []
    start = threading.Barrier(2)

    def write_lookups() -> None:
        try:
            start.wait()
            for index in range(100):
                repository.save_candidate_ti_lookup(
                    {
                        "id": f"lookup-{index}",
                        "candidate_id": "candidate-1",
                        "fetched_at": f"2026-08-08T00:00:{index:02d}+00:00",
                        "providers": {},
                    }
                )
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    def read_lookups() -> None:
        try:
            start.wait()
            for _ in range(100):
                repository.list_candidate_ti_lookups("candidate-1")
        except Exception as exc:  # pragma: no cover - asserted below
            errors.append(exc)

    writer = threading.Thread(target=write_lookups)
    reader = threading.Thread(target=read_lookups)
    writer.start()
    reader.start()
    writer.join()
    reader.join()

    assert errors == []
    assert len(repository.list_candidate_ti_lookups("candidate-1")) == 100


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
    repository.save_candidate_action(
        {
            "id": "response-1",
            "candidate_id": "candidate-1",
            "verdict_id": "decision-1",
            "status": "COMPLETED",
            "note": "isolated",
            "created_at": "2026-08-08T00:03:00+00:00",
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
    assert reopened.list_candidate_actions("candidate-1")[0]["id"] == "response-1"
