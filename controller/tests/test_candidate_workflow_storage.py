"""Candidate workflow resource persistence tests."""

import json
import sqlite3
import threading
from pathlib import Path

import pytest

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def _candidate(candidate_id: str, score: int = 50) -> dict[str, object]:
    # Candidate 저장 계약 테스트용 최소 detector 결과다.
    return {
        "id": candidate_id,
        "candidate_ip": f"203.0.113.{score}",
        "score": score,
        "severity": "HIGH",
    }


def test_sqlite_migrates_legacy_job_candidate_json_once(tmp_path: Path) -> None:
    # 구버전 DB의 Job별 JSON 배열을 만든 뒤 새 Repository가 후보 단위 행으로 이관하는지 검증한다.
    path = tmp_path / "legacy-candidates.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE candidates(job_id TEXT PRIMARY KEY, data TEXT NOT NULL)")
    connection.execute(
        "INSERT INTO candidates(job_id,data) VALUES(?,?)",
        ("job-1", json.dumps([_candidate("candidate-1"), _candidate("candidate-2", 80)])),
    )
    connection.commit()
    connection.close()

    repository = SQLiteRepository(path)

    assert repository.get_candidates("job-1") == [
        _candidate("candidate-1"),
        _candidate("candidate-2", 80),
    ]
    rows = repository.connection.execute(
        "SELECT candidate_id,job_id FROM candidate_records ORDER BY position"
    ).fetchall()
    assert rows == [("candidate-1", "job-1"), ("candidate-2", "job-1")]
    assert repository.connection.execute("SELECT COUNT(*) FROM candidates").fetchone() == (0,)

    # 재시작해도 중복 행이 생기지 않아야 한다.
    repository.close()
    reopened = SQLiteRepository(path)
    assert reopened.connection.execute("SELECT COUNT(*) FROM candidate_records").fetchone() == (2,)


def test_sqlite_replaces_job_candidates_in_normalized_table(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "normalized-candidates.db")
    repository.save_candidates("job-1", [_candidate("candidate-1"), _candidate("candidate-2", 80)])

    repository.save_candidates("job-1", [_candidate("candidate-2", 90)])

    assert repository.get_candidates("job-1") == [_candidate("candidate-2", 90)]
    assert repository.list_candidate_sets() == {"job-1": [_candidate("candidate-2", 90)]}
    assert repository.update_candidate("candidate-2", {"score_adjustment": -10})["score"] == 80
    assert repository.delete_candidate("candidate-2") is True
    assert repository.get_candidates("job-1") == []


@pytest.mark.parametrize("repository_kind", ["memory", "sqlite"])
def test_candidate_query_prefilters_normalized_rows(tmp_path: Path, repository_kind: str) -> None:
    repository = (
        MemoryRepository()
        if repository_kind == "memory"
        else SQLiteRepository(tmp_path / "query-candidates.db")
    )
    repository.save_candidates(
        "job-1",
        [
            _candidate("candidate-high", 90),
            {**_candidate("candidate-low", 40), "severity": "LOW"},
            {**_candidate("candidate-hidden", 95), "excluded": True},
        ],
    )

    assert repository.query_candidates(minimum_score=80) == [
        ("job-1", _candidate("candidate-high", 90))
    ]
    assert repository.query_candidates(minimum_score=80, include_suppressed=True) == [
        ("job-1", _candidate("candidate-high", 90)),
        ("job-1", {**_candidate("candidate-hidden", 95), "excluded": True}),
    ]


def test_sqlite_candidate_page_sorts_and_paginates_in_repository(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "controller.db")
    repository.save_candidates(
        "job-1",
        [
            _candidate("candidate-low", 10),
            _candidate("candidate-high", 90),
            _candidate("candidate-middle", 50),
        ],
    )

    rows, total = repository.query_candidate_page(
        minimum_score=0,
        severity=None,
        include_suppressed=False,
        sort="-score",
        page=2,
        page_size=1,
    )

    assert total == 3
    assert rows == [("job-1", _candidate("candidate-middle", 50))]


def test_sqlite_candidate_workflow_counts_use_latest_decision_and_action(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "controller.db")
    repository.save_candidates(
        "job-1",
        [_candidate("candidate-new", 90), _candidate("candidate-done", 80)],
    )
    repository.save_candidate_decision(
        {
            "id": "decision-1",
            "candidate_id": "candidate-done",
            "verdict": "CONFIRMED_C2",
            "confidence": "HIGH",
            "note": "verified",
            "created_by": "analyst",
            "created_at": "2026-08-13T00:00:00+00:00",
        }
    )
    repository.save_candidate_decision(
        {
            "id": "decision-invalid",
            "candidate_id": "candidate-new",
            "verdict": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "note": "invalid legacy timestamp",
            "created_by": "analyst",
            "created_at": "not-a-date",
        }
    )
    repository.save_candidate_decision(
        {
            "id": "decision-naive",
            "candidate_id": "candidate-new",
            "verdict": "FALSE_POSITIVE",
            "confidence": "HIGH",
            "note": "timezone missing",
            "created_by": "analyst",
            "created_at": "2026-08-14T00:00:00",
        }
    )
    repository.save_candidate_action(
        {
            "id": "action-1",
            "candidate_id": "candidate-done",
            "verdict_id": "decision-1",
            "status": "COMPLETED",
            "created_at": "2026-08-13T00:01:00+00:00",
        }
    )

    counts = repository.candidate_workflow_counts(
        minimum_score=0,
        severity=None,
        include_suppressed=False,
    )

    assert counts["needs_review"] == 1
    assert counts["action_completed"] == 1
    assert counts["done"] == 1


def test_sqlite_candidate_misp_action_claim_is_atomic(tmp_path: Path) -> None:
    repository = SQLiteRepository(tmp_path / "controller.db")
    action = {
        "id": "management:candidate-1:100:1",
        "candidate_id": "candidate-1",
        "status": "PENDING",
        "created_at": "2026-08-13T00:00:00+00:00",
    }

    assert repository.claim_candidate_misp_action(action) is True
    assert repository.claim_candidate_misp_action(action) is False
    assert repository.list_candidate_misp_actions("candidate-1") == [action]


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
