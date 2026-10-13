"""Atomic result publication through the real controller delivery path."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.queueing import MemoryControllerQueue
from c2hunter_controller.repositories import SQLiteRepository


def test_first_success_preserves_parts_and_duplicate_keeps_analyst_edit(adapter: Any) -> None:
    original = seed(adapter)
    delivery = Delivery()
    application = create_app(Settings(environment="test"), adapter, queue=delivery)
    assert application.state.process_results_once() is True
    application.state.wait_for_candidate_enrichment()
    assert adapter.get_job("job")["status"] == "COMPLETED"
    assert adapter.get_candidates("job")[0]["id"] == "new"
    assert adapter.get_job("job")["flow_records"] == original["flow_records"]
    assert adapter.get_job("job")["payload_signatures"] == original["payload_signatures"]
    adapter.update_candidate("new", {"score": 12, "excluded": True})
    saved = adapter.get_candidates("job")
    assert application.state.process_results_once() is True
    assert adapter.get_candidates("job") == saved
    assert delivery.acked == ["delivery-1", "delivery-1"]


class Delivery(MemoryControllerQueue):
    def __init__(self) -> None:
        super().__init__()
        self.acked: list[str] = []
        self.result: dict[str, Any] = {
            "receipt": "delivery-1",
            "job_id": "job",
            "status": "COMPLETED",
            "result": {"candidates": [{"id": "new", "score": 90}]},
        }

    def ready(self) -> bool:
        return True

    def claim_result(self, timeout: int = 0) -> dict[str, Any]:
        return self.result

    def ack_result(self, receipt: str) -> None:
        self.acked.append(receipt)


def seed(repository: Any) -> dict[str, Any]:
    job = {
        "id": "job",
        "idempotency_key": "key",
        "status": "ANALYZING",
        "analysis": {"module": "c2"},
        "candidate_count": 1,
        "transitions": [],
        "flow_records": [{"retained": 1}],
        "payload_signatures": [{"retained": 2}],
    }
    repository.save_job(job)
    repository.save_candidates("job", [{"id": "old", "score": 40}])
    return job


def test_result_insert_fault_never_publishes_terminal_metadata(tmp_path: Path) -> None:
    path = tmp_path / "publication.db"
    repository = SQLiteRepository(path)
    seed(repository)
    delivery = Delivery()
    application = create_app(Settings(environment="test"), repository, queue=delivery)
    repository.connection.execute(
        "CREATE TEMP TRIGGER fail_insert AFTER INSERT ON candidate_records "
        "BEGIN SELECT RAISE(ABORT, 'candidate fault'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="candidate fault"):
        application.state.process_results_once()
    # Observe committed state before touching the writer or a migrating repository.
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as reader:
        assert reader.execute(
            "SELECT json_extract(data,'$.status') FROM objects WHERE kind='job' AND id='job'"
        ).fetchone() == ("ANALYZING",)
        assert reader.execute("SELECT candidate_id FROM candidate_records").fetchall() == [("old",)]
    assert delivery.acked == []
    assert not repository.connection.in_transaction
    repository.connection.execute("DROP TRIGGER fail_insert")
    assert application.state.process_results_once() is True
    assert delivery.acked == ["delivery-1"]
    assert repository.get_job("job")["status"] == "COMPLETED"
    assert repository.get_candidates("job")[0]["id"] == "new"
    application.state.wait_for_candidate_enrichment()
