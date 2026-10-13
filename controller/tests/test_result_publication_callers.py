from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from publication_fixtures import publication_adapter  # noqa: F401
from test_result_publication import Delivery, seed

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository


@pytest.mark.parametrize("module", ["network_anomaly", "ddos_attack"])
def test_worker_empty_result_replaces_old_candidates_atomically(adapter: Any, module: str) -> None:
    original = seed(adapter)
    adapter.save_job({**original, "analysis": {"module": module}})
    delivery = Delivery()
    result = analyze_ddos_attack([]) if module == "ddos_attack" else {"summary": {"flow_count": 0}}
    delivery.result["result"] = {module: result}
    app = create_app(Settings(environment="test"), adapter, queue=delivery)
    assert app.state.process_results_once()
    saved = adapter.get_job("job")
    assert saved["status"] == "COMPLETED"
    assert saved["candidate_count"] == 0
    assert adapter.get_candidates("job") == []
    assert delivery.acked == ["delivery-1"]


def test_local_runtime_callback_retains_failed_delivery_for_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = SQLiteRepository(tmp_path / "local.db")
    seed(repository)
    app = create_app(
        Settings(environment="test"),
        repository,
        local_analysis_worker_health_path=tmp_path / "health.json",
    )
    runtime = app.state.local_analysis_runtime
    acks: list[str] = []
    monkeypatch.setattr(runtime.queue, "ack_result", acks.append)
    result = Delivery().result
    repository.connection.execute(
        "CREATE TEMP TRIGGER fail_result AFTER INSERT ON candidate_records "
        "BEGIN SELECT RAISE(ABORT,'local fault'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="local fault"):
        runtime.publish(result)
    assert acks == []
    assert repository.get_job("job")["status"] == "ANALYZING"
    assert repository.get_candidates("job")[0]["id"] == "old"
    repository.connection.execute("DROP TRIGGER fail_result")
    runtime.publish(result)
    app.state.wait_for_candidate_enrichment()
    assert acks == ["delivery-1"]
    repository.update_candidate("new", {"score": 10})
    saved = repository.get_candidates("job")
    runtime.publish(result)
    assert acks == ["delivery-1", "delivery-1"]
    assert repository.get_candidates("job") == saved
    assert not runtime.thread.is_alive()
    repository.close()


def test_controller_cas_loser_acks_without_enriching(
    adapter: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = seed(adapter)
    complete = adapter.complete_job_with_candidates
    calls: list[str] = []

    def cancel_then_complete(job: dict[str, Any], candidates: list[dict[str, Any]]) -> bool:
        assert adapter.transition_job_terminal({**original, "status": "CANCELLED"})
        return complete(job, candidates)

    class Intel:
        def lookup_ip(self, ip: str) -> dict[str, Any]:
            calls.append(ip)
            return {}

    monkeypatch.setattr(adapter, "complete_job_with_candidates", cancel_then_complete)
    delivery = Delivery()
    delivery.result["result"]["candidates"][0]["candidate_ip"] = "203.0.113.1"
    app = create_app(
        Settings(environment="test"), adapter, queue=delivery, threat_intel_service=Intel()
    )
    assert app.state.process_results_once()
    app.state.wait_for_candidate_enrichment()
    assert calls == []
    assert delivery.acked == ["delivery-1"]
    assert adapter.get_job("job")["status"] == "CANCELLED"
    assert adapter.get_candidates("job")[0]["id"] == "old"
