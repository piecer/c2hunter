import json
from pathlib import Path

import pytest

from c2hunter_controller.ai_analysis import AIAnalysisError, AIAnalysisService
from c2hunter_controller.app import _validated_ddos_report
from c2hunter_controller.ddos_ai import build_ddos_input
from c2hunter_controller.repositories import MemoryRepository

CASES = json.loads(
    (Path(__file__).resolve().parents[2] / "web/tests/fixtures/ddos-review-corpus.json").read_text()
)


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
@pytest.mark.parametrize("consumer", [_validated_ddos_report, build_ddos_input], ids=["API", "AI"])
def test_independent_closed_contract(case, consumer):
    if case["expected"]:
        consumer(case["report"])
    else:
        with pytest.raises(ValueError):
            consumer(case["report"])


class NoModelGateway:
    provider = "test"
    model = "never-invoked"
    prompt_name = "candidate_system"
    prompt_version = "1.1"
    calls = 0

    def ready(self):
        return True

    def interpret_ddos_cancellable(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("Model execution is not permitted")


@pytest.mark.parametrize("case", CASES, ids=lambda c: c["name"])
def test_saved_report_ai_admission(case):
    repo = MemoryRepository()
    gateway = NoModelGateway()
    repo.save_job(
        {
            "id": "ddos-job",
            "status": "COMPLETED",
            "ddos_attack": case["report"],
            "analysis": {"module": "ddos_attack"},
            "created_at": "2026-09-19T00:00:00Z",
        }
    )
    service = AIAnalysisService(repo, gateway)
    kwargs = dict(
        analysis_job_id="ddos-job",
        idempotency_key=case["name"],
        candidate_limit=5,
        created_by="operator",
        analysis_kind="DDOS_ATTACK",
        language="en",
    )
    if case["expected"]:
        run, created = service.create_run(**kwargs)
        assert created and repo.get_ai_run(run["id"])["status"] == "QUEUED"
    else:
        with pytest.raises(AIAnalysisError):
            service.create_run(**kwargs)
        assert repo.list_ai_runs("ddos-job") == []
    assert gateway.calls == 0
