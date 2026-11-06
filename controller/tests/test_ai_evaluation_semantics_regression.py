"""Reviewer-owned offline regressions; no product source edits or model requests."""

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from c2hunter_controller import ai_investigation_evaluation as m
from c2hunter_controller.ai_investigation_evaluation_runtime import LocalExperiment

R = Path(__file__).resolve().parents[1]


@pytest.fixture
def mock_provider(monkeypatch):
    requests = []
    client = httpx.AsyncClient

    class Stream(httpx.AsyncByteStream):
        def __init__(self, raw):
            self.raw = raw

        async def __aiter__(self):
            yield json.dumps(self.raw).encode()

    async def respond(request):
        assert request.url.path == "/api/chat", "No metadata calls in reviewer probes"
        body = json.loads(request.content)
        requests.append(body)
        if "Candidate evidence bundle JSON:" in body["messages"][1]["content"]:
            bundle = json.loads(body["messages"][1]["content"].split("\n", 1)[1])
            content = {
                "candidate": {
                    "external_ip": bundle["candidate"]["external_ip"],
                    "verdict": "INCONCLUSIVE",
                    "confidence": 0.2,
                    "summary_ko": "불확실",
                    "summary_en": "Uncertain",
                }
            }
        else:
            e = json.loads(body["messages"][1]["content"])["observations"][0]
            content = {
                "action": "finish",
                "verdict": "NEEDS_REVIEW",
                "support": [
                    {
                        "text": "Observed rows",
                        "evidence_ids": [e["evidence_id"]],
                        "metric_refs": [e["metrics"][0]["ref"]],
                    }
                ],
                "counterevidence": [],
                "uncertainty": ["No baseline"],
                "next_checks": [],
            }
        return httpx.Response(
            200,
            stream=Stream(
                {
                    "message": {"content": json.dumps(content)},
                    "done_reason": "stop",
                    "prompt_eval_count": 10,
                    "eval_count": 5,
                }
            ),
        )

    def scripted(**kwargs):
        kwargs["transport"] = httpx.MockTransport(respond)
        return client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", scripted)
    return requests


def rows_for(case, model="offline-A", temperature=0):
    e = LocalExperiment(real_local_model=True, model=model)
    e.legacy.temperature = temperature
    e.investigation = replace(e.investigation, temperature=temperature)
    rows = m.evaluate_pair(case, e.legacy, e.investigation)
    m.collect_telemetry(rows, e)
    assert all(r["status"] == "COMPLETED" for r in rows)
    return rows


@pytest.mark.parametrize("kind", ["model", "configuration"])
def test_mixed_real_arm_provenance_must_not_aggregate_as_valid(mock_provider, kind):
    cases = m.generate_cases()[:2]
    first = rows_for(cases[0])
    second = rows_for(
        cases[1],
        model="offline-B" if kind == "model" else "offline-A",
        temperature=1 if kind == "configuration" else 0,
    )
    metadata = {"comparison_valid": True, "config": {"model": "offline-A", "temperature": 0}}
    metadata["config_sha256"] = m.digest(metadata["config"])
    metadata["source_sha256"] = m.digest(m.source_manifest())
    # Actual persisted execution identities differ, not arbitrary invented row fields.
    identities = [
        r["interpretation"].get("execution") for r in first + second if r["arm"] == "investigation"
    ]
    assert identities[0] != identities[1]
    try:
        report = m.build_report(cases, first + second, metadata=metadata)
    except ValueError:
        return
    (R / "evidence" / f"accepted-mixed-{kind}.json").write_text(m.serialize_report(report))
    pytest.fail(f"Accepted mixed {kind} identities with complete=true and comparison_valid=true")


def test_reused_experiment_must_keep_per_case_trace_isolated(mock_provider):
    e = LocalExperiment(real_local_model=True, model="offline-A")
    cases = m.generate_cases()[:2]
    first = m.evaluate_pair(cases[0], e.legacy, e.investigation)
    m.collect_telemetry(first, e)
    before = deepcopy(first)
    second = m.evaluate_pair(cases[1], e.legacy, e.investigation)
    m.collect_telemetry(second, e)
    report = m.build_report(cases, first + second)
    observations = {
        "requests": len(mock_provider),
        "before_call_lengths": [len(r["calls"]) for r in before],
        "after_call_lengths": [len(r["calls"]) for r in first + second],
        "reported_attempts": {a: x["http_attempts"] for a, x in report["metrics"].items()},
        "audit_lengths": [len(r["output_audits"]) for r in first + second],
    }
    (R / "evidence/reused-trace.json").write_text(json.dumps(observations, indent=2) + "\n")
    assert first == before, f"Earlier case telemetry mutated: {observations}"
    assert all(len(r["calls"]) == 1 for r in first + second)


def minimal(case, arm):
    return dict(
        case_id=case.case_id,
        scenario=case.scenario,
        expected=case.expected,
        arm=arm,
        target_ip=case.target_ip,
        data_sha256=case.data_sha256,
        stored_source_sha256="a" * 64,
        status="COMPLETED",
        verdict="INCONCLUSIVE",
        reason=None,
        selected_ips=[case.target_ip],
        source_unchanged=True,
        facts=[],
        interpretation=None,
        evidence=[],
        steps=[],
        elapsed_seconds=0.0,
    )


def test_pair_mismatched_stored_source_digest_must_reject():
    c = m.generate_cases()[0]
    rows = [minimal(c, a) for a in ("legacy", "investigation")]
    rows[1]["stored_source_sha256"] = "b" * 64
    with pytest.raises(ValueError):
        m.build_report((c,), rows)


def test_exact_full_matrix_structure_and_failure_retention():
    cases = m.generate_cases()
    rows = [minimal(c, a) for c in cases for a in ("legacy", "investigation")]
    rows[0].update(status="NOT_SELECTED", verdict=None, selected_ips=[])
    rows[1].update(status="PARTIAL", verdict="INCONCLUSIVE", reason="MODEL_INVALID")
    rows[-1].update(status="FAILED", verdict=None, reason="SOURCE_INVALID")
    report = m.build_report(cases, rows)
    assert report["complete"] and report["expected_rows"] == 18
    assert report["metrics"]["legacy"]["omissions"] == 1
    assert report["metrics"]["investigation"]["partial"] == 1
    assert report["metrics"]["investigation"]["failures"] == 1
    for badcases, badrows in [
        (cases, rows[:-1]),
        (cases, rows + [rows[0]]),
        (cases + (cases[0],), rows),
        (cases, [{**rows[0], "case_id": "foreign"}, *rows[1:]]),
        (cases, [{**rows[0], "data_sha256": "b" * 64}, *rows[1:]]),
    ]:
        with pytest.raises(ValueError):
            m.build_report(badcases, badrows)


def test_actual_selection_characterization_top_one_is_not_top_five_proof():
    from c2hunter_controller.ai_analysis import AIAnalysisService, _prefilter_candidate_dicts
    from c2hunter_controller.ai_gateway import SYSTEM_PROMPT, OllamaGateway
    from c2hunter_controller.repositories import MemoryRepository

    case = m.generate_cases()[-1]
    repo = MemoryRepository()
    try:
        repo.save_job(deepcopy(case.job))
        assert repo.get_candidates(case.case_id) == []
        candidates = _prefilter_candidate_dicts(case.job)
        service = AIAnalysisService(
            repo, OllamaGateway(base_url="http://127.0.0.1:1", model="unused")
        )
        selected = {}
        for limit in (1, 5):
            run, _ = service.create_run(
                analysis_job_id=case.case_id,
                idempotency_key=str(limit),
                candidate_limit=limit,
                created_by="review",
                discovery_mode="legacy",
            )
            selected[str(limit)] = [c["candidate_ip"] for c in run["candidate_snapshots"]]
        obs = {
            "prefilter_ips": [c["candidate_ip"] for c in candidates],
            "selected": selected,
            "target_rows": sum(
                r["destination_ip"] == case.target_ip for r in case.job["flow_records"]
            ),
            "total_rows": len(case.job["flow_records"]),
        }
        (R / "evidence/selection.json").write_text(json.dumps(obs, indent=2) + "\n")
        assert m.QUESTION in SYSTEM_PROMPT
        assert obs["target_rows"] == 1 and obs["total_rows"] == 25
        assert len(candidates) < 6
        assert case.target_ip not in selected["1"]
        assert m.digest(repo.get_job(case.case_id)) == case.data_sha256
        assert repo.get_candidates(case.case_id) == []
    finally:
        repo.close()


@pytest.fixture(autouse=True)
def owned_artifacts(tmp_path, monkeypatch):
    import sys

    (tmp_path / "evidence").mkdir(exist_ok=True)
    monkeypatch.setattr(sys.modules[__name__], "R", tmp_path)
