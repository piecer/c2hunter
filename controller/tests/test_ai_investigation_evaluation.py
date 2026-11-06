"""Generated-only evaluator regression tests; no real model permission."""

import importlib
import json


def api():
    assert importlib.util.find_spec("c2hunter_controller.ai_investigation_evaluation"), (
        "generated evaluation implementation is missing"
    )
    return importlib.import_module("c2hunter_controller.ai_investigation_evaluation")


def test_generated_cases_deterministic_bounded_and_label_free():
    m = api()
    cases = m.generate_cases()
    assert len(cases) == 9
    assert [c.model_dump() for c in cases] == [c.model_dump() for c in m.generate_cases()]
    assert len({c.case_id for c in cases}) == 9
    for case in cases:
        assert 1 <= len(case.job["flow_records"]) <= 256
        assert case.job["id"] == case.case_id
        assert case.target_ip == "203.0.113.10"
        data = json.dumps(case.job)
        assert all(c.scenario not in data for c in cases)
        assert "expected" not in data and "label" not in data
        assert case.data_sha256 == m.digest(case.job)
    missing = cases[-1].job["flow_records"][0]
    assert "domain" not in missing and "tcp_flags" not in missing
    flood = cases[6].job["flow_records"][0]
    assert flood["tcp_ack_count"] == 0 and flood["tcp_flags_observed"] is True
    quality = cases[7].job
    assert quality["status"] == "PARTIALLY_COMPLETED"
    assert any(f.get("timestamp") == "invalid-time" for f in quality["flow_records"])


def test_actual_legacy_and_investigation_dispatch(monkeypatch):
    import httpx

    from c2hunter_controller.ai_gateway import OllamaGateway
    from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway

    m = api()
    assert hasattr(m, "evaluate_pair"), "actual two-service dispatcher missing"
    requests = []

    async def respond(request):
        body = json.loads(request.content)
        requests.append(body)
        if "Candidate evidence bundle JSON:" in body["messages"][1]["content"]:
            content = {
                "candidate": {
                    "external_ip": "203.0.113.10",
                    "verdict": "INCONCLUSIVE",
                    "confidence": 0.2,
                    "summary_ko": "불확실",
                    "summary_en": "Uncertain",
                }
            }
        else:
            observation = json.loads(body["messages"][1]["content"])["observations"][0]
            content = {
                "action": "finish",
                "verdict": "NEEDS_REVIEW",
                "support": [
                    {
                        "text": "Observed rows",
                        "evidence_ids": [observation["evidence_id"]],
                        "metric_refs": [observation["metrics"][0]["ref"]],
                    }
                ],
                "counterevidence": [],
                "uncertainty": ["No baseline"],
                "next_checks": [],
            }

        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield json.dumps(
                    {"message": {"content": json.dumps(content)}, "done_reason": "stop"}
                ).encode()

        return httpx.Response(200, stream=Stream())

    client = httpx.AsyncClient

    def scripted_client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(respond)
        return client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", scripted_client)
    legacy = OllamaGateway(base_url="http://127.0.0.1:11434", model="scripted", retries=0)
    investigation = InvestigationModelGateway.from_configured_gateway(legacy)
    case = m.generate_cases()[3]
    rows = m.evaluate_pair(case, legacy, investigation)
    assert [r["status"] for r in rows] == ["COMPLETED", "COMPLETED"]
    assert [r["arm"] for r in rows] == ["legacy", "investigation"]
    assert rows[0]["verdict"] == "INCONCLUSIVE"
    assert rows[1]["verdict"] == "NEEDS_REVIEW"
    assert rows[1]["facts"] and rows[1]["evidence"]
    assert len(requests) == 2
    assert all(r["source_unchanged"] for r in rows)
    assert all(r["data_sha256"] == case.data_sha256 for r in rows)
    assert all(c.scenario not in json.dumps(requests) for c in m.generate_cases())
    omitted = m.evaluate_pair(m.generate_cases()[-1], legacy, investigation)
    assert omitted[0]["status"] == "NOT_SELECTED"
    assert omitted[0]["verdict"] is None
    assert omitted[0]["selected_ips"] == ["203.0.113.20"]


def runtime_api():
    name = "c2hunter_controller.ai_investigation_evaluation_runtime"
    assert importlib.util.find_spec(name), "bounded real runtime is missing"
    return importlib.import_module(name)


def test_explicit_opt_in_endpoint_and_attempt_budget():
    import pytest

    r = runtime_api()
    with pytest.raises(ValueError, match="opt-in"):
        r.LocalExperiment()
    for endpoint in (
        "https://example.com",
        "http://localhost:11434",
        "http://127.0.0.1:11434/escape",
        "http://user@127.0.0.1:11434",
        "http://127.0.0.1:11434?x=y",
    ):
        with pytest.raises(ValueError, match="endpoint"):
            r.LocalExperiment(real_local_model=True, endpoint=endpoint)
    experiment = r.LocalExperiment(real_local_model=True)
    assert experiment.legacy.retries == 0
    assert experiment.legacy.temperature == experiment.investigation.temperature == 0
    assert experiment.legacy.max_output_tokens == experiment.investigation.max_output_tokens == 2048
    assert experiment.investigation.timeout_seconds == 60
    for _ in range(12):
        experiment.budget.admit()
    with pytest.raises(ValueError, match="attempt budget"):
        experiment.budget.admit()
    assert experiment.budget.attempts == 12


def test_bounded_metadata_rejects_redirect_encoding_and_overflow(monkeypatch):
    import httpx
    import pytest

    r = runtime_api()
    client = httpx.AsyncClient
    seen = []
    state = {"status": 200, "headers": {}, "chunks": [b'{"models":[]}']}

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            for chunk in state["chunks"]:
                yield chunk

    async def respond(request):
        seen.append(str(request.url))
        return httpx.Response(state["status"], headers=state["headers"], stream=Stream())

    def scripted_client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        kwargs["transport"] = httpx.MockTransport(respond)
        return client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", scripted_client)
    experiment = r.LocalExperiment(real_local_model=True)
    with pytest.raises(ValueError, match="MODEL_NOT_INSTALLED"):
        experiment.metadata()
    state.update(status=302, headers={"Location": "http://example.com/"})
    with pytest.raises(ValueError, match="HTTP_STATUS"):
        experiment.metadata()
    state.update(status=200, headers={"Content-Encoding": "gzip"})
    with pytest.raises(ValueError, match="CONTENT_ENCODING"):
        experiment.metadata()
    state.update(headers={}, chunks=[b"x" * (r.RESPONSE_LIMIT + 1)])
    with pytest.raises(ValueError, match="RESPONSE_LIMIT"):
        experiment.metadata()
    assert seen == ["http://127.0.0.1:11434/api/tags"] * 4
    assert experiment.budget.attempts == 0


def test_observed_real_gateway_failures_are_not_retried_until_good(monkeypatch):
    import httpx

    r = runtime_api()
    m = api()
    client = httpx.AsyncClient
    requests = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield (
                b'{"message":{"content":"{}"},"prompt_eval_count":12,'
                b'"eval_count":3,"done_reason":"stop"}'
            )

    async def respond(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, stream=Stream())

    def scripted_client(**kwargs):
        assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        kwargs["transport"] = httpx.MockTransport(respond)
        return client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", scripted_client)
    experiment = r.LocalExperiment(real_local_model=True)
    rows = m.evaluate_pair(m.generate_cases()[3], experiment.legacy, experiment.investigation)
    assert rows[0]["status"] == "FAILED"
    assert rows[1]["status"] == "PARTIAL"
    assert len(requests) == experiment.budget.attempts == 4
    assert len(experiment.legacy_trace.calls) == len(experiment.investigation_trace.calls) == 2
    assert experiment.legacy_trace.calls[0]["input_tokens"] == 12
    assert experiment.investigation_trace.calls[0]["output_tokens"] == 3
    assert experiment.legacy_trace.calls[1]["repair_requested"] is True
    assert experiment.investigation_trace.calls[1]["repair_requested"] is True


def outcome(case, arm="legacy", **updates):
    row = dict(
        case_id=case.case_id,
        scenario=case.scenario,
        expected=case.expected,
        arm=arm,
        data_sha256=case.data_sha256,
        stored_source_sha256="a" * 64,
        target_ip=case.target_ip,
        status="COMPLETED",
        verdict="INCONCLUSIVE",
        reason=None,
        selected_ips=[case.target_ip],
        source_unchanged=True,
        facts=[],
        interpretation=None,
        evidence=[],
        steps=[],
        elapsed_seconds=1.0,
    )
    row.update(updates)
    return row


def test_metrics_keep_omission_failure_abstention_and_unknown_cost_separate():
    m = api()
    assert hasattr(m, "build_report"), "truthful matrix report missing"
    cases = m.generate_cases()[:3]
    rows = [outcome(c, a) for c in cases for a in ("legacy", "investigation")]
    rows[0].update(status="NOT_SELECTED", verdict=None, selected_ips=[])
    rows[2].update(status="FAILED", verdict=None, reason="MODEL_OUTPUT_INVALID")
    rows[4].update(verdict="LIKELY_C2")
    report = m.build_report(cases, rows)
    metrics = report["metrics"]["legacy"]
    assert metrics["omissions"] == 1 and metrics["failures"] == 1
    assert metrics["assessed"] == 1 and metrics["false_positives"] == 1
    assert metrics["on_assessed_binary_proxy_accuracy"] == 0
    assert report["metrics"]["investigation"]["model_abstentions"] == 3
    assert report["metrics"]["investigation"]["on_assessed_binary_proxy_accuracy"] is None
    assert report["metrics"]["legacy"]["input_tokens"] is None
    assert report["metrics"]["legacy"]["cost_usd"] is None
    assert report["complete"] is True and report["expected_rows"] == 6


def test_exact_matrix_rejects_duplicate_missing_foreign_and_tampered_rows():
    import pytest

    m = api()
    assert hasattr(m, "build_report"), "matrix validation missing"
    case = m.generate_cases()[0]
    row = outcome(case, status="FAILED", verdict=None, reason="MODEL_TIMEOUT")
    with pytest.raises(ValueError):
        m.build_report((case,), [row])
    with pytest.raises(ValueError):
        m.build_report((case,), [row, row])
    second = {**row, "arm": "investigation"}
    for change in (
        {"case_id": "foreign"},
        {"data_sha256": "b" * 64},
        {"expected": "POSITIVE"},
        {"source_unchanged": False},
        {"status": "UNKNOWN"},
        {"verdict": "LIKELY_BENIGN"},
        {"elapsed_seconds": float("nan")},
    ):
        with pytest.raises(ValueError):
            m.build_report((case,), [row, {**second, **change}])
    good = m.build_report((case,), [row, second])
    assert json.loads(m.serialize_report(good))["complete"] is True
    with pytest.raises(ValueError, match="report limit"):
        m.serialize_report({"oversize": "x" * (m.REPORT_LIMIT + 1)})


def test_citation_existence_is_not_semantic_prose_verification():
    m = api()
    assert hasattr(m, "audit_output"), "bounded output audit missing"
    evidence = {"evidence_id": "a" * 64, "metrics": [{"ref": "a" * 64 + ":rows", "value": 2}]}
    content = dict(
        action="finish",
        verdict="NEEDS_REVIEW",
        support=[
            dict(text="Unverified prose", evidence_ids=["a" * 64], metric_refs=["a" * 64 + ":rows"])
        ],
        counterevidence=[],
        uncertainty=["No baseline"],
        next_checks=[],
    )
    valid = m.audit_output("investigation", json.dumps(content), [evidence])
    assert valid["schema_valid"] is True
    assert valid["citation_count"] == 1 and valid["invalid_citations"] == 0
    assert valid["typed_ref_count"] == 1 and valid["invalid_typed_refs"] == 0
    assert valid["semantic_prose_verified"] is None
    content["support"][0]["evidence_ids"] = ["b" * 64]
    content["support"][0]["metric_refs"] = ["b" * 64 + ":invented"]
    invalid = m.audit_output("investigation", json.dumps(content), [evidence])
    assert invalid["invalid_citations"] == invalid["invalid_typed_refs"] == 1
    assert m.audit_output("investigation", "{}", [evidence])["schema_valid"] is False
    assert m.audit_output("legacy", "not json", [])["json_valid"] is False
    assert m.audit_output("investigation", None, [])["schema_valid"] is None


def test_offline_cli_never_constructs_real_runtime(tmp_path, monkeypatch):
    m = api()
    r = runtime_api()
    assert hasattr(m, "main"), "working opt-in CLI missing"

    def forbidden(**kwargs):
        raise AssertionError("offline CLI constructed a real runtime")

    monkeypatch.setattr(r, "LocalExperiment", forbidden)
    output = tmp_path / "offline"
    assert m.main(["--output", str(output)]) == 0
    report = json.loads((output / "report.json").read_text())
    assert report["execution"] == "OFFLINE_NOT_EXECUTED"
    assert report["complete"] is False and report["expected_rows"] == 18
    assert report["rows"] == []
    assert len(json.loads((output / "generated-cases.json").read_text())) == 9
    assert "not real-traffic accuracy" in (output / "report.md").read_text()
    assert (output / "source-manifest.json").exists()


def test_cli_one_pair_with_actual_paths_and_metadata_binding(tmp_path, monkeypatch):
    import httpx

    m = api()
    assert hasattr(m, "main"), "working opt-in CLI missing"
    client = httpx.AsyncClient
    paths = []

    class Stream(httpx.AsyncByteStream):
        def __init__(self, raw):
            self.raw = raw

        async def __aiter__(self):
            yield json.dumps(self.raw).encode()

    async def respond(request):
        paths.append(request.url.path)
        if request.url.path == "/api/tags":
            raw = {
                "models": [
                    {
                        "name": "llama3.1:8b",
                        "digest": m.PILOT_DIGEST,
                        "size": 1,
                        "modified_at": "2026-01-01T00:00:00Z",
                    }
                ]
            }
        elif request.url.path == "/api/ps":
            raw = {"models": []}
        else:
            raw = {"message": {"content": "{}"}, "done_reason": "stop"}
        return httpx.Response(200, stream=Stream(raw))

    def scripted_client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(respond)
        return client(**kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", scripted_client)
    output = tmp_path / "smoke"
    assert m.main(["--output", str(output), "--real-local-model"]) == 0
    report = json.loads((output / "report.json").read_text())
    assert report["expected_rows"] == 2 and report["complete"] is True
    assert report["metadata"]["comparison_valid"] is True
    assert report["metadata"]["order"] == ["legacy", "investigation"]
    assert report["metadata"]["model_before"]["tag"]["digest"] == m.PILOT_DIGEST
    assert report["metrics"]["legacy"]["invalid_output_count"] == 2
    assert report["metrics"]["investigation"]["invalid_output_count"] == 2
    assert report["metrics"]["legacy"]["cost_usd"] is None
    assert report["rows"][1]["typed_facts_verified"] is True
    assert report["rows"][1]["typed_fact_mismatches"] == 0
    assert paths == ["/api/tags", "/api/ps"] + ["/api/chat"] * 4 + ["/api/tags", "/api/ps"]
    assert json.loads((output / "admission.json").read_text())["inference_started"] is False
    assert "hidden" not in json.dumps(report["rows"])


def test_invalid_source_is_a_real_outcome_not_a_missing_matrix_row(monkeypatch):
    from c2hunter_controller.ai_gateway import OllamaGateway
    from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway

    m = api()
    legacy = OllamaGateway(base_url="http://127.0.0.1:1", model="unused")
    monkeypatch.setattr(legacy, "_request_completion", lambda *args: {"message": {"content": "{}"}})
    investigation = InvestigationModelGateway.from_configured_gateway(legacy)
    case = m.generate_cases()[7]
    rows = m.evaluate_pair(case, legacy, investigation)
    assert rows[1]["status"] == "FAILED" and rows[1]["reason"] == "SOURCE_INVALID"
    assert rows[1]["stored_source_sha256"] is None
    assert m.build_report((case,), rows)["complete"] is True


def test_unresolved_service_state_is_reported_without_fabricated_completion(monkeypatch):
    from c2hunter_controller.ai_gateway import OllamaGateway
    from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway

    m = api()
    legacy = OllamaGateway(base_url="http://127.0.0.1:1", model="unused")
    monkeypatch.setattr(legacy, "_request_completion", lambda *args: {"message": {"content": "{}"}})

    def fault(*args, **kwargs):
        raise RuntimeError("synthetic callback fault")

    monkeypatch.setattr(InvestigationModelGateway, "complete", fault)
    case = m.generate_cases()[3]
    rows = m.evaluate_pair(case, legacy, InvestigationModelGateway.from_configured_gateway(legacy))
    assert rows[1]["status"] == "EXECUTION_UNRESOLVED"
    assert rows[1]["reason"] == "INTERNAL_ERROR"
    assert rows[1]["stored_status"] == "INVESTIGATING"
    assert m.build_report((case,), rows)["metrics"]["investigation"]["failures"] == 1


def test_generic_question_matches_legacy_fixed_task():
    from c2hunter_controller.ai_gateway import SYSTEM_PROMPT

    assert api().QUESTION in SYSTEM_PROMPT


def test_all_generated_scenarios_readable_and_legacy_selection_is_real():
    from c2hunter_controller.ai_analysis import AIAnalysisError, AIAnalysisService
    from c2hunter_controller.ai_gateway import OllamaGateway
    from c2hunter_controller.repositories import MemoryRepository

    m = api()
    for case in m.generate_cases():
        repo = MemoryRepository()
        try:
            repo.save_job(case.job)
            if case.scenario == "partial_or_bad_time_quality":
                import pytest

                from c2hunter_controller.ai_investigation_contract import InvestigationError

                with pytest.raises(InvestigationError, match="SOURCE_INVALID"):
                    repo.read_investigation_source(case.case_id)
            else:
                snapshot = repo.read_investigation_source(case.case_id)
                assert len(snapshot.rows) == len(case.job["flow_records"])
                assert snapshot.binding.source_sha256
            service = AIAnalysisService(
                repo, OllamaGateway(base_url="http://127.0.0.1:1", model="unused")
            )
            try:
                run, _ = service.create_run(
                    analysis_job_id=case.case_id,
                    idempotency_key="test",
                    candidate_limit=1,
                    created_by="test",
                )
            except AIAnalysisError as exc:
                assert str(exc) == "analysis job has no candidates"
                assert case.scenario == "syn_flood_only"
            else:
                assert run["candidate_snapshots"]
                if case.scenario == "jitter_beacon":
                    assert run["candidate_snapshots"][0]["candidate_ip"] == case.target_ip
                if case.scenario == "observed_nonshortlisted_peer":
                    assert case.target_ip not in [
                        c["candidate_ip"] for c in run["candidate_snapshots"]
                    ]
            assert m.digest(repo.get_job(case.case_id)) == case.data_sha256
        finally:
            repo.close()
