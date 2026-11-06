"""Actual services, mocked HTTP only: matrix and boundary regressions."""

import json
from dataclasses import replace

import httpx
import pytest

from c2hunter_controller import ai_investigation_evaluation as ev
from c2hunter_controller import ai_investigation_evaluation_runtime as rt


class Wire(httpx.AsyncByteStream):
    def __init__(self, value):
        self.raw = json.dumps(value).encode()

    async def __aiter__(self):
        yield self.raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("modified_at", {"x": {}}),
        ("modified_at", "x" * 513),
        ("modified_at", True),
        ("modified_at", float("inf")),
        ("size", {}),
        ("size", True),
        ("size", -1),
        ("size", 2**63),
        ("size", float("nan")),
        ("size", "4900000000"),
    ],
)
def test_metadata_rejects_invalid_optional_scalars(monkeypatch, field, value):
    tag = {"name": rt.MODEL, "digest": ev.PILOT_DIGEST, field: value}
    monkeypatch.setattr(
        httpx,
        "AsyncHTTPTransport",
        lambda **kw: httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Wire({"models": [tag]}))
        ),
    )
    with pytest.raises(ValueError, match="INVALID_TAG_METADATA"):
        rt.LocalExperiment(real_local_model=True).metadata()


@pytest.mark.parametrize(
    "optional", [{}, {"size": 4900000000, "modified_at": "2026-01-01T00:00:00Z"}]
)
def test_metadata_accepts_large_model_and_missing_optionals(monkeypatch, optional):
    tag = {"name": rt.MODEL, "digest": ev.PILOT_DIGEST, **optional}
    monkeypatch.setattr(
        httpx,
        "AsyncHTTPTransport",
        lambda **kw: httpx.MockTransport(
            lambda request: httpx.Response(200, stream=Wire({"models": [tag]}))
        ),
    )
    observed = rt.LocalExperiment(real_local_model=True).metadata()
    assert observed["tag"]["size"] == optional.get("size")
    assert observed["tag"]["modified_at"] == optional.get("modified_at")


@pytest.mark.parametrize("name", [{"private": "RAW_METADATA"}, True, "x" * 513])
def test_loaded_model_names_are_bounded_strict_scalars(monkeypatch, name):
    def handle(request):
        models = [{"name": rt.MODEL, "digest": ev.PILOT_DIGEST}]
        if request.url.path == "/api/ps":
            models = [{"name": name}]
        return httpx.Response(200, stream=Wire({"models": models}))

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    with pytest.raises(ValueError, match="INVALID_LOADED_MODELS"):
        rt.LocalExperiment(real_local_model=True).metadata()


@pytest.fixture
def matrix_provider(monkeypatch):
    requests = []
    experiments = []
    original = rt.LocalExperiment

    class ObservedExperiment(original):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            experiments.append(self)

    def handle(request):
        requests.append(request)
        if request.url.path == "/api/tags":
            body = {"models": [{"name": rt.MODEL, "digest": ev.PILOT_DIGEST}]}
        elif request.url.path == "/api/ps":
            body = {"models": []}
        else:
            assert request.url.path == "/api/chat"
            body = {"message": {"content": "{}", "thinking": "PRIVATE_SENTINEL"}}
        return httpx.Response(200, stream=Wire(body))

    monkeypatch.setattr(rt, "LocalExperiment", ObservedExperiment)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    return requests, experiments


def test_opt_in_matrix_executes_fixed_nine_actual_pairs(tmp_path, matrix_provider):
    output = tmp_path / "matrix"
    code = ev.main(["--output", str(output), "--real-local-matrix"])
    assert code in (0, 2)
    report = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "matrix-manifest.json").read_text())
    requests, experiments = matrix_provider
    assert report["complete"] and report["expected_rows"] == 18
    assert len(report["rows"]) == 18
    assert len(experiments) == len({id(e.budget) for e in experiments}) == 9
    assert [e["case_id"] for e in manifest["pairs"]] == [c.case_id for c in ev.generate_cases()]
    assert all(e["state"] == "OBSERVED" for e in manifest["pairs"])
    attempts = sum(r.method == "POST" for r in requests)
    assert 0 < attempts == sum(e.budget.attempts for e in experiments) <= 108
    assert manifest["admitted_inference_attempts"] == attempts
    assert all(e.budget.attempts <= 12 for e in experiments)
    assert all(e.budget.deadline <= manifest["deadline_monotonic"] for e in experiments)
    assert sum(len(r["calls"]) for r in report["rows"]) == attempts
    for entry in manifest["pairs"]:
        saved = json.loads((output / entry["report"]).read_text())
        assert ev.digest(saved) == entry["report_sha256"]
        assert len(saved["rows"]) == 2
        assert (output / entry["report"]).with_name("observed-rows.json").exists()
    source_invalid = [r for r in report["rows"] if r["reason"] == "SOURCE_INVALID"]
    assert source_invalid and source_invalid[0]["stored_source_sha256"] is None
    assert any(r["status"] == "NOT_SELECTED" for r in report["rows"])
    assert any(r["status"] == "PARTIAL" for r in report["rows"])
    assert "PRIVATE_SENTINEL" not in (output / "report.json").read_text()
    assert all(r["cost_usd"] is None for r in report["metrics"].values())


def test_matrix_config_drift_preserves_both_pairs_before_stopping(
    tmp_path, monkeypatch, matrix_provider
):
    original = rt.LocalExperiment
    requests, experiments = matrix_provider

    class Drift(original):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            if len(experiments) == 2:
                self.legacy.temperature = 1
                self.investigation = replace(self.investigation, temperature=1)

    monkeypatch.setattr(rt, "LocalExperiment", Drift)
    output = tmp_path / "drift"
    assert ev.main(["--output", str(output), "--real-local-matrix"]) == 2
    summary = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "matrix-manifest.json").read_text())
    assert not summary["complete"] and not summary["metadata"]["comparison_valid"]
    assert len(summary["rows"]) == 4
    assert len(experiments) == 2 and sum(r.method == "POST" for r in requests) == 8
    for case in ev.generate_cases()[:2]:
        pair = json.loads((output / case.case_id / "report.json").read_text())
        assert len(pair["rows"]) == 2
    assert not pair["metadata"]["comparison_valid"]
    assert all(p["state"] == "OBSERVED" for p in manifest["pairs"][:2])
    assert all(p["state"] == "NOT_RUN" for p in manifest["pairs"][2:])
    first_progress = json.loads((output / "progress-01.json").read_text())
    assert first_progress["pairs"][0] == manifest["pairs"][0]


@pytest.mark.parametrize("fault", ["before", "after", "drift", "shape"])
def test_matrix_metadata_fault_keeps_completed_pair_and_marks_unrun(
    tmp_path, monkeypatch, matrix_provider, fault
):
    requests, experiments = matrix_provider
    tags = 0
    first_bytes = None
    output = tmp_path / fault

    def handle(request):
        nonlocal tags, first_bytes
        requests.append(request)
        if request.url.path == "/api/tags":
            tags += 1
            if tags == 3:
                first_bytes = (output / "generated-01/report.json").read_bytes()
            status = (
                503
                if (fault == "before" and tags == 3) or (fault == "after" and tags == 4)
                else 200
            )
            tag = {"name": rt.MODEL, "digest": ev.PILOT_DIGEST}
            if tags == 4 and fault == "drift":
                tag["digest"] = "f" * 64
            if tags == 4 and fault == "shape":
                tag["modified_at"] = {"private": "PRIVATE_SENTINEL"}
            body = {"models": [tag]}
        else:
            status = 200
            body = {"models": []} if request.method == "GET" else {"message": {"content": "{}"}}
        return httpx.Response(status, stream=Wire(body))

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    assert ev.main(["--output", str(output), "--real-local-matrix"]) == 2
    summary = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "matrix-manifest.json").read_text())
    assert len(summary["rows"]) == (2 if fault == "before" else 4)
    assert not summary["complete"] and not summary["metadata"]["comparison_valid"]
    assert len(experiments) == 2
    assert first_bytes == (output / "generated-01/report.json").read_bytes()
    assert all(p["state"] == "NOT_RUN" for p in manifest["pairs"][2:])
    assert "PRIVATE_SENTINEL" not in (output / "report.json").read_text()
    assert manifest["pairs"][1]["state"] == ("UNRESOLVED" if fault == "before" else "OBSERVED")
    if fault != "before":
        assert len(json.loads((output / "generated-02/report.json").read_text())["rows"]) == 2


def test_global_attempt_ceiling_never_resets_with_fresh_pairs(matrix_provider):
    requests, _ = matrix_provider
    parent = rt.AttemptBudget(limit=108)
    for _ in range(9):
        experiment = rt.LocalExperiment(real_local_model=True, matrix_budget=parent)
        for _ in range(12):
            experiment.legacy._request_completion(
                [{"role": "user", "content": "bounded control"}], {}, lambda: False
            )
        assert experiment.budget.attempts == 12
        with pytest.raises(ValueError, match="attempt budget"):
            experiment.budget.admit()
    final = rt.LocalExperiment(real_local_model=True, matrix_budget=parent)
    with pytest.raises(ValueError, match="attempt budget"):
        final.legacy._request_completion([{"role": "user", "content": "denied"}], {}, lambda: False)
    assert parent.attempts == len(requests) == 108
    assert final.budget.attempts == 0


def test_matrix_global_expiry_preserves_first_pair_without_admitting_next(
    tmp_path, monkeypatch, matrix_provider
):
    requests, experiments = matrix_provider
    original = rt.LocalExperiment.metadata

    def expire(self):
        result = original(self)
        if self.budget.attempts:
            self.budget.parent.deadline = rt.time.monotonic() - 1
        return result

    monkeypatch.setattr(rt.LocalExperiment, "metadata", expire)
    output = tmp_path / "expired"
    assert ev.main(["--output", str(output), "--real-local-matrix"]) == 2
    summary = json.loads((output / "report.json").read_text())
    manifest = json.loads((output / "matrix-manifest.json").read_text())
    assert len(experiments) == 1 and len(summary["rows"]) == 2
    assert not summary["complete"] and not summary["metadata"]["comparison_valid"]
    assert sum(r.method == "POST" for r in requests) == 4
    assert manifest["pairs"][0]["state"] == "OBSERVED"
    assert all(p["state"] == "NOT_RUN" for p in manifest["pairs"][1:])


def test_matrix_expiry_after_last_pair_invalidates_final_comparison(
    tmp_path, monkeypatch, matrix_provider
):
    _, experiments = matrix_provider
    original = rt.LocalExperiment.metadata

    def expire_last(self):
        result = original(self)
        if len(experiments) == 9 and self.budget.attempts:
            self.budget.parent.deadline = rt.time.monotonic() - 1
        return result

    monkeypatch.setattr(rt.LocalExperiment, "metadata", expire_last)
    output = tmp_path / "expired-last"
    assert ev.main(["--output", str(output), "--real-local-matrix"]) == 2
    report = json.loads((output / "report.json").read_text())
    assert len(report["rows"]) == 18 and report["complete"]
    assert not report["metadata"]["comparison_valid"]
    assert (output / "generated-09/report.json").exists()


def test_offline_rows_cannot_assert_verified_provenance(matrix_provider):
    experiment = rt.LocalExperiment(real_local_model=True)
    case = ev.generate_cases()[0]
    rows = ev.evaluate_pair(case, experiment.legacy, experiment.investigation)
    ev.collect_telemetry(rows, experiment)
    report = ev.build_report((case,), rows, metadata={"comparison_valid": True})
    assert not report["metadata"]["comparison_valid"]


@pytest.mark.parametrize("kind", ["runtime", "source", "temperature"])
def test_producer_bound_identity_rejects_mixed_common_fingerprint(matrix_provider, kind):
    cases = ev.generate_cases()[:2]
    rows = []
    for case in cases:
        experiment = rt.LocalExperiment(real_local_model=True)
        pair = ev.evaluate_pair(case, experiment.legacy, experiment.investigation)
        ev.collect_telemetry(pair, experiment)
        rows.extend(pair)
    for row in rows[2:]:
        if kind == "runtime":
            row["provenance"]["runtime"]["python"] = "different"
        elif kind == "source":
            row["provenance"]["source_sha256"] = "f" * 64
        else:
            row["provenance"]["common"]["temperature"] = 1
    with pytest.raises(ValueError, match="mixed execution"):
        ev.build_report(cases, rows)


def test_legacy_late_decode_not_accepted(monkeypatch):
    import time

    original = rt.json.loads
    experiment = rt.LocalExperiment(real_local_model=True)
    experiment.budget.deadline = time.monotonic() + 0.03
    physical = []

    def late(value, *args, **kwargs):
        parsed = original(value, *args, **kwargs)
        if isinstance(value, bytearray):
            time.sleep(0.06)
        return parsed

    def handle(request):
        physical.append(request)
        return httpx.Response(200, stream=Wire({"message": {"content": "{}"}}))

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    monkeypatch.setattr(rt.json, "loads", late)
    with pytest.raises(TimeoutError):
        experiment.legacy._request_completion(
            [{"role": "user", "content": "control"}], {}, lambda: False
        )
    assert len(physical) == 1
    assert experiment.legacy_trace.calls[0]["error"] == "TIMEOUT"
    assert experiment.legacy_trace.calls[0]["input_tokens"] is None
