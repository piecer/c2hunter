"""New offline boundary probes. All HTTP is genuine incremental MockTransport."""

import json
import time
from pathlib import Path

import httpx
import pytest

from c2hunter_controller import ai_investigation_evaluation as ev
from c2hunter_controller import ai_investigation_evaluation_report as reporting
from c2hunter_controller import ai_investigation_evaluation_runtime as rt
from c2hunter_controller.ai_investigation_gateway import InvestigationGatewayError

ROOT = Path(__file__).parent
OBSERVATIONS = {}
MESSAGES = [{"role": "user", "content": "{}"}]
SCHEMA = {"type": "object"}
SENTINEL = "PRIVATE_PROVIDER_ENVELOPE_SENTINEL"


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.yielded = 0
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk

    async def aclose(self):
        self.closed = True


def wire(value):
    encoded = json.dumps(value).encode()
    return Chunks([encoded[i : i + 1024] for i in range(0, len(encoded), 1024)])


def mock_transport(monkeypatch, handler):
    construction = []

    def create(**kwargs):
        construction.append(kwargs)
        return httpx.MockTransport(handler)

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", create)
    return construction


def new_call(experiment, cancel=lambda: False):
    return experiment.investigation.complete(
        MESSAGES,
        SCHEMA,
        should_cancel=cancel,
        deadline_monotonic=experiment.budget.deadline,
        before_attempt=lambda: None,
    )


def old_call(experiment, cancel=lambda: False):
    return experiment.legacy._request_completion(MESSAGES, SCHEMA, cancel)


def test_allowlist_and_no_auth_fail_before_transport(monkeypatch):
    dispatched = []
    construction = mock_transport(monkeypatch, lambda req: dispatched.append(req))
    local = rt.LocalHTTP(rt.AttemptBudget(), rt.Trace())
    for method, url, headers in [
        ("POST", rt.ENDPOINT + "/api/pull", None),
        ("GET", rt.ENDPOINT + "/api/tags?x=1", None),
        ("GET", "http://localhost:11434/api/tags", None),
        ("GET", "http://127.0.0.1:11435/api/tags", None),
        ("GET", rt.ENDPOINT + "/api/tags", {"Authorization": "sentinel"}),
    ]:
        with pytest.raises(ValueError):
            local.request(method, url, headers=headers)
    with pytest.raises(ValueError):
        rt.LocalExperiment()
    with pytest.raises(ValueError):
        rt.LocalExperiment(real_local_model=True, endpoint="http://localhost:11434")
    assert dispatched == construction == []


def test_stream_limit_before_decoder_and_rejection_closes(monkeypatch):
    local = rt.LocalHTTP(rt.AttemptBudget(), rt.Trace())
    raw = b'{"v":"' + b"x" * (rt.RESPONSE_LIMIT - 8) + b'"}'
    assert len(raw) == rt.RESPONSE_LIMIT
    streams = []
    active = {"overflow": False, "status": 200, "encoding": "identity"}

    def handle(request):
        chunks = [raw[i : i + 4096] for i in range(0, len(raw), 4096)]
        if active["overflow"]:
            chunks += [b"!", b"NEVER_READ"]
        stream = Chunks(chunks)
        streams.append(stream)
        assert request.headers["accept-encoding"] == "identity"
        assert "authorization" not in request.headers
        return httpx.Response(
            active["status"],
            headers={
                "Content-Encoding": active["encoding"],
                "Location": "https://example.invalid/",
            },
            stream=stream,
        )

    construction = mock_transport(monkeypatch, handle)
    assert len(local.request("GET", rt.ENDPOINT + "/api/tags")["v"]) == rt.RESPONSE_LIMIT - 8
    loads = json.loads
    decoded = []

    def observe_loads(value, *a, **kw):
        decoded.append(len(value))
        return loads(value, *a, **kw)

    monkeypatch.setattr(rt.json, "loads", observe_loads)
    active["overflow"] = True
    with pytest.raises(ValueError, match="RESPONSE_LIMIT"):
        local.request("GET", rt.ENDPOINT + "/api/tags")
    assert decoded == [] and streams[-1].yielded == 65 and streams[-1].closed
    for status, encoding, error in [
        (302, "identity", "HTTP_STATUS"),
        (200, "gzip", "CONTENT_ENCODING"),
    ]:
        active.update(status=status, encoding=encoding)
        with pytest.raises(ValueError, match=error):
            local.request("GET", rt.ENDPOINT + "/api/tags")
        assert streams[-1].yielded == 0 and streams[-1].closed
    assert all(c["trust_env"] is False and c["retries"] == 0 for c in construction)
    OBSERVATIONS["streaming"] = {
        "exact_bytes": len(raw),
        "overflow_decode_calls": len(decoded),
        "all_closed": all(s.closed for s in streams),
    }


def test_shared_budget_at_twelve_and_unknown_usage(monkeypatch):
    dispatched = []

    def handle(req):
        dispatched.append(str(req.url))
        return httpx.Response(
            200,
            stream=wire(
                {"message": {"content": "{}"}, "prompt_eval_count": True, "eval_count": -1}
            ),
        )

    mock_transport(monkeypatch, handle)
    ex = rt.LocalExperiment(real_local_model=True)
    ex.budget.attempts = 10
    old_call(ex)
    new_call(ex)
    with pytest.raises(ValueError, match="attempt budget"):
        old_call(ex)
    with pytest.raises(InvestigationGatewayError, match="ATTEMPT_REJECTED"):
        new_call(ex)
    assert ex.budget.attempts == 12 and len(dispatched) == 2
    for trace in (ex.legacy_trace, ex.investigation_trace):
        assert trace.calls[0]["input_tokens"] is None and trace.calls[0]["output_tokens"] is None
        assert trace.calls[1]["http_attempts"] == 0
    OBSERVATIONS["shared_budget"] = {
        "initial": 10,
        "final": ex.budget.attempts,
        "dispatched": len(dispatched),
        "legacy": ex.legacy_trace.calls,
        "investigation": ex.investigation_trace.calls,
    }


def test_actual_legacy_dispatch_rechecks_after_body_encoding(monkeypatch):
    import httpx._content as content

    dispatched = []
    ex = rt.LocalExperiment(real_local_model=True)

    def handle(req):
        dispatched.append({"at": time.monotonic(), "deadline": ex.budget.deadline})
        return httpx.Response(200, stream=wire({"message": {"content": "{}"}}))

    mock_transport(monkeypatch, handle)
    real_dumps = content.json_dumps

    def slow_encoding(*args, **kwargs):
        encoded = real_dumps(*args, **kwargs)
        # Bounded scheduling pause at real HTTPX JSON encoding, not a hostile callback.
        time.sleep(0.06)
        return encoded

    ex.budget.deadline = time.monotonic() + 0.03
    monkeypatch.setattr(content, "json_dumps", slow_encoding)
    error = None
    try:
        old_call(ex)
    except Exception as exc:
        error = type(exc).__name__
    OBSERVATIONS["legacy_post_encoding_deadline"] = {
        "dispatched": dispatched,
        "error": error,
        "trace": ex.legacy_trace.calls,
    }
    assert dispatched == [], (
        "Actual legacy HTTP dispatch occurred after cumulative deadline during body encoding"
    )


def test_client_setup_late_return_blocks_both_arms(monkeypatch):
    sent = []

    def delayed_transport(**kwargs):
        time.sleep(0.05)
        return httpx.MockTransport(lambda req: sent.append(req))

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", delayed_transport)
    for arm in ("legacy", "investigation"):
        ex = rt.LocalExperiment(real_local_model=True)
        ex.budget.deadline = time.monotonic() + 0.02
        with pytest.raises((TimeoutError, InvestigationGatewayError)):
            (old_call if arm == "legacy" else new_call)(ex)
    assert sent == []


def test_legacy_cancel_records_explicit_error(monkeypatch):
    cancelled = False
    stream = wire({"message": {"content": "{}"}})

    def handle(req):
        nonlocal cancelled
        cancelled = True
        return httpx.Response(200, stream=stream)

    mock_transport(monkeypatch, handle)
    ex = rt.LocalExperiment(real_local_model=True)
    with pytest.raises(InterruptedError):
        old_call(ex, lambda: cancelled)
    call = ex.legacy_trace.calls[0]
    OBSERVATIONS["legacy_cancel"] = dict(call, stream_closed=stream.closed)
    assert call["http_attempts"] == 1 and call["completed_responses"] == 0 and stream.closed
    assert call["error"] == "CANCELLED", (
        "Cancellation after HTTP admission is exported with error=null"
    )


def test_production_observer_preserves_limits_and_error_accounting(monkeypatch):
    active = {"size": 65537}
    streams = []

    def handle(req):
        if active["size"]:
            stream = Chunks([b"x" * 4096] * 16 + [b"!"])
        else:
            stream = wire({"message": {"content": '{"x":"' + "x" * 16384 + '"}'}})
        streams.append(stream)
        return httpx.Response(200, stream=stream)

    mock_transport(monkeypatch, handle)
    ex = rt.LocalExperiment(real_local_model=True)
    with pytest.raises(InvestigationGatewayError, match="RESPONSE_LIMIT"):
        new_call(ex)
    active["size"] = 0
    with pytest.raises(InvestigationGatewayError, match="MODEL_TEXT_LIMIT"):
        new_call(ex)
    assert [
        (c["http_attempts"], c["completed_responses"]) for c in ex.investigation_trace.calls
    ] == [(1, 0), (1, 1)]
    assert all(s.closed for s in streams)


def test_offline_cli_no_network_and_output_ownership(monkeypatch):
    construction = mock_transport(monkeypatch, lambda req: pytest.fail("network not permitted"))
    dest = ROOT / "cli-offline"
    assert ev.main(["--output", str(dest)]) == 0
    report = json.loads((dest / "report.json").read_text())
    assert (
        report["execution"] == "OFFLINE_NOT_EXECUTED"
        and not report["complete"]
        and report["rows"] == []
    )
    before = {p.name: p.read_bytes() for p in dest.iterdir()}
    with pytest.raises(FileExistsError):
        ev.main(["--output", str(dest)])
    alias = ROOT / "cli-symlink"
    alias.symlink_to(dest, target_is_directory=True)
    with pytest.raises(FileExistsError):
        ev.main(["--output", str(alias)])
    assert before == {p.name: p.read_bytes() for p in dest.iterdir()}
    assert construction == []


@pytest.mark.parametrize("post", ["drift", "unavailable", "malformed_shape"])
def test_cli_retains_actual_outcomes_on_bad_post_metadata(monkeypatch, post):
    tags = chats = 0
    seen = []
    streams = []

    def handle(req):
        nonlocal tags, chats
        seen.append((req.method, str(req.url)))
        status = 200
        if req.url.path == "/api/tags":
            tags += 1
            tag = {
                "name": rt.MODEL,
                "digest": ev.PILOT_DIGEST,
                "size": 123,
                "modified_at": "2026-01-01T00:00:00Z",
            }
            if tags > 1:
                if post == "drift":
                    tag["digest"] = "f" * 64
                elif post == "unavailable":
                    status = 503
                else:
                    nested = {"untrusted": "metadata"}
                    for _ in range(35):
                        nested = {"x": nested}
                    tag["modified_at"] = nested
            body = {"models": [tag]}
        elif req.url.path == "/api/ps":
            body = {"models": []}
        elif req.url.path == "/api/chat":
            chats += 1
            # Real unchanged gateway/schema/repair/store paths consume these invalid outputs.
            body = {"message": {"content": "{}", "thinking": SENTINEL}, "error": SENTINEL}
        else:
            pytest.fail("unapproved HTTP route")
        stream = wire(body)
        streams.append(stream)
        return httpx.Response(status, stream=stream)

    mock_transport(monkeypatch, handle)
    dest = ROOT / ("cli-post-" + post)
    caught = None
    code = None
    try:
        code = ev.main(["--output", str(dest), "--real-local-model"])
    except Exception as exc:
        caught = {"type": type(exc).__name__, "message": str(exc)}
    report_path = dest / "report.json"
    OBSERVATIONS["cli_post_" + post] = {
        "returncode": code,
        "exception": caught,
        "chats": chats,
        "tags": tags,
        "report_exists": report_path.exists(),
        "requests": seen,
    }
    assert chats == 4 and tags == 2 and all(s.closed for s in streams)
    assert caught is None and code == 2 and report_path.exists(), (
        "Post-inference invalid metadata discarded completed arm outcomes "
        "instead of persisting invalid comparison"
    )
    raw = report_path.read_text()
    report = json.loads(raw)
    assert (
        len(report["rows"]) == 2
        and report["complete"]
        and not report["metadata"]["comparison_valid"]
    )
    assert report["rows"][0]["status"] == "FAILED"
    assert report["rows"][1]["status"] == "PARTIAL"
    assert report["metadata"]["admitted_inference_attempts"] == 4
    assert report["metadata"]["backend_generation_physically_cancelled"] is None
    assert SENTINEL not in raw and '"inputs"' not in raw and '"outputs"' not in raw
    assert [c["repair_requested"] for c in report["rows"][0]["calls"]] == [False, True]
    assert [c["repair_requested"] for c in report["rows"][1]["calls"]] == [False, True]


def test_report_limits_on_bounded_provider_sized_input():
    assert reporting.serialize_report({"x": "a" * 262144}).startswith("{")
    nested = {}
    for _ in range(34):
        nested = {"x": nested}
    with pytest.raises(ValueError, match="report limit"):
        reporting.serialize_report(nested)
    with pytest.raises(ValueError, match="report limit"):
        reporting.serialize_report({"x": [0] * 100001})
    with pytest.raises(ValueError, match="report limit"):
        reporting.serialize_report({"x": "\x00" * 400000})


@pytest.fixture(autouse=True)
def owned_artifacts(tmp_path, monkeypatch):
    import sys

    (tmp_path / "evidence").mkdir(exist_ok=True)
    monkeypatch.setattr(sys.modules[__name__], "ROOT", tmp_path)
