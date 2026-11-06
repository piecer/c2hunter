"""Actual CLI/services/stores/gateways; only provider HTTP is synthetic.

The cooperative clock jumps at real finalization, not a fake budget or report.
This is not an 8100-second wait or an arbitrary-preemption realtime guarantee.
"""

import builtins
import json
import runpy
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from c2hunter_controller import ai_investigation_evaluation as ev
from c2hunter_controller import ai_investigation_evaluation_matrix as mx
from c2hunter_controller import ai_investigation_evaluation_runtime as rt


@pytest.fixture
def provider(monkeypatch):
    state = {"requests": [], "experiments": [], "streams": []}
    original = rt.LocalExperiment

    class Observed(original):
        def __init__(self, **kwargs):
            super().__init__(**kwargs)
            state["experiments"].append(self)

    class Wire(httpx.AsyncByteStream):
        def __init__(self, value):
            self.raw = json.dumps(value).encode()
            self.closed = False

        async def __aiter__(self):
            yield self.raw

        async def aclose(self):
            self.closed = True

    def handle(request):
        state["requests"].append((request.method, request.url.path))
        if request.url.path == "/api/tags":
            body = {"models": [{"name": rt.MODEL, "digest": ev.PILOT_DIGEST}]}
        elif request.url.path == "/api/ps":
            body = {"models": []}
        else:
            assert request.method == "POST" and request.url.path == "/api/chat"
            body = {"message": {"content": "{}"}}
        stream = Wire(body)
        state["streams"].append(stream)
        return httpx.Response(200, stream=stream)

    monkeypatch.setattr(rt, "LocalExperiment", Observed)
    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **kw: httpx.MockTransport(handle))
    yield state
    assert all(s.closed for s in state["streams"])


@pytest.mark.parametrize("late", [False, True])
def test_actual_cli_final_serializer_deadline(monkeypatch, tmp_path, provider, late):
    offset = [0.0]
    monotonic = time.monotonic
    clock = SimpleNamespace(monotonic=lambda: monotonic() + offset[0])
    monkeypatch.setattr(mx, "time", clock)
    monkeypatch.setattr(rt, "time", clock)
    serialize = ev.serialize_report
    fired = []
    retained = {}
    dest = tmp_path / "matrix"

    def final_serialization(value):
        text = serialize(value)
        if (
            not fired
            and isinstance(value, dict)
            and value.get("execution") == "REAL_LOCAL_MATRIX"
            and value["metadata"]["comparison_valid"]
        ):
            assert len(value["rows"]) == 18
            fired.append(True)
            retained.update(
                (str(p.relative_to(dest)), p.read_bytes())
                for p in dest.rglob("*.json")
                if p.parent != dest or p.name.startswith("progress-")
            )
            if late:
                offset[0] = 8101.0
        return text

    monkeypatch.setattr(ev, "serialize_report", final_serialization)
    code = ev.main(["--output", str(dest), "--real-local-matrix"])
    saved = json.loads((dest / "report.json").read_text())
    manifest = json.loads((dest / "matrix-manifest.json").read_text())
    assert fired == [True] and len(provider["experiments"]) == 9
    assert len(list(dest.glob("generated-*/report.json"))) == 9
    assert len(list(dest.glob("generated-*/observed-rows.json"))) == 9
    assert len(list(dest.glob("progress-*.json"))) == 9
    assert saved["complete"] and len(saved["rows"]) == 18
    for name, raw in retained.items():
        assert (dest / name).read_bytes() == raw
    assert all(p["state"] == "OBSERVED" for p in manifest["pairs"])
    assert sum(m == "POST" for m, _ in provider["requests"]) == 28
    assert (clock.monotonic() >= manifest["deadline_monotonic"]) is late
    assert code == (2 if late else 0)
    assert saved["metadata"]["comparison_valid"] is not late
    assert manifest["comparison_valid"] is not late


@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize(
    "mode,stage",
    [
        ("matrix", "render"),
        ("matrix", "report.json"),
        ("matrix", "report.md"),
        ("matrix", "matrix-manifest.json"),
        ("matrix", "terminal"),
        ("pair", "serializer"),
        ("pair", "terminal"),
        ("module", "terminal"),
    ],
)
def test_actual_final_publication_boundaries(monkeypatch, tmp_path, provider, mode, stage, late):
    dest = tmp_path / "output"
    offset = [0.0]
    monotonic = time.monotonic
    clock = SimpleNamespace(monotonic=lambda: monotonic() + offset[0])
    monkeypatch.setattr(mx, "time", clock)
    monkeypatch.setattr(rt, "time", clock)
    execution = "REAL_LOCAL_MODEL" if mode == "pair" else "REAL_LOCAL_MATRIX"
    fired = []
    retained = {}
    rows_before = []
    module_origins = []

    def trip():
        if fired:
            return
        fired.append(True)
        retained.update(
            (str(p.relative_to(dest)), p.read_bytes())
            for p in dest.rglob("*.json")
            if p.parent != dest or p.name.startswith("progress-") or p.name == "observed-rows.json"
        )
        if mode == "module":
            module_origins.append(sys.modules["__main__"].__file__)
        if late:
            offset[0] = 901.0 if mode == "pair" else 8101.0

    serialize = ev.serialize_report

    def serialization(value):
        text = serialize(value)
        if (
            isinstance(value, dict)
            and value.get("execution") == execution
            and value["metadata"]["comparison_valid"]
        ):
            rows_before[:] = json.loads(text)["rows"]
            if stage == "serializer":
                trip()
        return text

    monkeypatch.setattr(ev, "serialize_report", serialization)
    render = ev.markdown_report

    def rendering(value):
        text = render(value)
        if value.get("execution") == execution and value["metadata"]["comparison_valid"]:
            trip()
        return text

    original_open = Path.open

    @contextmanager
    def closing(path, *args, **kwargs):
        with original_open(path, *args, **kwargs) as stream:
            yield stream
        # Injection follows the actual write and ordinary close, not open-entry.
        trip()

    def opening(path, mode="r", *args, **kwargs):
        if path == dest / stage and mode in {"w", "x"} and not fired:
            return closing(path, mode, *args, **kwargs)
        return original_open(path, mode, *args, **kwargs)

    original_print = builtins.print

    def terminal(*args, **kwargs):
        original_print(*args, **kwargs)
        if args and isinstance(args[0], str) and '"execution":' in args[0]:
            trip()

    if stage == "render":
        monkeypatch.setattr(ev, "markdown_report", rendering)
    elif stage in {"report.json", "report.md", "matrix-manifest.json"}:
        monkeypatch.setattr(Path, "open", opening)
    elif stage == "terminal":
        monkeypatch.setattr(builtins, "print", terminal)
    flags = [
        "--output",
        str(dest),
        "--real-local-model" if mode == "pair" else "--real-local-matrix",
    ]
    if mode == "module":
        monkeypatch.setattr(sys, "argv", [ev.__name__, *flags])
        with pytest.raises(SystemExit) as exc:
            runpy.run_module(ev.__name__, run_name="__main__", alter_sys=True)
        code = exc.value.code
        assert module_origins == [ev.__file__]
    else:
        code = ev.main(flags)
    report = json.loads((dest / "report.json").read_text())
    assert fired == [True]
    assert code == (2 if late else 0)
    assert report["complete"] and report["metadata"]["comparison_valid"] is not late
    assert len(report["rows"]) == (2 if mode == "pair" else 18)
    if mode != "module":
        assert report["rows"] == rows_before
    assert len(provider["experiments"]) == (1 if mode == "pair" else 9)
    assert sum(m == "POST" for m, _ in provider["requests"]) == (4 if mode == "pair" else 28)
    for name, raw in retained.items():
        assert (dest / name).read_bytes() == raw
    if mode != "pair":
        manifest = json.loads((dest / "matrix-manifest.json").read_text())
        assert manifest["complete"] and manifest["comparison_valid"] is not late
        assert len(list(dest.glob("generated-*/report.json"))) == 9
        assert len(list(dest.glob("generated-*/observed-rows.json"))) == 9
        assert len(list(dest.glob("progress-*.json"))) == 9
        assert all(e["state"] == "OBSERVED" for e in manifest["pairs"])
        if late:
            assert manifest["stop_reason"] == "MATRIX_DEADLINE_EXCEEDED"
    if late:
        assert "False" in (dest / "report.md").read_text()
