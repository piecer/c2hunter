"""Raw framing, closed JSON and schema rejection before repository IO."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest

from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_http_routes import SCOPE, headers, raw_http, scope_body, settings


@pytest.mark.parametrize("kind", ["declared", "chunked", "understated", "exact"])
def test_body_limit_stream_once(kind: str, monkeypatch: Any) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    raw = json.dumps(scope_body()).encode()
    raw += b" " * (16384 - len(raw))
    if kind == "exact":
        chunks, extra, expected_reads, status = [raw[:8192], raw[8192:]], [], 2, 201
    elif kind == "declared":
        chunks, extra, expected_reads, status = (
            [raw + b"x"],
            [(b"content-length", b"16385")],
            0,
            413,
        )
    else:
        chunks = [b"x" * 8192, b"y" * 8193, b"NEVER_READ"]
        extra = (
            [(b"transfer-encoding", b"chunked")]
            if kind == "chunked"
            else [(b"content-length", b"1")]
        )
        expected_reads, status = 2, 413
    calls = []
    original = repo.create_baseline_scope

    def observe(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        return original(*a, **kw)

    monkeypatch.setattr(repo, "create_baseline_scope", observe)
    actual, value, reads = asyncio.run(raw_http(app, "PUT", SCOPE, chunks, headers(), extra))
    assert (actual, reads, len(calls)) == (status, expected_reads, int(kind == "exact"))
    if status == 413:
        assert value["error"]["code"] == "BASELINE_BODY_LIMIT"
    repo.close()


@pytest.mark.parametrize(
    "raw",
    [
        b"{",
        b"[]",
        b"null",
        b'"text"',
        b"\xff",
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":1e999}',
        b'{"a":1,"a":2}',
        b'{"x":{"a":1,"a":2}}',
        b'{"x":' + b"[" * 16 + b"0" + b"]" * 16 + b"}",
        json.dumps(dict(scope_body(), actor="sensitive-injected-actor")).encode(),
        json.dumps(dict(scope_body(), scope_id="12345678-1234-1234-1234-123456789abc")).encode(),
        json.dumps(dict(scope_body(), window_seconds=True)).encode(),
        json.dumps(dict(scope_body(), window_seconds="60")).encode(),
        b"{}",
    ],
)
def test_closed_json_schema_no_io(raw: bytes, monkeypatch: Any) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    calls = []

    def forbidden(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("repository must not be reached")

    monkeypatch.setattr(repo, "create_baseline_scope", forbidden)
    status, body, reads = asyncio.run(raw_http(app, "PUT", SCOPE, [raw], headers()))
    assert (status, body["error"]["code"], reads, calls) == (422, "VALIDATION_ERROR", 1, [])
    assert set(body) == {"error"}
    assert set(body["error"]) == {"code", "message", "details", "request_id"}
    assert body["error"]["details"] is None
    assert "sensitive-injected-actor" not in json.dumps(body)
    repo.close()
