"""Finite route/body/query boundary no-dispatch matrix."""

from __future__ import annotations

import asyncio
import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_http_preview import PREVIEW
from tests.test_baseline_http_routes import BASE, SCOPE, headers, raw_http, scope_body, settings
from tests.test_historical_source import review

APPROVAL = {
    "expected_revision": 0,
    "idempotency_key": "x",
    "source_job_id": "root",
    "source_binding_sha256": "0" * 64,
    "normality": "APPROVED_NORMAL",
    "quality_review": review().to_mapping(),
    "reason": "fixture",
}
CONTROL = {
    "expected_revision": 0,
    "idempotency_key": "x",
    "action": "RETIRE",
    "reason": "fixture",
    "generation_id": None,
}
BODIES = [
    ("PUT", SCOPE, scope_body()),
    ("POST", SCOPE + "/preview", PREVIEW),
    ("POST", SCOPE + "/approvals", APPROVAL),
    ("POST", SCOPE + "/control", CONTROL),
]
PAGES = [
    BASE + "/scopes",
    SCOPE + "/control-events",
    SCOPE + "/generations/00000000-0000-0000-0000-000000000001/sources",
]


@pytest.mark.parametrize("method,path,payload", BODIES)
@pytest.mark.parametrize("bad", ["oversize", "duplicate", "unknown", "missing"])
def test_body_matrix_before_dispatch(
    method: str, path: str, payload: dict[str, Any], bad: str, monkeypatch: Any
) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    calls = []

    async def fail(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("rejected request dispatched")

    monkeypatch.setattr(app.state.baseline_transport, "call", fail)
    chunks = {
        "oversize": [b" " * 8192, b" " * 8193, b"undrained"],
        "duplicate": [b'{"a":0,"a":1}'],
        "unknown": [json.dumps(dict(payload, actor="injected")).encode()],
        "missing": [b"{}"],
    }[bad]
    status, body, reads = asyncio.run(raw_http(app, method, path, chunks, headers()))
    assert (status, body["error"]["code"], calls) == (
        (413, "BASELINE_BODY_LIMIT", []) if bad == "oversize" else (422, "VALIDATION_ERROR", [])
    )
    assert reads == (2 if bad == "oversize" else 1)
    repo.close()


@pytest.mark.parametrize(
    "method,path,payload", BODIES + [("GET", SCOPE, None)] + [("GET", p, None) for p in PAGES]
)
def test_no_unknown_query_before_dispatch(
    method: str, path: str, payload: Any, monkeypatch: Any
) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    calls = []

    async def fail(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("unsupported filter dispatched")

    monkeypatch.setattr(app.state.baseline_transport, "call", fail)
    with TestClient(app) as client:
        response = client.request(
            method, path + "?filter=not-supported", json=payload, headers=headers()
        )
        assert (response.status_code, response.json()["error"]["code"], calls) == (
            422,
            "VALIDATION_ERROR",
            [],
        )
    repo.close()


@pytest.mark.parametrize("path", PAGES)
@pytest.mark.parametrize(
    "query",
    [
        "offset=true",
        "limit=false",
        "offset=1.0",
        "offset=-1",
        "limit=21",
        "limit=0",
        "offset=0&offset=1",
    ],
)
def test_every_page_strict_query_no_dispatch(path: str, query: str, monkeypatch: Any) -> None:
    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    calls = []

    async def fail(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("bad page dispatched")

    monkeypatch.setattr(app.state.baseline_transport, "call", fail)
    with TestClient(app) as client:
        response = client.get(path + "?" + query, headers=headers())
        assert (response.status_code, response.json()["error"]["code"], calls) == (
            422,
            "VALIDATION_ERROR",
            [],
        )
    repo.close()
