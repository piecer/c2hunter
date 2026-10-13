"""Protocol-only router surface and exact parser boundaries (regressions)."""

import asyncio
import json
from typing import Any

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from c2hunter_controller.api_errors import ApiError
from c2hunter_controller.app import _error
from c2hunter_controller.baseline_admission import BaselineAdmission
from c2hunter_controller.historical_baseline_api import BaselineTransport, _body, baseline_router
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.security import Principal, Role
from tests.test_baseline_http_approval import approval
from tests.test_baseline_http_routes import BASE, SCOPE, headers
from tests.test_historical_source import stored


def test_only_eight_repository_operations() -> None:
    repo = MemoryRepository()
    repo.save_job(stored())
    allowed = {
        "create_baseline_scope",
        "get_baseline_scope",
        "page_baseline_scopes",
        "preview_baseline_source",
        "publish_baseline_source",
        "control_baseline_scope",
        "page_baseline_sources",
        "page_baseline_control_events",
    }
    calls = []

    class ProtocolOnly:
        def __getattr__(self, name: str) -> Any:
            assert name in allowed, "generic dependency forbidden"
            calls.append(name)
            return getattr(repo, name)

    app = FastAPI()
    transport = BaselineTransport()
    app.include_router(baseline_router(ProtocolOnly(), transport, BaselineAdmission()))
    app.router.add_event_handler("shutdown", transport.shutdown)

    @app.middleware("http")
    async def trusted_fixture(request: Request, call_next: Any) -> Any:
        request.state.principal = Principal("static-admin", Role.ADMIN)
        return await call_next(request)

    @app.exception_handler(ApiError)
    async def error(request: Request, exc: ApiError) -> Any:
        return _error(request, exc.status, exc.code, exc.message, exc.details)

    with TestClient(app) as client:
        body = approval(client)
        publication = client.post(SCOPE + "/approvals", json=body, headers=headers())
        assert publication.status_code == 201
        generation = publication.json()["receipt"]["generation_id"]
        assert client.get(SCOPE).status_code == 200
        assert client.get(BASE + "/scopes").status_code == 200
        assert client.get(SCOPE + "/generations/" + generation + "/sources").status_code == 200
        assert client.get(SCOPE + "/control-events").status_code == 200
        assert (
            client.post(
                SCOPE + "/control",
                json={
                    "expected_revision": 1,
                    "idempotency_key": "control",
                    "action": "FREEZE",
                    "reason": "fixture",
                    "generation_id": None,
                },
            ).status_code
            == 200
        )
        assert client.post(SCOPE + "/approvals", json=body).status_code == 200
    assert set(calls) == allowed
    with pytest.raises(AssertionError):
        _ = ProtocolOnly().get_job
    repo.close()


@pytest.mark.parametrize("depth", [16, 17])
def test_json_depth_boundary_before_decoder(depth: int, monkeypatch: Any) -> None:
    raw = b'{"x":' + b"[" * (depth - 1) + b"0" + b"]" * (depth - 1) + b"}"
    reads = []
    calls = []
    original = json.loads

    def observe(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        return original(*a, **kw)

    monkeypatch.setattr(json, "loads", observe)

    async def receive() -> Any:
        reads.append(True)
        return {"type": "http.request", "body": raw, "more_body": False}

    request = Request({"type": "http", "headers": []}, receive)
    if depth == 16:
        assert "x" in asyncio.run(_body(request))
        assert calls == [True]
    else:
        with pytest.raises(ApiError) as error:
            asyncio.run(_body(request))
        assert error.value.status == 422 and calls == []
    assert reads == [True]
