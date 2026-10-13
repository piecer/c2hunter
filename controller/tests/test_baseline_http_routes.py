"""Real baseline-management HTTP vertical regressions."""

from __future__ import annotations

import hashlib
from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import config

BASE = "/api/v1/historical-baselines"
SCOPE = BASE + "/scopes/" + config().scope_id
TOKENS = {role: "synthetic-" + role for role in ("viewer", "analyst", "admin")}


def settings(auth: bool = True) -> Settings:
    return Settings(
        environment="test",
        api_auth_required=auth,
        **{
            role + "_token_sha256": hashlib.sha256(token.encode()).hexdigest()
            for role, token in TOKENS.items()
        },
        ai_analysis_enabled=False,
        database_url="memory://",
        redis_url="memory://",
        clickhouse_url="memory://",
        s3_endpoint="memory://",
    )


def headers(role: str = "admin") -> dict[str, str]:
    return {"Authorization": "Bearer " + TOKENS[role]}


def scope_body() -> dict[str, Any]:
    result = config().to_mapping()
    del result["scope_id"]
    return result


@pytest.fixture(params=["memory", "sqlite"])
def repository(request: Any, tmp_path: Any) -> Any:
    repo = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "http.db")
    )
    yield repo
    repo.close()


def test_real_http_uses_two_slot_owner_and_lifecycle(repository: Any, monkeypatch: Any) -> None:
    import asyncio
    import threading

    import httpx

    from tests.test_baseline_http_transport import reached

    app = create_app(settings(), repository=repository)

    async def run() -> None:
        first, second, release = threading.Event(), threading.Event(), threading.Event()
        calls = []
        original = repository.get_baseline_scope

        def blocked(*args: Any) -> Any:
            calls.append(True)
            if len(calls) <= 2:
                (first if len(calls) == 1 else second).set()
                assert release.wait(5)
            return original(*args)

        repository.create_baseline_scope(
            config(),
            "static-admin",
            __import__("tests.test_historical_source", fromlist=["START"]).START,
        )
        monkeypatch.setattr(repository, "get_baseline_scope", blocked)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test", headers=headers()
        ) as client:
            a = asyncio.create_task(client.get(SCOPE))
            b = asyncio.create_task(client.get(SCOPE))
            try:
                await reached(first)
                await reached(second)
                response = await asyncio.wait_for(client.get(SCOPE), 1)
                assert (
                    response.status_code == 503
                    and response.json()["error"]["code"] == "BASELINE_BUSY"
                )
                assert len(calls) == 2
                assert (await asyncio.wait_for(client.get("/api/v1/health"), 1)).status_code == 200
            finally:
                release.set()
                assert (await a).status_code == (await b).status_code == 200
        async with app.router.lifespan_context(app):
            pass
        assert not app.state.baseline_transport._pending

    asyncio.run(run())


def test_real_scope_roundtrip(repository: Any) -> None:
    app = create_app(settings(), repository=repository)
    with TestClient(app) as client:
        response = client.put(SCOPE, json=scope_body(), headers=headers())
        assert response.status_code == 201, response.text
        value = response.json()
        assert set(value) == {
            "config",
            "config_sha256",
            "control_revision",
            "frozen",
            "state",
            "accepted_event_end",
            "active",
            "previous",
            "created_by",
            "created_at",
        }
        assert value["config"] == config().to_mapping()
        assert value["created_by"] == "static-admin"
        assert value["control_revision"] == 0
        assert client.get(SCOPE, headers=headers("viewer")).json() == value
        replay = client.put(SCOPE, json=scope_body(), headers=headers())
        assert replay.status_code == 200 and replay.json() == value


async def raw_http(
    app: Any,
    method: str,
    path: str,
    chunks: list[bytes],
    auth: dict[str, str],
    extra: list[tuple[bytes, bytes]] | None = None,
) -> tuple[int, dict[str, Any], int]:
    import asyncio
    import json

    sent = []
    reads = 0
    ended = asyncio.Event()

    async def receive() -> dict[str, Any]:
        nonlocal reads
        if reads >= len(chunks):
            await ended.wait()
            return {"type": "http.disconnect"}
        index = reads
        reads += 1
        return {"type": "http.request", "body": chunks[index], "more_body": index + 1 < len(chunks)}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    await app(
        {
            "type": "http",
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "root_path": "",
            "headers": [(k.lower().encode(), v.encode()) for k, v in auth.items()] + (extra or []),
            "client": ("127.0.0.1", 1),
            "server": ("test", 80),
        },
        receive,
        send,
    )
    status = next(m["status"] for m in sent if m["type"] == "http.response.start")
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, json.loads(body), reads


ROUTES = [
    ("PUT", SCOPE, "admin"),
    ("GET", BASE + "/scopes", "viewer"),
    ("GET", SCOPE, "viewer"),
    ("POST", SCOPE + "/preview", "analyst"),
    ("POST", SCOPE + "/approvals", "admin"),
    ("POST", SCOPE + "/control", "admin"),
    ("GET", SCOPE + "/generations/00000000-0000-0000-0000-000000000001/sources", "analyst"),
    ("GET", SCOPE + "/control-events", "analyst"),
]


@pytest.mark.parametrize("method,path,minimum", ROUTES)
@pytest.mark.parametrize("mode", ["off", "missing", "bad", "viewer", "analyst"])
def test_auth_before_any_body(method: str, path: str, minimum: str, mode: str) -> None:
    import asyncio

    order = ["viewer", "analyst", "admin"]
    if mode in order and order.index(mode) >= order.index(minimum):
        pytest.skip("authorized roles exercised by operation tests")
    repo = MemoryRepository()
    app = create_app(settings(mode != "off"), repository=repo)
    auth = (
        {}
        if mode in ("off", "missing")
        else ({"Authorization": "Bearer invalid"} if mode == "bad" else headers(mode))
    )
    status, body, reads = asyncio.run(raw_http(app, method, path, [b"x" * 20000], auth))
    code = {
        "off": "BASELINE_AUTH_REQUIRED",
        "missing": "AUTH_TOKEN_REQUIRED",
        "bad": "INVALID_AUTH_TOKEN",
        "viewer": "INSUFFICIENT_ROLE",
        "analyst": "INSUFFICIENT_ROLE",
    }[mode]
    assert (status, body.get("error", {}).get("code"), reads) == (
        401 if mode in ("missing", "bad") else 403,
        code,
        0,
    )
    repo.close()
