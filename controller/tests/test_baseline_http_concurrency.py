"""Real ASGI cancellation and repository-serialized race schedules."""

from __future__ import annotations

import asyncio
import threading
from typing import Any

import httpx
import pytest

from c2hunter_controller import historical_generation as g
from c2hunter_controller.app import create_app
from c2hunter_controller.baseline_admission import BaselineLease
from tests import test_baseline_http_routes as routes
from tests.test_baseline_http_admission import seed
from tests.test_baseline_http_preview import PREVIEW
from tests.test_baseline_http_routes import SCOPE, headers, settings
from tests.test_baseline_http_transport import reached
from tests.test_historical_source import config

repository = routes.repository


def test_cancel_actual_publication_owns_compute_and_transport(
    repository: Any, monkeypatch: Any
) -> None:
    body = seed(repository).to_mapping()
    app = create_app(settings(), repository=repository)
    entered, release = threading.Event(), threading.Event()
    original = g.produce_generation
    calls = []

    def blocked(**kw: Any) -> Any:
        calls.append(True)
        entered.set()
        assert release.wait(5)
        return original(**kw)

    monkeypatch.setattr(g, "produce_generation", blocked)

    async def run() -> None:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test", headers=headers()
            ) as client:
                request = asyncio.create_task(client.post(SCOPE + "/approvals", json=body))
                contender = None
                try:
                    await reached(entered)
                    request.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await request
                    with BaselineLease(app.state.baseline_admission) as lease:
                        assert not lease.acquire()
                    assert len(app.state.baseline_transport._pending) == 1
                    busy = await client.post(SCOPE + "/preview", json=PREVIEW)
                    assert (busy.status_code, busy.json()["error"]["code"]) == (
                        503,
                        "BASELINE_BUSY",
                    )
                    # This synchronous same-facade read may wait for its existing mutex.
                    contender = asyncio.create_task(client.get(SCOPE))
                    async with asyncio.timeout(2):
                        while len(app.state.baseline_transport._pending) != 2:
                            await asyncio.sleep(0)
                    full = await client.post(SCOPE + "/approvals", json=body)
                    assert (full.status_code, full.json()["error"]["code"]) == (
                        503,
                        "BASELINE_BUSY",
                    )
                    assert (
                        await asyncio.wait_for(client.get("/api/v1/health"), 1)
                    ).status_code == 200
                    assert calls == [True]
                finally:
                    release.set()
                    if contender is not None:
                        assert (await contender).status_code == 200
                    await app.state.baseline_transport.shutdown()
        with BaselineLease(app.state.baseline_admission) as lease:
            assert lease.acquire()
        assert not app.state.baseline_transport._pending

    asyncio.run(run())
    assert repository.get_baseline_scope(config().scope_id).control_revision == 1
    assert repository.page_baseline_control_events(config().scope_id).total == 1


@pytest.mark.parametrize("same", [False, True])
def test_serialized_same_facade_race_no_duplicate_computation(
    repository: Any, monkeypatch: Any, same: bool
) -> None:
    body = seed(repository).to_mapping()
    app = create_app(settings(), repository=repository)
    entered, release = threading.Event(), threading.Event()
    original = g.produce_generation
    counters = {"live": 0, "maximum": 0, "calls": 0}

    def blocked(**kw: Any) -> Any:
        counters["live"] += 1
        counters["calls"] += 1
        counters["maximum"] = max(counters["maximum"], counters["live"])
        entered.set()
        try:
            assert release.wait(5)
            return original(**kw)
        finally:
            counters["live"] -= 1

    monkeypatch.setattr(g, "produce_generation", blocked)

    async def run() -> None:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://test", headers=headers()
            ) as client:
                a = asyncio.create_task(client.post(SCOPE + "/approvals", json=body))
                b = None
                try:
                    await reached(entered)
                    b = asyncio.create_task(
                        client.post(
                            SCOPE + "/approvals",
                            json=body if same else dict(body, idempotency_key="different"),
                        )
                    )
                    async with asyncio.timeout(2):
                        while len(app.state.baseline_transport._pending) != 2:
                            await asyncio.sleep(0)
                    assert counters["maximum"] == 1
                    assert (
                        await asyncio.wait_for(client.get("/api/v1/health"), 1)
                    ).status_code == 200
                finally:
                    release.set()
                    first = await a
                    second = await b if b else None
                assert first.status_code == 201 and second is not None
                assert second.status_code == (200 if same else 409)
                if same:
                    assert second.json()["receipt"] == first.json()["receipt"]
                else:
                    assert second.json()["error"]["code"] == "BASELINE_REVISION_CONFLICT"
        assert counters == {"live": 0, "maximum": 1, "calls": 1}

    asyncio.run(run())
