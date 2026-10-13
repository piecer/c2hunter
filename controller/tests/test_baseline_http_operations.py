"""Baseline operations through actual registered HTTP paths."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from tests import test_baseline_http_routes as routes
from tests.test_baseline_http_routes import BASE, SCOPE, headers, scope_body, settings

repository = routes.repository


def test_scope_page_and_closed_misses(repository: Any) -> None:
    with TestClient(create_app(settings(), repository=repository)) as client:
        assert client.put(SCOPE, json=scope_body(), headers=headers()).status_code == 201
        page = client.get(BASE + "/scopes?offset=0&limit=1", headers=headers("viewer"))
        assert page.status_code == 200
        assert set(page.json()) == {"items", "total", "offset", "limit", "next_offset"}
        assert page.json()["total"] == 1 and len(page.json()["items"]) == 1
        assert page.json()["next_offset"] is None
        conflict = client.put(SCOPE, json=dict(scope_body(), name="changed"), headers=headers())
        assert (conflict.status_code, conflict.json()["error"]["code"]) == (
            409,
            "BASELINE_SCOPE_EXISTS",
        )
        missing = client.get(
            BASE + "/scopes/00000000-0000-0000-0000-000000000001", headers=headers()
        )
        assert (missing.status_code, missing.json()["error"]["code"]) == (
            404,
            "BASELINE_SCOPE_NOT_FOUND",
        )


@pytest.mark.parametrize(
    "suffix",
    [
        "?offset=-1",
        "?offset=17",
        "?offset=true",
        "?offset=1.0",
        "?offset=01",
        "?offset=%2B1",
        "?limit=0",
        "?limit=21",
        "?limit=1&limit=2",
        "?filter=x",
    ],
)
def test_page_arguments_before_io(suffix: str, monkeypatch: Any) -> None:
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    calls = []

    def forbidden(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("must validate before IO")

    monkeypatch.setattr(repo, "page_baseline_scopes", forbidden)
    with TestClient(app) as client:
        response = client.get(BASE + "/scopes" + suffix, headers=headers())
        assert (response.status_code, response.json()["error"]["code"], calls) == (
            422,
            "VALIDATION_ERROR",
            [],
        )
    repo.close()


@pytest.mark.parametrize("identifier", ["not-a-uuid", "12345678123412341234123456789abc"])
def test_literal_scope_id_before_io(identifier: str, monkeypatch: Any) -> None:
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    app = create_app(settings(), repository=repo)
    calls = []

    def forbidden(*a: Any, **kw: Any) -> Any:
        calls.append(True)
        raise AssertionError("must validate before IO")

    monkeypatch.setattr(repo, "get_baseline_scope", forbidden)
    with TestClient(app) as client:
        response = client.get(BASE + "/scopes/" + identifier, headers=headers())
        assert (response.status_code, response.json()["error"]["code"], calls) == (
            422,
            "VALIDATION_ERROR",
            [],
        )
    repo.close()
