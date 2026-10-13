"""Approval HTTP publication and authoritative replay while computation busy."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as read
from c2hunter_controller.app import create_app
from c2hunter_controller.baseline_admission import BaselineLease
from tests import test_baseline_http_routes as routes
from tests.test_baseline_http_preview import PREVIEW
from tests.test_baseline_http_routes import SCOPE, headers, scope_body, settings
from tests.test_historical_source import START, config, review, stored

repository = routes.repository


def approval(client: TestClient) -> dict[str, Any]:
    assert client.put(SCOPE, json=scope_body(), headers=headers()).status_code == 201
    preview = client.post(SCOPE + "/preview", json=PREVIEW, headers=headers("analyst"))
    assert preview.status_code == 200
    return {
        "expected_revision": 0,
        "idempotency_key": "http-approval",
        "source_job_id": "root",
        "source_binding_sha256": preview.json()["source_binding_sha256"],
        "normality": "APPROVED_NORMAL",
        "quality_review": review().to_mapping(),
        "reason": "Synthetic normal review",
    }


def test_approval_replay_busy_sourcegone_current_control(repository: Any, monkeypatch: Any) -> None:
    repository.save_job(stored())
    app = create_app(settings(), repository=repository)
    with TestClient(app) as client:
        body = approval(client)
        response = client.post(SCOPE + "/approvals", json=body, headers=headers())
        assert response.status_code == 201, response.text
        result = response.json()
        assert set(result) == {"scope", "receipt"}
        assert set(result["receipt"]) == {
            "operation_id",
            "action",
            "revision",
            "actor",
            "occurred_at",
            "generation_id",
            "source_job_id",
            "source_binding_sha256",
        }
        assert result["receipt"]["actor"] == "static-admin"
        repository.control_baseline_scope(
            config().scope_id,
            g.ControlRequest(
                expected_revision=1,
                idempotency_key="retire",
                action="RETIRE",
                reason="fixture",
                generation_id=None,
            ),
            "static-admin",
            START,
        )
        repository.delete_job("root")
        lease = BaselineLease(app.state.baseline_admission)
        assert lease.acquire()
        calls = []

        def forbidden(*a: Any, **kw: Any) -> Any:
            calls.append(True)
            raise AssertionError("replay must not acquire source or produce")

        with monkeypatch.context() as m:
            for name in ["_memory_acquire", "_sqlite_acquire", "_postgres_acquire"]:
                m.setattr(read, name, forbidden)
            m.setattr(g, "produce_generation", forbidden)
            try:
                replay = client.post(SCOPE + "/approvals", json=body, headers=headers())
                assert replay.status_code == 200
                assert replay.json()["receipt"] == result["receipt"]
                assert replay.json()["scope"]["state"] == "RETIRED"
                assert replay.json()["scope"]["control_revision"] == 2
                changed = client.post(
                    SCOPE + "/approvals", json=dict(body, reason="changed"), headers=headers()
                )
                assert (changed.status_code, changed.json()["error"]["code"]) == (
                    409,
                    "BASELINE_IDEMPOTENCY_CONFLICT",
                )
                busy = client.post(
                    SCOPE + "/approvals", json=dict(body, idempotency_key="new"), headers=headers()
                )
                assert (busy.status_code, busy.json()["error"]["code"]) == (503, "BASELINE_BUSY")
                assert calls == []
            finally:
                lease.close()
        assert repository.page_baseline_control_events(config().scope_id).total == 2


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected_revision", True),
        ("expected_revision", "0"),
        ("normality", False),
        ("quality_review", None),
        ("approved_by", "injected"),
        ("source_binding_sha256", "x"),
    ],
)
def test_approval_closed_schema_before_publication(
    repository: Any, monkeypatch: Any, field: str, value: Any
) -> None:
    repository.save_job(stored())
    app = create_app(settings(), repository=repository)
    with TestClient(app) as client:
        body = approval(client)
        body[field] = value
        calls = []

        def forbidden(*a: Any, **kw: Any) -> Any:
            calls.append(True)
            raise AssertionError("invalid request reached publisher")

        monkeypatch.setattr(repository, "publish_baseline_source", forbidden)
        response = client.post(SCOPE + "/approvals", json=body, headers=headers())
        assert (response.status_code, response.json()["error"]["code"], calls) == (
            422,
            "VALIDATION_ERROR",
            [],
        )
