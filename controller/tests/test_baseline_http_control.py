"""Public control and bounded retained-page paths."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from tests import test_baseline_http_routes as routes
from tests.test_baseline_http_approval import approval
from tests.test_baseline_http_routes import SCOPE, headers, settings
from tests.test_historical_source import stored

repository = routes.repository


def test_real_control_replay_and_changed_key(repository: Any) -> None:
    repository.save_job(stored())
    with TestClient(create_app(settings(), repository=repository)) as client:
        body = approval(client)
        published = client.post(SCOPE + "/approvals", json=body, headers=headers())
        assert published.status_code == 201
        control = {
            "expected_revision": 1,
            "idempotency_key": "control",
            "action": "FREEZE",
            "reason": "Synthetic control",
            "generation_id": None,
        }
        first = client.post(SCOPE + "/control", json=control, headers=headers())
        assert first.status_code == 200, first.text
        result = first.json()
        assert set(result) == {"scope", "receipt"}
        assert set(result["receipt"]) == {
            "operation_id",
            "action",
            "revision",
            "actor",
            "occurred_at",
            "generation_id",
        }
        assert result["scope"]["frozen"] is True and result["scope"]["control_revision"] == 2
        assert result["receipt"]["actor"] == "static-admin"
        replay = client.post(SCOPE + "/control", json=control, headers=headers())
        assert replay.status_code == 200 and replay.json() == result
        changed = client.post(
            SCOPE + "/control", json=dict(control, action="UNFREEZE"), headers=headers()
        )
        assert (changed.status_code, changed.json()["error"]["code"]) == (
            409,
            "BASELINE_IDEMPOTENCY_CONFLICT",
        )
        frozen = client.post(
            SCOPE + "/approvals",
            json=dict(body, expected_revision=2, idempotency_key="new"),
            headers=headers(),
        )
        assert (frozen.status_code, frozen.json()["error"]["code"]) == (409, "BASELINE_FROZEN")


@pytest.mark.parametrize(
    "updates",
    [
        {"generation_id": "invalid"},
        {"actor": "injected"},
        {"expected_revision": True},
        {"action": "ROLLBACK"},
        {"action": "REVOKE", "generation_id": "00000000-0000-0000-0000-000000000001"},
    ],
)
def test_control_validation(repository: Any, updates: dict[str, Any]) -> None:
    body = {
        "expected_revision": 0,
        "idempotency_key": "x",
        "action": "FREEZE",
        "reason": "x",
        "generation_id": None,
    }
    body.update(updates)
    with TestClient(create_app(settings(), repository=repository)) as client:
        response = client.post(SCOPE + "/control", json=body, headers=headers())
        assert (response.status_code, response.json()["error"]["code"]) == (422, "VALIDATION_ERROR")
