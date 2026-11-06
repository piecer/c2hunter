"""Uncertain selection is not a negative observation at the real HTTP boundary."""

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from c2hunter_controller.schemas import FlowRecord
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_http_runtime import (
    BASE,
    HEADERS,
    configured,
    request_from,
    settings,
)
from tests.test_ai_investigation_loop import structured_provider


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize(
    ("case", "status", "code"),
    [
        ("unknown", "UNAVAILABLE", "TARGET_SCOPE_UNAVAILABLE"),
        ("partial", "NOT_FOUND_IN_INSPECTED_SCOPE", "TARGET_NOT_FOUND_IN_INSPECTED_SCOPE"),
        ("absent", "NOT_OBSERVED", "TARGET_NOT_OBSERVED"),
    ],
)
def test_http_preview_and_admission_preserve_selection_uncertainty(
    tmp_path, backend, case, status, code
):
    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "scope.db")
    row = flow(
        direction="BIDIRECTIONAL" if case == "unknown" else "OUTBOUND",
        destination_ip="2001:db8::1" if case == "unknown" else "2001:db8::2",
    )
    source = job([FlowRecord.model_validate(row).model_dump(mode="json")])
    if case == "partial":
        source["status"] = "PARTIALLY_COMPLETED"
    repo.save_job(source)
    try:
        with structured_provider(lambda *_: None) as (gateway, calls):
            app = create_app(
                settings(), repo, ai_gateway=configured(gateway), local_ai_worker_enabled=True
            )
            with TestClient(app) as client:
                preview = client.post(
                    BASE + "/source-preview",
                    headers=HEADERS,
                    json={"target_ip": "2001:db8::1", "traffic_direction": "OUTBOUND"},
                )
                assert preview.status_code == 200, preview.text
                body = preview.json()
                assert body["status"] == status
                assert body["counts"]["matched"] == 0
                assert body["counts"]["scope_unavailable"] == (1 if case == "unknown" else 0)
                payload = {**request_from(body), "traffic_direction": "OUTBOUND"}
                rejected = client.post(BASE, headers=HEADERS, json=payload)
                assert rejected.status_code == 422, rejected.text
                assert rejected.json()["error"]["code"] == code
                assert client.get(BASE, headers=HEADERS).json()["items"] == []
                assert calls == []
    finally:
        repo.close()
