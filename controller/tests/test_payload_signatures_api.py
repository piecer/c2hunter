from typing import Any

from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def signature(identifier: str, *, enabled: bool, created_at: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "name": identifier,
        "description": "",
        "enabled": enabled,
        "version": 1,
        "created_at": created_at,
    }


def test_payload_signature_list_filters_sorts_and_paginates() -> None:
    repository = MemoryRepository()
    repository.save_payload_signature(signature("older", enabled=True, created_at="2026-01-01"))
    repository.save_payload_signature(signature("newer", enabled=True, created_at="2026-01-02"))
    repository.save_payload_signature(signature("disabled", enabled=False, created_at="2026-01-03"))
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get(
        "/api/v1/payload-signatures",
        params={"enabled": True, "page": 1, "page_size": 1},
    )

    assert response.status_code == 200
    assert response.json() == {
        "items": [signature("newer", enabled=True, created_at="2026-01-02")],
        "page": 1,
        "page_size": 1,
        "total": 2,
    }


def test_payload_signature_update_and_delete_not_found_contracts() -> None:
    repository = MemoryRepository()
    repository.save_payload_signature(signature("signature", enabled=True, created_at="2026-01-01"))
    client = TestClient(create_app(Settings(environment="test"), repository))

    updated = client.patch("/api/v1/payload-signatures/signature", json={"name": "renamed"})
    missing_update = client.patch("/api/v1/payload-signatures/missing", json={"enabled": False})
    missing_delete = client.delete("/api/v1/payload-signatures/missing")
    deleted = client.delete("/api/v1/payload-signatures/signature")

    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert missing_update.status_code == 404
    assert missing_update.json()["error"]["code"] == "SIGNATURE_NOT_FOUND"
    assert missing_delete.status_code == 404
    assert deleted.json() == {"deleted": True, "signature_id": "signature"}


class ConcurrentDeleteRepository(MemoryRepository):
    def delete_payload_signature(self, signature_id: str) -> bool:
        self.payload_signatures.pop(signature_id, None)
        return False


def test_payload_signature_delete_handles_concurrent_removal() -> None:
    repository = ConcurrentDeleteRepository()
    repository.save_payload_signature(signature("signature", enabled=True, created_at="2026-01-01"))
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.delete("/api/v1/payload-signatures/signature")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "SIGNATURE_NOT_FOUND"
