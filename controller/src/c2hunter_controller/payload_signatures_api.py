from typing import Any

from fastapi import APIRouter, Query

from .api_errors import ApiError
from .repositories import Repository
from .schemas import PayloadSignatureUpdate


def _page(items: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "page": page,
        "page_size": page_size,
        "total": len(items),
    }


def payload_signature_router(repository: Repository) -> APIRouter:
    """Build payload-signature routes against the configured repository boundary."""
    router = APIRouter(prefix="/api/v1/payload-signatures", tags=["payload-signatures"])

    @router.get("")
    def list_payload_signatures(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        signatures = repository.list_payload_signatures()
        if enabled is not None:
            signatures = [
                signature for signature in signatures if signature.get("enabled") is enabled
            ]
        signatures.sort(key=lambda item: str(item["created_at"]), reverse=True)
        return _page(signatures, page, page_size)

    @router.patch("/{signature_id}")
    def update_payload_signature(
        signature_id: str, payload: PayloadSignatureUpdate
    ) -> dict[str, Any]:
        signature = repository.get_payload_signature(signature_id)
        if signature is None:
            raise ApiError(404, "SIGNATURE_NOT_FOUND", "서명을 찾을 수 없습니다")
        changes = payload.model_dump(exclude_unset=True)
        updated = {**signature, **changes}
        if "version" not in changes:
            updated["version"] = int(signature.get("version", 1)) + 1
        return repository.save_payload_signature(updated)

    @router.delete("/{signature_id}")
    def delete_payload_signature(signature_id: str) -> dict[str, Any]:
        if repository.get_payload_signature(signature_id) is None:
            raise ApiError(404, "SIGNATURE_NOT_FOUND", "서명을 찾을 수 없습니다")
        if not repository.delete_payload_signature(signature_id):
            raise ApiError(404, "SIGNATURE_NOT_FOUND", "서명을 찾을 수 없습니다")
        return {"deleted": True, "signature_id": signature_id}

    return router
