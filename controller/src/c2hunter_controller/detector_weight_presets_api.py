import uuid
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter

from .api_errors import ApiError
from .repositories import Repository
from .schemas import DetectorWeightPresetCreate, DetectorWeightPresetUpdate


def detector_weight_preset_router(repository: Repository) -> APIRouter:
    """Build detector-weight preset CRUD routes against a repository boundary."""
    router = APIRouter(
        prefix="/api/v1/detector-weight-presets",
        tags=["detector-weight-presets"],
    )

    @router.get("")
    def list_detector_weight_presets() -> dict[str, Any]:
        presets = repository.list_detector_weight_presets()
        presets.sort(key=lambda preset: (not bool(preset.get("is_default")), preset["name"]))
        return {"items": presets, "total": len(presets)}

    @router.post("", status_code=201)
    def create_detector_weight_preset(
        payload: DetectorWeightPresetCreate,
    ) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        data = payload.model_dump(exclude={"set_as_default"})
        return repository.save_detector_weight_preset(
            {
                **data,
                "id": str(uuid.uuid4()),
                "is_default": payload.set_as_default,
                "created_at": now,
                "updated_at": now,
            }
        )

    @router.patch("/{preset_id}")
    def update_detector_weight_preset(
        preset_id: str, payload: DetectorWeightPresetUpdate
    ) -> dict[str, Any]:
        updates = payload.model_dump(exclude_unset=True, exclude={"set_as_default"})
        updates["updated_at"] = datetime.now(UTC).isoformat()
        preset = repository.update_detector_weight_preset(
            preset_id,
            updates,
            set_as_default=payload.set_as_default is True,
        )
        if preset is None:
            raise ApiError(
                404,
                "DETECTOR_WEIGHT_PRESET_NOT_FOUND",
                "가중치 preset을 찾을 수 없습니다",
            )
        return preset

    @router.delete("/{preset_id}")
    def delete_detector_weight_preset(preset_id: str) -> dict[str, Any]:
        if not repository.delete_detector_weight_preset(preset_id):
            raise ApiError(
                404,
                "DETECTOR_WEIGHT_PRESET_NOT_FOUND",
                "가중치 preset을 찾을 수 없습니다",
            )
        return {"deleted": True, "preset_id": preset_id}

    return router
