import uuid
from typing import Any

from fastapi import APIRouter, Query

from .api_errors import ApiError
from .repositories import Repository
from .schemas import SensorGroupCreate


def _page(items: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "page": page,
        "page_size": page_size,
        "total": len(items),
    }


def sensor_group_router(repository: Repository) -> APIRouter:
    """Build sensor-group routes against the configured repository boundary."""
    router = APIRouter(prefix="/api/v1/sensor-groups", tags=["sensor-groups"])

    @router.post("", status_code=201)
    def create_group(payload: SensorGroupCreate) -> dict[str, Any]:
        missing = [
            sensor_id
            for sensor_id in payload.sensor_ids
            if repository.get_sensor(sensor_id) is None
        ]
        if missing:
            raise ApiError(
                404,
                "SENSOR_NOT_FOUND",
                "그룹 멤버 센서를 찾을 수 없습니다",
                {"sensor_ids": missing},
            )
        return repository.create_group({"id": str(uuid.uuid4()), **payload.model_dump()})

    @router.get("")
    def list_groups(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        name: str | None = None,
        sort: str = "name",
    ) -> dict[str, Any]:
        items = repository.list_groups()
        if name:
            items = [item for item in items if name.lower() in item["name"].lower()]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"name", "id"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: item[field], reverse=descending)
        return _page(items, page, page_size)

    return router
