import uuid
from datetime import UTC, datetime
from typing import Any

from c2hunter_analysis.domain import AllowlistEntry
from fastapi import APIRouter, Query, Response

from .api_errors import ApiError
from .repositories import Repository
from .schemas import AllowlistCreate


def _page(items: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "page": page,
        "page_size": page_size,
        "total": len(items),
    }


def allowlist_router(repository: Repository) -> APIRouter:
    """Build allowlist CRUD routes and candidate suppression side effects."""
    router = APIRouter(prefix="/api/v1/allowlist", tags=["allowlist"])

    @router.post("", status_code=201)
    def create_allowlist_entry(payload: AllowlistCreate) -> dict[str, Any]:
        created_at = datetime.now(UTC)
        entry = {
            "id": str(uuid.uuid4()),
            **payload.model_dump(mode="json"),
            "created_at": created_at.isoformat(),
        }
        saved = repository.save_allowlist(entry)
        policy = AllowlistEntry.from_mapping(saved)
        for job_id, candidates in repository.list_candidate_sets().items():
            changed = False
            for candidate in candidates:
                metrics = [
                    evidence.get("metrics", {})
                    for evidence in candidate.get("evidence", [])
                    if isinstance(evidence, dict)
                ]
                if policy.matches_metrics(str(candidate["candidate_ip"]), metrics, created_at):
                    candidate.update(
                        {
                            "excluded": True,
                            "exclude_reason": f"Allowlist: {saved['description']}",
                            "suppressed_at": created_at.isoformat(),
                            "suppressed_by_allowlist_id": saved["id"],
                            "updated_at": created_at.isoformat(),
                        }
                    )
                    changed = True
            if changed:
                repository.save_candidates(job_id, candidates)
                job = repository.get_job(job_id)
                if job is not None:
                    job["candidate_count"] = sum(
                        not candidate.get("excluded", False) for candidate in candidates
                    )
                    repository.save_job_metadata(job)
        return saved

    @router.get("")
    def list_allowlist(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        type: str | None = None,
        enabled: bool | None = None,
        sort: str = "value",
    ) -> dict[str, Any]:
        items = repository.list_allowlist()
        if type:
            items = [item for item in items if item["type"] == type]
        if enabled is not None:
            items = [item for item in items if item["enabled"] is enabled]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"value", "type", "created_at", "expires_at"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        return _page(items, page, page_size)

    @router.delete("/{entry_id}", status_code=204)
    def delete_allowlist_entry(entry_id: str) -> Response:
        if not repository.delete_allowlist(entry_id):
            raise ApiError(404, "ALLOWLIST_NOT_FOUND", "allowlist 항목을 찾을 수 없습니다")
        return Response(status_code=204)

    return router
