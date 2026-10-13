"""Closed historical AI transport projections; stored evidence stays private."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Query, Request
from pydantic import ValidationError

from . import historical_ai as dto
from . import historical_ai_storage as custody
from .api_errors import ApiError
from .historical_baseline_api import _ERROR_STATUS, _body, _invalid
from .schemas import AIAnalysisRunCreate
from .security import Role

if TYPE_CHECKING:
    from .historical_baseline_api import BaselineTransport
    from .repositories import Repository

RUN_FIELDS = frozenset(
    {
        "id",
        "analysis_job_id",
        "dataset_id",
        "idempotency_key",
        "status",
        "progress_percent",
        "candidate_limit",
        "candidate_ids",
        "provider",
        "model_name",
        "prompt_name",
        "prompt_version",
        "prompt_hash",
        "input_schema_version",
        "output_schema_version",
        "created_by",
        "created_at",
        "updated_at",
        "transitions",
        "analysis_kind",
        "language",
        "discovery_mode",
        "baseline_mode",
        "selection_summary",
        "baseline_summary",
        "completed_at",
        "error_code",
        "error_message",
    }
)


def public_run(run: dict[str, Any]) -> dict[str, Any]:
    if custody.historical_marker(run):
        view, _ = custody.materialize_historical_run(run)
        public = {key: view[key] for key in RUN_FIELDS if key in view}
        public["candidate_count"] = len(view["candidate_ids"])
        return public
    return {
        **{
            key: value
            for key, value in run.items()
            if key not in {"ddos_input", "selection_inventory"}
        },
        "candidate_count": len(run.get("candidate_ids", [])),
    }


def transport_error(error: Exception) -> ApiError:
    code = getattr(error, "code", "BASELINE_STORAGE_UNAVAILABLE")
    if code in {"HISTORICAL_SNAPSHOT_INVALID", "BASELINE_STORAGE_UNAVAILABLE"}:
        return ApiError(503, "BASELINE_STORAGE_UNAVAILABLE", "기준선 저장소를 사용할 수 없습니다")
    if code == "BASELINE_MODE_NOT_ALLOWED":
        return ApiError(422, code, "이 분석 모드에서는 기준선을 사용할 수 없습니다")
    if code == "BASELINE_RUN_SNAPSHOT_LIMIT":
        return ApiError(413, code, "기준선 실행 근거 제한을 초과했습니다")
    if code == "VALIDATION_ERROR":
        return _invalid()
    if code in _ERROR_STATUS:
        return ApiError(_ERROR_STATUS[code], code, "기준선 요청을 처리할 수 없습니다")
    return ApiError(503, "BASELINE_STORAGE_UNAVAILABLE", "기준선 저장소를 사용할 수 없습니다")


@contextmanager
def domain_errors() -> Iterator[None]:
    try:
        yield
    except (dto.HistoricalAIError, *custody.HISTORICAL_STORAGE_ERRORS) as error:
        raise transport_error(error) from None


def require_analyst(request: Request) -> None:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise ApiError(403, "BASELINE_AUTH_REQUIRED", "인증이 필요합니다")
    if principal.role < Role.ANALYST:
        raise ApiError(403, "INSUFFICIENT_ROLE", "ANALYST 역할이 필요합니다")


async def create_payload(request: Request) -> AIAnalysisRunCreate:
    body = await _body(request)
    historical = (
        body.get("baseline_mode", "off") != "off" or body.get("baseline_reference") is not None
    )
    if historical:
        require_analyst(request)
        if body.get("baseline_mode") == "historical" and (
            body.get("analysis_kind", "C2") != "C2"
            or body.get("discovery_mode", "legacy") != "shadow"
        ):
            raise transport_error(dto.HistoricalAIError("BASELINE_MODE_NOT_ALLOWED"))
        try:
            body = dto.FrozenAIAnalysisRunCreate.model_validate(body).to_mapping()
        except (ValueError, TypeError):
            raise _invalid() from None
    try:
        return AIAnalysisRunCreate.model_validate(body)
    except ValidationError:
        raise _invalid() from None


def saved_page(run: dict[str, Any], field: str, offset: int, limit: int) -> dict[str, Any]:
    if not custody.historical_marker(run):
        raise ApiError(404, "HISTORICAL_BASELINE_NOT_FOUND", "저장된 기준선 근거가 없습니다")
    if field not in {"baseline_comparisons", "baseline_sources"}:
        raise ValueError("unsupported saved page")
    view, _ = custody.materialize_historical_run(run)
    rows = view[field]
    items = rows[offset : offset + limit]
    next_offset = offset + len(items)
    return {
        "items": items,
        "total": len(rows),
        "offset": offset,
        "limit": limit,
        "next_offset": next_offset if next_offset < len(rows) else None,
    }


def saved_pages_router(repository: Repository, transport: BaselineTransport) -> APIRouter:
    router = APIRouter(prefix="/api/v1/ai-runs")

    def read(run_id: str, field: str, offset: int, limit: int) -> dict[str, Any]:
        try:
            run = repository.get_ai_run(run_id)
            if run is None:
                raise ApiError(404, "AI_RUN_NOT_FOUND", "AI 분석 Run을 찾을 수 없습니다")
            return saved_page(run, field, offset, limit)
        except (dto.HistoricalAIError, *custody.HISTORICAL_STORAGE_ERRORS) as error:
            raise transport_error(error) from None

    @router.get("/{run_id}/baseline-comparisons")
    async def comparisons(
        run_id: str,
        request: Request,
        offset: int = Query(0, ge=0, le=128),
        limit: int = Query(20, ge=1, le=50),
    ) -> dict[str, Any]:
        require_analyst(request)
        result: dict[str, Any] = await transport.call(
            read, run_id, "baseline_comparisons", offset, limit
        )
        return result

    @router.get("/{run_id}/baseline-sources")
    async def sources(
        run_id: str,
        request: Request,
        offset: int = Query(0, ge=0, le=16),
        limit: int = Query(20, ge=1, le=50),
    ) -> dict[str, Any]:
        require_analyst(request)
        result: dict[str, Any] = await transport.call(
            read, run_id, "baseline_sources", offset, limit
        )
        return result

    return router
