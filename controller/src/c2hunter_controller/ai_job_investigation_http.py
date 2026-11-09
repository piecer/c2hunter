"""Opt-in authenticated JOB transport. No source preview or implicit DDL."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from .ai_investigation_contract import InvestigationError
from .ai_investigation_gateway import InvestigationGatewayError, InvestigationModelGateway
from .ai_investigation_http import (
    ERRORS,
    InvestigationRoute,
    TransportError,
    _identifier,
    _integer,
    _owner,
    body,
    encoded,
)
from .ai_investigation_store import InvestigationStorageError, InvestigationStoreError
from .ai_job_investigation import JobInvestigationService
from .ai_job_investigation_runtime_schema import JobCapabilities
from .ai_job_investigation_schema import JobRequest, Reason
from .ai_job_investigation_store import JobInvestigationRunStore, initialize_job_investigation_store
from .repositories import MemoryRepository, SQLiteRepository
from .security import SecurityError

BASE = "/api/v1/analysis-jobs/{job_id}/ai-job-investigations"
JOB_ERRORS = ERRORS | {
    "JOB_DISABLED": (503, "Experimental JOB investigations are disabled"),
    "JOB_DISPATCH_UNSUPPORTED": (503, "An owned capable JOB dispatcher is required"),
    "POOL_EMPTY": (422, "No selectable observed peers"),
    "SOURCE_CHANGED": (409, "Investigation source changed"),
    "JOB_RESPONSE_LIMIT": (503, "JOB response exceeds byte limit"),
    "SOURCE_STORAGE_UNAVAILABLE": (503, "Investigation source storage is unavailable"),
}


def job_failure(
    request: Request, code: str, status: int | None = None, message: str | None = None
) -> Response:
    if code == "RESPONSE_TOO_LARGE":
        code = "JOB_RESPONSE_LIMIT"
    if status is None:
        code = code if code in JOB_ERRORS else "INTERNAL_ERROR"
        status, message = JOB_ERRORS[code]
    return encoded(
        {
            "error": {
                "code": code,
                "message": message,
                "details": None,
                "request_id": str(getattr(request.state, "request_id", ""))[:200],
            }
        },
        status,
    )


def configured_job_service(
    repository: Any, configured: object, *, enabled: bool, bootstrap_local: bool = False
) -> tuple[JobInvestigationService | None, str | None]:
    try:
        if bootstrap_local and isinstance(repository, MemoryRepository | SQLiteRepository):
            initialize_job_investigation_store(repository)
        store = JobInvestigationRunStore(repository)
    except InvestigationStoreError as exc:
        return None, exc.code if exc.code == "STORE_NOT_INITIALIZED" else "UNAVAILABLE"
    except InvestigationStorageError:
        return None, "UNAVAILABLE"
    try:
        gateway = InvestigationModelGateway.from_configured_gateway(configured)
    except InvestigationGatewayError:
        gateway = None
    # Preserve history even when disabled or the configured model is unavailable.
    return JobInvestigationService(repository, store, gateway, enabled=enabled), None


def job_investigation_router(
    service: JobInvestigationService | None, unavailable_reason: Callable[[], str | None]
) -> APIRouter:
    router = APIRouter(route_class=InvestigationRoute)

    def required() -> JobInvestigationService:
        if service is None:
            raise TransportError(unavailable_reason() or "UNAVAILABLE")
        return service

    async def call(request: Request, operation: Callable[[], Response]) -> Response:
        try:
            return await run_in_threadpool(operation)
        except SecurityError as exc:
            return job_failure(request, exc.code, exc.status, exc.message)
        except (TransportError, InvestigationError, InvestigationStoreError) as exc:
            return job_failure(request, exc.code)
        except InvestigationStorageError:
            return job_failure(request, "STORAGE_UNAVAILABLE")
        except Exception:
            return job_failure(request, "INTERNAL_ERROR")

    @router.get("/api/v1/ai-job-investigations/capabilities")
    async def capabilities(request: Request) -> Response:
        def operation() -> Response:
            _owner(request)
            reason: Reason | None = (
                service.unavailable_reason() if service is not None else "UNAVAILABLE"
            )
            return encoded(
                JobCapabilities(
                    availability="UNAVAILABLE" if reason else "CONFIGURED_NOT_PROBED",
                    dispatch_scope="UNAVAILABLE" if reason else "OWNED_CAPABLE_RUNTIME",
                    remote_server_allowed=bool(
                        service and service.gateway and service.gateway.server_allow_remote
                    ),
                    reason=reason,
                )
            )

        return await call(request, operation)

    @router.post(BASE)
    async def create(job_id: str, request: Request) -> Response:
        owner = _owner(request)
        _identifier(job_id)
        payload = await body(request, JobRequest)

        def operation() -> Response:
            run, created = required().admit(owner, job_id, payload)
            return encoded(run, 202 if created else 200)

        return await call(request, operation)

    @router.get(BASE)
    async def page(job_id: str, request: Request) -> Response:
        def operation() -> Response:
            owner = _owner(request)
            _identifier(job_id)
            limit = _integer(request, "limit", 1, 1)
            after = request.query_params.get("after", "")
            if after and (len(after) != 64 or any(c not in "0123456789abcdef" for c in after)):
                raise TransportError("INVALID_PAGE")
            rows = required().page(owner, job_id, after=after, limit=limit + 1)
            return encoded(
                dict(
                    items=[r.model_dump(mode="json") for r in rows[:limit]],
                    next_cursor=rows[limit - 1].id if len(rows) > limit else None,
                )
            )

        return await call(request, operation)

    def scoped(request: Request, job_id: str, run_id: str) -> tuple[JobInvestigationService, str]:
        owner = _owner(request)
        _identifier(job_id)
        _identifier(run_id)
        svc = required()
        if svc.store.get(owner, job_id, run_id) is None:
            raise TransportError("NOT_FOUND")
        return svc, owner

    @router.get(BASE + "/{run_id}")
    async def get(job_id: str, run_id: str, request: Request) -> Response:
        def operation() -> Response:
            svc, owner = scoped(request, job_id, run_id)
            return encoded(svc.get(owner, job_id, run_id))

        return await call(request, operation)

    @router.get(BASE + "/{run_id}/steps")
    async def steps(job_id: str, run_id: str, request: Request) -> Response:
        def operation() -> Response:
            svc, owner = scoped(request, job_id, run_id)
            limit = _integer(request, "limit", 10, 10)
            after = _integer(request, "after", 0, 24, 0)
            rows = svc.steps(owner, job_id, run_id, after=after, limit=limit + 1)
            return encoded(
                dict(
                    items=[r.model_dump(mode="json") for r in rows[:limit]],
                    next_cursor=rows[limit - 1].sequence if len(rows) > limit else None,
                )
            )

        return await call(request, operation)

    @router.get(BASE + "/{run_id}/evidence/{evidence_id}")
    async def evidence(job_id: str, run_id: str, evidence_id: str, request: Request) -> Response:
        def operation() -> Response:
            svc, owner = scoped(request, job_id, run_id)
            _identifier(evidence_id)
            value = svc.evidence(owner, job_id, run_id, evidence_id)
            if value is None:
                raise TransportError("NOT_FOUND")
            return encoded(value)

        return await call(request, operation)

    @router.post(BASE + "/{run_id}/cancel")
    async def cancel(job_id: str, run_id: str, request: Request) -> Response:
        def operation() -> Response:
            svc, owner = scoped(request, job_id, run_id)
            return encoded(svc.cancel(owner, job_id, run_id))

        return await call(request, operation)

    return router
