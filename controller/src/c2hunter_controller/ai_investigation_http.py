"""Authenticated, byte-bounded transport for the investigation service.

Producer DTOs own the wire schema. This module never calls the model, exposes
saved snapshots/claims, or silently initializes a production SQL schema.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, Request
from fastapi.routing import APIRoute
from pydantic import BaseModel, ValidationError
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from .ai_investigation import InvestigationService
from .ai_investigation_contract import InvestigationError, InvestigationScope, canonical_bytes
from .ai_investigation_schema import InvestigationCapabilities, InvestigationRequest
from .ai_investigation_store import InvestigationStorageError, InvestigationStoreError
from .security import Principal, Role, SecurityError, require_role

REQUEST_LIMIT = 16 * 1024
RESPONSE_LIMIT = 256 * 1024
BASE = "/api/v1/analysis-jobs/{job_id}/ai-investigations"

# Closed codes only; exception strings and storage/provider details never cross HTTP.
ERRORS = {
    "INVALID_REQUEST": (422, "Invalid investigation request"),
    "INVALID_HEADER": (422, "Invalid investigation identifier"),
    "INVALID_PAGE": (422, "Invalid investigation page"),
    "INVALID_SOURCE_ARGUMENTS": (422, "Invalid investigation source scope"),
    "BODY_TOO_LARGE": (413, "Investigation request exceeds byte limit"),
    "RESPONSE_TOO_LARGE": (503, "Investigation response exceeds byte limit"),
    "NOT_FOUND": (404, "Investigation resource not found"),
    "SOURCE_NOT_FOUND": (404, "Investigation source not found"),
    "SOURCE_CHANGED": (409, "Investigation source changed; preview again"),
    "SOURCE_STATE": (409, "Investigation source is not complete"),
    "SOURCE_UNAVAILABLE": (409, "Investigation source is unavailable"),
    "SOURCE_INVALID": (422, "Investigation source is invalid"),
    "SOURCE_LIMIT": (413, "Investigation source exceeds limits"),
    "TARGET_NOT_OBSERVED": (422, "Target was not observed in this source scope"),
    "TARGET_SCOPE_UNAVAILABLE": (
        422,
        "Target scope cannot be determined from available observations",
    ),
    "TARGET_NOT_FOUND_IN_INSPECTED_SCOPE": (
        422,
        "Target was not found in the inspected source scope",
    ),
    "REMOTE_NOT_ALLOWED": (403, "Remote investigation provider is not allowed"),
    "IDEMPOTENCY_CONFLICT": (409, "Investigation idempotency key conflicts"),
    "SOURCE_BUSY": (429, "Investigation preparation is busy"),
    "OWNER_QUEUE_FULL": (429, "Investigation owner queue is full"),
    "QUEUE_FULL": (429, "Investigation queue is full"),
    "RETENTION_FULL": (429, "Investigation retention is full"),
    "STORE_BUSY": (503, "Investigation storage is busy"),
    "UNAVAILABLE": (503, "Investigation capability is unavailable"),
    "STORE_NOT_INITIALIZED": (503, "Investigation storage migration is required"),
    "STORAGE_UNAVAILABLE": (503, "Investigation storage is unavailable"),
    "STORE_CORRUPT": (503, "Investigation saved data is unavailable"),
    "INTERNAL_ERROR": (500, "Investigation request failed"),
}


class TransportError(Exception):
    def __init__(self, code: str) -> None:
        self.code = code


def investigation_path(path: str) -> bool:
    parts = path.strip("/").split("/")
    return (
        len(parts) >= 3
        and parts[:2] == ["api", "v1"]
        and parts[2] in {"ai-investigations", "ai-job-investigations"}
    ) or (
        len(parts) >= 5
        and parts[:3] == ["api", "v1", "analysis-jobs"]
        and parts[4] in {"ai-investigations", "ai-job-investigations"}
    )


def owner_key(principal: Principal) -> str:
    # subject is the authenticator's exact stable identity, NOT bearer material,
    # role, a fallback anonymous name, or an actor submitted in the request.
    return hashlib.sha256(
        b"c2hunter:ai-investigation:owner:v1\x00" + principal.subject.encode("utf-8")
    ).hexdigest()


def _owner(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    if not isinstance(principal, Principal):
        raise SecurityError(401, "AUTH_TOKEN_REQUIRED", "Bearer authentication required")
    require_role(principal, Role.ANALYST)
    return owner_key(principal)


def _identifier(value: str) -> str:
    if not (1 <= len(value) <= 200 and value.isascii() and all(32 < ord(c) < 127 for c in value)):
        raise TransportError("INVALID_HEADER")
    return value


def encoded(value: Any, status: int = 200, *, headers: dict[str, str] | None = None) -> Response:
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    raw = canonical_bytes(value)
    if len(raw) > RESPONSE_LIMIT:
        raise TransportError("RESPONSE_TOO_LARGE")
    return Response(raw, status_code=status, media_type="application/json", headers=headers)


async def bounded_body(request: Request) -> bytes:
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isascii() or not length.isdecimal():
            raise TransportError("INVALID_REQUEST")
        if len(length) > 8 or int(length) > REQUEST_LIMIT:
            raise TransportError("BODY_TOO_LARGE")
    raw = bytearray()
    async for chunk in request.stream():
        if len(raw) + len(chunk) > REQUEST_LIMIT:
            raise TransportError("BODY_TOO_LARGE")
        raw.extend(chunk)
    return bytes(raw)


async def body(request: Request, model: type[BaseModel]) -> BaseModel:
    try:
        return model.model_validate_json(request.state.investigation_body)
    except (ValidationError, ValueError, UnicodeError):
        raise TransportError("INVALID_REQUEST") from None


def _integer(request: Request, name: str, default: int, maximum: int, minimum: int = 1) -> int:
    text = request.query_params.get(name, str(default))
    if not text.isascii() or not text.isdecimal() or len(text) > 3:
        raise TransportError("INVALID_PAGE")
    value = int(text)
    if not minimum <= value <= maximum:
        raise TransportError("INVALID_PAGE")
    return value


class InvestigationRoute(APIRoute):
    def get_route_handler(self) -> Callable[..., Any]:
        original = super().get_route_handler()

        async def handle(request: Request) -> Response:
            try:
                _owner(request)
                request.state.investigation_body = await bounded_body(request)
                return await original(request)
            except SecurityError as exc:
                return failure(request, exc.code, exc.status, exc.message)
            except TransportError as exc:
                return failure(request, exc.code)
            except Exception:
                return failure(request, "INTERNAL_ERROR")

        return handle


def investigation_router(
    service: InvestigationService | None,
    dispatch_available: Callable[[], bool],
    unavailable_reason: Callable[[], str | None],
) -> APIRouter:
    router = APIRouter(route_class=InvestigationRoute)

    def required() -> InvestigationService:
        if service is None:
            reason = unavailable_reason()
            raise TransportError(
                "STORE_NOT_INITIALIZED" if reason == "STORE_NOT_INITIALIZED" else "UNAVAILABLE"
            )
        return service

    async def call(request: Request, operation: Callable[[], Any]) -> Response:
        try:
            return await run_in_threadpool(operation)
        except SecurityError as exc:
            return failure(request, exc.code, exc.status, exc.message)
        except (TransportError, InvestigationError, InvestigationStoreError) as exc:
            return failure(request, exc.code)
        except InvestigationStorageError:
            return failure(request, "STORAGE_UNAVAILABLE")
        except Exception:
            return failure(request, "INTERNAL_ERROR")

    @router.get("/api/v1/ai-investigations/capabilities")
    async def capabilities(request: Request) -> Response:
        def operation() -> Response:
            _owner(request)
            available = service is not None and service.gateway is not None and dispatch_available()
            caps = (
                service.capabilities()
                if available and service is not None
                else InvestigationCapabilities(
                    availability="UNAVAILABLE", remote_server_allowed=False
                )
            )
            reason = unavailable_reason() if not available else None
            return encoded(
                caps,
                headers={"x-investigation-unavailable-reason": reason or "DISPATCH_UNAVAILABLE"}
                if not available
                else None,
            )

        return await call(request, operation)

    @router.post(BASE + "/source-preview")
    async def preview(job_id: str, request: Request) -> Response:
        return await submit(job_id, request, preview_only=True)

    @router.post(BASE)
    async def create(job_id: str, request: Request) -> Response:
        return await submit(job_id, request, preview_only=False)

    async def submit(job_id: str, request: Request, *, preview_only: bool) -> Response:
        try:
            owner = _owner(request)
            _identifier(job_id)
            payload = await body(
                request, InvestigationScope if preview_only else InvestigationRequest
            )
        except SecurityError as exc:
            return failure(request, exc.code, exc.status, exc.message)
        except TransportError as exc:
            return failure(request, exc.code)

        def operation() -> Response:
            svc = required()
            if preview_only:
                return encoded(svc.source_preview(owner, job_id, payload))
            if not isinstance(payload, InvestigationRequest):
                raise TransportError("INVALID_REQUEST")
            # Exact replay remains available even when dispatch/provider is down.
            if not dispatch_available():
                prior = svc.store.lookup(
                    owner_id=owner,
                    job_id=job_id,
                    idempotency_key=payload.idempotency_key,
                    request_json=canonical_bytes(payload.model_dump(mode="json")),
                )
                if prior is None:
                    raise TransportError("UNAVAILABLE")
            run, created = svc.admit(owner, job_id, payload)
            return encoded(run, 202 if created else 200)

        return await call(request, operation)

    @router.get(BASE)
    async def page(job_id: str, request: Request) -> Response:
        def operation() -> Response:
            owner = _owner(request)
            _identifier(job_id)
            limit = _integer(request, "limit", 5, 5)
            after = request.query_params.get("after", "")
            if after and (len(after) != 64 or any(c not in "0123456789abcdef" for c in after)):
                raise TransportError("INVALID_PAGE")
            rows = required().page(owner, job_id, after=after, limit=limit + 1)
            return encoded(
                {
                    "items": [r.model_dump(mode="json") for r in rows[:limit]],
                    "next_cursor": rows[limit - 1].id if len(rows) > limit else None,
                }
            )

        return await call(request, operation)

    def scoped(request: Request, job_id: str, run_id: str) -> tuple[InvestigationService, str]:
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
                {
                    "items": [r.model_dump(mode="json") for r in rows[:limit]],
                    "next_cursor": rows[limit - 1].sequence if len(rows) > limit else None,
                }
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


def failure(
    request: Request, code: str, status: int | None = None, message: str | None = None
) -> Response:
    parts = request.scope.get("path", "").strip("/").split("/")
    if (len(parts) >= 3 and parts[:3] == ["api", "v1", "ai-job-investigations"]) or (
        len(parts) >= 5
        and parts[:3] == ["api", "v1", "analysis-jobs"]
        and parts[4] == "ai-job-investigations"
    ):
        from .ai_job_investigation_http import job_failure

        return job_failure(request, code, status, message)
    if status is None:
        code = code if code in ERRORS else "INTERNAL_ERROR"
        status, message = ERRORS[code]
    # Client-provided request IDs must not bypass the response byte ceiling.
    request_id = str(getattr(request.state, "request_id", ""))[:200]
    return encoded(
        {"error": {"code": code, "message": message, "details": None, "request_id": request_id}},
        status,
    )
