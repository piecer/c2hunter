"""Account wire API. Blocking store operations never run on the event loop."""

from __future__ import annotations

import threading
from typing import Any, Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictStr, ValidationError
from starlette.concurrency import run_in_threadpool

from .auth_browser import PRELOGIN_COOKIE, SESSION_COOKIE, prelogin, proof, set_cookie
from .auth_http import error_response
from .auth_models import Actor, AuthError
from .auth_store import AuthStore
from .config import Settings
from .security import Role

_HASH_ADMISSION = threading.BoundedSemaphore(2)


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    username: StrictStr
    password: StrictStr


class EmptyBody(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PasswordBody(EmptyBody):
    current_password: StrictStr
    new_password: StrictStr


class CreateBody(LoginBody):
    role: Literal["VIEWER", "ANALYST", "ADMIN"]


class UpdateBody(EmptyBody):
    role: Literal["VIEWER", "ANALYST", "ADMIN"] | None = None
    active: bool | None = None


class ResetBody(EmptyBody):
    password: StrictStr


class RevokeBody(EmptyBody):
    session_id: StrictStr | None = None


class Page(EmptyBody):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=10000000)


class AuditPage(Page):
    limit: int = Field(default=50, ge=1, le=1000)
    user_id: StrictStr | None = None
    action: StrictStr | None = None
    outcome: StrictStr | None = None
    target: StrictStr | None = None
    since: float | None = Field(default=None, allow_inf_nan=False)
    until: float | None = Field(default=None, allow_inf_nan=False)


def query_model(request: Request, model: type[BaseModel]) -> dict[str, Any]:
    data: dict[str, Any] = dict(request.query_params)
    try:
        if len(data) != len(request.query_params.multi_items()):
            raise ValueError("duplicate query")
        for name in ("limit", "offset"):
            if name in data:
                data[name] = int(data[name])
        for name in ("since", "until"):
            if name in data:
                data[name] = float(data[name])
        return model.model_validate(data).model_dump(exclude_none=True)
    except (ValidationError, ValueError):
        raise AuthError("VALIDATION_ERROR", 422) from None


async def json_model(request: Request, model: type[BaseModel]) -> Any:
    try:
        return model.model_validate(await request.json())
    except (ValidationError, ValueError, UnicodeError):
        raise AuthError("VALIDATION_ERROR", 422) from None


class HashAdmissionError(AuthError):
    def __init__(self) -> None:
        super().__init__("RATE_LIMIT_EXCEEDED", 429)


async def expensive(operation: Any, *args: Any, **kwargs: Any) -> Any:
    if not _HASH_ADMISSION.acquire(blocking=False):
        raise HashAdmissionError()
    try:
        return await run_in_threadpool(operation, *args, **kwargs)
    finally:
        _HASH_ADMISSION.release()


def account_router(settings: Settings, store: AuthStore | None) -> APIRouter:
    router = APIRouter(prefix="/api/v1")
    secure = not (settings.auth_public_origin or "").startswith("http://")

    def require_store() -> AuthStore:
        if not settings.account_auth_enabled:
            raise AuthError("ACCOUNT_LOGIN_DISABLED", 404)
        if store is None:
            raise AuthError("ACCOUNT_SETUP_REQUIRED")
        return store

    @router.get("/auth/csrf")
    async def csrf(request: Request, response: Response) -> dict[str, Any]:
        if not settings.account_auth_enabled:
            return {
                "csrf_token": None,
                "account_login_enabled": False,
                "setup_required": False,
                "dev_login_enabled": settings.dev_login_enabled,
            }
        require_store()
        cookie, token = prelogin(request.state.auth_key)
        set_cookie(response, PRELOGIN_COOKIE, cookie, secure=secure, age=600)
        return {
            "csrf_token": token,
            "account_login_enabled": True,
            "setup_required": False,
            "dev_login_enabled": False,
        }

    @router.post("/auth/login")
    async def login(request: Request, response: Response) -> dict[str, Any]:
        active_store = require_store()
        body = await json_model(request, LoginBody)
        try:
            result = await expensive(
                active_store.login,
                body.username,
                body.password,
                prior_token=request.state.auth_cookie,
                source_ip=request.state.auth_source_ip,
                request_id=request.state.request_id,
            )
        except HashAdmissionError:
            await run_in_threadpool(
                active_store.record_event,
                Actor(auth_kind="unauthenticated"),
                "auth.login_limited",
                "auth",
                "denied",
                request_id=request.state.request_id,
                source_ip=request.state.auth_source_ip,
                status=429,
                details={"reason": "rate_limited"},
            )
            raise
        set_cookie(response, SESSION_COOKIE, result.token, secure=secure, age=43200)
        set_cookie(response, PRELOGIN_COOKIE, "", secure=secure, age=0)
        return {
            "user": result.user.to_dict(),
            "session_id": result.session_id,
            "identity_scope": result.identity_scope,
            "csrf_token": proof(request.state.auth_key, "session-csrf", result.token),
        }

    @router.get("/auth/me")
    async def me(request: Request) -> dict[str, Any]:
        active_store = require_store()
        available = await run_in_threadpool(active_store.ready)
        session = request.state.auth_session
        if session is None:
            principal = request.state.principal
            return {
                "user": None,
                "principal": {"subject": principal.subject, "role": principal.role.name},
                "csrf_token": None,
                "session_id": None,
                "identity_scope": "legacy:" + principal.subject,
                "audit_available": available,
                "auth_kind": "bearer",
            }
        return {
            "user": session.user.to_dict(),
            "session_id": session.session_id,
            "csrf_token": proof(request.state.auth_key, "session-csrf", request.state.auth_cookie),
            "identity_scope": session.identity_scope,
            "audit_available": available,
            "auth_kind": "session",
        }

    def empty_response(*, expire: bool = False) -> Response:
        response = Response(status_code=204)
        if expire:
            set_cookie(response, SESSION_COOKIE, "", secure=secure, age=0)
        return response

    @router.post("/auth/logout")
    async def logout(request: Request) -> Response:
        active_store = require_store()
        await json_model(request, EmptyBody)
        await run_in_threadpool(
            active_store.logout, request.state.auth_cookie, request_id=request.state.request_id
        )
        return empty_response(expire=True)

    @router.post("/auth/password")
    async def password(request: Request) -> Response:
        active_store = require_store()
        body = await json_model(request, PasswordBody)
        await expensive(
            active_store.change_password,
            request.state.auth_cookie,
            body.current_password,
            body.new_password,
            request_id=request.state.request_id,
        )
        return empty_response(expire=True)

    @router.get("/auth/sessions")
    async def sessions(request: Request) -> dict[str, Any]:
        return await run_in_threadpool(
            require_store().list_sessions, request.state.auth_cookie, **query_model(request, Page)
        )

    @router.post("/auth/sessions/revoke")
    async def revoke(request: Request) -> Response:
        active_store = require_store()
        body = await json_model(request, RevokeBody)
        expire = await run_in_threadpool(
            active_store.revoke_sessions,
            request.state.auth_cookie,
            session_id=body.session_id,
            request_id=request.state.request_id,
        )
        return empty_response(expire=expire)

    @router.get("/admin/users")
    async def users(request: Request) -> dict[str, Any]:
        return await run_in_threadpool(
            require_store().list_users, request.state.auth_cookie, **query_model(request, Page)
        )

    @router.post("/admin/users", status_code=201)
    async def create(request: Request) -> dict[str, Any]:
        active_store = require_store()
        body = await json_model(request, CreateBody)
        user = await expensive(
            active_store.create_user,
            request.state.auth_cookie,
            body.username,
            body.password,
            Role[body.role],
            request_id=request.state.request_id,
        )
        return user.to_dict()

    @router.patch("/admin/users/{user_id}")
    async def update(user_id: str, request: Request) -> dict[str, Any]:
        active_store = require_store()
        body = await json_model(request, UpdateBody)
        if not body.model_fields_set or any(
            getattr(body, name) is None for name in body.model_fields_set
        ):
            raise AuthError("VALIDATION_ERROR", 422)
        user = await run_in_threadpool(
            active_store.update_user,
            request.state.auth_cookie,
            user_id,
            role=Role[body.role] if body.role else None,
            active=body.active,
            request_id=request.state.request_id,
        )
        return user.to_dict()

    @router.post("/admin/users/{user_id}/reset-password")
    async def reset(user_id: str, request: Request) -> Response:
        active_store = require_store()
        body = await json_model(request, ResetBody)
        await expensive(
            active_store.reset_password,
            request.state.auth_cookie,
            user_id,
            body.password,
            request_id=request.state.request_id,
        )
        return empty_response()

    @router.post("/admin/users/{user_id}/revoke-sessions")
    async def revoke_user(user_id: str, request: Request) -> Response:
        active_store = require_store()
        await json_model(request, EmptyBody)
        await run_in_threadpool(
            active_store.revoke_user_sessions,
            request.state.auth_cookie,
            user_id,
            request_id=request.state.request_id,
        )
        return empty_response()

    @router.get("/auth/activity")
    async def activity(request: Request) -> dict[str, Any]:
        return await run_in_threadpool(
            require_store().list_audit,
            request.state.auth_cookie,
            own=True,
            **query_model(request, AuditPage),
        )

    @router.get("/admin/audit")
    async def audit(request: Request) -> dict[str, Any]:
        return await run_in_threadpool(
            require_store().list_audit, request.state.auth_cookie, **query_model(request, AuditPage)
        )

    @router.post("/admin/audit/export")
    async def export(request: Request) -> Response:
        active_store = require_store()
        body = await json_model(request, AuditPage)
        result = await run_in_threadpool(
            active_store.export_audit,
            request.state.auth_cookie,
            request_id=request.state.request_id,
            **body.model_dump(exclude_none=True),
        )
        return Response(
            result.content,
            media_type="application/x-ndjson",
            headers={
                "X-Total-Count": str(result.total),
                "X-Next-Offset": "" if result.next_offset is None else str(result.next_offset),
            },
        )

    return router


async def auth_error_handler(request: Request, exc: Exception) -> Response:
    from .auth_job_context import current_job_audit

    if not isinstance(exc, AuthError):
        raise exc
    return error_response(
        request, exc, unknown=exc.status == 503 and current_job_audit() is not None
    )
