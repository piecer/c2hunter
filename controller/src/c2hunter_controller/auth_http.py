"""Closed account boundary shared by every application HTTP handler."""

from __future__ import annotations

import hmac
import ipaddress
import uuid
from contextlib import nullcontext
from typing import Any
from urllib.parse import urlsplit

from fastapi import Request
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .auth_browser import PRELOGIN_COOKIE, SESSION_COOKIE, cookie_value, proof, verify_prelogin
from .auth_job_context import bind_job_audit
from .auth_models import Actor, AuthError
from .auth_policy import lookup_rule
from .auth_store import AuthStore
from .config import Settings
from .security import Principal, SecurityError, TokenAuthenticator, trusted_client_ip

HARDENING = {
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "frame-ancestors 'none'; base-uri 'none'; object-src 'none'",
}


def error_response(request: Request, exc: AuthError, *, unknown: bool = False) -> JSONResponse:
    error: dict[str, Any] = {"code": exc.code, "message": exc.message}
    if unknown:
        error["outcome"] = "unknown"
    return JSONResponse(
        {"error": error, "request_id": request.state.request_id}, status_code=exc.status
    )


class AccountBoundary:
    def __init__(
        self,
        app: ASGIApp,
        *,
        settings: Settings,
        store: AuthStore | None,
        authenticator: TokenAuthenticator,
    ) -> None:
        self.app = app
        self.settings = settings
        self.store = store
        self.authenticator = authenticator

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)
        request.state.request_id = str(uuid.uuid4())
        enabled = self.settings.account_auth_enabled
        path = request.url.path
        account_path = path.startswith(("/api/v1/auth/", "/api/v1/admin/"))

        async def hardened(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.update(HARDENING)
                headers["x-request-id"] = request.state.request_id
            await send(message)

        if not enabled:
            if account_path and path != "/api/v1/auth/dev-login":
                request.state.account_boundary_verified = True
            await self.app(scope, receive, hardened)
            return
        rule = lookup_rule(request.method, path)
        actor = Actor(auth_kind="unauthenticated")
        target = rule.template if rule and rule.template.startswith("/api/") else "auth"
        intent: str | None = None
        source_ip: str | None = None
        started_response = False
        try:
            if rule and rule.access in {"device", "public"} and not account_path:
                if path == "/api/v1/ready":
                    if self.store is None or not self.settings.auth_public_origin:
                        raise AuthError("ACCOUNT_SETUP_REQUIRED")
                    if not await run_in_threadpool(self.store.ready):
                        raise AuthError("ACCOUNT_SETUP_REQUIRED")
                await self.app(scope, receive, hardened)
                return
            store = self.store
            if not self.settings.auth_public_origin or store is None:
                raise AuthError("ACCOUNT_SETUP_REQUIRED")
            if not await run_in_threadpool(store.ready):
                raise AuthError("ACCOUNT_SETUP_REQUIRED")
            key = await run_in_threadpool(store.hmac_key)
            peer = request.client.host if request.client else ""
            candidate_ip = trusted_client_ip(
                peer, request.headers.get("x-forwarded-for"), self.settings.trusted_proxy_networks
            )
            try:
                source_ip = str(ipaddress.ip_address(candidate_ip))
            except ValueError:
                pass
            authority = urlsplit(self.settings.auth_public_origin).netloc
            if request.headers.getlist("host") != [authority]:
                raise AuthError("ORIGIN_INVALID", 403)
            origins = request.headers.getlist("origin")
            if origins and origins != [self.settings.auth_public_origin]:
                raise AuthError("ORIGIN_INVALID", 403)
            authorization = request.headers.getlist("authorization")
            token = cookie_value(request, SESSION_COOKIE)
            if len(authorization) > 1 or (authorization and token is not None):
                raise AuthError("AUTH_REQUIRED", 401)
            session = None
            principal = None
            if authorization:
                try:
                    principal = self.authenticator.authenticate(authorization[0])
                except (SecurityError, UnicodeError):
                    raise AuthError("AUTH_REQUIRED", 401) from None
                actor = Actor(principal.subject, principal.subject, principal.role, "bearer")
            elif token and path not in {"/api/v1/auth/login", "/api/v1/auth/csrf"}:
                session = await run_in_threadpool(store.authenticate, token)
                principal = Principal(session.identity_scope, session.user.role)
                actor = session.actor
            if rule is None or rule.access == "disabled":
                raise AuthError("INSUFFICIENT_ROLE", 403)
            if rule.access not in {"public", "device"}:
                if principal is None:
                    raise AuthError("AUTH_REQUIRED", 401)
                if rule.access == "session" and session is None:
                    raise AuthError("INSUFFICIENT_ROLE", 403)
                if rule.minimum_role is not None and principal.role < rule.minimum_role:
                    raise AuthError("INSUFFICIENT_ROLE", 403)
                if session and session.user.must_change_password and not rule.forced_change:
                    raise AuthError("PASSWORD_CHANGE_REQUIRED", 403)
            protected_effect = (
                request.method not in {"GET", "HEAD", "OPTIONS"} or rule.external_read
            )
            if protected_effect and (not authorization or path == "/api/v1/auth/login"):
                if origins != [self.settings.auth_public_origin]:
                    raise AuthError("ORIGIN_INVALID", 403)
                csrf_headers = request.headers.getlist("x-csrf-token")
                if len(csrf_headers) != 1:
                    raise AuthError("CSRF_INVALID", 403)
                csrf = csrf_headers[0]
                if path == "/api/v1/auth/login":
                    verify_prelogin(key, cookie_value(request, PRELOGIN_COOKIE) or "", csrf)
                elif session is None or not hmac.compare_digest(
                    csrf.encode(), proof(key, "session-csrf", token or "").encode()
                ):
                    raise AuthError("CSRF_INVALID", 403)
            # Bound credentials before a parser, model validator or expensive work sees them.
            if account_path and protected_effect:
                body = bytearray()
                async for chunk in request.stream():
                    if len(body) + len(chunk) > 16384:
                        raise AuthError("REQUEST_TOO_LARGE", 413)
                    body.extend(chunk)
                consumed = False
                original_receive = receive

                async def bounded_receive() -> Message:
                    nonlocal consumed
                    if not consumed:
                        consumed = True
                        return {"type": "http.request", "body": bytes(body), "more_body": False}
                    return await original_receive()

                receive = bounded_receive
            request.state.principal = principal
            request.state.auth_session = session
            request.state.auth_cookie = token
            request.state.auth_key = key
            request.state.auth_source_ip = source_ip
            request.state.account_boundary_verified = True
            if protected_effect and not account_path:
                intent = await run_in_threadpool(
                    store.record_event,
                    actor,
                    "http.operation",
                    target,
                    "started",
                    request_id=request.state.request_id,
                    source_ip=source_ip,
                )

            async def audited_send(message: Message) -> None:
                nonlocal started_response
                if message["type"] == "http.response.start":
                    if message["status"] in {401, 403, 429} and path != "/api/v1/auth/login":
                        await run_in_threadpool(
                            store.record_event,
                            actor,
                            "access.denied",
                            target,
                            "denied",
                            request_id=request.state.request_id,
                            source_ip=source_ip,
                            status=message["status"],
                        )
                    if intent:
                        await run_in_threadpool(
                            store.record_event,
                            actor,
                            "http.operation",
                            target,
                            "succeeded" if message["status"] < 400 else "failed",
                            request_id=request.state.request_id,
                            source_ip=source_ip,
                            status=message["status"],
                        )
                    if request.method == "GET" and message["status"] < 400:
                        status_routes = {
                            "/api/v1/analysis-jobs/{job_id}": ("analysis", -1),
                            "/api/v1/pcap-exports/{export_id}": ("pcap_export", -1),
                            "/api/v1/ai-runs/{run_id}": ("ai_run", -1),
                            "/api/v1/analysis-jobs/{job_id}/ai-investigations/{run_id}": (
                                "ip_investigation",
                                -1,
                            ),
                            "/api/v1/analysis-jobs/{job_id}/ai-job-investigations/{run_id}": (
                                "job_investigation",
                                -1,
                            ),
                        }
                        if rule.template in status_routes:
                            family, position = status_routes[rule.template]
                            resource_id = path.split("/")[position]
                            audit_status = await run_in_threadpool(
                                store.job_audit_status, family, resource_id
                            )
                            MutableHeaders(scope=message)["X-C2Hunter-Audit-Status"] = audit_status
                    started_response = True
                await hardened(message)

            context = (
                bind_job_audit(store, actor, request.state.request_id, intent)
                if intent
                else nullcontext()
            )
            with context:
                await self.app(scope, receive, audited_send)
        except AuthError as caught:
            exc = caught
            if started_response:
                raise
            if intent:
                exc = AuthError("SECURITY_UNAVAILABLE")
            elif self.store is not None and exc.status < 500:
                try:
                    await run_in_threadpool(
                        self.store.record_event,
                        actor,
                        "access.denied",
                        target,
                        "denied",
                        request_id=request.state.request_id,
                        source_ip=source_ip,
                        status=exc.status,
                    )
                except AuthError as audit_error:
                    exc = audit_error
            await error_response(request, exc, unknown=bool(intent))(scope, receive, hardened)
        except Exception:
            if started_response:
                raise
            failure = AuthError("INTERNAL_ERROR", 500)
            if intent and self.store is not None:
                try:
                    await run_in_threadpool(
                        self.store.record_event,
                        actor,
                        "http.operation",
                        target,
                        "unknown",
                        request_id=request.state.request_id,
                        source_ip=source_ip,
                        status=500,
                    )
                except AuthError:
                    failure = AuthError("SECURITY_UNAVAILABLE")
            await error_response(request, failure, unknown=bool(intent))(scope, receive, hardened)
