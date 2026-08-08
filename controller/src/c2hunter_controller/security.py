from __future__ import annotations

import hashlib
import hmac
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import IntEnum


class Role(IntEnum):
    VIEWER = 1
    ANALYST = 2
    ADMIN = 3


@dataclass(frozen=True)
class Principal:
    subject: str
    role: Role


@dataclass(frozen=True)
class SecurityError(Exception):
    status: int
    code: str
    message: str
    retry_after: int | None = None


@dataclass(frozen=True)
class Session:
    subject: str
    role: Role
    expires_at: datetime


class SessionStore:
    """Store only token digests and expire development sessions lazily."""

    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def add(self, token: str, subject: str, role: Role, ttl_seconds: int) -> None:
        session = Session(
            subject=subject,
            role=role,
            expires_at=datetime.now(UTC) + timedelta(seconds=ttl_seconds),
        )
        with self._lock:
            self._sessions[_token_hash(token)] = session

    def authenticate(self, token: str) -> Principal | None:
        digest = _token_hash(token)
        now = datetime.now(UTC)
        with self._lock:
            session = self._sessions.get(digest)
            if session is None:
                return None
            if session.expires_at <= now:
                del self._sessions[digest]
                return None
            return Principal(session.subject, session.role)


class TokenAuthenticator:
    def __init__(
        self,
        sessions: SessionStore,
        *,
        viewer_token_sha256: str = "",
        analyst_token_sha256: str = "",
        admin_token_sha256: str = "",
    ) -> None:
        self._sessions = sessions
        self._static_tokens = (
            (viewer_token_sha256, Role.VIEWER),
            (analyst_token_sha256, Role.ANALYST),
            (admin_token_sha256, Role.ADMIN),
        )

    def authenticate(self, authorization: str | None) -> Principal:
        if not authorization:
            raise SecurityError(401, "AUTH_TOKEN_REQUIRED", "Bearer 인증 토큰이 필요합니다")
        scheme, separator, token = authorization.partition(" ")
        if not separator or scheme.lower() != "bearer" or not token.strip():
            raise SecurityError(401, "INVALID_AUTH_TOKEN", "Bearer 인증 토큰이 유효하지 않습니다")
        token = token.strip()
        principal = self._sessions.authenticate(token)
        if principal is not None:
            return principal
        digest = _token_hash(token)
        for configured_digest, role in self._static_tokens:
            if configured_digest and hmac.compare_digest(configured_digest, digest):
                return Principal(f"static-{role.name.lower()}", role)
        raise SecurityError(401, "INVALID_AUTH_TOKEN", "Bearer 인증 토큰이 유효하지 않습니다")


class FixedWindowRateLimiter:
    """Bound request timestamps per scope and client without external state."""

    def __init__(self, window_seconds: int) -> None:
        self._window_seconds = window_seconds
        self._requests: dict[tuple[str, str], deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, scope: str, client_key: str, limit: int) -> None:
        now = time.monotonic()
        cutoff = now - self._window_seconds
        key = (scope, client_key)
        with self._lock:
            requests = self._requests[key]
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= limit:
                retry_after = max(1, math.ceil(self._window_seconds - (now - requests[0])))
                raise SecurityError(
                    429,
                    "RATE_LIMIT_EXCEEDED",
                    "요청 한도를 초과했습니다",
                    retry_after=retry_after,
                )
            requests.append(now)


def is_enrollment_claim(method: str, path: str) -> bool:
    parts = path.removeprefix("/api/v1/").strip("/").split("/")
    return (
        method == "POST"
        and len(parts) == 3
        and parts[0] == "sensor-enrollments"
        and parts[2] == "claim"
    )


def required_role(method: str, path: str) -> Role | None:
    """Return the minimum human role, or None for health and sensor-authenticated routes."""
    if path in {"/api/v1/health", "/api/v1/ready", "/api/v1/metrics", "/api/v1/auth/dev-login"}:
        return None
    if is_enrollment_claim(method, path):
        return None

    parts = path.removeprefix("/api/v1/").strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "sensors":
        suffix = parts[2:]
        sensor_posts = (["heartbeat"], ["flow-batches"])
        if method == "POST" and (parts[1] == "register" or suffix in sensor_posts):
            return None
        if method == "GET" and suffix == ["agent-config"]:
            return None
        if method == "PUT" and len(suffix) == 2 and suffix[0] == "pcap-segments":
            return None

    if method == "GET":
        return Role.VIEWER
    if method == "POST" and parts[0] == "candidates" and parts[-1] == "misp-exports":
        return Role.ADMIN
    if parts[0] in {"sensor-enrollments", "sensor-groups", "detector-weight-presets"}:
        return Role.ADMIN
    if parts[0] == "sensors" and parts[-1] in {"configuration", "rotate", "revoke"}:
        return Role.ADMIN
    return Role.ANALYST


def require_role(principal: Principal, role: Role) -> None:
    if principal.role < role:
        raise SecurityError(403, "INSUFFICIENT_ROLE", f"{role.name} 역할이 필요합니다")


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
