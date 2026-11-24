"""Immutable account projections and safe errors; no credential serialization."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .security import Role


class AuthError(Exception):
    def __init__(self, code: str, status: int = 503) -> None:
        self.code = code
        self.status = status
        self.message = code
        super().__init__(code)


@dataclass(frozen=True)
class SafeUser:
    id: str
    username: str
    role: Role
    active: bool
    must_change_password: bool

    def to_dict(self) -> dict[str, Any]:
        return dict(
            id=self.id,
            username=self.username,
            role=self.role.name,
            active=self.active,
            must_change_password=self.must_change_password,
        )


@dataclass(frozen=True)
class Actor:
    id: str | None = None
    name: str | None = None
    role: Role | None = None
    auth_kind: str = "system"

    @classmethod
    def user(cls, user: SafeUser) -> Actor:
        return cls(user.id, user.username, user.role, "session")


@dataclass(frozen=True)
class AuthSession:
    user: SafeUser
    session_id: str
    created_at: float
    last_seen_at: float
    expires_at: float

    @property
    def identity_scope(self) -> str:
        return "user:" + self.user.id

    @property
    def actor(self) -> Actor:
        return Actor.user(self.user)


@dataclass(frozen=True, repr=False)
class LoginResult(AuthSession):
    # Internal-only cookie material, not a wire model or a loggable value.
    token: str


@dataclass(frozen=True)
class AuditExport:
    content: str
    total: int
    next_offset: int | None


@dataclass(frozen=True)
class JobLink:
    id: str
    family: str
    resource_id: str
    actor: Actor
    request_id: str
    intent_id: str
    terminal_status: str | None
    event_id: str | None
