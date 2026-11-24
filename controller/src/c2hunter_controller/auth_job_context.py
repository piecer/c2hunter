"""Internal admitted authority; carry a captured reservation across thread handoff.

This module never authenticates a caller. Only the HTTP admission boundary binds
it after authentication and durable operation intent. Worker processes obtain
identity from persisted job links, never from this request-local context.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field

from .auth_models import Actor, JobLink
from .auth_store import AuthStore


@dataclass(frozen=True)
class JobAuditContext:
    store: AuthStore = field(repr=False)
    actor: Actor
    request_id: str
    intent_id: str

    def reserve(self, family: str, resource_id: str) -> JobLink:
        return self.store.reserve_job(
            family, resource_id, self.actor, self.request_id, self.intent_id
        )


_current: ContextVar[JobAuditContext | None] = ContextVar("c2hunter_job_audit", default=None)


def current_job_audit() -> JobAuditContext | None:
    """Capture this value before any thread handoff; new threads have no authority."""
    return _current.get()


@contextmanager
def bind_job_audit(
    store: AuthStore, actor: Actor, request_id: str, intent_id: str
) -> Iterator[JobAuditContext]:
    context = JobAuditContext(store, actor, request_id, intent_id)
    token = _current.set(context)
    try:
        yield context
    finally:
        _current.reset(token)
