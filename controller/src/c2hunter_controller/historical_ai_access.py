"""Request-local AI privacy authority; absence of a public scope is internal.

Only repository get/list-run entries may request the compact exception. This
context grants no descendant or mutation capability through that exception.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass


class HistoricalAccessDenied(ValueError):
    status_code = 403

    def __init__(self, code: str) -> None:
        self.code = code
        self.message = (
            "인증이 필요합니다" if code == "BASELINE_AUTH_REQUIRED" else "ANALYST 역할이 필요합니다"
        )
        super().__init__(self.message)


@dataclass(frozen=True)
class _PublicAccess:
    role: int | None
    compact_runs: bool


_access: ContextVar[_PublicAccess | None] = ContextVar("historical_ai_public_access", default=None)


@contextmanager
def public_ai_access(role: int | None, *, compact_runs: bool = False) -> Iterator[None]:
    token = _access.set(_PublicAccess(role, compact_runs))
    try:
        yield
    finally:
        _access.reset(token)


def authorize(historical: bool, *, compact: bool = False) -> None:
    access = _access.get()
    if not historical or access is None or (compact and access.compact_runs):
        return
    if access.role is None:
        raise HistoricalAccessDenied("BASELINE_AUTH_REQUIRED")
    if not isinstance(access.role, int) or access.role not in (2, 3):
        raise HistoricalAccessDenied("INSUFFICIENT_ROLE")
