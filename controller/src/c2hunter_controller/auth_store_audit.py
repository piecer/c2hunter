"""Closed security-event inputs and bounded scalar SQL audit queries."""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from ipaddress import ip_address
from typing import Any
from uuid import UUID

from .auth_models import Actor, AuthError
from .auth_schema import SQL
from .security import Role

ACTIONS = {
    "schema.init": {"count"},
    "audit.reconcile": {"count"},
    "audit.prune": {"count"},
    "account.bootstrap": set(),
    "account.create": {"role", "must_change_password"},
    "account.update": {"role", "active"},
    "account.reset": {"must_change_password"},
    "account.password_change": set(),
    "account.local_reset": {"must_change_password"},
    "auth.login": set(),
    "auth.login_limited": {"reason"},
    "auth.logout": set(),
    "session.revoke": {"count"},
    "access.denied": {"reason"},
    "audit.export": {"count"},
    "http.operation": {"reason"},
    "job.lifecycle": {"family", "intent_id", "domain_status", "reason"},
}
OUTCOMES = {"started", "succeeded", "failed", "denied", "cancelled", "unknown"}
FAMILIES = {"analysis", "pcap_export", "ai_run", "ip_investigation", "job_investigation"}
REASONS = {
    "invalid_credentials",
    "rate_limited",
    "insufficient_role",
    "password_change_required",
    "auth_required",
    "csrf_invalid",
    "origin_invalid",
    "audit_unavailable",
    "unresolved",
}


def safe_id(value: str) -> bool:
    return bool(re.fullmatch(r"[a-f0-9]{32}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value))


def safe_resource_id(value: str) -> bool:
    return safe_id(value) or bool(re.fullmatch(r"[a-f0-9]{64}", value))


def safe_target(value: str) -> bool:
    return bool(
        value in {"auth", "account"}
        or safe_resource_id(value)
        or len(value) <= 256
        and re.fullmatch(
            r"/(?:[a-z][a-z0-9_-]*|\{[a-z][a-z0-9_]*\})"
            r"(?:/(?:[a-z][a-z0-9_-]*|\{[a-z][a-z0-9_]*\}))*",
            value,
        )
    )


def validate(
    actor: Actor,
    action: str,
    target: str,
    outcome: str,
    timestamp: float,
    request_id: str | None,
    source_ip: str | None,
    status: int | None,
    job_id: str | None,
    details: dict[str, Any],
) -> None:
    try:
        valid_actor = actor.auth_kind in {"session", "bearer", "system", "unauthenticated"}
        if actor.auth_kind in {"system", "unauthenticated"}:
            valid_actor &= actor.id is None and actor.name is None and actor.role is None
        else:
            valid_actor &= (
                isinstance(actor.id, str)
                and isinstance(actor.name, str)
                and bool(re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", actor.name))
                and isinstance(actor.role, Role)
            )
            if actor.auth_kind == "session":
                valid_actor &= safe_id(actor.id or "")
            else:
                valid_actor &= bool(re.fullmatch(r"[A-Za-z0-9_.:@-]{1,100}", actor.id or ""))
        if not (
            valid_actor
            and action in ACTIONS
            and outcome in OUTCOMES
            and safe_target(target)
            and math.isfinite(timestamp)
            and set(details) <= ACTIONS[action]
        ):
            raise ValueError
        if request_id is not None and str(UUID(request_id)) != request_id:
            raise ValueError
        if source_ip is not None:
            ip_address(source_ip)
        if status is not None and (type(status) is not int or not 100 <= status <= 599):
            raise ValueError
        if job_id is not None and not safe_resource_id(job_id):
            raise ValueError
        for key, value in details.items():
            validators: dict[str, Callable[[Any], bool]] = {
                "role": lambda v: v in Role.__members__,
                "active": lambda v: type(v) is bool,
                "must_change_password": lambda v: type(v) is bool,
                "count": lambda v: type(v) is int and v >= 0,
                "family": lambda v: v in FAMILIES,
                "intent_id": lambda v: bool(re.fullmatch(r"[a-f0-9]{32}", v)),
                "reason": lambda v: v in REASONS,
                "domain_status": lambda v: False,
            }
            valid = validators[key](value)
            if key == "domain_status":
                from .auth_store_jobs import terminal_outcome

                valid = terminal_outcome(details.get("family", ""), value) is not None
            if not valid:
                raise ValueError
    except (ValueError, TypeError, KeyError):
        raise AuthError("INVALID_AUDIT", 422) from None


def query(
    sql: SQL,
    *,
    user_id: str | None = None,
    action: str | None = None,
    outcome: str | None = None,
    target: str | None = None,
    since: float | None = None,
    until: float | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    if (
        action is not None
        and action not in ACTIONS
        or outcome is not None
        and outcome not in OUTCOMES
        or target is not None
        and not safe_target(target)
        or user_id is not None
        and not safe_id(user_id)
    ):
        raise AuthError("INVALID_AUDIT_FILTER", 422)
    if any(
        type(t) not in (int, float) or not math.isfinite(t) for t in (since, until) if t is not None
    ):
        raise AuthError("INVALID_AUDIT_FILTER", 422)
    args = (
        user_id,
        user_id,
        action,
        action,
        outcome,
        outcome,
        target,
        target,
        since,
        since,
        until,
        until,
    )
    total = sql.execute(
        """SELECT count(*) AS n FROM auth_audit
        WHERE (CAST(? AS TEXT) IS NULL OR actor_id=?)
        AND (CAST(? AS TEXT) IS NULL OR action=?)
        AND (CAST(? AS TEXT) IS NULL OR outcome=?)
        AND (CAST(? AS TEXT) IS NULL OR target=?)
        AND (CAST(? AS DOUBLE PRECISION) IS NULL OR timestamp>=?)
        AND (CAST(? AS DOUBLE PRECISION) IS NULL OR timestamp<=?)""",
        args,
    ).fetchone()["n"]
    rows = sql.execute(
        """SELECT * FROM auth_audit
        WHERE (CAST(? AS TEXT) IS NULL OR actor_id=?)
        AND (CAST(? AS TEXT) IS NULL OR action=?)
        AND (CAST(? AS TEXT) IS NULL OR outcome=?)
        AND (CAST(? AS TEXT) IS NULL OR target=?)
        AND (CAST(? AS DOUBLE PRECISION) IS NULL OR timestamp>=?)
        AND (CAST(? AS DOUBLE PRECISION) IS NULL OR timestamp<=?)
        ORDER BY timestamp DESC,id DESC LIMIT ? OFFSET ?""",
        (*args, limit, offset),
    ).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item["details"])
        items.append(item)
    return dict(items=items, total=total)
