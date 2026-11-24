"""Internal reservation ledger; callers supply authoritative *resource* states, not attempts.

Mappings are frozen against jobs.JobState, AIAnalysisState, export states and the
shared IP/JOB Status literal; regression tests compare the actual domain definitions.
No worker dispatch, domain write or automatic startup reconciliation lives here.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING, Any

from .auth_models import Actor, AuthError, JobLink
from .auth_store_audit import safe_id, safe_resource_id
from .security import Role

if TYPE_CHECKING:
    from .auth_store import AuthStore

_BASE = {"COMPLETED": "succeeded", "FAILED": "failed", "CANCELLED": "cancelled"}
TERMINALS = {
    "analysis": {**_BASE, "PARTIALLY_COMPLETED": "succeeded"},
    "pcap_export": dict(_BASE),
    "ai_run": dict(_BASE),
    "ip_investigation": {**_BASE, "PARTIAL": "succeeded"},
    "job_investigation": {**_BASE, "PARTIAL": "succeeded"},
}
STATES = {
    "analysis": set(TERMINALS["analysis"])
    | {"CREATED", "WAITING_FOR_SENSOR", "CAPTURING", "UPLOADING", "INGESTING", "ANALYZING"},
    "pcap_export": set(_BASE) | {"QUEUED", "RUNNING"},
    "ai_run": set(_BASE) | {"QUEUED", "PREPARING", "ANALYZING", "VALIDATING"},
    "ip_investigation": set(TERMINALS["ip_investigation"])
    | {"QUEUED", "PREPARING", "INVESTIGATING", "VALIDATING"},
    "job_investigation": set(TERMINALS["job_investigation"])
    | {"QUEUED", "PREPARING", "INVESTIGATING", "VALIDATING"},
}


def terminal_outcome(family: str, state: str) -> str | None:
    if family not in STATES or state not in STATES[family]:
        raise AuthError("INVALID_DOMAIN_STATUS", 422)
    return TERMINALS[family].get(state)


def validate_link(family: str, resource_id: str) -> None:
    if family not in STATES or not safe_resource_id(resource_id):
        raise AuthError("INVALID_JOB_LINK", 422)


def link(row: Any) -> JobLink:
    return JobLink(
        row["id"],
        row["family"],
        row["resource_id"],
        Actor(
            row["actor_id"],
            row["actor_name"],
            Role[row["actor_role"]] if row["actor_role"] else None,
            row["auth_kind"],
        ),
        row["request_id"],
        row["intent_id"],
        row["terminal_status"],
        row["event_id"],
    )


def reserve(
    store: AuthStore, family: str, resource_id: str, actor: Actor, request_id: str, intent_id: str
) -> JobLink:
    validate_link(family, resource_id)
    with store.db.transaction() as sql:
        row = sql.execute(
            "SELECT * FROM auth_job_links WHERE family=? AND resource_id=?", (family, resource_id)
        ).fetchone()
        if row:
            return link(row)
        store._audit(
            sql,
            actor,
            "job.lifecycle",
            resource_id,
            "started",
            request_id=request_id,
            job_id=resource_id,
            details={"family": family, "intent_id": intent_id},
        )
        link_id = secrets.token_hex(16)
        sql.execute(
            """INSERT INTO auth_job_links
            (id,family,resource_id,actor_id,actor_name,actor_role,auth_kind,request_id,intent_id)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                link_id,
                family,
                resource_id,
                actor.id,
                actor.name,
                actor.role.name if actor.role else None,
                actor.auth_kind,
                request_id,
                intent_id,
            ),
        )
        return link(sql.execute("SELECT * FROM auth_job_links WHERE id=?", (link_id,)).fetchone())


def finish(store: AuthStore, family: str, resource_id: str, domain_status: str) -> str:
    validate_link(family, resource_id)
    outcome = terminal_outcome(family, domain_status)
    with store.db.transaction() as sql:
        row = sql.execute(
            "SELECT * FROM auth_job_links WHERE family=? AND resource_id=?", (family, resource_id)
        ).fetchone()
        if not row:
            return "unknown"
        winning = link(row)
        if winning.terminal_status is not None:
            if winning.terminal_status != domain_status:
                raise AuthError("AUDIT_TERMINAL_CONFLICT", 409)
            return "complete"
        if outcome is None:
            return "pending"
        event_id = store._audit(
            sql,
            winning.actor,
            "job.lifecycle",
            resource_id,
            outcome,
            request_id=winning.request_id,
            job_id=resource_id,
            details={
                "family": family,
                "intent_id": winning.intent_id,
                "domain_status": domain_status,
            },
        )
        sql.execute(
            "UPDATE auth_job_links SET terminal_status=?,event_id=? WHERE id=?",
            (domain_status, event_id, winning.id),
        )
        return "complete"


def status(store: AuthStore, family: str, resource_id: str) -> str:
    validate_link(family, resource_id)
    with store.db.transaction() as sql:
        row = sql.execute(
            "SELECT event_id FROM auth_job_links WHERE family=? AND resource_id=?",
            (family, resource_id),
        ).fetchone()
        return ("complete" if row["event_id"] else "pending") if row else "unknown"


def pending(store: AuthStore, limit: int, cursor: str | None) -> dict[str, Any]:
    store._page(limit, 0, 1000)
    if cursor is not None and not safe_id(cursor):
        raise AuthError("INVALID_CURSOR", 422)
    with store.db.transaction() as sql:
        rows = sql.execute(
            """SELECT * FROM auth_job_links
            WHERE event_id IS NULL AND id>? ORDER BY id LIMIT ?""",
            (cursor or "", limit + 1),
        ).fetchall()
        items = [link(row) for row in rows[:limit]]
        return dict(items=items, next_cursor=items[-1].id if len(rows) > limit else None)
