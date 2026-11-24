"""Persistent account authority. Each public operation owns a short SQL transaction."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from . import auth_store_jobs
from .auth_models import Actor, AuditExport, AuthError, AuthSession, JobLink, LoginResult, SafeUser
from .auth_passwords import PasswordBusy, PasswordError, Passwords
from .auth_schema import POSTGRES_WRITE_READINESS, SQL, Database
from .auth_store_audit import query as audit_query
from .auth_store_audit import validate as validate_audit
from .security import Role


class AuthStore:
    def __init__(
        self,
        *,
        sqlite_path: Path | str | None = None,
        database_url: str | None = None,
        passwords: Passwords | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db = Database(sqlite_path=sqlite_path, database_url=database_url)
        self.sqlite_path = self.db.path
        self.passwords = passwords or Passwords()
        self.clock = clock

    def initialize(self) -> None:
        with self.db.transaction(initialize=True) as sql:
            if self.db.initialize(sql):
                self._audit(sql, Actor(), "schema.init", "auth", "succeeded")

    def ready(self) -> bool:
        try:
            with self.db.transaction() as sql:
                if sql.postgres:
                    # Observation only, not a guarantee against later backend failures.
                    state = sql.execute(POSTGRES_WRITE_READINESS).fetchone()
                    if not state or state["ready"] is not True:
                        return False
                sql.execute("SELECT id FROM auth_audit LIMIT 1").fetchone()
                sql.execute("SELECT id FROM auth_users LIMIT 1").fetchone()
            return True
        except AuthError:
            return False

    def hmac_key(self) -> bytes:
        with self.db.transaction() as sql:
            row = sql.execute("SELECT value FROM auth_meta WHERE key='hmac_key'").fetchone()
            try:
                key = bytes.fromhex(row["value"])
                if len(key) != 32:
                    raise ValueError
                return key
            except (TypeError, ValueError):
                raise AuthError("ACCOUNT_SETUP_REQUIRED") from None

    @staticmethod
    def _username(username: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,64}", username):
            raise AuthError("INVALID_USERNAME", 422)
        return username.lower()

    @staticmethod
    def _user(row: Any) -> SafeUser:
        return SafeUser(
            row["id"],
            row["username"],
            Role[row["role"]],
            bool(row["active"]),
            bool(row["must_change_password"]),
        )

    def _audit(
        self,
        sql: SQL,
        actor: Actor,
        action: str,
        target: str,
        outcome: str,
        *,
        request_id: str | None = None,
        source_ip: str | None = None,
        status: int | None = None,
        job_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        timestamp = self.clock()
        validate_audit(
            actor,
            action,
            target,
            outcome,
            timestamp,
            request_id,
            source_ip,
            status,
            job_id,
            details or {},
        )
        event_id = secrets.token_hex(16)
        sql.execute(
            """INSERT INTO auth_audit
            (id,timestamp,actor_id,actor_name,actor_role,auth_kind,action,target,outcome,
             request_id,source_ip,status,job_id,details) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event_id,
                timestamp,
                actor.id,
                actor.name,
                actor.role.name if actor.role else None,
                actor.auth_kind,
                action,
                target,
                outcome,
                request_id,
                source_ip,
                status,
                job_id,
                json.dumps(details or {}),
            ),
        )
        return event_id

    def bootstrap(self, username: str, password: str) -> SafeUser:
        username = self._username(username)
        # Fail setup closed before expensive work, without creating files.
        with self.db.transaction():
            pass
        encoded = self._hash(password)
        with self.db.transaction() as sql:
            if sql.execute("SELECT id FROM auth_users LIMIT 1").fetchone():
                raise AuthError("USER_EXISTS", 409)
            user = SafeUser(secrets.token_hex(16), username, Role.ADMIN, True, False)
            sql.execute(
                "INSERT INTO auth_users VALUES (?,?,?,?,?,?,?)",
                (user.id, username, "ADMIN", 1, 0, encoded, 1),
            )
            self._audit(sql, Actor(), "account.bootstrap", user.id, "succeeded")
            return user

    def local_reset_password(self, username: str, password: str) -> None:
        """Local CLI authority only; never expose this method through an HTTP handler."""
        username = self._username(username)
        with self.db.transaction():
            pass
        encoded = self._hash(password)
        with self.db.transaction() as sql:
            row = sql.execute("SELECT id FROM auth_users WHERE username=?", (username,)).fetchone()
            if row is None:
                raise AuthError("USER_NOT_FOUND", 404)
            sql.execute(
                "UPDATE auth_users SET password_hash=?,must_change_password=1 WHERE id=?",
                (encoded, row["id"]),
            )
            self._invalidate(sql, row["id"])
            self._audit(
                sql,
                Actor(),
                "account.local_reset",
                row["id"],
                "succeeded",
                details={"must_change_password": True},
            )

    @staticmethod
    def _digest(token: str) -> str:
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise AuthError("AUTH_REQUIRED", 401)
        return hashlib.sha256(token.encode("ascii")).hexdigest()

    def _session(self, sql: SQL, token: str) -> AuthSession:
        row = sql.execute(
            """SELECT u.*,s.id AS session_id,s.created_at,s.last_seen_at,
            s.expires_at,s.generation AS session_generation FROM auth_sessions s
            JOIN auth_users u ON u.id=s.user_id WHERE s.digest=?""",
            (self._digest(token),),
        ).fetchone()
        now = self.clock()
        if (
            not row
            or not row["active"]
            or row["generation"] != row["session_generation"]
            or row["expires_at"] <= now
            or row["last_seen_at"] + 1800 <= now
        ):
            raise AuthError("AUTH_REQUIRED", 401)
        return AuthSession(
            self._user(row),
            row["session_id"],
            row["created_at"],
            row["last_seen_at"],
            row["expires_at"],
        )

    def authenticate(self, token: str) -> AuthSession:
        with self.db.transaction() as sql:
            session = self._session(sql, token)
            sql.execute(
                "UPDATE auth_sessions SET last_seen_at=? WHERE id=?",
                (self.clock(), session.session_id),
            )
            return session

    def _throttle(self, sql: SQL, keys: list[str], attempt: str) -> bool:
        now = self.clock()
        sql.execute("DELETE FROM auth_throttle WHERE updated_at<=?", (now - 900,))
        rows: dict[str, list[Any]] = {}
        missing = 0
        for key in keys:
            row = sql.execute("SELECT entries FROM auth_throttle WHERE key=?", (key,)).fetchone()
            entries = [e for e in json.loads(row["entries"]) if e[0] > now - 900] if row else []
            if len(entries) >= 10:
                return False
            missing += row is None
            rows[key] = entries
        count = sql.execute("SELECT count(*) AS n FROM auth_throttle").fetchone()["n"]
        if count + missing > 10000:
            return False
        for key, entries in rows.items():
            entries.append([now, attempt])
            sql.execute(
                """INSERT INTO auth_throttle(key,entries,updated_at) VALUES (?,?,?)
                ON CONFLICT(key) DO UPDATE SET entries=excluded.entries,
                updated_at=excluded.updated_at""",
                (key, json.dumps(entries), now),
            )
        return True

    def login(
        self,
        username: str,
        password: str,
        *,
        prior_token: str | None = None,
        source_ip: str | None = None,
        request_id: str | None = None,
    ) -> LoginResult:
        if source_ip is not None:
            source_ip = str(ip_address(source_ip))
        try:
            canonical = self._username(username)
        except AuthError:
            canonical = ""
        key = self.hmac_key()
        names = ["username:" + canonical]
        if source_ip:
            names.append("ip:" + source_ip)
        keys = [hmac.digest(key, name.encode(), "sha256").hex() for name in names]
        attempt = secrets.token_hex(16)
        with self.db.transaction() as sql:
            allowed = self._throttle(sql, keys, attempt)
            captured = sql.execute(
                "SELECT * FROM auth_users WHERE username=?", (canonical,)
            ).fetchone()
            if not allowed:
                self._audit(
                    sql,
                    Actor(auth_kind="unauthenticated"),
                    "auth.login_limited",
                    "/auth/login",
                    "denied",
                    source_ip=source_ip,
                    request_id=request_id,
                    status=429,
                )
        if not allowed:
            raise AuthError("RATE_LIMIT_EXCEEDED", 429)
        failure = "INVALID_CREDENTIALS"
        try:
            valid = self.passwords.verify(captured["password_hash"] if captured else None, password)
        except PasswordError:
            valid = False
        except PasswordBusy:
            valid = False
            failure = "RATE_LIMIT_EXCEEDED"
        result: LoginResult | None = None
        with self.db.transaction() as sql:
            current = sql.execute(
                "SELECT * FROM auth_users WHERE username=?", (canonical,)
            ).fetchone()
            valid = bool(
                valid
                and captured
                and current
                and current["active"]
                and all(current[k] == captured[k] for k in ("id", "password_hash", "generation"))
            )
            actor = Actor.user(self._user(current)) if valid else Actor(auth_kind="unauthenticated")
            self._audit(
                sql,
                actor,
                "auth.login" if failure == "INVALID_CREDENTIALS" else "auth.login_limited",
                "/auth/login",
                "succeeded" if valid else "failed",
                request_id=request_id,
                source_ip=source_ip,
                status=200 if valid else (429 if failure == "RATE_LIMIT_EXCEEDED" else 401),
            )
            if valid:
                for throttle_key in keys:
                    row = sql.execute(
                        "SELECT entries FROM auth_throttle WHERE key=?", (throttle_key,)
                    ).fetchone()
                    if row:
                        entries = [e for e in json.loads(row["entries"]) if e[1] != attempt]
                        sql.execute(
                            "UPDATE auth_throttle SET entries=? WHERE key=?",
                            (json.dumps(entries), throttle_key),
                        )
                if prior_token:
                    try:
                        digest = self._digest(prior_token)
                    except AuthError:
                        digest = ""
                    sql.execute("DELETE FROM auth_sessions WHERE digest=?", (digest,))
                now = self.clock()
                sql.execute(
                    "DELETE FROM auth_sessions WHERE expires_at<=? OR last_seen_at<=?",
                    (now, now - 1800),
                )
                token = secrets.token_urlsafe(32)
                session_id = secrets.token_hex(16)
                sql.execute(
                    "INSERT INTO auth_sessions VALUES (?,?,?,?,?,?,?)",
                    (
                        session_id,
                        self._digest(token),
                        current["id"],
                        current["generation"],
                        now,
                        now,
                        now + 43200,
                    ),
                )
                result = LoginResult(self._user(current), session_id, now, now, now + 43200, token)
        if result is None:
            raise AuthError(failure, 429 if failure == "RATE_LIMIT_EXCEEDED" else 401)
        return result

    def reserve_job(
        self, family: str, resource_id: str, actor: Actor, request_id: str, intent_id: str
    ) -> JobLink:
        return auth_store_jobs.reserve(self, family, resource_id, actor, request_id, intent_id)

    def finish_job(self, family: str, resource_id: str, domain_status: str) -> str:
        return auth_store_jobs.finish(self, family, resource_id, domain_status)

    def job_audit_status(self, family: str, resource_id: str) -> str:
        return auth_store_jobs.status(self, family, resource_id)

    def pending_job_links(self, limit: int = 100, cursor: str | None = None) -> dict[str, Any]:
        return auth_store_jobs.pending(self, limit, cursor)

    @contextmanager
    def _authorized(
        self, token: str, *, admin: bool = False, forced: bool = False
    ) -> Iterator[tuple[SQL, AuthSession]]:
        actor = Actor(auth_kind="unauthenticated")
        try:
            with self.db.transaction() as sql:
                session = self._session(sql, token)
                actor = session.actor
                if session.user.must_change_password and not forced:
                    raise AuthError("PASSWORD_CHANGE_REQUIRED", 403)
                if admin and session.user.role != Role.ADMIN:
                    raise AuthError("INSUFFICIENT_ROLE", 403)
                yield sql, session
        except AuthError as exc:
            if exc.status in (401, 403):
                with self.db.transaction() as sql:
                    self._audit(sql, actor, "access.denied", "account", "denied", status=exc.status)
            raise

    @staticmethod
    def _page(limit: int, offset: int, maximum: int = 200) -> None:
        if (
            type(limit) is not int
            or type(offset) is not int
            or not 1 <= limit <= maximum
            or not 0 <= offset <= 10000000
        ):
            raise AuthError("INVALID_PAGINATION", 422)

    def _hash(self, password: str) -> str:
        try:
            return self.passwords.hash(password)
        except PasswordError:
            raise AuthError("INVALID_PASSWORD", 422) from None
        except PasswordBusy:
            raise AuthError("RATE_LIMIT_EXCEEDED", 429) from None

    def list_users(self, token: str, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        self._page(limit, offset)
        with self._authorized(token, admin=True) as (sql, _):
            rows = sql.execute(
                "SELECT * FROM auth_users ORDER BY username,id LIMIT ? OFFSET ?", (limit, offset)
            ).fetchall()
            total = sql.execute("SELECT count(*) AS n FROM auth_users").fetchone()["n"]
            return dict(items=[self._user(row).to_dict() for row in rows], total=total)

    def create_user(
        self, token: str, username: str, password: str, role: Role, *, request_id: str | None = None
    ) -> SafeUser:
        username = self._username(username)
        if not isinstance(role, Role):
            raise AuthError("INVALID_ROLE", 422)
        with self._authorized(token, admin=True):
            pass
        encoded = self._hash(password)
        with self._authorized(token, admin=True) as (sql, session):
            if sql.execute("SELECT id FROM auth_users WHERE username=?", (username,)).fetchone():
                raise AuthError("USER_EXISTS", 409)
            user = SafeUser(secrets.token_hex(16), username, role, True, True)
            sql.execute(
                "INSERT INTO auth_users VALUES (?,?,?,?,?,?,?)",
                (user.id, username, role.name, 1, 1, encoded, 1),
            )
            self._audit(
                sql,
                session.actor,
                "account.create",
                user.id,
                "succeeded",
                request_id=request_id,
                details={"role": role.name, "must_change_password": True},
            )
            return user

    @staticmethod
    def _target(sql: SQL, user_id: str) -> Any:
        row = sql.execute("SELECT * FROM auth_users WHERE id=?", (user_id,)).fetchone()
        if not row:
            raise AuthError("USER_NOT_FOUND", 404)
        return row

    @staticmethod
    def _invalidate(sql: SQL, user_id: str) -> None:
        sql.execute("UPDATE auth_users SET generation=generation+1 WHERE id=?", (user_id,))
        sql.execute("DELETE FROM auth_sessions WHERE user_id=?", (user_id,))

    def update_user(
        self,
        token: str,
        user_id: str,
        *,
        role: Role | None = None,
        active: bool | None = None,
        request_id: str | None = None,
    ) -> SafeUser:
        if (
            role is None
            and active is None
            or role is not None
            and not isinstance(role, Role)
            or active is not None
            and type(active) is not bool
        ):
            raise AuthError("INVALID_UPDATE", 422)
        with self._authorized(token, admin=True) as (sql, session):
            old = self._target(sql, user_id)
            new_role = role.name if role else old["role"]
            new_active = bool(old["active"]) if active is None else active
            if old["role"] == "ADMIN" and old["active"] and (new_role != "ADMIN" or not new_active):
                count = sql.execute(
                    "SELECT count(*) AS n FROM auth_users WHERE role='ADMIN' AND active=1"
                ).fetchone()["n"]
                if count <= 1:
                    raise AuthError("LAST_ADMIN", 409)
            sql.execute(
                "UPDATE auth_users SET role=?,active=? WHERE id=?",
                (new_role, int(new_active), user_id),
            )
            self._invalidate(sql, user_id)
            self._audit(
                sql,
                session.actor,
                "account.update",
                user_id,
                "succeeded",
                request_id=request_id,
                details={"role": new_role, "active": new_active},
            )
            return self._user(self._target(sql, user_id))

    def reset_password(
        self, token: str, user_id: str, password: str, *, request_id: str | None = None
    ) -> None:
        with self._authorized(token, admin=True):
            pass
        encoded = self._hash(password)
        with self._authorized(token, admin=True) as (sql, session):
            self._target(sql, user_id)
            sql.execute(
                "UPDATE auth_users SET password_hash=?,must_change_password=1 WHERE id=?",
                (encoded, user_id),
            )
            self._invalidate(sql, user_id)
            self._audit(
                sql,
                session.actor,
                "account.reset",
                user_id,
                "succeeded",
                request_id=request_id,
                details={"must_change_password": True},
            )

    def change_password(
        self, token: str, current_password: str, new_password: str, *, request_id: str | None = None
    ) -> None:
        with self._authorized(token, forced=True) as (sql, session):
            captured = dict(self._target(sql, session.user.id))
        try:
            valid = self.passwords.verify(captured["password_hash"], current_password)
        except PasswordError:
            valid = False
        except PasswordBusy:
            raise AuthError("RATE_LIMIT_EXCEEDED", 429) from None
        encoded = self._hash(new_password) if valid else None
        with self._authorized(token, forced=True) as (sql, session):
            current = self._target(sql, session.user.id)
            if any(current[k] != captured[k] for k in ("id", "password_hash", "generation")):
                raise AuthError("AUTH_REQUIRED", 401)
            if valid:
                sql.execute(
                    "UPDATE auth_users SET password_hash=?,must_change_password=0 WHERE id=?",
                    (encoded, session.user.id),
                )
                self._invalidate(sql, session.user.id)
            self._audit(
                sql,
                session.actor,
                "account.password_change",
                session.user.id,
                "succeeded" if valid else "denied",
                request_id=request_id,
            )
        if not valid:
            raise AuthError("INVALID_CREDENTIALS", 401)

    def list_sessions(self, token: str, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        self._page(limit, offset)
        with self._authorized(token) as (sql, session):
            args = (session.user.id, session.user.id, self.clock(), self.clock() - 1800)
            rows = sql.execute(
                """SELECT id,created_at,last_seen_at,expires_at FROM auth_sessions
                WHERE user_id=? AND generation=(SELECT generation FROM auth_users WHERE id=?)
                AND expires_at>? AND last_seen_at>?
                ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?""",
                (*args, limit, offset),
            ).fetchall()
            total = sql.execute(
                """SELECT count(*) AS n FROM auth_sessions
                WHERE user_id=? AND generation=(SELECT generation FROM auth_users WHERE id=?)
                AND expires_at>? AND last_seen_at>?""",
                args,
            ).fetchone()["n"]
            return dict(
                items=[dict(row, current=row["id"] == session.session_id) for row in rows],
                total=total,
            )

    def revoke_sessions(
        self, token: str, *, session_id: str | None = None, request_id: str | None = None
    ) -> bool:
        with self._authorized(token) as (sql, session):
            if session_id is None:
                self._invalidate(sql, session.user.id)
            else:
                sql.execute(
                    "DELETE FROM auth_sessions WHERE user_id=? AND id=?",
                    (session.user.id, session_id),
                )
            self._audit(
                sql,
                session.actor,
                "session.revoke",
                session.user.id,
                "succeeded",
                request_id=request_id,
            )
            return session_id is None or session_id == session.session_id

    def revoke_user_sessions(
        self, token: str, user_id: str, *, request_id: str | None = None
    ) -> None:
        with self._authorized(token, admin=True) as (sql, session):
            self._target(sql, user_id)
            self._invalidate(sql, user_id)
            self._audit(
                sql, session.actor, "session.revoke", user_id, "succeeded", request_id=request_id
            )

    def logout(self, token: str, *, request_id: str | None = None) -> None:
        with self._authorized(token, forced=True) as (sql, session):
            sql.execute("DELETE FROM auth_sessions WHERE id=?", (session.session_id,))
            self._audit(
                sql,
                session.actor,
                "auth.logout",
                session.user.id,
                "succeeded",
                request_id=request_id,
            )

    def record_event(
        self,
        actor: Actor,
        action: str,
        target: str,
        outcome: str,
        *,
        request_id: str | None = None,
        source_ip: str | None = None,
        status: int | None = None,
        job_id: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> str:
        """Internal server-only durable event; never accept an actor from a request body."""
        with self.db.transaction() as sql:
            return self._audit(
                sql,
                actor,
                action,
                target,
                outcome,
                request_id=request_id,
                source_ip=source_ip,
                status=status,
                job_id=job_id,
                details=details,
            )

    def prune_audit(self, retention_days: int = 180) -> int:
        """Internal maintenance only: one oldest-first, transactional deletion pass."""
        if type(retention_days) is not int or not 1 <= retention_days <= 3650:
            raise ValueError("Audit retention must be 1..3650 days")
        with self.db.transaction() as sql:
            deleted = sql.execute(
                """DELETE FROM auth_audit WHERE id IN (
                    SELECT a.id FROM auth_audit a WHERE a.timestamp<?
                    AND NOT EXISTS (SELECT 1 FROM auth_job_links j WHERE j.intent_id=a.id)
                    AND NOT EXISTS (SELECT 1 FROM auth_job_links j WHERE j.event_id=a.id)
                    AND (a.outcome<>'started' OR (
                        a.action='http.operation' AND EXISTS (
                            SELECT 1 FROM auth_audit terminal
                            WHERE terminal.request_id=a.request_id
                            AND terminal.action=a.action AND terminal.target=a.target
                            AND terminal.auth_kind=a.auth_kind
                            AND (terminal.actor_id=a.actor_id OR
                                 (terminal.actor_id IS NULL AND a.actor_id IS NULL))
                            AND terminal.timestamp>=a.timestamp
                            AND terminal.outcome IN ('succeeded','failed','denied','cancelled')
                        )
                    ))
                    ORDER BY a.timestamp,a.id LIMIT 1000
                ) RETURNING id""",
                (self.clock() - retention_days * 86400,),
            ).fetchall()
            count = len(deleted)
            self._audit(sql, Actor(), "audit.prune", "auth", "succeeded", details={"count": count})
            return count

    def list_audit(
        self,
        token: str,
        *,
        own: bool = False,
        user_id: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        target: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        self._page(limit, offset, 1000)
        with self._authorized(token, admin=not own) as (sql, session):
            return audit_query(
                sql,
                user_id=session.user.id if own else user_id,
                action=action,
                outcome=outcome,
                target=target,
                since=since,
                until=until,
                limit=limit,
                offset=offset,
            )

    def export_audit(
        self,
        token: str,
        *,
        user_id: str | None = None,
        action: str | None = None,
        outcome: str | None = None,
        target: str | None = None,
        since: float | None = None,
        until: float | None = None,
        limit: int = 50,
        offset: int = 0,
        request_id: str | None = None,
    ) -> AuditExport:
        self._page(limit, offset, 1000)
        with self._authorized(token, admin=True) as (sql, session):
            self._audit(
                sql,
                session.actor,
                "audit.export",
                "/admin/audit/export",
                "succeeded",
                request_id=request_id,
                details={"count": limit},
            )
            page = audit_query(
                sql,
                user_id=user_id,
                action=action,
                outcome=outcome,
                target=target,
                since=since,
                until=until,
                limit=limit,
                offset=offset,
            )
            content = "".join(json.dumps(item, ensure_ascii=True) + "\n" for item in page["items"])
            next_offset = offset + len(page["items"])
            result = AuditExport(
                content, page["total"], next_offset if next_offset < page["total"] else None
            )
        return result
