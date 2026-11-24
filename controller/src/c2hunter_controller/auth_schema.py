"""Independently versioned, explicit auth schema; never imported by core migrations."""

from __future__ import annotations

import os
import secrets
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row

from .auth_models import AuthError

VERSION = "1"
DDL = (
    "CREATE TABLE IF NOT EXISTS auth_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    """CREATE TABLE IF NOT EXISTS auth_users (
        id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, role TEXT NOT NULL,
        active INTEGER NOT NULL, must_change_password INTEGER NOT NULL,
        password_hash TEXT NOT NULL, generation INTEGER NOT NULL)""",
    """CREATE TABLE IF NOT EXISTS auth_audit (
        id TEXT PRIMARY KEY, timestamp DOUBLE PRECISION NOT NULL, actor_id TEXT,
        actor_name TEXT, actor_role TEXT, auth_kind TEXT NOT NULL, action TEXT NOT NULL,
        target TEXT NOT NULL, outcome TEXT NOT NULL, request_id TEXT, source_ip TEXT,
        status INTEGER, job_id TEXT, details TEXT NOT NULL)""",
    "CREATE INDEX IF NOT EXISTS auth_audit_order ON auth_audit(timestamp DESC,id DESC)",
    """CREATE TABLE IF NOT EXISTS auth_sessions (
        id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL,
        generation INTEGER NOT NULL, created_at DOUBLE PRECISION NOT NULL,
        last_seen_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL,
        FOREIGN KEY(user_id) REFERENCES auth_users(id))""",
    "CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id)",
    """CREATE TABLE IF NOT EXISTS auth_job_links (
        id TEXT PRIMARY KEY, family TEXT NOT NULL, resource_id TEXT NOT NULL,
        actor_id TEXT, actor_name TEXT, actor_role TEXT, auth_kind TEXT NOT NULL,
        request_id TEXT NOT NULL, intent_id TEXT NOT NULL, terminal_status TEXT, event_id TEXT,
        UNIQUE(family,resource_id), FOREIGN KEY(event_id) REFERENCES auth_audit(id))""",
    "CREATE INDEX IF NOT EXISTS auth_job_pending ON auth_job_links(event_id,id)",
    "CREATE INDEX IF NOT EXISTS auth_job_intent ON auth_job_links(intent_id)",
    """CREATE INDEX IF NOT EXISTS auth_audit_http_terminal
        ON auth_audit(request_id,action,target,timestamp)""",
    """CREATE TABLE IF NOT EXISTS auth_throttle (
        key TEXT PRIMARY KEY, entries TEXT NOT NULL, updated_at DOUBLE PRECISION NOT NULL)""",
)


READINESS_QUERIES = (
    "SELECT id,username,role,active,must_change_password,password_hash,generation "
    "FROM auth_users LIMIT 0",
    """SELECT id,timestamp,actor_id,actor_name,actor_role,auth_kind,action,target,outcome,
        request_id,source_ip,status,job_id,details FROM auth_audit LIMIT 0""",
    """SELECT id,digest,user_id,generation,created_at,last_seen_at,expires_at
        FROM auth_sessions LIMIT 0""",
    "SELECT key,entries,updated_at FROM auth_throttle LIMIT 0",
    """SELECT id,family,resource_id,actor_id,actor_name,actor_role,auth_kind,request_id,
        intent_id,terminal_status,event_id FROM auth_job_links LIMIT 0""",
)


# Runtime DML only: initialization is explicit and needs separate DDL/meta rights.
# SELECT/schema access is already exercised by transaction's shape/key queries.
# One bounded catalog observation; each privilege is conjunctive (a comma-list
# passed to has_table_privilege would instead mean ANY listed privilege).
# Column grants are sufficient when they cover the actual INSERT/UPDATE targets.
POSTGRES_WRITE_READINESS = """
    SELECT current_setting('transaction_read_only') = 'off' AND bool_and(
        has_table_privilege(relation, privilege) OR (
            columns IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM unnest(string_to_array(columns, ',')) AS required(column_name)
                WHERE NOT has_column_privilege(relation, column_name, privilege)
            )
        )
    ) AS ready
    FROM (VALUES
        ('auth_users', 'INSERT',
         'id,username,role,active,must_change_password,password_hash,generation'),
        ('auth_users', 'UPDATE', 'role,active,must_change_password,password_hash,generation'),
        ('auth_sessions', 'INSERT',
         'id,digest,user_id,generation,created_at,last_seen_at,expires_at'),
        ('auth_sessions', 'UPDATE', 'last_seen_at'),
        ('auth_sessions', 'DELETE', NULL),
        ('auth_audit', 'INSERT',
         'id,timestamp,actor_id,actor_name,actor_role,auth_kind,action,target,outcome,'
         'request_id,source_ip,status,job_id,details'),
        ('auth_throttle', 'INSERT', 'key,entries,updated_at'),
        ('auth_throttle', 'UPDATE', 'entries,updated_at'),
        ('auth_throttle', 'DELETE', NULL),
        ('auth_job_links', 'INSERT',
         'id,family,resource_id,actor_id,actor_name,actor_role,auth_kind,request_id,intent_id'),
        ('auth_job_links', 'UPDATE', 'terminal_status,event_id')
    ) AS required(relation, privilege, columns)
"""


class SQL:
    def __init__(self, connection: Any, postgres: bool) -> None:
        self.connection = connection
        self.postgres = postgres

    def execute(self, statement: str, parameters: tuple[Any, ...] = ()) -> Any:
        return self.connection.execute(
            statement.replace("?", "%s") if self.postgres else statement, parameters
        )


class Database:
    def __init__(
        self, *, sqlite_path: Path | str | None = None, database_url: str | None = None
    ) -> None:
        if (sqlite_path is None) == (database_url is None):
            raise ValueError("Choose exactly one persistent auth backend")
        if database_url is not None and not database_url.startswith(
            ("postgresql://", "postgres://")
        ):
            raise ValueError("Auth database URL must be PostgreSQL")
        self.path = Path(sqlite_path).absolute() if sqlite_path is not None else None
        self.dsn = database_url

    def _private_path(self, create: bool) -> Path:
        path = self.path
        if path is None:
            raise AuthError("ACCOUNT_SETUP_REQUIRED")
        for part in [path, *path.parents]:
            if part.is_symlink():
                raise AuthError("ACCOUNT_SETUP_REQUIRED")
        if create and not path.parent.exists():
            path.parent.mkdir(mode=0o700, parents=True)
        parent = path.parent.stat()
        if parent.st_uid != os.getuid() or stat.S_IMODE(parent.st_mode) != 0o700:
            raise AuthError("ACCOUNT_SETUP_REQUIRED")
        if create:
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            raise AuthError("ACCOUNT_SETUP_REQUIRED")
        return path

    @contextmanager
    def transaction(self, *, initialize: bool = False) -> Iterator[SQL]:
        connection: Any = None
        try:
            if self.dsn is not None:
                connection = psycopg.connect(self.dsn, connect_timeout=5, row_factory=dict_row)
                connection.execute("SET LOCAL lock_timeout = '5s'")
                connection.execute("SET LOCAL statement_timeout = '10s'")
                # Same bounded lock covers explicit schema changes and all auth mutations.
                connection.execute("SELECT pg_advisory_xact_lock(1127375189, 1)")
            else:
                path = self._private_path(initialize)
                connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, timeout=5)
                connection.row_factory = sqlite3.Row
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("BEGIN IMMEDIATE")
            sql = SQL(connection, self.dsn is not None)
            if not initialize:
                try:
                    version = sql.execute(
                        "SELECT value FROM auth_meta WHERE key='version'"
                    ).fetchone()
                    key = sql.execute("SELECT value FROM auth_meta WHERE key='hmac_key'").fetchone()
                    if not key or not isinstance(key["value"], str) or len(key["value"]) != 64:
                        raise AuthError("ACCOUNT_SETUP_REQUIRED")
                    try:
                        if len(bytes.fromhex(key["value"])) != 32:
                            raise ValueError
                    except ValueError:
                        raise AuthError("ACCOUNT_SETUP_REQUIRED") from None
                    for query in READINESS_QUERIES:
                        sql.execute(query)
                except sqlite3.OperationalError as exc:
                    if exc.sqlite_errorcode != sqlite3.SQLITE_ERROR:
                        raise
                    raise AuthError("ACCOUNT_SETUP_REQUIRED") from None
                except (psycopg.errors.UndefinedTable, psycopg.errors.UndefinedColumn):
                    raise AuthError("ACCOUNT_SETUP_REQUIRED") from None
                if not version or version["value"] != VERSION:
                    raise AuthError("ACCOUNT_SETUP_REQUIRED")
            yield sql
            connection.commit()
        except AuthError:
            if connection is not None:
                connection.rollback()
            raise
        except FileNotFoundError:
            raise AuthError("ACCOUNT_SETUP_REQUIRED") from None
        except (OSError, sqlite3.Error, psycopg.Error):
            if connection is not None:
                connection.rollback()
            raise AuthError("SECURITY_UNAVAILABLE") from None
        finally:
            if connection is not None:
                connection.close()

    def initialize(self, sql: SQL) -> bool:
        for statement in DDL:
            sql.execute(statement)
        version = sql.execute("SELECT value FROM auth_meta WHERE key='version'").fetchone()
        if version:
            if version["value"] != VERSION:
                raise AuthError("ACCOUNT_SETUP_REQUIRED")
            return False
        sql.execute("INSERT INTO auth_meta(key,value) VALUES (?,?)", ("version", VERSION))
        sql.execute(
            "INSERT INTO auth_meta(key,value) VALUES (?,?)", ("hmac_key", secrets.token_hex(32))
        )
        return True
