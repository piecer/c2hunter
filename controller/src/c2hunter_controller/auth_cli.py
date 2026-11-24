"""Explicit local auth administration. Never imports the HTTP application/settings.

Passwords are confirmed on a TTY with getpass; no password argument or stdin fallback.
The reconciliation reader is a bounded server-only integration seam, not a dispatcher.
Configured PostgreSQL readers are metadata-only; process-local memory is refused.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
import warnings
from collections.abc import Callable
from typing import Any, NoReturn

from .auth_models import Actor, AuthError, JobLink
from .auth_store import AuthStore


def configured_store() -> AuthStore:
    dsn = os.environ.get("C2HUNTER_DATABASE_URL", "memory://")
    if dsn == "memory://":
        return AuthStore(
            sqlite_path=os.environ.get("C2HUNTER_AUTH_DATABASE_PATH", "data/security/auth.sqlite3")
        )
    return AuthStore(database_url=dsn)


def _password() -> str:
    # getpass normally warns then echoes through redirected stdin. Refuse that fallback.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        first = getpass.getpass("Password: ")
        second = getpass.getpass("Confirm password: ")
    if first != second:
        raise AuthError("PASSWORD_MISMATCH", 422)
    return first


def reconcile(
    store: AuthStore,
    reader: Callable[[JobLink], str | None],
    *,
    limit: int = 100,
    cursor: str | None = None,
) -> dict[str, Any]:
    page = store.pending_job_links(limit, cursor)
    completed = 0
    for link in page["items"]:
        state = reader(link)
        if state is not None:
            completed += store.finish_job(link.family, link.resource_id, state) == "complete"
    count = len(page["items"])
    store.record_event(Actor(), "audit.reconcile", "auth", "succeeded", details={"count": count})
    return dict(
        examined=count,
        completed=completed,
        pending=count - completed,
        next_cursor=page["next_cursor"],
    )


def _limit(value: str) -> int:
    parsed = int(value)
    if not 1 <= parsed <= 1000:
        raise argparse.ArgumentTypeError("limit must be 1..1000")
    return parsed


class SafeParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse otherwise includes unrecognized values, possibly submitted passwords.
        self.print_usage(sys.stderr)
        self.exit(2, "Invalid command arguments\n")


def main(
    argv: list[str] | None = None, *, reader: Callable[[JobLink], str | None] | None = None
) -> int:
    parser = SafeParser(prog="python -m c2hunter_controller.auth_cli")
    commands = parser.add_subparsers(dest="command", required=True, parser_class=SafeParser)
    commands.add_parser("init")
    for command in ("bootstrap", "reset-password"):
        commands.add_parser(command).add_argument("username")
    reconcile_parser = commands.add_parser("reconcile-audit")
    reconcile_parser.add_argument("--limit", type=_limit, default=100)
    reconcile_parser.add_argument("--cursor", default=None)
    args = parser.parse_args(argv)
    try:
        store = configured_store()
        if args.command == "init":
            store.initialize()
        elif args.command == "bootstrap":
            store.bootstrap(args.username, _password())
        elif args.command == "reset-password":
            store.local_reset_password(args.username, _password())
        else:
            if reader is None:
                from .auth_reconcile import configured_reader

                with configured_reader() as persistent_reader:
                    result = reconcile(
                        store, persistent_reader, limit=args.limit, cursor=args.cursor
                    )
            else:
                result = reconcile(store, reader, limit=args.limit, cursor=args.cursor)
            print(json.dumps(result))
            return 0
        print("Auth operation completed")
        return 0
    except AuthError as exc:
        print(exc.code, file=sys.stderr)
    except (ValueError, EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print("Auth operation refused", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
