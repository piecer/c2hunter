"""Explicit PostgreSQL migration: python -m c2hunter_controller.migrate."""

from __future__ import annotations

import argparse
import os
import sys
from typing import cast

from .production import MinioBlobStore, PostgresRepository


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Initialize/upgrade the controller PostgreSQL schema"
    )
    parser.add_argument("--lock-timeout", type=float, default=30, metavar="SECONDS")
    args = parser.parse_args(argv)
    # Read only this variable: no application creation, .env loading, blob store,
    # queue connection, model initialization or fallback database.
    database_url = os.environ.get("C2HUNTER_DATABASE_URL")
    if not database_url:
        print("C2HUNTER_DATABASE_URL is required", file=sys.stderr)
        return 2
    try:
        # Schema operations never use blob storage; no service client is created.
        repo = PostgresRepository(database_url, cast(MinioBlobStore, None))
        repo.initialize_schema(lock_timeout_seconds=args.lock_timeout)
    except Exception:
        # Driver errors can include credentials, DSNs and legacy JSON contents.
        print("PostgreSQL migration failed; schema is not confirmed ready", file=sys.stderr)
        return 1
    print("PostgreSQL controller schema ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
