"""Shared adapter matrix; PostgreSQL is opt-in and fixture-owned only."""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from c2hunter_controller.production import MinioBlobStore, PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.fixture(name="adapter", params=["memory", "sqlite", "postgres"])
def publication_adapter(request: pytest.FixtureRequest, tmp_path: Path) -> Iterator[Any]:
    if request.param == "memory":
        yield MemoryRepository()
    elif request.param == "sqlite":
        repository = SQLiteRepository(tmp_path / "adapter.db")
        yield repository
        repository.close()
    else:
        config = os.environ.get("H2H3_PG_FIXTURE")
        if not config:
            pytest.skip("requires invocation-owned PostgreSQL fixture")
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        dsn = json.loads(Path(config).read_text())["dsn"]
        schema = "publication_" + uuid.uuid4().hex
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        repository = PostgresRepository(
            make_conninfo(dsn, options=f"-c search_path={schema}"),
            cast(MinioBlobStore, SimpleNamespace(delete=lambda key: None)),
        )
        try:
            assert repository.connection is not None
            yield repository
        finally:
            repository.close()
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))
