"""Explicit isolation for legacy migration tests, not PostgreSQL emulation."""

from typing import Any

import pytest

from c2hunter_controller import historical_ai_sql
from c2hunter_controller.production import PostgresRepository


def isolate_historical_migration(
    monkeypatch: pytest.MonkeyPatch, repository: PostgresRepository, expected: Any
) -> list[Any]:
    """Keep PCAP DDL/commit assertions separate from the additive owner migration.

    Only callers that opt in replace this initializer. The real initializer's
    constructor ordering, transaction and failure contracts are exercised in
    test_historical_ai_storage_postgres; real PG catalog acceptance is separate.
    """
    calls: list[Any] = []

    def initialize(connection: Any) -> None:
        assert connection is expected
        assert repository._connection is None
        assert not connection.closed and connection.autocommit is False
        assert connection.commits == 2
        assert any("CREATE TABLE IF NOT EXISTS baseline_catalog" in q for q, _ in connection.calls)
        calls.append(connection)

    monkeypatch.setattr(historical_ai_sql, "initialize_postgres", initialize)
    return calls
