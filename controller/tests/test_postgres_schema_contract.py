"""Offline contracts for schema metadata and the explicit migration CLI."""

import hashlib
import json
from pathlib import Path

import pytest

from c2hunter_controller import migrate, postgres_schema
from c2hunter_controller.production import PostgresRepository


def test_schema_refusal_preserves_historical_http_unavailable_contract():
    from c2hunter_controller.api_errors import ApiError
    from c2hunter_controller.historical_ai_http import domain_errors

    with pytest.raises(ApiError) as raised, domain_errors():
        raise postgres_schema.SchemaNotReady()
    assert raised.value.status == 503
    assert raised.value.code == "BASELINE_STORAGE_UNAVAILABLE"


def test_schema_digest_is_bound_to_reviewable_catalog_fixture():
    value = json.loads((Path(__file__).parent / "fixtures/postgres_schema_v1.json").read_text())
    encoded = json.dumps(value["layout"], separators=(",", ":"), ensure_ascii=True).encode()
    assert hashlib.sha256(encoded).hexdigest() == value["sha256"] == postgres_schema.LAYOUT_SHA256
    assert tuple(value["tables"]) == postgres_schema.TABLES


@pytest.mark.parametrize("timeout", [0, -1, 301, float("inf"), float("nan")])
def test_invalid_migration_lock_budget_refuses_before_connect(monkeypatch, timeout):
    import psycopg

    def forbidden(*args, **kwargs):
        pytest.fail("invalid lock budget attempted a connection")

    monkeypatch.setattr(psycopg, "connect", forbidden)
    repo = PostgresRepository("unused", None)
    with pytest.raises(ValueError, match="migration lock timeout"):
        repo.initialize_schema(lock_timeout_seconds=timeout)


def test_cli_requires_explicit_database_without_loading_settings(monkeypatch, capsys):
    monkeypatch.delenv("C2HUNTER_DATABASE_URL", raising=False)
    assert migrate.main([]) == 2
    assert "C2HUNTER_DATABASE_URL is required" in capsys.readouterr().err


def test_cli_failure_is_nonzero_and_sanitized(monkeypatch, capsys):
    monkeypatch.setenv("C2HUNTER_DATABASE_URL", "synthetic-sensitive-url")

    def fail(self, **kwargs):
        raise RuntimeError("synthetic-sensitive-url and legacy private data")

    monkeypatch.setattr(PostgresRepository, "initialize_schema", fail)
    assert migrate.main([]) == 1
    result = capsys.readouterr()
    assert result.out == ""
    assert result.err == "PostgreSQL migration failed; schema is not confirmed ready\n"
