"""Memory corruption is not legitimate absence; keys remain literal UUIDs."""

from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from c2hunter_controller.repositories import MemoryRepository
from tests import test_baseline_scope_storage as storage_fixtures
from tests import test_historical_read_postgres as pg_fixtures
from tests.test_historical_source import START, config

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


def test_memory_present_null_is_corruption_not_absence() -> None:
    repo = MemoryRepository()
    repo._baseline_scopes[config().scope_id] = None
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.get_baseline_scope(config().scope_id)


def test_memory_bad_catalog_key_is_storage_corruption() -> None:
    repo = MemoryRepository()
    value, _ = repo.create_baseline_scope(config(), "admin", START)
    repo._baseline_scopes[17] = value
    with pytest.raises(ValueError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        repo.page_baseline_scopes()


def test_uuid_spelling_preserved_and_lexical_page(scope_repo: Any) -> None:
    ids = [
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA",
        "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB",
    ]
    for identifier in ids:
        cfg = h.ScopeConfig.from_mapping(dict(config().to_mapping(), scope_id=identifier))
        result, _ = scope_repo.create_baseline_scope(cfg, "admin", START)
        assert result.config.scope_id == identifier
    assert [item.config.scope_id for item in scope_repo.page_baseline_scopes().items] == sorted(ids)
