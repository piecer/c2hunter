"""Stored clock values are observations, never float-rounded assertions."""

from typing import Any

import pytest

from tests import test_baseline_scope_storage as storage_fixtures
from tests import test_historical_read_postgres as pg_fixtures
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("offset", [9007199254740993, -9007199254740993, 0, -3000.25])
def test_clock_observation_literal_value_is_preserved(scope_repo: Any, offset: Any) -> None:
    scope_repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    raw["operations"] = {"sensors": {"sensor": {"clock_offset_ms": offset}}}
    scope_repo.save_job(raw)
    result = scope_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
    assert result.stored_clock_offset_ms == offset
    assert type(result.stored_clock_offset_ms) is type(offset)
    assert result.to_mapping()["stored_clock_offset_ms"] == offset
    assert type(result.to_mapping()["stored_clock_offset_ms"]) is type(offset)
