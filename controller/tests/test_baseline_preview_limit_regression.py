"""Persisted preview limits retain domain codes; shared future PG replay."""

from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_read as r
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


def source(axis: str, extra: int, quality: str) -> dict[str, Any]:
    raw = stored()
    if quality == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    elif quality == "clock":
        raw["capture_quality"] = {"clock_skew_detected": True}
    if axis == "packet_sizes":
        raw["flow_records"][0]["packet_sizes"] = [1] * (128 + extra)
    elif axis == "syn":
        for row in raw["flow_records"]:
            row["tcp_syn_only_observations"] = [[0, i] for i in range(8)]
        if extra:
            raw["flow_records"][-1]["tcp_syn_only_observations"].append([0, 99])
    elif axis == "invalid":
        raw["flow_records"][0]["packet_count"] = True
    else:
        raw["operations"] = {axis: [f"sensor-{i}" for i in range(128 + extra)]}
    return raw


@pytest.mark.parametrize("axis", ["packet_sizes", "warnings", "failed_sensors", "syn"])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "clock"])
@pytest.mark.parametrize("extra", [0, 1])
def test_persisted_preview_limit_code(
    scope_repo: Any, axis: str, purpose: str, quality: str, extra: int
) -> None:
    repo = scope_repo
    scope, _ = repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(source(axis, extra, quality))
    if extra:
        with pytest.raises(r.HistoricalReadError) as caught:
            repo.preview_baseline_source(scope.config.scope_id, "root", 0, purpose)
        actual = caught.value.code
    else:
        preview = repo.preview_baseline_source(scope.config.scope_id, "root", 0, purpose)
        assert preview.flow_count == 32
        assert preview.known_partial is (quality == "partial" or axis == "failed_sensors")
        assert preview.admissible is (quality == "clean" and axis != "failed_sensors")
        actual = None
    if hasattr(repo, "connection"):
        assert (
            repo.connection.info.transaction_status.name == "IDLE"
            if hasattr(repo, "database_url")
            else not repo.connection.in_transaction
        )
    assert repo.get_baseline_scope(scope.config.scope_id) == scope
    repo.save_job(stored())
    with ThreadPoolExecutor(max_workers=1) as pool:
        assert (
            pool.submit(repo.preview_baseline_source, scope.config.scope_id, "root", 0, purpose)
            .result(10)
            .admissible
        )
    assert actual == ("BASELINE_SOURCE_LIMIT" if extra else None)


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "clock"])
def test_semantic_malformed_remains_invalid(scope_repo: Any, purpose: str, quality: str) -> None:
    scope_repo.create_baseline_scope(config(), "admin", START)
    scope_repo.save_job(source("invalid", 0, quality))
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
        scope_repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
