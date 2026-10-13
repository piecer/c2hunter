"""Candidate context limits preserve the existing source projection policy."""

from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_read as r
from tests.test_baseline_preview_admission_completion import candidate_rows
from tests.test_baseline_scope_bounds import recording
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize(
    "field", ["internal_hosts", "hosts", "protocols", "ports", "prefilter_factors"]
)
@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "clock"])
def test_candidate_context_domain_code(
    scope_repo: Any, field: str, extra: int, purpose: str, quality: str, monkeypatch: Any
) -> None:
    repo = scope_repo
    repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    if quality == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    if quality == "clock":
        raw["capture_quality"] = {"clock_skew_detected": True}
    repo.save_job(raw)
    scalar = (
        443
        if field == "ports"
        else {"name": "fixture"}
        if field == "prefilter_factors"
        else "fixture"
    )
    candidate_rows(
        repo,
        [
            {
                "id": "rule",
                "candidate_ip": "203.0.113.9",
                "score": 40,
                field: [scalar] * (128 + extra),
            }
        ],
    )
    queries = []
    recording(repo, monkeypatch, queries)
    if extra and purpose == "COMPARISON":
        # Raw-context _array uses SOURCE_LIMIT; do not invent CANDIDATE_LIMIT,
        # which is reserved here for the acquisition row/count/byte budgets.
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LIMIT$"):
            repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
    else:
        result = repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
        assert result.flow_count == 32 and result.admissible is (quality == "clean")
    if purpose == "APPROVAL":
        assert not any("candidate" in query.lower() for query in queries)
