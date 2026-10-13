"""Observed SQL purity, fast revision and whole-source/candidate bounds."""

from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_read as r
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


def recording(repo: Any, monkeypatch: Any, statements: list[str]) -> None:
    if hasattr(repo, "jobs"):
        return
    if not hasattr(repo, "database_url"):
        repo.connection.set_trace_callback(statements.append)
        return
    import psycopg

    class Cursor(psycopg.Cursor):
        def execute(self, query: Any, params: Any = None, **kwargs: Any) -> Any:
            statements.append(str(query))
            return super().execute(query, params, **kwargs)

    class ServerCursor(psycopg.ServerCursor):
        def execute(self, query: Any, params: Any = None, **kwargs: Any) -> Any:
            statements.append(str(query))
            return super().execute(query, params, **kwargs)

    monkeypatch.setattr(repo.connection, "cursor_factory", Cursor)
    monkeypatch.setattr(repo.connection, "server_cursor_factory", ServerCursor)


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
def test_observed_preview_mutations_and_candidate_selects(
    scope_repo: Any, monkeypatch: Any, purpose: str
) -> None:
    repo = scope_repo
    repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(stored())
    repo.save_candidates("root", [{"id": "one", "candidate_ip": "203.0.113.9", "score": 1}])
    statements: list[str] = []
    recording(repo, monkeypatch, statements)
    if hasattr(repo, "jobs"):
        before = repr(
            {key: value for key, value in vars(repo).items() if isinstance(value, dict | list)}
        )
    with monkeypatch.context() as guard:
        guard.setattr("uuid.uuid4", lambda: pytest.fail("preview allocated identifier"))
        guard.setattr(
            "c2hunter_controller.historical_baseline.QualityReview.__init__",
            lambda *_a, **_k: pytest.fail("preview constructed assertion"),
        )
        result = repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
    assert result.eligible_profile_count == 4
    if hasattr(repo, "jobs"):
        assert before == repr(
            {key: value for key, value in vars(repo).items() if isinstance(value, dict | list)}
        )
    writes = [
        q
        for q in statements
        if q.lstrip().split(" ", 1)[0].upper()
        in {"INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP", "ALTER"}
    ]
    candidates = [
        q
        for q in statements
        if "candidate" in q.lower() and q.lstrip().upper().startswith("SELECT")
    ]
    assert writes == []
    if purpose == "APPROVAL":
        assert candidates == []
    elif not hasattr(repo, "jobs"):
        assert len(candidates) >= 2
    receipt(
        {
            "backend": "memory"
            if hasattr(repo, "jobs")
            else "postgres"
            if hasattr(repo, "database_url")
            else "sqlite",
            "purpose": purpose,
            "statements": len(statements),
            "candidate_selects": len(candidates),
            "mutations": len(writes),
        }
    )


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
def test_fast_revision_precedes_source(scope_repo: Any, monkeypatch: Any, purpose: str) -> None:
    scope_repo.create_baseline_scope(config(), "admin", START)
    for name in ("_memory_acquire", "_sqlite_acquire", "_postgres_acquire"):
        monkeypatch.setattr(
            r, name, lambda *_a, **_k: pytest.fail("source acquired after stale revision")
        )
    with pytest.raises(ValueError, match="^BASELINE_REVISION_CONFLICT$"):
        scope_repo.preview_baseline_source(config().scope_id, "nonexistent", 1, purpose)


@pytest.mark.parametrize("row_count", [8192, 8193])
def test_actual_preview_flow_count_boundary(scope_repo: Any, row_count: int) -> None:
    raw = stored()
    raw["status"] = "PARTIALLY_COMPLETED"
    raw["flow_records"] = [raw["flow_records"][0]] * row_count
    scope_repo.create_baseline_scope(config(), "admin", START)
    scope_repo.save_job(raw)
    if row_count == 8193:
        with pytest.raises(ValueError, match="^BASELINE_SOURCE_LIMIT$"):
            scope_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
    else:
        result = scope_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
        assert (
            result.flow_count == 8192
            and result.eligible_profile_count == 1
            and not result.admissible
        )


@pytest.mark.parametrize("count", [2048, 2049])
def test_candidate_count_does_not_touch_approval(scope_repo: Any, count: int) -> None:
    scope_repo.create_baseline_scope(config(), "admin", START)
    scope_repo.save_job(stored())
    scope_repo.save_candidates(
        "root",
        [
            {"id": f"rule-{i:04}", "candidate_ip": "203.0.113.9", "score": i % 100}
            for i in range(count)
        ],
    )
    assert scope_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL").admissible
    if count == 2049:
        with pytest.raises(ValueError, match="^BASELINE_CANDIDATE_LIMIT$"):
            scope_repo.preview_baseline_source(config().scope_id, "root", 0, "COMPARISON")
    else:
        assert scope_repo.preview_baseline_source(
            config().scope_id, "root", 0, "COMPARISON"
        ).admissible


def test_candidate_mutation_binds_comparison_only(scope_repo: Any) -> None:
    repo = scope_repo
    repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(stored())
    candidates = [
        {"id": "one", "candidate_ip": "203.0.113.9", "score": 1},
        {"id": "two", "candidate_ip": "203.0.113.10", "score": 2},
    ]
    repo.save_candidates("root", candidates)
    first = {
        p: repo.preview_baseline_source(config().scope_id, "root", 0, p)
        for p in ("APPROVAL", "COMPARISON")
    }
    repo.save_candidates(
        "root", [dict(candidates[1], excluded=True), dict(candidates[0], score=99)]
    )
    second = {
        p: repo.preview_baseline_source(config().scope_id, "root", 0, p)
        for p in ("APPROVAL", "COMPARISON")
    }
    assert first["APPROVAL"] == second["APPROVAL"]
    assert first["COMPARISON"].source_binding_sha256 != second["COMPARISON"].source_binding_sha256
    assert first["COMPARISON"].observation_sha256 == second["COMPARISON"].observation_sha256


@pytest.mark.parametrize("offset,limit", [(True, 1), (-1, 1), (17, 1), (0, True), (0, 0), (0, 21)])
def test_invalid_pagination_before_sql(
    scope_repo: Any, monkeypatch: Any, offset: Any, limit: Any
) -> None:
    monkeypatch.setattr(
        bs._SQL, "execute", lambda *_a, **_k: pytest.fail("SQL before argument validation")
    )
    with pytest.raises(ValueError):
        scope_repo.page_baseline_scopes(offset, limit)
