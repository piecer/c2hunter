"""Repository-only scope/structural preview vertical; no review authority."""

from datetime import timedelta
from typing import Any

import pytest

import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_baseline as h
from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_read import poison
from tests.test_historical_source import START, config, stored

pg_repo = pg_fixtures.pg_repo

PREVIEW_KEYS = set(
    "scope_id scope_revision scope_config_sha256 source_job_id "
    "root_job_id dataset_id source_binding_sha256 observation_sha256 "
    "feature_observation_sha256 origin origin_assurance "
    "actual_sensor_id event_start event_end flow_count profile_count "
    "eligible_profile_count excluded_profile_count admissible reasons "
    "required_review producer_completeness known_partial "
    "stored_clock_offset_ms".split()
)


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def scope_repo(request: Any, tmp_path: Any) -> Any:
    if request.param == "postgres":
        return request.getfixturevalue("pg_repo")
    repo = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "scopes.sqlite")
    )
    request.addfinalizer(repo.close)
    return repo


def test_create_preview_reopen_vertical(scope_repo: Any, monkeypatch: Any) -> None:
    repo = scope_repo
    create = getattr(repo, "create_baseline_scope", None)
    assert callable(create), "scope-create repository operation is missing"
    cfg = config()
    view, created = create(cfg, "admin", START)
    assert created is True
    assert view.config == cfg and view.config_sha256 == h.scope_config_sha256(cfg)
    assert view.control_revision == 0 and view.state == "EMPTY" and view.frozen is False
    assert view.active is None and view.previous is None and view.accepted_event_end is None
    assert view.created_by == "admin" and view.created_at == START
    assert create(cfg, "admin", START + timedelta(days=1)) == (view, False)
    assert repo.get_baseline_scope(cfg.scope_id) == view
    page = repo.page_baseline_scopes(0, 20)
    assert page.to_mapping() == {
        "items": [view.to_mapping()],
        "total": 1,
        "offset": 0,
        "limit": 20,
        "next_offset": None,
    }
    repo.save_job(stored())
    for name in ("get_job", "get_job_summary", "list_jobs", "get_candidates"):
        monkeypatch.setattr(repo, name, poison)
    monkeypatch.setattr("c2hunter_controller.historical_source.source_build_input", poison)
    result = repo.preview_baseline_source(cfg.scope_id, "root", 0, "APPROVAL")
    assert set(result.to_mapping()) == PREVIEW_KEYS
    assert result.flow_count == 32
    assert (result.profile_count, result.eligible_profile_count, result.excluded_profile_count) == (
        4,
        4,
        0,
    )
    assert result.admissible is True and result.known_partial is False
    assert result.stored_clock_offset_ms is None
    assert result.reasons == ("ADMIN_ASSERTED_IDENTITY", "PRODUCER_COMPLETENESS_UNKNOWN")
    assert result.actual_sensor_id == "sensor"
    assert result.required_review == "EXPLICIT_NORMAL_AND_QUALITY_ASSERTION"
    assert result.producer_completeness == "UNKNOWN"
    reopened = None
    if isinstance(repo, SQLiteRepository):
        reopened = SQLiteRepository(repo._path)
    elif isinstance(repo, PostgresRepository):
        reopened = PostgresRepository(repo.database_url, None)
    if reopened is not None:
        try:
            assert reopened.get_baseline_scope(cfg.scope_id) == view
            assert reopened.preview_baseline_source(cfg.scope_id, "root", 0, "APPROVAL") == result
        finally:
            reopened.close()
