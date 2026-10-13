"""Actual PG adapter gates using one externally owned server, isolated schemas."""

from typing import Any

import pytest

from tests import test_baseline_http_approval as approval
from tests import test_baseline_http_concurrency as concurrency
from tests import test_baseline_http_pages as pages
from tests import test_baseline_http_preview as preview
from tests import test_historical_read_postgres as fixtures

pg_repo = fixtures.pg_repo


def test_pg_eight_real_routes(pg_repo: Any) -> None:
    pages.test_eight_paths_sources_events_retire_reopen(pg_repo)


def test_pg_replay_compute_busy(pg_repo: Any, monkeypatch: Any) -> None:
    approval.test_approval_replay_busy_sourcegone_current_control(pg_repo, monkeypatch)


def test_pg_shared_preview_admission(pg_repo: Any, monkeypatch: Any) -> None:
    preview.test_preview_compute_busy_before_source_and_distinct_app(pg_repo, monkeypatch)


def test_pg_http_cancellation_lifetime(pg_repo: Any, monkeypatch: Any) -> None:
    concurrency.test_cancel_actual_publication_owns_compute_and_transport(pg_repo, monkeypatch)


@pytest.mark.parametrize("same", [False, True])
def test_pg_serialized_races(pg_repo: Any, monkeypatch: Any, same: bool) -> None:
    concurrency.test_serialized_same_facade_race_no_duplicate_computation(
        pg_repo, monkeypatch, same
    )
