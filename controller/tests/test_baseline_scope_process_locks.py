"""One live fixture, genuinely separate-process PostgreSQL lock ownership."""

import os
import time
from typing import Any

import pytest

from tests import test_historical_read_postgres as pg_fixtures
from tests.test_baseline_scope_faults import receipt
from tests.test_historical_source import START, config, stored

pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("site", ["catalog", "job", "scope"])
def test_separate_process_pg_lock_and_reap(pg_repo: Any, site: str) -> None:
    import psycopg

    pg_repo.create_baseline_scope(config(), "admin", START)
    pg_repo.save_job(stored())
    ready_r, ready_w = os.pipe()
    release_r, release_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(ready_r)
        os.close(release_w)
        code = 1
        try:
            with psycopg.connect(pg_repo.database_url) as connection:
                query = {
                    "catalog": "SELECT id FROM baseline_catalog FOR UPDATE",
                    "job": "SELECT id FROM controller_objects "
                    "WHERE kind='job' AND id='root' FOR UPDATE",
                    "scope": "SELECT scope_id FROM baseline_scopes FOR UPDATE",
                }[site]
                connection.execute(query)
                os.write(ready_w, b"R")
                assert os.read(release_r, 1) == b"X"
                connection.rollback()
            code = 0
        finally:
            os.close(ready_w)
            os.close(release_r)
            os._exit(code)
    os.close(ready_w)
    os.close(release_r)
    try:
        assert os.read(ready_r, 1) == b"R"
        start = time.monotonic()
        with pytest.raises(ValueError, match="^BASELINE_BUSY$"):
            if site == "catalog":
                pg_repo.create_baseline_scope(config(), "admin", START)
            else:
                pg_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
        elapsed = time.monotonic() - start
        assert 4.5 <= elapsed < 12
        assert pg_repo.connection.info.transaction_status.name == "IDLE"
    finally:
        os.close(ready_r)
        try:
            os.write(release_w, b"X")
        finally:
            os.close(release_w)
            reaped, status = os.waitpid(pid, 0)
    assert reaped == pid and os.waitstatus_to_exitcode(status) == 0
    receipt(
        {
            "backend": "postgres",
            "separate_process_lock": site,
            "elapsed": elapsed,
            "blocker_pid": pid,
            "reaped": True,
            "fired": 1,
        }
    )
    assert pg_repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL").admissible
