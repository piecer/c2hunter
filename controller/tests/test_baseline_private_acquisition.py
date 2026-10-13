"""Private acquisition preserves transaction custody independently of finish."""

from typing import Any

import pytest

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_read as r
from tests.test_historical_source import stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("missing", [False, True])
def test_private_acquisition_preserves_caller_sentinel(scope_repo: Any, missing: bool) -> None:
    repo = scope_repo
    repo.save_job(stored())
    if hasattr(repo, "jobs"):
        operation = getattr(r, "_memory_acquire", None)
        assert callable(operation), "private Memory acquisition missing"
        with repo._lock:
            if missing:
                with pytest.raises(ValueError, match="BASELINE_SOURCE_NOT_FOUND"):
                    operation(repo.jobs, repo.candidates, "absent", "APPROVAL", structural=True)
            else:
                assert (
                    len(
                        operation(
                            repo.jobs, repo.candidates, "root", "APPROVAL", structural=True
                        ).flows
                    )
                    == 32
                )
        return
    pg = hasattr(repo, "database_url")
    operation = getattr(r, "_postgres_acquire" if pg else "_sqlite_acquire", None)
    assert callable(operation), "private caller-owned SQL acquisition missing"
    con = repo.connection
    con.execute("CREATE TEMP TABLE scope_sentinel(value INTEGER)")
    con.commit()
    con.execute("BEGIN")
    con.execute("INSERT INTO scope_sentinel VALUES(73)")
    try:
        with con.cursor() if pg else __import__("contextlib").nullcontext(con) as cursor:
            if missing:
                with pytest.raises(ValueError, match="BASELINE_SOURCE_NOT_FOUND"):
                    operation(cursor, "absent", "APPROVAL", structural=True)
            else:
                assert len(operation(cursor, "root", "APPROVAL", structural=True).flows) == 32
        assert (con.info.transaction_status.name == "INTRANS") if pg else con.in_transaction
        assert con.execute("SELECT value FROM scope_sentinel").fetchone()[0] == 73
    finally:
        con.rollback()
    assert con.execute("SELECT count(*) FROM scope_sentinel").fetchone()[0] == 0
    con.rollback()
