"""Caller-owned private acquisition and final preview retain custody."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import START, config, stored


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("fault", ["none", "missing", "limit", "malformed"])
def test_private_preview_caller_custody(
    backend: str, purpose: str, fault: str, tmp_path: Any, record_property: Any
) -> None:
    repo = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "custody.sqlite")
    )
    with closing(repo):
        head, _ = repo.create_baseline_scope(config(), "admin", START)
        raw = stored()
        if fault == "limit":
            raw["flow_records"][0]["packet_sizes"] = [1] * 129
        if fault == "malformed":
            raw["flow_records"][0]["packet_count"] = True
        repo.save_job(raw)
        con = None if backend == "memory" else repo.connection
        if con is not None:
            con.execute("CREATE TEMP TABLE owned_sentinel(value INTEGER)")
            con.commit()
            con.execute("BEGIN")
            con.execute("INSERT INTO owned_sentinel VALUES(97)")
        selected = "absent" if fault == "missing" else "root"
        try:
            with repo._lock:

                def operation() -> Any:
                    acquired = (
                        r._memory_acquire(
                            repo.jobs, repo.candidates, selected, purpose, structural=True
                        )
                        if con is None
                        else r._sqlite_acquire(con, selected, purpose, structural=True)
                    )
                    return bs.finish_preview(acquired, head, purpose)

                if fault == "none":
                    assert operation().admissible
                else:
                    code = {
                        "missing": "BASELINE_SOURCE_NOT_FOUND",
                        "limit": "BASELINE_SOURCE_LIMIT",
                        "malformed": "BASELINE_SOURCE_INVALID",
                    }[fault]
                    with pytest.raises(r.HistoricalReadError, match="^" + code + "$"):
                        operation()
                if con is not None:
                    assert con.in_transaction
                    assert con.execute("SELECT value FROM owned_sentinel").fetchone() == (97,)
                    for public in (
                        lambda: repo.create_baseline_scope(config(), "admin", START),
                        lambda: repo.get_baseline_scope(config().scope_id),
                        repo.page_baseline_scopes,
                        lambda: repo.preview_baseline_source(config().scope_id, "root", 0, purpose),
                    ):
                        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_BUSY$"):
                            public()
                        assert con.in_transaction
                        assert con.execute("SELECT value FROM owned_sentinel").fetchone() == (97,)
        finally:
            if con is not None:
                con.rollback()
        if con is not None:
            assert con.execute("SELECT count(*) FROM owned_sentinel").fetchone() == (0,)
            assert not con.in_transaction
        repo.save_job(stored())
        with ThreadPoolExecutor(max_workers=1) as pool:
            assert (
                pool.submit(repo.preview_baseline_source, config().scope_id, "root", 0, purpose)
                .result(10)
                .admissible
            )
        record_property(
            "caller_custody",
            "memory-held-lock" if con is None else "active-sentinel-until-caller-rollback",
        )
