"""Actual source-byte admission and operation-schema migration failures."""

import sqlite3
from contextlib import closing
from typing import Any

import pytest

from c2hunter_controller import _baseline_storage as bs
from c2hunter_controller import historical_generation as g
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import SQLiteRepository
from tests import test_baseline_approval_contract as fixtures
from tests.test_historical_read_bounds import pad, put_flows, put_metadata
from tests.test_historical_source import START, config, review, stored

approval_repo = fixtures.approval_repo
pg_repo = fixtures.pg_repo


@pytest.mark.parametrize(
    "axis,limit", [("flow-row", 65536), ("metadata", 262144), ("flow-count", 8192)]
)
@pytest.mark.parametrize("extra", [0, 1])
def test_source_admission_budget(
    approval_repo: Any, axis: str, limit: int, extra: int, monkeypatch: Any
) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    repo.save_job(raw)
    if axis == "flow-count":
        rows = [dict(raw["flow_records"][i % 32]) for i in range(limit + extra)]
        put_flows(repo, rows)
    elif axis == "flow-row":
        rows = raw["flow_records"]
        rows[0] = pad(repo, rows[0], limit + extra)
        put_flows(repo, rows)
    else:
        metadata = {k: v for k, v in raw.items() if k != "flow_records"}
        put_metadata(repo, pad(repo, metadata, limit + extra))
    request = g.ApprovalRequest(
        expected_revision=0,
        idempotency_key="bounds",
        source_job_id="root",
        source_binding_sha256="0" * 64,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="synthetic admission",
    )
    if not extra:
        preview = repo.preview_baseline_source(config().scope_id, "root", 0, "APPROVAL")
        request = g.ApprovalRequest.from_mapping(
            dict(request.to_mapping(), source_binding_sha256=preview.source_binding_sha256)
        )
        assert repo.publish_baseline_source(config().scope_id, request, "reviewer", START).created
    else:

        def forbidden(*args: Any, **kw: Any) -> Any:
            raise AssertionError("over-budget source reached producer")

        monkeypatch.setattr(g, "produce_generation", forbidden)
        with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_LIMIT$"):
            repo.publish_baseline_source(config().scope_id, request, "reviewer", START)
        assert repo.get_baseline_scope(config().scope_id).control_revision == 0


def test_partial_state_before_flows(approval_repo: Any, monkeypatch: Any) -> None:
    repo = approval_repo
    repo.create_baseline_scope(config(), "admin", START)
    request = fixtures.prepare(repo)
    raw = repo.get_job(request.source_job_id)
    raw["status"] = "PARTIALLY_COMPLETED"
    repo.save_job(raw)

    def forbidden(*args: Any, **kw: Any) -> Any:
        raise AssertionError("partial approval reached flow acquisition")

    for name in ("_admit_rows", "_sqlite_flows", "_pg_flows"):
        monkeypatch.setattr(r, name, forbidden)
    with pytest.raises(bs.BaselineStorageError, match="^BASELINE_SOURCE_STATE$"):
        repo.publish_baseline_source(config().scope_id, request, "reviewer", START)


def test_sqlite_new_operation_ddl_failure_closes_owned_connection(
    tmp_path: Any, monkeypatch: Any
) -> None:
    path = tmp_path / "migration.sqlite"
    with closing(SQLiteRepository(path)) as old:
        old.create_baseline_scope(config(), "admin", START)
        old.save_job(stored())
        old.connection.execute("DROP TABLE baseline_operations")
        old.connection.commit()
    actual_connect = sqlite3.connect
    observed, fired = [], []

    def connect(*args: Any, **kw: Any) -> Any:
        connection = actual_connect(*args, **kw)
        observed.append(connection)

        def authorize(action: int, first: str, *_args: Any) -> int:
            if action == sqlite3.SQLITE_CREATE_TABLE and first == "baseline_operations":
                fired.append(True)
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorize)
        return connection

    with monkeypatch.context() as guard:
        guard.setattr(sqlite3, "connect", connect)
        try:
            with pytest.raises(sqlite3.DatabaseError):
                SQLiteRepository(path)
            assert fired == [True] and len(observed) == 1
            with pytest.raises(sqlite3.ProgrammingError):
                observed[0].execute("SELECT 1")
        finally:
            for connection in observed:
                connection.close()
    with closing(SQLiteRepository(path)) as reopened:
        assert reopened.get_baseline_scope(config().scope_id).control_revision == 0
        assert reopened.get_job("root")["id"] == "root"
        assert reopened.connection.execute(
            "SELECT count(*) FROM baseline_operations"
        ).fetchone() == (0,)
