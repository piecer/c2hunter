from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest
from publication_fixtures import publication_adapter  # noqa: F401

from c2hunter_controller.production import PostgresRepository
from c2hunter_controller.repositories import SQLiteRepository


def legacy_sqlite(path: Path, *, orphan: bool = False) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            "CREATE TABLE objects(kind TEXT,id TEXT,data TEXT,PRIMARY KEY(kind,id));"
            "CREATE TABLE candidates(job_id TEXT PRIMARY KEY,data TEXT NOT NULL);"
        )
        if not orphan:
            connection.execute(
                "INSERT INTO objects VALUES('job','job',?)",
                (
                    json.dumps(
                        {
                            "id": "job",
                            "status": "ANALYZING",
                            "flow_records": [{"f": 1}],
                            "payload_signatures": [{"s": 2}],
                        }
                    ),
                ),
            )
        connection.execute("INSERT INTO candidates VALUES('job',?)", (json.dumps([{"id": "old"}]),))


def test_sqlite_initializer_owns_one_embedded_and_candidate_transaction(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    legacy_sqlite(path)
    repository = SQLiteRepository(path)
    assert repository.get_job("job")["flow_records"] == [{"f": 1}]
    assert repository.get_job("job")["payload_signatures"] == [{"s": 2}]
    assert repository.get_candidates("job") == [{"id": "old"}]
    assert not repository.connection.in_transaction
    repository.close()


def test_sqlite_initializer_never_migrates_orphans(tmp_path: Path) -> None:
    path = tmp_path / "orphan.db"
    legacy_sqlite(path, orphan=True)
    repository = SQLiteRepository(path)
    assert repository.get_candidates("job") == []
    repository.close()


def test_pg_initializer_never_migrates_orphans(adapter: Any) -> None:
    if not isinstance(adapter, PostgresRepository):
        pytest.skip("PostgreSQL migration")
    adapter.connection.execute(
        "INSERT INTO job_candidates(job_id,data) VALUES('missing','[{\"id\":\"orphan\"}]')"
    )
    adapter.connection.commit()
    adapter.close()
    adapter.initialize_schema()
    assert adapter.get_candidates("missing") == []
    assert adapter.connection.execute(
        "SELECT data FROM job_candidates WHERE job_id='missing'"
    ).fetchone() == ([{"id": "orphan"}],)
    adapter.connection.rollback()


@pytest.mark.parametrize("point", ["flow", "signature", "candidate"])
def test_sqlite_migration_failure_rolls_back_all_embedded_parts(tmp_path: Path, point: str) -> None:
    path = tmp_path / "rollback.db"
    repository = SQLiteRepository(path)
    repository.close()
    job = {"id": "job", "flow_records": [{"f": 1}], "payload_signatures": [{"s": 2}]}
    table = {
        "flow": "job_flow_records",
        "signature": "job_payload_signatures",
        "candidate": "candidate_records",
    }[point]
    with sqlite3.connect(path) as connection:
        connection.execute("INSERT INTO objects VALUES('job','job',?)", (json.dumps(job),))
        connection.execute("INSERT INTO candidates VALUES('job','[{\"id\":\"old\"}]')")
        connection.execute(
            f"CREATE TRIGGER fail_migration AFTER INSERT ON {table} "
            "BEGIN SELECT RAISE(ABORT,'migration fault'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="migration fault"):
        SQLiteRepository(path)
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as reader:
        assert (
            json.loads(reader.execute("SELECT data FROM objects WHERE id='job'").fetchone()[0])
            == job
        )
        for name in ("job_flow_records", "job_payload_signatures", "candidate_records"):
            assert reader.execute(f"SELECT count(*) FROM {name}").fetchone() == (0,)
        assert reader.execute("SELECT count(*) FROM candidates").fetchone() == (1,)
