"""Real PG H4 only. One externally owned private fixture; unique schemas."""

import os
import uuid
from collections.abc import Iterator
from typing import Any

import pytest

from c2hunter_controller.production import PostgresRepository
from tests.test_historical_read import build, poison, read
from tests.test_historical_source import config, review, stored


@pytest.fixture
def pg_repo() -> Iterator[Any]:
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    dsn = os.environ.get("H4_TEST_PG_DSN")
    if not dsn:
        pytest.skip("requires the single owned H4 implementation PostgreSQL fixture")
    schema = "h4_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
    private = make_conninfo(dsn, options="-c search_path=" + schema)
    repo = PostgresRepository(private, None)
    try:
        repo.initialize_schema()
        assert repo.connection is not None
        yield repo
    finally:
        if repo._connection is not None:
            repo._connection.close()
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema)))


@pytest.mark.parametrize("aggregate", [False, True])
@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
def test_pg_persisted_builder(
    pg_repo: Any, aggregate: bool, purpose: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_controller.historical_source import project_source

    raw = stored(aggregate=aggregate)
    control = build(
        project_source(raw, ancestors=(), scope=config(), quality_review=review()), purpose
    )
    assert len(control.profiles) == 4
    pg_repo.save_job(raw)
    pg_repo.save_candidates("root", [{"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}])
    for name in ("get_job", "list_jobs", "get_candidates", "_load_job_flow_records"):
        monkeypatch.setattr(pg_repo, name, poison)
    result = read(pg_repo, purpose)
    assert build(result.source, purpose) == control
    assert len(result.candidates) == (1 if purpose == "COMPARISON" else 0)


def test_pg_chunk_overflow_before_payload(pg_repo: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    pg_repo.save_job(stored())
    with pg_repo.connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO job_flow_record_chunks(job_id,chunk_no,data) VALUES('root',%s,'{}')",
            [(index,) for index in range(1, 65)],
        )
    pg_repo.connection.commit()
    monkeypatch.setattr("c2hunter_controller.historical_source.project_source", poison)
    monkeypatch.setattr(pg_repo, "_load_job_flow_records", poison)
    with pytest.raises(ValueError, match="^BASELINE_SOURCE_LIMIT$"):
        read(pg_repo)


@pytest.mark.parametrize("legacy", [False, True])
def test_pg_explicit_empty_storage_is_distinct_from_missing(pg_repo: Any, legacy: bool) -> None:
    pg_repo.save_job(stored())
    pg_repo.connection.execute("DELETE FROM job_flow_record_chunks WHERE job_id='root'")
    if legacy:
        pg_repo.connection.execute("INSERT INTO job_flow_records(job_id,data) VALUES('root','[]')")
    else:
        pg_repo.connection.execute(
            "INSERT INTO job_flow_record_chunks(job_id,chunk_no,data) VALUES('root',0,'[]')"
        )
    pg_repo.connection.commit()
    assert read(pg_repo).source.strict_flows == ()


def test_pg_64_chunks_original_order(pg_repo: Any) -> None:
    import json

    raw = stored()
    pg_repo.save_job(raw)
    pg_repo.connection.execute("DELETE FROM job_flow_record_chunks WHERE job_id='root'")
    with pg_repo.connection.cursor() as cursor:
        cursor.executemany(
            "INSERT INTO job_flow_record_chunks(job_id,chunk_no,data) VALUES('root',%s,%s::jsonb)",
            [
                (index, json.dumps([dict(raw["flow_records"][0], total_bytes=index + 1)]))
                for index in reversed(range(64))
            ],
        )
    pg_repo.connection.commit()
    assert [f.total_bytes for f in read(pg_repo).source.strict_flows] == list(range(1, 65))


@pytest.mark.parametrize("oversize", [False, True])
def test_pg_legacy_array_admission(
    pg_repo: Any, oversize: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import json

    raw = stored()
    pg_repo.save_job(raw)
    pg_repo.connection.execute("DELETE FROM job_flow_record_chunks WHERE job_id='root'")
    rows = raw["flow_records"]
    if oversize:
        rows[0]["unused"] = "é" * 65536
    pg_repo.connection.execute(
        "INSERT INTO job_flow_records(job_id,data) VALUES('root',%s::jsonb)", (json.dumps(rows),)
    )
    pg_repo.connection.commit()
    if oversize:
        monkeypatch.setattr("c2hunter_controller.historical_source.project_source", poison)
        with pytest.raises(ValueError, match="^BASELINE_SOURCE_LIMIT$"):
            read(pg_repo)
    else:
        assert len(read(pg_repo).source.strict_flows) == 32


def test_pg_jsonb_is_normalized_not_wire_uniqueness(pg_repo: Any) -> None:
    import json

    raw = stored()
    pg_repo.save_job(raw)
    row = json.dumps(raw["flow_records"][0])
    pg_repo.connection.execute(
        "UPDATE job_flow_record_chunks SET data=%s::jsonb WHERE job_id='root'",
        ('[{"total_bytes":999,' + row[1:] + "]",),
    )
    pg_repo.connection.commit()
    # JSONB already retained the last duplicate: this path does not claim to
    # recover or certify uniqueness of a wire representation it never stored.
    assert read(pg_repo).source.strict_flows[0].total_bytes == 100
