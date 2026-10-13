"""Real PostgreSQL observation presence; generic omission contracts stay unchanged."""

from datetime import UTC, datetime
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from c2hunter_controller.production import PostgresRepository
from tests import test_historical_read_postgres as pg_fixtures
from tests.test_historical_read import build
from tests.test_historical_source import config, review, stored

pg_repo = pg_fixtures.pg_repo
JOB_ID = " root:é "


def source() -> dict[str, Any]:
    return {**stored(), "id": JOB_ID, "idempotency_key": "empty-presence"}


def prepare(repo: Any) -> dict[str, Any]:
    raw = source()
    raw.update(mode="PCAP_UPLOAD", status="ANALYZING", processing={"phase": "UPLOAD_STORED"})
    repo.save_job(raw)
    claimed = repo.claim_pcap_preparation(now=datetime.now(UTC), lease_seconds=300)
    assert claimed is not None
    assert claimed["processing"]["phase"] == "PARSING"
    return {
        **source(),
        "processing": {**claimed["processing"], "phase": "ANALYSIS_ENQUEUE_PENDING"},
    }


def publish(repo: Any, operation: str, raw: dict[str, Any]) -> None:
    if operation == "create":
        returned, created = repo.create_job(raw)
        assert created is True
        assert returned == raw
    elif operation == "save":
        assert repo.save_job(raw) == raw
    else:
        assert (
            repo.publish_pcap_preparation(
                raw,
                attempt=raw["processing"]["attempt"],
                lease_token=raw["processing"]["lease_token"],
            )
            is True
        )


def observe(repo: Any) -> dict[str, Any]:
    """Independent driver before touching the writer or running initializer."""
    import psycopg

    with psycopg.connect(repo.database_url, autocommit=True) as reader:
        return {
            table: reader.execute(f"SELECT * FROM {table} ORDER BY 1,2").fetchall()
            for table in (
                "controller_objects",
                "job_idempotency",
                "job_flow_record_chunks",
                "job_flow_records",
                "job_payload_signatures",
                "candidate_records",
                "audit_events",
            )
        }


def assert_observation(repo: Any, expected: list[Any] | None) -> None:
    import psycopg

    with psycopg.connect(repo.database_url, autocommit=True) as reader:
        chunks = reader.execute(
            "SELECT chunk_no,data,jsonb_array_length(data),octet_length(data::text) "
            "FROM job_flow_record_chunks WHERE job_id=%s ORDER BY chunk_no",
            (JOB_ID,),
        ).fetchall()
        assert (
            reader.execute(
                "SELECT data FROM job_flow_records WHERE job_id=%s", (JOB_ID,)
            ).fetchall()
            == []
        )
        if expected is None:
            assert chunks == []
        elif not expected:
            assert chunks == [(0, [], 0, 2)]
        else:
            assert [row for chunk in chunks for row in chunk[1]] == expected
        metadata = reader.execute(
            "SELECT data FROM controller_objects WHERE kind='job' AND id=%s", (JOB_ID,)
        ).fetchone()[0]
        assert "flow_records" not in metadata
        assert metadata["id"] == JOB_ID
    assert repo.get_job(JOB_ID)["flow_records"] == (expected or [])
    if expected is None:
        with pytest.raises(ValueError, match="^BASELINE_SOURCE_INVALID$"):
            repo.read_historical_source(
                JOB_ID, purpose="COMPARISON", scope=config(), quality_review=review()
            )
    else:
        for purpose in ("COMPARISON", "APPROVAL"):
            snapshot = repo.read_historical_source(
                JOB_ID, purpose=purpose, scope=config(), quality_review=review()
            )
            assert len(snapshot.source.strict_flows) == len(expected)
            assert snapshot.source_binding_sha256 == h.source_binding_sha256(
                snapshot.source.source_binding(), purpose=purpose, candidates=snapshot.candidates
            )
            if not expected:
                assert build(snapshot.source, purpose).profiles == ()


@pytest.mark.parametrize("operation", ["create", "save", "preparation"])
@pytest.mark.parametrize("presence", ["missing", "empty", "nonempty"])
def test_explicit_observation_presence_roundtrip(
    pg_repo: Any, operation: str, presence: str
) -> None:
    raw = prepare(pg_repo) if operation == "preparation" else source()
    expected = raw["flow_records"]
    if presence == "missing":
        del raw["flow_records"]
        expected = None
    elif presence == "empty":
        raw["flow_records"] = expected = []
    publish(pg_repo, operation, raw)
    assert_observation(pg_repo, expected)
    # Constructor/initializer on a second driver must neither erase the marker
    # nor fabricate one for historical absence.
    reopened = PostgresRepository(pg_repo.database_url, None)
    try:
        assert_observation(reopened, expected)
    finally:
        reopened.close()


@pytest.mark.parametrize("initial", ["missing", "empty", "nonempty"])
def test_save_omission_preserves_existing_parts(pg_repo: Any, initial: str) -> None:
    raw = source()
    expected = raw["flow_records"]
    if initial == "missing":
        del raw["flow_records"]
        expected = None
    elif initial == "empty":
        raw["flow_records"] = expected = []
    publish(pg_repo, "create", raw)
    update = {key: value for key, value in source().items() if key != "flow_records"}
    update["note"] = "metadata only"
    assert pg_repo.save_job(update) == update
    assert_observation(pg_repo, expected)


def test_nonempty_empty_nonempty_and_duplicate_create(pg_repo: Any) -> None:
    raw = source()
    publish(pg_repo, "create", raw)
    assert_observation(pg_repo, raw["flow_records"])
    empty = {**raw, "flow_records": []}
    publish(pg_repo, "save", empty)
    assert_observation(pg_repo, [])
    returned, created = pg_repo.create_job(raw)
    assert created is False
    assert returned["flow_records"] == []
    publish(pg_repo, "save", raw)
    assert_observation(pg_repo, raw["flow_records"])
    assert PostgresRepository._json_array_chunks([]) == []


@pytest.mark.parametrize("operation", ["create", "save", "preparation"])
@pytest.mark.parametrize("point", ["insert", "commit"])
def test_empty_marker_real_fault_rolls_back_all_relations(
    pg_repo: Any, operation: str, point: str
) -> None:
    import psycopg

    raw = prepare(pg_repo) if operation == "preparation" else source()
    if operation == "save":
        pg_repo.save_job(raw)
    if operation != "create":
        pg_repo.save_candidates(
            JOB_ID, [{"id": "retained", "candidate_ip": "203.0.113.9", "score": 40}]
        )
    before = observe(pg_repo)
    connection = pg_repo.connection
    # Sequence advancement is nontransactional: independently proves fault fired
    # even when the entire publication transaction is rolled back.
    connection.execute("CREATE SEQUENCE empty_fault_fired")
    connection.execute(
        "CREATE FUNCTION reject_empty() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF NEW.data = '[]'::jsonb THEN PERFORM nextval('empty_fault_fired'); "
        "RAISE EXCEPTION 'explicit empty marker fault'; END IF; RETURN NEW; END $$"
    )
    if point == "commit":
        connection.execute(
            "CREATE CONSTRAINT TRIGGER fail_empty AFTER INSERT ON job_flow_record_chunks "
            "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_empty()"
        )
    else:
        connection.execute(
            "CREATE TRIGGER fail_empty AFTER INSERT ON job_flow_record_chunks "
            "FOR EACH ROW EXECUTE FUNCTION reject_empty()"
        )
    connection.commit()
    raw.update(flow_records=[], payload_signatures=[{"signature": "replacement"}], note="changed")
    with pytest.raises(psycopg.errors.RaiseException, match="explicit empty marker fault"):
        publish(pg_repo, operation, raw)
    assert observe(pg_repo) == before
    with psycopg.connect(pg_repo.database_url, autocommit=True) as reader:
        assert reader.execute("SELECT last_value,is_called FROM empty_fault_fired").fetchone() == (
            1,
            True,
        )
    assert connection.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    connection.execute("DROP TRIGGER fail_empty ON job_flow_record_chunks")
    connection.commit()
    publish(pg_repo, operation, raw)
    assert_observation(pg_repo, [])


@pytest.mark.parametrize("operation", ["create", "save", "preparation"])
def test_serialization_error_identity_and_reuse(pg_repo: Any, operation: str) -> None:
    raw = prepare(pg_repo) if operation == "preparation" else source()
    if operation == "save":
        pg_repo.save_job(raw)
    before = observe(pg_repo)
    fault = RuntimeError("flow serialization identity")

    class BadValue:
        def __str__(self) -> str:
            raise fault

    raw["flow_records"] = [BadValue()]
    with pytest.raises(RuntimeError) as caught:
        publish(pg_repo, operation, raw)
    assert caught.value is fault
    assert observe(pg_repo) == before
    raw["flow_records"] = []
    publish(pg_repo, operation, raw)
    assert_observation(pg_repo, [])


@pytest.mark.parametrize("operation", ["save", "preparation"])
@pytest.mark.parametrize("rollback", [False, True])
def test_empty_replacement_keeps_parent_fence(
    pg_repo: Any, operation: str, rollback: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    import threading
    from concurrent.futures import ThreadPoolExecutor

    import psycopg

    from tests.test_candidate_fencing_races import wait_for_pg_block

    raw = prepare(pg_repo) if operation == "preparation" else source()
    if operation == "save":
        pg_repo.save_job(raw)
    before = observe(pg_repo)
    entered, release = threading.Event(), threading.Event()
    fault = RuntimeError("empty publication rollback")
    original = PostgresRepository._json_array_chunks

    def held(records: list[Any]) -> list[str]:
        assert records == []
        entered.set()
        if not release.wait(10):
            raise RuntimeError("empty publication barrier timeout")
        if rollback:
            raise fault
        return original(records)

    monkeypatch.setattr(PostgresRepository, "_json_array_chunks", staticmethod(held))
    second = PostgresRepository(pg_repo.database_url, None)
    second._connection = psycopg.connect(pg_repo.database_url)
    reader_pid = second.connection.info.backend_pid
    try:
        with (
            psycopg.connect(pg_repo.database_url, autocommit=True) as observer,
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            writer = pool.submit(publish, pg_repo, operation, {**raw, "flow_records": []})
            try:
                assert entered.wait(10)
                reader = pool.submit(
                    second.read_historical_source,
                    JOB_ID,
                    purpose="COMPARISON",
                    scope=config(),
                    quality_review=review(),
                )
                wait_for_pg_block(observer, reader_pid, reader)
                assert observe(pg_repo) == before
                assert not reader.done()
            finally:
                release.set()
            if rollback:
                with pytest.raises(RuntimeError) as caught:
                    writer.result(timeout=10)
                assert caught.value is fault
                assert observe(pg_repo) == before
                if operation == "preparation":
                    with pytest.raises(ValueError, match="^BASELINE_SOURCE_STATE$"):
                        reader.result(timeout=10)
                else:
                    assert len(reader.result(timeout=10).source.strict_flows) == 32
            else:
                writer.result(timeout=10)
                if operation == "preparation":
                    # The discovered pre-publication metadata changed while the
                    # reader waited: H4 must reject that stale discovery, not
                    # silently combine it with the new empty flow observation.
                    with pytest.raises(ValueError, match="^BASELINE_SOURCE_CHANGED$"):
                        reader.result(timeout=10)
                    assert_observation(second, [])
                else:
                    assert reader.result(timeout=10).source.strict_flows == ()
    finally:
        release.set()
        second.close()


@pytest.mark.parametrize("denial", ["token", "cancelled"])
def test_denied_preparation_never_writes_empty_marker(pg_repo: Any, denial: str) -> None:
    raw = prepare(pg_repo)
    if denial == "cancelled":
        current = pg_repo.get_job_summary(JOB_ID)
        pg_repo.save_job_metadata({**current, "status": "CANCELLED"})
    before = observe(pg_repo)
    assert (
        pg_repo.publish_pcap_preparation(
            {**raw, "flow_records": []},
            attempt=raw["processing"]["attempt"],
            lease_token="stale-token" if denial == "token" else raw["processing"]["lease_token"],
        )
        is False
    )
    assert observe(pg_repo) == before
