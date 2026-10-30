"""Heartbeat audit policy on invocation-owned PostgreSQL, never a live service."""

import pytest

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests import test_postgres_schema_lifecycle as lifecycle

database = lifecycle.database
repository = lifecycle.repository

CONTEXT = {"clock_skew_threshold_seconds": 2, "heartbeat_timeout_seconds": 30}


def baseline():
    return {
        "sensor_id": "heartbeat",
        "reported_at": "2026-01-01T00:00:00+00:00",
        "last_heartbeat_at": "2026-01-01T00:00:00+00:00",
        "clock_offset_ms": 0,
        "status": "ONLINE",
        "reported_status": "ONLINE",
        "derived_status": "ONLINE",
        "cpu_percent": 0,
        "memory_percent": 0,
        "disk_percent": 0,
        "pending_bytes": 0,
        "received_packets": 10,
        "dropped_packets": 0,
        "pcap_dropped_packets": 0,
        "last_error": None,
        "active_job_ids": [],
        "completed_capture_jobs": [],
        "interfaces": [
            {
                "interface": "eth0",
                "direction": "BIDIRECTIONAL",
                "received_packets": 10,
                "dropped_packets": 0,
                "status": "ONLINE",
                "last_error": None,
            }
        ],
        "config_version": 1,
        "capture_sources": ["eth0"],
    }


def telemetry():
    result = baseline()
    result.update(
        reported_at="2026-01-01T00:00:01+00:00",
        last_heartbeat_at="2026-01-01T00:00:01+00:00",
        clock_offset_ms=10,
        cpu_percent=12,
        memory_percent=23,
        disk_percent=34,
        pending_bytes=123,
        received_packets=20,
    )
    result["interfaces"][0]["received_packets"] = 20
    return result


@pytest.fixture
def pg(database):
    dsn, control = database
    repo = repository(dsn)
    repo.initialize_schema()
    repo.upsert_sensor(baseline())
    try:
        yield repo, control
    finally:
        repo.close()


def test_postgres_context_compatibility_and_missing_sensor(pg):
    repo, control = pg
    before = audits(control)
    assert repo.update_sensor_heartbeat("missing", {}, **CONTEXT) is None
    assert audits(control) == before


def test_routine_telemetry_updates_current_state_without_audit(pg):
    repo, control = pg
    before = audits(control)
    result = repo.update_sensor_heartbeat("heartbeat", telemetry(), **CONTEXT)
    assert result == telemetry()
    assert repo.get_sensor("heartbeat") == telemetry()
    result["interfaces"].clear()
    assert repo.get_sensor("heartbeat")["interfaces"] == telemetry()["interfaces"]
    assert audits(control) == before


@pytest.mark.parametrize("sensor_id", ["heartbeat", "missing"])
def test_borrowed_heartbeat_never_finishes_callers_transaction(pg, sensor_id):
    repo, control = pg
    before = audits(control)
    connection = repo.connection
    connection.execute("INSERT INTO controller_objects VALUES ('probe','caller','{}')")
    repo.update_sensor_heartbeat(sensor_id, {"status": "DEGRADED"}, **CONTEXT)
    assert control.execute(
        "SELECT count(*) FROM controller_objects WHERE kind='probe'"
    ).fetchone() == (0,)
    connection.rollback()
    assert repo.get_sensor("heartbeat") == baseline()
    assert audits(control) == before


def audits(control):
    return control.execute(
        "SELECT kind,object_id,data FROM audit_events ORDER BY sequence"
    ).fetchall()


def test_optional_context_is_accepted_without_changing_shared_backend_audits(tmp_path):
    for repo in (MemoryRepository(), SQLiteRepository(str(tmp_path / "heartbeat.sqlite"))):
        try:
            repo.upsert_sensor(baseline())
            result = repo.update_sensor_heartbeat("heartbeat", telemetry(), **CONTEXT)
            assert result == telemetry()
            result["interfaces"].clear()
            assert repo.get_sensor("heartbeat") == telemetry()
            assert repo.update_sensor_heartbeat("missing", {}, **CONTEXT) is None
            if isinstance(repo, MemoryRepository):
                assert repo.audit_events == []
            else:
                assert repo.connection.execute("SELECT count(*) FROM audit_events").fetchone() == (
                    0,
                )
        finally:
            repo.close()
    reopened = SQLiteRepository(str(tmp_path / "heartbeat.sqlite"))
    try:
        assert reopened.get_sensor("heartbeat") == telemetry()
    finally:
        reopened.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", "DEGRADED"),
        ("reported_status", "DEGRADED"),
        ("derived_status", "DEGRADED"),
        ("last_error", "capture failed"),
        ("dropped_packets", 1),
        ("pcap_dropped_packets", 1),
        ("received_packets", 0),
        ("clock_offset_ms", 2001),
        ("last_heartbeat_at", "2026-01-01T00:00:31+00:00"),
        ("last_heartbeat_at", "2025-12-31T23:59:59+00:00"),
        ("reported_at", "2025-12-31T23:59:59+00:00"),
        ("active_job_ids", ["job"]),
        ("completed_capture_jobs", [{"job_id": "job", "stop_reason": "DONE"}]),
        ("observed_interfaces", [{"name": "new", "mac_address": "00:11:22:33:44:55"}]),
        ("config_version", 2),
        ("capture_sources", ["eth1"]),
        ("internal_networks", ["10.0.0.0/8"]),
        ("unknown_security_field", True),
        ("received_packets", None),
        ("received_packets", True),
        ("clock_offset_ms", "unknown"),
        ("reported_at", "bad"),
        ("pending_bytes", -1),
        ("interfaces", None),
        ("interfaces", [{}]),
        ("interfaces", []),
    ],
)
def test_important_or_uncertain_changes_keep_original_event(pg, field, value):
    repo, control = pg
    before = audits(control)
    fields = telemetry()
    fields[field] = value
    repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
    assert repo.get_sensor("heartbeat") == fields
    assert audits(control) == before + [("sensor-heartbeat", "heartbeat", fields)]


@pytest.mark.parametrize(
    "field,value",
    [
        ("interface", "eth1"),
        ("direction", "INBOUND"),
        ("status", "DEGRADED"),
        ("last_error", "drop"),
        ("received_packets", 0),
        ("dropped_packets", 1),
        ("unknown", "new"),
    ],
)
def test_interface_semantics_are_not_volatile(pg, field, value):
    repo, control = pg
    before = audits(control)
    fields = telemetry()
    fields["interfaces"][0][field] = value
    repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
    assert audits(control) == before + [("sensor-heartbeat", "heartbeat", fields)]


def test_context_fallback_first_receipt_and_repeated_registration(pg):
    repo, control = pg
    contexts = [
        {},
        {**CONTEXT, "clock_skew_threshold_seconds": None},
        {**CONTEXT, "heartbeat_timeout_seconds": 0},
        {**CONTEXT, "heartbeat_timeout_seconds": "30"},
        {**CONTEXT, "heartbeat_timeout_seconds": True},
        {**CONTEXT, "clock_skew_threshold_seconds": float("inf")},
    ]
    for context in contexts:
        before = audits(control)
        repo.update_sensor_heartbeat("heartbeat", telemetry(), **context)
        assert audits(control) == before + [("sensor-heartbeat", "heartbeat", telemetry())]
    for _ in range(2):
        before = audits(control)
        repo.upsert_sensor({"sensor_id": "heartbeat"})
        repo.update_sensor_heartbeat("heartbeat", telemetry(), **CONTEXT)
        assert audits(control) == before + [
            ("sensor", "heartbeat", {"sensor_id": "heartbeat"}),
            ("sensor-heartbeat", "heartbeat", telemetry()),
        ]
    before = audits(control)
    for _ in range(2):
        repo.append_audit_event("security", "heartbeat", {"same": True})
    assert audits(control) == before + [("security", "heartbeat", {"same": True})] * 2


def test_clock_boundary_and_error_clearing_even_when_already_degraded(pg):
    repo, control = pg
    state = baseline()
    state.update(
        status="DEGRADED",
        reported_status="DEGRADED",
        derived_status="DEGRADED",
        last_error="old",
        clock_offset_ms=2001,
    )
    repo.upsert_sensor(state)
    for fields in (
        {"clock_offset_ms": 1999},
        {"clock_offset_ms": -2001},
        {"last_error": "changed"},
        {"last_error": None},
    ):
        before = audits(control)
        repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
        assert audits(control) == before + [("sensor-heartbeat", "heartbeat", fields)]


@pytest.mark.parametrize("phase", ["update", "audit", "serialization", "copy", "commit"])
@pytest.mark.parametrize("borrowed", [False, True])
def test_faults_preserve_atomicity_original_exception_and_retry(pg, monkeypatch, phase, borrowed):
    import psycopg

    from c2hunter_controller import production

    repo, control = pg
    before = audits(control)
    connection = repo.connection
    failure = RuntimeError("injected " + phase)
    events = []

    class Proxy:
        def __getattr__(self, name):
            return getattr(connection, name)

        def commit(self):
            events.append("commit")
            if phase == "commit":
                raise failure
            connection.commit()

        def rollback(self):
            events.append("rollback")
            connection.rollback()

    repo._connection = Proxy()
    fired = []

    def fail(*args, **kwargs):
        fired.append(True)
        raise failure

    fields = {"status": "DEGRADED"}
    with monkeypatch.context() as patch:
        if phase == "audit":
            patch.setattr(repo, "_audit", fail)
        elif phase == "serialization":
            patch.setattr(repo, "_json", fail)
        elif phase == "copy":
            patch.setattr(production, "deepcopy", fail)
        elif phase == "update":
            control.execute(
                "CREATE FUNCTION heartbeat_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEG"
                "IN RAISE EXCEPTION 'heartbeat update refused'; END $$"
            )
            control.execute(
                "CREATE TRIGGER heartbeat_refuse BEFORE UPDATE ON controller_objects FOR EACH "
                "ROW EXECUTE FUNCTION heartbeat_refuse()"
            )
        if borrowed:
            connection.execute("INSERT INTO controller_objects VALUES ('probe','caller','{}')")
        if phase == "commit" and borrowed:
            repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
        else:
            with pytest.raises(
                psycopg.errors.RaiseException if phase == "update" else RuntimeError
            ) as raised:
                repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
            if phase != "update":
                assert raised.value is failure
            if phase not in {"update", "commit"}:
                assert fired == [True]
    assert events == (
        [] if borrowed else ["commit", "rollback"] if phase == "commit" else ["rollback"]
    )
    assert (
        control.execute("SELECT data FROM controller_objects WHERE kind='sensor'").fetchone()[0]
        == baseline()
    )
    assert audits(control) == before
    if borrowed:
        connection.rollback()
    if phase == "update":
        control.execute("DROP TRIGGER heartbeat_refuse ON controller_objects")
    repo._connection = connection
    repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
    assert audits(control) == before + [("sensor-heartbeat", "heartbeat", fields)]


@pytest.mark.parametrize(
    "first,second,expected",
    [
        ("DEGRADED", "DEGRADED", 1),
        ("DEGRADED", "OFFLINE", 2),
        ("ONLINE", "DEGRADED", 1),
        ("configuration", "ONLINE", 0),
    ],
)
def test_waiting_heartbeat_uses_latest_locked_row_and_preserves_configuration(
    pg, first, second, expected
):
    import threading
    import time
    from concurrent.futures import ThreadPoolExecutor

    import psycopg

    repo, control = pg
    before = audits(control)
    connection = repo.connection
    other = repository(repo.database_url)
    original = other.connection
    original.close()
    entered = threading.Event()

    class ObservedCursor(psycopg.Cursor):
        def execute(self, query, *args, **kwargs):
            if "FOR UPDATE" in str(query):
                entered.set()
            return super().execute(query, *args, **kwargs)

    other._connection = psycopg.connect(repo.database_url, cursor_factory=ObservedCursor)
    connection.execute("SELECT 1")
    if first == "configuration":
        result, code = repo.update_sensor_configuration(
            "heartbeat", 1, {"capture_sources": ["new"]}
        )
        assert code == "OK" and result["config_version"] == 2
    else:
        repo.update_sensor_heartbeat("heartbeat", {"status": first}, **CONTEXT)
    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(
                other.update_sensor_heartbeat, "heartbeat", {"status": second}, **CONTEXT
            )
            try:
                assert entered.wait(3)
                deadline = time.monotonic() + 3
                while not control.execute(
                    "SELECT 1 FROM pg_locks WHERE pid=%s AND NOT granted",
                    (other._connection.info.backend_pid,),
                ).fetchone():
                    assert time.monotonic() < deadline
                    time.sleep(0.01)
            finally:
                connection.commit()
            result = future.result(timeout=5)
        assert result["status"] == second
        new = audits(control)[len(before) :]
        assert len([event for event in new if event[0] == "sensor-heartbeat"]) == expected
        if first == "configuration":
            assert result["capture_sources"] == ["new"] and result["config_version"] == 2
            assert len(new) == 1 and new[0][0] == "sensor-configuration"
    finally:
        other.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("status", None),
        ("last_error", {}),
        ("active_job_ids", None),
        ("completed_capture_jobs", [None]),
    ],
)
def test_malformed_comparison_baseline_is_never_suppressed(field, value):
    from c2hunter_controller.heartbeat_audit import routine_telemetry

    before, after = baseline(), telemetry()
    before[field] = after[field] = value
    assert not routine_telemetry(before, after, **CONTEXT)


@pytest.mark.parametrize("branch", ["audit", "telemetry"])
def test_real_sql_failure_rolls_back_state_and_audit(pg, branch):
    import psycopg

    repo, control = pg
    before = audits(control)
    target = "audit_events" if branch == "audit" else "controller_objects"
    event = "INSERT" if branch == "audit" else "UPDATE"
    control.execute(
        "CREATE FUNCTION deny_heartbeat() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE E"
        "XCEPTION 'heartbeat SQL fault'; END $$"
    )
    from psycopg.sql import SQL, Identifier

    control.execute(
        SQL(
            "CREATE TRIGGER deny_heartbeat BEFORE {} ON {} FOR EACH ROW EXECUTE FUNCTION deny_"
            "heartbeat()"
        ).format(SQL(event), Identifier(target))
    )
    fields = {"status": "DEGRADED"} if branch == "audit" else telemetry()
    with pytest.raises(psycopg.errors.RaiseException, match="heartbeat SQL fault"):
        repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
    assert repo.connection.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
    assert repo.get_sensor("heartbeat") == baseline()
    assert audits(control) == before
    control.execute(SQL("DROP TRIGGER deny_heartbeat ON {}").format(Identifier(target)))
    repo.update_sensor_heartbeat("heartbeat", fields, **CONTEXT)
    assert audits(control) == before + (
        [("sensor-heartbeat", "heartbeat", fields)] if branch == "audit" else []
    )


def test_registration_configuration_and_security_history_is_preserved(pg):
    repo, control = pg
    before = audits(control)
    for _ in range(2):
        repo.upsert_sensor(baseline())
        repo.save_sensor_credential({"sensor_id": "heartbeat", "token_hash": "fixture"})
        repo.save_enrollment({"enrollment_id": "enrollment", "revoked_at": None})
    result, code = repo.update_sensor_configuration("heartbeat", 1, {"capture_sources": ["new"]})
    assert code == "OK" and result["config_version"] == 2
    events = audits(control)[len(before) :]
    assert [event[0] for event in events] == ["sensor", "sensor_credential", "enrollment"] * 2 + [
        "sensor-configuration"
    ]
    assert repo.update_sensor_configuration("heartbeat", 1, {})[1] == "CONFLICT"
    assert repo.update_sensor_configuration("missing", 1, {})[1] == "NOT_FOUND"
    assert audits(control)[len(before) :] == events
