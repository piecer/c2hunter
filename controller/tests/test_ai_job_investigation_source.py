"""JOB producer tests: local stored observations, no provider or server."""

import json
from copy import deepcopy
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
from itertools import accumulate

import pytest

from c2hunter_controller.repositories import MemoryRepository


def flow(**updates):
    row = dict(
        sensor_id="s1",
        timestamp="2026-01-01T00:00:00+00:00",
        source_ip="10.0.0.1",
        destination_ip="2001:db8::1",
        protocol="UDP",
        direction="OUTBOUND",
        packet_count=1,
        total_bytes=80,
        duration_seconds=0,
    )
    return row | updates


def job(rows=None):
    return dict(
        id="job",
        dataset_id="dataset",
        status="PARTIALLY_COMPLETED",
        analysis={"module": "c2"},
        flow_records=[flow()] if rows is None else rows,
    )


def read(repo, **kwargs):
    method = getattr(repo, "read_job_investigation_source", None)
    assert callable(method), "bounded JOB producer missing"
    return method("job", **kwargs)


def poison(*args, **kwargs):
    raise AssertionError("unbounded hydration or premature work")


@pytest.fixture(params=["memory", "sqlite", "postgres-double"])
def adapter(request, tmp_path, monkeypatch):
    from c2hunter_controller.repositories import SQLiteRepository
    from tests import test_ai_investigation_postgres as pg

    raw = behavior_job()
    if request.param == "postgres-double":
        monkeypatch.setattr(pg, "job", lambda: deepcopy(raw))
        original = pg.Cursor.execute

        def execute(cursor, sql, args=None):
            original(cursor, sql, args)
            if sql.startswith("SELECT j.value::text"):
                cursor.rows = [(json.dumps(r),) for r in raw["flow_records"]]

        monkeypatch.setattr(pg.Cursor, "execute", execute)
        repo = pg.repository(pg.Connection())
    else:
        repo = (
            MemoryRepository()
            if request.param == "memory"
            else SQLiteRepository(tmp_path / "job.db")
        )
        repo.save_job(raw)
        request.addfinalizer(repo.close)
    return repo


def test_three_adapters_one_acquisition_projection_under_fence(adapter, monkeypatch):
    from c2hunter_analysis import behavior_discovery as detector

    from c2hunter_controller import ai_job_investigation_read as reader

    calls = {"projection": 0, "behavior": 0}
    project = reader._project
    discover = detector.discover_behavior_candidates

    def check_fence():
        assert adapter._lock._is_owned()
        if hasattr(adapter, "connection"):
            conn = adapter.connection
            assert conn.in_transaction if hasattr(conn, "in_transaction") else conn.active

    def projection(*args):
        check_fence()
        calls["projection"] += 1
        return project(*args)

    def behavior(*args, **kwargs):
        check_fence()
        calls["behavior"] += 1
        return discover(*args, **kwargs)

    monkeypatch.setattr(reader, "_project", projection)
    monkeypatch.setattr(detector, "discover_behavior_candidates", behavior)
    monkeypatch.setattr(adapter, "get_job", poison)
    monkeypatch.setattr(adapter, "get_candidates", poison)
    result = read(adapter)
    assert result.pool.entries[0].ip == "198.51.100.9"
    assert calls == {"projection": 1, "behavior": 1}
    if hasattr(adapter, "connection"):
        conn = adapter.connection
        if hasattr(conn, "payload_reads"):
            assert conn.payload_reads == 1
            assert not conn.active
        else:
            assert not conn.in_transaction


def test_observed_union_is_detached_and_non_candidate(monkeypatch):
    repo = MemoryRepository()
    raw = job(
        [
            flow(),
            flow(source_ip="2001:db8::1", destination_ip="10.0.0.2", direction="INBOUND"),
            flow(destination_ip="10.0.0.1"),
        ]
    )
    original = deepcopy(raw)
    repo.save_job(raw)
    monkeypatch.setattr(repo, "get_job", poison)
    result = read(repo)
    assert result.snapshot.status == "PARTIALLY_COMPLETED"
    assert [p.ip for p in result.pool.entries] == ["10.0.0.1", "10.0.0.2", "2001:db8::1"]
    assert [p.matched_rows for p in result.pool.entries] == [2, 1, 2]
    assert all(p.behavior_state == "UNAVAILABLE" for p in result.pool.entries)
    assert result.pool.discovery.state == "UNAVAILABLE"
    assert result.pool.discovery.examined_peers is None
    assert result.pool.observed_peers == 3
    assert result.pool.legacy_membership == "NOT_READ"
    assert "CAPTURE_COMPLETENESS_UNKNOWN" in result.pool.limitations
    assert "CURRENT_JOB_ONLY_NOT_VALIDATED" in result.pool.limitations
    assert raw == original
    assert result == read(repo)
    raw["flow_records"][0]["total_bytes"] = 999
    assert result.snapshot.rows[0].total_bytes == 80
    assert result.pool.source_sha256 == result.snapshot.binding.source_sha256


@pytest.mark.parametrize("module", ["ddos_attack", "network_anomaly"])
def test_job_only_c2_before_rows(module, monkeypatch):
    from c2hunter_controller import historical_read as bounded

    repo = MemoryRepository()
    raw = job() | {"analysis": {"module": module}}
    repo.save_job(raw)
    monkeypatch.setattr(bounded, "_admit_rows", poison)
    with pytest.raises(ValueError, match="SOURCE_UNAVAILABLE"):
        read(repo)


@pytest.mark.parametrize("axis", ["dropped", "skew", "missing_clock", "bad_quality"])
def test_capture_quality_and_clock_are_not_promoted_to_complete(axis):
    repo = MemoryRepository()
    raw = behavior_job()
    if axis == "dropped":
        raw["capture_quality"]["dropped_packet_count"] = 3
    elif axis == "skew":
        raw["capture_quality"]["clock_skew_detected"] = True
    elif axis == "missing_clock":
        raw["operations"]["sensors"]["s1"].pop("clock_offset_ms")
    else:
        raw["capture_quality"]["dropped_packet_count"] = True
    repo.save_job(raw)
    result = read(repo)
    if axis == "dropped":
        assert "CAPTURE_LOSS_REPORTED" in result.pool.discovery.warnings
        assert result.pool.discovery.state == "PARTIAL"
        assert result.pool.entries[0].behavior_state == "PRIORITIZED"
    else:
        assert result.pool.discovery.state == "UNAVAILABLE"
    assert "CAPTURE_COMPLETENESS_UNKNOWN" in result.pool.limitations


def test_aggregate_timing_and_bidirectional_semantics(monkeypatch):
    from c2hunter_analysis import behavior_discovery as detector

    raw = behavior_job()
    for row in raw["flow_records"]:
        row.update(
            packet_count=5, duration_seconds=5, bidirectional=True, direction="BIDIRECTIONAL"
        )
    repo = MemoryRepository()
    repo.save_job(raw)
    seen = []
    original = detector.discover_behavior_candidates

    def observe(context):
        seen.append(context)
        return original(context)

    monkeypatch.setattr(detector, "discover_behavior_candidates", observe)
    result = read(repo)
    assert len(seen) == 1
    assert all(f.bidirectional and f.direction == "BIDIRECTIONAL" for f in seen[0].flows)
    assert "AGGREGATED_FLOW_TIMING_UNAVAILABLE" in result.pool.discovery.warnings
    assert all(p.behavior_state == "NOT_PRIORITIZED" for p in result.pool.entries)
    assert result.snapshot.rows[0].packet_count == 5
    assert result.snapshot.rows[0].direction == "UNKNOWN"


def test_real_legacy_top_five_omits_observed_pool_peer():
    from c2hunter_controller.ai_analysis import _ranked_candidate_snapshots

    raw = behavior_job()
    raw["flow_records"] = raw["flow_records"][:48]
    for index, row in enumerate(raw["flow_records"]):
        row.update(
            timestamp=(
                datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=(index % 8) * 30)
            ).isoformat(),
            total_bytes=100,
            payload_length=60,
            payload_hash="a" * 64,
        )
    original = deepcopy(raw)
    all_ranked = _ranked_candidate_snapshots(raw, [], 32)
    legacy_five = _ranked_candidate_snapshots(raw, [], 5)
    assert len(legacy_five) == 5
    outside = {p["candidate_ip"] for p in all_ranked} - {p["candidate_ip"] for p in legacy_five}
    assert outside, "fixture must demonstrate actual selector exclusion"
    repo = MemoryRepository()
    repo.save_job(raw)
    result = read(repo)
    assert outside <= {p.ip for p in result.pool.entries}
    assert all("candidate_id" not in p.model_dump() for p in result.pool.entries)
    assert not repo.get_candidates("job")
    assert raw == original
    # Final model selection/adaptive evidence is a later service acceptance gate.


def test_mixed_control_suppression_is_row_local():
    from c2hunter_controller.ai_investigation_contract import InvestigationScope
    from c2hunter_controller.ai_investigation_evidence import EvidenceService

    rows = [
        flow(protocol="TCP", tcp_flags={flag: 1}, payload_length=0)
        for flag in ("syn", "fin", "rst")
    ]
    rows += [
        flow(),
        flow(protocol="TCP", tcp_flags={"syn": 1, "ack": 1}, payload_length=0),
        flow(protocol="TCP", tcp_flags={"syn": 1}, payload_length=8),
        flow(protocol="TCP"),
    ]
    repo = MemoryRepository()
    repo.save_job(job(rows))
    result = read(repo)
    for peer in result.pool.entries:
        assert (
            peer.matched_rows,
            peer.eligible_rows,
            peer.suppressed_control_rows,
            peer.eligibility_unavailable_rows,
        ) == (7, 3, 3, 1)
        evidence = EvidenceService(result.snapshot, InvestigationScope(target_ip=peer.ip))
        assert evidence.call("peer_overview", {}).counts.matched == 7


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize(
    "axis,limit", [("row", 65536), ("metadata", 262144), ("rows", 8192), ("total", 8388608)]
)
@pytest.mark.parametrize("extra", [0, 1])
def test_raw_exact_plus_one_admission(backend, axis, limit, extra, tmp_path, monkeypatch):
    from c2hunter_controller import ai_job_investigation_read as reader
    from c2hunter_controller.ai_investigation_contract import canonical_bytes
    from c2hunter_controller.repositories import SQLiteRepository

    repo = MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "bounds.db")
    raw = job()

    def pad(value, size):
        result = dict(value, unused="")
        result["unused"] = "x" * (size - len(canonical_bytes(result)))
        assert len(canonical_bytes(result)) == size
        return result

    if axis == "row":
        raw["flow_records"] = [pad(flow(), limit + extra)]
    elif axis == "metadata":
        metadata = {k: v for k, v in raw.items() if k != "flow_records"}
        raw = pad(metadata, limit + extra) | {"flow_records": raw["flow_records"]}
    elif axis == "rows":
        raw["flow_records"] = [flow()] * (limit + extra)
    else:
        count = 131
        quotient, remainder = divmod(limit + extra - 2 - (count - 1), count)
        raw["flow_records"] = [pad(flow(), quotient + (i < remainder)) for i in range(count)]
        assert len(canonical_bytes(raw["flow_records"])) == limit + extra
    repo.save_job(raw)
    if backend == "sqlite":
        repo.connection.execute(
            "UPDATE job_flow_records SET data=?", (canonical_bytes(raw["flow_records"]).decode(),)
        )
        repo.connection.execute(
            "UPDATE objects SET data=? WHERE kind='job'",
            (canonical_bytes({k: v for k, v in raw.items() if k != "flow_records"}).decode(),),
        )
        repo.connection.commit()
    calls = []
    project = reader._project

    def observe(*args):
        calls.append(1)
        return project(*args)

    monkeypatch.setattr(reader, "_project", observe)
    try:
        if extra or axis == "rows":
            with pytest.raises(ValueError, match="SOURCE_LIMIT"):
                read(repo)
        else:
            result = read(repo)
            assert len(result.snapshot.rows) == len(raw["flow_records"])
        # Exact 8192 raw rows pass admission, then fail the separate preparation cap.
        assert len(calls) == (0 if extra else 1)
    finally:
        repo.close()


def test_expected_source_pins_raw_metadata_and_rows_before_behavior(monkeypatch):
    from c2hunter_controller import ai_job_investigation_read as reader

    repo = MemoryRepository()
    raw = behavior_job()
    repo.save_job(raw)
    first = read(repo, expected_source_sha256=None)
    assert read(repo, expected_source_sha256=first.snapshot.binding.source_sha256) == first
    raw["capture_quality"]["dropped_packet_count"] = 1
    repo.save_job(raw)
    monkeypatch.setattr(reader, "discover", poison)
    with pytest.raises(ValueError, match="SOURCE_CHANGED"):
        read(repo, expected_source_sha256=first.snapshot.binding.source_sha256)


def test_pg_pretransfer_limit_and_foreign_transaction():
    from psycopg.pq import TransactionStatus

    from tests.test_ai_investigation_postgres import Connection, repository

    connection = Connection(size=8388609)
    with pytest.raises(ValueError, match="SOURCE_LIMIT"):
        read(repository(connection))
    assert connection.payload_reads == 0
    assert not connection.active
    connection.info.transaction_status = TransactionStatus.INTRANS
    before = list(connection.queries)
    with pytest.raises(ValueError, match="SOURCE_BUSY"):
        read(repository(connection))
    assert connection.queries == before


@pytest.mark.parametrize(
    "axis", ["parameter_bool", "parameter_text", "counter_relation", "syn_shape"]
)
def test_unsupported_behavior_semantics_keep_observed_pool(axis, monkeypatch):
    from c2hunter_analysis import behavior_discovery as detector

    raw = behavior_job()
    if axis == "parameter_bool":
        raw["analysis"]["tcp_syn_retry_min_intervals"] = True
    elif axis == "parameter_text":
        raw["analysis"]["tcp_syn_retry_detection_enabled"] = "false"
    elif axis == "counter_relation":
        raw["flow_records"][0]["tcp_syn_count"] = 1
    else:
        raw["flow_records"][0].update(
            tcp_flags_observed=True,
            tcp_syn_count=1,
            tcp_syn_only_count=1,
            tcp_syn_only_observations=[],
        )
    repo = MemoryRepository()
    repo.save_job(raw)
    monkeypatch.setattr(detector, "discover_behavior_candidates", poison)
    result = read(repo)
    assert len(result.pool.entries) == 10
    assert result.pool.discovery.state == "UNAVAILABLE"


def test_ipv6_canonical_behavior_identity_and_reported_clock_penalty():
    raw = behavior_job()
    for row in raw["flow_records"]:
        if row["destination_ip"] == "198.51.100.9":
            row["destination_ip"] = "2001:0DB8:0:0:0:0:0:0009"
    repo = MemoryRepository()
    repo.save_job(raw)
    first = read(repo)
    assert first.pool.entries[0].ip == "2001:db8::9"
    raw["operations"]["sensors"]["s1"]["clock_offset_ms"] = 3000
    repo.save_job(raw)
    second = read(repo)
    assert second.pool.entries[0].behavior_score == first.pool.entries[0].behavior_score - 10
    assert "CAPTURE_CLOCK_UNCERTAINTY" in second.pool.discovery.warnings


def test_detector_peer_budget_keeps_explicit_exclusions():
    from c2hunter_controller.ai_job_investigation_behavior import discover

    raw = behavior_job()
    seed = raw["flow_records"][0]
    # Adapter boundary only: this many projected rows exceeds preparation size.
    raw["flow_records"] = [dict(seed, destination_ip=f"2001:db8::{i:x}") for i in range(1, 258)]
    scores, coverage = discover(
        {k: v for k, v in raw.items() if k != "flow_records"}, raw["flow_records"]
    )
    assert scores == {}
    assert coverage.state == "PARTIAL"
    assert coverage.examined_peers == 0 and coverage.excluded_peers == 257
    assert "PEER_BUDGET_EXCEEDED:256" in coverage.warnings


@pytest.mark.parametrize("status", ["COMPLETED", "PARTIALLY_COMPLETED"])
def test_current_job_no_lineage_or_completeness_inference(status):
    repo = MemoryRepository()
    raw = job() | {"status": status, "parent_job_id": "unread-ancestor"}
    repo.save_job(raw)
    result = read(repo)
    assert result.snapshot.status == status
    assert "CAPTURE_COMPLETENESS_UNKNOWN" in result.pool.limitations
    assert "CURRENT_JOB_ONLY_NOT_VALIDATED" in result.pool.limitations


def test_sqlite_source_fence_does_not_finish_foreign_transaction(tmp_path):
    from c2hunter_controller.repositories import SQLiteRepository

    repo = SQLiteRepository(tmp_path / "foreign.db")
    repo.save_job(job())
    repo.connection.execute("BEGIN")
    repo.connection.execute("INSERT INTO objects VALUES('caller','owned','{}')")
    try:
        with pytest.raises(ValueError, match="SOURCE_BUSY"):
            read(repo)
        assert repo.connection.in_transaction
        assert repo.connection.execute("SELECT id FROM objects WHERE kind='caller'").fetchone() == (
            "owned",
        )
    finally:
        repo.connection.rollback()
        repo.close()


def test_tcp_syn_and_payload_fields_reach_actual_detector_unchanged(monkeypatch):
    from c2hunter_analysis import behavior_discovery as detector

    raw = behavior_job()
    row = raw["flow_records"][0]
    row.update(
        tcp_flags={"syn": 1, "ack": 0},
        tcp_flags_observed=True,
        tcp_syn_count=1,
        tcp_syn_only_count=1,
        tcp_syn_only_observations=[{"offset_us": 0, "sequence": 123}],
        payload_hash="a" * 64,
        last_payload_hash="b" * 64,
        payload_prefix_hash="c" * 64,
        payload_simhash="d" * 16,
        payload_length=12,
    )
    repo = MemoryRepository()
    repo.save_job(raw)
    original = detector.discover_behavior_candidates
    observed = []

    def inspect(context):
        observed.append(context.flows[0])
        return original(context)

    monkeypatch.setattr(detector, "discover_behavior_candidates", inspect)
    result = read(repo)
    assert len(observed) == 1
    seen = observed[0]
    assert seen.tcp_syn_only_observations == ((0, 123),)
    assert seen.tcp_syn_count == seen.tcp_syn_only_count == 1
    assert seen.tcp_flags == row["tcp_flags"]
    assert seen.payload_length == 12 and seen.payload_hash == row["payload_hash"]
    assert seen.last_payload_hash == row["last_payload_hash"]
    assert seen.payload_prefix_hash == row["payload_prefix_hash"]
    assert seen.payload_simhash == row["payload_simhash"]
    assert result.snapshot.rows[0].c2_eligibility == "ELIGIBLE"


def behavior_job():
    from c2hunter_analysis.domain import Flow

    rows = []
    for index in range(1, 10):
        outlier = index == 9
        intervals = (
            [300, 900, 450, 1050, 600, 1200, 750] if outlier else [1, 2, 8, 32, 128, 512, 2048]
        )
        sizes = [120, 121, 119, 120, 122, 119, 121, 120] if outlier else [64, 128, 256, 512] * 2
        for second, size in zip(accumulate([0, *intervals]), sizes, strict=True):
            value = Flow(
                sensor_id="s1",
                timestamp=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=second),
                source_ip="10.0.0.1",
                destination_ip=f"198.51.100.{index}",
                source_port=50000,
                destination_port=443,
                protocol="TCP",
                direction="OUTBOUND",
                total_bytes=size,
            )
            rows.append(
                json.loads(json.dumps(asdict(value) | {"timestamp": value.timestamp.isoformat()}))
            )
    return job(rows) | {
        "sensor_ids": ["s1"],
        "internal_networks": ["10.0.0.0/8"],
        "operations": {"sensors": {"s1": {"clock_offset_ms": 0}}},
        "capture_quality": {"dropped_packet_count": 0, "clock_skew_detected": False},
    }


def test_real_behavior_once_and_actual_coverage(monkeypatch):
    from c2hunter_analysis import behavior_discovery as detector

    repo = MemoryRepository()
    raw = behavior_job()
    repo.save_job(raw)
    calls = []
    original = detector.discover_behavior_candidates

    def observe(context, **kwargs):
        calls.append(context)
        assert repo._lock._is_owned()
        assert kwargs.get("trusted_peers") is None
        return original(context, **kwargs)

    monkeypatch.setattr(detector, "discover_behavior_candidates", observe)
    result = read(repo)
    assert len(calls) == 1, "actual detector must run once, no default unavailable stub"
    assert calls[0].internal_cidrs == ("10.0.0.0/8",)
    assert calls[0].clock_offsets_ms == {"s1": 0.0}
    assert result.pool.entries[0].ip == "198.51.100.9"
    assert result.pool.entries[0].behavior_state == "PRIORITIZED"
    assert result.pool.entries[0].behavior_score > 0
    assert all(p.behavior_state == "NOT_PRIORITIZED" for p in result.pool.entries[1:])
    assert result.pool.discovery.examined_peers == 9
    assert result.pool.discovery.excluded_peers == 0
    assert "NO_SIGNAL" not in result.pool.model_dump_json()


@pytest.mark.parametrize(
    "missing", ["packet_count", "total_bytes", "duration_seconds", "bidirectional", "tcp_syn_count"]
)
def test_missing_behavior_measurement_is_not_default_zero(missing, monkeypatch):
    from c2hunter_analysis import behavior_discovery as detector

    repo = MemoryRepository()
    raw = behavior_job()
    del raw["flow_records"][0][missing]
    repo.save_job(raw)
    monkeypatch.setattr(detector, "discover_behavior_candidates", poison)
    result = read(repo)
    assert result.pool.discovery.state == "UNAVAILABLE"
    assert len(result.pool.entries) == 10
    assert all(p.behavior_state == "UNAVAILABLE" for p in result.pool.entries)
