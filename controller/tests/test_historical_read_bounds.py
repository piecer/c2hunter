"""Admission boundaries on the actual three storage layouts."""

import json
from pathlib import Path
from typing import Any

import pytest

from c2hunter_controller import historical_read as r
from c2hunter_controller import historical_source as s
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_read import build, poison, read
from tests.test_historical_read_postgres import pg_repo  # noqa: F401
from tests.test_historical_source import config, review, stored


@pytest.fixture(params=["memory", "sqlite", "postgres"])
def adapter(request: Any, tmp_path: Path) -> Any:
    if request.param == "postgres":
        return request.getfixturevalue("pg_repo")
    repo = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "source.sqlite")
    )
    request.addfinalizer(repo.close)
    return repo


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("status", "ANALYZING", "BASELINE_SOURCE_STATE"),
        ("analysis", {"module": "ddos_attack"}, "BASELINE_SOURCE_INVALID"),
    ],
)
def test_metadata_state_before_flows(
    adapter: Any, field: str, value: Any, code: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = stored()
    raw[field] = value
    adapter.save_job(raw)
    for name in ("_admit_rows", "_sqlite_flows", "_pg_flows"):
        monkeypatch.setattr(r, name, poison)
    with pytest.raises(r.HistoricalReadError, match="^" + code + "$"):
        read(adapter)


def wire(adapter: Any, value: Any) -> str:
    # Memory has no wire document; its normative representation is canonical UTF-8.
    if isinstance(adapter, MemoryRepository):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(adapter, SQLiteRepository):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return json.dumps(value, ensure_ascii=False, separators=(", ", ": "))


def put_flows(adapter: Any, rows: list[dict[str, Any]]) -> None:
    if isinstance(adapter, MemoryRepository):
        adapter.jobs["root"]["flow_records"] = rows
    elif isinstance(adapter, SQLiteRepository):
        adapter.connection.execute(
            "UPDATE job_flow_records SET data=? WHERE job_id='root'", (wire(adapter, rows),)
        )
        adapter.connection.commit()
    else:
        adapter.connection.execute(
            "UPDATE job_flow_record_chunks SET data=%s::jsonb WHERE job_id='root'",
            (wire(adapter, rows),),
        )
        adapter.connection.commit()


def put_metadata(adapter: Any, metadata: dict[str, Any]) -> None:
    if isinstance(adapter, MemoryRepository):
        adapter.jobs["root"].update(metadata)
    elif isinstance(adapter, SQLiteRepository):
        adapter.connection.execute(
            "UPDATE objects SET data=? WHERE kind='job' AND id='root'", (wire(adapter, metadata),)
        )
        adapter.connection.commit()
    else:
        adapter.connection.execute(
            "UPDATE controller_objects SET data=%s::jsonb WHERE kind='job' AND id='root'",
            (wire(adapter, metadata),),
        )
        adapter.connection.commit()


def pad(adapter: Any, row: dict[str, Any], size: int) -> dict[str, Any]:
    result = dict(row, unused="é")
    missing = size - len(wire(adapter, result).encode())
    assert missing >= 0
    result["unused"] += "x" * missing
    assert len(wire(adapter, result).encode()) == size
    return result


@pytest.mark.parametrize(
    "axis,limit",
    [("flow-count", 8192), ("flow-row", 65536), ("metadata", 262144), ("candidate-count", 2048)],
)
@pytest.mark.parametrize("extra", [0, 1])
def test_exact_admission_limits(
    adapter: Any, axis: str, limit: int, extra: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = stored()
    adapter.save_job(raw)
    if axis == "flow-count":
        rows = [dict(raw["flow_records"][0]) for _ in range(limit + extra)]
        put_flows(adapter, rows)
    elif axis == "flow-row":
        put_flows(adapter, [pad(adapter, raw["flow_records"][0], limit + extra)])
    elif axis == "metadata":
        metadata = {k: v for k, v in raw.items() if k != "flow_records"}
        put_metadata(adapter, pad(adapter, metadata, limit + extra))
    else:
        adapter.save_candidates(
            "root",
            [
                {"id": f"rule-{i}", "candidate_ip": "203.0.113.9", "score": 40}
                for i in range(limit + extra)
            ],
        )
    if extra:
        monkeypatch.setattr(s, "project_source", poison)
        with pytest.raises(
            r.HistoricalReadError,
            match="^BASELINE_"
            + ("CANDIDATE" if axis.startswith("candidate") else "SOURCE")
            + "_LIMIT$",
        ):
            read(adapter)
    else:
        result = read(adapter)
        assert result.source.original.id == "root"


@pytest.mark.parametrize("extra", [0, 1])
def test_candidate_stored_byte_sum_exact(
    adapter: Any, extra: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter.save_job(stored())
    # Candidate budget is the sum of stored rows, not an invented array wrapper.
    rows = [
        pad(adapter, {"id": f"rule-{i}", "candidate_ip": "203.0.113.9", "score": 40}, 65536)
        for i in range(64)
    ]
    if extra:
        rows.append({"id": "tail", "candidate_ip": "203.0.113.9", "score": 40})
    if isinstance(adapter, MemoryRepository):
        adapter.candidates["root"] = rows
    else:
        adapter.save_candidates("root", rows)
        table = adapter.connection
        for row in rows:
            if isinstance(adapter, SQLiteRepository):
                table.execute(
                    "UPDATE candidate_records SET data=? WHERE candidate_id=?",
                    (wire(adapter, row), row["id"]),
                )
            else:
                table.execute(
                    "UPDATE candidate_records SET data=%s::jsonb WHERE candidate_id=%s",
                    (wire(adapter, row), row["id"]),
                )
        table.commit()
    if extra:
        monkeypatch.setattr(s, "project_source", poison)
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_CANDIDATE_LIMIT$"):
            read(adapter)
    else:
        assert len(read(adapter).candidates) == 64


class RecordingCursor:
    def __init__(self, cursor: Any, connection: Any, query: str = "") -> None:
        self.inner, self.connection, self.query = cursor, connection, query

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def __enter__(self) -> Any:
        self.inner.__enter__()
        return self

    def __exit__(self, *args: Any) -> Any:
        return self.inner.__exit__(*args)

    def execute(self, query: Any, params: Any = None) -> Any:
        self.query = str(query)
        self.inner.execute(query, params)
        return self

    def capture(self, rows: list[Any], request: int | None) -> None:
        cells = [len(value.encode()) for row in rows for value in row if isinstance(value, str)]
        self.connection.observed.append((self.query, request, len(rows), tuple(cells)))

    def fetchone(self) -> Any:
        row = self.inner.fetchone()
        self.capture([] if row is None else [row], None)
        return row

    def fetchmany(self, size: int = 128) -> Any:
        rows = self.inner.fetchmany(size)
        self.capture(rows, size)
        return rows

    def fetchall(self) -> Any:
        raise AssertionError("reader must not fetchall")


class RecordingConnection:
    def __init__(self, inner: Any) -> None:
        self.inner = inner
        self.observed: list[Any] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def cursor(self, *args: Any, **kwargs: Any) -> Any:
        return RecordingCursor(self.inner.cursor(*args, **kwargs), self)

    def execute(self, query: str, params: Any = ()) -> Any:
        return self.cursor().execute(query, params)


def record_driver(adapter: Any, monkeypatch: pytest.MonkeyPatch) -> RecordingConnection:
    connection = RecordingConnection(adapter.connection)
    monkeypatch.setattr(
        adapter,
        "connection" if isinstance(adapter, SQLiteRepository) else "_connection",
        connection,
    )
    return connection


def test_driver_materializes_only_bounded_rows(
    adapter: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    if isinstance(adapter, MemoryRepository):
        pytest.skip("driver transfer applies only to SQL adapters")
    raw = stored()
    raw["flow_records"] *= 9
    adapter.save_job(raw)
    adapter.save_candidates(
        "root",
        [{"id": f"rule-{i}", "candidate_ip": "203.0.113.9", "score": 40} for i in range(257)],
    )
    recorder = record_driver(adapter, monkeypatch)
    result = read(adapter)
    assert len(result.source.strict_flows) == 288
    assert len(result.candidates) == 257
    batches = [item for item in recorder.observed if item[1] is not None]
    assert any(item[2] == 128 for item in batches)
    assert all(item[1] <= 128 and item[2] <= 128 for item in batches)
    assert all(size <= 65536 for _, _, _, sizes in batches for size in sizes)
    # Every actual driver-returned flow/candidate cell was observed, not inferred
    # from the SQL spelling. Metadata is independently bounded to 256 KiB.
    assert sum(n for q, _, n, _ in batches if "j.value" in q) == 288
    assert sum(n for q, _, n, _ in batches if "candidate_id,data" in q) == 257
    assert all(size <= 262144 for _, _, _, sizes in recorder.observed for size in sizes)


@pytest.mark.parametrize(
    "axis", ["metadata", "flow-row", "flow-total", "candidate-row", "candidate-total"]
)
def test_rejected_bytes_never_cross_driver(
    adapter: Any, axis: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if isinstance(adapter, MemoryRepository):
        pytest.skip("driver transfer applies only to SQL adapters")
    raw = stored()
    adapter.save_job(raw)
    if axis == "metadata":
        put_metadata(
            adapter, pad(adapter, {k: v for k, v in raw.items() if k != "flow_records"}, 262145)
        )
    elif axis == "flow-row":
        put_flows(adapter, [pad(adapter, raw["flow_records"][0], 65537)])
    elif axis == "flow-total":
        put_flows(adapter, [pad(adapter, raw["flow_records"][0], 65536) for _ in range(129)])
    elif axis == "candidate-row":
        adapter.save_candidates(
            "root",
            [pad(adapter, {"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}, 65537)],
        )
    else:
        adapter.save_candidates(
            "root",
            [
                pad(adapter, {"id": f"rule-{i}", "candidate_ip": "203.0.113.9", "score": 40}, 65536)
                for i in range(65)
            ],
        )
    recorder = record_driver(adapter, monkeypatch)
    monkeypatch.setattr(s, "project_source", poison)
    with pytest.raises(r.HistoricalReadError, match="_LIMIT$"):
        read(adapter)
    assert not any(
        sizes
        for query, _, _, sizes in recorder.observed
        if (
            "candidate_id,data" in query
            if axis.startswith("candidate")
            else "j.value" in query
            if axis.startswith("flow")
            else "SELECT data" in query
        )
    )


@pytest.mark.parametrize("extra", [0, 1])
def test_flow_total_exact_utf8(adapter: Any, extra: int, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = stored()
    adapter.save_job(raw)
    rows = [pad(adapter, raw["flow_records"][0], 64000) for _ in range(131)]
    remaining = 8 * 1024 * 1024 + extra - len(wire(adapter, rows).encode())
    assert 0 < remaining < len(rows) * (65536 - 64000)
    for row in rows:
        portion = min(remaining, 65536 - 64000)
        row["unused"] += "x" * portion
        remaining -= portion
    assert remaining == 0
    assert len(wire(adapter, rows).encode()) == 8 * 1024 * 1024 + extra
    put_flows(adapter, rows)
    if extra:
        monkeypatch.setattr(s, "project_source", poison)
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LIMIT$"):
            read(adapter)
    else:
        assert len(read(adapter).source.strict_flows) == 131


@pytest.mark.parametrize("length", [16, 17])
def test_lineage_limit(adapter: Any, length: int) -> None:
    for index in range(length):
        raw = stored()
        raw.update(
            id="root" if index == 0 else f"parent-{index}",
            parent_job_id=f"parent-{index + 1}" if index + 1 < length else None,
        )
        adapter.save_job(raw)
    if length == 17:
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LINEAGE_INVALID$"):
            read(adapter)
    else:
        assert len(read(adapter).source.lineage) == 16


@pytest.mark.parametrize("parent", ["missing", "root"])
def test_lineage_missing_cycle(adapter: Any, parent: str) -> None:
    raw = stored()
    raw["parent_job_id"] = parent
    adapter.save_job(raw)
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LINEAGE_INVALID$"):
        read(adapter)


def test_missing_empty_and_partial_are_distinct(adapter: Any) -> None:
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_NOT_FOUND$"):
        read(adapter)
    raw = stored()
    raw.update(status="PARTIALLY_COMPLETED", capture_incomplete=True)
    adapter.save_job(raw)
    result = read(adapter)
    assert "TARGET_PARTIAL_CAPTURE" in s.target_vetoes(result.source, quality_review=review())
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_STATE$"):
        read(adapter, "APPROVAL")
    raw.update(status="COMPLETED", flow_records=[])
    adapter.save_job(raw)
    empty = read(adapter)
    assert empty.source.strict_flows == ()
    assert build(empty.source).profiles == ()


def test_candidate_and_original_binding_controls(adapter: Any) -> None:
    raw = stored()
    adapter.save_job(raw)
    approval = read(adapter, "APPROVAL")
    before = read(adapter)
    candidate = {"id": "rule", "candidate_ip": "203.0.113.9", "score": 40, "excluded": False}
    adapter.save_candidates("root", [candidate])
    after = read(adapter)
    assert after.source_binding_sha256 != before.source_binding_sha256
    assert read(adapter, "APPROVAL").source_binding_sha256 == approval.source_binding_sha256
    candidate["excluded"] = True
    adapter.save_candidates("root", [candidate])
    assert read(adapter).source_binding_sha256 != after.source_binding_sha256
    assert before.candidates == ()
    raw["flow_records"][0]["total_bytes"] += 1
    adapter.save_job(raw)
    assert read(adapter, "APPROVAL").source_binding_sha256 != approval.source_binding_sha256
    assert before.source.strict_flows[0].total_bytes == 100


@pytest.mark.parametrize("axis", ["metadata", "flow", "candidate"])
def test_sqlite_duplicate_keys_reach_canonical_decoder(tmp_path: Path, axis: str) -> None:
    repo = SQLiteRepository(tmp_path / "duplicate.sqlite")
    raw = stored()
    repo.save_job(raw)
    if axis == "metadata":
        text = wire(repo, {k: v for k, v in raw.items() if k != "flow_records"})
        repo.connection.execute(
            "UPDATE objects SET data=? WHERE kind='job'", ('{"status":"COMPLETED",' + text[1:],)
        )
    elif axis == "flow":
        row = wire(repo, raw["flow_records"][0])
        repo.connection.execute(
            "UPDATE job_flow_records SET data=?", ('[{"total_bytes":100,' + row[1:] + "]",)
        )
    else:
        repo.save_candidates("root", [{"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}])
        repo.connection.execute(
            "UPDATE candidate_records SET data=?",
            ('{"id":"rule","candidate_ip":"203.0.113.9","score":40,"score":41}',),
        )
    repo.connection.commit()
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
        read(repo)
    assert not repo.connection.in_transaction
    repo.close()


@pytest.mark.parametrize("value", [True, 2**64, "1", None])
def test_malformed_measurement_rejected(adapter: Any, value: Any) -> None:
    raw = stored()
    raw["flow_records"][0]["packet_count"] = value
    adapter.save_job(raw)
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
        read(adapter)


def test_foreign_transaction_not_committed_or_rolled_back(adapter: Any) -> None:
    if isinstance(adapter, MemoryRepository):
        pytest.skip("SQL transaction ownership")
    adapter.save_job(stored())
    adapter.connection.execute("BEGIN")
    if isinstance(adapter, SQLiteRepository):
        adapter.connection.execute("INSERT INTO objects VALUES('h4','caller','{}')")
    else:
        adapter.connection.execute("INSERT INTO controller_objects VALUES('h4','caller','{}')")
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_BUSY$"):
        read(adapter)
    table = "objects" if isinstance(adapter, SQLiteRepository) else "controller_objects"
    assert adapter.connection.execute(f"SELECT id FROM {table} WHERE kind='h4'").fetchone() == (
        "caller",
    )
    adapter.connection.rollback()
    assert read(adapter).source.original.id == "root"


@pytest.mark.parametrize("extra", [0, 1])
def test_candidate_cumulative_exact_plus_one(adapter: Any, extra: int) -> None:
    adapter.save_job(stored())
    quotient, remainder = divmod(4 * 1024 * 1024 + extra, 65)
    rows = [
        pad(
            adapter,
            {"id": f"rule-{i}", "candidate_ip": "203.0.113.9", "score": 40},
            quotient + (i < remainder),
        )
        for i in range(65)
    ]
    assert sum(len(wire(adapter, row).encode()) for row in rows) == 4 * 1024 * 1024 + extra
    if isinstance(adapter, MemoryRepository):
        adapter.candidates["root"] = rows
    else:
        adapter.save_candidates("root", rows)
        for row in rows:
            query = (
                "UPDATE candidate_records SET data=? WHERE candidate_id=?"
                if isinstance(adapter, SQLiteRepository)
                else "UPDATE candidate_records SET data=%s::jsonb WHERE candidate_id=%s"
            )
            adapter.connection.execute(query, (wire(adapter, row), row["id"]))
        adapter.connection.commit()
    if extra:
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_CANDIDATE_LIMIT$"):
            read(adapter)
    else:
        assert len(read(adapter).candidates) == 65


@pytest.mark.parametrize(
    "argument,value",
    [
        ("job_id", "root\x00"),
        ("job_id", "root\ud800"),
        ("job_id", 1),
        ("purpose", "approval"),
        ("scope", {}),
        ("quality_review", {}),
    ],
)
def test_arguments_fail_before_any_storage(
    adapter: Any, argument: str, value: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = dict(job_id="root", purpose="COMPARISON", scope=config(), quality_review=review())
    args[argument] = value
    for name in ("memory_snapshot", "sqlite_snapshot", "postgres_snapshot"):
        monkeypatch.setattr(r, name, poison)
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
        adapter.read_historical_source(**args)


def test_no_review_is_not_invented(adapter: Any) -> None:
    adapter.save_job(stored())
    result = adapter.read_historical_source(
        "root", purpose="COMPARISON", scope=config(), quality_review=None
    )
    assert s.target_vetoes(result.source, quality_review=None) == ("TARGET_REVIEW_REQUIRED",)


@pytest.mark.parametrize("shape", ["embedded", "absent", "malformed"])
def test_sqlite_explicit_legacy_and_missing_handling(tmp_path: Path, shape: str) -> None:
    repo = SQLiteRepository(tmp_path / "legacy.sqlite")
    raw = stored()
    repo.save_job(raw)
    if shape == "embedded":
        repo.connection.execute("UPDATE objects SET data=? WHERE kind='job'", (wire(repo, raw),))
    elif shape == "absent":
        repo.connection.execute("DELETE FROM job_flow_records")
    else:
        repo.connection.execute("UPDATE job_flow_records SET data='[broken'")
    repo.connection.commit()
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_INVALID$"):
        read(repo)
    repo.close()


def test_sqlite_autocommit_connection_is_not_adopted(tmp_path: Path) -> None:
    repo = SQLiteRepository(tmp_path / "autocommit.sqlite")
    repo.save_job(stored())
    repo.connection.autocommit = True
    try:
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_BUSY$"):
            read(repo)
        assert not repo.connection.in_transaction
    finally:
        repo.connection.execute("ROLLBACK") if repo.connection.in_transaction else None
        repo.close()


@pytest.mark.parametrize(
    "axis,extra",
    [
        ("depth", 0),
        ("depth", 1),
        ("nodes", 0),
        ("nodes", 1),
        ("context", 0),
        ("context", 1),
        ("syn", 0),
        ("syn", 1),
    ],
)
def test_retained_raw_structural_budgets(adapter: Any, axis: str, extra: int) -> None:
    raw = stored()
    if axis == "depth":
        value: Any = 0
        for _ in range(14 + extra):
            value = [value]
        raw["flow_records"][0]["unused"] = value
    elif axis == "nodes":
        from c2hunter_controller import historical_baseline as h

        raw["flow_records"] = [dict(raw["flow_records"][0], unused=[]) for _ in range(16)]
        meter = h._OriginalBudget(8 * 1024 * 1024)
        meter.visit(raw["flow_records"])
        quotient, remainder = divmod(262144 + extra - meter.nodes, 16)
        for index, row in enumerate(raw["flow_records"]):
            row["unused"] = [0] * (quotient + (index < remainder))
    elif axis == "context":
        raw["flow_records"][0]["packet_sizes"] = [1] * (128 + extra)
    else:
        for row in raw["flow_records"]:
            row["tcp_syn_only_observations"] = [[0, index] for index in range(8)]
        if extra:
            raw["flow_records"][-1]["tcp_syn_only_observations"].append([0, 99])
    adapter.save_job(raw)
    if extra:
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LIMIT$"):
            read(adapter)
    else:
        assert read(adapter).source.original.id == "root"


def test_sqlite_outage_not_missing(tmp_path: Path) -> None:
    repo = SQLiteRepository(tmp_path / "closed.sqlite")
    repo.save_job(stored())
    repo.connection.execute("DROP TABLE job_flow_records")
    repo.connection.commit()
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        read(repo)
    repo.close()


def test_closed_sqlite_is_static_outage(tmp_path: Path) -> None:
    repo = SQLiteRepository(tmp_path / "closed.sqlite")
    repo.close()
    with pytest.raises(r.HistoricalReadError, match="^BASELINE_STORAGE_UNAVAILABLE$"):
        read(repo)
