"""Actual persisted preview admission, ported from independent PG behavior.

The fixture uses real adapters. PostgreSQL is retained for a separately
allocated future replay; a skip is never reported as its acceptance.
"""

from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import MemoryRepository
from tests.test_historical_read_bounds import pad, put_flows, put_metadata, wire
from tests.test_historical_read_node_admission import nodes
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo
AXES = (
    "metadata",
    "metadata-depth",
    "flow-total",
    "flow-row",
    "flow-count",
    "candidate-count",
    "candidate-total",
    "candidate-row",
    "flow-depth",
    "flow-nodes",
    "candidate-depth",
    "candidate-nodes",
    "tcp_flags",
    "allowlist",
    "sensors",
    "capture_completions",
    "profiles",
)


class Cursor:
    def __init__(self, inner: Any, owner: Any) -> None:
        self.inner, self.owner, self.query = inner, owner, ""

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def execute(self, query: str, params: Any = ()) -> Any:
        self.query = query
        self.owner.queries.append(query)
        self.inner.execute(query, params)
        return self

    def capture(self, rows: Any, requested: Any) -> Any:
        self.owner.transfers.append(
            (
                self.query,
                requested,
                len(rows),
                [len(v.encode()) for row in rows for v in row if isinstance(v, str)],
            )
        )
        return rows

    def fetchone(self) -> Any:
        row = self.inner.fetchone()
        self.capture([] if row is None else [row], None)
        return row

    def fetchall(self) -> Any:
        return self.capture(self.inner.fetchall(), None)

    def fetchmany(self, size: int = 128) -> Any:
        return self.capture(self.inner.fetchmany(size), size)


class Connection:
    def __init__(self, inner: Any) -> None:
        self.inner, self.queries, self.transfers = inner, [], []

    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def execute(self, query: str, params: Any = ()) -> Any:
        return Cursor(self.inner.cursor(), self).execute(query, params)


def candidate_rows(repo: Any, rows: Any) -> None:
    if isinstance(repo, MemoryRepository):
        repo.candidates["root"] = rows
    else:
        repo.save_candidates("root", rows)
        query = "UPDATE candidate_records SET data=? WHERE candidate_id=?"
        if hasattr(repo, "database_url"):
            query = "UPDATE candidate_records SET data=%s::jsonb WHERE candidate_id=%s"
        for row in rows:
            repo.connection.execute(query, (wire(repo, row), row["id"]))
        repo.connection.commit()


def prepare(repo, axis, extra, quality):
    raw = stored()
    if quality == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    if quality == "clock":
        raw["capture_quality"] = {"clock_skew_detected": True}
    rows = raw["flow_records"]
    candidate = {"id": "rule", "candidate_ip": "203.0.113.9", "score": 40}
    expected = (
        "BASELINE_CANDIDATE_LIMIT" if axis.startswith("candidate") else "BASELINE_SOURCE_LIMIT"
    )
    if axis == "profiles":
        rows = [dict(rows[0], destination_port=10000 + i) for i in range(128 + extra)]
        expected = "BASELINE_PROFILE_LIMIT"
    if axis == "flow-count":
        rows = [dict(rows[0]) for _ in range(8192 + extra)]
    if axis == "flow-row":
        rows = [pad(repo, rows[0], 65536 + extra)]
    if axis == "flow-total":
        rows = [pad(repo, rows[0], 64000) for _ in range(131)]
        remain = 8388608 + extra - len(wire(repo, rows).encode())
        for row in rows:
            n = min(remain, 1536)
            row["unused"] += "x" * n
            remain -= n
        assert remain == 0 and len(wire(repo, rows).encode()) == 8388608 + extra
    if axis.endswith("depth"):
        nested = 0
        for _ in range((15 if axis == "metadata-depth" else 14) + extra):
            nested = [nested]
        if axis == "metadata-depth":
            raw["unused"] = nested
        elif axis == "flow-depth":
            rows[0]["unused"] = nested
        else:
            candidate["unused"] = nested
    if axis.endswith("nodes"):
        prototype = rows[0] if axis == "flow-nodes" else candidate
        ns = [dict(prototype, unused=[0] * 15000, id=f"row-{i}") for i in range(17)]
        tail = dict(prototype, unused=[], id="last")
        tail["unused"] = [0] * (262144 + extra - nodes(ns) - nodes(tail))
        ns.append(tail)
        assert nodes(ns) == 262144 + extra
        if axis == "flow-nodes":
            rows = ns
    if axis == "packet_sizes":
        rows[0]["packet_sizes"] = [1] * (128 + extra)
    if axis == "tcp_flags":
        rows[0]["tcp_flags"] = {str(i): 1 for i in range(16 + extra)}
    if axis == "syn":
        for row in rows:
            row["tcp_syn_only_observations"] = [[0, i] for i in range(8)]
        if extra:
            rows[-1]["tcp_syn_only_observations"].append([0, 99])
    if axis == "allowlist":
        raw["allowlist"] = [
            {"type": "IP", "value": "203.0.113.9", "description": str(i)}
            for i in range(128 + extra)
        ]
    if axis in ("warnings", "failed_sensors"):
        raw["operations"] = {axis: [f"sensor-{i}" for i in range(128 + extra)]}
    if axis == "sensors":
        raw["operations"] = {
            "sensors": {f"sensor-{i}": {"clock_offset_ms": 0} for i in range(128 + extra)}
        }
    if axis == "capture_completions":
        raw["capture_completions"] = {
            f"sensor-{i}": {
                "stop_reason": "MAX_PACKETS",
                "reported_at": raw["end_time"],
            }
            for i in range(128 + extra)
        }
    raw["flow_records"] = rows
    repo.save_job(raw)
    # Byte probes overwrite the actual JSONB cells to avoid writer enrichment affecting exact sizes.
    if axis in ("flow-row", "flow-total"):
        put_flows(repo, rows)
    if axis == "metadata":
        put_metadata(
            repo,
            pad(
                repo,
                {k: v for k, v in raw.items() if k != "flow_records"},
                262144 + extra,
            ),
        )
    if axis.startswith("candidate"):
        if axis == "candidate-count":
            cs = [dict(candidate, id=f"row-{i}") for i in range(2048 + extra)]
        elif axis == "candidate-total":
            q, rem = divmod(4194304 + extra, 65)
            cs = [pad(repo, dict(candidate, id=f"row-{i}"), q + (i < rem)) for i in range(65)]
            assert sum(len(wire(repo, c).encode()) for c in cs) == 4194304 + extra
        elif axis == "candidate-row":
            cs = [pad(repo, candidate, 65536 + extra)]
        elif axis == "candidate-nodes":
            cs = ns
        else:
            cs = [candidate]
        candidate_rows(repo, cs)
    return raw, expected


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "clock"])
@pytest.mark.parametrize("extra", [0, 1])
@pytest.mark.parametrize("axis", AXES)
def test_public_preview_admission_matrix(
    scope_repo: Any,
    monkeypatch: Any,
    record_property: Any,
    axis: str,
    extra: int,
    quality: str,
    purpose: str,
) -> None:
    repo = scope_repo
    scope, _ = repo.create_baseline_scope(config(), "admin", START)
    _, expected = prepare(repo, axis, extra, quality)
    recorder = None
    if not isinstance(repo, MemoryRepository) and not hasattr(repo, "database_url"):
        recorder = Connection(repo.connection)
        monkeypatch.setattr(repo, "connection", recorder)
    decoded, feature, suppressed, projected, candidate_calls = [], [], [], [], []
    decode0, feature0, suppress0, project0, admit0 = (
        r._decode,
        b._dispersion,
        b.syn_retry_duplicate_flow_ids,
        h.project_original_job,
        r._admit_rows,
    )

    def decode(text: str, **kw: Any) -> Any:
        value = decode0(text, **kw)
        decoded.append((nodes(value), "unused" in value))
        return value

    def features(*args: Any, **kw: Any) -> Any:
        feature.append(1)
        return feature0(*args, **kw)

    def suppress(*args: Any, **kw: Any) -> Any:
        suppressed.append(1)
        return suppress0(*args, **kw)

    def project(*args: Any, **kw: Any) -> Any:
        projected.append(1)
        return project0(*args, **kw)

    def admit(*args: Any, **kw: Any) -> Any:
        if kw.get("candidates"):
            candidate_calls.append(1)
        return admit0(*args, **kw)

    monkeypatch.setattr(r, "_decode", decode)
    monkeypatch.setattr(r, "_admit_rows", admit)
    monkeypatch.setattr(b, "_dispersion", features)
    monkeypatch.setattr(b, "syn_retry_duplicate_flow_ids", suppress)
    monkeypatch.setattr(h, "project_original_job", project)
    monkeypatch.setattr(
        h.QualityReview, "__init__", lambda *_a, **_kw: pytest.fail("preview assertion")
    )
    monkeypatch.setattr("uuid.uuid4", lambda: pytest.fail("preview ID"))
    before = repr({k: v for k, v in vars(repo).items() if isinstance(v, dict | list)})
    reject = bool(extra and not (axis.startswith("candidate") and purpose == "APPROVAL"))
    if reject:
        with pytest.raises(r.HistoricalReadError, match="^" + expected + "$"):
            repo.preview_baseline_source(scope.config.scope_id, "root", 0, purpose)
        assert not feature and not suppressed
        if axis not in ("tcp_flags", "allowlist", "sensors", "capture_completions", "profiles"):
            assert not projected
        if axis.endswith("nodes") and recorder:
            counts = [n for n, marked in decoded if marked]
            assert 1 + sum(counts[:-1]) <= 262144 < 1 + sum(counts)
    else:
        result = repo.preview_baseline_source(scope.config.scope_id, "root", 0, purpose)
        assert result.scope_revision == 0 and result.flow_count > 0
        assert projected and suppressed
        if quality != "clean":
            assert not result.admissible
    if isinstance(repo, MemoryRepository):
        assert before == repr({k: v for k, v in vars(repo).items() if isinstance(v, dict | list)})
        if purpose == "APPROVAL":
            assert candidate_calls == []
    if recorder:
        assert not repo.connection.in_transaction
        assert not any(
            q.lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE")) for q in recorder.queries
        )
        if purpose == "APPROVAL":
            assert not any("candidate" in q.lower() for q in recorder.queries)
        if reject and axis in (
            "metadata",
            "flow-total",
            "flow-row",
            "flow-count",
            "candidate-count",
            "candidate-total",
            "candidate-row",
        ):
            marker = (
                "candidate_id,data"
                if axis.startswith("candidate")
                else "SELECT data FROM objects"
                if axis == "metadata"
                else "SELECT j.value"
            )
            assert not any(sizes for query, _, _, sizes in recorder.transfers if marker in query)
        assert all(
            request <= 128 and count <= 128
            for _, request, count, _ in recorder.transfers
            if request is not None
        )
    record_property(
        "observed",
        dict(
            projection=len(projected),
            suppression=len(suppressed),
            feature=len(feature),
            decoded=len(decoded),
            reject=reject,
        ),
    )
