"""Reachable context boundaries and earlier-cap precedence on actual preview."""

from typing import Any

import pytest
from c2hunter_analysis import behavior_baseline as b

import tests.test_baseline_scope_storage as storage_fixtures
import tests.test_historical_read_postgres as pg_fixtures
from c2hunter_controller import historical_baseline as h
from c2hunter_controller import historical_read as r
from c2hunter_controller.repositories import MemoryRepository
from tests.test_baseline_preview_admission_completion import Connection
from tests.test_historical_read_bounds import pad, put_metadata, wire
from tests.test_historical_read_node_admission import nodes
from tests.test_historical_source import START, config, stored

scope_repo = storage_fixtures.scope_repo
pg_repo = pg_fixtures.pg_repo


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "clock"])
@pytest.mark.parametrize("count", [1, 128, 129])
@pytest.mark.parametrize("axis", ["sensor_ids", "internal_networks"])
def test_source_context_precedence(
    scope_repo: Any, purpose: str, quality: str, count: int, axis: str, monkeypatch: Any
) -> None:
    repo = scope_repo
    raw = stored()
    cfg = config()
    if quality == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    if quality == "clock":
        raw["capture_quality"] = {"clock_skew_detected": True}
    if axis == "sensor_ids":
        raw[axis] = ["sensor"] if count == 1 else [f"sensor-{i}" for i in range(count)]
    else:
        networks = ["10.0.0.0/24"] + [f"10.1.{i}.0/24" for i in range(count - 1)]
        raw[axis] = sorted(networks)
        if count <= 128:
            cfg = h.ScopeConfig.from_mapping(
                dict(cfg.to_mapping(), internal_networks=sorted(networks))
            )
    repo.create_baseline_scope(cfg, "admin", START)
    repo.save_job(raw)
    feature = []
    original = b._dispersion

    def observe(*a: Any, **kw: Any) -> Any:
        feature.append(1)
        return original(*a, **kw)

    monkeypatch.setattr(b, "_dispersion", observe)
    if count > 128 or (axis == "sensor_ids" and count > 1):
        expected = "BASELINE_SOURCE_LIMIT" if count > 128 else "BASELINE_SCOPE_MISMATCH"
        with pytest.raises(r.HistoricalReadError, match="^" + expected + "$"):
            repo.preview_baseline_source(cfg.scope_id, "root", 0, purpose)
        assert feature == []
    else:
        result = repo.preview_baseline_source(cfg.scope_id, "root", 0, purpose)
        assert result.flow_count == 32 and result.admissible is (quality == "clean")


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("extra", [0, 1])
def test_metadata_nodes_obey_earlier_byte_boundary(
    scope_repo: Any, purpose: str, extra: int, monkeypatch: Any, record_property: Any
) -> None:
    repo = scope_repo
    repo.create_baseline_scope(config(), "admin", START)
    raw = stored()
    repo.save_job(raw)
    metadata = {k: v for k, v in raw.items() if k != "flow_records"}
    metadata["unused"] = [0] * 80000
    admitted = pad(repo, metadata, 262144 + extra)
    # Padding replaces the marker: retain the large node collection separately.
    metadata["many_nodes"] = metadata.pop("unused")
    admitted = pad(repo, metadata, 262144 + extra)
    assert nodes(admitted) < 262144
    put_metadata(repo, admitted)
    decoded = []
    decode0 = r._decode

    def decode(text: str, **kw: Any) -> Any:
        if "many_nodes" in text:
            decoded.append(1)
        return decode0(text, **kw)

    monkeypatch.setattr(r, "_decode", decode)
    recorder = None
    if not isinstance(repo, MemoryRepository) and not hasattr(repo, "database_url"):
        recorder = Connection(repo.connection)
        monkeypatch.setattr(repo, "connection", recorder)
    if extra:
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_SOURCE_LIMIT$"):
            repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
        assert decoded == []
        if recorder:
            assert not any(
                sizes for q, _, _, sizes in recorder.transfers if "SELECT data FROM objects" in q
            )
    else:
        assert repo.preview_baseline_source(config().scope_id, "root", 0, purpose).admissible
    # Literal node-cap input cannot fit this metadata representation's byte cap.
    literal = dict(metadata, many_nodes=[])
    literal["many_nodes"] = [0] * (262144 - nodes(literal))
    assert nodes(literal) == 262144
    assert len(wire(repo, literal).encode()) > 262144
    record_property("literal_node_cap_bytes", len(wire(repo, literal).encode()))


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("count", [128, 129, 256, 257])
def test_peer_limit_has_earlier_raw_profile_limit(
    scope_repo: Any, count: int, purpose: str, monkeypatch: Any
) -> None:
    repo = scope_repo
    raw = stored()
    raw["flow_records"] = [
        dict(raw["flow_records"][0], destination_ip=f"203.0.{i // 254}.{1 + i % 254}")
        for i in range(count)
    ]
    repo.create_baseline_scope(config(), "admin", START)
    repo.save_job(raw)
    if count > 128:
        monkeypatch.setattr(
            b, "_dispersion", lambda *_a, **_k: pytest.fail("feature before profile limit")
        )
        with pytest.raises(r.HistoricalReadError, match="^BASELINE_PROFILE_LIMIT$"):
            repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
    else:
        result = repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
        assert result.profile_count == 128 and not result.admissible


@pytest.mark.parametrize("axis", ["hosts", "internal_networks"])
@pytest.mark.parametrize("count", [128, 129])
def test_typed_scope_collection_boundary(scope_repo: Any, axis: str, count: int) -> None:
    cfg = config()
    if axis == "hosts":
        values = [{"ip": f"10.0.0.{i + 1}", "epoch": "fixture"} for i in range(count)]
    else:
        values = sorted(["10.0.0.0/24"] + [f"10.1.{i}.0/24" for i in range(count - 1)])
    mapping = dict(cfg.to_mapping(), **{axis: values})
    if count == 129:
        with pytest.raises(ValueError):
            h.ScopeConfig.from_mapping(mapping)
        forged = cfg.model_copy(update={axis: tuple(values)})
        with pytest.raises(ValueError):
            scope_repo.create_baseline_scope(forged, "admin", START)
        assert scope_repo.page_baseline_scopes().total == 0
    else:
        cfg = h.ScopeConfig.from_mapping(mapping)
        scope_repo.create_baseline_scope(cfg, "admin", START)
        raw = stored()
        raw["internal_networks"] = list(cfg.internal_networks)
        scope_repo.save_job(raw)
        for purpose in ("APPROVAL", "COMPARISON"):
            assert scope_repo.preview_baseline_source(cfg.scope_id, "root", 0, purpose).admissible


@pytest.mark.parametrize("purpose", ["APPROVAL", "COMPARISON"])
@pytest.mark.parametrize("quality", ["clean", "partial", "clock"])
@pytest.mark.parametrize("fault", ["state", "module", "malformed", "lineage"])
def test_preview_negative_fact_precedence(
    scope_repo: Any, purpose: str, quality: str, fault: str, monkeypatch: Any
) -> None:
    raw = stored()
    if quality == "partial":
        raw["status"] = "PARTIALLY_COMPLETED"
    if quality == "clock":
        raw["capture_quality"] = {"clock_skew_detected": True}
    codes = {
        "state": "BASELINE_SOURCE_STATE",
        "module": "BASELINE_SOURCE_INVALID",
        "malformed": "BASELINE_SOURCE_INVALID",
        "lineage": "BASELINE_SOURCE_LINEAGE_INVALID",
    }
    if fault == "state":
        raw["status"] = "CANCELLED"
    elif fault == "module":
        raw["analysis"] = {"module": "other"}
    elif fault == "malformed":
        raw["flow_records"][0]["packet_count"] = True
    else:
        raw["parent_job_id"] = "missing-parent"
    scope_repo.create_baseline_scope(config(), "admin", START)
    scope_repo.save_job(raw)
    if fault in ("state", "module", "lineage"):
        for name in ("_admit_rows", "_sqlite_flows", "_pg_flows"):
            monkeypatch.setattr(
                r, name, lambda *_a, **_k: pytest.fail("flows before metadata gate")
            )
    with pytest.raises(r.HistoricalReadError, match="^" + codes[fault] + "$"):
        scope_repo.preview_baseline_source(config().scope_id, "root", 0, purpose)
