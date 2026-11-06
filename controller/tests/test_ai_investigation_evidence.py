"""Synthetic evidence tracer bullets; never call operating stores or models."""

from pathlib import Path
from typing import Any

import pytest

from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


def flow(**updates: Any) -> dict[str, Any]:
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
    row.update(updates)
    return row


def job(rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    return {
        "id": "job",
        "dataset_id": "dataset",
        "parent_job_id": None,
        "status": "COMPLETED",
        "analysis": {"module": "c2"},
        "flow_records": [flow()] if rows is None else rows,
    }


@pytest.fixture(params=["memory", "sqlite"])
def repo(request: Any, tmp_path: Path) -> Any:
    value = MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "s.db")
    yield value
    value.close()


def read(repo: Any, **kwargs: Any) -> Any:
    method = getattr(repo, "read_investigation_source", None)
    assert callable(method), "bounded investigation read entrypoint is missing"
    return method("job", **kwargs)


def poison(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("unbounded loader or premature hydration")


def test_detached_source_without_candidates(repo: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    raw = job()
    repo.save_job(raw)
    monkeypatch.setattr(repo, "get_job", poison)
    snapshot = read(repo)
    assert snapshot.binding.job_id == "job"
    assert snapshot.binding.dataset_id == "dataset"
    assert snapshot.rows[0].ordinal == 0
    assert snapshot.rows[0].source_ip == "10.0.0.1"
    assert snapshot.rows[0].destination_ip == "2001:db8::1"
    assert "total_bytes" in snapshot.rows[0].present_fields
    assert snapshot == read(repo)
    raw["flow_records"][0]["total_bytes"] = 999
    assert snapshot.rows[0].total_bytes == 80
    with pytest.raises((ValueError, AttributeError, TypeError)):
        snapshot.rows[0].total_bytes = 999


def test_source_missing_empty_and_changed(repo: Any) -> None:
    from c2hunter_controller.ai_investigation_contract import InvestigationError

    with pytest.raises(InvestigationError, match="^SOURCE_NOT_FOUND$"):
        read(repo)
    raw = job([])
    repo.save_job(raw)
    empty = read(repo)
    assert empty.rows == ()
    assert read(repo, expected_source_sha256=empty.binding.source_sha256) == empty
    raw["flow_records"] = [flow()]
    repo.save_job(raw)
    with pytest.raises(InvestigationError, match="^SOURCE_CHANGED$"):
        read(repo, expected_source_sha256=empty.binding.source_sha256)
    if isinstance(repo, MemoryRepository):
        del repo.jobs["job"]["flow_records"]
    else:
        repo.connection.execute("DELETE FROM job_flow_records WHERE job_id='job'")
        repo.connection.commit()
    with pytest.raises(InvestigationError, match="^SOURCE_UNAVAILABLE$"):
        read(repo)


@pytest.mark.parametrize("module", ["c2", "network_anomaly", "ddos_attack"])
def test_actual_observations_allow_non_c2_modules(repo: Any, module: str) -> None:
    from c2hunter_controller.schemas import AnalysisParameters

    raw = job()
    raw["analysis"] = AnalysisParameters(module=module).model_dump(mode="json")
    repo.save_job(raw)
    assert len(read(repo).rows) == 1


def test_source_limit_before_projection(repo: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    from c2hunter_controller import ai_investigation_read as reader
    from c2hunter_controller.ai_investigation_contract import InvestigationError

    repo.save_job(job([flow()] * 8192))
    assert len(read(repo).rows) == 8192
    repo.save_job(job([flow()] * 8193))
    monkeypatch.setattr(reader, "_project", poison)
    monkeypatch.setattr("c2hunter_controller.repositories.deepcopy", poison)
    if isinstance(repo, SQLiteRepository):
        original = reader.bounded._decode

        def decode(raw: str, **kw: Any) -> Any:
            assert kw.get("max_bytes") != 64 * 1024, "flow decoded before count admission"
            return original(raw, **kw)

        monkeypatch.setattr(reader.bounded, "_decode", decode)
    with pytest.raises(InvestigationError, match="^SOURCE_LIMIT$"):
        read(repo)


def service(repo: Any, **scope: Any) -> Any:
    import importlib.util

    from c2hunter_controller import ai_investigation_contract as contract

    assert importlib.util.find_spec("c2hunter_controller.ai_investigation_evidence"), (
        "tools missing"
    )
    from c2hunter_controller.ai_investigation_evidence import EvidenceService

    return EvidenceService(read(repo), contract.InvestigationScope(**scope))


def test_overview_bidirectional_non_candidate_scope(repo: Any) -> None:
    repo.save_job(
        job(
            [
                flow(),
                flow(
                    source_ip="2001:db8::1",
                    destination_ip="10.0.0.1",
                    direction="INBOUND",
                    total_bytes=120,
                ),
                flow(sensor_id="s2", total_bytes=50),
            ]
        )
    )
    tools = service(repo, target_ip="2001:0DB8::1")
    result = tools.call("peer_overview", {})
    assert result.scope.target_ip == "2001:db8::1"
    metrics = {m.name: m.value for m in result.metrics}
    assert metrics["matched_rows"] == 3
    assert metrics["total_bytes"] == 250
    assert metrics["sensor_count"] == 2
    assert "SENSOR_IDENTITIES_NOT_MERGED" in result.limitations
    assert tools.call("peer_overview", {}).model_dump_json() == result.model_dump_json()
    source_only = service(repo, target_ip="10.0.0.1", endpoint_side="source", sensor_id="s1")
    assert source_only.call("peer_overview", {}).counts.matched == 1
    inbound = service(repo, target_ip="10.0.0.1", traffic_direction="INBOUND")
    assert inbound.call("peer_overview", {}).counts.matched == 1
    absent = service(repo, target_ip="10.0.0.99").call("peer_overview", {})
    assert absent.status == "NOT_OBSERVED"
    assert absent.counts.inspected == 3


@pytest.mark.parametrize("ip", [" 10.0.0.1", "10.0.0.1/32", "localhost", "fe80::1%eth0", 1])
def test_scope_rejects_nonliteral_ip(repo: Any, ip: Any) -> None:
    repo.save_job(job())
    with pytest.raises(ValueError):
        service(repo, target_ip=ip)
