"""Byte budgets and persisted-source boundaries, synthetic sources only."""

from typing import Any

import pytest

from tests import test_ai_investigation_evidence as fixtures
from tests.test_ai_investigation_evidence import flow, job, read, service

repo = fixtures.repo


def test_tool_reply_and_retained_evidence_budgets(repo: Any) -> None:
    from c2hunter_controller.ai_investigation_contract import canonical_bytes

    repo.save_job(job([flow(sensor_id="센" * 200, domain="a" * 240 + ".test")] * 60))
    tools = service(repo, target_ip="10.0.0.1")
    result = tools.call("peer_flow_samples", {"limit": 50})
    assert len(canonical_bytes(result.model_dump(mode="json"))) <= 32768
    assert result.counts.retained == len(result.samples)
    assert result.counts.omitted == 60 - len(result.samples)
    assert "REPLY_BYTE_LIMIT" in result.limitations
    for limit in range(49, 0, -1):
        try:
            tools.call("peer_flow_samples", {"limit": limit})
        except ValueError as exc:
            assert str(exc) == "EVIDENCE_BUDGET"
            break
    else:
        pytest.fail("run evidence budget missing")
    assert tools.retained_bytes <= 256 * 1024
    assert tools.call("peer_flow_samples", {"limit": 50}) == result


def test_partial_source_no_match_is_not_full_capture_absence(repo: Any) -> None:
    raw = job()
    raw["status"] = "PARTIALLY_COMPLETED"
    repo.save_job(raw)
    result = service(repo, target_ip="10.0.0.99").call("peer_overview", {})
    assert result.status == "NOT_FOUND_IN_INSPECTED_SCOPE"
    assert "PARTIAL_SOURCE" in result.limitations


def test_state_and_module_gate_before_flow_decode(
    repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_controller import ai_investigation_read as reader

    raw = job()
    raw["status"] = "RUNNING"
    repo.save_job(raw)
    monkeypatch.setattr(reader.bounded, "_admit_rows", lambda *a, **k: pytest.fail("hydrated"))
    monkeypatch.setattr(reader.bounded, "_sqlite_flows", lambda *a, **k: pytest.fail("hydrated"))
    with pytest.raises(ValueError, match="SOURCE_STATE"):
        read(repo)


@pytest.mark.parametrize("boundary", ["metadata", "row", "flows"])
def test_exact_and_plus_one_source_bytes(
    repo: Any, boundary: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_controller import ai_investigation_read as reader
    from c2hunter_controller.ai_investigation_contract import canonical_bytes
    from c2hunter_controller.repositories import MemoryRepository

    def padded(size: int) -> dict[str, Any]:
        row = flow(padding="")
        row["padding"] = "x" * (size - len(canonical_bytes(row)))
        assert len(canonical_bytes(row)) == size
        return row

    raw = job()
    if boundary == "row":
        raw["flow_records"] = [padded(65536)]
    elif boundary == "flows":
        rows = [padded(65536) for _ in range(127)]
        rows.append(padded(8 * 1024 * 1024 - 2 - 127 - 127 * 65536))
        raw["flow_records"] = rows
        assert len(canonical_bytes(rows)) == 8 * 1024 * 1024
    else:
        raw["padding"] = ""
        metadata = {k: v for k, v in raw.items() if k != "flow_records"}
        raw["padding"] = "x" * (256 * 1024 - len(canonical_bytes(metadata)))

    def save() -> None:
        if isinstance(repo, MemoryRepository):
            repo.save_job(raw)
        else:
            repo.save_job(job())
            metadata = {k: v for k, v in raw.items() if k != "flow_records"}
            repo.connection.execute(
                "UPDATE objects SET data=? WHERE kind='job' AND id='job'",
                (canonical_bytes(metadata).decode(),),
            )
            repo.connection.execute(
                "UPDATE job_flow_records SET data=? WHERE job_id='job'",
                (canonical_bytes(raw["flow_records"]).decode(),),
            )
            repo.connection.commit()

    save()
    assert len(read(repo).rows) == len(raw["flow_records"])
    if boundary == "metadata":
        raw["padding"] += "x"
    else:
        raw["flow_records"][-1]["padding"] += "x"
    save()
    monkeypatch.setattr(reader, "_project", lambda *a: pytest.fail("projected oversize source"))
    original = reader.bounded._decode

    def decode(value: str, **kw: Any) -> Any:
        assert boundary != "metadata", "metadata transferred before byte gate"
        assert kw.get("max_bytes") != 65536, "flow transferred before byte gate"
        return original(value, **kw)

    monkeypatch.setattr(reader.bounded, "_decode", decode)
    with pytest.raises(ValueError, match="^SOURCE_LIMIT$"):
        read(repo)


def test_snapshot_copy_tampering_and_metric_references(repo: Any) -> None:
    from c2hunter_controller.ai_investigation_contract import InvestigationScope
    from c2hunter_controller.ai_investigation_evidence import EvidenceService

    repo.save_job(job())
    snapshot = read(repo)
    forged = snapshot.model_copy(
        update={"rows": (snapshot.rows[0].model_copy(update={"total_bytes": 9}),)}
    )
    with pytest.raises(ValueError, match="SOURCE_INVALID"):
        EvidenceService(forged, InvestigationScope(target_ip="10.0.0.1"))
    tools = EvidenceService(snapshot, InvestigationScope(target_ip="10.0.0.1"))
    result = tools.call("peer_overview", {})
    assert tools.resolve_metric(result.metrics[0].ref) == result.metrics[0]
    with pytest.raises(ValueError, match="REFERENCE_MISMATCH"):
        tools.resolve_metric("0" * 64 + ":matched_rows")


def test_reachable_exact_reply_bytes_then_one_more(repo: Any) -> None:
    from c2hunter_controller.ai_investigation_contract import canonical_bytes

    rows = [flow(domain="a.test") for _ in range(30)]
    repo.save_job(job(rows))
    initial = service(repo, target_ip="10.0.0.1").call("peer_flow_samples", {})
    assert len(initial.samples) == 30
    remaining = 32768 - len(canonical_bytes(initial.model_dump(mode="json")))
    for row in rows:
        increase = min(247, remaining)
        row["domain"] = "a" * increase + row["domain"]
        remaining -= increase
    assert remaining == 0
    repo.save_job(job(rows))
    exact = service(repo, target_ip="10.0.0.1").call("peer_flow_samples", {})
    assert len(exact.samples) == 30
    assert len(canonical_bytes(exact.model_dump(mode="json"))) == 32768
    for row in rows:
        if len(row["domain"]) < 253:
            row["domain"] = "a" + row["domain"]
            break
    repo.save_job(job(rows))
    overflow = service(repo, target_ip="10.0.0.1").call("peer_flow_samples", {})
    assert len(overflow.samples) == 29
    assert overflow.counts.omitted == 1
    assert "REPLY_BYTE_LIMIT" in overflow.limitations
    assert len(canonical_bytes(overflow.model_dump(mode="json"))) <= 32768
