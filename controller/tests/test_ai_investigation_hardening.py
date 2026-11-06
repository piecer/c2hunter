"""Admission, immutability and suppression regression closure."""

from typing import Any

import pytest

from tests import test_ai_investigation_evidence as fixtures
from tests.test_ai_investigation_evidence import flow, job, read, service

repo = fixtures.repo


def test_control_suppression_visible_without_protocol_tool(repo: Any) -> None:
    repo.save_job(job([flow(protocol="TCP", tcp_flags={"rst": 1}, payload_length=0), flow()]))
    tools = service(repo, target_ip="10.0.0.1")
    result = tools.call("peer_overview", {})
    metrics = {m.name: m.value for m in result.metrics}
    assert metrics["suppressed_control_rows"] == 1
    assert metrics["c2_eligible_rows"] == 1
    samples = tools.call("peer_flow_samples", {})
    assert samples.samples[0].c2_eligibility == "SUPPRESSED_OUTBOUND_CONTROL"
    assert "CONTROL_TRAFFIC_NOT_C2_EVIDENCE" in samples.limitations


def test_unknown_flags_not_false_observed_zero(repo: Any) -> None:
    repo.save_job(job([flow(protocol="TCP", tcp_flags={"ack": 1}, tcp_flags_observed=1)]))
    with pytest.raises(ValueError, match="SOURCE_INVALID"):
        read(repo)


def test_argument_admission_before_read_and_sqlite_errors(
    repo: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    from c2hunter_controller.ai_investigation_contract import InvestigationError
    from c2hunter_controller.repositories import SQLiteRepository

    repo.save_job(job())
    with pytest.raises(InvestigationError, match="INVALID_SOURCE_ARGUMENTS"):
        repo.read_investigation_source("job", expected_source_sha256="invalid")
    if isinstance(repo, SQLiteRepository):
        repo.close()
        with pytest.raises(InvestigationError, match="SOURCE_STORAGE_UNAVAILABLE"):
            read(repo)


def test_read_only_no_hidden_mutation(repo: Any) -> None:
    from copy import deepcopy

    from c2hunter_controller.repositories import MemoryRepository

    repo.save_job(job())
    if isinstance(repo, MemoryRepository):
        before = deepcopy(repo.jobs)
    else:
        before = repo.connection.total_changes
    tools = service(repo, target_ip="10.0.0.1")
    for tool in (
        "peer_overview",
        "peer_flow_samples",
        "peer_timeline",
        "peer_protocol_observations",
        "compare_peer_cohort",
    ):
        first = tools.call(tool, {})
        assert first == tools.call(tool, {})
    if isinstance(repo, MemoryRepository):
        assert repo.jobs == before
        repo.jobs["job"]["flow_records"][0]["total_bytes"] = 999
        assert tools.call("peer_overview", {}).metrics[1].value == 80
    else:
        assert repo.connection.total_changes == before
        assert not repo.connection.in_transaction


def test_directional_metrics_are_addressable(repo: Any) -> None:
    repo.save_job(job([flow(total_bytes=80), flow(direction="INBOUND", total_bytes=120)]))
    tools = service(repo, target_ip="10.0.0.1")
    result = tools.call("peer_overview", {})
    metrics = {m.name: m for m in result.metrics}
    assert metrics["outbound_bytes"].value == 80
    assert metrics["inbound_bytes"].value == 120
    assert metrics["outbound_rows"].value == 1
    assert tools.resolve_metric(metrics["inbound_bytes"].ref).value == 120


def test_invalid_dataset_metadata_rejects_before_flow_hydration(
    repo: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from c2hunter_controller import ai_investigation_read as reader

    raw = job()
    raw["dataset_id"] = ""
    repo.save_job(raw)
    monkeypatch.setattr(reader.bounded, "_admit_rows", lambda *a, **k: pytest.fail("hydrated"))
    monkeypatch.setattr(reader.bounded, "_sqlite_flows", lambda *a, **k: pytest.fail("hydrated"))
    with pytest.raises(ValueError, match="SOURCE_INVALID"):
        read(repo)


@pytest.mark.parametrize("rows", [None, [flow(packet_count=0)]])
def test_present_invalid_source_is_not_missing_or_empty(repo: Any, rows: Any) -> None:
    raw = job()
    raw["flow_records"] = rows
    repo.save_job(raw)
    with pytest.raises(ValueError, match="SOURCE_INVALID"):
        read(repo)
