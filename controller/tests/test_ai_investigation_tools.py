"""Additional vertical slices using actual synthetic Memory/SQLite adapters."""

from typing import Any

import pytest

from tests import test_ai_investigation_evidence as fixtures
from tests.test_ai_investigation_evidence import flow, job, read, service

repo = fixtures.repo


def test_samples_references_presence_and_redaction(repo: Any) -> None:
    raw = flow(payload="Authorization: secret", source_port=123, domain="example.test")
    del raw["total_bytes"]
    repo.save_job(job([raw] * 51))
    tools = service(repo, target_ip="10.0.0.1")
    evidence = tools.call("peer_flow_samples", {"limit": 50})
    assert 0 < len(evidence.samples) <= 50
    assert evidence.counts.omitted == 51 - len(evidence.samples)
    assert evidence.samples[0].row.total_bytes is None
    assert "total_bytes" not in evidence.samples[0].row.present_fields
    assert "secret" not in evidence.model_dump_json()
    assert tools.resolve_row(evidence.samples[0].ref) == evidence.samples[0].row
    assert tools.validate_evidence(evidence) == evidence
    repo.save_job(job([flow(total_bytes=99)]))
    other = service(repo, target_ip="10.0.0.1")
    with pytest.raises(ValueError, match="REFERENCE_MISMATCH"):
        other.resolve_row(evidence.samples[0].ref)
    with pytest.raises(ValueError, match="REFERENCE_MISMATCH"):
        other.validate_evidence(evidence)
    metric = tools.call("peer_overview", {}).metrics[1]
    assert metric.value is None
    assert metric.observed_rows == 0
    assert metric.unavailable_rows == 51


@pytest.mark.parametrize(
    "field,value",
    [
        ("total_bytes", -1),
        ("packet_count", True),
        ("duration_seconds", -1),
        ("total_bytes", 2**53),
        ("source_ip", "10.0.0.1/32"),
        ("timestamp", "2026-01-01T00:00:00"),
        ("sensor_id", ""),
        ("protocol", "SQL"),
    ],
)
def test_invalid_source_scalars_are_not_facts(repo: Any, field: str, value: Any) -> None:
    repo.save_job(job([flow(**{field: value})]))
    with pytest.raises(ValueError, match="SOURCE_INVALID"):
        read(repo)


def test_time_scope_and_canonical_source_ip(repo: Any) -> None:
    repo.save_job(
        job([flow(destination_ip="2001:0DB8::1"), flow(timestamp="2026-01-01T00:00:01+00:00")])
    )
    tools = service(
        repo,
        target_ip="2001:db8::1",
        start_time="2026-01-01T00:00:00Z",
        end_time="2026-01-01T00:00:00Z",
    )
    assert tools.call("peer_overview", {}).counts.matched == 1


@pytest.mark.parametrize(
    "args",
    [{"limit": 51}, {"limit": True}, {"sql": "select 1"}, {"job_id": "foreign"}, [], {"limit": 0}],
)
def test_tool_args_closed(repo: Any, args: Any) -> None:
    repo.save_job(job())
    with pytest.raises(ValueError, match="INVALID_TOOL_ARGUMENTS"):
        service(repo, target_ip="10.0.0.1").call("peer_flow_samples", args)


def test_timeline_distributes_observations_not_aggregate_flush_beacons(repo: Any) -> None:
    from datetime import UTC, datetime, timedelta

    start = datetime(2026, 1, 1, tzinfo=UTC)
    rows = [
        flow(
            timestamp=(start + timedelta(seconds=i)).isoformat(),
            packet_count=10,
            duration_seconds=1,
        )
        for i in range(121)
    ]
    rows.append(flow(sensor_id="s2"))
    repo.save_job(job(rows))
    result = service(repo, target_ip="10.0.0.1").call("peer_timeline", {"limit": 120})
    assert len(result.timeline) <= 120
    assert sum(bucket.rows for bucket in result.timeline) + result.counts.omitted == 122
    assert sum(bucket.aggregate_rows for bucket in result.timeline) > 0
    assert "AGGREGATE_NOT_PACKET_TIMING" in result.limitations
    assert "TIMING_QUALITY_UNAVAILABLE" in result.limitations
    assert result.timeline[0].sensor_id == "s1"
    assert all(bucket.packet_interval_mean_seconds is None for bucket in result.timeline)


def test_actual_protocol_presence_and_mixed_control_policy(repo: Any) -> None:
    repo.save_job(
        job(
            [
                flow(protocol="TCP", tcp_flags={"syn": 1, "ack": 0}, payload_length=0),
                flow(domain="updates.example.test", tls_fingerprint="abc123", payload_length=0),
                flow(protocol="TCP", direction="INBOUND", tcp_flags={"ack": 1}, payload_length=12),
            ]
        )
    )
    tools = service(repo, target_ip="10.0.0.1")
    result = tools.call("peer_protocol_observations", {})
    assert len(result.protocols) == 3
    assert result.protocols[0].c2_eligibility == "SUPPRESSED_OUTBOUND_CONTROL"
    assert result.protocols[1].c2_eligibility == "ELIGIBLE"
    assert result.protocols[2].c2_eligibility == "ELIGIBLE"
    assert result.protocols[1].domain == "updates.example.test"
    assert result.protocols[1].tls_fingerprint == "abc123"
    assert result.protocols[0].domain is None
    assert result.counts.matched == 3
    repo.save_job(job([flow()]))
    result = service(repo, target_ip="10.0.0.1").call("peer_protocol_observations", {})
    assert result.status == "UNAVAILABLE"
    assert result.counts.unavailable == 1
    assert result.protocols == ()


def test_cohort_keeps_sensor_identity_and_is_not_normal_verdict(repo: Any) -> None:
    rows = [flow(source_ip=f"10.0.0.{i}", total_bytes=i) for i in range(1, 23)]
    rows.append(flow(sensor_id="s2", source_ip="10.0.0.2", total_bytes=999))
    repo.save_job(job(rows))
    result = service(repo, target_ip="10.0.0.1").call("compare_peer_cohort", {"limit": 20})
    assert len(result.cohort) == 20
    assert result.cohort_total == 22  # only target-observed sensor, exclude target IP
    assert result.cohort_omitted == 2
    assert all(peer.sensor_id == "s1" for peer in result.cohort)
    assert all(peer.ip != "10.0.0.1" for peer in result.cohort)
    assert all(peer.comparison == "SAME_SOURCE_PROTOCOL_OVERLAP" for peer in result.cohort)
    assert "SIMILARITY_IS_NOT_NORMALITY" in result.limitations
    assert result.cohort[0].total_bytes is not None
