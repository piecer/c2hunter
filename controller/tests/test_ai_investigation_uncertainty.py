"""Actual producer uncertainty survives downstream selection and comparisons."""

import pytest

from c2hunter_controller.ai_investigation_contract import (
    Counts,
    Evidence,
    InvestigationError,
    InvestigationScope,
    RowReference,
    canonical_bytes,
    digest,
)
from c2hunter_controller.ai_investigation_evidence import EvidenceService
from tests import test_ai_investigation_evidence as fixtures
from tests.test_ai_investigation_producers import pcap_row, producer_job, producer_row

repo = fixtures.repo
TOOLS = (
    "peer_overview",
    "peer_flow_samples",
    "peer_timeline",
    "peer_protocol_observations",
    "compare_peer_cohort",
)


def assert_counts(evidence):
    c = evidence.counts
    assert c.inspected == c.matched + c.not_observed + c.scope_unavailable
    assert c.matched == c.retained + c.omitted + c.unavailable


@pytest.mark.parametrize("mixed", [False, True])
@pytest.mark.parametrize("direction", ["BIDIRECTIONAL", "UNKNOWN"])
def test_direction_uncertainty_is_not_absence_or_exact_total(repo, mixed, direction):
    rows = [producer_row(direction=direction)]
    if mixed:
        rows.append(producer_row(direction="OUTBOUND", domain="known.example"))
    repo.save_job(producer_job(rows))
    snapshot = fixtures.read(repo)
    service = EvidenceService(
        snapshot, InvestigationScope(target_ip="10.0.0.1", traffic_direction="OUTBOUND")
    )
    for tool in TOOLS:
        evidence = service.call(tool, {})
        assert evidence.status == ("OBSERVED" if mixed else "UNAVAILABLE")
        assert evidence.counts.not_observed == 0
        assert evidence.counts.matched == int(mixed)
        assert evidence.counts.scope_unavailable == 1
        assert_counts(evidence)
        metrics = {m.name: m for m in evidence.metrics}
        for name in (
            "matched_rows",
            "total_bytes",
            "packet_count",
            "sensor_count",
            "outbound_rows",
            "outbound_bytes",
        ):
            metric = metrics[name]
            assert metric.value is None
            assert metric.observed_rows == int(mixed)
            assert metric.unavailable_rows == 1
        assert "SOURCE_FIELDS_UNAVAILABLE" in evidence.limitations
        assert all(s.ref.ordinal == 1 for s in evidence.samples)
        if tool == "peer_flow_samples":
            assert len(evidence.samples) == int(mixed)
        if tool == "compare_peer_cohort" and not mixed:
            assert not evidence.cohort and evidence.cohort_total == 0
            assert evidence.cohort_unavailable_rows == 1
    assert [r.row_sha256 for r in snapshot.rows] == [digest(r) for r in rows]


@pytest.mark.parametrize("outside", ["endpoint", "side", "sensor", "before", "after"])
def test_unknown_direction_outside_overall_scope_does_not_pollute(repo, outside):
    row = producer_row(direction="BIDIRECTIONAL", protocol="IP_50")
    scope = dict(target_ip="10.0.0.1", traffic_direction="OUTBOUND")
    if outside == "endpoint":
        scope["target_ip"] = "10.0.0.99"
    elif outside == "side":
        scope["endpoint_side"] = "destination"
    elif outside == "sensor":
        scope["sensor_id"] = "s2"
    elif outside == "before":
        scope["start_time"] = "2026-01-02T00:00:00Z"
    else:
        scope["end_time"] = "2025-12-31T00:00:00Z"
    repo.save_job(producer_job([row]))
    service = EvidenceService(fixtures.read(repo), InvestigationScope(**scope))
    for tool in TOOLS:
        evidence = service.call(tool, {})
        assert evidence.status == "NOT_OBSERVED"
        assert evidence.counts.scope_unavailable == 0 and evidence.counts.not_observed == 1
        assert evidence.cohort_unavailable_rows == 0
        assert all(m.value == 0 and m.unavailable_rows == 0 for m in evidence.metrics)
        assert "SOURCE_FIELDS_UNAVAILABLE" not in evidence.limitations
        assert_counts(evidence)


@pytest.mark.parametrize("direction", ["INBOUND", "OUTBOUND"])
def test_known_direction_positive_and_negative_controls(repo, direction):
    repo.save_job(producer_job([producer_row(direction=direction, domain="known.example")]))
    service = EvidenceService(
        fixtures.read(repo), InvestigationScope(target_ip="10.0.0.1", traffic_direction="OUTBOUND")
    )
    for tool in TOOLS:
        evidence = service.call(tool, {})
        assert evidence.status == ("OBSERVED" if direction == "OUTBOUND" else "NOT_OBSERVED")
        assert evidence.counts.scope_unavailable == 0
        assert_counts(evidence)
        metrics = {m.name: m for m in evidence.metrics}
        assert metrics["outbound_rows"].value == int(direction == "OUTBOUND")
        assert metrics["total_bytes"].value == (80 if direction == "OUTBOUND" else 0)
        assert all(m.unavailable_rows == 0 for m in evidence.metrics)


@pytest.mark.parametrize("direction", ["BIDIRECTIONAL", "UNKNOWN"])
def test_unfiltered_direction_buckets_retain_unknown_coverage(repo, direction):
    rows = [producer_row(direction=direction), producer_row(direction="OUTBOUND")]
    repo.save_job(producer_job(rows))
    service = EvidenceService(fixtures.read(repo), InvestigationScope(target_ip="10.0.0.1"))
    for tool in TOOLS:
        evidence = service.call(tool, {})
        metrics = {m.name: m for m in evidence.metrics}
        assert evidence.counts.matched == 2 and evidence.counts.scope_unavailable == 0
        assert metrics["matched_rows"].value == 2 and metrics["total_bytes"].value == 160
        assert metrics["unknown_rows"].value == 1  # observed projection category, not absence
        for name in ("outbound_rows", "outbound_bytes", "inbound_rows", "internal_rows"):
            assert metrics[name].value is None
            assert metrics[name].unavailable_rows == 1
        assert metrics["outbound_rows"].observed_rows == 1
        assert_counts(evidence)


@pytest.mark.parametrize("target_protocol", ["IP_47", "OTHER", "UDP"])
def test_cohort_excludes_unknown_actual_protocols(repo, target_protocol):
    target = (
        pcap_row(protocol=47, payload=b"\x00" * 8)
        if target_protocol == "IP_47"
        else producer_row(protocol=target_protocol)
    )
    peer = pcap_row(protocol=50, payload=b"\x00" * 8)
    peer.update(source_ip="10.0.0.2", destination_ip="203.0.113.2")
    rows = [target, peer]
    repo.save_job(producer_job(rows))
    snapshot = fixtures.read(repo)
    evidence = EvidenceService(snapshot, InvestigationScope(target_ip="10.0.0.1")).call(
        "compare_peer_cohort", {}
    )
    assert not any(p.ip == "10.0.0.2" for p in evidence.cohort)
    assert evidence.cohort_unavailable_rows == (1 if target_protocol == "UDP" else 2)
    assert evidence.cohort_total == len(evidence.cohort) + evidence.cohort_omitted
    assert "SOURCE_FIELDS_UNAVAILABLE" in evidence.limitations
    if target_protocol != "UDP":
        assert evidence.cohort_total == 0 and evidence.status == "UNAVAILABLE"
    assert [r.row_sha256 for r in snapshot.rows] == [digest(r) for r in rows]


@pytest.mark.parametrize("protocol", ["TCP", "UDP"])
def test_cohort_keeps_known_matches_with_uncertain_non_target_inputs(repo, protocol):
    rows = [
        producer_row(protocol=protocol),
        producer_row(protocol=protocol, source_ip="10.0.0.2", destination_ip="203.0.113.2"),
        producer_row(protocol="IP_50", source_ip="10.0.0.3", destination_ip="203.0.113.3"),
    ]
    repo.save_job(producer_job(rows))
    evidence = EvidenceService(fixtures.read(repo), InvestigationScope(target_ip="10.0.0.1")).call(
        "compare_peer_cohort", {}
    )
    assert evidence.status == "OBSERVED"
    assert {p.ip for p in evidence.cohort} == {"203.0.113.1", "10.0.0.2", "203.0.113.2"}
    assert all(p.comparison == "SAME_SOURCE_PROTOCOL_OVERLAP" for p in evidence.cohort)
    assert evidence.cohort_unavailable_rows == 1
    assert "SOURCE_FIELDS_UNAVAILABLE" in evidence.limitations


@pytest.mark.parametrize("outside", ["sensor", "before", "after", "direction", "protocol"])
def test_irrelevant_peer_uncertainty_does_not_qualify_known_cohort(repo, outside):
    scope = dict(
        target_ip="10.0.0.1",
        traffic_direction="OUTBOUND",
        start_time="2026-01-01T00:00:00Z",
        end_time="2026-01-01T00:00:00Z",
    )
    peer = producer_row(
        protocol="IP_50",
        direction="BIDIRECTIONAL",
        source_ip="10.0.0.2",
        destination_ip="203.0.113.2",
    )
    if outside == "sensor":
        peer["sensor_id"] = "s2"
    elif outside == "before":
        peer["timestamp"] = "2025-12-31T00:00:00Z"
    elif outside == "after":
        peer["timestamp"] = "2026-01-02T00:00:00Z"
    elif outside == "direction":
        peer["direction"] = "INBOUND"
    else:
        peer["protocol"] = "TCP"  # Unknown direction cannot make TCP equal UDP.
    repo.save_job(producer_job([producer_row(), peer]))
    evidence = EvidenceService(fixtures.read(repo), InvestigationScope(**scope)).call(
        "compare_peer_cohort", {}
    )
    assert evidence.cohort_total == 1 and evidence.cohort_unavailable_rows == 0
    assert evidence.cohort[0].ip == "203.0.113.1"
    assert evidence.counts.scope_unavailable == 0
    assert "SOURCE_FIELDS_UNAVAILABLE" not in evidence.limitations


@pytest.mark.parametrize("target_unknown", [False, True])
def test_cohort_direction_eligibility_never_becomes_observed_comparison(repo, target_unknown):
    target = producer_row(direction="BIDIRECTIONAL" if target_unknown else "OUTBOUND")
    peer = producer_row(
        source_ip="10.0.0.2",
        destination_ip="203.0.113.2",
        direction="OUTBOUND" if target_unknown else "BIDIRECTIONAL",
    )
    repo.save_job(producer_job([target, peer]))
    evidence = EvidenceService(
        fixtures.read(repo), InvestigationScope(target_ip="10.0.0.1", traffic_direction="OUTBOUND")
    ).call("compare_peer_cohort", {})
    assert not any(p.ip == "10.0.0.2" for p in evidence.cohort)
    assert evidence.cohort_unavailable_rows == (2 if target_unknown else 1)
    assert evidence.counts.scope_unavailable == int(target_unknown)
    assert evidence.status == ("UNAVAILABLE" if target_unknown else "OBSERVED")
    assert_counts(evidence)


@pytest.mark.parametrize("requested", ["INBOUND", "OUTBOUND", "INTERNAL", "UNKNOWN"])
def test_collapsed_direction_remains_uncertain_under_every_filter(repo, requested):
    repo.save_job(producer_job([producer_row(direction="BIDIRECTIONAL")]))
    snapshot = fixtures.read(repo)
    service = EvidenceService(
        snapshot, InvestigationScope(target_ip="10.0.0.1", traffic_direction=requested)
    )
    evidence = service.call("peer_overview", {})
    assert evidence.status == "UNAVAILABLE" and evidence.counts.scope_unavailable == 1
    assert next(m for m in evidence.metrics if m.name == requested.lower() + "_rows").value is None
    row = snapshot.rows[0]
    with pytest.raises(InvestigationError, match="REFERENCE_MISMATCH"):
        service.resolve_row(
            RowReference(
                source_sha256=snapshot.binding.source_sha256,
                ordinal=row.ordinal,
                row_sha256=row.row_sha256,
            )
        )
    assert (
        Evidence.model_validate_json(canonical_bytes(evidence.model_dump(mode="json"))) == evidence
    )
    assert service.validate_evidence(evidence) == evidence


@pytest.mark.parametrize("bad", [-1, 8193, True, "1", 0.5, None])
def test_uncertainty_fields_are_strict_and_bounded(bad):
    counts = dict(inspected=0, matched=0, retained=0, omitted=0, not_observed=0)
    with pytest.raises(ValueError):
        Counts(**counts, scope_unavailable=bad)
    assert Counts(**counts).scope_unavailable == 0
    schema = Evidence.model_json_schema()
    field = schema["properties"]["cohort_unavailable_rows"]
    assert (field["type"], field["minimum"], field["maximum"], field["default"]) == (
        "integer",
        0,
        8192,
        0,
    )
    # Use a producer-created instance, never an invented evidence envelope.
    from c2hunter_controller.repositories import MemoryRepository

    repo = MemoryRepository()
    repo.save_job(producer_job([producer_row()]))
    evidence = EvidenceService(fixtures.read(repo), InvestigationScope(target_ip="10.0.0.1")).call(
        "peer_overview", {}
    )
    with pytest.raises(ValueError):
        Evidence.model_validate(evidence.model_copy(update={"cohort_unavailable_rows": bad}))
    with pytest.raises(ValueError):
        Evidence.model_validate(
            evidence.model_copy(
                update={"counts": evidence.counts.model_copy(update={"scope_unavailable": bad})}
            )
        )
    assert schema["additionalProperties"] is False
    assert schema["$defs"]["Counts"]["additionalProperties"] is False


def test_metric_unknown_selection_and_missing_measurement_are_separate(repo):
    rows = [
        producer_row(direction="BIDIRECTIONAL"),
        producer_row(total_bytes=0),
        producer_row(),
        producer_row(),
    ]
    rows[2].pop("total_bytes")
    repo.save_job(producer_job(rows))
    service = EvidenceService(
        fixtures.read(repo), InvestigationScope(target_ip="10.0.0.1", traffic_direction="OUTBOUND")
    )
    evidence = service.call("peer_flow_samples", {"limit": 1})
    assert_counts(evidence)
    assert (
        evidence.counts.matched,
        evidence.counts.retained,
        evidence.counts.omitted,
        evidence.counts.scope_unavailable,
    ) == (3, 1, 2, 1)
    metric = next(m for m in evidence.metrics if m.name == "total_bytes")
    assert (metric.value, metric.observed_rows, metric.unavailable_rows) == (None, 2, 2)
    assert evidence.samples[0].row.total_bytes == 0
