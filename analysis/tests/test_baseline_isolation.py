"""Exact-key and family-precedence closure cases for the review matrix."""

from dataclasses import replace
from datetime import timedelta

import pytest
from test_baseline_adversarial import T0, S, compare, history, req

from c2hunter_analysis import behavior_baseline as b


@pytest.mark.parametrize("dimension", ["peer", "port", "protocol", "host", "representation"])
def test_exact_key_never_falls_back_across_dimensions(dimension):
    r = req(T0 + timedelta(days=2), size_change=True, direction_change=True)
    h = history()
    if dimension == "peer":
        r = replace(r, flows=tuple(replace(f, destination_ip="203.0.113.10") for f in r.flows))
    if dimension == "port":
        r = replace(r, flows=tuple(replace(f, destination_port=8443) for f in r.flows))
    if dimension == "protocol":
        r = replace(r, flows=tuple(replace(f, protocol="UDP") for f in r.flows))
    if dimension == "host":
        scope = replace(S, hosts=(*S.hosts, b.HostEpoch("192.168.1.11", "lease-B")))
        r = replace(
            r, scope=scope, flows=tuple(replace(f, source_ip="192.168.1.11") for f in r.flows)
        )
    if dimension == "representation":
        r = replace(r, flows=(replace(r.flows[0], packet_count=2), *r.flows[1:]))
    result = compare(r, h)
    row = result.comparisons[0]
    assert row.status == "MISSING" and not result.candidates and row.historical_anomaly_score == 0
    assert all(getattr(row, n).status == "MISSING" for n in b.FEATURES)
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result


@pytest.mark.parametrize("sample_count", [1, 7, 8])
def test_sparse_current_overrides_missing_and_preserves_nulls(sample_count):
    r = req(T0 + timedelta(days=2))
    r = replace(r, flows=r.flows[:sample_count])
    result = compare(r, None)
    row = result.comparisons[0]
    assert row.status == ("INCOMPATIBLE" if sample_count < 8 else "MISSING")
    assert not result.candidates and row.source_window_ids == ()
    if sample_count < 8:
        assert all(getattr(row, n).current is None for n in b.FEATURES)
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result


@pytest.mark.parametrize("null_families", [("recurrence",), ("recurrence", "outbound_share")])
def test_feature_local_nulls_preserve_available_family_precedence(null_families):
    h = history()
    r = req(T0 + timedelta(days=2))
    r = replace(
        r,
        flows=tuple(
            replace(f, timestamp=r.event_start, bidirectional="outbound_share" in null_families)
            for f in r.flows
        ),
    )
    result = compare(r, h)
    row = result.comparisons[0]
    assert row.status == ("READY" if len(null_families) == 1 else "INSUFFICIENT")
    for name in b.FEATURES:
        assert getattr(row, name).status == ("INCOMPATIBLE" if name in null_families else "READY")
    assert not result.candidates
    assert b.baseline_comparison_from_mapping(b.baseline_comparison_to_mapping(result)) == result
