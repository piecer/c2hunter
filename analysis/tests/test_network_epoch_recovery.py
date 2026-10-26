"""Bounded production epochs; the separate legacy detector is not patched."""

from datetime import timedelta

import pytest
from test_network_anomaly import frame, records

from c2hunter_analysis import network_report as nr


def at(record, seconds, **changes):
    return {**record, "timestamp": record["timestamp"] + timedelta(seconds=seconds), **changes}


def saturated(*, popped=False, reverse=False, known=True, count=4097):
    syn, data = records(
        frame(seq=100, reverse=reverse),
        frame(flags=24, seq=101, payload=b"x", reverse=reverse),
    )
    data["timestamp"] = syn["timestamp"]
    items = [syn] if known else []
    if popped:
        response = records(frame(flags=18, seq=500, ack=101, reverse=not reverse))[0]
        items.append(at(response, 0.0001))
    items.extend(at(data, (i + 1) / 1000, tcp_sequence=101 + i) for i in range(count))
    return syn, data, items


def patterns(report):
    return {i["pattern"]: i["event_count"] for i in report["issues"]}


def sticky(report, limited):
    summary = report["summary"]
    assert summary["tracking_limited_records"] == limited
    assert summary["incomplete_records"] >= limited
    assert summary["counts_are_lower_bounds"] is True
    assert summary["truncated"] is True
    assert summary["coverage_complete"] is False
    assert "CORRELATION_LIMIT_REACHED" in report["warnings"]
    assert summary["scanned_records"] == sum(
        summary[k] for k in ("evaluated_records", "incomplete_records", "skipped_records")
    )


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("popped", [False, True])
def test_changed_trusted_syn_recovers_at_actual_production_cap(reverse, popped):
    assert (nr.MAX_FLOW_CORRELATIONS, nr.MAX_TOTAL_CORRELATIONS, nr.MAX_TRACKED_FLOWS) == (
        4096,
        131072,
        8192,
    )
    syn, _, items = saturated(popped=popped, reverse=reverse)
    report = nr.analyze_network_report(
        items + [at(syn, 5, tcp_sequence=900000), at(syn, 6, tcp_sequence=900000)]
    )
    assert patterns(report) == {"syn_retransmissions": 1}
    sticky(report, 1)
    assert report["summary"]["evaluated_records"] == len(items) + 1
    measurement = report["issues"][0]["examples"][0]["measurements"]
    assert "CORRELATION_LIMIT_REACHED" in measurement["reasons"]
    assert measurement["rtt_sources"]["syn_ack"] == int(popped)


@pytest.mark.parametrize("protocol", [6, 17])
def test_idle_is_strict_and_first_old_payload_is_not_a_repeat(monkeypatch, protocol):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    packet = records(frame(protocol=protocol, flags=24, payload=b"x"))[0]
    items = [at(packet, i, payload_hash=str(i)) for i in range(3)]
    # Exactly60s since the last observed record cannot recover, and advances time.
    boundary = nr.analyze_network_report(items + [at(packet, 62, payload_hash="0")])
    sticky(boundary, 2)
    assert patterns(boundary) == {}
    items += [at(packet, 62, payload_hash="0"), at(packet, 122.001, payload_hash="0")]
    first = nr.analyze_network_report(items)
    assert first["summary"]["evaluated_records"] == 3
    assert patterns(first) == {}
    report = nr.analyze_network_report(items + [at(packet, 123, payload_hash="0")])
    pattern = "data_retransmissions" if protocol == 6 else "udp_duplicate_candidates"
    assert patterns(report) == {pattern: 1}
    sticky(report, 2)
    measurement = report["issues"][0]["examples"][0]["measurements"]
    assert measurement["observed_rtt_ms"]["count"] == 0
    assert measurement["interarrival_variation_ms"]["a_to_b"]["max"] <= 1000


@pytest.mark.parametrize("flags", [2, 16, 18, 4, 1, 32, 3, 34, 6])
def test_same_syn_and_controls_do_not_recover_but_idle_can(monkeypatch, flags):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, _, items = saturated(count=3)
    control = records(frame(flags=flags, seq=100 if flags == 2 else 900000))[0]
    report = nr.analyze_network_report(items + [at(control, 5), at(control, 6)])
    assert patterns(report) == {}
    sticky(report, 3)
    # A complete control may meet independent idle; it is not changed-SYN proof.
    report = nr.analyze_network_report(items + [at(control, 61)])
    sticky(report, 1)
    assert report["summary"]["evaluated_records"] == len(items)


@pytest.mark.parametrize("kind", ["incomplete", "ack", "same_syn", "data"])
def test_every_suppressed_observation_advances_idle_watermark(monkeypatch, kind):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, data, items = saturated(count=3)
    control = records(frame(flags=16))[0]
    packet = {
        "incomplete": {**data, "packet_evidence_complete": False},
        "ack": control,
        "same_syn": syn,
        "data": data,
    }[kind]
    items += [at(packet, i) for i in (30, 60, 90, 120)]
    # No new epoch proof: only30s since the observed row, not150s since evaluation.
    report = nr.analyze_network_report(items + [at(syn, 150), at(syn, 151)])
    assert patterns(report) == {}
    sticky(report, 7)
    # Incomplete at >60 does not itself recover and restarts the idle clock.
    items += [at(data, 181, packet_evidence_complete=False), at(syn, 241)]
    report = nr.analyze_network_report(items)
    assert patterns(report) == {}
    sticky(report, 7)
    report = nr.analyze_network_report(items + [at(syn, 301.001), at(syn, 302)])
    assert patterns(report) == {"syn_retransmissions": 1}
    sticky(report, 7)


@pytest.mark.parametrize(
    "invalid",
    [
        {"packet_evidence_complete": False},
        {"tcp_sequence": -1},
        {"tcp_sequence": 2**32},
        {"tcp_sequence": True},
        {"packet_count": 2},
        {"timestamp": "not-a-time"},
        {"source_ip": "not-an-ip"},
    ],
)
def test_invalid_changed_syn_never_recovers(monkeypatch, invalid):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, _, items = saturated(count=3)
    report = nr.analyze_network_report(
        items + [{**at(syn, 70, tcp_sequence=900000), **invalid}, at(syn, 71), at(syn, 72)]
    )
    # Invalid identity/time is not an observation. Valid complete later rows can
    # independently recover by idle; invalid packet evidence advances time instead.
    invalid_identity = "timestamp" in invalid or "source_ip" in invalid
    assert patterns(report) == ({"syn_retransmissions": 1} if invalid_identity else {})
    sticky(report, 1 if invalid_identity else 4)


@pytest.mark.parametrize("reverse_unknown", [False, True])
def test_unknown_direction_anchor_is_not_learned_while_limited(monkeypatch, reverse_unknown):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, _, items = saturated(count=3, known=reverse_unknown)
    if reverse_unknown:
        syn = records(frame(seq=100, reverse=True))[0]
    tail = [at(syn, 5, tcp_sequence=900000), at(syn, 6, tcp_sequence=800000)]
    report = nr.analyze_network_report(items + tail)
    assert patterns(report) == {}
    sticky(report, 3)
    report = nr.analyze_network_report(items + tail + [at(syn, 67), at(syn, 68)])
    assert patterns(report) == {"syn_retransmissions": 1}
    sticky(report, 3)


@pytest.mark.parametrize("incomplete", [False, True])
def test_suppressed_time_regression_poison_is_sticky(monkeypatch, incomplete):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, data, items = saturated(count=3)
    items += [at(data, 50), at(data, 40, packet_evidence_complete=not incomplete)]
    report = nr.analyze_network_report(items + [at(syn, 120, tcp_sequence=900000)] * 2)
    assert patterns(report) == {}
    sticky(report, 5)
    assert "NON_MONOTONIC_TIMESTAMPS" in report["warnings"]


def test_previous_observation_and_gap_survive_recovery(monkeypatch):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, data, items = saturated(count=3)
    items.insert(1, syn)
    items += [
        at(data, 5, packet_evidence_complete=False),
        at(syn, 6, tcp_sequence=900000),
        at(syn, 7, tcp_sequence=900000),
    ]
    report = nr.analyze_network_report(items)
    assert patterns(report) == {"syn_retransmissions": 2}
    sticky(report, 2)
    measurement = report["issues"][0]["examples"][0]["measurements"]
    assert {"CORRELATION_LIMIT_REACHED", "INCOMPLETE_PACKET_EVIDENCE"} <= set(
        measurement["reasons"]
    )
    assert measurement["observed_rtt_ms"]["count"] == 0


def test_credit_conservation_at_every_processing_boundary(monkeypatch):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    monkeypatch.setattr(nr, "MAX_TOTAL_CORRELATIONS", 3)
    captured = []
    failures = []
    original = nr.Flow

    class AuditedFlow(original):
        def __init__(self, budget):
            super().__init__(budget)
            captured.append(self)

        def reserve(self):
            before = self.budget.correlations
            try:
                super().reserve()
            except nr.TrackingLimit:
                assert self.budget.correlations == before
                failures.append(before)
                raise

    monkeypatch.setattr(nr, "Flow", AuditedFlow)
    syn, data, _ = saturated(count=3)
    udp = records(frame(protocol=17, payload=b"u"))[0]
    other = {**data, "source_port": 50001}
    items = [
        syn,
        udp,
        {**udp, "payload_hash": "v"},
        other,
        data,
        at(syn, 1, tcp_sequence=200),
        at(data, 2),
        at(udp, 3, packet_evidence_complete=False),
        at(syn, 4, tcp_sequence=300),
    ]
    # Global full: fixed-state SYN may recover, but allocating data relimits.
    # Clearing a different flow releases only that flow's exact live credits.
    for epoch in range(5):
        start = 5 + epoch * 5
        items += [
            at(data, start, payload_hash="a"),
            at(data, start + 1, payload_hash="b"),
            at(data, start + 2, payload_hash="c"),
            at(syn, start + 3, tcp_sequence=400 + epoch),
            at(syn, start + 4, tcp_sequence=400 + epoch),
        ]

    snapshots = []

    def check():
        if not captured:
            return
        actual = sum(len(f.udp) + sum(len(d.seen) for d in f.tcp) for f in captured)
        assert captured[0].budget.correlations == actual
        assert 0 <= actual <= 3
        assert all(len(f.udp) + sum(len(d.seen) for d in f.tcp) <= 2 for f in captured)
        snapshots.append(actual)

    def stream():
        for item in items:
            check()
            yield item
        check()

    report = nr.analyze_network_report(stream())
    assert patterns(report) == {"syn_retransmissions": 5}
    assert len(failures) == 7
    assert snapshots[:9] == [0, 1, 2, 3, 3, 3, 3, 1, 1]
    sticky(report, 7)
    for flow in captured:
        flow.clear_correlations()
        check()
        flow.clear_correlations()
        check()
    assert captured[0].budget.correlations == 0


def test_closed_normal_epoch_cannot_supply_stale_anchor(monkeypatch):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, _, items = saturated(count=3)
    rst = records(frame(flags=4))[0]
    items.insert(1, rst)
    report = nr.analyze_network_report(items + [at(syn, 5, tcp_sequence=900000)] * 2)
    assert patterns(report) == {}
    sticky(report, 3)


@pytest.mark.parametrize("known", [False, True])
def test_idle_recovers_at_actual_production_cap_without_cross_gap_rtt(known):
    syn, _, items = saturated(known=known)
    report = nr.analyze_network_report(items + [at(syn, 70), at(syn, 71)])
    assert patterns(report) == {"syn_retransmissions": 1}
    sticky(report, 1)
    measurements = report["issues"][0]["examples"][0]["measurements"]
    assert measurements["observed_rtt_ms"]["count"] == 0
    assert measurements["interarrival_variation_ms"]["a_to_b"]["max"] == 1000


def test_completed_fin_epoch_does_not_retain_recovery_anchor(monkeypatch):
    monkeypatch.setattr(nr, "MAX_FLOW_CORRELATIONS", 2)
    syn, _, data = saturated(count=3)
    closing = records(
        frame(flags=17, seq=101, ack=500),
        frame(flags=17, seq=500, ack=102, reverse=True),
        frame(flags=16, seq=102, ack=501),
    )
    items = [syn] + [at(row, i + 1) for i, row in enumerate(closing)]
    items += [at(row, 5) for row in data[1:]]
    report = nr.analyze_network_report(items + [at(syn, 10, tcp_sequence=900000)] * 2)
    assert patterns(report) == {}
    sticky(report, 3)
