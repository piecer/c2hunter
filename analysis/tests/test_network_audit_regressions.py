"""Targeted audit regressions using the existing genuine packet encoder/parser."""

from datetime import timedelta

import pytest
from test_network_anomaly import frame, records

from c2hunter_analysis.network_anomaly import analyze_network_anomalies
from c2hunter_analysis.network_report import analyze_network_report


def test_legacy_udp_incomplete_evidence_breaks_duplicate_correlation():
    packet, gap, later = records(*(frame(protocol=17, payload=b"query") for _ in range(3)))
    gap = {**gap, "packet_evidence_complete": False}
    result = analyze_network_anomalies([packet, gap, later])
    flow = result["flows"][0]
    assert "INCOMPLETE_PACKET_EVIDENCE" in flow["warnings"]
    assert flow["observed_directions"]["a_to_b"]["packets"] == 3
    assert flow["metrics"]["udp_duplicate_candidates"] == 0


@pytest.mark.parametrize(
    ("flags", "payload", "window"),
    [(16, b"x", 8192), (17, b"", 8192), (48, b"", 8192), (16, b"", 0)],
    ids=["payload", "fin", "urg", "zero-window"],
)
def test_report_excludes_non_duplicate_ack_signatures(flags, payload, window):
    data = frame(flags=24, seq=101, payload=b"abc")
    ack = frame(flags=flags, seq=500, ack=101, reverse=True, payload=payload, window=window)
    result = analyze_network_report(records(data, ack, ack))
    assert all(issue["pattern"] != "duplicate_acks" for issue in result["issues"])
    assert result["summary"]["evaluated_records"] == 3
    assert result["summary"]["incomplete_records"] == 0


@pytest.mark.parametrize("protocol", [6, 17], ids=["tcp", "udp"])
@pytest.mark.parametrize("gap", [60, 60.000001], ids=["at-idle-boundary", "past-idle-boundary"])
def test_report_idle_epoch_boundary(protocol, gap):
    packet = records(frame(protocol=protocol, flags=24, payload=b"query"))[0]
    later = {**packet, "timestamp": packet["timestamp"] + timedelta(seconds=gap)}
    result = analyze_network_report([packet, later])
    pattern = "data_retransmissions" if protocol == 6 else "udp_duplicate_candidates"
    assert [(issue["pattern"], issue["event_count"]) for issue in result["issues"]] == (
        [(pattern, 1)] if gap == 60 else []
    )
    assert result["summary"]["evaluated_records"] == 2
    assert result["summary"]["tracking_limited_records"] == 0


def test_report_reverse_sender_scopes_data_repeat_to_receiver_and_ack_to_sender():
    data = frame(flags=24, seq=500, payload=b"abc", reverse=True)
    ack = frame(flags=16, seq=101, ack=500)
    result = analyze_network_report(records(data, data, ack, ack))
    issues = {issue["pattern"]: issue for issue in result["issues"]}
    assert set(issues) == {"data_retransmissions", "duplicate_acks"}
    for issue in issues.values():
        assert issue["scope"]["peer"] == {"ip": "10.0.0.1", "port": 50000}
        assert issue["event_count"] == 1
        assert issue["affected_host_count"] == 2
    assert result["summary"]["suspect_flow_count"] == 1
    assert result["summary"]["detailed_flow_count"] == 1


def test_report_unknown_protocol_is_not_normal_even_with_bidirectional_visibility():
    packets = records(frame(flags=16), frame(flags=16, reverse=True))
    result = analyze_network_report([{**packet, "protocol": "GRE"} for packet in packets])
    assert result["issues"] == []
    assert result["summary"]["verdict"] == "insufficient_evidence"
    assert result["summary"]["incomplete_records"] == 2
    assert result["summary"]["evaluated_records"] == 0
    assert "INCOMPLETE_PACKET_EVIDENCE" in result["warnings"]
    assert "ONE_DIRECTION_OBSERVED" not in result["warnings"]
