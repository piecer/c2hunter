from test_network_anomaly import frame, records


def report(items, **kwargs):
    from c2hunter_analysis import network_report

    return network_report.analyze_network_report(items, **kwargs)


def test_flow_budget_counts_every_record_and_never_claims_normal(monkeypatch):
    from c2hunter_analysis import network_report

    monkeypatch.setattr(network_report, "MAX_TRACKED_FLOWS", 2, raising=False)
    packet = records(frame(flags=16))[0]
    result = report({**packet, "source_port": 10000 + i} for i in range(100))
    summary = result["summary"]
    assert summary["flow_count"] == 2
    assert summary["scanned_records"] == 100
    assert summary["evaluated_records"] == 2
    assert summary["incomplete_records"] == summary["tracking_limited_records"] == 98
    assert summary["counts_are_lower_bounds"] is True
    assert summary["coverage_complete"] is False
    assert summary["truncated"] is True
    assert summary["verdict"] == "insufficient_evidence"
    assert "FLOW_TRACKING_LIMIT_REACHED" in result["warnings"]


def test_correlation_budgets_preserve_observations_and_exact_coverage(monkeypatch):
    from c2hunter_analysis import network_report

    for name, limit in (("MAX_FLOW_CORRELATIONS", 2), ("MAX_TOTAL_CORRELATIONS", 2)):
        with monkeypatch.context() as patch:
            patch.setattr(network_report, name, limit, raising=False)
            for protocol in (6, 17):
                packet = records(frame(protocol=protocol, flags=24, payload=b"x"))[0]
                items = [packet, packet]
                items.extend({**packet, "payload_hash": str(i)} for i in range(10))
                result = report(items)
                summary = result["summary"]
                assert summary["tracking_limited_records"] == 9
                assert summary["evaluated_records"] == 3
                assert summary["incomplete_records"] == 9
                assert summary["verdict"] == "anomaly_observed"
                assert result["issues"][0]["event_count"] == 1
                assert "CORRELATION_LIMIT_REACHED" in result["warnings"]


def test_pending_quote_and_observation_budgets_are_explicit(monkeypatch):
    from c2hunter_analysis import network_report

    udp = frame(protocol=17, payload=b"query")
    packet = records(frame(protocol=1, reverse=True, payload=udp[14:42]))[0]
    items = [
        {**packet, "icmp_quoted_flow": {**packet["icmp_quoted_flow"], "destination_port": i}}
        for i in range(20)
    ]
    for name, warning in (
        ("MAX_PENDING_QUOTES", "ICMP_QUOTE_LIMIT_REACHED"),
        ("MAX_FLOW_OBSERVATIONS", "OBSERVATION_LIMIT_REACHED"),
    ):
        with monkeypatch.context() as patch:
            patch.setattr(network_report, name, 2, raising=False)
            result = report(items)
            summary = result["summary"]
            assert summary["evaluated_records"] == 2
            assert summary["tracking_limited_records"] == summary["incomplete_records"] == 18
            assert summary["issue_count"] == 2
            assert warning in result["warnings"]
            assert summary["counts_are_lower_bounds"] is True


def test_hostile_optional_values_cannot_expand_or_break_publication():
    import json
    from datetime import UTC, datetime

    packet = records(frame())[0]
    huge = 10**10000
    result = report([{**packet, "icmp_code": huge, "icmp_type": huge}] * 2)
    assert result["issues"][0]["examples"][0]["facts"].get("icmp_code") is None
    assert len(json.dumps(result, allow_nan=False)) < 10000
    for change in (
        {"payload_hash": "x" * 1000000},
        {"timestamp": "2026-01-01T00:00:00" + "0" * 1000000},
        {"timestamp": datetime.max.replace(tzinfo=UTC)},
    ):
        result = report([{**packet, **change}] * 2)
        assert result["summary"]["verdict"] == "insufficient_evidence"
        assert result["issues"] == []
    udp = frame(protocol=17, payload=b"query")
    error = records(frame(protocol=1, reverse=True, payload=udp[14:42]))[0]
    quote = {**error["icmp_quoted_flow"], "protocol": "x" * 1000000}
    result = report([{**error, "icmp_quoted_flow": quote}])
    assert "INCOMPLETE_ICMP_QUOTE" in result["warnings"]
    assert len(json.dumps(result)) < 10000


def test_actual_high_cardinality_hosts_and_maximum_publication_stay_bounded():
    import json

    from c2hunter_analysis import network_report

    packet = records(frame())[0]

    def many_hosts():
        for i in range(network_report.MAX_TRACKED_FLOWS + 1000):
            item = {**packet, "source_ip": f"2001:db8::{i:x}"}
            yield item
            yield item

    result = report(many_hosts())
    summary = result["summary"]
    assert summary["flow_count"] == network_report.MAX_TRACKED_FLOWS
    assert summary["tracking_limited_records"] == 2000
    assert result["issues"][0]["affected_host_count"] == network_report.MAX_TRACKED_FLOWS + 1
    assert summary["scanned_records"] == sum(
        summary[k] for k in ("evaluated_records", "incomplete_records", "skipped_records")
    )
    assert len(json.dumps(result, allow_nan=False).encode()) < 10000

    def maximum_details():
        for group in range(100):
            for example in range(11):
                item = {
                    **packet,
                    "sensor_id": chr(0x10000 + group) * 256,
                    "source_ip": "abcd:abcd:abcd:abcd:abcd:abcd:abcd:abcd",
                    "destination_ip": "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                    "source_port": example,
                }
                yield item
                yield item

    result = report(maximum_details(), max_issues=100, max_examples=10)
    assert result["summary"]["issue_count"] == 100
    assert sum(len(issue["examples"]) for issue in result["issues"]) == 1000
    assert len(json.dumps(result, allow_nan=False).encode()) < 4 * 1024 * 1024


def test_global_correlation_budget_spans_flows_and_releases_state(monkeypatch):
    from c2hunter_analysis import network_report

    monkeypatch.setattr(network_report, "MAX_TOTAL_CORRELATIONS", 2)
    packet = records(frame(flags=24, payload=b"x"))[0]
    other = {**packet, "source_port": 50001}
    third = {**packet, "source_port": 50002}
    limited = report([packet, other, third])
    assert limited["summary"]["tracking_limited_records"] == 1
    invalid = {**packet, "packet_evidence_complete": False}
    released = report([packet, other, invalid, third, third])
    assert released["summary"]["tracking_limited_records"] == 0
    assert released["issues"][0]["event_count"] == 1


def test_normal_handshake_has_no_issues():
    result = report(records(frame(), frame(flags=18, seq=500, ack=101, reverse=True)))
    assert result["summary"]["verdict"] == "no_clear_anomaly"
    assert result["issues"] == []
    assert result["summary"]["detailed_flow_count"] == 0
    assert result["summary"]["evaluated_records"] == 2


def test_same_pattern_merges_all_flows_before_bounded_details():
    base = records(frame(), frame(), frame(flags=20, ack=101, reverse=True))
    items = []
    for port in range(50000, 51100):
        for record in base:
            field = "source_port" if record["source_ip"] == "10.0.0.1" else "destination_port"
            items.append({**record, field: port})
    result = report(iter(items), max_issues=1, max_examples=2)
    summary = result["summary"]
    assert summary["verdict"] == "anomaly_observed"
    assert summary["flow_count"] == summary["suspect_flow_count"] == 1100
    assert summary["scanned_records"] == summary["evaluated_records"] == 3300
    assert summary["issue_count"] == 2
    assert summary["omitted_issue_count"] == 1
    assert summary["detailed_flow_count"] == 2
    issue = result["issues"][0]
    assert issue["event_count"] == issue["affected_flow_count"] == 1100
    assert issue["affected_host_count"] == 2
    assert len(issue["examples"]) == 2
    assert issue["omitted_examples"] == 1098
    assert issue["scope"]["peer"] == {"ip": "203.0.113.1", "port": 443}


def test_transport_candidates_preserve_strict_evidence():
    data = frame(flags=24, seq=101, payload=b"abc")
    ack = frame(flags=16, seq=500, ack=101, reverse=True)
    result = report(records(data, data, ack, ack))
    counts = {i["pattern"]: i["event_count"] for i in result["issues"]}
    assert counts == {"data_retransmissions": 1, "duplicate_acks": 1}
    assert report(records(ack, ack))["issues"] == []
    assert report(records(data, frame(flags=24, seq=101, payload=b"xyz")))["issues"] == []
    udp = frame(protocol=17, payload=b"query")
    assert report(records(udp, udp))["issues"][0]["pattern"] == "udp_duplicate_candidates"
    error = frame(protocol=1, reverse=True, payload=udp[14:42])
    icmp = report(records(udp, error))
    assert [(i["pattern"], i["event_count"]) for i in icmp["issues"]] == [("icmp_errors", 1)]
    assert icmp["issues"][0]["scope"]["peer"] == {"ip": "203.0.113.1", "port": 443}


def test_incomplete_evidence_never_becomes_normal_or_false_repeat():
    from datetime import timedelta

    packet = records(frame(flags=24, seq=101, payload=b"abc"))[0]
    for invalid in (
        {"packet_evidence_complete": False},
        {"tcp_window": None},
        {"tcp_sequence": -1},
        {"packet_count": 10},
        {"payload_hash": None},
    ):
        result = report([{**packet, **invalid}] * 2 + [{}])
        assert result["summary"]["verdict"] == "insufficient_evidence"
        assert result["summary"]["incomplete_records"] == 2
        assert result["summary"]["skipped_records"] == 1
        assert result["summary"]["evaluated_records"] == 0
        assert result["summary"]["scanned_records"] == 3
        assert result["issues"] == []
    assert report([])["summary"]["verdict"] == "insufficient_evidence"
    later = {**packet, "timestamp": packet["timestamp"] + timedelta(seconds=61)}
    assert report([packet, later])["issues"] == []
    assert report([later, packet])["summary"]["verdict"] == "insufficient_evidence"
    assert report([later, packet])["issues"] == []
    mixed = report([packet, packet, {**packet, "packet_evidence_complete": False}])
    assert mixed["summary"]["verdict"] == "anomaly_observed"
    assert mixed["summary"]["coverage_complete"] is False
    assert mixed["issues"][0]["event_count"] == 1


def test_all_records_beyond_legacy_caps_and_bounded_wire():
    import json

    ack = records(frame(flags=16, seq=500, ack=101, reverse=True))[0]
    syn = records(frame())[0]
    result = report(iter([ack] * 100001 + [syn, syn]))
    assert result["summary"]["scanned_records"] == 100003
    assert result["issues"][0]["event_count"] == 1
    data = records(*(frame(flags=24, seq=i * 10, payload=b"x") for i in range(300)))
    late = {**data[-1], "tcp_sequence": 0}
    result = report([*data, late])
    assert result["issues"][0]["event_count"] == 1
    assert result["summary"]["evaluated_records"] == 301
    assert "FLOW_STATE_LIMIT_REACHED" not in result["warnings"]
    assert len(json.dumps(result, allow_nan=False)) < 10000


def test_vantage_scope_and_specific_diagnostic_details():
    items = records(frame(), frame())
    result = report([*items, *({**r, "capture_interface_id": 1} for r in items)])
    assert result["summary"]["issue_count"] == 2
    for issue in result["issues"]:
        assert "sequence" in " ".join(issue["evidence"]).lower()
        assert "handshake" in " ".join(issue["next_checks"]).lower()
        assert issue["severity"] == "observation"
        assert issue["examples"][0]["facts"]["tcp_sequence"] == 100


def test_wire_limits_validation_and_untrusted_identifiers():
    import json

    import pytest

    for kwargs in ({"max_issues": 0}, {"max_issues": True}, {"max_examples": 11}):
        with pytest.raises(ValueError):
            report([], **kwargs)
    packet = records(frame())[0]
    malformed = {**packet, "source_ip": "fe80::1%" + "x" * 1000000}
    result = report([malformed, malformed])
    assert result["summary"]["skipped_records"] == 2
    assert len(json.dumps(result)) < 10000


def test_icmp_quote_scope_is_independent_of_input_flow_arrival():
    udp = frame(protocol=17, payload=b"query")
    error = frame(protocol=1, reverse=True, payload=udp[14:42])
    parsed = records(udp, error)
    early = report([parsed[1], parsed[0]])
    late = report(parsed)
    assert early["issues"] == late["issues"]
    assert early["issues"][0]["examples"][0]["facts"]["icmp_type"] == 3
    bad = {**parsed[1], "icmp_type": 10**10000}
    assert report([bad])["summary"]["verdict"] == "insufficient_evidence"
