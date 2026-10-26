"""Family selection uses real PCAP/parser/schema evidence, not injected groups."""

import importlib.util
import json
from collections import Counter
from pathlib import Path

import pytest

from c2hunter_analysis.network_report import analyze_network_report

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "family_fixture", ROOT / "web/tests/network_family_fixture.py"
)
assert spec and spec.loader
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


def test_dominant_family_preserves_reset_and_exact_coverage():
    report = analyze_network_report(fixture.records(fixture.capture()))
    assert Counter(i["pattern"] for i in report["issues"]) == {
        "udp_duplicate_candidates": 19,
        "matched_resets": 1,
    }
    assert report["family_coverage"] == {
        "version": "network-family-coverage-v1",
        "selection_policy": "family-first-v1",
        "families": [
            {
                "pattern": "matched_resets",
                "observed_groups": 1,
                "retained_groups": 1,
                "omitted_groups": 0,
            },
            {
                "pattern": "udp_duplicate_candidates",
                "observed_groups": 20,
                "retained_groups": 19,
                "omitted_groups": 1,
            },
        ],
    }
    assert report["summary"]["issue_count"] == 21
    assert report["summary"]["omitted_issue_count"] == 1
    assert report["summary"]["detailed_flow_count"] == 20
    assert report["issues"][-1]["id"] == "pattern-20"
    assert report["issues"][-1]["event_count"] == 1


def identity(issue):
    scope = issue["scope"]
    return (
        scope["sensor_id"],
        scope["interface_id"],
        scope["protocol"],
        issue["pattern"],
        (scope["peer"]["ip"], scope["peer"]["port"]),
    )


def assert_counts(report):
    families = report["family_coverage"]["families"]
    actual = Counter(i["pattern"] for i in report["issues"])
    assert len(families) <= 6
    assert [f["pattern"] for f in families] == sorted(
        actual.keys() | {f["pattern"] for f in families}
    )
    for row in families:
        assert row["observed_groups"] > 0
        assert row["observed_groups"] == row["retained_groups"] + row["omitted_groups"]
        assert row["retained_groups"] == actual[row["pattern"]]
    for key, summary in [
        ("observed_groups", "issue_count"),
        ("retained_groups", "displayed_issue_count"),
        ("omitted_groups", "omitted_issue_count"),
    ]:
        assert sum(r[key] for r in families) == report["summary"][summary]
    distinct = {
        (
            i["scope"]["sensor_id"],
            i["scope"]["interface_id"],
            i["scope"]["protocol"],
            e["endpoint_a"]["ip"],
            e["endpoint_a"]["port"],
            e["endpoint_b"]["ip"],
            e["endpoint_b"]["port"],
        )
        for i in report["issues"]
        for e in i["examples"]
    }
    assert report["summary"]["detailed_flow_count"] == len(distinct)


@pytest.mark.parametrize("limit", [1, 5, 6, 7, 20, 100])
def test_all_six_families_retain_rank_and_actual_distinct_examples(limit):
    records = fixture.records(fixture.capture(20, all_families=True))
    full = analyze_network_report(records, max_issues=100)
    ordered = full["issues"]
    assert len({i["pattern"] for i in ordered}) == 6
    assert ordered == sorted(ordered, key=lambda i: (-i["event_count"], repr(identity(i))))
    representatives = {}
    for item in ordered:
        representatives.setdefault(item["pattern"], item)
    chosen = list(representatives.values())[:limit]
    for item in ordered:
        if len(chosen) < limit and item not in chosen:
            chosen.append(item)
    expected = sorted(chosen, key=lambda i: (-i["event_count"], repr(identity(i))))
    report = analyze_network_report(records, max_issues=limit)
    assert [identity(i) for i in report["issues"]] == [identity(i) for i in expected]
    assert fixture.canonical(report) == fixture.canonical(
        analyze_network_report(records, max_issues=limit)
    )
    assert_counts(report)
    assert report["summary"]["detailed_flow_count"] <= len(report["issues"])
    for item, original in zip(report["issues"], expected, strict=True):
        assert {k: v for k, v in item.items() if k != "id"} == {
            k: v for k, v in original.items() if k != "id"
        }
    for key in [
        "scanned_records",
        "evaluated_records",
        "skipped_records",
        "incomplete_records",
        "tracking_limited_records",
        "flow_count",
        "suspect_flow_count",
        "coverage_complete",
        "counts_are_lower_bounds",
    ]:
        assert report["summary"][key] == full["summary"][key]
    assert report["warnings"] == full["warnings"]


def test_single_family_matches_actual_old_producer_order_and_facts():
    legacy = json.loads((ROOT / "web/tests/fixtures/network-family-legacy.json").read_text())
    rows = fixture.records(fixture.capture())
    report = analyze_network_report([r for r in rows if r["protocol"] == "UDP"])
    assert report["issues"] == legacy["issues"]
    assert_counts(report)


@pytest.mark.parametrize(
    "field,values",
    [
        ("sensor_id", ["capture-a", "capture-b"]),
        ("capture_interface_id", [None, 0, 1]),
        ("destination_port", [443, 444]),
    ],
)
def test_scope_separation_remains_exact(field, values):
    rows = fixture.records(fixture.capture(1))[:4]
    inputs = [{**row, field: value} for value in values for row in rows]
    report = analyze_network_report(inputs)
    assert len(report["issues"]) == len(values)
    assert len({identity(i) for i in report["issues"]}) == len(values)
    assert all(i["event_count"] == 3 and i["affected_flow_count"] == 1 for i in report["issues"])
    assert_counts(report)


def test_empty_normal_partial_and_lower_bound_are_not_reinterpreted(monkeypatch):
    from test_network_anomaly import capture, frame

    from c2hunter_analysis import network_report

    for rows in ([], fixture.records(capture(frame(), frame(flags=18, ack=101, reverse=True)))):
        report = analyze_network_report(rows)
        assert report["family_coverage"]["families"] == []
        assert_counts(report)
    rows = fixture.records(fixture.capture())
    partial = analyze_network_report([*rows, {}, {**rows[0], "packet_evidence_complete": False}])
    assert partial["summary"]["skipped_records"] == 1
    assert partial["summary"]["incomplete_records"] == 1
    assert_counts(partial)
    monkeypatch.setattr(network_report, "MAX_TRACKED_FLOWS", 1)
    limited = analyze_network_report(rows)
    assert limited["summary"]["counts_are_lower_bounds"] is True
    assert limited["summary"]["tracking_limited_records"] > 0
    assert "FLOW_TRACKING_LIMIT_REACHED" in limited["warnings"]
    assert_counts(limited)


@pytest.mark.parametrize("max_examples", [3, 10])
def test_repeated_summary_prose_is_unique_without_dropping_example_evidence(max_examples):
    from test_network_anomaly import capture, frame

    from c2hunter_analysis.network_measurements import describe

    rows = fixture.records(capture(frame(), frame()))
    report = analyze_network_report(
        [{**row, "source_ip": f"10.0.0.{host}"} for host in range(1, 12) for row in rows],
        max_examples=max_examples,
    )
    issue = report["issues"][0]
    assert len(issue["examples"]) == max_examples
    assert report["summary"]["detailed_flow_count"] == max_examples
    assert issue["event_count"] == issue["affected_flow_count"] == 11
    assert issue["omitted_examples"] == 11 - max_examples
    lines = [line for example in issue["examples"] for line in describe(example["measurements"])]
    assert len(lines) > len(set(lines))
    assert issue["detailed_analysis"] == list(dict.fromkeys(lines))
    assert all(e["facts"]["tcp_sequence"] == 100 for e in issue["examples"])


@pytest.mark.parametrize(
    "kwargs", [{"max_issues": 0}, {"max_issues": 101}, {"max_examples": 0}, {"max_examples": 11}]
)
def test_existing_output_limits_are_unchanged(kwargs):
    with pytest.raises(ValueError):
        analyze_network_report([], **kwargs)
