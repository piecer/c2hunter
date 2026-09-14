"""Real producer witnesses for minimum-facts-first AI publication (no model I/O)."""

from copy import deepcopy
from pathlib import Path

import pytest
from c2hunter_analysis.network_report import analyze_network_report

from c2hunter_controller.network_ai import build_network_input, canonical_network_input

MINIMUM = (
    "id",
    "pattern",
    "event_count",
    "affected_flow_count",
    "affected_host_count",
    "first_seen",
    "last_seen",
)


def rich_report(monkeypatch, peers=20, max_issues=20):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "analysis" / "tests"))
    from test_network_anomaly import frame, records

    packets = []
    for peer in range(peers):
        # Parsed genuine PCAP records, with distinct peer addresses for grouping.
        group = records(
            frame(),
            frame(flags=18, seq=500, ack=101, reverse=True),
            frame(flags=24, seq=101, payload=b"abc"),
            frame(flags=24, seq=101, payload=b"abc"),
        )
        for packet in group:
            for key in ("source_ip", "destination_ip"):
                if packet[key] == "203.0.113.1":
                    packet[key] = f"203.0.113.{peer + 1}"
        packets.extend(group)
    return analyze_network_report(packets, max_issues=max_issues)


@pytest.mark.parametrize("long_prose", [False, True])
def test_all_real_producer_minimum_facts_precede_optional_details(monkeypatch, long_prose):
    report = rich_report(monkeypatch)
    assert len(report["issues"]) == 20
    if long_prose:
        for item in report["issues"]:
            for key in ("evidence", "uncertainty", "detailed_analysis", "next_checks"):
                item[key] = ['한😀\\"\n' * 400] * 10
    original = deepcopy(report)
    bundles = []
    for language in ("ko", "en"):
        bundle = build_network_input(report, language)
        assert len(bundle["issues"]) == 20
        assert bundle["omitted_input_issues"] == 0
        assert [{key: i[key] for key in MINIMUM} for i in bundle["issues"]] == [
            {key: i[key] for key in MINIMUM} for i in report["issues"]
        ]
        assert len(canonical_network_input(bundle).encode("utf-8")) <= 24000
        assert build_network_input(report, language) == bundle
        bundle.pop("language")
        bundles.append(bundle)
    assert bundles[0] == bundles[1]
    assert report == original


def test_detail_counts_include_summary_clipping(monkeypatch):
    report = rich_report(monkeypatch, peers=1)
    report["summary"]["suspected_cause"] = deepcopy(report["summary"]["suspected_cause"])
    report["summary"]["suspected_cause"]["summary"] = "한" * 401
    bundle = build_network_input(report)
    assert bundle["input_detail_counts"]["clipped_text_characters"] == 1


@pytest.mark.parametrize(
    ("peers", "max_issues", "producer_omitted", "input_omitted"),
    [
        (25, 20, 5, 0),
        (25, 25, 0, 5),
        (30, 25, 5, 5),
    ],
)
def test_producer_projection_detail_omissions_and_citations_are_distinct(
    monkeypatch, peers, max_issues, producer_omitted, input_omitted
):
    from test_network_ai import response

    from c2hunter_controller.network_ai import validate_network_interpretation

    report = rich_report(monkeypatch, peers, max_issues)
    bundle = build_network_input(report)
    assert bundle["summary"]["omitted_issue_count"] == producer_omitted
    assert bundle["omitted_input_issues"] == input_omitted
    assert len(bundle["issues"]) == 20
    counts = bundle["input_detail_counts"]
    assert counts["available"] == counts["retained"] + counts["omitted"]
    assert counts["omitted"] > 0
    assert all(type(v) is int and v >= 0 for v in counts.values())
    validate_network_interpretation(response(issue_ids=[i["id"] for i in bundle["issues"]]), bundle)
    for identity in ["invented", *[i["id"] for i in report["issues"][20:]]]:
        with pytest.raises(ValueError, match="unknown network issue IDs"):
            validate_network_interpretation(response(issue_ids=[identity]), bundle)


def test_empty_and_legacy_unknown_details_stay_unknown():
    from test_network_ai import issue

    empty = build_network_input(analyze_network_report([]))
    assert empty["issues"] == []
    assert empty["omitted_input_issues"] == 0
    assert empty["input_detail_counts"]["available"] == 0
    report = analyze_network_report([])
    report["issues"] = [issue()]
    del report["summary"]["suspected_cause"]
    for hostile in (None, "RAW_SENTINEL", 42, {}, [None, {"facts": "RAW_SENTINEL"}]):
        report["issues"][0].update(
            examples=hostile,
            evidence=hostile,
            uncertainty=hostile,
            detailed_analysis=hostile,
            next_checks=hostile,
        )
        bundle = build_network_input(report)
        assert len(bundle["issues"]) == 1
        assert "observed_measurements" not in bundle["issues"][0]
        assert "suspected_cause" not in bundle["summary"]
        assert "RAW_SENTINEL" not in canonical_network_input(bundle)


def test_first_rich_issue_cannot_starve_later_minimum_or_numeric_facts(monkeypatch):
    report = rich_report(monkeypatch)
    for key in ("evidence", "uncertainty", "detailed_analysis", "next_checks"):
        report["issues"][0][key] = ["한😀" * 1000] * 100
    report["issues"][0]["examples"] *= 100
    bundle = build_network_input(report)
    assert len(bundle["issues"]) == 20
    for source, item in zip(report["issues"], bundle["issues"], strict=True):
        assert item["observed_facts"][0] == source["examples"][0]["facts"]
    counts = bundle["input_detail_counts"]
    assert counts["capped_example_entries"] == 98
    assert counts["capped_diagnostic_entries"] >= 384
    assert counts["clipped_text_characters"] > 0


@pytest.mark.parametrize("mutation", ["measurement", "cause", "id", "duplicate", "count"])
def test_last_issue_validation_cannot_be_skipped_due_to_early_budget_pressure(
    monkeypatch, mutation
):
    report = rich_report(monkeypatch)
    for item in report["issues"]:
        item["evidence"] = ["한😀" * 400] * 4
    last = report["issues"][-1]
    if mutation == "measurement":
        last["examples"][0]["measurements"]["observed_rtt_ms"]["mean"] = float("inf")
    elif mutation == "cause":
        last["suspected_cause"]["confidence"] = "high"
    elif mutation == "id":
        del last["id"]
    elif mutation == "duplicate":
        last["id"] = report["issues"][0]["id"]
    else:
        last["event_count"] = True
    with pytest.raises(ValueError):
        build_network_input(report)


def test_twenty_maximum_bounded_minimum_facts_fit(monkeypatch):
    report = rich_report(monkeypatch)
    for index, item in enumerate(report["issues"]):
        item["id"] = str(index).zfill(100)
        item["first_seen"] = item["last_seen"] = "😀" * 64
        for key in ("event_count", "affected_flow_count", "affected_host_count"):
            item[key] = 2**63 - 1
    bundle = build_network_input(report)
    assert len(bundle["issues"]) == 20
    assert len(canonical_network_input(bundle).encode("utf-8")) <= 24000
    for item in bundle["issues"]:
        assert item["event_count"] == 2**63 - 1


def test_irreducible_escaped_minimum_never_silently_drops_issues(monkeypatch):
    report = rich_report(monkeypatch)
    for index, item in enumerate(report["issues"]):
        item["id"] = "\x00" * 98 + str(index).zfill(2)
        item["first_seen"] = item["last_seen"] = "\x00" * 64
    with pytest.raises(ValueError, match="minimum facts exceed byte budget"):
        build_network_input(report)


def test_exact_utf8_limit_accepts_whole_unit_but_limit_minus_one_omits(monkeypatch):
    from test_network_ai import issue

    from c2hunter_controller import network_ai

    report = analyze_network_report([])
    item = issue()
    item.update(examples=[], uncertainty=[], next_checks=[], evidence=['한😀\\"\n<>&\u2028'])
    report["issues"] = [item]
    full = build_network_input(report)
    exact = len(canonical_network_input(full).encode("utf-8"))
    monkeypatch.setattr(network_ai, "MAX_NETWORK_INPUT_BYTES", exact)
    assert build_network_input(report) == full
    monkeypatch.setattr(network_ai, "MAX_NETWORK_INPUT_BYTES", exact - 1)
    bounded = build_network_input(report)
    assert bounded["issues"][0]["evidence"] == []
    assert bounded["input_detail_counts"]["omitted"] == 1
    assert len(canonical_network_input(bounded).encode("utf-8")) <= exact - 1


def test_actual_24000_byte_boundary_includes_escaped_mandatory_text(monkeypatch):
    report = rich_report(monkeypatch)
    del report["summary"]["suspected_cause"]
    report["issues"] = [{key: item[key] for key in MINIMUM} for item in report["issues"]]
    report["warnings"] = [""] * 4
    report["limitations"] = [""] * 4
    base = len(canonical_network_input(build_network_input(report)).encode("utf-8"))
    escaped, remainder = divmod(24000 - base, 6)
    text = "\x00" * escaped + "x" * remainder
    assert len(text) <= 3200
    chunks = [text[i * 400 : (i + 1) * 400] for i in range(8)]
    report["warnings"], report["limitations"] = chunks[:4], chunks[4:]
    bundle = build_network_input(report)
    assert len(bundle["issues"]) == 20
    assert len(canonical_network_input(bundle).encode("utf-8")) == 24000
    report["limitations"][-1] += "x"
    with pytest.raises(ValueError, match="minimum facts exceed byte budget"):
        build_network_input(report)


def test_whole_report_serialization_work_is_constant(monkeypatch):
    from c2hunter_controller import network_ai

    report = rich_report(monkeypatch)
    calls = []
    serializer = network_ai.canonical_network_input

    def counted(value):
        if "schema_version" in value:
            calls.append(True)
        return serializer(value)

    monkeypatch.setattr(network_ai, "canonical_network_input", counted)
    build_network_input(report)
    assert len(calls) == 2
