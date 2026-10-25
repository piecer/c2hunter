"""Source provenance must not replace packet-local quality or invent counts."""

from copy import deepcopy

import pytest
from test_network_anomaly import frame, records

from c2hunter_analysis.network_coverage import analyze_network_job
from c2hunter_analysis.network_report import analyze_network_report


def native_rows():
    return list(
        records(
            frame(),
            frame(flags=18, seq=500, ack=101, reverse=True),
            frame(flags=16, seq=101, ack=501),
            frame(flags=24, seq=101, ack=501, payload=b"abc"),
            frame(flags=24, seq=101, ack=501, payload=b"abc"),
        )
    )


@pytest.mark.parametrize(
    "metadata,code,omission",
    [
        (
            {"capture_quality": {"dropped_packet_count": 2, "clock_skew_detected": False}},
            "SENSOR_DROPS_REPORTED",
            True,
        ),
        (
            {"capture_quality": {"dropped_packet_count": 0, "clock_skew_detected": True}},
            "SENSOR_CLOCK_SKEW",
            False,
        ),
        ({}, "SENSOR_CAPTURE_QUALITY_UNAVAILABLE", False),
        (
            {"capture_quality": {"dropped_packet_count": None, "clock_skew_detected": False}},
            "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
            False,
        ),
        (
            {"capture_quality": {"dropped_packet_count": 0}},
            "SENSOR_CAPTURE_QUALITY_UNAVAILABLE",
            False,
        ),
        ({"capture_incomplete": True}, "PARTIAL_CAPTURE", True),
        ({"error_code": "LIVE_CAPTURE_RESTART_INCOMPLETE"}, "PARTIAL_CAPTURE", True),
    ],
)
def test_source_quality_is_qualified_without_erasing_positive_local_facts(metadata, code, omission):
    rows = native_rows()
    baseline = analyze_network_report(rows)
    job = {"analysis": {"module": "network_anomaly"}, "flow_records": rows, **metadata}
    before = deepcopy(job)
    report = analyze_network_job(job)
    assert code in report["warnings"]
    assert report["summary"]["coverage_complete"] is False
    assert report["summary"]["truncated"] is omission
    assert report["summary"]["counts_are_lower_bounds"] is omission
    assert report["summary"]["verdict"] == "anomaly_observed"
    assert report["issues"] == baseline["issues"]
    assert job == before


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "source": {
                "captured_packet_count": 5,
                "parsed_packet_count": 5,
                "skipped_packet_count": 0,
            }
        },
        {"capture_quality": {"dropped_packet_count": 0, "clock_skew_detected": False}},
    ],
)
def test_observed_zero_is_not_unknown_and_pure_report_is_unchanged(metadata):
    rows = native_rows()
    assert analyze_network_job({"flow_records": rows, **metadata}) == analyze_network_report(rows)


def test_inherited_qualifiers_are_monotone_bounded_and_not_cumulative_counts():
    from c2hunter_analysis.network_coverage import SOURCE_WARNINGS, attach_network_coverage_context

    parent = {
        "analysis": {"module": "network_anomaly"},
        "flow_records": native_rows(),
        "source": {"captured_packet_count": 8, "skipped_packet_count": 3},
        "capture_limit": {"discarded_packets": 2},
        "capture_quality": {"dropped_packet_count": 4, "clock_skew_detected": True},
        "capture_incomplete": True,
    }
    attach_network_coverage_context(parent)
    before = deepcopy(parent)
    child = {
        "analysis": parent["analysis"],
        "flow_records": parent["flow_records"][:3],
        "network_coverage_context": {**parent["network_coverage_context"], "UNTRUSTED_EXTRA": True},
        "capture_quality": {"dropped_packet_count": 0, "clock_skew_detected": False},
    }
    for _ in range(2):
        attach_network_coverage_context(child)
        report = analyze_network_job(child)
        assert set(child["network_coverage_context"]) == set(SOURCE_WARNINGS)
        assert "UNTRUSTED_EXTRA" not in report["warnings"]
        assert len(report["warnings"]) == len(set(report["warnings"]))
        assert report["summary"]["scanned_records"] == 3
        assert report["summary"]["skipped_records"] == 0
        assert report["summary"]["coverage_complete"] is False
        assert child["network_coverage_context"]["SENSOR_DROPS_REPORTED"] is True
        assert child["network_coverage_context"]["SENSOR_CLOCK_SKEW"] is True
        assert child["network_coverage_context"]["PARTIAL_CAPTURE"] is True
        child = deepcopy(child)
    assert parent == before
