from __future__ import annotations

import copy
import hashlib

import pytest
from c2hunter_analysis.ddos_job import analyze_ddos_job
from c2hunter_analysis.pcap import parse_pcap
from pcap_guidance_fixture_builder import packets, pcap_bytes

from c2hunter_controller.pcap_attack_guidance_schema import validate_job_guidance


def quiet_then_burst(*, quiet_seconds: int = 20, peak_packets: int = 600):
    content = pcap_bytes(
        packets(quiet_seconds, span_us=quiet_seconds * 1_000_000, protocol=17)
        + packets(peak_packets, start=20, span_us=3_000_000, protocol=17)
    )
    parsed = parse_pcap(
        content,
        sensor_id="quiet-baseline-regression",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_network_evidence=True,
    )
    job = {
        "id": "quiet-baseline-job",
        "dataset_id": "pcap:" + hashlib.sha256(content).hexdigest(),
        "source_type": "PCAP_UPLOAD",
        "analysis": {"module": "ddos_attack"},
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": parsed.records,
        "packet_count": parsed.captured_packet_count,
        "flow_count": len(parsed.records),
    }
    job.update(analyze_ddos_job(job))
    return job


def test_original_quiet_relative_burst_is_a_review_candidate_not_a_ddos_finding():
    job = quiet_then_burst()
    assert job["ddos_attack"]["findings"] == []
    guide = validate_job_guidance(job)
    assert guide is not None
    assert guide["status"] == "REVIEW_CANDIDATES"
    (candidate,) = guide["candidates"]
    assert candidate["family"] == "UDP_BURST"
    assert candidate["packet_count"] == 600
    assert candidate["baseline_window_count"] == 4
    assert candidate["baseline_packet_count"] == 20
    assert candidate["reason_codes"] == ["RELATIVE_RATE_INCREASE"]
    assert "WITHIN_CAPTURE_NOT_KNOWN_NORMAL" in candidate["uncertainty_codes"]


def test_two_occupied_baseline_windows_are_not_padded_with_idle_time():
    guide = validate_job_guidance(quiet_then_burst(quiet_seconds=10))
    assert guide is not None
    assert guide["candidates"] == []


def test_quiet_baseline_does_not_remove_candidate_minimum_packet_guard():
    guide = validate_job_guidance(quiet_then_burst(peak_packets=31))
    assert guide is not None
    assert guide["candidates"] == []


def test_schema_rejects_more_occupied_windows_than_observed_baseline_packets():
    job = quiet_then_burst()
    assert job["pcap_attack_guidance"]["candidates"]
    changed = copy.deepcopy(job)
    changed["pcap_attack_guidance"]["candidates"][0]["baseline_window_count"] = 21
    with pytest.raises(ValueError):
        validate_job_guidance(changed)
