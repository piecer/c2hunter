"""Frozen original reviewer bytes, not substitutes generated after repair."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from c2hunter_analysis.pcap import parse_pcap
from fastapi.testclient import TestClient
from test_pcap_guidance_temporal_responses import guide_for

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

FIXTURES = Path(__file__).parent / "fixtures/pcap_guidance_review"
CASES = [
    (
        "handshake_same_window",
        "2666f274e62ced460f4a2c8fbe26c62704d9ef6e87a1980b810a6e98a81766d4",
        0,
        1,
    ),
    (
        "handshake_cross_window",
        "12ef9b44621b2272ce25fabf6f11f53cbd08174ffd2452d3ce10fa35fc46ab18",
        0,
        1,
    ),
    (
        "handshake_responses_before_requests",
        "383d55818f0c16a323cff50ed976df14f4ecf3ab6ba255757b570fa73f359f68",
        1,
        0,
    ),
    (
        "relative_burst_below_packet_floor",
        "2d89998fdf66c21e69eae9de785d205e217919c68379fed854cc2273202dfae3",
        1,
        0,
    ),
]


@pytest.mark.parametrize("name,digest,candidates,suppressed", CASES)
def test_original_review_pcaps(name, digest, candidates, suppressed):
    raw = (FIXTURES / f"{name}.pcap").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == digest
    parsed = parse_pcap(
        raw,
        sensor_id="original-review",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_network_evidence=True,
    )
    assert parsed.skipped_packet_count == 0
    guide = guide_for(parsed.records)
    assert len(guide["candidates"]) == candidates
    assert guide["summary"]["suppressed_handshake_window_count"] == suppressed
    if name == "relative_burst_below_packet_floor":
        assert guide["summary"]["eligible_packet_count"] == 620
        candidate = guide["candidates"][0]
        assert candidate["family"] == "UDP_BURST"
        assert candidate["packet_count"] == 600
        assert candidate["baseline_window_count"] == 4
        assert candidate["baseline_packet_count"] == 20
        assert candidate["reason_codes"] == ["RELATIVE_RATE_INCREASE"]


def test_new_producer_fixtures_have_temporal_and_partial_baseline_semantics():
    import json

    from pcap_guidance_fixture_builder import FIXTURES as GENERATED

    cross = json.loads((GENERATED / "cross_boundary_replies.guide.json").read_bytes())
    assert cross["candidates"] == []
    assert cross["summary"]["suppressed_handshake_window_count"] == 1
    past = json.loads((GENERATED / "preceding_only_replies.guide.json").read_bytes())
    assert past["candidates"][0]["family"] == "SYN_CONCENTRATION"
    assert past["summary"]["suppressed_handshake_window_count"] == 0
    edge = json.loads((GENERATED / "partial_edge_baseline.guide.json").read_bytes())
    assert edge["candidates"][0]["baseline_window_count"] == 3
    assert edge["candidates"][0]["baseline_packet_count"] == 3
    assert edge["candidates"][0]["reason_codes"] == ["RELATIVE_RATE_INCREASE"]


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_original_B1_quiet_baseline_survives_upload_readback_and_reanalysis(tmp_path, backend):
    repository = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "quiet.db")
    )
    try:
        client = TestClient(create_app(Settings(environment="test"), repository))
        raw = (FIXTURES / "relative_burst_below_packet_floor.pcap").read_bytes()
        response = client.post(
            "/api/v1/pcap-analysis-jobs?name=quiet&filename=quiet.pcap&analysis_module=ddos_attack",
            content=raw,
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        )
        assert response.status_code == 201, response.text
        parent = response.json()
        guide = parent["pcap_attack_guidance"]
        assert guide["candidates"][0]["baseline_packet_count"] == 20
        assert guide["candidates"][0]["packet_count"] == 600
        job_id = parent["id"]
        assert client.get(f"/api/v1/analysis-jobs/{job_id}").json()["pcap_attack_guidance"] == guide
        listed = client.get("/api/v1/analysis-jobs").json()["items"][0]
        assert "pcap_attack_guidance" not in listed
        assert listed["pcap_attack_guidance_summary"]["status"] == "REVIEW_CANDIDATES"
        response = client.post(
            f"/api/v1/analysis-jobs/{job_id}/reanalyze",
            json={"idempotency_key": "quiet-child"},
        )
        assert response.status_code == 201, response.text
        child = response.json()
        assert child["pcap_attack_guidance"]["job_id"] == child["id"] != job_id
        assert child["pcap_attack_guidance"]["candidates"] == guide["candidates"]
        assert repository.get_job(job_id)["pcap_attack_guidance"] == guide
    finally:
        if backend == "sqlite":
            repository.close()
