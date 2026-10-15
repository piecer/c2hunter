import json
from copy import deepcopy
from pathlib import Path

import pytest
from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from c2hunter_worker.analysis import execute_analysis

from c2hunter_controller.app import _validated_ddos_report
from c2hunter_controller.ddos_ai import build_ddos_input

CORPUS = Path(__file__).parents[2] / "web/tests/fixtures/ddos-signature-corpus.json"


@pytest.mark.parametrize("case", json.loads(CORPUS.read_text()), ids=lambda case: case["name"])
def test_shared_signature_corpus(case):
    if case["accepted"]:
        _validated_ddos_report(case["report"])
        build_ddos_input(case["report"])
    else:
        with pytest.raises(ValueError):
            _validated_ddos_report(case["report"])
        with pytest.raises(ValueError):
            build_ddos_input(case["report"])


ROWS = json.loads(
    (Path(__file__).parents[2] / "analysis/tests/fixtures/ddos-pcap-coordination.json").read_text()
)
PARAMETERS = {
    "module": "ddos_attack",
    "ddos_min_duration_seconds": 2,
    "ddos_min_source_count": 3,
    "ddos_min_packet_count": 6,
    "ddos_min_packets_per_second": 2,
}


def test_worker_report_response_ai_closed_v4():
    report = execute_analysis(
        {"flow_records": ROWS, "analysis": PARAMETERS, "internal_networks": ["10.0.0.0/8"]}
    )["ddos_attack"]
    assert report == analyze_ddos_attack(ROWS, parameters=PARAMETERS)
    wire = _validated_ddos_report(report)
    assert (
        wire["findings"][0]["signature_candidates"] == report["findings"][0]["signature_candidates"]
    )
    ai = build_ddos_input(wire)
    assert ai["schema_version"] == "ddos-ai-input-v4"
    assert (
        ai["findings"][0]["signature_candidates"][0]["evaluation"]
        == report["findings"][0]["signature_candidates"][0]["evaluation"]
    )
    for key, value in [("matched_records", 999), ("packet_match_rate", 0), ("omitted_records", -1)]:
        bad = deepcopy(report)
        bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"][key] = value
        with pytest.raises(ValueError):
            _validated_ddos_report(bad)
    bad = deepcopy(report)
    bad["findings"][0]["signature_candidates"][0]["evaluation"]["normal"]["result"] = {}
    with pytest.raises(ValueError):
        _validated_ddos_report(bad)
