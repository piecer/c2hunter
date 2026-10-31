"""Existing DDoS report contract: one/two-source packet-threshold warning."""

import json

from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from c2hunter_controller.schemas import DDoSAttackReport

reports = {}
for sources in (1, 2):
    records = [
        {
            "sensor_id": "test",
            "timestamp": "2026-09-15T00:00:00+00:00",
            "source_ip": f"198.51.100.{index + 1}",
            "destination_ip": "10.0.0.10",
            "source_port": 40000,
            "destination_port": 443,
            "protocol": "UDP",
            "direction": "INBOUND",
            "packet_count": 1200 // sources,
            "total_bytes": 72000 // sources,
            "duration_seconds": 600,
        }
        for index in range(sources)
    ]
    report = analyze_ddos_attack(records, internal_cidrs=("10.0.0.0/8",))
    DDoSAttackReport.model_validate(report)
    assert "DOS_LIKE_TRAFFIC" in report["warnings"]
    assert report["verdict"] == "insufficient_evidence"
    reports[str(sources)] = report
print(json.dumps(reports, sort_keys=True))
