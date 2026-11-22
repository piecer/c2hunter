"""Full Network job envelope through the production public projection.

Report bytes come from the real parser/analyzer on stdin. Metadata is synthetic,
not a deployed job; no controller, model or external service is contacted.
"""
import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / part) for part in (
    "controller/src", "analysis/src", "sensor/worker/src",
)]
from c2hunter_controller.app import _public_job

report = json.load(sys.stdin)
job = _public_job({
    "id": "full-envelope-network-job",
    "name": "장기 관측 Network investigation — " * 6,
    "description": "분석가 참고 Analyst note with complete operational context. " * 40,
    "dataset_id": "dataset-" + "0123456789abcdef" * 8,
    "status": "COMPLETED",
    "source_type": "PCAP_UPLOAD", "mode": "PCAP_UPLOAD",
    "analysis": {"module": "network_anomaly"},
    "network_anomaly": report,
    "processing": {"phase": "COMPLETED", "phase_started_at": "2026-10-27T00:00:00Z"},
    "source": {"filename": "장기관측-capture-" * 12 + ".pcap",
               "capture_format": "pcap", "size_bytes": 12345678,
               "captured_packet_count": report["summary"]["scanned_records"],
               "parsed_packet_count": report["summary"]["scanned_records"],
               "skipped_packet_count": 0, "link_types": [1], "sha256": "ab" * 32},
    "warnings": ["Operational warning: preserve the original capture and observation context. " * 6],
    "flow_records": [], "preparation_lease_token": "must-not-be-public",
})
assert "flow_records" not in job and "preparation_lease_token" not in job
print(json.dumps(job, ensure_ascii=False))
