"""Local fixture smoke: PYTHONPATH=analysis/src python analysis/tests/network_anomaly_smoke.py."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from c2hunter_analysis.network_anomaly import analyze_network_anomalies
from c2hunter_analysis.pcap import parse_pcap


def main() -> None:
    fixtures = Path(__file__).with_name("fixtures") / "network_anomaly"
    expected = {
        "normal.pcap": (2, "TCP", {}),
        "syn_reset.pcap": (3, "TCP", {"syn_retransmissions": 1, "matched_resets": 1}),
        "tcp_repeat.pcap": (5, "TCP", {"data_retransmissions": 1, "duplicate_acks": 1}),
        "udp_duplicate.pcap": (3, "UDP", {"udp_duplicate_candidates": 2}),
        "icmp_quote.pcap": (2, "UDP", {"icmp_errors": 1}),
    }
    paths = sorted(fixtures.glob("*.pcap"))
    if {p.name for p in paths} != set(expected):
        raise RuntimeError("expected all five PCAP samples")
    results = {}
    for path in paths:
        data = path.read_bytes()
        parsed = parse_pcap(
            data,
            sensor_id="fixture-sensor",
            internal_networks=["10.0.0.0/8"],
            retain_packet_bytes=False,
            retain_network_evidence=True,
        )
        result = analyze_network_anomalies(parsed.records)
        count, protocol, positives = expected[path.name]
        assert parsed.parsed_packet_count == count
        assert all(r["packet_evidence_complete"] for r in parsed.records)
        metric = next(f["metrics"] for f in result["flows"] if f["protocol"] == protocol)
        for counter in (
            "syn_retransmissions",
            "data_retransmissions",
            "duplicate_acks",
            "matched_resets",
            "udp_duplicate_candidates",
            "icmp_errors",
        ):
            assert metric[counter] == positives.get(counter, 0), (path.name, counter, metric)
        assert metric["observed_rtt_ms"]["count"] == (1 if path.name == "normal.pcap" else 0)
        results[path.name] = {
            "sha256": hashlib.sha256(data).hexdigest(),
            "parsed_packets": parsed.parsed_packet_count,
            "flows": result["summary"]["flow_count"],
            "metrics": [f["metrics"] for f in result["flows"]],
            "warnings": [f["warnings"] for f in result["flows"]],
        }
    print(json.dumps(results, indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
