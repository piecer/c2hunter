#!/usr/bin/env python3
"""Emit a deterministic report through the real DDoS producer for Web contract tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from c2hunter_analysis.ddos_attack import analyze_ddos_attack

start = datetime(2026, 9, 15, tzinfo=UTC)
records = [
    {
        "sensor_id": "sensor-a",
        "timestamp": (start + timedelta(seconds=index // 4)).isoformat(),
        "source_ip": f"198.51.100.{index + 1}",
        "destination_ip": "10.0.0.10",
        "source_port": 40000 + index,
        "destination_port": 443,
        "protocol": "TCP",
        "direction": "INBOUND",
        "packet_count": 12,
        "total_bytes": 720,
        "duration_seconds": 3,
        "tcp_flags": {"syn": 12, "ack": 0, "rst": 0, "fin": 0},
        "tcp_flags_observed": True,
        "tcp_syn_count": 12,
        "tcp_syn_only_count": 12,
        "packet_evidence_complete": False,
    }
    for index in range(100)
]
report = analyze_ddos_attack(
    records,
    internal_cidrs=("10.0.0.0/8",),
    parameters={
        "ddos_min_duration_seconds": 2,
        "ddos_min_source_count": 20,
        "ddos_min_packet_count": 1000,
        "ddos_min_packets_per_second": 10,
        "ddos_min_bits_per_second": 1_000_000_000,
    },
)
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
