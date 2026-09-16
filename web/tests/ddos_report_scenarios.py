#!/usr/bin/env python3
"""Emit every DDoS presentation family through the production analyzer."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from c2hunter_analysis.ddos_attack import analyze_ddos_attack

START = datetime(2026, 9, 15, tzinfo=UTC)
PARAMETERS = {
    "ddos_min_source_count": 20,
    "ddos_min_packet_count": 1000,
    "ddos_min_packets_per_second": 10,
    "ddos_min_bits_per_second": 1_000_000_000,
}


def flows(
    protocol: str,
    *,
    direction: str = "INBOUND",
    target: str = "10.0.0.10",
    source_port: int | None = None,
    flags: dict[str, int] | None = None,
    icmp_type: int | None = None,
    size: int = 720,
) -> list[dict[str, object]]:
    result = []
    for index in range(100):
        packets = 12
        source = (
            f"10.1.0.{index + 1}"
            if direction == "OUTBOUND"
            else f"198.51.100.{index + 1}"
        )
        row: dict[str, object] = {
            "sensor_id": "scenario-sensor",
            "timestamp": (START + timedelta(seconds=index // 4)).isoformat(),
            "source_ip": source,
            "destination_ip": target,
            "source_port": source_port if source_port is not None else 40000 + index,
            "destination_port": 443,
            "protocol": protocol,
            "direction": direction,
            "packet_count": packets,
            "total_bytes": size,
            "duration_seconds": 3,
            "tcp_flags": flags,
            "tcp_flags_observed": flags is not None,
            "transport_payload_length": 0,
            "packet_evidence_complete": False,
            "icmp_type": icmp_type,
        }
        if flags:
            row.update(
                {
                    "tcp_syn_only_count": packets
                    if flags.get("syn") and not flags.get("ack")
                    else 0,
                    "tcp_syn_ack_count": packets
                    if flags.get("syn") and flags.get("ack")
                    else 0,
                    "tcp_ack_only_count": packets
                    if flags.get("ack") and not flags.get("syn")
                    else 0,
                    "tcp_rst_count": packets if flags.get("rst") else 0,
                    "tcp_fin_count": packets if flags.get("fin") else 0,
                }
            )
        result.append(row)
    return result


def analyze(rows: list[dict[str, object]], parameters: dict[str, object] | None = None):
    return analyze_ddos_attack(
        rows,
        internal_cidrs=("10.0.0.0/8",),
        parameters=parameters or PARAMETERS,
    )


syn = flows("TCP", flags={"syn": 1})
udp = flows("UDP")
scenarios = {
    "tcp_syn_inbound": analyze(syn),
    "tcp_ack_inbound": analyze(flows("TCP", flags={"ack": 1})),
    "tcp_rst_inbound": analyze(flows("TCP", flags={"rst": 1})),
    "udp_outbound_participant": analyze(
        flows("UDP", direction="OUTBOUND", target="203.0.113.80")
    ),
    "possible_reflection": analyze(flows("UDP", source_port=53, size=7200)),
    "icmp_echo": analyze(flows("ICMP", icmp_type=8)),
    "icmp_generic": analyze(flows("ICMP", icmp_type=3)),
    "multi_vector": analyze(syn + udp),
    "no_clear_attack": analyze(
        flows("UDP")[:100], {**PARAMETERS, "ddos_min_packet_count": 10_000}
    ),
    "insufficient_evidence": analyze(
        [
            {
                **row,
                "source_ip": "192.0.2.1",
                "destination_ip": "198.51.100.1",
                "direction": "UNKNOWN",
            }
            for row in flows("UDP")
        ]
    ),
}
print(json.dumps(scenarios, sort_keys=True, separators=(",", ":")))
