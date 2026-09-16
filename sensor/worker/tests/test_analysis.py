from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from c2hunter_worker.analysis import execute_analysis

START = datetime(2026, 9, 15, tzinfo=UTC)


def payload(module: str = "ddos_attack") -> dict[str, object]:
    return {
        "dataset_id": "ddos-worker",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(seconds=10)).isoformat(),
        "sensor_ids": ["sensor-a"],
        "internal_networks": ["10.0.0.0/8"],
        "analysis": {
            "module": module,
            "ddos_min_duration_seconds": 2,
            "ddos_min_source_count": 3,
            "ddos_min_packet_count": 6,
            "ddos_min_packets_per_second": 2,
            "ddos_min_bits_per_second": 1_000_000,
        },
        "flow_records": [
            {
                "sensor_id": "sensor-a",
                "timestamp": (START + timedelta(seconds=second)).isoformat(),
                "source_ip": f"198.51.100.{source}",
                "destination_ip": "10.0.0.10",
                "source_port": 40000 + source,
                "destination_port": 443,
                "protocol": "TCP",
                "direction": "INBOUND",
                "packet_count": 1,
                "total_bytes": 60,
                "duration_seconds": 0,
                "tcp_flags": {"syn": 1, "ack": 0, "rst": 0},
                "tcp_flags_observed": True,
                "tcp_syn_count": 1,
                "tcp_syn_only_count": 1,
                "packet_evidence_complete": True,
            }
            for second in range(25)
            for source in range(1, 5)
        ],
    }


def test_worker_executes_ddos_report_without_candidates() -> None:
    request = payload()
    request["ddos_coverage_context"] = {"parser_skipped_packet_count": 1}
    result = execute_analysis(request)
    assert result["candidates"] == []
    assert result["ddos_attack"]["version"] == "ddos-attack-report-v1"
    assert result["ddos_attack"]["findings"][0]["attack_type"] == "TCP_SYN_FLOOD"
    assert result["ddos_attack"]["summary"]["coverage_complete"] is False
    assert "PARSER_SKIPPED_PACKETS" in result["ddos_attack"]["warnings"]


def test_worker_rejects_unknown_module_instead_of_falling_back_to_c2() -> None:
    with pytest.raises(ValueError, match="unsupported analysis module"):
        execute_analysis(payload("future_module"))


def test_worker_c2_projection_ignores_ddos_payload_cardinality_metadata() -> None:
    request = payload("c2")
    request["flow_records"][0]["transport_payload_packet_count"] = 0  # type: ignore[index]
    result = execute_analysis(request)
    assert isinstance(result["candidates"], list)
