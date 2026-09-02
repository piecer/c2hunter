from copy import deepcopy
from datetime import UTC, datetime, timedelta

from c2hunter_controller.jobs import calculate

START = datetime(2026, 9, 2, tzinfo=UTC)


def retry_job() -> dict[str, object]:
    return {
        "dataset_id": "dataset",
        "start_time": START.isoformat(),
        "end_time": (START + timedelta(minutes=5)).isoformat(),
        "sensor_ids": ["sensor-a"],
        "internal_networks": ["10.0.0.0/8"],
        "analysis": {
            "minimum_candidate_score": 60,
            "periodicity_min_samples": 5,
        },
        "flow_records": [
            {
                "sensor_id": "sensor-a",
                "timestamp": START.isoformat(),
                "source_ip": "10.0.0.1",
                "destination_ip": "203.0.113.40",
                "source_port": 50000,
                "destination_port": 443,
                "protocol": "TCP",
                "direction": "OUTBOUND",
                "packet_count": 4,
                "total_bytes": 240,
                "duration_seconds": 12,
                "tcp_flags": {"syn": 4},
                "tcp_flags_observed": True,
                "tcp_syn_count": 4,
                "tcp_ack_count": 0,
                "tcp_rst_count": 0,
                "tcp_syn_only_count": 4,
                "tcp_syn_ack_count": 0,
                "tcp_ack_only_count": 0,
                "tcp_syn_only_observations": [
                    {"offset_us": 0, "sequence": 12345},
                    {"offset_us": 2_000_000, "sequence": 12345},
                    {"offset_us": 6_000_000, "sequence": 12345},
                    {"offset_us": 12_000_000, "sequence": 12345},
                ],
                "bidirectional": False,
                "packet_sizes": [60],
            }
        ],
    }


def test_operational_communication_candidate_survives_c2_score_threshold() -> None:
    candidates = calculate(retry_job())

    assert len(candidates) == 1
    assert candidates[0]["candidate_kind"] == "COMMUNICATION_STATUS"
    assert candidates[0]["score"] == 0
    assert candidates[0]["evidence"][0]["type"] == "TCP_COMMUNICATION_ATTEMPT_PATTERN"


def test_operational_evidence_does_not_bypass_threshold_for_mixed_c2_candidate() -> None:
    job = deepcopy(retry_job())
    analysis = job["analysis"]
    records = job["flow_records"]
    assert isinstance(analysis, dict)
    assert isinstance(records, list)
    assert isinstance(records[0], dict)
    analysis["non_well_known_port_min_observations"] = 1
    records[0]["destination_port"] = 4444
    records.append(
        {
            "sensor_id": "sensor-a",
            "timestamp": (START + timedelta(seconds=20)).isoformat(),
            "source_ip": "10.0.0.1",
            "destination_ip": "203.0.113.40",
            "source_port": 53000,
            "destination_port": 4444,
            "protocol": "UDP",
            "direction": "OUTBOUND",
            "packet_count": 1,
            "total_bytes": 60,
            "packet_sizes": [60],
        }
    )

    analysis["minimum_candidate_score"] = 80

    assert calculate(job) == []
