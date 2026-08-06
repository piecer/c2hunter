from concurrent.futures import ThreadPoolExecutor

from c2hunter_controller.capture_limits import allocate_sensor_limit, limit_flow_records
from c2hunter_controller.repositories import MemoryRepository


def test_allocate_sensor_limit_never_exceeds_analysis_total() -> None:
    sensors = ["sensor-c", "sensor-a", "sensor-b"]
    quotas = [allocate_sensor_limit(10, sensors, sensor) for sensor in sensors]
    assert quotas == [3, 4, 3]
    assert sum(value or 0 for value in quotas) == 10


def test_allocate_sensor_limit_returns_zero_for_unassigned_small_quota() -> None:
    sensors = ["sensor-a", "sensor-b", "sensor-c"]
    assert allocate_sensor_limit(2, sensors, "sensor-a") == 1
    assert allocate_sensor_limit(2, sensors, "sensor-b") == 1
    assert allocate_sensor_limit(2, sensors, "sensor-c") == 0
    assert allocate_sensor_limit(None, sensors, "sensor-c") is None


def test_limit_flow_records_trims_inside_aggregated_flow() -> None:
    records = [
        {
            "timestamp": "2026-08-04T00:00:00+00:00",
            "packet_count": 3,
            "total_bytes": 300,
        },
        {
            "timestamp": "2026-08-04T00:00:01+00:00",
            "packet_count": 5,
            "total_bytes": 1000,
        },
        {
            "timestamp": "2026-08-04T00:00:02+00:00",
            "packet_count": 2,
            "total_bytes": 500,
        },
    ]

    limited, summary = limit_flow_records(records, 6)

    assert [record["packet_count"] for record in limited] == [3, 3]
    assert limited[1]["total_bytes"] == 600
    assert summary == {
        "configured_max_packets": 6,
        "observed_packets": 10,
        "retained_packets": 6,
        "discarded_packets": 4,
    }


def test_limit_flow_records_keeps_unlimited_input_unchanged() -> None:
    records = [{"packet_count": 4, "total_bytes": 400}]
    limited, summary = limit_flow_records(records, None)
    assert limited == records
    assert limited is not records
    assert summary["retained_packets"] == 4
    assert summary["discarded_packets"] == 0


def test_memory_sensor_pcap_limit_reservation_is_atomic() -> None:
    repository = MemoryRepository()
    content = b"x" * 32

    def save(index: int) -> str:
        segment = {
            "id": f"segment-{index}",
            "sensor_id": f"sensor-{index}",
            "analysis_job_id": "job-a",
            "filename": f"job-a--eth{index}.pcap",
            "size_bytes": len(content),
            "sha256": f"digest-{index}",
            "uploaded_at": "2026-08-07T00:00:00+00:00",
        }
        _, status = repository.save_sensor_pcap_limited(segment, content, len(content))
        return status

    with ThreadPoolExecutor(max_workers=2) as executor:
        statuses = list(executor.map(save, range(2)))

    assert sorted(statuses) == ["LIMIT", "OK"]
    assert len(repository.list_sensor_pcaps()) == 1


def test_memory_sensor_pcap_limited_save_is_idempotent() -> None:
    repository = MemoryRepository()
    segment = {
        "id": "segment-a",
        "sensor_id": "sensor-a",
        "analysis_job_id": "job-a",
        "filename": "job-a--eth0.pcap",
        "size_bytes": 4,
        "sha256": "digest",
        "uploaded_at": "2026-08-07T00:00:00+00:00",
    }
    assert repository.save_sensor_pcap_limited(segment, b"pcap", 4)[1] == "OK"
    assert repository.save_sensor_pcap_limited(segment, b"pcap", 4)[1] == "EXISTS"
