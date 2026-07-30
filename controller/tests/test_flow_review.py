from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.flow_review import filter_flows
from c2hunter_controller.repositories import MemoryRepository


def _job() -> dict[str, object]:
    return {
        "id": "job-flow-filter",
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": [
            {
                "sensor_id": "s1",
                "timestamp": "2026-07-30T00:00:00+00:00",
                "source_ip": "10.0.0.1",
                "destination_ip": "203.0.113.10",
                "source_port": 50000,
                "destination_port": 443,
                "protocol": "TCP",
                "direction": "OUTBOUND",
            },
            {
                "sensor_id": "s1",
                "timestamp": "2026-07-30T00:00:01+00:00",
                "source_ip": "10.0.0.2",
                "destination_ip": "203.0.113.10",
                "source_port": 50001,
                "destination_port": 80,
                "protocol": "TCP",
                "direction": "OUTBOUND",
            },
            {
                "sensor_id": "s1",
                "timestamp": "2026-07-30T00:00:02+00:00",
                "source_ip": "10.0.0.3",
                "destination_ip": "198.51.100.20",
                "source_port": 50002,
                "destination_port": 443,
                "protocol": "TCP",
                "direction": "OUTBOUND",
            },
        ],
    }


def test_filter_flows_excludes_only_records_matching_all_conditions() -> None:
    result = filter_flows(
        _job(),
        candidate_ip="203.0.113.10",
        destination_port=443,
        exclude_matches=True,
    )

    assert [(flow["destination_ip"], flow["destination_port"]) for flow in result] == [
        ("203.0.113.10", 80),
        ("198.51.100.20", 443),
    ]


def test_filter_flows_rejects_exclusion_without_active_conditions() -> None:
    calls = (
        lambda: filter_flows(_job(), exclude_matches=True),
        lambda: filter_flows(_job(), exclude_matches=True, candidate_ip=""),
        lambda: filter_flows(_job(), exclude_matches=True, direction=""),
        lambda: filter_flows(_job(), exclude_matches=True, protocol=""),
    )
    for call in calls:
        try:
            call()
        except ValueError as exc:
            assert "exclusion condition" in str(exc)
        else:
            raise AssertionError("conditionless exclusion was accepted")


def test_flow_api_exposes_exclusion_mode_and_requires_a_condition() -> None:
    repository = MemoryRepository()
    repository.save_job(_job())
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get(
        "/api/v1/analysis-jobs/job-flow-filter/flows",
        params={
            "candidate_ip": "203.0.113.10",
            "destination_port": 443,
            "exclude_matches": True,
        },
    )
    assert response.status_code == 200
    assert response.json()["total"] == 2

    invalid = client.get(
        "/api/v1/analysis-jobs/job-flow-filter/flows",
        params={"exclude_matches": True, "candidate_ip": ""},
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "INVALID_FLOW_EXCLUSION"
