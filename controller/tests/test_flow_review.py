import json
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.flow_review import (
    decorate_flow,
    filter_flows,
    flow_id,
    label_snapshot,
    payload_ascii,
)
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


def test_filter_flows_combines_multiple_include_and_exclude_groups() -> None:
    result = filter_flows(
        _job(),
        include_filters=[
            {"candidate_ip": "203.0.113.10", "destination_port": 80},
            {"candidate_ip": "198.51.100.20", "destination_port": 443},
        ],
        exclude_filters=[{"candidate_ip": "198.51.100.20"}],
    )

    assert [(flow["destination_ip"], flow["destination_port"]) for flow in result] == [
        ("203.0.113.10", 80)
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


def test_flow_api_accepts_repeated_include_and_exclude_filters() -> None:
    repository = MemoryRepository()
    repository.save_job(_job())
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get(
        "/api/v1/analysis-jobs/job-flow-filter/flows",
        params=[
            ("include_filter", json.dumps({"protocol": "TCP"})),
            ("exclude_filter", json.dumps({"candidate_ip": "203.0.113.10"})),
            ("exclude_filter", json.dumps({"candidate_ip": "198.51.100.20"})),
        ],
    )

    assert response.status_code == 200
    assert response.json()["total"] == 0


def test_flow_api_rejects_empty_structured_filter_group() -> None:
    repository = MemoryRepository()
    repository.save_job(_job())
    client = TestClient(create_app(Settings(environment="test"), repository))

    response = client.get(
        "/api/v1/analysis-jobs/job-flow-filter/flows",
        params={"exclude_filter": json.dumps({"candidate_ip": ""})},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_ENDPOINT_FILTER"


@pytest.mark.parametrize(
    ("direction", "source_ip", "destination_ip", "external_ip", "service_port"),
    [
        ("INBOUND", "203.0.113.10", "10.0.0.1", "203.0.113.10", 443),
        ("UNKNOWN", "10.0.0.1", "203.0.113.10", "203.0.113.10", 8443),
        ("UNKNOWN", "203.0.113.10", "10.0.0.1", "203.0.113.10", 443),
        ("UNKNOWN", "203.0.113.10", "198.51.100.20", None, None),
    ],
)
def test_decorate_flow_resolves_endpoint_roles(
    direction: str,
    source_ip: str,
    destination_ip: str,
    external_ip: str | None,
    service_port: int | None,
) -> None:
    flow = decorate_flow(
        "job",
        {
            "sensor_id": "sensor",
            "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_port": 443,
            "destination_port": 8443,
            "protocol": "TCP",
            "direction": direction,
            "packet_sizes": (64, 128),
        },
        ["10.0.0.0/8"],
    )

    assert flow["external_ip"] == external_ip
    assert flow["service_port"] == service_port
    assert flow["packet_sizes"] == [64, 128]


@pytest.mark.parametrize(
    ("flow_filter", "message"),
    [
        ({"unsupported": True}, "supported conditions"),
        ({"direction": "SIDEWAYS"}, "unsupported flow direction"),
        ({"protocol": "x" * 33}, "protocol is too long"),
        ({"port": 65536}, "between 0 and 65535"),
        ({"source_port": True}, "between 0 and 65535"),
        ({"has_payload": "yes"}, "must be boolean"),
    ],
)
def test_filter_flows_rejects_invalid_structured_conditions(
    flow_filter: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        filter_flows(_job(), include_filters=[flow_filter])


def test_filter_flows_uses_latest_label_and_all_match_dimensions() -> None:
    job = _job()
    first = dict(job["flow_records"][0])  # type: ignore[index]
    identifier = flow_id(str(job["id"]), first)
    labels = [
        {"flow_id": identifier, "label": "benign", "created_at": "2026-01-01"},
        {"flow_id": identifier, "label": "suspicious", "created_at": "2026-01-02"},
    ]

    result = filter_flows(
        job,
        labels=labels,
        direction="outbound",
        protocol="tcp",
        port=443,
        source_port=50000,
        destination_port=443,
        has_payload=False,
    )

    assert len(result) == 1
    assert result[0]["current_label"]["label"] == "suspicious"
    assert label_snapshot(result[0])["external_ip"] == "203.0.113.10"


def test_payload_ascii_and_flow_id_normalize_display_and_timestamps() -> None:
    assert payload_ascii("410d0a090042") == "A\\r\\n\\t.B"
    record = dict(_job()["flow_records"][0])  # type: ignore[index]
    record["timestamp"] = "2026-07-30T00:00:00Z"
    normalized = flow_id("job", record)
    record["timestamp"] = datetime(2026, 7, 30, tzinfo=UTC)
    assert flow_id("job", record) == normalized
    record["timestamp"] = "not-a-timestamp"
    assert flow_id("job", record) != normalized
