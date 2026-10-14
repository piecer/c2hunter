"""Real producer wire regressions for the stage-1 evidence boundary."""

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from fastapi.testclient import TestClient
from test_durable_pipeline import AGENT_HEADERS, AGENT_TOKEN, QueueStub, sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import FlowRecord
from c2hunter_controller.storage import MemoryFlowStore

FIXTURES = Path(__file__).parents[2] / "analysis/tests/fixtures"
WIRES = json.loads((FIXTURES / "ddos-live-timestamp-boundaries.json").read_text())


@pytest.fixture
def ingress():
    repository = MemoryRepository()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            repository,
            flow_store=MemoryFlowStore(),
            queue=QueueStub(),
        )
    )
    for sensor_id in {"fixture", "review"}:
        repository.upsert_sensor({"sensor_id": sensor_id})
        repository.save_sensor_credential(
            {
                "sensor_id": sensor_id,
                "token_hash": hashlib.sha256(AGENT_TOKEN.encode()).hexdigest(),
            }
        )
        assert (
            client.post(
                "/api/v1/sensors/register",
                json={**sensor(), "sensor_id": sensor_id},
                headers=AGENT_HEADERS,
            ).status_code
            == 201
        )
    return client


@pytest.mark.parametrize("name", sorted(WIRES))
def test_go_timestamp_wire_through_authenticated_ingress_and_analyzer(ingress, name):
    raw = WIRES[name]["flows"][0]
    assert analyze_ddos_attack([raw])["summary"]["evaluated_records"] == 1
    for sidecar in (True, False):
        row = {k: v for k, v in raw.items() if sidecar or k != "ddos_packet_evidence"}
        response = ingress.post(
            f"/api/v1/sensors/{raw['sensor_id']}/flow-batches",
            json={
                "batch_id": f"{name}-{sidecar}",
                "records": [row],
            },
            headers=AGENT_HEADERS,
        )
        assert response.status_code == 202, response.text
        admitted = FlowRecord.model_validate(row).model_dump(mode="json")
        assert admitted["duration_seconds"] == raw["duration_seconds"]
        result = analyze_ddos_attack([admitted])
        assert result["summary"]["evaluated_records"] == 1
        assert admitted["packet_count"] == raw["packet_count"]
        assert result["summary"]["packet_count"] == raw["packet_count"]


@pytest.mark.parametrize(
    "name", ["micro", "nano_long", "nano_short", "micro_rollover", "second_rollover"]
)
@pytest.mark.parametrize("offset", [-1, 2])
def test_timestamp_true_out_of_interval_rejected(ingress, offset, name):
    raw = deepcopy(WIRES[name]["flows"][0])
    samples = raw["ddos_packet_evidence"]["samples"]
    samples[0]["timestamp_us"] = samples[0 if offset < 0 else -1]["timestamp_us"] + offset
    response = ingress.post(
        "/api/v1/sensors/fixture/flow-batches",
        json={
            "batch_id": f"invalid-{offset}",
            "records": [raw],
        },
        headers=AGENT_HEADERS,
    )
    assert response.status_code == 422
    assert "DDoS sample outside flow interval" in response.text


CORPUS = json.loads(
    (Path(__file__).parents[2] / "web/tests/fixtures/ddos-correction-corpus.json").read_text()
)


@pytest.mark.parametrize("case", CORPUS, ids=lambda case: case["name"])
def test_shared_serialized_report_publication_contract(case):
    from c2hunter_controller.app import _validated_ddos_report

    document = json.loads(json.dumps(case["report"]))
    if case["accepted"]:
        published = _validated_ddos_report(document)
        assert published["version"] == document["version"]
        assert [f["id"] for f in published["findings"]] == [f["id"] for f in document["findings"]]
        for raw, saved in zip(document["findings"], published["findings"], strict=True):
            assert saved.get("classification") == raw.get("classification")
    else:
        with pytest.raises(ValueError) as error:
            _validated_ddos_report(document)
        if case["reason"]:
            assert case["reason"] in str(error.value)


def test_reverse_loss_qualification_survives_publication_and_ai():
    from c2hunter_controller.app import _validated_ddos_report
    from c2hunter_controller.ddos_ai import build_ddos_input

    case = next(c for c in CORPUS if c["name"] == "producer/reverse-request-loss")
    published = _validated_ddos_report(case["report"])
    for language in ("ko", "en"):
        projected = build_ddos_input(published, language)
        c = projected["findings"][0]["classification"]
        assert c == published["findings"][0]["classification"]
        assert c["evidence"]["coverage_limited"] is True
        assert c["axes"]["delivery_mechanism"]["confidence"] == "low"
        assert "EVIDENCE_COVERAGE_LIMITED" in c["axes"]["delivery_mechanism"]["unknown_codes"]
