"""Real network fixture timing stays consistent through strict HTTP ingress."""

import struct
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.encoders import jsonable_encoder
from fastapi.testclient import TestClient
from pydantic import ValidationError
from test_durable_pipeline import AGENT_HEADERS, QueueStub, register_sensor

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import FlowRecord
from c2hunter_controller.storage import MemoryFlowStore


@pytest.fixture
def packet_fixture(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[2] / "analysis/tests"))
    import test_network_anomaly

    return test_network_anomaly


@pytest.mark.parametrize("count", [0, 1, 12])
def test_default_capture_bytes_are_unchanged(packet_fixture, count):
    frames = [packet_fixture.frame(payload=bytes([index])) for index in range(count)]
    expected = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate(frames):
        seconds, micros = divmod(index * 100000, 1000000)
        expected += struct.pack("<IIII", 1 + seconds, micros, len(packet), len(packet)) + packet
    assert packet_fixture.capture(*frames) == expected


@pytest.mark.parametrize(
    "timing, expected_us",
    [
        ({}, [1_000_000, 1_100_000]),
        (
            {"start_time": datetime(2026, 1, 1, tzinfo=UTC), "interval": timedelta(0)},
            [1_767_225_600_000_000, 1_767_225_600_000_000],
        ),
        (
            {
                "start_time": datetime(2026, 1, 1, tzinfo=UTC),
                "interval": timedelta(seconds=1),
            },
            [1_767_225_600_000_000, 1_767_225_601_000_000],
        ),
        (
            {
                "start_time": datetime(2026, 1, 1, microsecond=999999, tzinfo=UTC),
                "interval": timedelta(microseconds=1),
            },
            [1_767_225_600_999_999, 1_767_225_601_000_000],
        ),
    ],
    ids=["original", "same-instant", "one-second", "microsecond-rollover"],
)
def test_packet_header_record_and_sidecar_timestamps_agree(packet_fixture, timing, expected_us):
    frames = [packet_fixture.frame(), packet_fixture.frame()]
    raw = packet_fixture.capture(*frames, **timing)
    offset = 24
    for packet, timestamp_us in zip(frames, expected_us, strict=True):
        seconds, micros, captured, original = struct.unpack_from("<IIII", raw, offset)
        assert seconds * 1_000_000 + micros == timestamp_us
        assert captured == original == len(packet)
        assert raw[offset + 16 : offset + 16 + captured] == packet
        offset += 16 + captured
    assert offset == len(raw)

    parsed = packet_fixture.records(*frames, **timing)
    assert len(parsed) == 2
    for record, timestamp_us in zip(parsed, expected_us, strict=True):
        assert record["timestamp"] == datetime(1970, 1, 1, tzinfo=UTC) + timedelta(
            microseconds=timestamp_us
        )
        assert record["packet_evidence_complete"] is True
        assert record["ddos_packet_evidence"]["samples"][0]["timestamp_us"] == timestamp_us
        assert (
            FlowRecord.model_validate(record).ddos_packet_evidence == record["ddos_packet_evidence"]
        )

    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False),
            MemoryRepository(),
            flow_store=MemoryFlowStore(),
            queue=QueueStub(),
        )
    )
    register_sensor(client)
    response = client.post(
        "/api/v1/sensors/s1/flow-batches",
        headers=AGENT_HEADERS,
        json={"batch_id": "consistent", "records": jsonable_encoder(parsed)},
    )
    assert response.status_code == 202, response.text
    assert response.json()["record_count"] == 2

    # Retiming only the record must still fail; never drop or repair its evidence.
    malformed = deepcopy(parsed)
    for record in malformed:
        record["timestamp"] += timedelta(seconds=61)
        with pytest.raises(ValidationError, match="DDoS sample outside flow interval"):
            FlowRecord.model_validate(record)
    response = client.post(
        "/api/v1/sensors/s1/flow-batches",
        headers=AGENT_HEADERS,
        json={"batch_id": "retimed-record-only", "records": jsonable_encoder(malformed)},
    )
    assert response.status_code == 422
    assert "DDoS sample outside flow interval" in response.text
