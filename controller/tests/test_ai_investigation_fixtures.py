"""Exact real-producer witnesses shared with future Web/worker consumers."""

from pathlib import Path

import pytest

from c2hunter_controller.ai_investigation_contract import (
    Evidence,
    InvestigationScope,
    canonical_bytes,
)
from c2hunter_controller.ai_investigation_evidence import EvidenceService
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_producers import go_rows, pcap_row, producer_job, producer_row

TOOLS = (
    "peer_overview",
    "peer_timeline",
    "peer_flow_samples",
    "peer_protocol_observations",
    "compare_peer_cohort",
)


def producer_fixtures() -> dict[str, bytes]:
    repo = MemoryRepository()
    repo.save_job(
        producer_job(
            [
                pcap_row(
                    protocol=17,
                    dport=53,
                    payload=(
                        b"\x00\x01\x01\x00\x00\x01"
                        + b"\x00" * 6
                        + b"\x07updates\x07example\x04test\x00\x00\x01\x00\x01"
                    ),
                ),
                pcap_row(flags=16, inbound=True),
                pcap_row(flags=2),
                *go_rows(),
                producer_row(source_ip="10.0.0.2"),
            ]
        )
    )
    service = EvidenceService(
        repo.read_investigation_source("job"), InvestigationScope(target_ip="10.0.0.1")
    )
    return {tool: canonical_bytes(service.call(tool, {}).model_dump(mode="json")) for tool in TOOLS}


@pytest.mark.parametrize("tool", TOOLS)
def test_real_producer_wire_fixture(tool: str) -> None:
    expected = producer_fixtures()[tool]
    saved = Path(__file__).parent / "fixtures" / "ai_investigation" / (tool + ".json")
    assert saved.read_bytes() == expected + b"\n"
    assert len(expected) <= 32768
    assert (
        canonical_bytes(Evidence.model_validate_json(expected).model_dump(mode="json")) == expected
    )
