from datetime import UTC, datetime, timedelta

import pytest

from c2hunter_analysis.domain import AnalysisContext, Flow
from c2hunter_analysis.traffic_suppression import is_outbound_control_flood

START = datetime(2026, 8, 28, tzinfo=UTC)
HOST = "10.0.0.10"
PEER = "203.0.113.200"


def flow(
    *,
    second: float = 0,
    direction: str = "OUTBOUND",
    packets: int = 40,
    flags: dict[str, int] | None = None,
    payload: bool = False,
    last_payload: bool = False,
    duration: float = 0,
) -> Flow:
    source_ip, destination_ip = (HOST, PEER) if direction != "INBOUND" else (PEER, HOST)
    return Flow(
        sensor_id="sensor-a",
        timestamp=START + timedelta(seconds=second),
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=50000 if direction != "INBOUND" else 443,
        destination_port=443 if direction != "INBOUND" else 50000,
        protocol="TCP",
        direction=direction,
        packet_count=packets,
        total_bytes=packets * 60,
        payload_hash="payload" if payload else None,
        last_payload_hash="last-payload" if last_payload else None,
        duration_seconds=duration,
        tcp_flags=flags,
    )


def context(flows: list[Flow]) -> AnalysisContext:
    return AnalysisContext(
        dataset_id="control-flood",
        start=START,
        end=START + timedelta(hours=1),
        flows=flows,
        internal_cidrs=("10.0.0.0/8",),
    )


@pytest.mark.parametrize("flag", ["syn", "fin", "rst"])
def test_bursty_outbound_control_flags_are_suppressed(flag: str) -> None:
    flows = [flow(second=index / 10, flags={flag.upper(): 40}) for index in range(3)]

    assert is_outbound_control_flood(context(flows), flows) is True


@pytest.mark.parametrize(
    "flows",
    [
        [flow(packets=31, flags={"syn": 31})],
        [
            flow(second=0, packets=20, flags={"syn": 20}),
            flow(second=30, packets=20, flags={"syn": 20}),
        ],
        [flow(flags={"syn": 40, "ack": 9})],
        [flow(flags={"syn": 40}), flow(direction="INBOUND", packets=9, flags={"ack": 9})],
        [flow(flags={"fin": 40}, payload=True)],
    ],
    ids=["below-minimum", "slow-rate", "acknowledged", "peer-replied", "payload-bearing"],
)
def test_legitimate_or_ambiguous_control_traffic_is_preserved(flows: list[Flow]) -> None:
    assert is_outbound_control_flood(context(flows), flows) is False


def test_unknown_direction_uses_network_roles_for_outbound_suppression() -> None:
    flows = [flow(second=index / 10, direction="UNKNOWN", flags={"syn": 40}) for index in range(3)]

    assert is_outbound_control_flood(context(flows), flows) is True


def test_inbound_control_flood_source_remains_a_candidate_peer() -> None:
    flows = [flow(second=index / 10, direction="INBOUND", flags={"syn": 40}) for index in range(3)]

    assert is_outbound_control_flood(context(flows), flows) is False


def test_single_aggregate_without_duration_cannot_prove_attack_rate() -> None:
    flows = [flow(packets=32, flags={"syn": 32})]

    assert is_outbound_control_flood(context(flows), flows) is False


def test_exact_rate_boundary_uses_stable_duration_arithmetic() -> None:
    exact = [flow(packets=32, flags={"syn": 32}, duration=6.4)]
    below = [flow(packets=32, flags={"syn": 32}, duration=6.400001)]

    assert is_outbound_control_flood(context(exact), exact) is True
    assert is_outbound_control_flood(context(below), below) is False


def test_disjoint_control_flag_counts_contribute_to_packet_union() -> None:
    flows = [flow(packets=40, flags={"syn": 20, "fin": 20}, duration=1)]

    assert is_outbound_control_flood(context(flows), flows) is True


def test_flag_counts_are_clamped_to_packet_count() -> None:
    flows = [flow(packets=31, flags={"syn": 1_000}, duration=1)]

    assert is_outbound_control_flood(context(flows), flows) is False


def test_last_payload_hash_preserves_control_bearing_flow() -> None:
    flows = [flow(second=index / 10, flags={"fin": 40}, last_payload=True) for index in range(3)]

    assert is_outbound_control_flood(context(flows), flows) is False


@pytest.mark.parametrize("duration", [float("inf"), 1e308])
def test_invalid_direct_flow_duration_fails_open_without_crashing(duration: float) -> None:
    flows = [flow(flags={"syn": 40}, duration=duration)]

    assert is_outbound_control_flood(context(flows), flows) is False
