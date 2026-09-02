from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from c2hunter_analysis.ai_candidates import PREFILTER_VERSION, generate_high_recall_candidates
from c2hunter_analysis.domain import AnalysisContext, Flow

START = datetime(2026, 8, 9, tzinfo=UTC)


def flow(
    second: float,
    host: str,
    peer: str,
    *,
    port: int = 443,
    protocol: str = "TCP",
    packets: int = 1,
    total_bytes: int = 128,
    payload_hash: str | None = None,
    last_payload_hash: str | None = None,
    flags: dict[str, int] | None = None,
) -> Flow:
    # 테스트는 외부 peer로 향하는 outbound Flow만 만들어 feature 차이를 격리한다.
    return Flow(
        sensor_id="sensor-a",
        timestamp=START + timedelta(seconds=second),
        source_ip=host,
        destination_ip=peer,
        source_port=50000,
        destination_port=port,
        protocol=protocol,
        direction="OUTBOUND",
        packet_count=packets,
        total_bytes=total_bytes,
        payload_hash=payload_hash,
        last_payload_hash=last_payload_hash,
        tcp_flags=flags,
    )


def context(flows: list[Flow]) -> AnalysisContext:
    # 모든 fixture가 같은 분석 범위를 사용해야 순위가 재현 가능하다.
    return AnalysisContext(
        dataset_id="phase-3-fixtures",
        start=START,
        end=START + timedelta(hours=2),
        flows=flows,
        selected_sensors=("sensor-a",),
    )


def fixture_flows(name: str) -> tuple[list[Flow], str, set[str]]:
    # AI-A~AI-J는 각 feature/penalty가 독립적으로 설명되는 최소 회귀 fixture다.
    peer = f"203.0.113.{ord(name[-1]) - 64}"
    if name == "AI-A":
        return (
            [flow(index * 30, "10.0.0.1", peer) for index in range(6)],
            peer,
            {"SINGLE_HOST_BEACON"},
        )
    if name == "AI-B":
        flows = [flow(index * 11, "10.0.0.1", peer, payload_hash="same") for index in range(5)]
        return flows, peer, {"PAYLOAD_CLUSTER"}
    if name == "AI-C":
        return (
            [flow(30, f"10.0.0.{index}", peer) for index in range(1, 5)],
            peer,
            {"SYNCHRONIZED_CLUSTER"},
        )
    if name == "AI-D":
        anomalous = [flow(index, "10.0.0.1", peer, total_bytes=5000) for index in range(20)]
        background = [flow(index, "10.0.0.2", f"198.51.100.{index}") for index in range(1, 8)]
        return anomalous + background, peer, {"ROBUST_ANOMALY"}
    if name == "AI-E":
        return [flow(1, "10.0.0.1", peer)], peer, {"PEER_BASELINE"}
    if name == "AI-F":
        return (
            [flow(index * 30, "10.0.0.1", peer) for index in range(6)],
            peer,
            {"TRUSTED_PEER_PENALTY"},
        )
    if name == "AI-G":
        flows = [flow(index * 17, "10.0.0.1", peer, port=53, protocol="UDP") for index in range(5)]
        return flows, peer, {"COMMON_SERVICE_PENALTY"}
    if name == "AI-H":
        return (
            [
                flow(index * 3, "10.0.0.1", peer, packets=30000, total_bytes=20_000_000)
                for index in range(5)
            ],
            peer,
            {"HIGH_VOLUME_PENALTY"},
        )
    if name == "AI-I":
        return (
            [
                flow(index * 30, host, peer)
                for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3")
                for index in range(5)
            ],
            peer,
            {"SINGLE_HOST_BEACON", "SYNCHRONIZED_CLUSTER"},
        )
    return (
        [
            flow(index * 13, "10.0.0.1", peer, protocol="UDP", payload_hash="udp-cluster")
            for index in range(5)
        ],
        peer,
        {"PAYLOAD_CLUSTER"},
    )


@pytest.mark.parametrize("name", [f"AI-{letter}" for letter in "ABCDEFGHIJ"])
def test_named_high_recall_fixtures_are_explainable(name: str) -> None:
    flows, peer, expected_factors = fixture_flows(name)
    trusted = {peer} if name == "AI-F" else set()

    candidate = next(
        item
        for item in generate_high_recall_candidates(context(flows), trusted_peers=trusted)
        if item.candidate_ip == peer
    )

    assert candidate.score_version == PREFILTER_VERSION
    assert 0 <= candidate.prefilter_score <= 100
    assert expected_factors <= {factor.name for factor in candidate.factors}
    assert all(factor.explanation and factor.metrics for factor in candidate.factors)


def test_known_malicious_fixture_is_ranked_in_top_twenty_deterministically() -> None:
    malicious_peer = "203.0.113.250"
    flows = [
        flow(index * 29, "10.0.0.10", malicious_peer, payload_hash="malicious-cluster")
        for index in range(8)
    ]
    flows.extend(flow(index * 7 + 1, "10.0.0.20", f"198.51.100.{index}") for index in range(1, 31))

    first = generate_high_recall_candidates(context(flows), limit=20)
    second = generate_high_recall_candidates(context(list(reversed(flows))), limit=20)

    assert malicious_peer in [candidate.candidate_ip for candidate in first]
    assert [candidate.candidate_ip for candidate in first] == [
        candidate.candidate_ip for candidate in second
    ]
    assert all(candidate.factors for candidate in first)


def test_benign_penalties_reduce_score_without_hiding_explanations() -> None:
    peer = "203.0.113.53"
    flows = [flow(index * 30, "10.0.0.1", peer, port=53, protocol="UDP") for index in range(6)]

    unpenalized = generate_high_recall_candidates(context(flows))[0]
    trusted = generate_high_recall_candidates(context(flows), trusted_peers={peer})[0]

    assert trusted.prefilter_score < unpenalized.prefilter_score
    assert any(factor.points < 0 for factor in trusted.factors)


@pytest.mark.parametrize("flag", ["syn", "fin", "rst"])
def test_outbound_tcp_control_flood_is_not_recommended_as_a_c2_candidate(
    flag: str,
) -> None:
    peer = "203.0.113.200"
    flows = [
        flow(
            index / 10,
            "10.0.0.10",
            peer,
            packets=20,
            total_bytes=1_200,
            flags={flag: 20},
        )
        for index in range(6)
    ]

    assert generate_high_recall_candidates(context(flows)) == []


def test_acknowledged_or_payload_bearing_control_traffic_remains_recommendable() -> None:
    acknowledged_peer = "203.0.113.201"
    payload_peer = "203.0.113.202"
    flows = [
        flow(
            index / 10,
            "10.0.0.10",
            acknowledged_peer,
            packets=20,
            flags={"syn": 20, "ack": 20},
        )
        for index in range(6)
    ]
    flows.extend(
        flow(
            index / 10,
            "10.0.0.11",
            payload_peer,
            packets=20,
            payload_hash="c2-payload",
            flags={"fin": 20},
        )
        for index in range(6)
    )

    candidates = generate_high_recall_candidates(context(flows))

    assert {candidate.candidate_ip for candidate in candidates} == {
        acknowledged_peer,
        payload_peer,
    }


def test_slow_periodic_syn_retries_are_not_treated_as_an_attack_burst() -> None:
    peer = "203.0.113.203"
    flows = [
        flow(
            index * 30,
            "10.0.0.10",
            peer,
            flags={"syn": 1},
        )
        for index in range(40)
    ]

    assert [
        candidate.candidate_ip for candidate in generate_high_recall_candidates(context(flows))
    ] == [peer]


def test_control_flood_does_not_hide_payload_bearing_udp_to_same_peer() -> None:
    peer = "203.0.113.204"
    flood = [
        flow(
            index / 10,
            "10.0.0.10",
            peer,
            packets=20,
            flags={"syn": 20},
        )
        for index in range(6)
    ]
    udp_c2 = [
        flow(
            index * 30,
            "10.0.0.11",
            peer,
            protocol="UDP",
            payload_hash="udp-c2",
        )
        for index in range(6)
    ]

    candidate = generate_high_recall_candidates(context([*flood, *udp_c2]))[0]
    baseline = next(factor for factor in candidate.factors if factor.name == "PEER_BASELINE")

    assert candidate.candidate_ip == peer
    assert baseline.metrics["flow_count"] == len(udp_c2)


def test_last_payload_hash_prevents_control_flow_suppression() -> None:
    peer = "203.0.113.205"
    flows = [
        flow(
            index / 10,
            "10.0.0.10",
            peer,
            packets=20,
            last_payload_hash="last-payload",
            flags={"fin": 20},
        )
        for index in range(6)
    ]

    assert [
        candidate.candidate_ip for candidate in generate_high_recall_candidates(context(flows))
    ] == [peer]
