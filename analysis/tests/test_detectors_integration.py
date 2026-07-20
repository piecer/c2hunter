from datetime import UTC, datetime, timedelta

from c2hunter_analysis.detectors import (
    CommandAttackDetector,
    CommonDestinationDetector,
    MultiSensorDetector,
    PeriodicBeaconDetector,
    PersistenceRarityDetector,
    ProtocolSimilarityDetector,
    SynchronizedCommunicationDetector,
    run_detectors,
)
from c2hunter_analysis.domain import AnalysisContext, Flow
from c2hunter_analysis.scoring import score_candidates

START = datetime(2026, 7, 20, tzinfo=UTC)
C2 = "203.0.113.44"


def flow(
    second: float,
    host: str,
    *,
    sensor: str = "s1",
    destination: str = C2,
    direction: str = "OUTBOUND",
    packets: int = 1,
    size: int = 60,
    port: int = 4444,
    payload: str | None = "sig",
) -> Flow:
    if direction == "INBOUND":
        return Flow(
            sensor,
            START + timedelta(seconds=second),
            destination,
            host,
            port,
            50000,
            "TCP",
            direction,
            packets,
            size,
            payload,
        )
    return Flow(
        sensor,
        START + timedelta(seconds=second),
        host,
        destination,
        50000,
        port,
        "TCP",
        direction,
        packets,
        size,
        payload,
    )


def context(flows: list[Flow], **parameters: object) -> AnalysisContext:
    return AnalysisContext(
        "dataset", START, START + timedelta(minutes=20), flows, parameters=parameters
    )


def test_common_destination_requires_multiple_internal_hosts() -> None:
    flows = [flow(i, f"10.0.0.{i}") for i in range(1, 6)]
    evidence = CommonDestinationDetector().analyze(context(flows, minimum_distinct_clients=3))
    assert evidence[0].candidate_ip == C2
    assert evidence[0].metrics["distinct_hosts"] == 5
    assert 0 < evidence[0].contribution <= 20
    assert (
        CommonDestinationDetector().analyze(
            context([flow(1, "10.0.0.1")], minimum_distinct_clients=3)
        )
        == []
    )


def test_periodic_beacon_accepts_jitter_and_rejects_irregular_samples() -> None:
    periodic = [flow(index * 30 + (-2 if index % 2 else 2), "10.0.0.1") for index in range(8)]
    evidence = PeriodicBeaconDetector().analyze(context(periodic, periodicity_min_samples=5))
    assert evidence[0].metrics["period_seconds"] == 30.0
    assert evidence[0].metrics["coefficient_of_variation"] < 0.2
    irregular = [flow(value, "10.0.0.1") for value in (1, 4, 40, 45, 180, 190)]
    assert PeriodicBeaconDetector().analyze(context(irregular, periodicity_min_samples=5)) == []


def test_periodic_beacon_preserves_meaningful_sub_five_second_period() -> None:
    short_period = [flow(index, "10.0.0.1") for index in range(5)]

    evidence = PeriodicBeaconDetector().analyze(context(short_period, periodicity_min_samples=5))

    assert evidence[0].metrics["period_seconds"] == 1.0
    assert evidence[0].metrics["matching_hosts"] == 1


def test_synchronization_needs_repeated_multi_host_windows() -> None:
    flows = [
        flow(base + offset / 10, f"10.0.0.{offset + 1}")
        for base in (10, 40, 70)
        for offset in range(4)
    ]
    evidence = SynchronizedCommunicationDetector().analyze(
        context(flows, synchronization_window_seconds=2)
    )
    assert evidence[0].metrics["repetition_count"] == 3
    assert evidence[0].metrics["synchronized_hosts"] == 4


def test_command_then_attack_correlates_direction_target_and_increase() -> None:
    commands = [flow(10, f"10.0.0.{i}", direction="INBOUND", size=40) for i in range(1, 5)]
    baseline = [flow(5, f"10.0.0.{i}", destination="198.51.100.99", packets=1) for i in range(1, 5)]
    attacks = [
        flow(12, f"10.0.0.{i}", destination="198.51.100.99", packets=100, size=6000, port=53)
        for i in range(1, 5)
    ]
    evidence = CommandAttackDetector().analyze(
        context(commands + baseline + attacks, minimum_distinct_clients=3)
    )
    assert evidence[0].candidate_ip == C2
    assert evidence[0].metrics["attack_target"] == "198.51.100.99"
    assert evidence[0].metrics["increase_ratio"] >= 100
    unknown = [Flow(**{**item.__dict__, "direction": "UNKNOWN"}) for item in commands]
    assert (
        CommandAttackDetector().analyze(context(unknown + attacks, minimum_distinct_clients=3))
        == []
    )


def test_persistence_similarity_and_multi_sensor_use_real_flow_features() -> None:
    flows = [
        flow(index * 120, f"10.0.0.{host}", sensor=sensor)
        for index in range(6)
        for host in range(1, 4)
        for sensor in ("s1", "s2")
    ]
    persistence = PersistenceRarityDetector().analyze(context(flows, minimum_distinct_clients=3))
    similarity = ProtocolSimilarityDetector().analyze(context(flows, minimum_distinct_clients=3))
    multi = MultiSensorDetector().analyze(context(flows, minimum_distinct_clients=3))
    assert persistence[0].metrics["duration_seconds"] >= 600
    assert similarity[0].metrics["dominant_feature_ratio"] == 1.0
    assert multi[0].metrics["distinct_sensors"] == 2
    assert multi[0].metrics["independent_hosts"] == 3


def test_synthetic_pipeline_combines_all_detector_evidence() -> None:
    flows = [
        flow(index * 30, f"10.0.0.{host}", sensor=("s1", "s2")[host % 2])
        for index in range(8)
        for host in range(1, 7)
    ]
    evidence = run_detectors(context(flows, minimum_distinct_clients=3, periodicity_min_samples=5))
    candidate = score_candidates(evidence, minimum_samples=5)[0]
    assert candidate.candidate_ip == C2
    assert candidate.score >= 60
    assert {item.type for item in candidate.evidence} >= {
        "COMMON_DESTINATION",
        "PERIODIC_BEACON",
        "SYNCHRONIZED_COMMUNICATION",
        "PROTOCOL_PAYLOAD_SIMILARITY",
        "MULTI_SENSOR_CONTEXT",
    }
