from datetime import UTC, datetime, timedelta

from c2hunter_analysis.detectors import (
    PeriodicBeaconDetector,
    PopulationAnomalyDetector,
    SingleHostCompositeBeaconDetector,
    run_detectors,
)
from c2hunter_analysis.domain import AnalysisContext, Flow

START = datetime(2026, 7, 20, tzinfo=UTC)


def flow(
    second: float,
    host: str,
    destination: str,
    *,
    port: int = 443,
    size: int = 500,
    payload: str | None = None,
    direction: str = "OUTBOUND",
) -> Flow:
    if direction == "INBOUND":
        return Flow(
            "s1",
            START + timedelta(seconds=second),
            destination,
            host,
            port,
            50000,
            "TCP",
            direction,
            1,
            size,
            payload,
        )
    return Flow(
        "s1",
        START + timedelta(seconds=second),
        host,
        destination,
        50000,
        port,
        "TCP",
        direction,
        1,
        size,
        payload,
    )


def context(flows: list[Flow], **parameters: object) -> AnalysisContext:
    return AnalysisContext(
        "dataset",
        START,
        START + timedelta(minutes=30),
        flows,
        parameters=parameters,
    )


def _timeline(
    host: str,
    destination: str,
    gaps: list[int],
    sizes: list[int],
    ports: list[int],
    payloads: list[str],
    *,
    direction: str = "OUTBOUND",
) -> list[Flow]:
    timestamps = [0.0]
    for gap in gaps:
        timestamps.append(timestamps[-1] + gap)
    return [
        flow(
            timestamp,
            host,
            destination,
            port=ports[index],
            size=sizes[index],
            payload=payloads[index],
            direction=direction,
        )
        for index, timestamp in enumerate(timestamps)
    ]


def _irregular_population(count: int) -> list[Flow]:
    gaps = [2, 47, 5, 91, 3, 60, 7]
    sizes = [200, 4800, 120, 3300, 90, 2600, 160, 4100]
    ports = [443, 80, 53, 123, 22, 443, 80, 53]
    flows: list[Flow] = []
    for index in range(count):
        flows.extend(
            _timeline(
                f"10.0.0.{index + 1}",
                f"198.51.100.{index + 10}",
                gaps,
                sizes,
                ports,
                [f"background-{index}-{sample}" for sample in range(8)],
            )
        )
    return flows


def _c2_like_outlier(
    host: str = "10.0.0.250",
    destination: str = "203.0.113.44",
    *,
    direction: str = "OUTBOUND",
) -> list[Flow]:
    # CV is about 0.320, deliberately above the existing <=0.30 beacon cutoff.
    gaps = [30, 45, 20, 40, 25, 45, 20]
    return _timeline(
        host,
        destination,
        gaps,
        [300] * 8,
        [443] * 8,
        ["stable-beacon-payload"] * 8,
        direction=direction,
    )


def test_detector_is_disabled_by_default() -> None:
    flows = _irregular_population(16) + _c2_like_outlier()
    assert PopulationAnomalyDetector().analyze(context(flows)) == []


def test_directional_population_signal_finds_rule_boundary_outlier() -> None:
    outlier = _c2_like_outlier()
    outlier_context = context(outlier, periodicity_min_samples=5)
    assert PeriodicBeaconDetector().analyze(outlier_context) == []
    assert SingleHostCompositeBeaconDetector().analyze(outlier_context) == []

    result = PopulationAnomalyDetector().analyze(
        context(
            _irregular_population(16) + outlier,
            ml_anomaly_enabled=True,
            ml_anomaly_min_population=16,
            ml_anomaly_z_threshold=3.5,
        )
    )

    assert len(result) == 1
    evidence = result[0]
    assert evidence.candidate_ip == "203.0.113.44"
    assert evidence.type == "ML_POPULATION_ANOMALY"
    assert 0 < evidence.contribution <= 5
    assert evidence.metrics["anomaly_score"] >= 3.5
    assert evidence.metrics["directional_feature_count"] >= 2
    assert "unsupervised_no_ground_truth" in evidence.warnings


def test_inbound_direction_uses_source_as_candidate() -> None:
    result = PopulationAnomalyDetector().analyze(
        context(
            _irregular_population(16)
            + _c2_like_outlier(
                host="10.0.0.250",
                destination="203.0.113.55",
                direction="INBOUND",
            ),
            ml_anomaly_enabled=True,
            ml_anomaly_min_population=16,
        )
    )
    assert [evidence.candidate_ip for evidence in result] == ["203.0.113.55"]


def test_opposite_direction_outlier_is_not_promoted() -> None:
    anti_c2 = _timeline(
        "10.0.0.251",
        "203.0.113.99",
        [1, 120, 2, 180, 1, 240, 3],
        [60, 9000, 70, 12000, 80, 15000, 90, 18000],
        [443, 80, 53, 123, 22, 110, 143, 25],
        [f"unique-{index}" for index in range(8)],
    )
    result = PopulationAnomalyDetector().analyze(
        context(
            _irregular_population(16) + anti_c2,
            ml_anomaly_enabled=True,
            ml_anomaly_min_population=16,
        )
    )
    assert result == []


def test_standalone_hunting_requires_explicit_option() -> None:
    flows = _irregular_population(16) + _c2_like_outlier()
    safe = run_detectors(
        context(
            flows,
            ml_anomaly_enabled=True,
            ml_anomaly_min_population=16,
        ),
        detectors=(PopulationAnomalyDetector(),),
    )
    assert safe == []

    standalone = run_detectors(
        context(
            flows,
            ml_anomaly_enabled=True,
            ml_anomaly_allow_standalone=True,
            ml_anomaly_min_population=16,
        ),
        detectors=(PopulationAnomalyDetector(),),
    )
    assert [evidence.candidate_ip for evidence in standalone] == ["203.0.113.44"]
