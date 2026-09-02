from datetime import UTC, datetime, timedelta

from c2hunter_analysis.detectors import (
    DEFAULT_DETECTORS,
    TCP_CONTROL_SUPPRESSION_DETECTOR_VERSION,
    CommonDestinationDetector,
    TCPSessionQualityDetector,
    run_detectors,
)
from c2hunter_analysis.domain import AnalysisContext, Flow
from c2hunter_analysis.scoring import score_candidates

START = datetime(2026, 8, 7, tzinfo=UTC)
CANDIDATE = "203.0.113.10"


def context(flows: list[Flow], **parameters: object) -> AnalysisContext:
    return AnalysisContext(
        "dataset",
        START,
        START + timedelta(minutes=10),
        flows,
        internal_cidrs=("10.0.0.0/8",),
        parameters=parameters,
    )


def tcp_flow(
    second: float,
    host: str,
    *,
    direction: str,
    source_port: int,
    destination_port: int,
    syn: int = 0,
    ack: int = 0,
    rst: int = 0,
    syn_only: int = 0,
    syn_ack: int = 0,
    ack_only: int = 0,
    bidirectional: bool = False,
    payload: bool = False,
    packets: int | None = None,
    flags: dict[str, int] | None = None,
) -> Flow:
    if direction == "OUTBOUND":
        source_ip, destination_ip = host, CANDIDATE
    else:
        source_ip, destination_ip = CANDIDATE, host
    return Flow(
        sensor_id="sensor-a",
        timestamp=START + timedelta(seconds=second),
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol="TCP",
        direction=direction,
        packet_count=packets or max(1, syn_only + syn_ack + ack_only + rst),
        total_bytes=60,
        payload_hash="a" * 64 if payload else None,
        tcp_flags_observed=True,
        tcp_syn_count=syn,
        tcp_ack_count=ack,
        tcp_rst_count=rst,
        tcp_syn_only_count=syn_only,
        tcp_syn_ack_count=syn_ack,
        tcp_ack_only_count=ack_only,
        bidirectional=bidirectional,
        tcp_flags=flags,
    )


def test_inbound_syn_scanner_is_removed_from_candidate_groups() -> None:
    flows: list[Flow] = []
    for index in range(1, 6):
        host = f"10.0.0.{index}"
        ephemeral = 40000 + index
        flows.extend(
            [
                tcp_flow(
                    index,
                    host,
                    direction="INBOUND",
                    source_port=ephemeral,
                    destination_port=22,
                    syn=1,
                    syn_only=1,
                    bidirectional=True,
                ),
                tcp_flow(
                    index + 0.001,
                    host,
                    direction="OUTBOUND",
                    source_port=22,
                    destination_port=ephemeral,
                    ack=1,
                    rst=1,
                    bidirectional=True,
                ),
            ]
        )

    analysis = context(flows, minimum_distinct_clients=3)
    assert CommonDestinationDetector().analyze(analysis) == []
    assert run_detectors(analysis) == []


def test_external_full_connect_scan_is_suppressed_by_fanout_profile() -> None:
    flows: list[Flow] = []
    for index in range(1, 9):
        host = f"10.0.0.{index}"
        ephemeral = 41000 + index
        flows.extend(
            [
                tcp_flow(
                    index,
                    host,
                    direction="INBOUND",
                    source_port=ephemeral,
                    destination_port=443,
                    syn=1,
                    ack=1,
                    syn_only=1,
                    ack_only=1,
                    bidirectional=True,
                ),
                tcp_flow(
                    index + 0.001,
                    host,
                    direction="OUTBOUND",
                    source_port=443,
                    destination_port=ephemeral,
                    syn=1,
                    ack=1,
                    syn_ack=1,
                    bidirectional=True,
                ),
            ]
        )

    analysis = context(flows, minimum_distinct_clients=3)
    assert CommonDestinationDetector().analyze(analysis) == []
    assert run_detectors(analysis) == []


def test_outbound_syn_start_is_kept_and_receives_context_bonus() -> None:
    flows = [
        tcp_flow(
            index,
            f"10.0.0.{index}",
            direction="OUTBOUND",
            source_port=50000 + index,
            destination_port=4444,
            syn=1,
            syn_only=1,
        )
        for index in range(1, 4)
    ]
    analysis = context(flows, minimum_distinct_clients=3)

    common = CommonDestinationDetector().analyze(analysis)
    session = TCPSessionQualityDetector().analyze(analysis)
    combined = run_detectors(analysis)
    candidate = score_candidates(combined)[0]

    assert common
    assert session[0].contribution == 5
    assert session[0].metrics["outbound_initiated_connections"] == 3
    assert session[0].metrics["established_connections"] == 0
    assert any(item.type == "TCP_SESSION_QUALITY" for item in candidate.evidence)


def test_outbound_control_flood_is_removed_from_deterministic_candidates() -> None:
    flows = [
        tcp_flow(
            index / 10,
            f"10.0.0.{(index % 3) + 1}",
            direction="OUTBOUND",
            source_port=52000 + index,
            destination_port=443,
            syn=20,
            syn_only=20,
            packets=20,
            flags={"syn": 20, "fin": 20},
        )
        for index in range(6)
    ]

    analysis = context(flows, minimum_distinct_clients=3)

    assert CommonDestinationDetector().analyze(analysis) == []
    assert run_detectors(analysis) == []
    assert CommonDestinationDetector().version == "1.1.0"

    gating_disabled = context(
        flows,
        minimum_distinct_clients=3,
        tcp_session_gating_enabled=False,
    )
    assert CommonDestinationDetector().analyze(gating_disabled) == []
    assert run_detectors(gating_disabled) == []


def test_control_suppression_versions_every_affected_detector() -> None:
    affected = {
        "common_destination",
        "non_well_known_port",
        "periodic_beacon",
        "single_host_composite_beacon",
        "synchronized_communication",
        "command_attack_correlation",
        "persistence_rarity",
        "protocol_similarity",
        "ml_population_anomaly",
        "multi_sensor_context",
        "tcp_session_quality",
    }
    versions = {detector.name: detector.version for detector in DEFAULT_DETECTORS}

    assert {versions[name] for name in affected} == {TCP_CONTROL_SUPPRESSION_DETECTOR_VERSION}
    assert versions["analyst_payload_signature"] == "1.0.0"


def test_control_flood_suppression_preserves_udp_rows_for_same_peer() -> None:
    flood = [
        tcp_flow(
            index / 10,
            f"10.0.0.{(index % 3) + 1}",
            direction="OUTBOUND",
            source_port=53000 + index,
            destination_port=443,
            syn=20,
            syn_only=20,
            packets=20,
            flags={"syn": 20},
        )
        for index in range(6)
    ]
    udp = [
        Flow(
            sensor_id="sensor-a",
            timestamp=START + timedelta(seconds=10 + index),
            source_ip=f"10.0.0.{index}",
            destination_ip=CANDIDATE,
            source_port=54000 + index,
            destination_port=8443,
            protocol="UDP",
            direction="OUTBOUND",
            packet_count=1,
            total_bytes=128,
            payload_hash="udp-c2",
        )
        for index in range(1, 4)
    ]

    evidence = CommonDestinationDetector().analyze(
        context([*flood, *udp], minimum_distinct_clients=3)
    )

    assert len(evidence) == 1
    assert evidence[0].metrics["sample_count"] == len(udp)
    assert evidence[0].version == "1.1.0"
    combined = run_detectors(context([*flood, *udp], minimum_distinct_clients=3))
    assert not any(item.type == "TCP_SESSION_QUALITY" for item in combined)


def test_completed_handshake_receives_full_session_quality_bonus() -> None:
    flows: list[Flow] = []
    for index in range(1, 4):
        host = f"10.0.0.{index}"
        port = 50000 + index
        flows.extend(
            [
                tcp_flow(
                    index,
                    host,
                    direction="OUTBOUND",
                    source_port=port,
                    destination_port=443,
                    syn=1,
                    ack=1,
                    syn_only=1,
                    ack_only=1,
                    bidirectional=True,
                    payload=True,
                ),
                tcp_flow(
                    index + 0.001,
                    host,
                    direction="INBOUND",
                    source_port=443,
                    destination_port=port,
                    syn=1,
                    ack=1,
                    syn_ack=1,
                    bidirectional=True,
                ),
            ]
        )

    session = TCPSessionQualityDetector().analyze(context(flows, minimum_distinct_clients=3))
    assert session[0].contribution == 15
    assert session[0].metrics["outbound_initiated_connections"] == 3
    assert session[0].metrics["established_connections"] == 3


def test_session_quality_never_creates_a_standalone_candidate() -> None:
    flow = tcp_flow(
        1,
        "10.0.0.1",
        direction="OUTBOUND",
        source_port=50001,
        destination_port=443,
        syn=1,
        syn_only=1,
    )
    analysis = context([flow], minimum_distinct_clients=3)
    assert TCPSessionQualityDetector().analyze(analysis)
    assert run_detectors(analysis) == []


def test_legacy_tcp_records_remain_compatible_but_can_be_disabled() -> None:
    legacy = [
        Flow(
            "sensor-a",
            START + timedelta(seconds=index),
            f"10.0.0.{index}",
            CANDIDATE,
            50000 + index,
            443,
            "TCP",
            "OUTBOUND",
        )
        for index in range(1, 4)
    ]
    assert CommonDestinationDetector().analyze(context(legacy, minimum_distinct_clients=3))
    assert (
        CommonDestinationDetector().analyze(
            context(
                legacy,
                minimum_distinct_clients=3,
                tcp_allow_legacy_without_flags=False,
            )
        )
        == []
    )


def test_syn_only_outbound_is_kept_by_default_when_gated() -> None:
    flows = [
        tcp_flow(
            index,
            f"10.0.0.{index}",
            direction="OUTBOUND",
            source_port=60000 + index,
            destination_port=4444,
            syn=1,
            syn_only=1,
        )
        for index in range(1, 4)
    ]

    analysis = context(flows, minimum_distinct_clients=3)

    assert CommonDestinationDetector().analyze(analysis)
    session = TCPSessionQualityDetector().analyze(analysis)
    assert session[0].metrics["outbound_initiated_connections"] == 3
    assert session[0].metrics["established_connections"] == 0
    assert session[0].metrics.get("syn_unanswered_connections", 0) == 0


def test_syn_only_outbound_can_be_required_to_have_established_session() -> None:
    flows = [
        tcp_flow(
            index,
            f"10.0.0.{index}",
            direction="OUTBOUND",
            source_port=60000 + index,
            destination_port=4444,
            syn=1,
            syn_only=1,
        )
        for index in range(1, 4)
    ]

    analysis = context(
        flows,
        minimum_distinct_clients=3,
        tcp_require_established_outbound=True,
    )

    assert CommonDestinationDetector().analyze(analysis) == []
    assert TCPSessionQualityDetector().analyze(analysis) == []
    assert run_detectors(analysis) == []


def test_syn_retries_with_established_peer_are_not_over_filtered() -> None:
    flows: list[Flow] = []
    for index in range(1, 4):
        host = f"10.0.0.{index}"
        port = 60000 + index
        # One unanswered SYN on its own port...
        flows.append(
            tcp_flow(
                index,
                host,
                direction="OUTBOUND",
                source_port=port,
                destination_port=4444,
                syn=1,
                syn_only=1,
            )
        )
        # ...plus a completed handshake on a distinct port for the same host.
        flows.extend(
            [
                tcp_flow(
                    index + 1.0,
                    host,
                    direction="OUTBOUND",
                    source_port=port + 10,
                    destination_port=4444,
                    syn=1,
                    ack=1,
                    syn_only=1,
                    ack_only=1,
                    bidirectional=True,
                    payload=True,
                ),
                tcp_flow(
                    index + 1.001,
                    host,
                    direction="INBOUND",
                    source_port=4444,
                    destination_port=port + 10,
                    syn=1,
                    ack=1,
                    syn_ack=1,
                    bidirectional=True,
                ),
            ]
        )

    analysis = context(
        flows,
        minimum_distinct_clients=3,
        tcp_require_established_outbound=True,
    )

    common = CommonDestinationDetector().analyze(analysis)
    session = TCPSessionQualityDetector().analyze(analysis)
    assert common
    assert session
    assert session[0].metrics["outbound_initiated_connections"] == 3
    assert session[0].metrics["established_connections"] == 3
