import hashlib
import importlib.util
import ipaddress
import json
import struct
import tempfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from c2hunter_analysis.detectors import run_detectors
from c2hunter_analysis.domain import (
    AnalysisContext,
    Candidate,
    Evidence,
    Flow,
    OperationalMetadata,
    PacketObservation,
)
from c2hunter_analysis.ingestion import deduplicate_observations
from c2hunter_analysis.scoring import score_candidates

GENERATOR_PATH = Path(__file__).parents[2] / "tools" / "traffic-generator" / "generate.py"
SPEC = importlib.util.spec_from_file_location("traffic_generator_for_analysis", GENERATOR_PATH)
assert SPEC and SPEC.loader
GENERATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GENERATOR)


def pcap_to_flows(path: Path, sensor_ids: list[str]) -> list[Flow]:
    """Convert the generated Ethernet/IPv4/UDP PCAP into analysis-domain Flow rows."""
    data = path.read_bytes()
    offset = 24
    flows: list[Flow] = []
    packet_index = 0
    while offset < len(data):
        seconds, micros, captured, _original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        packet = data[offset : offset + captured]
        offset += captured
        source_ip = str(ipaddress.ip_address(packet[26:30]))
        destination_ip = str(ipaddress.ip_address(packet[30:34]))
        source_port, destination_port, udp_length, _checksum = struct.unpack_from(
            "!HHHH", packet, 34
        )
        payload = packet[42 : 42 + udp_length - 8]
        source_internal = ipaddress.ip_address(source_ip) in ipaddress.ip_network("10.0.0.0/8")
        sensor = sensor_ids[packet_index]
        packet_index += 1
        flows.append(
            Flow(
                sensor_id=sensor,
                timestamp=datetime.fromtimestamp(seconds + micros / 1_000_000, UTC),
                source_ip=source_ip,
                destination_ip=destination_ip,
                source_port=source_port,
                destination_port=destination_port,
                protocol="UDP",
                direction="OUTBOUND" if source_internal else "INBOUND",
                packet_count=1,
                total_bytes=len(payload),
                payload_hash=hashlib.sha256(payload).hexdigest(),
                domain=(payload.decode(errors="replace") if payload.startswith(b"sni-") else None),
                packet_sizes=(len(payload),),
            )
        )
    aggregated: dict[tuple[object, ...], Flow] = {}
    for flow in flows:
        key = (
            flow.sensor_id,
            flow.source_ip,
            flow.destination_ip,
            flow.source_port,
            flow.destination_port,
            int(flow.timestamp.timestamp() // 10),
        )
        current = aggregated.get(key)
        if current is None:
            aggregated[key] = flow
        else:
            aggregated[key] = replace(
                current,
                packet_count=current.packet_count + flow.packet_count,
                total_bytes=current.total_bytes + flow.total_bytes,
                packet_sizes=current.packet_sizes + flow.packet_sizes,
            )
    assert packet_index == len(sensor_ids)
    return list(aggregated.values())


def pcap_to_observations(path: Path, sensor_ids: list[str]) -> list[PacketObservation]:
    data = path.read_bytes()
    offset = 24
    observations: list[PacketObservation] = []
    while offset < len(data):
        seconds, micros, captured, _original = struct.unpack_from("<IIII", data, offset)
        offset += 16
        packet = data[offset : offset + captured]
        offset += captured
        source_port, destination_port, udp_length, _checksum = struct.unpack_from(
            "!HHHH", packet, 34
        )
        payload = packet[42 : 42 + udp_length - 8]
        observations.append(
            PacketObservation(
                sensor_id=sensor_ids[len(observations)],
                timestamp=datetime.fromtimestamp(seconds + micros / 1_000_000, UTC),
                source_ip=str(ipaddress.ip_address(packet[26:30])),
                destination_ip=str(ipaddress.ip_address(packet[30:34])),
                source_port=source_port,
                destination_port=destination_port,
                protocol="UDP",
                ip_id=struct.unpack_from("!H", packet, 18)[0],
                tcp_sequence=0,
                payload_length=len(payload),
                payload_hash=hashlib.sha256(payload).hexdigest(),
            )
        )
    assert len(observations) == len(sensor_ids)
    return observations


def analyze_generated_pcap(path: Path) -> tuple[list[Flow], list[Evidence], list[Candidate]]:
    metadata = json.loads(path.with_suffix(".json").read_text())
    sensor_ids = metadata["observations"]["packet_sensor_ids"]
    flows = pcap_to_flows(path, sensor_ids)
    timestamps = [flow.timestamp for flow in flows]
    context = AnalysisContext(
        dataset_id=path.stem,
        start=min(timestamps) - timedelta(microseconds=1),
        end=max(timestamps) + timedelta(microseconds=1),
        flows=flows,
        selected_sensors=tuple(sorted(set(sensor_ids))),
        clock_offsets_ms={
            sensor: details.get("clock_offset_ms", 0)
            for sensor, details in metadata.get("operations", {}).get("sensors", {}).items()
        },
        parameters={
            "minimum_distinct_clients": 3,
            "periodicity_min_samples": 5,
            "synchronization_window_seconds": 2,
            **metadata.get("analysis_context", {}),
        },
    )
    evidence = run_detectors(context)
    return flows, evidence, score_candidates(evidence, minimum_samples=5)


def test_generated_scenario_a_pcap_satisfies_positive_analysis_oracle() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        flows, evidence, candidates = analyze_generated_pcap(Path(directory, "scenario-a.pcap"))
        oracle = scenarios["A"]["oracle"]
        candidate = next(item for item in candidates if item.candidate_ip == "203.0.113.10")

        assert len(flows) == scenarios["A"]["packet_count"]
        assert len(candidate.hosts) == oracle["distinct_internal_hosts"]
        assert candidate.score >= oracle["minimum_score"]
        assert set(oracle["evidence"]) <= {item.type for item in evidence}


def test_generated_scenario_b_pcap_satisfies_correlation_oracle() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        _flows, evidence, candidates = analyze_generated_pcap(Path(directory, "scenario-b.pcap"))
        oracle = scenarios["B"]["oracle"]
        candidate = next(item for item in candidates if item.candidate_ip == "203.0.113.10")
        candidate_evidence = {item.type: item for item in candidate.evidence}

        assert candidate.score >= oracle["minimum_score"]
        assert set(oracle["evidence"]) <= set(candidate_evidence)
        assert (
            candidate_evidence["COMMAND_ATTACK_CORRELATION"].metrics["attack_target"]
            == oracle["attack_target"]
        )
        assert set(candidate.sensors) == set(oracle["sensors"])


def test_generated_scenario_c_pcap_applies_public_dns_ntp_benign_evidence() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        _flows, evidence, candidates = analyze_generated_pcap(Path(directory, "scenario-c.pcap"))
        oracle = scenarios["C"]["oracle"]

        assert candidates
        assert max(candidate.score for candidate in candidates) <= oracle["maximum_score"]
        assert all(
            oracle["adjustment"] in {adjustment.kind for adjustment in candidate.adjustments}
            for candidate in candidates
        )
        assert all(
            any(item.metrics.get("public_dns_ntp") is True for item in candidate.evidence)
            for candidate in candidates
        )
        assert {item.candidate_ip for item in evidence} == {"192.0.2.53", "192.0.2.123"}


def test_generated_scenario_d_pcap_applies_cdn_context_and_diverse_sni() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        _flows, _evidence, candidates = analyze_generated_pcap(Path(directory, "scenario-d.pcap"))
        oracle = scenarios["D"]["oracle"]
        candidate = next(item for item in candidates if item.candidate_ip == "192.0.2.80")

        assert candidate.score <= oracle["maximum_score"]
        assert "CDN_CLOUD" in {adjustment.kind for adjustment in candidate.adjustments}
        benign = next(item for item in candidate.evidence if item.metrics.get("cdn_cloud") is True)
        assert benign.metrics["distinct_domains"] == 50
        assert benign.metrics["trusted_cdn_suffix"] == "cdn.test"


def test_generated_scenario_e_sidecar_models_duplicate_sensor_observations() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        path = Path(directory, "scenario-e.pcap")
        metadata = json.loads(path.with_suffix(".json").read_text())
        observations = pcap_to_observations(path, metadata["observations"]["packet_sensor_ids"])
        packets = deduplicate_observations(observations)
        oracle = scenarios["E"]["oracle"]

        assert len(packets) == oracle["logical_packet_count"]
        assert len(packets[0].observations) == oracle["sensor_observations"]
        assert {item.sensor_id for item in packets[0].observations} == set(oracle["sensors"])


def test_generated_scenario_f_operational_skew_reduces_detector_confidence() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        path = Path(directory, "scenario-f.pcap")
        metadata = json.loads(path.with_suffix(".json").read_text())
        operations = OperationalMetadata.from_mapping(metadata["operations"])
        _flows, evidence, _candidates = analyze_generated_pcap(path)
        synchronized = next(item for item in evidence if item.type == "SYNCHRONIZED_COMMUNICATION")
        oracle = scenarios["F"]["oracle"]

        assert operations.sensor_status("sensor-b") == oracle["sensor_status"]
        assert operations.clock_offsets_ms["sensor-b"] == oracle["clock_skew_seconds"] * 1000
        assert operations.confidence < 1.0
        assert oracle["warning"] in operations.warnings
        assert synchronized.confidence == operations.confidence
        assert "clock_skew" in synchronized.warnings


def test_generated_scenario_g_disconnect_reports_partial_completion_and_loss() -> None:
    with tempfile.TemporaryDirectory() as directory:
        scenarios = GENERATOR.generate_all(Path(directory), seed=20260720)
        path = Path(directory, "scenario-g.pcap")
        metadata = json.loads(path.with_suffix(".json").read_text())
        operations = OperationalMetadata.from_mapping(metadata["operations"])
        oracle = scenarios["G"]["oracle"]

        assert operations.completion_status == oracle["status"]
        assert list(operations.completed_sensors) == oracle["completed_sensors"]
        assert list(operations.failed_sensors) == oracle["failed_sensors"]
        assert operations.loss_reported is oracle["loss_reported"]
        assert operations.loss_report["sensor-b"] == "sensor disconnected during collection"
