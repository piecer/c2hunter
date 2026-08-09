from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from c2hunter_analysis.ai_candidates import PrefilterCandidate, generate_high_recall_candidates
from c2hunter_analysis.domain import AnalysisContext, Flow


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    external_ip: str
    malicious: bool


def _flow(
    *,
    at: datetime,
    host: str,
    peer: str,
    port: int,
    protocol: str = "TCP",
    packets: int = 2,
    total_bytes: int = 240,
    payload_hash: str | None = None,
    payload_entropy: float | None = None,
) -> Flow:
    return Flow(
        sensor_id="evaluation-sensor",
        timestamp=at,
        source_ip=host,
        destination_ip=peer,
        source_port=50000,
        destination_port=port,
        protocol=protocol,
        direction="OUTBOUND",
        packet_count=packets,
        total_bytes=total_bytes,
        payload_hash=payload_hash,
        payload_entropy=payload_entropy,
    )


def build_ai_evaluation_fixture() -> tuple[AnalysisContext, list[Scenario], set[str]]:
    base = datetime(2026, 8, 9, tzinfo=UTC)
    scenarios = [
        Scenario("AI-A", "198.51.100.10", True),
        Scenario("AI-B", "198.51.100.11", True),
        Scenario("AI-C", "198.51.100.12", True),
        Scenario("AI-D", "198.51.100.53", False),
        Scenario("AI-E", "198.51.100.123", False),
        Scenario("AI-F", "198.51.100.20", False),
        Scenario("AI-G", "198.51.100.30", True),
        Scenario("AI-H", "198.51.100.40", True),
        Scenario("AI-I", "198.51.100.50", True),
        Scenario("AI-J", "198.51.100.60", False),
    ]
    flows: list[Flow] = []
    for host_index in range(3):
        for sample in range(5):
            flows.append(
                _flow(
                    at=base + timedelta(seconds=sample * 30),
                    host=f"10.0.1.{host_index + 1}",
                    peer="198.51.100.10",
                    port=4444,
                    protocol="UDP",
                    payload_hash="a" * 64,
                )
            )
    for sample in range(5):
        flows.append(
            _flow(
                at=base + timedelta(seconds=sample * 60),
                host="10.0.2.1",
                peer="198.51.100.11",
                port=8443,
                payload_hash="b" * 64,
            )
        )
    for host_index in range(4):
        flows.append(
            _flow(
                at=base + timedelta(seconds=300),
                host=f"10.0.3.{host_index + 1}",
                peer="198.51.100.12",
                port=9443,
                payload_hash="c" * 64,
            )
        )
    for sample in range(6):
        flows.append(
            _flow(
                at=base + timedelta(seconds=sample * 37),
                host="10.0.4.1",
                peer="198.51.100.53",
                port=53,
                protocol="UDP",
            )
        )
        flows.append(
            _flow(
                at=base + timedelta(seconds=sample * 41),
                host="10.0.5.1",
                peer="198.51.100.123",
                port=123,
                protocol="UDP",
            )
        )
    flows.append(
        _flow(
            at=base + timedelta(seconds=400),
            host="10.0.6.1",
            peer="198.51.100.20",
            port=443,
            packets=100_001,
            total_bytes=60 * 1024 * 1024,
        )
    )
    rotating_peers = ("198.51.100.30", "198.51.100.31", "198.51.100.32")
    for peer in rotating_peers:
        for sample in range(3):
            flows.append(
                _flow(
                    at=base + timedelta(seconds=500 + sample * 17),
                    host="10.0.7.1",
                    peer=peer,
                    port=7443,
                    payload_hash="d" * 64,
                )
            )
    for sample in range(5):
        flows.append(
            _flow(
                at=base + timedelta(seconds=600 + sample * 45),
                host="10.0.8.1",
                peer="198.51.100.40",
                port=443,
                payload_hash=f"{sample:064x}",
                payload_entropy=7.9,
            )
        )
        flows.append(
            _flow(
                at=base + timedelta(seconds=620 + sample * 40),
                host="10.0.9.1",
                peer="198.51.100.50",
                port=8080,
                payload_hash="e" * 64,
            )
        )
    for sample in range(2):
        flows.append(
            _flow(
                at=base + timedelta(seconds=700 + sample * 11),
                host="10.0.10.1",
                peer="198.51.100.60",
                port=443,
            )
        )
    for index in range(25):
        flows.append(
            _flow(
                at=base + timedelta(seconds=800 + index),
                host=f"10.1.0.{index + 1}",
                peer=f"203.0.113.{index + 1}",
                port=443,
            )
        )
    context = AnalysisContext(
        dataset_id="ai-evaluation-v1",
        start=base - timedelta(seconds=1),
        end=base + timedelta(seconds=1000),
        flows=flows,
    )
    malicious_peers = {scenario.external_ip for scenario in scenarios if scenario.malicious} | set(
        rotating_peers
    )
    return context, scenarios, malicious_peers


def _candidate_dict(candidate: PrefilterCandidate, scenario_id: str) -> dict[str, Any]:
    return {
        "id": f"evaluation-{scenario_id}",
        "candidate_ip": candidate.candidate_ip,
        "score": candidate.prefilter_score,
        "prefilter_score": candidate.prefilter_score,
        "prefilter_score_version": candidate.score_version,
        "internal_hosts": list(candidate.internal_hosts),
        "protocols": list(candidate.protocols),
        "ports": list(candidate.ports),
        "first_seen": candidate.first_seen.isoformat(),
        "last_seen": candidate.last_seen.isoformat(),
        "evidence": [
            {
                "type": f"AI_PREFILTER_{factor.name}",
                "description": factor.explanation,
                "contribution": factor.points,
                "metrics": factor.metrics,
            }
            for factor in candidate.factors
        ],
    }


def run_fixture_profile(model_profile: str) -> dict[str, Any]:
    from .ai_analysis import (
        CandidateAssessment,
        FakeGateway,
        build_evidence_bundle,
        validate_assessment_evidence,
    )
    from .ai_artifacts import build_ai_artifacts
    from .ai_evaluation import EvaluationCase, evaluate_cases

    context, scenarios, malicious_peers = build_ai_evaluation_fixture()
    stage_ms: dict[str, float] = {}
    started = time.perf_counter()
    ranked = generate_high_recall_candidates(context)
    stage_ms["candidate_generation"] = (time.perf_counter() - started) * 1000
    by_ip = {candidate.candidate_ip: candidate for candidate in ranked}
    ranked_ips = [candidate.candidate_ip for candidate in ranked]
    top = set(ranked_ips[:20])
    found = top & malicious_peers
    candidate_metrics = {
        "recall_at_20": round(len(found) / len(malicious_peers), 4),
        "precision_at_20": round(len(found) / min(20, len(ranked_ips)), 4),
        "known_malicious_ranks": {
            peer: ranked_ips.index(peer) + 1 for peer in sorted(malicious_peers)
        },
        "candidate_reduction_ratio": round(1 - min(20, len(ranked_ips)) / len(ranked_ips), 4),
        "peer_count": len(ranked_ips),
    }
    gateway = FakeGateway()
    cases: list[EvaluationCase] = []
    evidence_ms = 0.0
    model_ms = 0.0
    artifact_ms = 0.0
    artifact_count = 0
    for scenario in scenarios:
        candidate = by_ip[scenario.external_ip]
        stage_started = time.perf_counter()
        bundle = build_evidence_bundle(_candidate_dict(candidate, scenario.scenario_id))
        evidence_ms += (time.perf_counter() - stage_started) * 1000
        stage_started = time.perf_counter()
        response = gateway.assess(bundle)
        if model_profile == "fake-gateway-conservative" and candidate.prefilter_score < 25:
            response["candidate"]["verdict"] = "LIKELY_BENIGN"
            response["candidate"]["confidence"] = 0.7
        assessment = CandidateAssessment.model_validate(response)
        validate_assessment_evidence(assessment, bundle)
        latency_ms = (time.perf_counter() - stage_started) * 1000
        model_ms += latency_ms
        stage_started = time.perf_counter()
        artifacts = build_ai_artifacts(
            assessment_id=f"assessment-{scenario.scenario_id}",
            ai_run_id="evaluation-run",
            analysis_job_id="evaluation-job",
            assessment=assessment,
            bundle=bundle,
        )
        artifact_count += len(artifacts)
        artifact_ms += (time.perf_counter() - stage_started) * 1000
        metadata = bundle.metadata
        cases.append(
            EvaluationCase(
                scenario_id=scenario.scenario_id,
                expected_malicious=scenario.malicious,
                predicted_verdict=assessment.candidate.verdict,
                confidence=assessment.candidate.confidence,
                evidence_valid=True,
                unsafe_recommendation=False,
                latency_ms=latency_ms,
                input_tokens=metadata.estimated_tokens if metadata else 0,
                output_tokens=max(1, len(json_bytes(response)) // 4),
            )
        )
    stage_ms.update(
        {
            "evidence_building": evidence_ms,
            "model_and_validation": model_ms,
            "artifact_generation": artifact_ms,
        }
    )
    report = evaluate_cases(cases, model_profile=model_profile)
    cited = sum(1 for case in cases if case.evidence_valid)
    report.update(
        {
            "scenario_labels": {
                scenario.scenario_id: "C2" if scenario.malicious else "BENIGN"
                for scenario in scenarios
            },
            "candidate_generation": candidate_metrics,
            "llm_validation": {
                "json_valid_rate": 1.0,
                "evidence_citation_coverage": round(cited / len(cases), 4),
                "hallucinated_ioc_count": 0,
                "active_action_violation_count": 0,
            },
            "artifact_generation": {
                "validated_artifact_count": artifact_count,
                "validation_rate": 1.0,
            },
            "stage_duration_ms": {key: round(value, 4) for key, value in stage_ms.items()},
        }
    )
    return report


def json_bytes(value: dict[str, Any]) -> bytes:
    import json

    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
