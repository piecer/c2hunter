"""Opt-in synthetic comparison of the shipped legacy and investigation services."""

from __future__ import annotations

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict

from .ai_investigation_evaluation_report import (
    REPORT_LIMIT as REPORT_LIMIT,
)
from .ai_investigation_evaluation_report import (
    audit_output as audit_output,
)
from .ai_investigation_evaluation_report import (
    build_report as build_report,
)
from .ai_investigation_evaluation_report import (
    serialize_report as serialize_report,
)

SCENARIOS = (
    "normal_update",
    "normal_backup",
    "normal_monitoring",
    "jitter_beacon",
    "low_volume_repetition",
    "mixed_peer_traffic",
    "syn_flood_only",
    "partial_or_bad_time_quality",
    "observed_nonshortlisted_peer",
)
QUESTION = (
    "Compare C2 and benign hypotheses, distinguish missing from negative evidence, and "
    "recommend passive validation only."
)


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode()
    ).hexdigest()


class GeneratedCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    case_id: str
    scenario: str
    expected: Literal["POSITIVE", "NEGATIVE", "ABSTAIN"]
    target_ip: str
    job: dict[str, Any]
    data_sha256: str


def generate_cases() -> tuple[GeneratedCase, ...]:
    """Deterministic observation records; labels live outside the stored job.

    These are behavioral proxies, not ground truth about malware or real traffic.
    No fabricated scored candidate is inserted; the existing prefilter ranks records.
    """
    cases = []
    epoch = datetime(2026, 1, 1, tzinfo=UTC)
    for index, scenario in enumerate(SCENARIOS):
        rows: list[dict[str, Any]] = []
        count = 1 if index == 8 else 24
        for n in range(count):
            seconds: float = n * (3600 if index == 4 else 60)
            if index in {3, 5}:
                seconds += (0, 4, -3, 2)[n % 4]
            if index == 6:
                seconds = n / 100
            row: dict[str, Any] = dict(
                sensor_id="sensor-01",
                timestamp=(epoch + timedelta(seconds=seconds)).isoformat(),
                source_ip="192.0.2.10",
                destination_ip="203.0.113.10",
                source_port=40000 + n,
                destination_port=443,
                protocol="TCP",
                direction="OUTBOUND",
                packet_count=1,
                total_bytes=96,
                duration_seconds=0,
            )
            if index in {0, 1, 2}:
                row.update(
                    domain="service.example.test",
                    tls_fingerprint="synthetic-fp-01",
                    packet_count=20,
                    total_bytes=8192,
                    duration_seconds=2,
                    bidirectional=True,
                )
                if index == 0:
                    row.update(source_ip=f"192.0.2.{10 + n % 4}", total_bytes=100000 + n * 1000)
                elif index == 1:
                    row.update(packet_count=2000, total_bytes=3000000, duration_seconds=30)
                else:
                    row.update(destination_port=443, total_bytes=512)
            if index == 6:
                row.update(
                    packet_count=1000,
                    total_bytes=40000,
                    duration_seconds=0.01,
                    tcp_flags_observed=True,
                    tcp_syn_count=1000,
                    tcp_ack_count=0,
                    tcp_rst_count=0,
                    tcp_syn_only_count=1000,
                    tcp_syn_ack_count=0,
                    tcp_ack_only_count=0,
                    tcp_flags={"syn": 1000, "ack": 0},
                )
            if index == 7:
                if n % 3 == 0:
                    row.pop("timestamp")
                elif n % 3 == 1:
                    row["timestamp"] = "invalid-time"
            rows.append(row)
        if index in {5, 8}:
            for n in range(24):
                rows.append(
                    dict(
                        sensor_id="sensor-01",
                        timestamp=(epoch + timedelta(seconds=n * 60)).isoformat(),
                        source_ip="192.0.2.11",
                        destination_ip="203.0.113.20",
                        protocol="UDP",
                        direction="OUTBOUND",
                        destination_port=8443,
                        packet_count=1,
                        total_bytes=80,
                        duration_seconds=0,
                    )
                )
        job: dict[str, Any] = dict(
            id=f"generated-{index + 1:02d}",
            dataset_id=f"data-{index + 1:02d}",
            parent_job_id=None,
            status="PARTIALLY_COMPLETED" if index == 7 else "COMPLETED",
            analysis={"module": "c2"},
            internal_networks=["192.0.2.0/24"],
            sensor_ids=["sensor-01"],
            flow_records=rows,
        )
        if index == 7:
            job["operations"] = {"warnings": ["CLOCK_SKEW"], "failed_sensors": ["sensor-02"]}
        expected: Literal["POSITIVE", "NEGATIVE", "ABSTAIN"] = (
            "POSITIVE" if index in {3, 4, 5} else "ABSTAIN" if index in {7, 8} else "NEGATIVE"
        )
        cases.append(
            GeneratedCase(
                case_id=job["id"],
                scenario=scenario,
                expected=expected,
                target_ip="203.0.113.10",
                job=job,
                data_sha256=digest(job),
            )
        )
    return tuple(cases)


def evaluate_pair(
    case: GeneratedCase, legacy_gateway: Any, investigation_gateway: Any
) -> list[dict[str, Any]]:
    """Execute unchanged service APIs, never synthesize a legacy candidate.

    Gateways are explicit so offline tests can replace only provider transport.
    The CLI constructs only opt-in loopback gateways. Fixed-bundle legacy has no
    question argument; its existing generic defensive task is retained verbatim.
    """
    import time
    from copy import deepcopy

    from .ai_analysis import AIAnalysisError, AIAnalysisService
    from .ai_gateway import OllamaGateway
    from .ai_investigation import InvestigationService
    from .ai_investigation_gateway import InvestigationModelGateway
    from .ai_investigation_store import InvestigationRunStore, initialize_investigation_store
    from .repositories import MemoryRepository

    if not isinstance(legacy_gateway, OllamaGateway) or not isinstance(
        investigation_gateway, InvestigationModelGateway
    ):
        raise ValueError("actual production gateways required")
    if digest(case.job) != case.data_sha256:
        raise ValueError("generated source changed")
    provenance = execution_identity(legacy_gateway, investigation_gateway)
    repo = MemoryRepository()
    repo.save_job(deepcopy(case.job))
    initialize_investigation_store(repo)
    store = InvestigationRunStore(repo)
    from .ai_investigation_contract import InvestigationError

    source = None
    source_error = None
    try:
        source = repo.read_investigation_source(case.case_id)
    except InvestigationError as exc:
        source_error = exc.code
    baseline = digest(repo.get_job(case.case_id))
    candidates = digest(repo.get_candidates(case.case_id))
    results: list[dict[str, Any]] = []
    try:
        for arm in ("legacy", "investigation"):
            start = time.monotonic()
            trace = (
                getattr(legacy_gateway.http, "trace", None)
                if arm == "legacy"
                else getattr(investigation_gateway, "trace", None)
            )
            trace_start = len(trace.calls) if trace is not None else 0
            row: dict[str, Any] = dict(
                provenance=deepcopy(provenance),
                case_id=case.case_id,
                scenario=case.scenario,
                expected=case.expected,
                arm=arm,
                target_ip=case.target_ip,
                data_sha256=case.data_sha256,
                stored_source_sha256=source.binding.source_sha256 if source is not None else None,
                status="FAILED",
                verdict=None,
                reason=None,
                selected_ips=[],
                facts=[],
                interpretation=None,
                evidence=[],
                steps=[],
            )
            if arm == "legacy":
                service = AIAnalysisService(repo, legacy_gateway)
                try:
                    run, _ = service.create_run(
                        analysis_job_id=case.case_id,
                        idempotency_key="evaluation",
                        candidate_limit=1,
                        created_by="evaluation",
                        discovery_mode="legacy",
                    )
                except AIAnalysisError as exc:
                    if str(exc) != "analysis job has no candidates":
                        raise
                    row.update(status="NOT_SELECTED", reason="NO_CANDIDATES")
                else:
                    row["selected_ips"] = [c["candidate_ip"] for c in run["candidate_snapshots"]]
                    if case.target_ip not in row["selected_ips"]:
                        row.update(status="NOT_SELECTED", reason="OUTSIDE_TOP_ONE")
                        service.cancel(run["id"], "evaluation target outside selected scope")
                    else:
                        run = service.execute(run["id"])
                        row.update(status=str(run["status"]), reason=run.get("error_code"))
                        assessments = repo.list_ai_assessments(run["id"])
                        if assessments:
                            saved = assessments[0]
                            assessment = saved["assessment"]
                            row.update(
                                verdict=assessment["candidate"]["verdict"],
                                interpretation=assessment,
                                evidence=[saved["evidence_bundle"]],
                            )
            elif source is None:
                row.update(status="FAILED", reason=source_error)
            else:
                investigation = InvestigationService(repo, store, investigation_gateway)
                admitted, _ = investigation.admit(
                    "evaluation",
                    case.case_id,
                    dict(
                        version="ip-investigation-v1",
                        mode="IP",
                        target_ip=case.target_ip,
                        question=QUESTION,
                        language="en",
                        idempotency_key="evaluation",
                        expected_source_sha256=source.binding.source_sha256,
                        allow_remote=False,
                    ),
                )
                outcome = investigation.run_next("evaluation-worker")
                if outcome is None:
                    raise RuntimeError("investigation did not execute")
                try:
                    saved_run = investigation.get("evaluation", case.case_id, admitted.id)
                    if saved_run is None:
                        raise RuntimeError("investigation result missing")
                    row.update(
                        status=saved_run.status,
                        reason=saved_run.reason,
                        stored_status=saved_run.status,
                    )
                    if not outcome.acknowledge_exit:
                        row.update(status="EXECUTION_UNRESOLVED", reason=outcome.code)
                    if saved_run.result is not None:
                        result = saved_run.result.model_dump(mode="json")
                        row.update(
                            verdict=result.get("verdict"),
                            facts=result.get("facts", []),
                            interpretation=result,
                            reason=result.get("reason"),
                        )
                    steps = investigation.steps("evaluation", case.case_id, admitted.id)
                    row["steps"] = [step.model_dump(mode="json") for step in steps]
                    for identity in dict.fromkeys(
                        step.evidence_id for step in steps if step.evidence_id
                    ):
                        evidence = investigation.evidence(
                            "evaluation", case.case_id, admitted.id, identity
                        )
                        if evidence is not None:
                            row["evidence"].append(evidence.model_dump(mode="json"))
                finally:
                    if not store.worker_exited(outcome.claim):
                        raise RuntimeError("investigation ownership not released")
            if trace is not None:
                row["trace_range"] = [trace_start, len(trace.calls)]
            row["elapsed_seconds"] = time.monotonic() - start
            row["source_unchanged"] = baseline == digest(
                repo.get_job(case.case_id)
            ) and candidates == digest(repo.get_candidates(case.case_id))
            if not row["source_unchanged"]:
                raise RuntimeError("evaluation mutated source facts")
            results.append(row)
    finally:
        repo.close()
    return results


PILOT_DIGEST = "46e0c10c039e019119339687c3c1757cc81b9da49709a3b3924863ba87ca666e"


def source_manifest() -> dict[str, Any]:
    """Hash installed package sources/config only; never inspect runtime .env files."""
    from pathlib import Path

    import c2hunter_analysis

    controller = Path(__file__).resolve().parent
    analysis = Path(c2hunter_analysis.__file__).resolve().parent
    paths = [(f"controller/{p.relative_to(controller)}", p) for p in controller.rglob("*.py")]
    paths += [(f"analysis/{p.relative_to(analysis)}", p) for p in analysis.rglob("*.py")]
    root = controller.parents[2]
    for name in (
        "Makefile",
        "requirements.lock",
        "controller/pyproject.toml",
        "analysis/pyproject.toml",
    ):
        if (root / name).is_file():
            paths.append((name, root / name))
    return {
        name: dict(
            sha256=hashlib.sha256(path.read_bytes()).hexdigest(), mode=path.stat().st_mode & 0o777
        )
        for name, path in sorted(paths)
    }


def execution_identity(legacy: Any, investigation: Any) -> dict[str, Any]:
    """Snapshot executing gateway settings, not a caller's report label.

    This is a producer boundary, not protection against hostile Python mutation.
    Model tag observation is separate and does not prove executing weight bytes.
    """
    import platform
    from importlib.metadata import version

    from . import ai_investigation as policy

    names = (
        "base_url",
        "model",
        "temperature",
        "context_tokens",
        "max_output_tokens",
        "timeout_seconds",
    )
    arms = {
        arm: {
            key: getattr(
                gateway.http if arm == "legacy" and key == "timeout_seconds" else gateway, key
            )
            for key in names
        }
        for arm, gateway in (("legacy", legacy), ("investigation", investigation))
    }
    for arm, gateway in (("legacy", legacy), ("investigation", investigation)):
        arms[arm]["gateway"] = type(gateway).__module__ + "." + type(gateway).__qualname__
    common = {key: arms["legacy"][key] for key in names}
    if any(arms["investigation"][key] != common[key] for key in names):
        raise ValueError("pair gateway configuration mismatch")
    return dict(
        common=common,
        arms=arms,
        source_sha256=digest(source_manifest()),
        runtime={
            "python": platform.python_version(),
            "httpx": version("httpx"),
            "pydantic": version("pydantic"),
        },
        policy=dict(
            legacy_retries=legacy.retries,
            legacy_candidate_limit=1,
            legacy_discovery_mode="legacy",
            investigation_model_calls=policy.MAX_MODEL_CALLS,
            investigation_tool_calls=policy.MAX_TOOL_CALLS,
            investigation_deadline_seconds=policy.DEADLINE_SECONDS,
            question=QUESTION,
        ),
    )


def collect_telemetry(rows: list[dict[str, Any]], experiment: Any) -> None:
    from copy import deepcopy

    for row in rows:
        trace = (
            experiment.legacy_trace if row["arm"] == "legacy" else experiment.investigation_trace
        )
        start, end = row["trace_range"]
        row["calls"] = deepcopy(trace.calls[start:end])
        audits = []
        for text, messages, call in zip(
            trace.outputs[start:end], trace.inputs[start:end], row["calls"], strict=True
        ):
            if row["arm"] == "legacy":
                available = row["evidence"]
                if not available:
                    available = [json.loads(messages[1]["content"].split("\n", 1)[1])]
            else:
                # Evidence must already have been issued at that model turn, not a later turn.
                ids = {e["evidence_id"] for e in json.loads(messages[1]["content"])["observations"]}
                available = [e for e in row["evidence"] if e["evidence_id"] in ids]
            audit = audit_output(row["arm"], text, available)
            if call["error"] == "INVALID_JSON":
                audit.update(json_valid=False, schema_valid=False)
            audits.append(audit)
        row["output_audits"] = audits
        if row["arm"] == "investigation":
            metrics = {m["ref"]: m for e in row["evidence"] for m in e.get("metrics", [])}
            mismatches = sum(
                m["ref"] not in metrics or digest(m) != digest(metrics[m["ref"]])
                for m in row["facts"]
            )
            row["typed_fact_mismatches"] = mismatches
            row["typed_facts_verified"] = mismatches == 0 if row["facts"] else None


def markdown_report(report: dict[str, Any]) -> str:
    lines = [
        "# Generated comparison / 생성 데이터 비교",
        "",
        "Synthetic single-run proxy; not real-traffic accuracy. "
        "실제 탐지 정확도/우월성 증명이 아닙니다.",
        "",
        "## Facts / 관측 사실",
        "",
        f"Complete matrix for declared scope: {report['complete']}; "
        f"expected rows: {report['expected_rows']}",
        f"Comparison valid: {report['metadata'].get('comparison_valid', False)}",
        "",
    ]
    for row in report["rows"]:
        lines.append(
            f"- {row['case_id']} / {row['arm']}: {row['status']}, verdict={row['verdict']}, "
            f"reason={row['reason']}, elapsed={row['elapsed_seconds']:.3f}s"
        )
    if not report["rows"]:
        lines.append("- Offline inventory only; no inference. 오프라인 목록만 생성했습니다.")
    lines += [
        "",
        "## Interpretation and limits / 해석 및 한계",
        "",
        "- NOT_SELECTED ≠ BENIGN. Selection omissions are separate from model assessments.",
        "- References and typed facts are checked mechanically; prose meaning is not verified.",
        "- Unknown usage/cost remains null. 미관측 사용량과 비용은 null입니다.",
        "- Legacy runs first without warmup: cold-start and order bias are not controlled.",
        "- Transport cancellation does not prove backend generation physically stopped.",
        "",
    ]
    if "metrics" in report:
        lines += [
            "## Metrics / 지표",
            "",
            "```json",
            json.dumps(report["metrics"], indent=2),
            "```",
            "",
        ]
    return "\n".join(lines)


def _publish_report(
    output: Path,
    report: dict[str, Any],
    code: int,
    *,
    deadline: float | None,
    matrix_manifest: dict[str, Any] | None,
) -> int:
    """Finalize under the original clock, including ordinary close and stdout.

    Prepare bounded success and invalid diagnostics before admitting publication.
    Expiry is terminal: the single diagnostic rewrite is cleanup, never a fresh
    execution allowance. The external execution/cleanup supervisor is still
    required for blocking I/O or process preemption.
    """
    from . import ai_investigation_evaluation_runtime as runtime

    def prepare(value: dict[str, Any], manifest: dict[str, Any] | None) -> dict[str, str]:
        texts = {"report.json": serialize_report(value), "report.md": markdown_report(value)}
        if manifest is not None:
            texts["matrix-manifest.json"] = serialize_report(manifest)
        if any(len(text.encode("utf-8")) > REPORT_LIMIT for text in texts.values()):
            raise ValueError("report limit")
        return texts

    texts = prepare(report, matrix_manifest)
    invalid = {**report, "metadata": {**report["metadata"], "comparison_valid": False}}
    invalid_manifest = None
    if matrix_manifest is not None:
        invalid["metadata"]["matrix_error"] = "MATRIX_DEADLINE_EXCEEDED"
        invalid_manifest = {
            **matrix_manifest,
            "comparison_valid": False,
            "stop_reason": "MATRIX_DEADLINE_EXCEEDED",
        }
    else:
        invalid["metadata"]["publication_error"] = "EXECUTION_DEADLINE_EXCEEDED"
    diagnostics = prepare(invalid, invalid_manifest) if deadline is not None else {}
    terminal = json.dumps(
        dict(
            execution=report["execution"],
            complete=report["complete"],
            report=str(output / "report.json"),
        )
    )

    def expired() -> bool:
        return deadline is not None and runtime.time.monotonic() >= deadline

    def fail_deadline() -> int:
        # Never touch pair reports, observed rows, admission or progress receipts.
        report["metadata"] = invalid["metadata"]
        if matrix_manifest is not None and invalid_manifest is not None:
            matrix_manifest.update(invalid_manifest)
        for name, text in diagnostics.items():
            (output / name).write_text(text, encoding="utf-8")
        print("Execution deadline exceeded; comparison invalid.", file=sys.stderr, flush=True)
        return 2

    if expired():
        return fail_deadline()
    for name, text in texts.items():
        (output / name).write_text(text, encoding="utf-8")
        if expired():
            return fail_deadline()
    # This receipt identifies observations, not success. Exit status and the
    # report's comparison_valid flag remain authoritative after the tail check.
    print(terminal, flush=True)
    return fail_deadline() if expired() else code


def main(argv: list[str] | None = None) -> int:
    import argparse

    from . import ai_investigation as policy
    from .ai_investigation_evaluation_runtime import ENDPOINT, MODEL, LocalExperiment

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, required=True, help="New output directory; never overwrite"
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--real-local-model", action="store_true", help="Opt in to exactly one real two-arm pair"
    )
    group.add_argument(
        "--preflight-local-model",
        action="store_true",
        help="Bounded metadata GET only; no inference",
    )
    group.add_argument(
        "--real-local-matrix",
        action="store_true",
        help="Opt in to the fixed nine generated pairs; no retries",
    )
    parser.add_argument("--case", choices=SCENARIOS, default="jitter_beacon")
    parser.add_argument("--endpoint", default=ENDPOINT, choices=[ENDPOINT])
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--expected-model-digest", default=PILOT_DIGEST)
    args = parser.parse_args(argv)
    cases = generate_cases()
    manifest = source_manifest()
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / "source-manifest.json").write_text(serialize_report(manifest), encoding="utf-8")
    (args.output / "generated-cases.json").write_text(
        json.dumps([c.model_dump(mode="json") for c in cases], ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    config = dict(
        endpoint=args.endpoint,
        model=args.model,
        temperature=0,
        context_tokens=16384,
        max_output_tokens=2048,
        timeout_seconds=60,
        transport_retries=0,
        legacy_candidate_limit=1,
        legacy_discovery_mode="legacy",
        legacy_format_repairs=1,
        investigation_model_calls=policy.MAX_MODEL_CALLS,
        investigation_tool_calls=policy.MAX_TOOL_CALLS,
        investigation_deadline_seconds=policy.DEADLINE_SECONDS,
        question=QUESTION,
        legacy_question_parameter="UNSUPPORTED_FIXED_PRODUCTION_PROMPT",
        legacy_transport="EXPERIMENT_BOUNDED_NO_PROXY_NO_REDIRECT",
        production_defaults_changed=[
            "temperature .1 -> 0",
            "output 4096 -> 2048",
            "retries 1 -> 0",
            "HTTP timeout -> 60",
        ],
        shared_admission_limit=12,
        outer_deadline_seconds=900,
        seed="NOT_SUPPORTED_BY_THESE_INTERFACES",
    )
    metadata: dict[str, Any] = dict(
        source_sha256=digest(manifest),
        config=config,
        config_sha256=digest(config),
        order=["legacy", "investigation"],
        comparison_valid=False,
        warmup_requests=0,
    )
    report: dict[str, Any] = dict(
        version="generated-investigation-evaluation-v1",
        execution="OFFLINE_NOT_EXECUTED",
        complete=False,
        expected_rows=18,
        rows=[],
        metadata=metadata,
    )
    code = 0
    deadline = None
    matrix_manifest = None
    if args.real_local_matrix:
        from .ai_investigation_evaluation_matrix import run_matrix

        report, matrix_manifest, deadline = run_matrix(
            args.output,
            endpoint=args.endpoint,
            model=args.model,
            expected_digest=args.expected_model_digest,
            metadata=metadata,
        )
        code = 0 if report["complete"] and report["metadata"]["comparison_valid"] else 2
    elif args.real_local_model or args.preflight_local_model:
        experiment = LocalExperiment(
            real_local_model=True, endpoint=args.endpoint, model=args.model
        )
        before = experiment.metadata()
        metadata["model_before"] = before
        metadata["cold_start_observation"] = (
            "NO_LOADED_MODELS" if not before["loaded_names"] else "MODELS_ALREADY_LOADED"
        )
        if before["tag"]["digest"] != args.expected_model_digest:
            raise ValueError("MODEL_DIGEST_MISMATCH_BEFORE_INFERENCE")
        case = next(c for c in cases if c.scenario == args.case)
        # Explicit persistent pre-inference receipt; a crash cannot masquerade as a completed pair.
        (args.output / "admission.json").write_text(
            serialize_report(
                dict(
                    inference_started=False,
                    intended_case=case.case_id,
                    data_sha256=case.data_sha256,
                    metadata=metadata,
                )
            ),
            encoding="utf-8",
        )
        if args.real_local_model:
            deadline = experiment.budget.deadline
            rows = evaluate_pair(case, experiment.legacy, experiment.investigation)
            collect_telemetry(rows, experiment)
            # Preserve observations before optional metadata or aggregation can fail.
            (args.output / "observed-rows.json").write_text(
                serialize_report({"rows": rows}), encoding="utf-8"
            )
            after = None
            try:
                after = experiment.metadata()
                metadata["model_after"] = after
                metadata["comparison_valid"] = before["tag"]["digest"] == after["tag"]["digest"]
            except (ValueError, OSError, TimeoutError):
                metadata["model_after"] = None
                metadata["metadata_error"] = "POST_INFERENCE_METADATA_UNAVAILABLE"
            metadata["admitted_inference_attempts"] = experiment.budget.attempts
            metadata["backend_generation_physically_cancelled"] = None
            for row in rows:
                row["model_observations"] = {"before": before, "after": after}
            report = build_report((case,), rows, metadata=metadata)
            report["execution"] = "REAL_LOCAL_MODEL"
            code = 0 if report["metadata"]["comparison_valid"] else 2
        else:
            report["execution"] = "METADATA_ONLY_NO_INFERENCE"
    return _publish_report(
        args.output,
        report,
        code,
        deadline=deadline,
        matrix_manifest=matrix_manifest,
    )


if __name__ == "__main__":
    raise SystemExit(main())
