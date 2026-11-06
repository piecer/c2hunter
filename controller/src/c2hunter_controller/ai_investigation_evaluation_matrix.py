"""Fixed nine-pair runner. No retries, resume, model tuning or default network access."""

from __future__ import annotations

import time
from copy import deepcopy
from pathlib import Path
from typing import Any

from . import ai_investigation_evaluation as ev
from . import ai_investigation_evaluation_runtime as rt


def _save(path: Path, value: dict[str, Any]) -> None:
    text = ev.serialize_report(value)
    with path.open("x", encoding="utf-8") as out:
        out.write(text)


def run_matrix(
    output: Path, *, endpoint: str, model: str, expected_digest: str, metadata: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], float]:
    """Run the fixed generated corpus; preserve each pair before the next admission.

    Called only by the explicit opt-in CLI. Metadata observes tags, not executing
    weight bytes. Synchronous services release their owned stores before return;
    cleanup is not a fresh inference or execution allowance. Return the original
    deadline and final manifest to the CLI publisher; helper completion is not
    successful final publication.
    """
    cases = ev.generate_cases()
    budget = rt.AttemptBudget(deadline=time.monotonic() + 8100, limit=108)
    entries: list[dict[str, Any]] = [
        dict(case_id=c.case_id, data_sha256=c.data_sha256, state="NOT_RUN", reason="NOT_REACHED")
        for c in cases
    ]
    manifest: dict[str, Any] = dict(
        version="generated-matrix-v1",
        pairs=entries,
        expected_rows=18,
        deadline_monotonic=budget.deadline,
        execution_ceiling_seconds=8100,
        inference_ceiling=108,
        per_pair_seconds=900,
        per_pair_inference_ceiling=12,
        required_supervisor_cleanup_seconds=30,
        deadline_enforcement="COOPERATIVE_WITH_EXTERNAL_SUPERVISOR_REQUIRED",
        admitted_inference_attempts=0,
        backend_generation_physically_cancelled=None,
    )
    _save(output / "matrix-admission.json", manifest)
    rows: list[dict[str, Any]] = []
    report: dict[str, Any] | None = None
    failure: str | None = None
    for index, case in enumerate(cases):
        entry = entries[index]
        try:
            budget.check()
            entry["state"] = "UNRESOLVED"
            experiment = rt.LocalExperiment(
                real_local_model=True, endpoint=endpoint, model=model, matrix_budget=budget
            )
            pair_dir = output / case.case_id
            pair_dir.mkdir()
            before = experiment.metadata()
            if before["tag"]["digest"] != expected_digest:
                raise ValueError("model identity mismatch")
            _save(
                pair_dir / "admission.json",
                dict(
                    case_id=case.case_id,
                    data_sha256=case.data_sha256,
                    model_before=before,
                    inference_started=False,
                ),
            )
            pair = ev.evaluate_pair(case, experiment.legacy, experiment.investigation)
            ev.collect_telemetry(pair, experiment)
            _save(pair_dir / "observed-rows.json", {"rows": pair})
            after = None
            try:
                after = experiment.metadata()
            except (ValueError, OSError, TimeoutError):
                pass
            for row in pair:
                row["model_observations"] = {"before": before, "after": after}
            pair_meta = deepcopy(metadata)
            pair_meta.update(
                model_before=before,
                model_after=after,
                admitted_inference_attempts=experiment.budget.attempts,
                cold_start_observation="NO_LOADED_MODELS"
                if not before["loaded_names"]
                else "MODELS_ALREADY_LOADED",
            )
            rows.extend(pair)
            try:
                pair_report = ev.build_report((case,), pair, metadata=pair_meta)
            except ValueError:
                pair_report = dict(
                    complete=True,
                    expected_rows=2,
                    rows=pair,
                    metadata={
                        **pair_meta,
                        "comparison_valid": False,
                        "comparison_error": "PAIR_IDENTITY_INVALID",
                    },
                )
            _save(pair_dir / "report.json", pair_report)
            entry.update(
                state="OBSERVED",
                reason=None,
                report=f"{case.case_id}/report.json",
                report_sha256=ev.digest(pair_report),
            )
            report = ev.build_report(cases[: index + 1], rows, metadata=metadata)
            if not report["metadata"]["comparison_valid"]:
                failure = "COMPARISON_IDENTITY_UNAVAILABLE_OR_CHANGED"
        except (ValueError, OSError, RuntimeError, TimeoutError):
            # Never publish arbitrary exception text or erase preceding observations.
            failure = "MATRIX_EXECUTION_OR_IDENTITY_INVALID"
            if entry["state"] != "OBSERVED":
                entry["reason"] = failure
        manifest["admitted_inference_attempts"] = budget.attempts
        _save(output / f"progress-{index + 1:02d}.json", manifest)
        if failure:
            break
    if time.monotonic() >= budget.deadline:
        failure = "MATRIX_DEADLINE_EXCEEDED"
    if report is None or failure:
        report = dict(
            version="generated-investigation-evaluation-v1",
            complete=len(rows) == 18,
            expected_rows=18,
            rows=rows,
            metadata={**metadata, "comparison_valid": False, "matrix_error": failure},
        )
    report["expected_rows"] = 18
    report["complete"] = len(rows) == 18
    report["execution"] = "REAL_LOCAL_MATRIX"
    manifest["complete"] = report["complete"]
    manifest["comparison_valid"] = report["metadata"]["comparison_valid"]
    manifest["stop_reason"] = failure
    return report, manifest, budget.deadline
