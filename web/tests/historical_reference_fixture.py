"""Deterministic no-I/O producer fixture; no model, LIVE run or real approval."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "controller"), str(ROOT / "controller/src"), str(ROOT / "analysis/src")]

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_read as reader
from c2hunter_controller._baseline_storage import finish_preview
from c2hunter_controller.historical_ai_builder import build_historical_target_snapshot
from c2hunter_controller.historical_ai_http import public_run, saved_page
from c2hunter_controller.historical_ai_storage import stage_admission
from c2hunter_controller.historical_baseline_api import _PREVIEW_FIELDS, _scope
from tests.historical_ai_fixtures import job, rule, world


def produce(sources: int, profiles: int = 1) -> dict:
    raw = job()
    if profiles > 1:
        from ipaddress import ip_address
        rows = raw["flow_records"]
        raw["flow_records"] = [
            {**row, ("destination_ip" if row["direction"] == "OUTBOUND" else "source_ip"): str(ip_address("203.0.113.1") + index)}
            for index in range(profiles) for row in rows
        ]
    inputs = world(kind="EVALUATION", candidates=[rule()], sources=sources, target=raw)
    request = inputs["request"]
    request["payload"]["baseline_reference"]["quality_review"] = None
    payload = dto.FrozenAIAnalysisRunCreate(**request["payload"])
    request["request_fingerprint"] = dto.request_fingerprint(
        request["analysis_job_id"], request["actor"], payload
    )
    request = dto.HistoricalAdmissionRequest(**request)
    jobs, candidates = {raw["id"]: raw}, {raw["id"]: [rule()]}
    scope = inputs["scope"]
    preview = finish_preview(reader._memory_acquire(jobs, candidates, raw["id"], "COMPARISON"), scope, "COMPARISON")
    target = reader.memory_ai_target(jobs, candidates, raw["id"], scope.config, None)
    run = stage_admission(request, target, scope, inputs["generation"], build_historical_target_snapshot)
    public = public_run(run)
    assert public["baseline_summary"]["quality_assurance"] == "UNREVIEWED"
    assert "TARGET_REVIEW_REQUIRED" in public["baseline_summary"]["warnings"]
    assert preview.source_binding_sha256 == payload.baseline_reference.target_source_binding_sha256
    return {
        "scope": _scope(scope),
        "preview": preview.model_dump(mode="json", include=_PREVIEW_FIELDS),
        "payload": payload.to_mapping(),
        "run": public,
        "comparisons": saved_page(run, "baseline_comparisons", 0, 20),
        "comparison_pages": [saved_page(run, "baseline_comparisons", offset, 20) for offset in range(0, profiles, 20)],
        "sources": saved_page(run, "baseline_sources", 0, 20),
    }


if __name__ == "__main__":
    assert Path(dto.__file__).resolve().is_relative_to(ROOT)
    from typing import get_args
    from c2hunter_analysis.behavior_baseline import ReasonCode
    print(json.dumps({"with_reference": produce(3), "empty": produce(0), "maximum": produce(3, 128), "reason_codes": sorted(get_args(ReasonCode))}, ensure_ascii=False, sort_keys=True))
