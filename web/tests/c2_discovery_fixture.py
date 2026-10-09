"""Emit real controller API bytes for the synthetic rule-free UI contract test."""
from __future__ import annotations

import json
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "analysis/src"), str(ROOT / "controller/src")]

from fastapi.testclient import TestClient

from c2hunter_controller.ai_analysis import FakeGateway
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository

job, target = runpy.run_path(str(ROOT / "controller/tests/test_ai_discovery.py"))["rule_free_job"]()
repo = MemoryRepository()
repo.jobs[job["id"]] = job
with TestClient(create_app(Settings(environment="test", ai_analysis_enabled=True), repo,
                           ai_gateway=FakeGateway())) as client:
    response = client.post(f"/api/v1/analysis-jobs/{job['id']}/ai-runs", json={
        "idempotency_key": "producer-contract", "candidate_limit": 1, "discovery_mode": "shadow",
    })
    assert response.status_code == 201, response.text
    run = response.json()
    assert run["status"] == "COMPLETED", run
    selection = client.get(f"/api/v1/ai-runs/{run['id']}/selection?offset=0&limit=20")
    assessments = client.get(f"/api/v1/ai-runs/{run['id']}/assessments")
    assert selection.status_code == assessments.status_code == 200
    # Preserve the actual serialized endpoint bodies; the browser parses these exact bytes.
    print(json.dumps({"target": target, "run_bytes": response.text,
                      "selection_bytes": selection.text, "assessment_bytes": assessments.text}))
