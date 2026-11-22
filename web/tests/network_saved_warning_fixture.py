"""Actual packet-cap admission warning -> retained old report -> public GET.

The retained report/envelope arrive on stdin from the existing producer fixtures.
Only the saved-era combination is modeled: GET must not silently backfill it.
No deployed controller, capture, worker or model is contacted.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / p) for p in (
    "controller/src", "controller/tests", "analysis/src", "analysis/tests", "sensor/worker/src",
)]

from fastapi.testclient import TestClient
from test_durable_pipeline import QueueStub, flow, job_payload, register_sensor
from c2hunter_controller.app import create_app, _public_job
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.storage import MemoryFlowStore


def witness(envelope):
    repo, store, queue = MemoryRepository(), MemoryFlowStore(), QueueStub()
    app = create_app(Settings(environment="test", inline_flow_records_enabled=False),
                     repo, flow_store=store, queue=queue)
    with TestClient(app) as client:
        register_sensor(client)
        store.ingest_batch("s1", "saved-warning-fixture", [flow(i) for i in range(1, 6)])
        request = job_payload()
        request["analysis"]["module"] = "network_anomaly"
        request["capture"]["max_packets"] = 3
        response = client.post("/api/v1/analysis-jobs", json=request)
        assert response.status_code == 201, response.text
        admitted = repo.get_job(response.json()["id"])
        assert admitted["capture_limit"]["retained_packets"] == 3
        assert admitted["capture_limit"]["discarded_packets"] == 2
        original = "capture.max_packets 제한으로 분석 데이터셋을 3 packets로 절단했습니다 (2 packets 제외)"
        assert original in admitted["warnings"]
        # Keep the actual emitted warning, not a copied formatter. This stored
        # report predates source-coverage propagation; do not re-run analysis.
        saved = {**admitted, **envelope, "warnings": [*admitted["warnings"], *envelope["warnings"]]}
        assert "CAPTURE_PACKET_LIMIT_REACHED" not in saved["network_anomaly"]["warnings"]
        repo.save_job(saved)
        result = client.get(f"/api/v1/analysis-jobs/{saved['id']}")
        assert result.status_code == 200, result.text
        public = result.json()
        assert public == json.loads(json.dumps(_public_job(repo.get_job_summary(saved["id"]))))
        assert public["network_anomaly"] == envelope["network_anomaly"]
        assert original in public["warnings"]
        assert "flow_records" not in public
        origins = {name: str(Path(module.__file__).resolve())
                   for name, module in list(sys.modules.items())
                   if name.startswith(("c2hunter_analysis", "c2hunter_controller"))
                   and getattr(module, "__file__", None)}
        assert all(Path(path).is_relative_to(ROOT) for path in origins.values())
        # A genuine legacy report has no source packet-cap qualifier either.
        from test_network_anomaly import frame, records
        from c2hunter_analysis.network_anomaly import analyze_network_anomalies
        legacy_report = analyze_network_anomalies(records(frame()))
        assert legacy_report["version"] == "network-anomaly-v1"
        assert "CAPTURE_PACKET_LIMIT_REACHED" not in legacy_report["warnings"]
        repo.save_job({**saved, "network_anomaly": legacy_report})
        legacy = client.get(f"/api/v1/analysis-jobs/{saved['id']}").json()
        assert legacy["network_anomaly"] == legacy_report
        assert legacy["warnings"] == public["warnings"]
        return {"job": public, "legacy": legacy, "warning": original, "origins": origins}


if __name__ == "__main__":
    print(json.dumps(witness(json.load(sys.stdin)), ensure_ascii=False))
