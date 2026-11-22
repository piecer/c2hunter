"""Real DDoS producer -> private persisted job -> public list/detail wire.

Synthetic packet observations and capture metadata, not a hand-written summary.
No listener, external services, production storage, provider or model calls.
"""
import hashlib
import json
import sys
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[2]
DENIED = []


def audit(event, args):
    if event in {"socket.bind", "socket.connect", "socket.connect_ex", "socket.getaddrinfo",
                 "socket.gethostbyname", "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn"}:
        DENIED.append(event)
        raise RuntimeError("History producer denies network/process operation: " + event)


sys.addaudithook(audit)
sys.path[:0] = [str(ROOT / part) for part in
               ("controller/tests", "controller/src", "analysis/src", "sensor/worker/src")]
from test_analysis_job_api import api
from test_ddos_attack_api import ddos_payload
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository
import c2hunter_controller.app as app_module
import c2hunter_analysis.ddos_attack as producer_module


def generate():
    repo = MemoryRepository()
    client = api(repository=repo, settings=Settings(
        _env_file=None, environment="test", database_url="memory://",
        clickhouse_url="memory://", redis_url="memory://", s3_endpoint="memory://",
        ai_analysis_enabled=False,
    ))
    try:
        created = client.post("/api/v1/analysis-jobs", json=ddos_payload("history-parent"))
        assert created.status_code == 201, created.text
        parent = repo.get_job(created.json()["id"])
        parent.pop("ddos_coverage_context", None)
        parent["source"] = {"captured_packet_count": 100, "skipped_packet_count": 3}
        parent["capture_quality"] = {"dropped_packet_count": 7, "clock_skew_detected": True}
        parent["capture_incomplete"] = True
        parent["capture"]["max_packets"] = 50
        repo.save_job_metadata(parent)
        response = client.post(
            f"/api/v1/analysis-jobs/{parent['id']}/reanalyze",
            json={"idempotency_key": "history-limited-child"},
        )
        assert response.status_code == 201, response.text
        child = repo.get_job(response.json()["id"])
        # Identity-only fixture substitution exercises literal transport encoding.
        # Report, warnings and compact summary remain the producer's saved values.
        child["id"] = "history:ddos% 한글?#"
        child["name"] = "Producer limited DDoS"
        repo.save_job(child)
        persisted = repo.get_job(child["id"])
        report = persisted["ddos_attack"]
        assert report["summary"]["counts_are_lower_bounds"] is True
        assert report["summary"]["truncated"] is True
        assert report["summary"]["coverage_complete"] is False
        assert report["summary"]["packet_count"] == 50
        assert report["warnings"]
        list_path = "/api/v1/analysis-jobs?search=Producer%20limited%20DDoS&status=COMPLETED&sort=name&page=1&page_size=50"
        detail_path = "/api/v1/analysis-jobs/" + quote(child["id"], safe="")
        listing = client.get(list_path)
        detail = client.get(detail_path)
        ai_runs = client.get(detail_path + "/ai-runs")
        assert ai_runs.status_code == 200, ai_runs.text
        assert ai_runs.json() == {"items": [], "total": 0, "page": 1, "page_size": 50}
        assert listing.status_code == detail.status_code == 200
        rows = listing.json()["items"]
        assert len(rows) == listing.json()["total"] == 1
        row = rows[0]
        assert row["id"] == child["id"]
        assert "ddos_attack" not in row
        assert set(row["ddos_attack_summary"]) == {
            "verdict", "confidence", "finding_count", "primary_attack_type",
            "primary_objective", "coverage_complete",
        }
        assert row["ddos_attack_summary"] == persisted["ddos_attack_summary"]
        assert row["warnings"] == persisted["warnings"]
        assert row["warnings"]
        assert detail.json()["ddos_attack"] == report
        assert repo.get_job(child["id"]) == persisted
        assert not DENIED
        origins = {}
        for module in (app_module, producer_module):
            assert module.__file__ is not None
            path = Path(module.__file__).resolve()
            assert path.is_relative_to(ROOT)
            origins[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"list_path": list_path, "detail_path": detail_path,
                "list_wire": listing.text, "detail_wire": detail.text,
                "ai_runs_wire": ai_runs.text,
                "persisted_report": report, "producer_origins": origins,
                "denied_operations": DENIED}
    finally:
        client.close()
        repo.close()


if __name__ == "__main__":
    print(json.dumps(generate(), ensure_ascii=False))
