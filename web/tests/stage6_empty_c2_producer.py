"""Actual COMPLETED, zero-candidate API wire from the memory-only producer."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def audit(event, args):
    if event in {
        "socket.bind", "socket.connect", "socket.connect_ex", "socket.getaddrinfo",
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        raise RuntimeError("Empty-result producer forbids " + event)


sys.addaudithook(audit)
sys.path[:0] = [str(ROOT / part) for part in (
    "controller/tests", "controller/src", "analysis/src", "sensor/worker/src",
)]
from test_analysis_job_api import api, payload, synthetic_flows
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository


def generate():
    repo = MemoryRepository()
    client = None
    try:
        client = api(repository=repo, settings=Settings(
            _env_file=None, environment="test", database_url="memory://",
            clickhouse_url="memory://", redis_url="memory://", s3_endpoint="memory://",
            ai_analysis_enabled=False,
        ))
        response = client.post("/api/v1/analysis-jobs", json=payload(
            flows=[synthetic_flows()[0]], key="test",
        ))
        assert response.status_code == 201, response.text
        job_id = response.json()["id"]
        detail = client.get("/api/v1/analysis-jobs/" + job_id)
        rows = client.get(
            "/api/v1/analysis-jobs/" + job_id
            + "/candidates?page=1&page_size=25&minimum_score=0&sort=-score"
        )
        assert detail.status_code == rows.status_code == 200
        assert detail.json()["status"] == "COMPLETED", detail.text
        assert rows.json()["total"] == 0 and rows.json()["items"] == []
        origins = {
            name: str(Path(module.__file__).resolve())
            for name, module in sys.modules.copy().items()
            if name.startswith("c2hunter_") and getattr(module, "__file__", None)
        }
        assert origins and all(Path(path).is_relative_to(ROOT) for path in origins.values())
        return {
            "job_wire": detail.text, "candidates_wire": rows.text,
            "origins": origins, "memory_only": True,
        }
    finally:
        if client is not None:
            client.close()
        repo.close()


if __name__ == "__main__":
    print(json.dumps(generate()))
