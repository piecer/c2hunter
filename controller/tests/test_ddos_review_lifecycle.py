from copy import deepcopy

from c2hunter_worker.analysis import execute_analysis
from fastapi.testclient import TestClient
from test_ddos_attack_api import ddos_payload
from test_durable_pipeline import QueueStub

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import SQLiteRepository


def test_cancelled_reference_job_not_resurrected_by_result(tmp_path):
    repo = SQLiteRepository(tmp_path / "cancel.db")
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    normal = client.post("/api/v1/analysis-jobs", json=ddos_payload("normal")).json()
    attack = client.post(
        "/api/v1/analysis-jobs",
        json={
            **ddos_payload("attack"),
            "ddos_normal_reference": {"job_id": normal["id"], "dataset_id": normal["dataset_id"]},
        },
    )
    assert attack.status_code == 201, attack.text
    queue = QueueStub()
    client = TestClient(
        create_app(
            Settings(environment="test", inline_flow_records_enabled=False), repo, queue=queue
        )
    )
    child = client.post(
        f"/api/v1/analysis-jobs/{attack.json()['id']}/reanalyze",
        json={"idempotency_key": "cancel-child"},
    )
    assert child.status_code == 201, child.text
    job_id = child.json()["id"]
    work = repo.get_job(job_id)
    cancelled = client.post(
        f"/api/v1/analysis-jobs/{job_id}/cancel", json={"reason": "review control"}
    )
    assert cancelled.status_code == 200, cancelled.text
    before = repo.get_job(job_id)
    queue.results.append(
        {
            "job_id": job_id,
            "status": "COMPLETED",
            "receipt": "cancel-result",
            "result": execute_analysis(work),
        }
    )
    assert client.app.state.process_results_once()
    assert repo.get_job(job_id) == before
    assert before["status"] == "CANCELLED" and queue.acked == ["cancel-result"]
    assert before["ddos_reference_snapshot"] == work["ddos_reference_snapshot"]
    repo.close()


def test_idempotency_different_valid_reference_keeps_original(tmp_path):
    repo = SQLiteRepository(tmp_path / "replay.db")
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    refs = []
    for key in ("normal-a", "normal-b"):
        r = client.post("/api/v1/analysis-jobs", json=ddos_payload(key))
        assert r.status_code == 201, r.text
        refs.append({"job_id": r.json()["id"], "dataset_id": r.json()["dataset_id"]})
    request = {**ddos_payload("attack"), "ddos_normal_reference": refs[0]}
    first = client.post("/api/v1/analysis-jobs", json=request)
    assert first.status_code == 201, first.text
    original = deepcopy(repo.get_job(first.json()["id"]))
    conflict = client.post(
        "/api/v1/analysis-jobs", json={**request, "ddos_normal_reference": refs[1]}
    )
    assert conflict.status_code == 409, conflict.text
    assert conflict.json()["error"]["code"] == "DDOS_REFERENCE_IDEMPOTENCY_CONFLICT"
    assert repo.get_job(original["id"]) == original and len(repo.list_jobs()) == 3
    repo.close()
