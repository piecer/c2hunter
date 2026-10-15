from copy import deepcopy

import pytest
from c2hunter_worker.analysis import execute_analysis
from fastapi.testclient import TestClient
from test_ddos_attack_api import ddos_payload

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


@pytest.mark.parametrize("sqlite", [False, True])
def test_selected_reference_is_durable_detached_and_private(tmp_path, sqlite):
    repo = SQLiteRepository(str(tmp_path / "reference.db")) if sqlite else MemoryRepository()
    repo.upsert_sensor({"sensor_id": "s1"})
    client = TestClient(create_app(Settings(environment="test"), repo))
    normal_request = ddos_payload("normal")
    # Held-out normal TCP ACKs, not a subset blessed from the attack dataset.
    for row in normal_request["flow_records"]:
        row.update(
            tcp_flags={"syn": 0, "ack": 1, "rst": 0, "fin": 0},
            tcp_syn_count=0,
            tcp_syn_only_count=0,
            tcp_ack_count=1,
            tcp_ack_only_count=1,
        )
    normal = client.post("/api/v1/analysis-jobs", json=normal_request).json()
    request = ddos_payload("attack")
    request["ddos_normal_reference"] = {"job_id": normal["id"], "dataset_id": normal["dataset_id"]}
    response = client.post("/api/v1/analysis-jobs", json=request)
    assert response.status_code == 201, response.text
    public = response.json()
    assert "ddos_reference_snapshot" not in public
    saved = repo.get_job(public["id"])
    snapshot = deepcopy(saved["ddos_reference_snapshot"])
    evaluation = public["ddos_attack"]["findings"][0]["signature_candidates"][0]["evaluation"]
    assert evaluation["normal"]["status"] == "MEASURED"
    assert evaluation["normal"]["result"]["matched_records"] == 0
    assert evaluation["normal"]["result"]["eligible_records"] == 100
    assert evaluation["normal"]["result"]["record_match_rate"] == 0
    predicate = evaluation["predicate"]
    # Independent application of emitted conditions to held-out raw normal data.
    independent_matches = sum(
        row["destination_ip"] == predicate["target_ip"]
        and row["direction"] == predicate["direction"]
        and row["protocol"] == predicate["protocol"]
        and (predicate["source_ports"] is None or row["source_port"] in predicate["source_ports"])
        and (
            predicate["destination_ports"] is None
            or row["destination_port"] in predicate["destination_ports"]
        )
        and all(
            row["tcp_flags"].get(key) == value
            for key, value in (predicate["tcp_flags"] or {}).items()
        )
        for row in normal_request["flow_records"]
    )
    assert evaluation["normal"]["result"]["matched_records"] == independent_matches
    assert snapshot["reference"]["dataset_id"] == normal["dataset_id"]
    # A valid report from a different request must not erase the selected reference.
    from c2hunter_controller.app import _validated_ddos_report

    without_reference = deepcopy(saved)
    without_reference.pop("ddos_reference_snapshot")
    without_reference.pop("ddos_reference_binding")
    foreign_report = execute_analysis(without_reference)["ddos_attack"]
    with pytest.raises(ValueError, match="reference"):
        _validated_ddos_report(foreign_report, saved)

    original = repo.get_job(normal["id"])
    original["flow_records"] = request["flow_records"]
    repo.save_job(original)
    repo.delete_job(normal["id"])
    assert repo.get_job(normal["id"]) is None
    if sqlite:
        repo.close()
        repo = SQLiteRepository(str(tmp_path / "reference.db"))
    assert repo.get_job(public["id"])["ddos_reference_snapshot"] == snapshot
    missing = repo.get_job(public["id"])
    missing.pop("ddos_reference_snapshot")
    with pytest.raises(ValueError, match="reference"):
        execute_analysis(missing)
    rerun = execute_analysis(repo.get_job(public["id"]))["ddos_attack"]
    assert rerun["findings"][0]["signature_candidates"][0]["evaluation"] == evaluation
    client = TestClient(create_app(Settings(environment="test"), repo))
    child = client.post(
        f"/api/v1/analysis-jobs/{public['id']}/reanalyze", json={"idempotency_key": "child"}
    )
    assert child.status_code == 201, child.text
    assert repo.get_job(child.json()["id"])["ddos_reference_snapshot"] == snapshot
    assert (
        "ddos_reference_snapshot" not in client.get(f"/api/v1/analysis-jobs/{public['id']}").json()
    )
    if sqlite:
        repo.close()
