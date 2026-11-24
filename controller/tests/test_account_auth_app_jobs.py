from pathlib import Path

from fastapi.testclient import TestClient
from test_account_auth_http import ORIGIN, configured_app, login
from test_analysis_job_api import payload, synthetic_flows

from c2hunter_controller.auth_models import AuthError


def test_analysis_reserves_before_publication_and_inline_terminal(tmp_path: Path, monkeypatch):
    app, store = configured_app(tmp_path)
    repo = app.state.repository
    repo.upsert_sensor({"sensor_id": "s1"})
    original = repo.create_job
    seen = []

    def checked(job):
        assert store.job_audit_status("analysis", job["id"]) == "pending"
        seen.append(job["id"])
        return original(job)

    monkeypatch.setattr(repo, "create_job", checked)
    with TestClient(app, base_url=ORIGIN) as client:
        identity = login(client).json()["user"]["id"]
        result = client.post("/api/v1/analysis-jobs", json=payload(flows=synthetic_flows()))
        assert result.status_code == 201, result.text
        job_id = result.json()["id"]
        assert store.job_audit_status("analysis", job_id) == "complete"
        assert (
            client.get(f"/api/v1/analysis-jobs/{job_id}").headers["x-c2hunter-audit-status"]
            == "complete"
        )
        events = client.get("/api/v1/admin/audit?action=job.lifecycle").json()["items"]
        assert len(events) == 2
        assert {event["actor_id"] for event in events} == {identity}
        replay = client.post("/api/v1/analysis-jobs", json=payload(flows=synthetic_flows()))
        assert replay.json()["id"] == job_id
    assert seen


def test_reservation_outage_has_no_domain_publication(tmp_path: Path, monkeypatch):
    app, store = configured_app(tmp_path)
    repo = app.state.repository
    repo.upsert_sensor({"sensor_id": "s1"})

    def unavailable(*args, **kwargs):
        raise AuthError("SECURITY_UNAVAILABLE")

    monkeypatch.setattr(store, "reserve_job", unavailable)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        response = client.post("/api/v1/analysis-jobs", json=payload())
        assert response.status_code == 503
        assert repo.list_jobs() == []


def test_terminal_failure_is_unknown_without_domain_rollback(tmp_path: Path, monkeypatch):
    app, store = configured_app(tmp_path)
    repo = app.state.repository
    repo.upsert_sensor({"sensor_id": "s1"})

    def unavailable(*args, **kwargs):
        raise AuthError("SECURITY_UNAVAILABLE")

    original = store.finish_job
    monkeypatch.setattr(store, "finish_job", unavailable)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        response = client.post("/api/v1/analysis-jobs", json=payload(flows=synthetic_flows()))
        assert response.status_code == 503
        assert response.json()["error"]["outcome"] == "unknown"
        jobs = repo.list_jobs()
        assert len(jobs) == 1 and jobs[0]["status"] == "COMPLETED"
        assert store.job_audit_status("analysis", jobs[0]["id"]) == "pending"
        monkeypatch.setattr(store, "finish_job", original)


def test_sync_pcap_export_finishes_and_preserves_owner(tmp_path: Path):
    from test_analysis_history_pcap_api import _pcap

    app, store = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        uploaded = client.post(
            "/api/v1/pcap-analysis-jobs?name=sample&filename=sample.pcap",
            content=_pcap(),
            headers={"content-type": "application/octet-stream"},
        )
        assert uploaded.status_code == 201, uploaded.text
        job_id = uploaded.json()["id"]
        assert store.job_audit_status("analysis", job_id) == "complete"
        exported = client.post("/api/v1/pcap-exports", json={"job_id": job_id})
        assert exported.status_code == 201, exported.text
        export_id = exported.json()["id"]
        assert store.job_audit_status("pcap_export", export_id) == "complete"
        assert client.get(f"/api/v1/pcap-exports/{export_id}/download").status_code == 200
        import uuid

        legacy_id = str(uuid.uuid4())
        metadata = app.state.repository.get_export_metadata(export_id)
        metadata["id"] = legacy_id
        metadata.pop("principal_scope", None)
        app.state.repository.save_export(metadata, _pcap())
        for path in (
            f"/api/v1/pcap-exports/{legacy_id}",
            f"/api/v1/pcap-exports/{legacy_id}/download",
        ):
            assert client.get(path).status_code == 404
        assert client.post(f"/api/v1/pcap-exports/{legacy_id}/cancel", json={}).status_code == 404


def test_unhandled_domain_failure_is_safe_and_audited(tmp_path: Path, monkeypatch):
    app, _ = configured_app(tmp_path)
    app.state.repository.upsert_sensor({"sensor_id": "s1"})

    def fail(job):
        raise RuntimeError("credential-bearing unexpected message")

    monkeypatch.setattr(app.state.repository, "create_job", fail)
    with TestClient(app, base_url=ORIGIN, raise_server_exceptions=False) as client:
        login(client)
        response = client.post("/api/v1/analysis-jobs", json=payload())
        assert response.status_code == 500
        assert response.headers["cache-control"] == "no-store"
        assert response.json()["error"]["outcome"] == "unknown"
        assert "credential-bearing" not in response.text
        events = client.get("/api/v1/admin/audit?action=http.operation").json()["items"]
        assert {item["outcome"] for item in events} == {"started", "unknown"}


def test_http_terminal_audit_failure_does_not_replay(tmp_path: Path, monkeypatch):
    app, store = configured_app(tmp_path)
    app.state.repository.upsert_sensor({"sensor_id": "s1"})
    original = store.record_event

    def fail_terminal(actor, action, target, outcome, **kwargs):
        if action == "http.operation" and outcome == "succeeded":
            raise AuthError("SECURITY_UNAVAILABLE")
        return original(actor, action, target, outcome, **kwargs)

    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        monkeypatch.setattr(store, "record_event", fail_terminal)
        response = client.post("/api/v1/analysis-jobs", json=payload())
        assert response.status_code == 503
        assert response.json()["error"]["outcome"] == "unknown"
        assert len(app.state.repository.list_jobs()) == 1


def test_worker_terminal_redelivery_repairs_before_ack(tmp_path: Path, monkeypatch):
    import pytest

    app, store = configured_app(tmp_path)
    repo, queue = app.state.repository, app.state.queue
    repo.upsert_sensor({"sensor_id": "s1"})
    acknowledgements = []
    monkeypatch.setattr(queue, "ack_result", acknowledgements.append)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        job_id = client.post("/api/v1/analysis-jobs", json=payload()).json()["id"]
        job = repo.get_job(job_id)
        job["status"] = "ANALYZING"
        repo.save_job(job)
        result = {
            "job_id": job_id,
            "receipt": "delivery",
            "status": "COMPLETED",
            "result": {"candidates": []},
        }
        original = store.finish_job

        def unavailable(*args, **kwargs):
            raise AuthError("SECURITY_UNAVAILABLE")

        monkeypatch.setattr(store, "finish_job", unavailable)
        queue.results.append(result)
        with pytest.raises(AuthError):
            app.state.process_results_once()
        assert not acknowledgements
        assert repo.get_job_summary(job_id)["status"] == "COMPLETED"
        monkeypatch.setattr(store, "finish_job", original)
        queue.results.append(result)
        assert app.state.process_results_once()
        assert acknowledgements == ["delivery"]
        assert store.job_audit_status("analysis", job_id) == "complete"
        queue.results.append(result)
        app.state.process_results_once()
        events = client.get("/api/v1/admin/audit?action=job.lifecycle").json()["items"]
        assert len(events) == 2


def test_live_restart_failure_audits_original_link(tmp_path: Path):
    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings
    from c2hunter_controller.repositories import SQLiteRepository
    from c2hunter_controller.storage import MemoryFlowStore

    _, store = configured_app(tmp_path)
    repo = SQLiteRepository(tmp_path / "jobs.sqlite3")
    repo.upsert_sensor({"sensor_id": "s1"})
    flows = MemoryFlowStore()
    settings = Settings(
        environment="test",
        api_auth_required=True,
        account_auth_enabled=True,
        auth_public_origin=ORIGIN,
        inline_flow_records_enabled=False,
    )
    first = create_app(settings, repo, auth_store=store, flow_store=flows)
    with TestClient(first, base_url=ORIGIN) as client:
        login(client)
        data = payload()
        data["mode"] = "LIVE"
        result = client.post("/api/v1/analysis-jobs", json=data)
        assert result.status_code == 201, result.text
        job_id = result.json()["id"]
        job = repo.get_job_summary(job_id)
        job["volatile_capture"] = {"owner": "local-analysis-v1", "store": flows.continuity_id}
        repo.save_job_metadata(job)
    restarted = create_app(
        settings,
        repo,
        auth_store=store,
        flow_store=MemoryFlowStore(),
        local_analysis_worker_health_path=tmp_path / "health.json",
    )
    # Observe the real preparation callback before a maintenance worker can repair it.
    restarted.state.local_analysis_runtime.prepare()
    assert repo.get_job_summary(job_id)["status"] == "FAILED"
    assert store.job_audit_status("analysis", job_id) == "complete"
    repo.close()


def test_inline_invalid_result_records_failed_terminal(tmp_path: Path, monkeypatch):
    import c2hunter_analysis.ddos_job as ddos
    from test_ddos_attack_api import ddos_payload

    app, store = configured_app(tmp_path)
    app.state.repository.upsert_sensor({"sensor_id": "s1"})
    monkeypatch.setattr(ddos, "analyze_ddos_job", lambda job: {})
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        response = client.post("/api/v1/analysis-jobs", json=ddos_payload())
        assert response.status_code == 500
        job = app.state.repository.list_jobs()[0]
        assert job["status"] == "FAILED"
        assert store.job_audit_status("analysis", job["id"]) == "complete"


def test_preparation_failure_audits_persisted_terminal(tmp_path: Path):
    app, store = configured_app(tmp_path)
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        response = client.post(
            "/api/v1/pcap-analysis-jobs/initiate",
            json={
                "name": "bad",
                "filename": "bad.pcap",
                "idempotency_key": "bad-capture",
                "internal_networks": ["10.0.0.0/8"],
            },
        )
        assert response.status_code == 201, response.text
        job_id = response.json()["id"]
        uploaded = client.put(
            f"/api/v1/pcap-analysis-jobs/{job_id}/capture",
            content=b"bad pcap",
            headers={"content-type": "application/octet-stream"},
        )
        assert uploaded.status_code == 202, uploaded.text
        assert app.state.process_pcap_preparations_once()
        assert app.state.repository.get_job_summary(job_id)["status"] == "FAILED"
        assert store.job_audit_status("analysis", job_id) == "complete"


def test_reanalysis_pcap_initiation_and_cancel_linkage(tmp_path: Path):
    app, store = configured_app(tmp_path)
    app.state.repository.upsert_sensor({"sensor_id": "s1"})
    with TestClient(app, base_url=ORIGIN) as client:
        login(client)
        initial = client.post("/api/v1/analysis-jobs", json=payload(flows=synthetic_flows())).json()
        replay = client.post(
            f"/api/v1/analysis-jobs/{initial['id']}/reanalyze",
            json={"idempotency_key": "reanalysis"},
        )
        assert replay.status_code == 201, replay.text
        assert store.job_audit_status("analysis", replay.json()["id"]) == "complete"
        initiation = client.post(
            "/api/v1/pcap-analysis-jobs/initiate",
            json={
                "name": "capture",
                "filename": "capture.pcap",
                "idempotency_key": "upload",
                "internal_networks": ["10.0.0.0/8"],
            },
        )
        assert initiation.status_code == 201, initiation.text
        job_id = initiation.json()["id"]
        assert store.job_audit_status("analysis", job_id) == "pending"
        cancelled = client.post(f"/api/v1/analysis-jobs/{job_id}/cancel", json={"reason": "test"})
        assert cancelled.status_code == 200, cancelled.text
        assert store.job_audit_status("analysis", job_id) == "complete"
