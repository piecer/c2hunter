"""Admission/HTTP fences and numerical budget controls; no outbound transport."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.ai_investigation_contract import InvestigationError
from c2hunter_controller.ai_investigation_http import RESPONSE_LIMIT
from c2hunter_controller.app import create_app
from tests.test_ai_investigation_http_runtime import HEADERS, configured, settings
from tests.test_ai_job_investigation_api import BASE, CAPS
from tests.test_ai_job_investigation_service import (
    adaptive,
    request_for,
    scripted,
    service_for,
)
from tests.test_ai_job_investigation_service import (
    repository as _repository,
)

repository = _repository


def test_owner_and_response_size_fences(repository, monkeypatch):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        config = settings(
            ai_job_investigation_enabled=True,
            ai_investigation_inline_enabled=True,
            admin_token_sha256=hashlib.sha256(b"admin").hexdigest(),
        )
        # Also prove the JOB path does not inherit anonymous legacy mode.
        config.api_auth_required = False
        app = create_app(config, repository, ai_gateway=configured(gateway))
        service = app.state.job_investigation_service
        monkeypatch.setattr(service.store, "claim", lambda _: None)
        with TestClient(app) as client:
            assert client.get(CAPS).status_code == 401
            posted = client.post(BASE, headers=HEADERS, json=request_for())
            assert posted.status_code == 202, posted.text
            path = BASE + "/" + posted.json()["id"]
            foreign = {"Authorization": "Bearer admin"}
            for suffix in ("", "/steps", "/evidence/" + "a" * 64):
                assert client.get(path + suffix, headers=foreign).status_code == 404
            assert client.post(path + "/cancel", headers=foreign).status_code == 404
            assert client.get(BASE, headers=foreign).json()["items"] == []
            monkeypatch.setattr(service, "get", lambda *_: {"oversized": "x" * RESPONSE_LIMIT})
            refused = client.get(path, headers=HEADERS)
            assert (
                refused.status_code == 503
                and refused.json()["error"]["code"] == "JOB_RESPONSE_LIMIT"
            )
            assert len(refused.content) < 1024 and calls == []
            # Old IP route/parser remains available and keeps its IP wire.
            ip = client.get("/api/v1/ai-investigations/capabilities", headers=HEADERS)
            assert ip.json()["version"] == "ip-investigation-v1"


@pytest.mark.parametrize("server,consent", [(False, False), (False, True), (True, False)])
def test_remote_consent_fail_closed(repository, monkeypatch, server, consent):
    with scripted(monkeypatch, adaptive) as (gateway, calls):
        from dataclasses import replace

        gateway = replace(gateway, base_url="https://8.8.8.8/v1", server_allow_remote=server)
        service = service_for(repository, gateway)
        with pytest.raises(InvestigationError, match="REMOTE_NOT_ALLOWED"):
            service.admit("alice", "job", request_for(allow_remote=consent))
        assert calls == [] and service.store.page("alice", "job") == []


def test_three_positive_peers_share_global_meters(repository, monkeypatch):
    from tests.test_ai_job_investigation_source import flow, job

    repository.save_job(
        job([flow(domain="x.test"), flow(destination_ip="2001:db8::2", domain="y.test")])
    )

    def respond(data, index):
        if index == 1:
            return dict(
                action="select_peers",
                pool_sha256=data["pool"]["pool_sha256"],
                peer_ids=[p["peer_id"] for p in data["pool"]["entries"]],
            )
        peers = data["selection"]["peer_ids"]
        if index == 2:
            return dict(
                action="request_tools",
                tools=[
                    dict(peer_id=p, tool="peer_protocol_observations", arguments={}) for p in peers
                ],
            )
        assessments = []
        for peer in peers:
            own = [e for e in data["observations"] if e["peer_id"] == peer]

            def interpretation(evidence):
                return dict(
                    text="관측된 자료",
                    evidence_ids=[evidence["evidence_id"]],
                    metric_refs=[evidence["metrics"][0]["ref"]],
                )

            assessments.append(
                dict(
                    peer_id=peer,
                    verdict="SUSPICIOUS_C2",
                    support=[interpretation(own[0])],
                    counterevidence=[interpretation(own[-1])],
                    uncertainty=["완전한 캡처 아님"],
                    next_checks=[],
                )
            )
        return dict(action="finish", assessments=assessments)

    with scripted(monkeypatch, respond) as (gateway, calls):
        service = service_for(repository, gateway)
        queued, _ = service.admit("alice", "job", request_for())
        result = service.run_next("worker")
        run = service.get("alice", "job", queued.id)
        assert result.acknowledge_exit and run.status == "COMPLETED"
        assert run.coverage.investigated_peers == 3
        assert run.progress.tool_calls == 7 and run.progress.model_calls == len(calls) == 3
        assert run.progress.source_records == 2 and run.progress.source_bytes == 8650752
        ids = [e.evidence_id for a in run.result.assessments for e in a.evidence_quality]
        assert len(ids) == len(set(ids)) == 6
