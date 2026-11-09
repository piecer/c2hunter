"""Frozen-byte producers execute real app/service/store/gateway paths offline."""

import time

import pytest
from fastapi.testclient import TestClient

from c2hunter_controller.ai_investigation_contract import Evidence, canonical_bytes
from c2hunter_controller.ai_investigation_http import encoded
from c2hunter_controller.ai_job_investigation_runtime_schema import (
    ACTION,
    JobCapabilities,
    JobResult,
    JobRun,
    JobStep,
)
from c2hunter_controller.app import create_app
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_investigation_http_runtime import HEADERS, configured, settings
from tests.test_ai_job_investigation_api import BASE, CAPS
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted
from tests.test_ai_job_investigation_source import flow, job
from tests.test_ai_job_investigation_worker import wait_for


def producer_fixtures():
    output = {}
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test")]))
    mode = ["completed"]

    def respond(data, index):
        return (
            adaptive(data, index)
            if mode[0] == "completed"
            else {"action": "finish", "assessments": []}
        )

    with pytest.MonkeyPatch.context() as patcher:
        with scripted(patcher, respond) as (gateway, calls):
            app = create_app(
                settings(ai_job_investigation_enabled=True, ai_investigation_inline_enabled=True),
                repo,
                ai_gateway=configured(gateway),
            )
            svc = app.state.job_investigation_service
            store = svc.store
            patcher.setattr(store, "clock", lambda: 1000.0)
            claim, commit, execute = store.claim, store.commit_selection, svc.execute_claim

            def record(name, value):
                output[name] = encoded(value).body + b"\n"

            def claimed(worker):
                if mode[0] == "cancelled":
                    return None
                result = claim(worker)
                if result is not None and mode[0] == "completed":
                    record("run_pending", svc.get(result["owner_id"], "job", result["id"]))
                return result

            def selected(claim, **kwargs):
                result = commit(claim, **kwargs)
                if mode[0] == "completed":
                    record("run_selected", svc.get(result["owner_id"], "job", result["id"]))
                return result

            def execution(claim, *, deadline_monotonic):
                return execute(
                    claim,
                    deadline_monotonic=time.monotonic() - 1
                    if mode[0] == "failed"
                    else deadline_monotonic,
                )

            patcher.setattr(store, "claim", claimed)
            patcher.setattr(store, "commit_selection", selected)
            patcher.setattr(svc, "execute_claim", execution)
            with TestClient(app) as client:
                response = client.get(CAPS, headers=HEADERS)
                assert response.status_code == 200
                output["capabilities"] = response.content + b"\n"
                for name in ("completed", "partial", "failed", "cancelled"):
                    mode[0] = name
                    posted = client.post(BASE, headers=HEADERS, json=request_for(name))
                    assert posted.status_code == 202, posted.text
                    path = BASE + "/" + posted.json()["id"]
                    if name == "completed":
                        output["run_queued"] = posted.content + b"\n"
                    if name == "cancelled":
                        response = client.post(path + "/cancel", headers=HEADERS)
                    else:

                        def done(path=path, name=name):
                            r = client.get(path, headers=HEADERS)
                            assert r.status_code == 200, r.text
                            return r if r.json()["status"] == name.upper() else None

                        response = wait_for(done)
                    output["run_" + name] = response.content + b"\n"
                    if name == "completed":
                        steps = client.get(path + "/steps", headers=HEADERS)
                        output["steps_page"] = steps.content + b"\n"
                        output["page_runs"] = client.get(BASE, headers=HEADERS).content + b"\n"
                        record(
                            "result_completed",
                            svc.get(posted.json()["owner_id"], "job", posted.json()["id"]).result,
                        )
                        for step in steps.json()["items"]:
                            record(
                                "step_"
                                + (
                                    "seed"
                                    if step["origin"] == "AUTOMATIC_SEED"
                                    else step["kind"].lower()
                                ),
                                step,
                            )
                            if step["tool"] == "peer_protocol_observations":
                                output["evidence_protocol"] = (
                                    client.get(
                                        path + "/evidence/" + step["evidence_id"], headers=HEADERS
                                    ).content
                                    + b"\n"
                                )
                    wait_for(lambda: app.state.investigation_runtime.active_count == 0)
                assert len(calls) == 5
            assert app.state.investigation_drained
    for name, model in {
        "run": JobRun,
        "step": JobStep,
        "result": JobResult,
        "capabilities": JobCapabilities,
        "evidence": Evidence,
    }.items():
        output["schema_" + name] = canonical_bytes(model.model_json_schema()) + b"\n"
    output["schema_action"] = canonical_bytes(ACTION.json_schema()) + b"\n"
    repo.close()
    return output


def test_producer_fixtures_are_real_repeatable_closed_bytes():
    producer = globals().get("producer_fixtures")
    assert callable(producer), "actual JOB producer fixtures missing"
    first, second = producer(), producer()
    assert first == second
    assert {
        "run_queued",
        "run_pending",
        "run_selected",
        "run_completed",
        "run_partial",
        "run_failed",
        "run_cancelled",
        "evidence_protocol",
        "schema_run",
        "schema_action",
    } <= first.keys()
    from c2hunter_controller.ai_job_investigation_runtime_schema import JobRun

    for name, raw in first.items():
        assert (
            raw.endswith(b"\n")
            and len(raw) <= (262144 if name.startswith("schema_") else 65536) + 1
        )
        if name.startswith("run_"):
            JobRun.model_validate_json(raw[:-1])
