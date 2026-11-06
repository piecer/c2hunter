"""Real Memory/SQLite + HTTP structured-provider loop; no real inference claim."""

from __future__ import annotations

import importlib
import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from c2hunter_controller.ai_gateway import OpenAICompatibleGateway
from c2hunter_controller.ai_investigation_contract import (
    InvestigationError,
    SourceSnapshot,
    canonical_bytes,
)
from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway
from c2hunter_controller.ai_investigation_schema import InvestigationRequest
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_ai_investigation_evidence import flow, job


def api():
    assert importlib.util.find_spec("c2hunter_controller.ai_investigation") is not None, (
        "bounded investigation service/loop is missing"
    )
    return importlib.import_module("c2hunter_controller.ai_investigation")


@contextmanager
def structured_provider(respond, *, port=0):
    requests = []
    failures = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            try:
                action = respond(body, len(requests))
                if action is None:
                    self.close_connection = True
                    return
                content = action if isinstance(action, str) else json.dumps(action)
            except Exception as exc:
                failures.append(exc)
                content = "{}"
            raw = json.dumps(
                {"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    gateway = InvestigationModelGateway.from_configured_gateway(
        OpenAICompatibleGateway(
            base_url=f"http://127.0.0.1:{server.server_port}",
            model="scripted-functional-only",
            context_tokens=65536,
            max_output_tokens=2048,
        )
    )
    try:
        yield gateway, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
        assert not failures, failures


@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    repo = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "loop.db")
    )
    initialize_investigation_store(repo)
    repo.save_job(job([flow(domain="updates.example.test"), flow(source_ip="10.0.0.2")]))
    instance = InvestigationRunStore(repo)
    yield instance, repo
    repo.close()


def request_for(repo, **updates):
    value = dict(
        version="ip-investigation-v1",
        mode="IP",
        target_ip="2001:0db8::1",
        question="관측된 사실을 설명해 주세요",
        language="ko",
        idempotency_key="key",
        expected_source_sha256=repo.read_investigation_source("job").binding.source_sha256,
    )
    value.update(updates)
    return value


def observations(body):
    return json.loads(body["messages"][-1]["content"])["observations"]


def finish(evidence, **updates):
    value = {
        "action": "finish",
        "verdict": "NEEDS_REVIEW",
        "support": [
            {
                "text": "관측된 통신은 추가 검토가 필요합니다.",
                "evidence_ids": [evidence["evidence_id"]],
                "metric_refs": [evidence["metrics"][0]["ref"]],
            }
        ],
        "counterevidence": [],
        "uncertainty": ["정상 기준선은 없습니다."],
        "next_checks": ["승인된 자산 목록과 비교하세요."],
    }
    value.update(updates)
    return value


def adaptive(body, index):
    seen = observations(body)
    tools = {item["tool"] for item in seen}
    if "peer_protocol_observations" not in tools:
        return {
            "action": "request_tools",
            "tools": [{"tool": "peer_protocol_observations", "arguments": {"limit": 2}}],
        }
    if "compare_peer_cohort" not in tools:
        assert any(item.get("protocols") for item in seen)
        return {
            "action": "request_tools",
            "tools": [{"tool": "compare_peer_cohort", "arguments": {}}],
        }
    return finish(seen[0])


def test_real_vertical_model_tool_changed_observation_saved_replay(store, monkeypatch):
    module = api()
    s, repo = store
    request = request_for(repo)
    with structured_provider(adaptive) as (gateway, requests):
        service = module.InvestigationService(repo, s, gateway)
        monkeypatch.setattr(repo, "get_job", lambda *_: pytest.fail("unbounded loader"))
        run, created = service.admit("alice", "job", request)
        assert created and run.status == "QUEUED"
        assert run.target_ip == "2001:db8::1"
        outcome = service.run_next("worker")
        assert outcome.code is None and outcome.acknowledge_exit
        saved = service.get("alice", "job", run.id)
        assert saved.status == "COMPLETED" and saved.result.verdict == "NEEDS_REVIEW"
        assert outcome.claim["revision"] == saved.revision
        assert outcome.claim["status"] == saved.status
        assert saved.result.facts[0].value == 2
        assert saved.result.partial_scope and saved.result.limitations
        assert len(requests) == 3
        assert requests[0]["messages"] != requests[1]["messages"] != requests[2]["messages"]
        assert outcome.claim["budgets"]["model_calls"] == 3
        assert outcome.claim["budgets"]["tool_calls"] == 3
        assert outcome.claim["budgets"]["transport_attempts"] == 3
        # Compute ownership remains held until a supervisor has joined execution.
        assert outcome.claim["slot"] == "HELD"
        assert s.worker_exited(outcome.claim)
        monkeypatch.setattr(
            repo, "read_investigation_source", lambda *_a, **_k: pytest.fail("replay read source")
        )
        replay, created = service.admit("alice", "job", request)
        assert not created and replay == saved
        assert service.get("bob", "job", run.id) is None
        assert service.page("alice", "job") == [saved]
        assert "lease_token" not in saved.model_dump_json()
        assert "snapshot" not in saved.model_dump_json()
        assert service.steps("alice", "job", run.id)
        evidence_id = saved.result.support[0].evidence_ids[0]
        assert service.evidence("alice", "job", run.id, evidence_id).evidence_id == evidence_id


def test_preview_truthful_caps_and_accounting(store):
    s, repo = store
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        caps = service.capabilities()
        assert caps.snapshot_bytes == 131072 and caps.retained_evidence_bytes == 131072
        assert caps.preparation_concurrency_scope == "PROCESS_ONLY"
        assert caps.source_bytes_accounting == "RESERVED_READER_UPPER_BOUND_NOT_MEASURED"
        preview = service.source_preview("alice", "job", {"target_ip": "2001:db8::1"})
        assert preview.status == "OBSERVED" and preview.counts.matched == 2
        assert preview.source.source_sha256 == request_for(repo)["expected_source_sha256"]
        assert preview.snapshot_bytes <= caps.snapshot_bytes
        assert requests == []
        run, _ = service.admit("alice", "job", request_for(repo))
        outcome = service.run_next("worker")
        saved = service.get("alice", "job", run.id)
        assert saved.progress.source_bytes == 8 * 1024 * 1024 + 256 * 1024
        assert saved.progress.source_records == 2
        assert s.worker_exited(outcome.claim)


def test_admission_bounds_replay_and_actual_source_changes(store, monkeypatch):
    s, repo = store
    with structured_provider(adaptive) as (gateway, requests):
        service = api().InvestigationService(repo, s, gateway)
        req = request_for(repo)
        absent = {**req, "target_ip": "203.0.113.255"}
        with pytest.raises(InvestigationError, match="TARGET_NOT_OBSERVED"):
            service.admit("alice", "job", absent)
        assert s.page("alice", "job") == []
        run, _ = service.admit("alice", "job", req)
        repo.save_job(job([flow(total_bytes=999)]))
        assert service.admit("alice", "job", {**req, "target_ip": "2001:db8::1"}) == (run, False)
        with pytest.raises(InvestigationError, match="SOURCE_CHANGED"):
            service.admit("alice", "job", {**req, "idempotency_key": "new"})
        assert not requests
        # Source changes cannot affect the frozen execution.
        outcome = service.run_next("worker")
        assert service.get("alice", "job", run.id).result.counts.matched == 2
        assert s.worker_exited(outcome.claim)
        repo.delete_job("job")
        assert service.admit("alice", "job", req)[0].status == "COMPLETED"
        assert service.get("alice", "job", run.id).status == "COMPLETED"


@pytest.mark.parametrize(
    "change",
    [
        {"baseline_id": "old"},
        {"mode": "HOST"},
        {"question": "x" * 2001},
        {"question": "\ud800"},
        {"allow_remote": 1},
        {"target_ip": "10.0.0.0/24"},
        {"target_ip": "http://127.0.0.1"},
        {"expected_source_sha256": ""},
        {"idempotency_key": "x" * 201},
        {"sensor_id": "bad\x00"},
    ],
)
def test_closed_request_before_source(store, monkeypatch, change):
    s, repo = store
    req = request_for(repo, **change)
    service = api().InvestigationService(repo, s, None)
    monkeypatch.setattr(
        repo, "read_investigation_source", lambda *_a, **_k: pytest.fail("invalid request read")
    )
    with pytest.raises(InvestigationError, match="INVALID_REQUEST"):
        service.admit("alice", "job", req)


def test_snapshot_strict_json_roundtrip_and_tampered_model_instance(store):
    _, repo = store
    snapshot = repo.read_investigation_source("job")
    raw = canonical_bytes(snapshot.model_dump(mode="json"))
    assert canonical_bytes(SourceSnapshot.model_validate_json(raw).model_dump(mode="json")) == raw
    broken = json.loads(raw)
    broken["rows"][0]["total_bytes"] = "80"
    with pytest.raises(ValueError):
        SourceSnapshot.model_validate_json(json.dumps(broken))
    req = InvestigationRequest.model_validate(request_for(repo))
    bad = req.model_copy(update={"allow_remote": "true"})
    with pytest.raises(InvestigationError, match="INVALID_REQUEST"):
        api().InvestigationService(repo, store[0], None).admit("alice", "job", bad)


def test_preparation_saturated_and_queue_early_reject(store, monkeypatch):
    s, repo = store
    service = api().InvestigationService.from_configured_gateway(
        repo, s, OpenAICompatibleGateway(base_url="http://127.0.0.1:1", model="not-called")
    )
    req = request_for(repo)
    gate = api()._PREPARATION_GATE
    assert gate.acquire(blocking=False) and gate.acquire(blocking=False)
    try:
        with pytest.raises(InvestigationError, match="SOURCE_BUSY"):
            service.admit("alice", "job", req)
    finally:
        gate.release()
        gate.release()
    for index in range(4):
        service.admit("alice", "job", {**req, "idempotency_key": str(index)})
    monkeypatch.setattr(
        repo, "read_investigation_source", lambda *_a, **_k: pytest.fail("full owner hydration")
    )
    with pytest.raises(ValueError, match="OWNER_QUEUE_FULL"):
        service.admit("alice", "job", req)
