"""Retained independent review probes; original six RED assertions unchanged.

Real source/store and loopback HTTP. Reports use the invocation-owned tmp_path.
The original unformatted review probe and RED execution remain in the handoff.
"""

import contextlib
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from c2hunter_controller.ai_gateway import OpenAICompatibleGateway
from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_contract import InvestigationError
from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def private_review_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(__import__(__name__, fromlist=["ROOT"]), "ROOT", tmp_path)
    (tmp_path / "reports").mkdir()


def record(name, data):
    (ROOT / "reports" / (name + ".json")).write_text(json.dumps(data, indent=2) + "\n")


def row(**changes):
    value = dict(
        sensor_id="sensor-one",
        timestamp="2026-01-01T00:00:00+00:00",
        source_ip="10.0.0.1",
        destination_ip="2001:db8::1",
        protocol="UDP",
        direction="OUTBOUND",
        packet_count=1,
        total_bytes=80,
        duration_seconds=0,
    )
    return {**value, **changes}


def save(repo, rows):
    repo.save_job(
        dict(
            id="job",
            dataset_id="dataset",
            parent_job_id=None,
            status="COMPLETED",
            analysis={"module": "c2"},
            flow_records=rows,
        )
    )


def request(repo, key="first"):
    return dict(
        target_ip="2001:db8::1",
        question="Explain retained evidence.",
        language="en",
        idempotency_key=key,
        expected_source_sha256=repo.read_investigation_source("job").binding.source_sha256,
    )


@contextlib.contextmanager
def backend(kind, tmp_path, rows=None):
    repo = MemoryRepository() if kind == "memory" else SQLiteRepository(tmp_path / "review.db")
    initialize_investigation_store(repo)
    save(repo, [row()] if rows is None else rows)
    try:
        yield repo, InvestigationRunStore(repo)
    finally:
        repo.close()


@contextlib.contextmanager
def provider(responder):
    requests, errors = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append(body)
                action = responder(body, len(requests))
                raw = json.dumps(
                    {
                        "choices": [
                            {"message": {"content": json.dumps(action)}, "finish_reason": "stop"}
                        ]
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                try:
                    self.wfile.write(raw)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            except Exception as exc:
                errors.append(repr(exc))
                self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = False
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    gateway = InvestigationModelGateway.from_configured_gateway(
        OpenAICompatibleGateway(
            base_url=f"http://127.0.0.1:{server.server_port}",
            model="independent-scripted-no-inference",
            context_tokens=65536,
            max_output_tokens=2048,
        )
    )
    try:
        yield gateway, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
        assert not thread.is_alive()
        assert not errors, errors


def obs(body):
    return json.loads(body["messages"][-1]["content"])["observations"]


def tools(name):
    return {"action": "request_tools", "tools": [{"tool": name, "arguments": {}}]}


def finish(e, verdict="NEEDS_REVIEW"):
    return {
        "action": "finish",
        "verdict": verdict,
        "support": [
            {
                "text": "A hypothesis requiring contextual verification.",
                "evidence_ids": [e["evidence_id"]],
                "metric_refs": [e["metrics"][0]["ref"]],
            }
        ],
        "counterevidence": [],
        "uncertainty": ["Capture completeness and baseline are unverified."],
        "next_checks": [],
    }


@pytest.mark.parametrize(
    "kind,tool,verdict,self_loop",
    [
        ("memory", "peer_protocol_observations", "SUSPICIOUS_C2", False),
        ("sqlite", "peer_protocol_observations", "BENIGN_HYPOTHESIS", False),
        ("sqlite", "compare_peer_cohort", "SUSPICIOUS_C2", True),
    ],
)
def test_positive_requires_available_nonempty_counterevidence(
    tmp_path, kind, tool, verdict, self_loop
):
    rows = [row(source_ip="2001:db8::1")] if self_loop else [row()]

    def respond(body, n):
        return tools(tool) if n == 1 else finish(obs(body)[0], verdict)

    with backend(kind, tmp_path, rows) as (repo, store), provider(respond) as (gateway, http):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        step = next(s for s in service.steps("alice", "job", run.id) if s.tool == tool)
        evidence = service.evidence("alice", "job", run.id, step.evidence_id)
        assert (
            (evidence.status == "UNAVAILABLE" and not evidence.protocols)
            if not self_loop
            else (evidence.cohort_total == 0 and not evidence.cohort)
        )
        assert store.worker_exited(outcome.claim)
        record(
            "positive-" + kind + "-" + tool,
            {
                "run": actual.model_dump(mode="json"),
                "counterevidence": evidence.model_dump(mode="json"),
                "http_requests": len(http),
                "outcome_code": outcome.code,
            },
        )
        assert actual.result.verdict not in {"SUSPICIOUS_C2", "BENIGN_HYPOTHESIS"}, (
            "Unusable counterevidence alone authorized a positive verdict"
        )


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_cancelled_progress_retains_actual_debits_and_slot_custody(tmp_path, kind):
    entered = threading.Event()
    release = threading.Event()
    outcomes = []

    def respond(body, n):
        entered.set()
        assert release.wait(5)
        return finish(obs(body)[0])

    with backend(kind, tmp_path) as (repo, store), provider(respond) as (gateway, http):
        service = InvestigationService(repo, store, gateway)
        req = request(repo)
        run, _ = service.admit("alice", "job", req)
        thread = threading.Thread(target=lambda: outcomes.append(service.run_next("worker")))
        thread.start()
        try:
            assert entered.wait(5)
            cancelled = service.cancel("alice", "job", run.id)
            successor, _ = service.admit("alice", "job", {**req, "idempotency_key": "successor"})
            assert store.claim("other-worker") is None, (
                "premature release while HTTP callback remains live"
            )
        finally:
            release.set()
            thread.join(5)
        assert not thread.is_alive() and len(outcomes) == 1
        outcome = outcomes[0]
        assert outcome.acknowledge_exit and outcome.code == "CANCELLED"
        assert store.claim("other-worker") is None, "service must not worker_exited automatically"
        assert store.worker_exited(outcome.claim)
        next_claim = store.claim("other-worker")
        assert next_claim["id"] == successor.id
        assert store.worker_exited(next_claim)
        final = service.get("alice", "job", run.id)
        record(
            "cancel-progress-" + kind,
            {
                "cancelled": cancelled.model_dump(mode="json"),
                "final": final.model_dump(mode="json"),
                "actual_durable_budgets": outcome.claim["budgets"],
                "http_requests": len(http),
                "thread_joined": not thread.is_alive(),
                "slot_held_until_ack": True,
            },
        )
        assert final.progress.model_calls == outcome.claim["budgets"]["model_calls"] == 1
        assert (
            final.progress.transport_attempts == outcome.claim["budgets"]["transport_attempts"] == 1
        )


def test_get_does_not_combine_old_epoch_with_new_progress(tmp_path, monkeypatch):
    with (
        backend("sqlite", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        original = store.saved_input
        triggered = []
        outcomes = []

        def advance(*args):
            if not triggered:
                triggered.append(True)
                outcomes.append(service.run_next("worker"))
            return original(*args)

        monkeypatch.setattr(store, "saved_input", advance)
        mixed = service.get("alice", "job", run.id)
        fresh = service.get("alice", "job", run.id)
        assert triggered and len(http) == 1 and fresh.status == "COMPLETED"
        assert store.worker_exited(outcomes[0].claim)
        record(
            "mixed-epoch",
            {
                "mixed": mixed.model_dump(mode="json"),
                "fresh": fresh.model_dump(mode="json"),
                "hook": "saved_input after get has captured QUEUED revision zero",
            },
        )
        assert not (
            mixed.status == "QUEUED" and (mixed.progress.model_calls or mixed.progress.tool_calls)
        ), "old status/revision paired with newer step progress"


def test_adaptive_history_authorization_handoff_and_frozen_source(tmp_path, monkeypatch):
    def respond(body, n):
        seen = obs(body)
        if n == 1:
            assert {e["tool"] for e in seen} == {"peer_overview"}
            return tools("peer_protocol_observations")
        assert len(seen) == 2 and seen[1]["protocols"][0]["domain"] == "update.example.test"
        return finish(seen[0], "BENIGN_HYPOTHESIS")

    with (
        backend("sqlite", tmp_path, [row(domain="update.example.test", payload="RAW_SECRET")]) as (
            repo,
            store,
        ),
        provider(respond) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        req = request(repo)
        source = repo.read_investigation_source("job")
        broken = source.model_copy(
            update={"rows": (source.rows[0].model_copy(update={"total_bytes": "80"}),)}
        )
        _reader = repo.read_investigation_source
        with monkeypatch.context() as mp:
            mp.setattr(repo, "read_investigation_source", lambda *a, **k: broken)
            with pytest.raises(InvestigationError, match="SOURCE_INVALID"):
                service.admit("alice", "job", req)
        assert store.page("alice", "job") == []
        run, created = service.admit("alice", "job", req)
        assert created
        save(repo, [row(total_bytes=999)])
        with pytest.raises(InvestigationError, match="SOURCE_CHANGED"):
            service.admit("alice", "job", {**req, "idempotency_key": "changed"})
        outcome = service.run_next("worker")
        actual = service.get("alice", "job", run.id)
        assert actual.status == "COMPLETED" and actual.result.partial_scope
        assert actual.result.source.source_sha256 == req["expected_source_sha256"]
        assert (
            actual.progress.model_calls == actual.progress.transport_attempts == 2
            and actual.progress.tool_calls == 2
        )
        assert "RAW_SECRET" not in json.dumps(http)
        evidence_id = actual.result.support[0].evidence_ids[0]
        for owner, job_id in [("bob", "job"), ("alice", "other-job")]:
            assert service.get(owner, job_id, run.id) is None
            assert service.steps(owner, job_id, run.id) == []
            assert service.evidence(owner, job_id, run.id, evidence_id) is None
            assert service.cancel(owner, job_id, run.id) is None
            assert service.page(owner, job_id) == []
        assert store.worker_exited(outcome.claim)
        repo.delete_job("job")
        unavailable = InvestigationService(repo, store, None)
        replay, is_new = unavailable.admit("alice", "job", req)
        assert not is_new and replay == actual
        exported = actual.model_dump_json()
        for secret_field in ["lease_token", "snapshot_json", "worker_id", "commitment"]:
            assert secret_field not in exported
        record(
            "adaptive-history",
            {
                "run": actual.model_dump(mode="json"),
                "http_requests": len(http),
                "tampered_snapshot_rejected": True,
                "foreign_owner_job_denied": True,
                "replay_after_delete": True,
                "note": (
                    "service caller must authenticate/authorize incoming owner/job; "
                    "HTTP here is provider only"
                ),
            },
        )


def test_late_transport_callback_cannot_start_http_or_reset_deadline(tmp_path, monkeypatch):
    with (
        backend("memory", tmp_path) as (repo, store),
        provider(lambda body, n: finish(obs(body)[0])) as (gateway, http),
    ):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request(repo))
        claim = store.claim("worker")
        deadline = time.monotonic() + 0.5
        reserve = store.reserve
        fired = []

        def late(c, **increments):
            updated = reserve(c, **increments)
            if "transport_attempts" in increments:
                assert time.monotonic() < deadline
                fired.append(True)
                time.sleep(max(0, deadline - time.monotonic()) + 0.02)
            return updated

        monkeypatch.setattr(store, "reserve", late)
        outcome = service.execute_claim(claim, deadline_monotonic=deadline)
        actual = service.get("alice", "job", run.id)
        assert fired and http == []
        assert actual.status == "PARTIAL" and actual.result.reason == "DEADLINE_EXCEEDED"
        assert actual.progress.model_calls == actual.progress.transport_attempts == 1
        assert store.worker_exited(outcome.claim)
        record(
            "deadline",
            {
                "run": actual.model_dump(mode="json"),
                "http_requests": len(http),
                "callback_fired": bool(fired),
                "outcome_code": outcome.code,
            },
        )
