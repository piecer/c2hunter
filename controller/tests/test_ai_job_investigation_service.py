"""Actual stored source, bounded gateway and JOB broker; no sockets."""

import json
from contextlib import contextmanager

import httpx
import pytest

from c2hunter_controller.ai_investigation_contract import canonical_bytes
from c2hunter_controller.ai_investigation_gateway import InvestigationModelGateway
from c2hunter_controller.ai_investigation_store import InvestigationStoreError
from c2hunter_controller.ai_job_investigation_store import (
    JobInvestigationRunStore,
    initialize_job_investigation_store,
)
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_ai_job_investigation_source import flow, job


@pytest.fixture(params=["memory", "sqlite"])
def repository(request, tmp_path):
    repo = (
        MemoryRepository() if request.param == "memory" else SQLiteRepository(tmp_path / "job.db")
    )
    repo.save_job(job([flow(domain="updates.example.test")]))
    initialize_job_investigation_store(repo)
    yield repo
    repo.close()


def request_for(key="one", **updates):
    return (
        dict(
            version="job-investigation-v1",
            mode="JOB",
            experimental=True,
            question="관측 자료에 근거하여 조사하세요",
            language="ko",
            idempotency_key=key,
            expected_source_sha256=None,
            allow_remote=False,
            baseline_mode="off",
        )
        | updates
    )


@contextmanager
def scripted(monkeypatch, responder):
    requests = []

    class Stream(httpx.AsyncByteStream):
        def __init__(self, data):
            self.data = data

        async def __aiter__(self):
            yield self.data

    async def handle(request):
        body = json.loads(request.content)
        requests.append(body)
        action = responder(json.loads(body["messages"][1]["content"]), len(requests))
        content = action if isinstance(action, str) else canonical_bytes(action).decode()
        raw = canonical_bytes(
            {"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}
        )
        return httpx.Response(200, stream=Stream(raw))

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", lambda **_: httpx.MockTransport(handle))
    gateway = InvestigationModelGateway(
        "openai-compatible", "http://127.0.0.1:49183/v1", "scripted", "", 0, 262144, 4096
    )
    yield gateway, requests


def adaptive(data, _):
    if data["selection"]["state"] == "PENDING":
        peer = next(p for p in data["pool"]["entries"] if p["ip"] == "2001:db8::1")
        return {
            "action": "select_peers",
            "pool_sha256": data["pool"]["pool_sha256"],
            "peer_ids": [peer["peer_id"]],
        }
    peer = data["selection"]["peer_ids"][0]
    evidence = data["observations"]
    if len(evidence) == 1:
        return {
            "action": "request_tools",
            "tools": [
                {"peer_id": peer, "tool": "peer_protocol_observations", "arguments": {"limit": 2}}
            ],
        }
    return {
        "action": "finish",
        "assessments": [
            {
                "peer_id": peer,
                "verdict": "NEEDS_REVIEW",
                "support": [
                    {
                        "text": "관측 자료 확인",
                        "evidence_ids": [evidence[-1]["evidence_id"]],
                        "metric_refs": [],
                    }
                ],
                "counterevidence": [],
                "uncertainty": ["캡처 완전성은 확인되지 않았습니다"],
                "next_checks": [],
            }
        ],
    }


def test_job_planning_counter_durable_and_ip_shape_unchanged(repository):
    store = JobInvestigationRunStore(repository)
    store.admit(
        owner_id="alice",
        job_id="job",
        idempotency_key="counter",
        request_json=b"{}",
        binding_json=b"{}",
        snapshot_json=b"{}",
    )
    claim = store.claim("worker")
    for _ in range(4):
        claim = store.reserve(claim, planning_responses=1)
    assert store.get("alice", "job", claim["id"])["progress"]["planning_responses"] == 4
    with pytest.raises(InvestigationStoreError, match="BUDGET_EXHAUSTED"):
        store.reserve(claim, planning_responses=1)
    from c2hunter_controller.ai_investigation_store import (
        InvestigationRunStore,
        initialize_investigation_store,
    )

    initialize_investigation_store(repository)
    ip = InvestigationRunStore(repository)
    run, _ = ip.admit(
        owner_id="bob",
        job_id="job",
        idempotency_key="ip",
        request_json=b"{}",
        binding_json=b"{}",
        snapshot_json=b"{}",
    )
    assert "planning_responses" not in run["progress"]


def test_stored_source_selection_tools_and_final(repository, monkeypatch):
    from c2hunter_controller import ai_job_investigation as implementation

    service_class = implementation.JobInvestigationService
    reads = []
    original = repository.read_job_investigation_source

    def read(*args, **kwargs):
        reads.append(args)
        return original(*args, **kwargs)

    monkeypatch.setattr(repository, "read_job_investigation_source", read)
    with scripted(monkeypatch, adaptive) as (gateway, requests):
        service = service_class(
            repository,
            JobInvestigationRunStore(repository),
            gateway,
            enabled=True,
            dispatch_available=lambda: True,
        )
        queued, created = service.admit("alice", "job", request_for())
        assert created and queued.selection.state == "PENDING"
        outcome = service.run_next("worker")
        assert outcome.acknowledge_exit and outcome.code is None
        run = service.get("alice", "job", queued.id)
        assert run.status == "COMPLETED"
        assert run.progress.model_calls == run.progress.transport_attempts == len(requests) == 3
        assert run.progress.tool_calls == 3 and run.progress.planning_responses == 2
        assert run.coverage.investigated_peers == run.coverage.selected_peers == 1
        assert run.coverage.capture_completeness == "UNKNOWN"
        assert run.result.source == run.source and run.result.progress == run.progress
        assert len(reads) == 1
        steps = service.steps("alice", "job", run.id, limit=10)
        assert [(s.tool, s.origin) for s in steps if s.kind == "TOOL"] == [
            ("select_peers", "MODEL_REQUEST"),
            ("peer_overview", "AUTOMATIC_SEED"),
            ("peer_protocol_observations", "MODEL_REQUEST"),
        ]
        for step in steps:
            if step.evidence_id:
                assert (
                    service.evidence("alice", "job", run.id, step.evidence_id).source == run.source
                )
        assert service.store.worker_exited(outcome.claim)
        service.gateway = None
        monkeypatch.setattr(
            repository,
            "read_job_investigation_source",
            lambda *_args, **_kwargs: pytest.fail("replay reads source"),
        )
        replay, created = service.admit("alice", "job", request_for())
        assert not created and replay == run and replay.request.expected_source_sha256 is None


def service_for(repo, gateway):
    from c2hunter_controller.ai_job_investigation import JobInvestigationService

    return JobInvestigationService(
        repo, JobInvestigationRunStore(repo), gateway, enabled=True, dispatch_available=lambda: True
    )


def test_three_selected_share_prepared_snapshot_without_revalidation(repository, monkeypatch):
    from c2hunter_controller.ai_investigation_contract import SourceSnapshot

    repository.save_job(job([flow(), flow(destination_ip="2001:db8::2")]))
    calls = []
    original = SourceSnapshot.model_validate
    monkeypatch.setattr(
        SourceSnapshot,
        "model_validate",
        lambda *a, **kw: (calls.append(a[0]), original(*a, **kw))[1],
    )

    def respond(data, index):
        if index == 1:
            return dict(
                action="select_peers",
                pool_sha256=data["pool"]["pool_sha256"],
                peer_ids=[p["peer_id"] for p in data["pool"]["entries"][:3]],
            )
        return {"action": "finish", "assessments": []}

    with scripted(monkeypatch, respond) as (gateway, _):
        service = service_for(repository, gateway)
        run, _ = service.admit("alice", "job", request_for())
        calls.clear()
        outcome = service.run_next("worker")
        assert outcome.acknowledge_exit
        assert calls == [], "validated immutable source must be shared, not revalidated per peer"
        current = service.get("alice", "job", run.id)
        assert current.status == "PARTIAL"
        assert current.progress.tool_calls == 4 and current.coverage.not_investigated_peers == 3
        assert all(a.mode == "FACTS_ONLY" for a in current.result.assessments)


@pytest.mark.parametrize("case", ["duplicate", "invalid_args", "foreign", "reselection"])
def test_invalid_attempts_charge_without_tool_execution(repository, monkeypatch, case):
    def respond(data, index):
        if index == 1:
            return adaptive(data, index)
        peer = data["selection"]["peer_ids"][0]
        if case == "reselection":
            return dict(
                action="select_peers", pool_sha256=data["pool"]["pool_sha256"], peer_ids=[peer]
            )
        call = dict(
            peer_id="f" * 64 if case == "foreign" else peer,
            tool="peer_timeline",
            arguments={"limit": 0 if case == "invalid_args" else 2},
        )
        return dict(action="request_tools", tools=[call, call] if case == "duplicate" else [call])

    with scripted(monkeypatch, respond) as (gateway, requests):
        service = service_for(repository, gateway)
        queued, _ = service.admit("alice", "job", request_for())
        outcome = service.run_next("worker")
        run = service.get("alice", "job", queued.id)
        assert outcome.acknowledge_exit and run.status == "PARTIAL"
        assert all(
            q.tool == "peer_overview" for a in run.result.assessments for q in a.evidence_quality
        )
        expected = 6 if case == "duplicate" else 4 if case == "invalid_args" else 3
        assert run.progress.tool_calls == expected
        assert len(requests) <= 3


def test_genuine_top_five_excluded_peer_adapts_to_evidence(repository, monkeypatch):
    from copy import deepcopy
    from datetime import UTC, datetime, timedelta

    from c2hunter_controller.ai_analysis import _ranked_candidate_snapshots
    from tests.test_ai_job_investigation_source import behavior_job

    raw = behavior_job()
    raw["flow_records"] = raw["flow_records"][:48]
    for index, row in enumerate(raw["flow_records"]):
        row.update(
            timestamp=(
                datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=(index % 8) * 30)
            ).isoformat(),
            total_bytes=100,
            payload_length=60,
            payload_hash="a" * 64,
        )
    five = _ranked_candidate_snapshots(raw, [], 5)
    outside = {p["candidate_ip"] for p in _ranked_candidate_snapshots(raw, [], 32)} - {
        p["candidate_ip"] for p in five
    }
    assert len(five) == 5 and outside
    target = sorted(outside)[0]
    choices = []
    for variant, domain in enumerate(["updates.example.test", "other.example.test"]):
        source = deepcopy(raw)
        for row in source["flow_records"]:
            if target in (row["source_ip"], row["destination_ip"]):
                row["domain"] = domain
        repository.save_job(source)

        def respond(data, index):
            if index == 1:
                peer = next(p for p in data["pool"]["entries"] if p["ip"] == target)
                return dict(
                    action="select_peers",
                    pool_sha256=data["pool"]["pool_sha256"],
                    peer_ids=[peer["peer_id"]],
                )
            peer = data["selection"]["peer_ids"][0]
            if index == 2:
                tool = "peer_protocol_observations"
            elif index == 3:
                observed = data["observations"][-1]["protocols"][0]["domain"]
                tool = (
                    "peer_timeline" if observed == "updates.example.test" else "peer_flow_samples"
                )
                choices.append(tool)
            else:
                return adaptive(data, index)
            return dict(
                action="request_tools",
                tools=[dict(peer_id=peer, tool=tool, arguments={"limit": 2})],
            )

        with scripted(monkeypatch, respond) as (gateway, requests):
            service = service_for(repository, gateway)
            queued, _ = service.admit("alice", "job", request_for(str(variant)))
            outcome = service.run_next("worker")
            run = service.get("alice", "job", queued.id)
            assert run.status == "COMPLETED" and run.progress.model_calls == len(requests) == 4
            selected = next(p for p in run.pool.entries if p.peer_id == run.selection.peer_ids[0])
            assert selected.ip == target and target not in {p["candidate_ip"] for p in five}
            assert run.result.source == run.source
            assert service.store.worker_exited(outcome.claim)
    assert choices == ["peer_timeline", "peer_flow_samples"]
