"""Adversarial execution/serialization witnesses against real stored producers."""

import time
from copy import deepcopy

import pytest

from c2hunter_controller.ai_investigation_contract import canonical_bytes
from c2hunter_controller.ai_job_investigation_runtime_schema import ACTION, JobRun, parse_action
from tests.test_ai_job_investigation_service import adaptive, request_for, scripted, service_for
from tests.test_ai_job_investigation_service import repository as _repository
from tests.test_ai_job_investigation_source import flow, job

repository = _repository


def run_case(repository, monkeypatch, responder=adaptive):
    with scripted(monkeypatch, responder) as (gateway, calls):
        service = service_for(repository, gateway)
        queued, _ = service.admit("alice", "job", request_for())
        outcome = service.run_next("worker")
        return service, queued, outcome, service.get("alice", "job", queued.id), calls


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_version",
        "missing_origin",
        "boolean_true",
        "cross_peer_quality",
        "bad_counts",
        "facts_reference",
    ],
)
def test_saved_wire_rejects_semantic_mutations(repository, monkeypatch, mutation):
    service, _, _, run, _ = run_case(repository, monkeypatch)
    data = run.model_dump(mode="json")
    if mutation == "missing_origin":
        from c2hunter_controller.ai_job_investigation_runtime_schema import JobStep

        step = service.steps("alice", "job", run.id)[0].model_dump(mode="json")
        del step["origin"]
        with pytest.raises(ValueError):
            JobStep.model_validate_json(canonical_bytes(step))
        return
    if mutation == "missing_version":
        del data["version"]
    elif mutation == "boolean_true":
        data["result"]["partial_scope"] = 1
    elif mutation == "cross_peer_quality":
        original = data["result"]["assessments"][0]
        other = deepcopy(original)
        other["peer_id"] = next(
            p["peer_id"] for p in data["pool"]["entries"] if p["peer_id"] != original["peer_id"]
        )
        data["selection"]["peer_ids"].append(other["peer_id"])
        data["result"]["assessments"].append(other)
        for cov in (data["coverage"], data["result"]["coverage"]):
            cov.update(
                selected_peers=2,
                investigated_peers=2,
                not_selected_peers=cov["not_selected_peers"] - 1,
            )
    elif mutation == "bad_counts":
        data["result"]["assessments"][0]["evidence_quality"][0]["counts"]["matched"] = 0
    else:
        data["result"]["assessments"][0]["facts"] = [
            {
                "ref": "f" * 64 + ":matched_rows",
                "name": "matched_rows",
                "unit": "rows",
                "value": 1,
                "observed_rows": 1,
                "unavailable_rows": 0,
            }
        ]
    with pytest.raises(ValueError):
        JobRun.model_validate_json(canonical_bytes(data))


@pytest.mark.parametrize("kind", ["cross", "missing", "positive_control", "benign_no_counter"])
def test_peer_local_assessment_and_conservative_partial(repository, monkeypatch, kind):
    rows = [flow(domain="x.test"), flow(destination_ip="2001:db8::2", domain="y.test")]
    if kind == "positive_control":
        rows = [flow(protocol="TCP", tcp_flags={"syn": 1}, payload_length=0, domain="x.test")]
    repository.save_job(job(rows))

    def respond(data, index):
        if index == 1:
            return dict(
                action="select_peers",
                pool_sha256=data["pool"]["pool_sha256"],
                peer_ids=[p["peer_id"] for p in data["pool"]["entries"][:3]],
            )
        peers = data["selection"]["peer_ids"]
        if index == 2 and kind == "positive_control":
            return dict(
                action="request_tools",
                tools=[dict(peer_id=peers[0], tool="peer_protocol_observations", arguments={})],
            )
        assessments = []
        for number, peer in enumerate(peers[:1] if kind == "missing" else peers):
            own = [e for e in data["observations"] if e["peer_id"] == peer]
            e = own[-1]
            if kind == "cross" and number == 1:
                e = next(e for e in data["observations"] if e["peer_id"] == peers[0])
            interpretation = dict(
                text="관측된 자료", evidence_ids=[e["evidence_id"]], metric_refs=[]
            )
            assessments.append(
                dict(
                    peer_id=peer,
                    verdict="SUSPICIOUS_C2"
                    if kind == "positive_control"
                    else "BENIGN_HYPOTHESIS"
                    if kind == "benign_no_counter"
                    else "NEEDS_REVIEW",
                    support=[interpretation],
                    counterevidence=[interpretation] if kind == "positive_control" else [],
                    uncertainty=["불확실"],
                    next_checks=[],
                )
            )
        return dict(action="finish", assessments=assessments)

    service, _, outcome, run, _ = run_case(repository, monkeypatch, respond)
    assert outcome.acknowledge_exit and run.status == "PARTIAL"
    assert run.coverage.investigated_peers == (1 if kind in {"cross", "missing"} else 0)
    assert run.coverage.not_investigated_peers >= 1
    assert not any(
        a.verdict in {"SUSPICIOUS_C2", "BENIGN_HYPOTHESIS"} for a in run.result.assessments
    )
    assert service.store.worker_exited(outcome.claim)


@pytest.mark.parametrize(
    "raw",
    [
        '{"action":"finish","action":"finish","assessments":[]}',
        '{"action":"finish","assessments":NaN}',
        '"' + "x" * 17000 + '"',
        '{"action":"finish","assessments":[]}',
    ],
)
def test_actual_gateway_invalid_raw_output_is_bounded(repository, monkeypatch, raw):
    _, _, outcome, run, calls = run_case(repository, monkeypatch, lambda *_: raw)
    assert outcome.acknowledge_exit and run.status == "PARTIAL"
    assert run.coverage.awaiting_selection_peers == len(run.pool.entries)
    assert run.result.assessments == () and run.coverage.investigated_peers == 0
    assert len(calls) <= 2 and run.progress.tool_calls == 0


@pytest.mark.parametrize("boundary", ["parse", "serialize"])
def test_original_deadline_guards_after_validation_and_encoding(repository, monkeypatch, boundary):
    from c2hunter_controller import ai_job_investigation as broker

    original = broker.parse_action if boundary == "parse" else broker._wire
    deadline = [False]

    def delayed(value):
        result = original(value)
        final = (boundary == "parse" and getattr(result, "action", None) == "finish") or (
            boundary == "serialize"
            and getattr(value, "kind", None) == "RESULT"
            and value.reason is None
        )
        if final:
            deadline[0] = True
        return result

    monkeypatch.setattr(broker, "parse_action" if boundary == "parse" else "_wire", delayed)
    old_guard = broker._Execution.guard

    def guard(executor):
        if deadline[0]:
            executor.deadline = time.monotonic() - 1
        return old_guard(executor)

    monkeypatch.setattr(broker._Execution, "guard", guard)
    _, _, outcome, run, _ = run_case(repository, monkeypatch)
    assert outcome.acknowledge_exit and run.status == "PARTIAL"
    assert run.result.reason == "DEADLINE_EXCEEDED"


def test_global_planning_and_tool_budget(repository, monkeypatch):
    def respond(data, index):
        if index == 1:
            return adaptive(data, index)
        peer = data["selection"]["peer_ids"][0]
        return dict(
            action="request_tools",
            tools=[
                dict(peer_id=peer, tool=tool, arguments={"limit": index})
                for tool in ("peer_timeline", "peer_flow_samples", "peer_protocol_observations")
            ],
        )

    _, _, outcome, run, calls = run_case(repository, monkeypatch, respond)
    assert outcome.acknowledge_exit and run.status == "PARTIAL"
    assert run.progress.planning_responses == 4
    assert run.progress.tool_calls == 11
    assert run.progress.model_calls == len(calls) == 5
    assert run.result.reason == "PLANNING_BUDGET"


def test_action_schema_limit_and_numeric_spelling():
    assert len(canonical_bytes(ACTION.json_schema())) <= 32768
    raw = (
        '{"action":"request_tools","tools":[{"peer_id":"'
        + "a" * 64
        + '","tool":"peer_timeline","arguments":{"limit":1e0}}]}'
    )
    assert parse_action(raw).tools[0].arguments.limit == 1
    with pytest.raises(ValueError):
        parse_action(raw.replace("1e0", "true"))
