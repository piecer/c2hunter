"""Real source/gateway helpers for independent review regressions."""

from c2hunter_controller.ai_job_investigation_store import initialize_job_investigation_store
from tests.test_ai_job_investigation_service import request_for, scripted, service_for


def verdict(data, peers=None, foreign_support=False, foreign_counter=False, text="관측"):
    peers = peers or data["selection"]["peer_ids"]
    assessments = []
    for peer in peers:
        own = [e for e in data["observations"] if e["peer_id"] == peer]
        support = own[0]
        counter = next(e for e in own if e["tool"] == "peer_protocol_observations")
        foreign = [
            e
            for e in data["observations"]
            if e["peer_id"] != peer and e["tool"] == "peer_protocol_observations"
        ]
        if foreign_support:
            support = foreign[0]
        if foreign_counter:
            counter = foreign[0]

        def interp(e):
            return {
                "text": text,
                "evidence_ids": [e["evidence_id"]],
                "metric_refs": [e["metrics"][0]["ref"]],
            }

        assessments.append(
            dict(
                peer_id=peer,
                verdict="SUSPICIOUS_C2",
                support=[interp(support)],
                counterevidence=[interp(counter)],
                uncertainty=["캡처 완전성 UNKNOWN"],
                next_checks=[],
            )
        )
    return dict(action="finish", assessments=assessments)


def responder(data, index):
    if index == 1:
        return dict(
            action="select_peers",
            pool_sha256=data["pool"]["pool_sha256"],
            peer_ids=[p["peer_id"] for p in data["pool"]["entries"]][:3],
        )
    if index == 2:
        return dict(
            action="request_tools",
            tools=[
                dict(peer_id=p, tool="peer_protocol_observations", arguments={})
                for p in data["selection"]["peer_ids"]
            ],
        )
    return verdict(data)


def execute(repo, patch, responder=responder, key="probe"):
    initialize_job_investigation_store(repo)
    with scripted(patch, responder) as (gateway, calls):
        svc = service_for(repo, gateway)
        run, _ = svc.admit("alice", "job", request_for(key))
        outcome = svc.run_next("independent")
        current = svc.get("alice", "job", run.id)
        return svc, outcome, current, calls
