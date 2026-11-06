"""Producer fixtures from the actual service + store + loopback HTTP gateway.

The injected storage clock makes fixture bytes reproducible; it is NOT a host
clock-quality or real-model-inference witness. No DTO is hand-authored here.
"""

import threading
import time
from pathlib import Path

from c2hunter_controller.ai_investigation import InvestigationService
from c2hunter_controller.ai_investigation_contract import Evidence, canonical_bytes
from c2hunter_controller.ai_investigation_schema import (
    InvestigationCapabilities,
    InvestigationResult,
    InvestigationRun,
    InvestigationStep,
    SourcePreview,
)
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.repositories import MemoryRepository
from c2hunter_controller.schemas import FlowRecord
from tests.test_ai_investigation_evidence import flow, job
from tests.test_ai_investigation_loop import (
    adaptive,
    finish,
    observations,
    request_for,
    structured_provider,
)

FIXTURES = Path(__file__).parent / "fixtures" / "ai_investigation_service"


def producer_fixtures():
    repo = MemoryRepository()
    repo.save_job(job([flow(domain="updates.example.test"), flow(source_ip="10.0.0.2")]))
    initialize_investigation_store(repo)
    output = {}
    record_states = [True]

    def record(name, model):
        output[name] = canonical_bytes(model.model_dump(mode="json")) + b"\n"

    class RecordingStore(InvestigationRunStore):
        def claim(self, worker_id):
            result = super().claim(worker_id)
            if result is not None and record_states[0]:
                record("run_preparing", service.get("alice", "job", result["id"]))
            return result

        def transition(self, claim, status):
            result = super().transition(claim, status)
            if record_states[0]:
                record("run_" + status.lower(), service.get("alice", "job", result["id"]))
            return result

    store = RecordingStore(repo, clock=lambda: 1000.0)
    with structured_provider(adaptive, port=49183) as (gateway, requests):
        service = InvestigationService(repo, store, gateway)
        record("capabilities", service.capabilities())
        record(
            "source_preview", service.source_preview("alice", "job", {"target_ip": "2001:db8::1"})
        )
        run, _ = service.admit("alice", "job", request_for(repo))
        record("run_queued", run)
        original_saved_input = store.saved_input
        outcomes = []

        def advance(*args):
            if not outcomes:
                outcomes.append(None)
                outcomes[0] = service.run_next("worker")
            return original_saved_input(*args)

        store.saved_input = advance
        coherent_queued = service.get("alice", "job", run.id)
        store.saved_input = original_saved_input
        outcome = outcomes[0]
        completed = service.get("alice", "job", run.id)
        assert coherent_queued == run and completed.progress.model_calls == 3
        record("run_epoch_queued", coherent_queued)
        record("run_epoch_completed", completed)
        assert outcome.code is None and completed.status == "COMPLETED" and len(requests) == 3
        record("run_completed", completed)
        record("result_completed", completed.result)
        for step in service.steps("alice", "job", run.id):
            if step.kind == "MODEL" and "step_model" not in output:
                record("step_model", step)
            if step.tool == "peer_protocol_observations":
                record("step_tool", step)
                record(
                    "evidence_protocol", service.evidence("alice", "job", run.id, step.evidence_id)
                )
        assert store.worker_exited(outcome.claim)
        record_states[0] = False
        run, _ = service.admit("alice", "job", request_for(repo, idempotency_key="failed"))
        claim = store.claim("worker")
        outcome = service.execute_claim(claim, deadline_monotonic=time.monotonic() - 1)
        record("run_failed", service.get("alice", "job", run.id))
        assert store.worker_exited(outcome.claim)
        run, _ = service.admit("alice", "job", request_for(repo, idempotency_key="cancelled"))
        record("run_cancelled", service.cancel("alice", "job", run.id))
    with structured_provider(lambda *_: {"action": "finish"}, port=49183) as (gateway, requests):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit("alice", "job", request_for(repo, idempotency_key="partial"))
        outcome = service.run_next("worker")
        partial = service.get("alice", "job", run.id)
        assert partial.status == "PARTIAL" and len(requests) == 2
        record("run_partial", partial)
        assert store.worker_exited(outcome.claim)
    entered = threading.Event()
    release = threading.Event()

    def held_response(body, n):
        entered.set()
        assert release.wait(5)
        return finish(observations(body)[0])

    with structured_provider(held_response, port=49183) as (gateway, requests):
        service = InvestigationService(repo, store, gateway)
        run, _ = service.admit(
            "alice", "job", request_for(repo, idempotency_key="cancel-after-charge")
        )
        outcomes = []
        worker = threading.Thread(target=lambda: outcomes.append(service.run_next("worker")))
        worker.start()
        try:
            assert entered.wait(5)
            cancelled = service.cancel("alice", "job", run.id)
            assert cancelled.progress.model_calls == cancelled.progress.transport_attempts == 1
            record("run_cancelled_after_charge", cancelled)
        finally:
            release.set()
            worker.join(5)
        assert not worker.is_alive() and len(requests) == 1
        assert service.get("alice", "job", run.id) == cancelled
        assert outcomes[0].code == "CANCELLED" and store.worker_exited(outcomes[0].claim)
    repo.save_job(
        job([FlowRecord.model_validate(flow(direction="BIDIRECTIONAL")).model_dump(mode="json")])
    )
    record(
        "source_preview_unavailable",
        service.source_preview(
            "alice", "job", {"target_ip": "2001:db8::1", "traffic_direction": "OUTBOUND"}
        ),
    )
    partial_source = job(
        [FlowRecord.model_validate(flow(destination_ip="2001:db8::2")).model_dump(mode="json")]
    )
    partial_source["status"] = "PARTIALLY_COMPLETED"
    repo.save_job(partial_source)
    record(
        "source_preview_partial",
        service.source_preview("alice", "job", {"target_ip": "2001:db8::1"}),
    )
    repo.close()
    return output


def test_actual_service_producer_shared_bytes():
    fixtures = producer_fixtures()
    assert {name for name in fixtures if name.startswith("run_")} == {
        "run_queued",
        "run_preparing",
        "run_investigating",
        "run_validating",
        "run_completed",
        "run_partial",
        "run_failed",
        "run_cancelled",
        "run_cancelled_after_charge",
        "run_epoch_queued",
        "run_epoch_completed",
    }
    for name, raw in fixtures.items():
        assert (FIXTURES / (name + ".json")).read_bytes() == raw
        model = (
            InvestigationRun
            if name.startswith("run_")
            else InvestigationStep
            if name.startswith("step_")
            else InvestigationResult
            if name.startswith("result_")
            else Evidence
            if name.startswith("evidence_")
            else InvestigationCapabilities
            if name == "capabilities"
            else SourcePreview
        )
        assert (
            canonical_bytes(model.model_validate_json(raw).model_dump(mode="json")) + b"\n" == raw
        )
        assert b"lease_token" not in raw and b"snapshot_json" not in raw
