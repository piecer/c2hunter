"""Legacy dispatch and repository-bearing cancellation callbacks; canned transport only."""

import pytest

from c2hunter_controller import ai_analysis as ai
from c2hunter_controller import ai_gateway as gw
from c2hunter_controller import historical_ai_storage as custody
from c2hunter_controller._baseline_storage import BaselineStorageError
from c2hunter_controller.ai_queueing import MemoryAIAnalysisWorkerQueue
from c2hunter_controller.ai_worker import AIAnalysisWorker
from c2hunter_controller.c2_diagnostics import C2Diagnostics
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_gateway import FakeHttpClient, source_candidate
from tests.test_c2_failure_diagnostics import diagnostics, envelope
from tests.test_historical_ai_execution import admitted


class LegacyGateway(gw.OllamaGateway):
    calls = 0

    def assess_cancellable(self, bundle, *, should_cancel):
        self.calls += 1
        return super().assess_cancellable(bundle, should_cancel=should_cancel)


class CustomCancellable(ai.FakeGateway):
    calls = 0

    def assess_cancellable(self, bundle, *, should_cancel):
        self.calls += 1
        assert not should_cancel()
        return super().assess(bundle)


class AssessOnly(ai.FakeGateway):
    calls = 0

    def assess(self, bundle):
        self.calls += 1
        return super().assess(bundle)


def model_for(http, cls=gw.OllamaGateway):
    return cls(base_url="http://offline.invalid", model="canned", retries=0, http_client=http)


def service_run(kind, model):
    repo = MemoryRepository()
    service = ai.AIAnalysisService(repo, model)
    if kind == "historical":
        run = admitted(repo)
        _, bundles = custody.materialize_historical_run(run)
        bundle = bundles[0]
    else:
        job = {"id": "job-1", "status": "COMPLETED"}
        repo.jobs[job["id"]] = job
        repo.save_candidates(job["id"], [source_candidate()])
        run, created = service.create_run(
            analysis_job_id=job["id"],
            idempotency_key="callback-boundary",
            candidate_limit=1,
            created_by="analyst",
        )
        assert created
        bundle = ai.build_evidence_bundle(source_candidate(), job=job)
    return repo, service, run, bundle


@pytest.mark.parametrize("cls", [LegacyGateway, CustomCancellable, AssessOnly])
def test_legacy_dispatch_keeps_old_call_shape_and_unknown_observations(cls):
    bundle = ai.build_evidence_bundle(source_candidate())
    value = ai.FakeGateway().assess(bundle)
    http = FakeHttpClient([envelope(value)])
    model = model_for(http, cls) if cls is LegacyGateway else cls()
    observed = C2Diagnostics()
    assert gw.assess_candidate(model, bundle, lambda: False, observed) == value
    assert model.calls == 1
    assert (
        observed.attempt_count is observed.repair_count is observed.transport_attempt_count is None
    )
    assert observed.output_bytes is observed.provider_finish_reason is None
    assert len(http.requests) == (1 if cls is LegacyGateway else 0)


@pytest.mark.parametrize("kind", ["ordinary", "historical"])
@pytest.mark.parametrize("cls", [LegacyGateway, CustomCancellable, AssessOnly])
def test_legacy_gateways_complete_through_both_service_consumers(caplog, kind, cls):
    http = FakeHttpClient([])
    model = model_for(http, cls) if cls is LegacyGateway else cls()
    repo, service, run, bundle = service_run(kind, model)
    http.responses.append(envelope(ai.FakeGateway().assess(bundle)))
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "compatibility"}])
    assert AIAnalysisWorker(queue, service).run_once(timeout=0)
    assert repo.get_ai_run(run["id"])["status"] == "COMPLETED"
    assert len(repo.list_ai_assessments(run["id"])) == 1
    assert model.calls == 1 and queue.acked == ["compatibility"]
    assert diagnostics(caplog) == []
    assert len(http.requests) == (1 if cls is LegacyGateway else 0)


def test_custom_type_error_after_work_is_not_retried():
    fault = TypeError("after custom work")

    class Custom(LegacyGateway):
        def assess_cancellable(self, bundle, *, should_cancel, **kwargs):
            assert kwargs == {}
            self.calls += 1
            raise fault

    model = model_for(FakeHttpClient([]), Custom)
    observed = C2Diagnostics()
    with pytest.raises(TypeError) as caught:
        gw.assess_candidate(
            model, ai.build_evidence_bundle(source_candidate()), lambda: False, observed
        )
    assert caught.value is fault and model.calls == 1
    assert observed.attempt_count is observed.transport_attempt_count is None


@pytest.mark.parametrize("base", [gw.OllamaGateway, gw.OpenAICompatibleGateway])
@pytest.mark.parametrize("inherit", [False, True])
@pytest.mark.parametrize("repair", [False, True])
def test_known_bound_implementation_preserves_local_repair_and_cache_counts(base, inherit, repair):
    class Inherited(base):
        pass

    bundle = ai.build_evidence_bundle(source_candidate())
    value = ai.FakeGateway().assess(bundle)
    replies = ([envelope({})] if repair else []) + [envelope(value)]
    if base is gw.OpenAICompatibleGateway:
        replies = [
            {"choices": [{"message": reply["message"], "finish_reason": reply["done_reason"]}]}
            for reply in replies
        ]
    http = FakeHttpClient(replies)
    model = model_for(http, Inherited if inherit else base)
    first, cached = C2Diagnostics(), C2Diagnostics()
    assert gw.assess_candidate(model, bundle, lambda: False, first) == value
    first_counts = (first.attempt_count, first.repair_count, first.transport_attempt_count)
    assert first_counts == (1 + repair, int(repair), 1 + repair)
    assert gw.assess_candidate(model, bundle, lambda: False, cached) == value
    assert cached.attempt_count == cached.repair_count == cached.transport_attempt_count == 0
    assert cached.output_bytes is cached.provider_finish_reason is None
    assert (first.attempt_count, first.repair_count, first.transport_attempt_count) == first_counts
    assert len(http.requests) == 1 + repair


# Callback ordinal and actual transport dispatch count at each legal boundary.
# Invalid initial output never reaches post-validation; repair has no entry/cache check.
CALLBACK_PHASES = [
    ("initial", "entry", 1, 0),
    ("initial", "before-request", 2, 0),
    ("initial", "before-transport", 3, 0),
    ("initial", "in-transport", 4, 1),
    ("initial", "after-response", 5, 1),
    ("initial", "post-validation", 6, 1),
    ("repair", "before-request", 6, 1),
    ("repair", "before-transport", 7, 1),
    ("repair", "in-transport", 8, 2),
    ("repair", "after-response", 9, 2),
    ("repair", "post-validation", 10, 2),
    ("cache", "entry", 1, 0),
    ("cache", "before-validation", 2, 0),
    ("cache", "post-validation", 3, 0),
    ("initial-retry", "before-transport", 5, 1),
    ("initial-retry", "in-transport", 6, 2),
    ("initial-retry", "after-response", 7, 2),
    ("initial-retry", "post-validation", 8, 2),
    ("repair-retry", "before-transport", 9, 2),
    ("repair-retry", "in-transport", 10, 3),
    ("repair-retry", "after-response", 11, 3),
    ("repair-retry", "post-validation", 12, 3),
]


class CallbackHttp(FakeHttpClient):
    def request_cancellable(self, method, url, *, headers=None, body=None, should_cancel):
        self.requests.append({"method": method, "url": url, "headers": headers, "body": body})
        if should_cancel():
            raise InterruptedError("canned cancellation")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


@pytest.mark.parametrize("mode,phase,check_number,dispatches", CALLBACK_PHASES)
@pytest.mark.parametrize("fault_type", [BaselineStorageError, custody.HistoricalStorageError])
@pytest.mark.parametrize("route", ["gateway", "historical-service", "historical-worker"])
def test_storage_callback_failure_escapes_without_repair_or_publication(
    caplog, monkeypatch, mode, phase, check_number, dispatches, fault_type, route
):
    http = CallbackHttp([])
    model = gw.OllamaGateway(
        base_url="http://offline.invalid", model="canned", retries=1, http_client=http
    )
    repo, service, run, bundle = service_run("historical", model)
    good = envelope(ai.FakeGateway().assess(bundle))
    http.responses = (
        ([envelope({})] if mode.startswith("repair") else [])
        + ([TimeoutError("canned retry")] if mode.endswith("retry") else [])
        + [good, good]
    )
    if mode == "cache":
        model.assess(bundle)
        http.requests.clear()
    fault = fault_type()
    fired, publication, observed_errors = [], [], []
    checks = 0
    armed = route == "gateway"
    original_get, original_save = repo.get_ai_run, repo.save_ai_run

    def get(identifier):
        nonlocal checks
        if armed:
            checks += 1
            if checks == check_number:
                fired.append((fault, len(http.requests)))
                raise fault
        return original_get(identifier)

    def save(value):
        nonlocal armed
        result = original_save(value)
        if value["status"] == "ANALYZING":
            armed = True
        return result

    def publish(value):
        publication.append(value)
        pytest.fail("storage callback failure must not publish assessment or artifact")

    monkeypatch.setattr(repo, "get_ai_run", get)
    monkeypatch.setattr(repo, "save_ai_run", save)
    monkeypatch.setattr(repo, "save_ai_assessment", publish)
    monkeypatch.setattr(repo, "save_ai_artifact", publish)
    if route == "historical-worker":
        queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "storage-fault"}])
        worker = AIAnalysisWorker(queue, service)
        original_observe = worker.metrics.observe_exception

        def observe(duration, exc):
            observed_errors.append(exc)
            original_observe(duration, exc)

        monkeypatch.setattr(worker.metrics, "observe_exception", observe)
        returned = worker.run_once(timeout=0)
        assert fired == [(fault, dispatches)], (mode, phase, checks)
        assert not returned and queue.acked == []
        assert len(observed_errors) == 1 and observed_errors[0] is fault
    else:
        with pytest.raises(fault_type) as caught:
            if route == "gateway":
                observed = C2Diagnostics()
                with observed.capture(run["id"]):
                    gw.assess_candidate(
                        model,
                        bundle,
                        lambda: get(run["id"])["status"] == "CANCELLED",
                        observed,
                    )
            else:
                service.execute(run["id"])
        assert caught.value is fault
    assert fired == [(fault, dispatches)], (mode, phase, checks)
    assert checks == check_number and len(http.requests) == dispatches
    assert diagnostics(caplog) == [] and publication == []
    assert repo.list_ai_assessments(run["id"]) == [] and repo.ai_artifacts == {}
    saved = original_get(run["id"])
    assert saved["status"] == ("QUEUED" if route == "gateway" else "ANALYZING")
    assert not any(step["to_status"] == "FAILED" for step in saved["transitions"])
    assert "failure_diagnostic" not in saved


@pytest.mark.parametrize("kind", ["ordinary", "historical"])
@pytest.mark.parametrize(
    "mode,check_number,dispatches", [("initial", 6, 1), ("repair", 10, 2), ("cache", 3, 0)]
)
def test_post_validation_cancellation_remains_cancelled_and_acknowledged(
    caplog, monkeypatch, kind, mode, check_number, dispatches
):
    http = CallbackHttp([])
    model = model_for(http)
    repo, service, run, bundle = service_run(kind, model)
    good = envelope(ai.FakeGateway().assess(bundle))
    http.responses = ([envelope({})] if mode == "repair" else []) + [good]
    if mode == "cache":
        model.assess(bundle)
        http.requests.clear()
    original_get, original_save = repo.get_ai_run, repo.save_ai_run
    checks, fired, armed = 0, [], False

    def save(value):
        nonlocal armed
        result = original_save(value)
        if value["status"] == "ANALYZING":
            armed = True
        return result

    def get(identifier):
        nonlocal checks, armed
        if armed:
            checks += 1
            if checks == check_number:
                armed = False
                fired.append(True)
                service.cancel(identifier, "canned cancellation")
        return original_get(identifier)

    monkeypatch.setattr(repo, "save_ai_run", save)
    monkeypatch.setattr(repo, "get_ai_run", get)
    queue = MemoryAIAnalysisWorkerQueue([{"ai_run_id": run["id"], "receipt": "cancelled"}])
    assert AIAnalysisWorker(queue, service).run_once(timeout=0)
    assert fired == [True] and checks == check_number
    assert original_get(run["id"])["status"] == "CANCELLED" and queue.acked == ["cancelled"]
    assert repo.list_ai_assessments(run["id"]) == [] and repo.ai_artifacts == {}
    assert len(http.requests) == dispatches
    (diagnostic,) = diagnostics(caplog)
    assert diagnostic["stage"] == "CANCELLED"
    assert diagnostic["attempt_count"] == diagnostic["transport_attempt_count"] == dispatches
    assert diagnostic["repair_count"] == (1 if mode == "repair" else 0)
