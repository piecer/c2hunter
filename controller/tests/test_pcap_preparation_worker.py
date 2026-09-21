from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from test_analysis_history_pcap_api import _pcap

from c2hunter_controller.app import _public_job, create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.jobs import JobState, StateMachine
from c2hunter_controller.pcap_preparation_worker import PcapPreparationWorker
from c2hunter_controller.queueing import MemoryControllerQueue
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository


class MutableClock:
    def __init__(self, value: datetime) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


@pytest.mark.parametrize(
    ("internal_phase", "public_phase"),
    [("ANALYSIS_ENQUEUE_PENDING", "PARSING"), ("ANALYSIS_CLAIMED", "ANALYSIS_QUEUED")],
)
def test_public_job_projects_internal_processing_phases(
    internal_phase: str, public_phase: str
) -> None:
    public = _public_job({"id": "job-1", "processing": {"phase": internal_phase}})
    assert public["processing"]["phase"] == public_phase


def _repository(tmp_path: Path, kind: str) -> Any:
    clock = MutableClock(datetime(2026, 9, 21, 5, 0, tzinfo=UTC))
    if kind == "memory":
        repository = MemoryRepository(_lease_clock=clock)
    else:
        repository = SQLiteRepository(tmp_path / "controller.db", _lease_clock=clock)
    cast(Any, repository).test_clock = clock
    return repository


def _accepted_job(repository: Any) -> str:
    client = TestClient(create_app(Settings(environment="test"), repository))
    created = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "leased preparation",
            "filename": "capture.pcap",
            "idempotency_key": "leased-preparation-1",
            "analysis_module": "c2",
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"module": "c2"},
        },
    ).json()
    response = client.put(
        f"/api/v1/pcap-analysis-jobs/{created['id']}/capture",
        content=_pcap(),
        headers={"content-type": "application/vnd.tcpdump.pcap"},
    )
    assert response.status_code == 202
    return str(created["id"])


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_pcap_preparation_claim_is_exclusive_until_lease_expires(tmp_path: Path, kind: str) -> None:
    repository = _repository(tmp_path, kind)
    job_id = _accepted_job(repository)
    now = datetime(2026, 9, 21, 5, 0, tzinfo=UTC)

    first = repository.claim_pcap_preparation(now=now, lease_seconds=30)
    repository.test_clock.value = now + timedelta(seconds=29)
    blocked = repository.claim_pcap_preparation(now=now + timedelta(seconds=29), lease_seconds=30)
    repository.test_clock.value = now + timedelta(seconds=31)
    reclaimed = repository.claim_pcap_preparation(now=now + timedelta(seconds=31), lease_seconds=30)

    assert first is not None
    assert first["id"] == job_id
    assert first["processing"]["phase"] == "PARSING"
    assert first["processing"]["attempt"] == 1
    assert blocked is None
    assert reclaimed is not None
    assert reclaimed["id"] == job_id
    assert reclaimed["processing"]["attempt"] == 2
    assert reclaimed["processing"]["lease_token"] != first["processing"]["lease_token"]


def test_pcap_preparation_persists_flows_before_analysis_enqueue() -> None:
    repository = MemoryRepository(_lease_clock=lambda: datetime(2026, 9, 21, 5, 0, tzinfo=UTC))
    job_id = _accepted_job(repository)
    enqueued: list[dict[str, Any]] = []
    worker = PcapPreparationWorker(
        repository,
        enqueue=enqueued.append,
        lease_seconds=30,
        max_packets=2_000_000,
    )

    assert worker.run_once(now=datetime(2026, 9, 21, 5, 0, tzinfo=UTC)) is True

    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["flow_records"]
    assert stored["status"] == "ANALYZING"
    assert stored["processing"]["phase"] == "ANALYSIS_QUEUED"
    assert stored["processing"]["lease_token"] == enqueued[0]["preparation_lease_token"]
    assert len(enqueued) == 1
    assert enqueued[0]["id"] == job_id
    assert enqueued[0]["flow_records"] == stored["flow_records"]


def test_sqlite_preparation_claim_hydrates_payload_signature_snapshot(tmp_path: Path) -> None:
    repository = _repository(tmp_path, "sqlite")
    repository.save_payload_signature(
        {
            "id": "signature-1",
            "name": "snapshot signature",
            "pattern": "beef",
            "enabled": True,
            "created_at": "2026-09-21T05:00:00+00:00",
        }
    )
    _accepted_job(repository)
    enqueued: list[dict[str, Any]] = []
    worker = PcapPreparationWorker(
        repository,
        enqueue=enqueued.append,
        lease_seconds=30,
        max_packets=2_000_000,
    )

    assert worker.run_once(now=datetime(2026, 9, 21, 5, 0, tzinfo=UTC)) is True

    assert [item["id"] for item in enqueued[0]["payload_signatures"]] == ["signature-1"]


def test_staged_ddos_preparation_attaches_parser_coverage_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository()
    client = TestClient(create_app(Settings(environment="test"), repository))
    created = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "ddos coverage",
            "filename": "capture.pcap",
            "idempotency_key": "ddos-coverage-1",
            "analysis_module": "ddos_attack",
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"module": "ddos_attack"},
        },
    ).json()
    assert (
        client.put(
            f"/api/v1/pcap-analysis-jobs/{created['id']}/capture",
            content=_pcap(),
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        ).status_code
        == 202
    )
    module = __import__("c2hunter_controller.pcap_preparation_worker", fromlist=["parse_pcap"])
    original_parse = module.parse_pcap

    def parse_with_skip(*args: Any, **kwargs: Any) -> Any:
        parsed = original_parse(*args, **kwargs)
        values = vars(parsed).copy()
        values["skipped_packet_count"] = 1
        return SimpleNamespace(**values)

    monkeypatch.setattr(module, "parse_pcap", parse_with_skip)
    enqueued: list[dict[str, Any]] = []
    worker = PcapPreparationWorker(
        repository, enqueue=enqueued.append, lease_seconds=30, max_packets=2_000_000
    )

    assert worker.run_once() is True

    assert enqueued[0]["ddos_coverage_context"] == {
        "parser_skipped_packet_count": 1,
        "sensor_dropped_packet_count": 0,
        "sensor_clock_skew_detected": False,
        "sensor_capture_quality_unavailable": False,
        "capture_partial": False,
    }


def test_app_exposes_one_durable_preparation_tick() -> None:
    repository = MemoryRepository()
    application = create_app(Settings(environment="test"), repository)
    client = TestClient(application)
    created = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "application preparation",
            "filename": "capture.pcap",
            "idempotency_key": "application-preparation-1",
            "analysis_module": "c2",
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"module": "c2"},
        },
    ).json()
    assert (
        client.put(
            f"/api/v1/pcap-analysis-jobs/{created['id']}/capture",
            content=_pcap(),
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        ).status_code
        == 202
    )

    assert application.state.process_pcap_preparations_once() is True

    current = client.get(f"/api/v1/analysis-jobs/{created['id']}").json()
    assert current["processing"]["phase"] == "ANALYSIS_QUEUED"


def test_public_job_hides_internal_preparation_lease() -> None:
    repository = MemoryRepository(_lease_clock=lambda: datetime(2026, 9, 21, 5, 0, tzinfo=UTC))
    job_id = _accepted_job(repository)
    claimed = repository.claim_pcap_preparation(
        now=datetime(2026, 9, 21, 5, 0, tzinfo=UTC), lease_seconds=30
    )
    assert claimed is not None
    claimed["processing"]["analysis_claim_token"] = "internal-analysis-token"
    claimed["processing"]["analysis_lease_expires_at"] = "2026-09-21T05:01:00+00:00"
    repository.save_job(claimed)
    client = TestClient(create_app(Settings(environment="test"), repository))

    processing = client.get(f"/api/v1/analysis-jobs/{job_id}").json()["processing"]

    assert processing["phase"] == "PARSING"
    assert "lease_token" not in processing
    assert "lease_expires_at" not in processing
    assert "analysis_claim_token" not in processing
    assert "analysis_lease_expires_at" not in processing
    listed = client.get("/api/v1/analysis-jobs").json()["items"][0]
    assert "preparation_lease_token" not in listed
    listed_processing = listed["processing"]
    assert "lease_token" not in listed_processing
    assert "analysis_claim_token" not in listed_processing


def test_worker_start_event_is_the_only_transition_to_analysis_running() -> None:
    repository = MemoryRepository()
    queue = MemoryControllerQueue()
    application = create_app(Settings(environment="test"), repository, queue=queue)
    client = TestClient(application)
    created = client.post(
        "/api/v1/pcap-analysis-jobs/initiate",
        json={
            "name": "truthful running state",
            "filename": "capture.pcap",
            "idempotency_key": "truthful-running-1",
            "analysis_module": "c2",
            "internal_networks": ["10.0.0.0/8"],
            "analysis": {"module": "c2"},
        },
    ).json()
    assert (
        client.put(
            f"/api/v1/pcap-analysis-jobs/{created['id']}/capture",
            content=_pcap(),
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        ).status_code
        == 202
    )
    assert application.state.process_pcap_preparations_once() is True
    assert (
        client.get(f"/api/v1/analysis-jobs/{created['id']}").json()["processing"]["phase"]
        == "ANALYSIS_QUEUED"
    )

    queue.results.append(
        {
            "job_id": created["id"],
            "status": "EVENT",
            "event": "ANALYSIS_STARTED",
            "occurred_at": "2026-09-21T05:00:01+00:00",
        }
    )
    assert application.state.process_results_once() is True

    current = client.get(f"/api/v1/analysis-jobs/{created['id']}").json()
    assert current["processing"]["phase"] == "ANALYSIS_RUNNING"
    assert current["processing"]["phase_started_at"] == "2026-09-21T05:00:01+00:00"


def test_delayed_start_event_cannot_overwrite_terminal_job() -> None:
    class TerminalDuringStartedSaveRepository(MemoryRepository):
        race_enabled = False

        def mark_analysis_started(
            self,
            job_id: str,
            occurred_at: str,
            *,
            attempt: int | None = None,
            lease_token: str | None = None,
        ) -> bool:
            if self.race_enabled:
                self.race_enabled = False
                terminal = self.get_job_summary(job_id)
                assert terminal is not None
                StateMachine().transition(terminal, JobState.COMPLETED, "terminal result won")
                terminal_processing = dict(terminal["processing"])
                terminal_processing["phase"] = "COMPLETED"
                terminal["processing"] = terminal_processing
                super().save_job_metadata(terminal)
            return super().mark_analysis_started(
                job_id, occurred_at, attempt=attempt, lease_token=lease_token
            )

    repository = TerminalDuringStartedSaveRepository()
    queue = MemoryControllerQueue()
    application = create_app(Settings(environment="test"), repository, queue=queue)
    job_id = _accepted_job(repository)
    assert application.state.process_pcap_preparations_once() is True
    repository.race_enabled = True
    queue.results.append(
        {
            "job_id": job_id,
            "status": "EVENT",
            "event": "ANALYSIS_STARTED",
            "occurred_at": datetime.now(UTC).isoformat(),
        }
    )

    assert application.state.process_results_once() is True
    stored = repository.get_job_summary(job_id)
    assert stored is not None
    assert stored["status"] == "COMPLETED"
    assert stored["processing"]["phase"] == "COMPLETED"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_atomic_terminal_transition_prevents_result_from_resurrecting_cancelled_job(
    tmp_path: Path, kind: str
) -> None:
    repository = _repository(tmp_path, kind)
    job_id = _accepted_job(repository)
    worker = PcapPreparationWorker(
        repository, enqueue=lambda _job: None, lease_seconds=30, max_packets=2_000_000
    )
    assert worker.run_once(now=datetime(2026, 9, 21, 5, 0, tzinfo=UTC)) is True
    result = repository.get_job_summary(job_id)
    cancellation = repository.get_job_summary(job_id)
    assert result is not None and cancellation is not None
    StateMachine().transition(cancellation, JobState.CANCELLED, "operator cancellation")
    cancellation["processing"] = {**cancellation["processing"], "phase": "CANCELLED"}
    StateMachine().transition(result, JobState.COMPLETED, "worker result")
    result["processing"] = {**result["processing"], "phase": "COMPLETED"}

    assert repository.transition_job_terminal(cancellation) is True
    assert repository.transition_job_terminal(result) is False

    stored = repository.get_job_summary(job_id)
    assert stored is not None
    assert stored["status"] == "CANCELLED"
    assert stored["processing"]["phase"] == "CANCELLED"


def test_cancelling_staged_upload_is_terminal_and_not_prepared() -> None:
    repository = MemoryRepository()
    application = create_app(Settings(environment="test"), repository)
    client = TestClient(application)
    job_id = _accepted_job(repository)

    response = client.post(
        f"/api/v1/analysis-jobs/{job_id}/cancel",
        json={"reason": "operator stopped offline analysis"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "CANCELLED"
    assert response.json()["processing"]["phase"] == "CANCELLED"
    assert application.state.process_pcap_preparations_once() is False


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_claimed_preparation_cannot_publish_after_cancellation(
    tmp_path: Path, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path, kind)
    job_id = _accepted_job(repository)
    enqueued: list[dict[str, Any]] = []
    worker = PcapPreparationWorker(
        repository, enqueue=enqueued.append, lease_seconds=30, max_packets=2_000_000
    )
    original_parse = __import__(
        "c2hunter_controller.pcap_preparation_worker", fromlist=["parse_pcap"]
    ).parse_pcap

    def cancel_during_parse(*args: Any, **kwargs: Any) -> Any:
        current = repository.get_job_summary(job_id)
        assert current is not None
        StateMachine().transition(current, JobState.CANCELLED, "cancelled while parsing")
        processing = dict(current["processing"])
        processing["phase"] = "CANCELLED"
        current["processing"] = processing
        repository.save_job_metadata(current)
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(
        "c2hunter_controller.pcap_preparation_worker.parse_pcap", cancel_during_parse
    )

    assert worker.run_once(now=datetime(2026, 9, 21, 5, 0, tzinfo=UTC)) is True
    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "CANCELLED"
    assert stored["processing"]["phase"] == "CANCELLED"
    assert stored["flow_records"] == []
    assert enqueued == []


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_reclaimed_preparation_fences_stale_worker_publication(
    tmp_path: Path, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = _repository(tmp_path, kind)
    job_id = _accepted_job(repository)
    enqueued: list[dict[str, Any]] = []
    worker = PcapPreparationWorker(
        repository, enqueue=enqueued.append, lease_seconds=30, max_packets=2_000_000
    )
    original_parse = __import__(
        "c2hunter_controller.pcap_preparation_worker", fromlist=["parse_pcap"]
    ).parse_pcap

    def reclaim_during_parse(*args: Any, **kwargs: Any) -> Any:
        repository.test_clock.value = datetime(2026, 9, 21, 5, 0, 31, tzinfo=UTC)
        reclaimed = repository.claim_pcap_preparation(
            now=datetime(2026, 9, 21, 5, 0, 31, tzinfo=UTC), lease_seconds=30
        )
        assert reclaimed is not None
        assert reclaimed["processing"]["attempt"] == 2
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(
        "c2hunter_controller.pcap_preparation_worker.parse_pcap", reclaim_during_parse
    )

    assert worker.run_once(now=datetime(2026, 9, 21, 5, 0, tzinfo=UTC)) is True
    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["processing"]["phase"] == "PARSING"
    assert stored["processing"]["attempt"] == 2
    assert stored["flow_records"] == []
    assert enqueued == []


def test_prepared_data_is_committed_before_analysis_enqueue() -> None:
    repository = MemoryRepository(_lease_clock=lambda: datetime(2026, 9, 21, 5, 0, tzinfo=UTC))
    job_id = _accepted_job(repository)
    observed: dict[str, Any] = {}

    def enqueue(job: dict[str, Any]) -> None:
        current = repository.get_job(job_id)
        assert current is not None
        observed.update(current)
        assert current["flow_records"]
        assert current["processing"]["phase"] == "ANALYSIS_ENQUEUE_PENDING"

    worker = PcapPreparationWorker(
        repository,
        enqueue=enqueue,
        lease_seconds=30,
        lease_renew_seconds=10,
        max_attempts=3,
        max_packets=2_000_000,
    )

    assert worker.run_once() is True
    assert observed["flow_records"]
    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["processing"]["phase"] == "ANALYSIS_QUEUED"


def test_enqueue_failure_keeps_committed_preparation_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = MemoryRepository(_lease_clock=lambda: datetime(2026, 9, 21, 5, 0, tzinfo=UTC))
    job_id = _accepted_job(repository)
    parse_calls = 0
    module = __import__("c2hunter_controller.pcap_preparation_worker", fromlist=["parse_pcap"])
    original_parse = module.parse_pcap

    def counted_parse(*args: Any, **kwargs: Any) -> Any:
        nonlocal parse_calls
        parse_calls += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(module, "parse_pcap", counted_parse)
    worker = PcapPreparationWorker(
        repository,
        enqueue=lambda _job: (_ for _ in ()).throw(RuntimeError("queue unavailable")),
        lease_seconds=30,
        lease_renew_seconds=10,
        max_attempts=3,
        max_packets=2_000_000,
    )

    with pytest.raises(RuntimeError, match="queue unavailable"):
        worker.run_once()
    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["flow_records"]
    assert stored["processing"]["phase"] == "ANALYSIS_ENQUEUE_PENDING"

    repository._lease_clock = lambda: datetime(2026, 9, 21, 5, 0, 31, tzinfo=UTC)
    enqueued: list[dict[str, Any]] = []
    retry = PcapPreparationWorker(
        repository,
        enqueue=enqueued.append,
        lease_seconds=30,
        lease_renew_seconds=10,
        max_attempts=3,
        max_packets=2_000_000,
    )
    assert retry.run_once() is True
    assert parse_calls == 1
    assert len(enqueued) == 1
    current = repository.get_job(job_id)
    assert current is not None
    assert current["processing"]["phase"] == "ANALYSIS_QUEUED"


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_long_preparation_renews_its_repository_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    repository = _repository(tmp_path, kind)
    job_id = _accepted_job(repository)
    entered = threading.Event()
    release = threading.Event()
    module = __import__("c2hunter_controller.pcap_preparation_worker", fromlist=["parse_pcap"])
    original_parse = module.parse_pcap

    def slow_parse(*args: Any, **kwargs: Any) -> Any:
        entered.set()
        assert release.wait(2)
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(module, "parse_pcap", slow_parse)
    enqueued: list[dict[str, Any]] = []
    worker = PcapPreparationWorker(
        repository,
        enqueue=enqueued.append,
        lease_seconds=30,
        lease_renew_seconds=0.01,
        max_attempts=3,
        max_packets=2_000_000,
    )
    thread = threading.Thread(target=worker.run_once)
    thread.start()
    assert entered.wait(2)
    repository.test_clock.value += timedelta(seconds=20)
    time.sleep(0.05)
    repository.test_clock.value += timedelta(seconds=20)
    time.sleep(0.05)
    release.set()
    thread.join(2)

    assert not thread.is_alive()
    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["processing"]["phase"] == "ANALYSIS_QUEUED"
    assert len(enqueued) == 1


@pytest.mark.parametrize("kind", ["memory", "sqlite"])
def test_preparation_attempt_exhaustion_is_terminal(tmp_path: Path, kind: str) -> None:
    repository = _repository(tmp_path, kind)
    job_id = _accepted_job(repository)
    now = datetime(2026, 9, 21, 5, 0, tzinfo=UTC)
    for attempt in range(1, 4):
        repository.test_clock.value = now + timedelta(seconds=31 * (attempt - 1))
        claimed = repository.claim_pcap_preparation(
            now=repository.test_clock.value,
            lease_seconds=30,
            max_attempts=3,
        )
        assert claimed is not None
        assert claimed["processing"]["attempt"] == attempt

    repository.test_clock.value = now + timedelta(seconds=93)
    assert (
        repository.claim_pcap_preparation(
            now=repository.test_clock.value,
            lease_seconds=30,
            max_attempts=3,
        )
        is None
    )
    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "FAILED"
    assert stored["processing"]["phase"] == "FAILED"
    assert stored["error_code"] == "PCAP_PREPARATION_ATTEMPTS_EXHAUSTED"


def test_uncertain_queue_delivery_retries_with_one_stable_message() -> None:
    clock = MutableClock(datetime(2026, 9, 21, 5, 0, tzinfo=UTC))
    repository = MemoryRepository(_lease_clock=clock)
    job_id = _accepted_job(repository)
    queue = MemoryControllerQueue()
    first = True

    def enqueue_then_lose_ack(job: dict[str, Any]) -> None:
        nonlocal first
        queue.enqueue(job)
        if first:
            first = False
            raise RuntimeError("queue acknowledgement lost")

    worker = PcapPreparationWorker(
        repository,
        enqueue=enqueue_then_lose_ack,
        lease_seconds=30,
        lease_renew_seconds=10,
        max_attempts=1,
        max_packets=2_000_000,
    )
    with pytest.raises(RuntimeError, match="acknowledgement lost"):
        worker.run_once()
    assert len(queue.jobs) == 1
    retained_attempt = queue.jobs[0]["preparation_attempt"]
    retained_token = queue.jobs[0]["preparation_lease_token"]

    clock.value += timedelta(seconds=31)
    assert worker.run_once() is True

    stored = repository.get_job(job_id)
    assert stored is not None
    assert stored["status"] == "ANALYZING"
    assert stored["processing"]["phase"] == "ANALYSIS_QUEUED"
    assert stored["processing"]["attempt"] == retained_attempt
    assert stored["processing"]["lease_token"] == retained_token
    assert len(queue.jobs) == 1
    assert queue.jobs[0]["message_id"] == f"analysis-job:{job_id}"


def test_completed_c2_result_redelivery_repairs_candidate_side_effects() -> None:
    class FailOnceCandidateRepository(MemoryRepository):
        fail_once = True

        def save_candidates(self, job_id: str, candidates: list[dict[str, Any]]) -> None:
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError("injected candidate persistence failure")
            super().save_candidates(job_id, candidates)

    repository = FailOnceCandidateRepository()
    queue = MemoryControllerQueue()
    application = create_app(Settings(environment="test"), repository, queue=queue)
    job_id = _accepted_job(repository)
    assert application.state.process_pcap_preparations_once() is True
    candidate = {"ip": "203.0.113.10", "score": 90}
    result = {
        "job_id": job_id,
        "status": "COMPLETED",
        "result": {"candidates": [candidate]},
    }
    queue.results.append(dict(result))

    with pytest.raises(RuntimeError, match="candidate persistence failure"):
        application.state.process_results_once()
    terminal = repository.get_job_summary(job_id)
    assert terminal is not None and terminal["status"] == "COMPLETED"
    assert repository.get_candidates(job_id) == []

    queue.results.append(dict(result))
    assert application.state.process_results_once() is True
    saved = repository.get_candidates(job_id)
    assert len(saved) == 1
    assert saved[0]["ip"] == candidate["ip"]
    assert saved[0]["score"] == candidate["score"]
    assert saved[0]["id"]
    assert "id" not in candidate
