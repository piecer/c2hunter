"""Impossible baseline facts reject at worker, write and read boundaries."""

from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from c2hunter_analysis.ddos_job import analyze_ddos_job
from pcap_guidance_fixture_builder import packets, pcap_bytes
from test_pcap_guidance_temporal_responses import analyze_samples, shifted

from c2hunter_controller.pcap_attack_guidance_schema import validate_job_guidance
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository

REVIEW_PCAP = Path(__file__).parent / "fixtures/pcap_guidance_review/contract_positive.pcap"


def produced_job(samples, *, origin=None):
    rows = analyze_samples(samples)
    job = {
        "id": "baseline-job",
        "dataset_id": "baseline-dataset",
        "source_type": "PCAP_UPLOAD",
        "analysis": {"module": "ddos_attack"},
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": rows,
        "idempotency_key": "baseline-key",
        "status": "COMPLETED",
        "candidate_count": 0,
    }
    job.update(analyze_ddos_job(job))
    if origin is not None:
        # Contract translation control: classic PCAP cannot encode pre-epoch
        # seconds. Do not alter parsed records' bound packet-evidence times.
        from c2hunter_analysis.pcap_attack_guidance import stamp

        delta = origin - datetime(2026, 9, 15, tzinfo=UTC)
        guide = job["pcap_attack_guidance"]
        for obj in [guide["summary"], *guide["candidates"], job["ddos_attack"]["summary"]]:
            for field in ("first_seen", "last_seen", "window_start", "window_end"):
                if field in obj:
                    obj[field] = stamp(datetime.fromisoformat(obj[field]) + delta)
    validate_job_guidance(job)
    return job


def forge_original(guide):
    candidate = guide["candidates"][0]
    candidate.update(
        packet_count=1000, syn_only_count=1000, baseline_window_count=3, baseline_packet_count=96
    )
    candidate["uncertainty_codes"] = sorted(
        "WITHIN_CAPTURE_NOT_KNOWN_NORMAL" if code == "WITHIN_CAPTURE_BASELINE_UNAVAILABLE" else code
        for code in candidate["uncertainty_codes"]
    )


def baseline_samples(*, target="10.0.0.10", partial=False):
    baseline = (
        shifted(packets(1, target=target, span_us=0), 4_999_999)
        + packets(1, start=5, target=target, span_us=0)
        + packets(1, start=10, target=target, span_us=0)
        if partial
        else sum(
            (
                packets(32, start=i * 5, target=target, flags=16, payload=b"normal")
                for i in range(3)
            ),
            [],
        )
    )
    return baseline + shifted(packets(160, start=15, target=target, span_us=0), 1)


@pytest.mark.parametrize("origin", [None, datetime(1969, 12, 31, 23, 59, 40, tzinfo=UTC)])
def test_partial_edge_occupied_windows_are_legitimate_baselines(origin):
    job = produced_job(baseline_samples(partial=True), origin=origin)
    guide = validate_job_guidance(job)
    candidate = guide["candidates"][0]
    assert candidate["baseline_window_count"] == 3
    assert candidate["baseline_packet_count"] == 3
    assert guide["summary"]["retained_window_count"] == 4
    assert guide["summary"]["first_seen"].endswith("4.999999Z")
    assert candidate["first_seen"].endswith("5.000001Z")


@pytest.mark.parametrize(
    "mutation", ["retained", "time", "disjoint_windows", "disjoint_packets", "omitted_packets"]
)
def test_baseline_constraints_reject_independent_impossibilities(mutation):
    samples = baseline_samples()
    if mutation.startswith("disjoint"):
        samples += baseline_samples(target="10.0.0.11")
    job = produced_job(samples)
    guide = job["pcap_attack_guidance"]
    summary = guide["summary"]
    if mutation == "retained":
        summary["retained_window_count"] = 3
    elif mutation == "time":
        # Three prior slots cannot fit between the report's first bucket and t=15.
        summary["first_seen"] = "2026-09-15T00:00:05.000000Z"
        job["ddos_attack"]["summary"]["first_seen"] = summary["first_seen"]
    elif mutation == "disjoint_windows":
        summary["retained_window_count"] = 7
    elif mutation == "disjoint_packets":
        for candidate in guide["candidates"]:
            candidate["baseline_packet_count"] = 200
    else:
        summary["omitted_observation_count"] = 1
        summary["coverage_complete"] = False
        guide["coverage_codes"] = sorted([*guide["coverage_codes"], "WINDOW_STATE_LIMIT"])
    with pytest.raises(ValueError):
        validate_job_guidance(job)


@pytest.mark.parametrize(
    "origin", [datetime(2026, 9, 15, tzinfo=UTC), datetime(1969, 12, 31, 23, 59, 40, tzinfo=UTC)]
)
def test_first_observation_one_microsecond_crosses_prior_slot_bound(origin):
    from c2hunter_analysis.pcap_attack_guidance import stamp

    job = produced_job(baseline_samples(partial=True), origin=origin)
    first = stamp(origin + timedelta(seconds=5))
    job["pcap_attack_guidance"]["summary"]["first_seen"] = first
    job["ddos_attack"]["summary"]["first_seen"] = first
    with pytest.raises(ValueError):
        validate_job_guidance(job)


def move_candidate_earlier(guide):
    from c2hunter_analysis.pcap_attack_guidance import stamp

    candidate = guide["candidates"][0]
    for field in ("window_start", "window_end", "first_seen", "last_seen"):
        candidate[field] = stamp(datetime.fromisoformat(candidate[field]) - timedelta(seconds=5))


def test_original_one_window_forgery_rejects_schema():
    assert pcap_bytes(packets(1200)) == REVIEW_PCAP.read_bytes()
    job = produced_job(packets(1200))
    forge_original(job["pcap_attack_guidance"])
    with pytest.raises(ValueError):
        validate_job_guidance(job)


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("mode", ["original", "retained", "time", "partial-valid"])
def test_original_forgery_is_not_acknowledged_as_completed_worker_result(tmp_path, backend, mode):
    from c2hunter_worker.analysis import execute_analysis
    from c2hunter_worker.runtime import Worker
    from fastapi.testclient import TestClient
    from test_durable_pipeline import QueueStub

    from c2hunter_controller.app import create_app
    from c2hunter_controller.config import Settings

    repository = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "worker.db")
    )
    queue = QueueStub()
    try:
        client = TestClient(
            create_app(
                Settings(environment="test", inline_flow_records_enabled=False),
                repository,
                queue=queue,
            )
        )
        created = client.post(
            "/api/v1/pcap-analysis-jobs/initiate",
            json={
                "name": "impossible baseline",
                "filename": "original.pcap",
                "idempotency_key": "baseline-staged",
                "analysis_module": "ddos_attack",
                "analysis": {"module": "ddos_attack"},
                "internal_networks": ["10.0.0.0/8"],
            },
        )
        assert created.status_code == 201, created.text
        job_id = created.json()["id"]
        accepted = client.put(
            f"/api/v1/pcap-analysis-jobs/{job_id}/capture",
            content=REVIEW_PCAP.read_bytes()
            if mode == "original"
            else pcap_bytes(baseline_samples(partial=True)),
            headers={"content-type": "application/vnd.tcpdump.pcap"},
        )
        assert accepted.status_code == 202, accepted.text
        assert client.app.state.process_pcap_preparations_once()
        (envelope,) = queue.jobs

        class Loader:
            def load(self, identifier):
                return repository.get_job(identifier)

            def claim_analysis(self, *args, **kwargs):
                return "CLAIMED", "baseline-claim"

            def renew_analysis(self, *args, **kwargs):
                return True

        worker = Worker(
            queue=queue,
            execute=execute_analysis,
            payload_loader=Loader(),
            health_path=tmp_path / "health.json",
        )
        result = worker._execute_job(envelope)
        assert result["status"] == "COMPLETED"
        guide = result["result"]["pcap_attack_guidance"]
        if mode == "original":
            assert guide["summary"]["retained_window_count"] == 1
            assert guide["candidates"][0]["packet_count"] == 1200
            forge_original(guide)
        elif mode == "retained":
            guide["summary"]["retained_window_count"] = 3
        elif mode == "time":
            move_candidate_earlier(guide)
        else:
            assert guide["candidates"][0]["baseline_packet_count"] == 3
        queue.results.append({**result, "receipt": "impossible-baseline"})
        assert client.app.state.process_results_once()
        detail = client.get(f"/api/v1/analysis-jobs/{job_id}")
        assert detail.status_code == 200, detail.text
        stored = detail.json()
        if mode == "partial-valid":
            assert stored["status"] == "COMPLETED"
            assert stored["pcap_attack_guidance"] == guide
            assert repository.get_job(job_id)["pcap_attack_guidance"] == guide
            assert queue.acked == ["impossible-baseline"]
            return
        assert stored["status"] == "FAILED"
        assert "pcap_attack_guidance" not in stored
        assert repository.get_job(job_id)["status"] == "FAILED"
        assert repository.get_candidates(job_id) == []
        # Poison messages are ACKed after recording failure, never completion.
        assert queue.acked == ["impossible-baseline"]
    finally:
        if backend == "sqlite":
            repository.close()


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
@pytest.mark.parametrize("mode", ["original", "retained", "time"])
def test_original_forgery_cannot_be_persisted_or_read_back(tmp_path, backend, mode):
    repository = (
        MemoryRepository() if backend == "memory" else SQLiteRepository(tmp_path / "state.db")
    )
    try:
        valid = produced_job(
            packets(1200) if mode == "original" else baseline_samples(partial=True)
        )
        repository.create_job(valid)
        bad = copy.deepcopy(valid)
        if mode == "original":
            forge_original(bad["pcap_attack_guidance"])
        elif mode == "retained":
            bad["pcap_attack_guidance"]["summary"]["retained_window_count"] = 3
        else:
            move_candidate_earlier(bad["pcap_attack_guidance"])
        for write in (
            repository.create_job,
            repository.save_job,
            repository.save_job_metadata,
            repository.transition_job_terminal,
            lambda value: repository.complete_job_with_candidates(value, []),
        ):
            with pytest.raises(ValueError):
                write(bad)
            assert (
                repository.get_job(valid["id"])["pcap_attack_guidance"]
                == valid["pcap_attack_guidance"]
            )
        if backend == "memory":
            repository.jobs[valid["id"]] = bad
        else:
            with repository.connection:
                repository.connection.execute(
                    "UPDATE objects SET data=? WHERE kind='job' AND id=?",
                    (json.dumps(bad, default=str), valid["id"]),
                )
        for read in (
            lambda: repository.get_job(valid["id"]),
            lambda: repository.get_job_summary(valid["id"]),
            repository.list_jobs,
        ):
            with pytest.raises(ValueError):
                read()
    finally:
        if backend == "sqlite":
            repository.close()
