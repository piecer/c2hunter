from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from typing import Any

from c2hunter_analysis.pcap import PcapParseError, parse_pcap

from .jobs import JobState, StateMachine
from .schemas import AnalysisJobCreate


def attach_ddos_coverage_context(job: dict[str, Any]) -> None:
    """Attach the shared immutable-dataset coverage contract for DDoS analysis."""
    if job.get("analysis", {}).get("module") != "ddos_attack":
        return
    raw_source = job.get("source")
    source: dict[str, Any] = raw_source if isinstance(raw_source, dict) else {}
    raw_quality = job.get("capture_quality")
    quality: dict[str, Any] = raw_quality if isinstance(raw_quality, dict) else {}
    is_uploaded_pcap = "captured_packet_count" in source
    previous = job.get("ddos_coverage_context", {})
    job["ddos_coverage_context"] = {
        "parser_skipped_packet_count": int(source.get("skipped_packet_count", 0) or 0),
        "sensor_dropped_packet_count": int(quality.get("dropped_packet_count", 0) or 0),
        "sensor_clock_skew_detected": bool(quality.get("clock_skew_detected", False)),
        "sensor_capture_quality_unavailable": not is_uploaded_pcap and not quality,
        "capture_partial": bool(
            int(job.get("capture_limit", {}).get("discarded_packets", 0) or 0) > 0
            or job.get("capture_incomplete") is True
            or job.get("error_code") == "LIVE_CAPTURE_RESTART_INCOMPLETE"
        ),
    }
    context = job["ddos_coverage_context"]
    for field, value in previous.items():
        if field == "sensor_capture_quality_unavailable":
            context[field] = value
        elif field in context:
            context[field] = max(context[field], value)


class PcapPreparationWorker:
    """Lease, durably prepare, and then enqueue one retained offline capture."""

    def __init__(
        self,
        repository: Any,
        *,
        enqueue: Callable[[dict[str, Any]], None],
        lease_seconds: int,
        max_packets: int,
        lease_renew_seconds: float | None = None,
        max_attempts: int = 3,
    ) -> None:
        self.repository = repository
        self.enqueue = enqueue
        self.lease_seconds = lease_seconds
        self.lease_renew_seconds = lease_renew_seconds or max(1.0, lease_seconds / 3)
        self.max_attempts = max_attempts
        self.max_packets = max_packets
        self.machine = StateMachine()

    def run_once(self, *, now: datetime | None = None) -> bool:
        claimed_at = now or datetime.now(UTC)
        job = self.repository.claim_pcap_preparation(
            now=claimed_at,
            lease_seconds=self.lease_seconds,
            max_attempts=self.max_attempts,
        )
        if job is None:
            return False
        job_id = str(job["id"])
        claimed_processing = dict(job["processing"])
        attempt = int(claimed_processing["attempt"])
        lease_token = str(claimed_processing["lease_token"])
        stop_heartbeat = threading.Event()
        lease_lost = threading.Event()

        def heartbeat() -> None:
            while not stop_heartbeat.wait(self.lease_renew_seconds):
                try:
                    renewed = self.repository.renew_pcap_preparation(
                        job_id,
                        attempt=attempt,
                        lease_token=lease_token,
                        lease_seconds=self.lease_seconds,
                    )
                except Exception:
                    renewed = False
                if not renewed:
                    lease_lost.set()
                    return

        heartbeat_thread = threading.Thread(
            target=heartbeat,
            name=f"pcap-preparation-heartbeat-{job_id}",
            daemon=True,
        )
        heartbeat_thread.start()
        try:
            if claimed_processing.get("phase") == "ANALYSIS_ENQUEUE_PENDING":
                return self._enqueue_prepared(
                    job,
                    attempt=attempt,
                    lease_token=lease_token,
                    lease_lost=lease_lost,
                )
            source = self.repository.open_job_capture(job_id)
            if source is None:
                raise RuntimeError("retained PCAP source is missing")
            with source:
                content = b"".join(source.iter_chunks())
            metadata = job.get("source")
            if not isinstance(metadata, dict):
                raise RuntimeError("retained PCAP metadata is missing")
            digest = hashlib.sha256(content).hexdigest()
            if len(content) != int(metadata.get("size_bytes", -1)) or digest != metadata.get(
                "sha256"
            ):
                raise RuntimeError("retained PCAP source integrity mismatch")
            sensor_id = f"pcap-upload:{digest[:12]}"
            try:
                parsed = parse_pcap(
                    content,
                    sensor_id=sensor_id,
                    internal_networks=list(job["internal_networks"]),
                    max_packets=self.max_packets,
                    retain_packet_bytes=False,
                    retain_network_evidence=job.get("analysis", {}).get("module")
                    in {"network_anomaly", "ddos_attack"},
                )
            except PcapParseError:
                self._fail(
                    job,
                    "PCAP_PARSE_FAILED",
                    "uploaded capture could not be parsed",
                    attempt=attempt,
                    lease_token=lease_token,
                )
                return True
            if lease_lost.is_set():
                return True
            self._apply_parsed_capture(job, parsed, digest=digest, sensor_id=sensor_id)
            self.machine.transition(job, JobState.ANALYZING, "prepared upload awaiting queue")
            occurred_at = datetime.now(UTC).isoformat()
            processing = dict(job["processing"])
            processing.update(
                {
                    "phase": "ANALYSIS_ENQUEUE_PENDING",
                    "phase_started_at": occurred_at,
                    "updated_at": occurred_at,
                }
            )
            job["processing"] = processing
            staged = self.repository.publish_pcap_preparation(
                job,
                attempt=attempt,
                lease_token=lease_token,
            )
            if not staged or lease_lost.is_set():
                return True
            return self._enqueue_prepared(
                job,
                attempt=attempt,
                lease_token=lease_token,
                lease_lost=lease_lost,
            )
        finally:
            stop_heartbeat.set()
            heartbeat_thread.join(timeout=max(1.0, self.lease_renew_seconds * 2))
            if heartbeat_thread.is_alive():
                raise RuntimeError("PCAP preparation heartbeat did not stop")

    def _apply_parsed_capture(
        self, job: dict[str, Any], parsed: Any, *, digest: str, sensor_id: str
    ) -> None:
        from datetime import timedelta

        end_time = parsed.end_time
        if end_time <= parsed.start_time:
            end_time = parsed.start_time + timedelta(microseconds=1)
        validated = AnalysisJobCreate.model_validate(
            {
                "name": job["name"],
                "idempotency_key": job["idempotency_key"],
                "sensor_ids": [sensor_id],
                "mode": "PCAP_UPLOAD",
                "start_time": parsed.start_time,
                "end_time": end_time,
                "capture": {
                    **dict(job["capture"]),
                    "max_packets": parsed.captured_packet_count,
                    "directions": ["INBOUND", "OUTBOUND", "UNKNOWN"],
                    "store_pcap": True,
                },
                "analysis": job["analysis"],
                "internal_networks": job["internal_networks"],
                "flow_records": list(parsed.records),
            }
        ).model_dump(mode="json")
        job.update(
            {
                "dataset_id": f"pcap:{digest}",
                "sensor_ids": validated["sensor_ids"],
                "start_time": validated["start_time"],
                "end_time": validated["end_time"],
                "capture": validated["capture"],
                "flow_records": validated["flow_records"],
                "flow_count": len(validated["flow_records"]),
                "packet_count": sum(
                    int(record.get("packet_count", 1)) for record in validated["flow_records"]
                ),
            }
        )
        metadata = dict(job["source"])
        job["source"] = {
            **metadata,
            "capture_format": parsed.capture_format,
            "captured_packet_count": parsed.captured_packet_count,
            "parsed_packet_count": parsed.parsed_packet_count,
            "skipped_packet_count": parsed.skipped_packet_count,
            "link_types": list(parsed.link_types),
        }
        attach_ddos_coverage_context(job)

    def _enqueue_prepared(
        self,
        job: dict[str, Any],
        *,
        attempt: int,
        lease_token: str,
        lease_lost: threading.Event,
    ) -> bool:
        if lease_lost.is_set():
            return True
        queued = deepcopy(job)
        occurred_at = datetime.now(UTC).isoformat()
        processing = dict(queued["processing"])
        processing.pop("lease_expires_at", None)
        processing.update(
            {
                "phase": "ANALYSIS_QUEUED",
                "phase_started_at": occurred_at,
                "updated_at": occurred_at,
            }
        )
        queued["processing"] = processing
        delivery = deepcopy(queued)
        delivery["message_id"] = f"analysis-job:{queued['id']}"
        delivery["preparation_attempt"] = attempt
        delivery["preparation_lease_token"] = lease_token
        self.enqueue(delivery)
        if lease_lost.is_set():
            return True
        self.repository.complete_pcap_preparation(
            queued,
            attempt=attempt,
            lease_token=lease_token,
        )
        return True

    def _fail(
        self,
        job: dict[str, Any],
        code: str,
        message: str,
        *,
        attempt: int,
        lease_token: str,
    ) -> None:
        job["error_code"] = code
        job["error"] = message
        self.machine.transition(job, JobState.FAILED, message)
        occurred_at = datetime.now(UTC).isoformat()
        job["processing"] = {
            "phase": "FAILED",
            "phase_started_at": occurred_at,
            "updated_at": occurred_at,
        }
        self.repository.fail_pcap_preparation(job, attempt=attempt, lease_token=lease_token)
