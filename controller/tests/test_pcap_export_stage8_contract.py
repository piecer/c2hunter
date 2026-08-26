from __future__ import annotations

import inspect
from copy import deepcopy

import pytest
from pydantic import ValidationError

from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_export_service import (
    PcapExportDependencies,
    PcapExportExecutor,
    choose_execution_mode,
)
from c2hunter_controller.schemas import PcapExportCreate, PcapExportJobResponse


def test_shared_executor_owns_processing_body_outside_request_composition() -> None:
    app_source = inspect.getsource(create_app)
    executor_source = inspect.getsource(PcapExportExecutor.execute)

    assert "def _create_pcap_export" not in app_source
    assert "dependencies.capture_writer" in executor_source
    assert "save_export_stream" in executor_source


def test_indexed_match_factory_is_an_optional_shared_executor_dependency() -> None:
    def sentinel(**_kwargs):
        return None

    dependencies = PcapExportDependencies(indexed_match_factory=sentinel)

    assert dependencies.indexed_match_factory is sentinel
    assert PcapExportDependencies().indexed_match_factory is None
    executor_source = inspect.getsource(PcapExportExecutor.execute)
    assert "indexed_match_factory" in executor_source


def test_hybrid_admission_uses_exact_boundaries_and_unknown_is_async() -> None:
    settings = Settings(environment="test")
    assert choose_execution_mode(settings, source_bytes=33_554_432, packet_count=100_000) == "SYNC"
    assert choose_execution_mode(settings, source_bytes=33_554_433, packet_count=100_000) == "ASYNC"
    assert choose_execution_mode(settings, source_bytes=1, packet_count=100_001) == "ASYNC"
    assert choose_execution_mode(settings, source_bytes=None, packet_count=1) == "ASYNC"
    assert choose_execution_mode(settings, source_bytes=1, packet_count=None) == "ASYNC"
    rollback = Settings(environment="test", pcap_export_execution_mode="sync_only")
    assert choose_execution_mode(rollback, source_bytes=None, packet_count=None) == "SYNC"


def test_export_config_rejects_invalid_lease_and_capacity_relationships() -> None:
    with pytest.raises(ValidationError):
        Settings(
            environment="test", pcap_export_lease_seconds=30, pcap_export_lease_renew_seconds=30
        )
    with pytest.raises(ValidationError):
        Settings(
            environment="test", pcap_export_queue_capacity=1, pcap_export_async_worker_concurrency=2
        )
    with pytest.raises(ValidationError):
        Settings(
            environment="test", pcap_export_lease_seconds=120, pcap_export_job_timeout_seconds=120
        )


def test_active_response_has_no_fabricated_artifact_fields() -> None:
    payload = PcapExportCreate(job_id="j", idempotency_key="abc")
    assert payload.idempotency_key == "abc"
    with pytest.raises(ValidationError):
        PcapExportCreate(job_id="j", idempotency_key="x" * 129)
    response = PcapExportJobResponse.model_validate(
        {
            "id": "e",
            "job_id": "j",
            "source_job_id": "s",
            "candidate_id": None,
            "status": "QUEUED",
            "execution_mode": "ASYNC",
            "progress": {
                "phase": "QUEUED",
                "percent": 0,
                "scanned_source_bytes": 0,
                "scanned_packet_count": 0,
                "matched_packet_count": 0,
                "exported_packet_count": 0,
            },
            "cancellation_requested": False,
            "attempt": 0,
            "max_attempts": 3,
            "source_generation": "a" * 64,
            "queued_at": "2026-01-01T00:00:00Z",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "started_at": None,
            "completed_at": None,
            "next_attempt_at": None,
            "status_url": "/api/v1/pcap-exports/e",
            "download_url": None,
            "error_code": None,
            "error": None,
        }
    )
    dumped = response.model_dump(exclude_none=True)
    assert "sha256" not in dumped and "size_bytes" not in dumped and "filename" not in dumped


def _completed_job_payload() -> dict[str, object]:
    return {
        "id": "e",
        "job_id": "j",
        "candidate_id": None,
        "status": "COMPLETED",
        "execution_mode": "ASYNC",
        "progress": {
            "phase": "TERMINAL",
            "percent": 100,
            "scanned_source_bytes": 10,
            "scanned_packet_count": 1,
            "matched_packet_count": 1,
            "exported_packet_count": 1,
        },
        "cancellation_requested": False,
        "attempt": 1,
        "max_attempts": 3,
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:00Z",
        "status_url": "/api/v1/pcap-exports/e",
        "download_url": "/api/v1/pcap-exports/e/download",
        "matched_packet_count": 1,
        "exported_packet_count": 1,
        "omitted_packet_count": 0,
        "truncated": False,
        "truncation_reasons": [],
        "size_bytes": 10,
        "sha256": "a" * 64,
        "capture_format": "PCAP",
        "filename": "e.pcap",
        "filter": {},
        "source_capture_count": 1,
        "scanned_source_capture_count": 1,
        "omitted_source_capture_count": 0,
        "source_total_bytes": 10,
        "scanned_source_bytes": 10,
        "scanned_packet_count": 1,
        "output_byte_limit": 100,
        "source_scan_byte_limit": 100,
        "source_scan_packet_limit": 10,
        "source_manifest": [{"id": "source", "sha256": "b" * 64}],
    }


_COMPLETED_FIELDS = [
    "download_url",
    "matched_packet_count",
    "exported_packet_count",
    "omitted_packet_count",
    "truncated",
    "truncation_reasons",
    "size_bytes",
    "sha256",
    "capture_format",
    "filename",
    "filter",
    "source_capture_count",
    "scanned_source_capture_count",
    "omitted_source_capture_count",
    "source_total_bytes",
    "scanned_source_bytes",
    "scanned_packet_count",
    "output_byte_limit",
    "source_scan_byte_limit",
    "source_scan_packet_limit",
    "source_manifest",
]


@pytest.mark.parametrize("missing", _COMPLETED_FIELDS)
def test_completed_response_rejects_each_missing_terminal_field(missing: str) -> None:
    payload = deepcopy(_completed_job_payload())
    payload.pop(missing)
    with pytest.raises(ValidationError, match="completed exports require"):
        PcapExportJobResponse.model_validate(payload)


def test_completed_response_openapi_declares_conditional_terminal_requirements() -> None:
    schema = PcapExportJobResponse.model_json_schema()
    completed_rule = schema["allOf"][0]
    assert completed_rule["if"]["properties"]["status"]["const"] == "COMPLETED"
    assert set(completed_rule["then"]["required"]) == set(_COMPLETED_FIELDS)
