"""Independent fixture oracle: no product parser/serializer/feature oracle calls."""

import hashlib
import json
import socket
from datetime import UTC, datetime, timedelta
from statistics import median
from typing import Any
from uuid import UUID

import pytest

from c2hunter_controller import historical_generation as g
from c2hunter_controller.repositories import MemoryRepository, SQLiteRepository
from tests.test_historical_source import START, config, review, stored

DUMPS = json.dumps


def canonical(value: Any) -> str:
    return DUMPS(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def original(value: Any) -> dict:
    if isinstance(value, dict):
        return {"kind": "object", "entries": [[k, original(v)] for k, v in value.items()]}
    if isinstance(value, list):
        return {"kind": "array", "items": [original(v) for v in value]}
    return {"kind": "scalar", "value": value}


def stamp(value: str | datetime) -> str:
    date = datetime.fromisoformat(value) if isinstance(value, str) else value
    return date.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def binding_fixture(raw: dict) -> dict:
    """Closed expected projection for the explicitly absent-quality root fixture."""
    absent = {"present": False}
    begin, end = stamp(raw["start_time"]), stamp(raw["end_time"])
    fields = (
        "id",
        "dataset_id",
        "parent_job_id",
        "source_type",
        "mode",
        "status",
        "start_time",
        "end_time",
    )
    facts = {
        key: absent
        for key in (
            "capture_incomplete",
            "error_code",
            "skipped_packet_count",
            "dropped_packet_count",
            "clock_skew_detected",
            "discarded_packets",
            "requested_end_time",
            "capture_stopped_at",
            "capture_completions",
            "failed_sensors",
        )
    }
    facts["sensor_offsets"] = []
    node = dict(
        {key: raw[key] for key in fields},
        start_time=begin,
        end_time=end,
        source=absent,
        quality=facts,
        inherited_quality=absent,
    )
    job = {key: raw[key] for key in (*fields, "sensor_ids", "internal_networks")}
    job.update(
        analysis=original(raw["analysis"]),
        allowlist={"present": True, "value": []},
        operations=absent,
        flow_records=[
            {"fields": original(row), "sensitive_keys_present": []} for row in raw["flow_records"]
        ],
    )
    quality = dict(
        schema_version="source-observation-quality-v1",
        original_start=begin,
        original_end=end,
        effective_start=begin,
        effective_end=end,
        restart_incomplete=False,
        stop_reasons=[],
        failed_sensors=[],
        sensor_offset_bounds=[],
        known_partial=False,
        clock_uncertain=False,
        producer_completeness="UNKNOWN",
    )
    quality.update(
        {
            key: absent
            for key in (
                "original_requested_end",
                "requested_end",
                "capture_stopped_at",
                "capture_incomplete",
                "skipped_packet_count",
                "dropped_packet_count",
                "discarded_packets",
                "clock_skew_detected",
            )
        }
    )
    return dict(
        original=job,
        lineage=[node],
        root_job_id=raw["id"],
        root_identity=canonical([raw["id"], raw["dataset_id"]]),
        root_content_sha256=None,
        origin="SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        actual_sensor_id="sensor",
        event_start=begin,
        event_end=end,
        internal_networks=raw["internal_networks"],
        quality=quality,
    )


def expected_document(
    raw: dict, scope: dict, request: dict, op: str, gen: str
) -> tuple[dict, dict]:
    binding = digest({"purpose": "APPROVAL", "source": binding_fixture(raw)})
    identity = {
        key: scope[key]
        for key in (
            "kind",
            "sensor_key",
            "stored_sensor_id",
            "internal_networks",
            "window_seconds",
            "hosts",
        )
    }
    identity["feature_version"] = "behavior-window-v1"
    scope_hash = digest(identity)
    fields = [
        "logical_sensor",
        "timestamp_us",
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "direction",
        "packet_count",
        "total_bytes",
        "duration_us",
        "tcp_syn_only_observations",
        "tcp_syn_only_observations_truncated",
        "tcp_flags_observed",
        "tcp_syn_count",
        "tcp_ack_count",
        "tcp_rst_count",
        "tcp_syn_only_count",
        "tcp_syn_ack_count",
        "tcp_ack_only_count",
        "tcp_flags",
        "bidirectional",
        "payload_observed",
    ]

    def micros(value: str) -> int:
        return (datetime.fromisoformat(value) - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(
            microseconds=1
        )

    observations = [
        [
            scope["sensor_key"],
            micros(row["timestamp"]),
            row["source_ip"],
            row["destination_ip"],
            row["source_port"],
            row["destination_port"],
            "TCP",
            "OUTBOUND",
            1,
            row["total_bytes"],
            0,
            None,
            False,
            False,
            0,
            0,
            0,
            0,
            0,
            0,
            [],
            False,
            False,
        ]
        for row in raw["flow_records"]
    ]
    observation = dict(
        schema_version="source-observation-v1",
        fields=fields,
        observations=sorted(observations, key=lambda row: canonical(row).encode()),
        event_start_us=micros(raw["start_time"]),
        event_end_us=micros(raw["end_time"]),
        internal_networks=raw["internal_networks"],
        trusted_peers=[],
    )
    feature_hash = digest(observation)
    observation["root_identity"] = canonical([raw["id"], raw["dataset_id"]])
    source = dict(
        source_receipt_id=op,
        source_job_id=raw["id"],
        root_job_id=raw["id"],
        dataset_id=raw["dataset_id"],
        root_identity=observation["root_identity"],
        ancestry_job_ids=[raw["id"]],
        root_content_sha256=None,
        source_binding_sha256=binding,
        observation_sha256=digest(observation),
        feature_observation_sha256=feature_hash,
        actual_sensor_id="sensor",
        sensor_key=scope["sensor_key"],
        event_start=stamp(raw["start_time"]),
        event_end=stamp(raw["end_time"]),
        origin="SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        normality="APPROVED_NORMAL",
        approved_by="reviewer",
        approved_at=stamp(START),
        reason=request["reason"],
        quality_review=request["quality_review"],
        producer_completeness="UNKNOWN",
        known_partial=False,
        limitations=[
            "ADMIN_ASSERTED_IDENTITY",
            "HUMAN_ASSERTED_CLOCK_BOUND",
            "PRODUCER_COMPLETENESS_UNKNOWN",
        ],
    )
    windows = []
    for host in scope["hosts"]:
        for port in (443, 8443):
            values = [
                float(row["total_bytes"])
                for row in raw["flow_records"]
                if row["source_ip"] == host["ip"] and row["destination_port"] == port
            ]
            center = median(values)
            windows.append(
                dict(
                    key=dict(
                        scope_config_sha256=scope_hash,
                        sensor_key=scope["sensor_key"],
                        internal_host_ip=host["ip"],
                        host_epoch=host["epoch"],
                        peer_ip="203.0.113.9",
                        protocol="TCP",
                        service_port=port,
                        observation_kind="PACKET",
                        feature_version="behavior-window-v1",
                    ),
                    source_receipt_id=op,
                    event_start=stamp(raw["start_time"]),
                    event_end=stamp(raw["end_time"]),
                    outbound_record_count=8,
                    recurrence=0.0,
                    size_dispersion=median(abs(v - center) for v in values) / center,
                    outbound_share=1.0,
                    limitations=[],
                )
            )
    doc = dict(
        schema_version="historical-baseline-v1",
        generation_id=gen,
        scope_id=scope["scope_id"],
        scope_config_sha256=scope_hash,
        feature_version="behavior-window-v1",
        publication_revision=1,
        published_at=stamp(START),
        published_by="reviewer",
        sources=[source],
        windows=windows,
    )
    receipt = dict(
        operation_id=op,
        action="APPROVE",
        revision=1,
        actor="reviewer",
        occurred_at=stamp(START),
        generation_id=gen,
        source_job_id=raw["id"],
        source_binding_sha256=binding,
    )
    return doc, receipt


@pytest.fixture(params=["memory", "sqlite"])
def repo(request: Any, tmp_path: Any) -> Any:
    result = (
        MemoryRepository()
        if request.param == "memory"
        else SQLiteRepository(tmp_path / "oracle.sqlite")
    )
    request.addfinalizer(result.close)
    return result


class SixMethods:
    """Consumer capability surface, without raw document or generic persistence."""

    def __init__(self, repo: Any) -> None:
        for name in (
            "create_baseline_scope",
            "get_baseline_scope",
            "page_baseline_scopes",
            "preview_baseline_source",
            "publish_baseline_source",
            "page_baseline_sources",
        ):
            setattr(self, name, getattr(repo, name))


def test_six_method_consumer_full_independent_oracle(repo: Any, monkeypatch: Any) -> None:
    raw = stored()
    repo.save_job(raw)
    client = SixMethods(repo)
    source = binding_fixture(raw)
    expected_binding = digest({"purpose": "APPROVAL", "source": source})
    forbidden_calls = []

    def forbidden(*args: Any, **kw: Any) -> Any:
        forbidden_calls.append(True)
        raise AssertionError("generic helper escaped six-method consumer")

    for name in (
        "get_job",
        "list_jobs",
        "save_job",
        "save_candidates",
        "get_candidates",
        "list_candidates",
        "_get",
        "_put",
        "_audit",
        "enqueue_job",
    ):
        if hasattr(repo, name):
            monkeypatch.setattr(repo, name, forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    view, created = client.create_baseline_scope(config(), "admin", START)
    assert created and view.control_revision == 0
    preview = client.preview_baseline_source(config().scope_id, raw["id"], 0, "APPROVAL")
    assert preview.source_binding_sha256 == expected_binding
    assert preview.required_review == "EXPLICIT_NORMAL_AND_QUALITY_ASSERTION"
    request = g.ApprovalRequest(
        expected_revision=0,
        idempotency_key="oracle",
        source_job_id=raw["id"],
        source_binding_sha256=expected_binding,
        normality="APPROVED_NORMAL",
        quality_review=review(),
        reason="Explicit oracle review",
    )
    ids = [
        UUID("00000000-0000-4000-8000-000000000001"),
        UUID("00000000-0000-4000-8000-000000000002"),
    ]
    allocated = []

    def allocate() -> UUID:
        allocated.append(ids[len(allocated)])
        return allocated[-1]

    doc, receipt = expected_document(
        raw, config().to_mapping(), request.to_mapping(), *map(str, ids)
    )
    monkeypatch.setattr("uuid.uuid4", allocate)
    result = client.publish_baseline_source(config().scope_id, request, "reviewer", START)
    assert result.created and result.receipt.to_mapping() == receipt
    assert client.get_baseline_scope(config().scope_id) == result.scope
    assert client.page_baseline_scopes().items == (result.scope,)
    assert (
        client.page_baseline_sources(config().scope_id, str(ids[1])).items[0].to_mapping()
        == doc["sources"][0]
    )
    repeated = client.publish_baseline_source(
        config().scope_id, request, "reviewer", START + timedelta(days=1)
    )
    assert not repeated.created and repeated.receipt == result.receipt and len(allocated) == 2
    if isinstance(repo, MemoryRepository):
        envelope = repo._baseline_generations[(config().scope_id, str(ids[1]))]
        operation = repo._baseline_operations[(config().scope_id, "oracle")]
    else:
        envelope = repo.connection.execute(
            "SELECT publication_revision,document_json,content_sha256,byte_size "
            "FROM baseline_generations"
        ).fetchone()
        operation = repo.connection.execute("SELECT * FROM baseline_operations").fetchone()
    expected_text = canonical(doc)
    assert envelope == (
        1,
        expected_text,
        hashlib.sha256(expected_text.encode()).hexdigest(),
        len(expected_text.encode()),
    )
    assert operation[3] == digest(
        dict(
            action="APPROVE",
            scope_id=config().scope_id,
            actor="reviewer",
            request=request.to_mapping(),
        )
    )
    assert operation[5:] == (canonical(receipt), digest(receipt), len(canonical(receipt).encode()))
    assert forbidden_calls == []
