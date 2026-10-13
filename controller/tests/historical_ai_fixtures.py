"""Deterministic no-I/O source fixtures, not real LIVE history or approval."""

from datetime import UTC, datetime, timedelta
from typing import Any

from c2hunter_controller import historical_baseline as h

START = datetime(2026, 1, 1, tzinfo=UTC)
PEER = "203.0.113.9"


def uid(index: int) -> str:
    return f"00000000-0000-0000-0000-{index:012x}"


def config(kind: str = "OPERATIONAL") -> h.ScopeConfig:
    return h.ScopeConfig.from_mapping(
        {
            "scope_id": uid(1000),
            "name": "synthetic fixture",
            "kind": kind,
            "sensor_key": "logical",
            "stored_sensor_id": "sensor" if kind == "OPERATIONAL" else None,
            "internal_networks": ["10.0.0.0/24"],
            "window_seconds": 60,
            "hosts": [{"ip": "10.0.0.1", "epoch": "one"}],
            "identity_assertion": "STABLE_SINGLE_HOST_NO_SHARED_NAT",
            "reason": "Synthetic source identity assertion",
        }
    )


def review(kind: str = "OPERATIONAL") -> h.QualityReview:
    return h.QualityReview(
        representative_window_asserted=True,
        stable_host_attribution_asserted=True,
        clock_offset_bound_ms=100,
        sensor_alias_asserted=kind == "EVALUATION",
        note="Synthetic target review, not measured completeness",
    )


def job(index: int = 3, *, changed: bool = True) -> dict[str, Any]:
    start = START + timedelta(hours=12 * index)
    offsets = (0, 1, 3, 6, 10, 15, 21, 28) if changed else tuple(range(8))
    sizes = (10, 10, 10, 10, 190, 190, 190, 190) if changed else (100,) * 8
    rows = [
        {
            "sensor_id": "sensor",
            "timestamp": (start + timedelta(seconds=offset)).isoformat(),
            "source_ip": "10.0.0.1",
            "destination_ip": PEER,
            "source_port": 40000,
            "destination_port": 443,
            "protocol": "TCP",
            "direction": "OUTBOUND",
            "packet_count": 1,
            "total_bytes": size + index,
            "duration_seconds": 0,
        }
        for offset, size in zip(offsets, sizes, strict=True)
    ]
    rows.append(
        {
            **rows[0],
            "timestamp": (start + timedelta(seconds=40)).isoformat(),
            "source_ip": PEER,
            "destination_ip": "10.0.0.1",
            "source_port": 443,
            "destination_port": 40000,
            "direction": "INBOUND",
            "total_bytes": 100 if changed else 8 * (100 + index),
        }
    )
    return {
        "id": f"root-{index}",
        "dataset_id": f"dataset-{index}",
        "parent_job_id": None,
        "source_type": "SENSOR_CAPTURE",
        "mode": "LIVE",
        "status": "COMPLETED",
        "start_time": start.isoformat(),
        "end_time": (start + timedelta(seconds=60)).isoformat(),
        "sensor_ids": ["sensor"],
        "internal_networks": ["10.0.0.0/24"],
        "analysis": {"module": "c2"},
        "allowlist": [],
        "flow_records": rows,
    }


def world(
    *,
    kind: str = "OPERATIONAL",
    target: dict[str, Any] | None = None,
    candidates: list[dict[str, Any]] | None = None,
    reviewed: bool = True,
    sources: int = 3,
    reference_jobs: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    from c2hunter_controller import historical_generation as g
    from c2hunter_controller.historical_read import HistoricalReadSnapshot
    from c2hunter_controller.historical_source import project_source

    cfg, quality = config(kind), review(kind)
    scope = g.ScopeView(
        config=cfg,
        config_sha256=h.scope_config_sha256(cfg),
        control_revision=0,
        frozen=False,
        state="EMPTY",
        accepted_event_end=None,
        active=None,
        previous=None,
        created_by="fixture-admin",
        created_at=START,
    )
    generation = None
    for index in range(sources):
        source = project_source(
            reference_jobs[index] if reference_jobs is not None else job(index, changed=False),
            ancestors=(),
            scope=cfg,
            quality_review=quality,
        )
        binding = h.source_binding_sha256(source.source_binding(), purpose="APPROVAL")
        generation = g.produce_generation(
            snapshot=HistoricalReadSnapshot(
                source=source, candidates=(), source_binding_sha256=binding
            ),
            scope=scope,
            current_generation=generation,
            accepted_event_end=scope.accepted_event_end,
            request=g.ApprovalRequest(
                expected_revision=scope.control_revision,
                idempotency_key=f"source-{index}",
                source_job_id=source.original.id,
                source_binding_sha256=binding,
                normality="APPROVED_NORMAL",
                quality_review=quality,
                reason="Independent synthetic normal fixture",
            ),
            operation_id=uid(index + 1),
            generation_id=uid(index + 100),
            actor="fixture-admin",
            now=START + timedelta(days=4, seconds=index),
        )
        scope = g.ScopeView.from_mapping(
            {
                **scope.to_mapping(),
                "control_revision": generation.publication_revision,
                "state": "HAS_REFERENCE",
                "previous": scope.active.to_mapping() if scope.active else None,
                "active": g.generation_view(generation).to_mapping(),
                "accepted_event_end": generation.sources[-1].event_end,
            }
        )
    original = target if target is not None else job()
    projected = project_source(
        original, ancestors=(), scope=cfg, quality_review=quality if reviewed else None
    )
    rows = tuple(h.project_candidate(row, position=i) for i, row in enumerate(candidates or []))
    binding = h.source_binding_sha256(
        projected.source_binding(), purpose="COMPARISON", candidates=rows
    )
    payload = {
        "idempotency_key": "request-1",
        "candidate_limit": 5,
        "analysis_kind": "C2",
        "language": "ko",
        "allow_remote": False,
        "discovery_mode": "shadow",
        "baseline_mode": "historical",
        "baseline_reference": {
            "scope_id": cfg.scope_id,
            "expected_revision": scope.control_revision,
            "generation_id": generation.generation_id if generation else None,
            "target_source_binding_sha256": binding,
            "quality_review": quality.to_mapping() if reviewed else None,
        },
    }
    request = {
        "analysis_job_id": original["id"],
        "payload": payload,
        "actor": "fixture-analyst",
        "run_id": uid(2000),
        "admitted_at": "2026-01-06T00:00:00.000000Z",
        "provider": "fake",
        "model_name": "fixture-only",
        "prompt_name": "c2",
        "prompt_version": "1",
        "prompt_hash": "a" * 64,
        "input_schema_version": "1.0",
        "output_schema_version": "1.0",
    }
    import hashlib

    request["request_fingerprint"] = hashlib.sha256(
        h.canonical_json(
            {
                "analysis_job_id": request["analysis_job_id"],
                "actor": request["actor"],
                "payload": payload,
            }
        ).encode()
    ).hexdigest()
    return dict(
        request=request,
        target=projected,
        candidates=rows,
        scope=scope,
        generation=generation,
        target_source_binding_sha256=binding,
    )


def decode_with_matching_commitment(saved: str, *, request: Any) -> Any:
    """Semantic mutation tests intentionally bypass only the independent hash gate."""
    import hashlib

    from c2hunter_controller.historical_ai import decode_historical_snapshot

    return decode_historical_snapshot(
        saved, request=request, expected_snapshot_sha256=hashlib.sha256(saved.encode()).hexdigest()
    )


def rule(peer: str = PEER, identifier: str = "rule", score: int = 80) -> dict[str, Any]:
    return {
        "id": identifier,
        "candidate_ip": peer,
        "candidate_kind": "C2",
        "score": score,
        "evidence": [
            {
                "type": "RULE",
                "description": "Rule fixture",
                "contribution": 10,
                "metrics": {"ordered": {"z": [], "a": {}}, "value": 2},
            }
        ],
    }
