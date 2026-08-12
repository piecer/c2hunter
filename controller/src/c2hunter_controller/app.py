from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
import threading
import uuid
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, wait
from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Annotated, Any, Literal, cast

from c2hunter_analysis.domain import AllowlistEntry
from c2hunter_analysis.pcap import PcapParseError, find_pcap_record, parse_pcap
from fastapi import FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from .ai_analysis import (
    AIAnalysisError,
    AIAnalysisService,
    CandidateAssessment,
    CandidateEvidenceBundle,
    ModelGateway,
)
from .ai_artifacts import AIArtifactError, AIArtifactService, build_ai_artifacts
from .ai_feedback import AIFeedbackError, AIFeedbackService
from .ai_gateway import create_model_gateway
from .ai_queueing import (
    AIAnalysisTaskQueue,
    InlineAIAnalysisTaskQueue,
    RedisAIAnalysisTaskQueue,
)
from .capture_limits import allocate_sensor_limit, limit_flow_records
from .config import Settings
from .detection_guidance import build_detection_guidance
from .flow_review import (
    filter_flows,
    flow_id,
    label_snapshot,
    payload_ascii,
)
from .integrations import (
    IntegrationError,
    JsonHttpClient,
    MispClient,
    MispPublisher,
    ThreatIntelLookup,
    ThreatIntelService,
)
from .jobs import JobState, StateMachine, build_job, calculate, summarize_candidate_traffic
from .pcap import build_pcap, filter_records
from .production import MinioBlobStore, PostgresRepository
from .queueing import ControllerQueue, MemoryControllerQueue, RedisControllerQueue
from .repositories import MemoryRepository, Repository
from .schemas import (
    AIAnalysisRunCancel,
    AIAnalysisRunCreate,
    AIArtifactReview,
    AIFeedbackCreate,
    AllowlistCreate,
    AnalysisJobCreate,
    AnalysisJobUpdate,
    AnalysisParameters,
    CancelRequest,
    CandidateActionCreate,
    CandidateUpdate,
    CandidateVerdictCreate,
    CaptureParameters,
    DetectorWeightPresetCreate,
    DetectorWeightPresetUpdate,
    DevLoginRequest,
    EnrollmentClaim,
    EnrollmentClaimResponse,
    EnrollmentCreate,
    EnrollmentCreateResponse,
    FlowBatchCreate,
    FlowLabelCreate,
    Heartbeat,
    MispExportCreate,
    PayloadSignatureUpdate,
    PcapExportCreate,
    ReanalysisRequest,
    SensorConfigurationResponse,
    SensorConfigurationUpdate,
    SensorGroupCreate,
    SensorRegistration,
)
from .security import (
    FixedWindowRateLimiter,
    Role,
    SecurityError,
    SessionStore,
    TokenAuthenticator,
    is_enrollment_claim,
    require_role,
    required_role,
)
from .storage import ClickHouseFlowStore, FlowStore, MemoryFlowStore

logger = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, details: Any = None) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.details = details


def _request_id(request: Request) -> str:
    return str(getattr(request.state, "request_id", ""))


def _error(
    request: Request, status: int, code: str, message: str, details: Any = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status,
        content={
            "error": {
                "code": code,
                "message": message,
                "details": details,
                "request_id": _request_id(request),
            }
        },
    )


def _page(items: list[dict[str, Any]], page: int, page_size: int) -> dict[str, Any]:
    start = (page - 1) * page_size
    return {
        "items": items[start : start + page_size],
        "page": page,
        "page_size": page_size,
        "total": len(items),
    }


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    """Never return retained packets or detector snapshots in control-plane responses."""
    return {
        key: value
        for key, value in job.items()
        if key not in {"flow_records", "payload_signatures"}
    }


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list | tuple | set):
        return []
    return sorted({str(item) for item in value if item is not None and str(item)})


def _public_candidate(
    candidate: dict[str, Any], job: dict[str, Any], *, include_traffic: bool = False
) -> dict[str, Any]:
    """Expose a stable candidate contract plus bounded traffic-derived context."""
    hosts = _string_list(candidate.get("hosts") or candidate.get("internal_hosts"))
    sensors = _string_list(candidate.get("sensors") or candidate.get("sensor_ids"))
    raw_evidence = candidate.get("evidence")
    evidence: list[dict[str, Any]] = (
        [item for item in raw_evidence if isinstance(item, dict)]
        if isinstance(raw_evidence, list | tuple)
        else []
    )
    raw_adjustments = candidate.get("adjustments")
    adjustments: list[dict[str, Any]] = (
        [item for item in raw_adjustments if isinstance(item, dict)]
        if isinstance(raw_adjustments, list | tuple)
        else []
    )
    traffic: dict[str, Any] = {
        "protocols": candidate.get("protocols") or [],
        "ports": candidate.get("ports") or [],
        "domains": candidate.get("domains") or [],
        "flow_count": int(candidate.get("flow_count", 0) or 0),
        "packet_count": int(candidate.get("packet_count", 0) or 0),
        "byte_count": int(candidate.get("byte_count", 0) or 0),
        "traffic_buckets": candidate.get("traffic_buckets") or [],
        "traffic_series": candidate.get("traffic_series") or [],
    }
    if include_traffic and not traffic["traffic_buckets"]:
        raw_records = job.get("flow_records")
        records: list[dict[str, Any]] = (
            [item for item in raw_records if isinstance(item, dict)]
            if isinstance(raw_records, list)
            else []
        )
        traffic.update(
            summarize_candidate_traffic(records, {str(candidate.get("candidate_ip", ""))}).get(
                str(candidate.get("candidate_ip", "")), {}
            )
        )
    related_targets = (
        set(_string_list(candidate.get("related_attack_targets")))
        | set(_string_list(traffic.get("related_attack_targets")))
        | {
            str(metrics["attack_target"])
            for item in evidence
            if isinstance(item, dict)
            and isinstance((metrics := item.get("metrics")), dict)
            and metrics.get("attack_target")
        }
    )
    return {
        **candidate,
        "job_id": job["id"],
        "hosts": hosts,
        "internal_hosts": hosts,
        "distinct_internal_hosts": len(hosts),
        "sensors": sensors,
        "sensor_ids": sensors,
        "evidence": evidence,
        "evidence_count": len(evidence),
        "adjustments": adjustments,
        **traffic,
        "related_attack_targets": sorted(related_targets),
        "workflow_status": _candidate_workflow_status(candidate),
        "action_status": _candidate_action_status(candidate),
    }


def _find_candidate(
    repo: Repository, candidate_id: str
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    workflow = _candidate_workflow_index(repo, candidate_id)
    jobs = {str(job["id"]): job for job in repo.list_jobs()}
    for job_id, candidates in repo.list_candidate_sets().items():
        candidate = next((item for item in candidates if item.get("id") == candidate_id), None)
        if candidate is not None and job_id in jobs:
            return jobs[job_id], _with_candidate_workflow(candidate, workflow)
    return None


_VALID_CANDIDATE_VERDICTS = {"CONFIRMED_C2", "FALSE_POSITIVE", "UNDER_REVIEW"}
_VALID_CANDIDATE_CONFIDENCES = {"CONFIRMED", "HIGH", "MEDIUM", "LOW"}


def _valid_candidate_decision(decision: object) -> bool:
    if not isinstance(decision, dict):
        return False
    required_string_fields = (
        "id",
        "candidate_id",
        "verdict",
        "confidence",
        "note",
        "created_by",
        "created_at",
    )
    if not all(
        isinstance(decision.get(field), str) and bool(decision.get(field))
        for field in required_string_fields
    ):
        return False
    try:
        created_at = datetime.fromisoformat(decision["created_at"])
    except ValueError:
        return False
    return (
        decision["verdict"] in _VALID_CANDIDATE_VERDICTS
        and decision["confidence"] in _VALID_CANDIDATE_CONFIDENCES
        and created_at.utcoffset() is not None
    )


def _candidate_workflow_index(
    repo: Repository, candidate_id: str | None = None
) -> dict[str, dict[str, Any]]:
    workflow: dict[str, dict[str, Any]] = {}
    decisions: list[dict[str, Any]] = []
    for decision in repo.list_candidate_decisions(candidate_id):
        if not _valid_candidate_decision(decision):
            logger.warning(
                "Ignoring malformed candidate decision id=%r candidate_id=%r",
                decision.get("id") if isinstance(decision, dict) else None,
                decision.get("candidate_id") if isinstance(decision, dict) else None,
            )
            continue
        decisions.append(decision)
    decisions.sort(key=lambda item: item["created_at"])
    for decision in decisions:
        entry = workflow.setdefault(str(decision["candidate_id"]), {})
        entry.setdefault("verdict_history", []).append(decision)
        entry["current_verdict"] = decision
    candidate_actions = sorted(
        repo.list_candidate_actions(candidate_id), key=lambda item: str(item["created_at"])
    )
    for action in candidate_actions:
        entry = workflow.setdefault(str(action["candidate_id"]), {})
        entry.setdefault("action_history", []).append(action)
        current_verdict = entry.get("current_verdict")
        if isinstance(current_verdict, dict) and action.get("verdict_id") == current_verdict.get(
            "id"
        ):
            entry["current_action"] = action
    lookups = sorted(
        repo.list_candidate_ti_lookups(candidate_id), key=lambda item: str(item["fetched_at"])
    )
    for lookup in lookups:
        workflow.setdefault(str(lookup["candidate_id"]), {})["threat_intelligence"] = lookup
    actions = sorted(
        repo.list_candidate_misp_actions(candidate_id), key=lambda item: str(item["created_at"])
    )
    for action in actions:
        entry = workflow.setdefault(str(action["candidate_id"]), {})
        entry.setdefault("misp_exports", []).append(action)
    return workflow


def _with_candidate_workflow(
    candidate: dict[str, Any], workflow: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    return {**candidate, **workflow.get(str(candidate["id"]), {})}


def _candidate_verdict(candidate: dict[str, Any]) -> str:
    current = candidate.get("current_verdict")
    return str(current.get("verdict")) if isinstance(current, dict) else "UNREVIEWED"


def _candidate_workflow_status(candidate: dict[str, Any]) -> str:
    verdict = _candidate_verdict(candidate)
    if verdict == "CONFIRMED_C2":
        return {
            "IN_PROGRESS": "ACTION_IN_PROGRESS",
            "COMPLETED": "ACTION_COMPLETED",
        }.get(_candidate_action_status(candidate), "ACTION_REQUIRED")
    return {
        "UNREVIEWED": "NEEDS_REVIEW",
        "UNDER_REVIEW": "IN_REVIEW",
        "FALSE_POSITIVE": "FALSE_POSITIVE",
    }[verdict]


def _candidate_action_status(candidate: dict[str, Any]) -> str:
    current = candidate.get("current_action")
    if isinstance(current, dict):
        return str(current.get("status") or "PENDING")
    return "PENDING" if _candidate_verdict(candidate) == "CONFIRMED_C2" else "NOT_REQUIRED"


def _candidate_workflow_counts(candidates: list[dict[str, Any]]) -> dict[str, int]:
    statuses = [_candidate_workflow_status(candidate) for candidate in candidates]
    return {
        "needs_review": statuses.count("NEEDS_REVIEW"),
        "in_review": statuses.count("IN_REVIEW"),
        "action_required": statuses.count("ACTION_REQUIRED"),
        "action_in_progress": statuses.count("ACTION_IN_PROGRESS"),
        "action_completed": statuses.count("ACTION_COMPLETED"),
        "false_positive": statuses.count("FALSE_POSITIVE"),
        "done": statuses.count("ACTION_COMPLETED") + statuses.count("FALSE_POSITIVE"),
    }


def _request_actor(request: Request) -> str:
    principal = getattr(request.state, "principal", None)
    return str(getattr(principal, "subject", "system"))


def _utc_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _dashboard_snapshot(
    repo: Repository,
    now: datetime | None = None,
    heartbeat_timeout_seconds: int = 30,
) -> dict[str, Any]:
    generated_at = (now or datetime.now(UTC)).astimezone(UTC)
    window_start = generated_at - timedelta(hours=24)
    sensors = repo.list_sensors()
    jobs = repo.list_jobs()
    jobs_by_id = {str(job["id"]): job for job in jobs}
    workflow = _candidate_workflow_index(repo)
    candidates = [
        _public_candidate(_with_candidate_workflow(candidate, workflow), job)
        for job_id, candidate_set in repo.list_candidate_sets().items()
        if (job := jobs_by_id.get(job_id)) is not None
        for candidate in candidate_set
        if not candidate.get("excluded", False)
    ]

    active_statuses = {
        "WAITING_FOR_SENSOR",
        "CAPTURING",
        "UPLOADING",
        "INGESTING",
        "ANALYZING",
    }
    sensor_status_by_id: dict[str, str] = {}
    for sensor in sensors:
        status = str(sensor.get("derived_status") or sensor.get("status") or "UNKNOWN").upper()
        last_heartbeat = _utc_datetime(sensor.get("last_heartbeat_at"))
        if last_heartbeat is not None and generated_at - last_heartbeat > timedelta(
            seconds=heartbeat_timeout_seconds
        ):
            status = "OFFLINE"
        sensor_status_by_id[str(sensor["sensor_id"])] = status
    sensor_statuses = list(sensor_status_by_id.values())

    sensor_quality = []
    for sensor in sensors:
        received_packets = int(sensor.get("received_packets", 0) or 0)
        dropped_packets = int(sensor.get("dropped_packets", 0) or 0)
        reported_packets = received_packets + dropped_packets
        sensor_quality.append(
            {
                "sensor_id": sensor["sensor_id"],
                "name": sensor.get("name") or sensor["sensor_id"],
                "status": sensor_status_by_id[str(sensor["sensor_id"])],
                "received_packets": received_packets,
                "dropped_packets": dropped_packets,
                "drop_rate_percent": round(
                    dropped_packets / reported_packets * 100 if reported_packets else 0.0,
                    2,
                ),
                "last_heartbeat_at": sensor.get("last_heartbeat_at"),
                "last_error": sensor.get("last_error"),
            }
        )
    sensor_quality.sort(
        key=lambda sensor: (
            {"OFFLINE": 0, "DEGRADED": 1}.get(str(sensor["status"]), 2),
            -float(sensor["drop_rate_percent"]),
            str(sensor["name"]),
        )
    )
    severity_counts = {
        severity: sum(
            str(candidate.get("severity", "LOW")).upper() == severity for candidate in candidates
        )
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    }

    hour_start = generated_at.replace(minute=0, second=0, microsecond=0)
    trend_hours = [hour_start - timedelta(hours=offset) for offset in range(23, -1, -1)]
    trend_counts = {hour: 0 for hour in trend_hours}
    for candidate in candidates:
        first_seen = _utc_datetime(candidate.get("first_seen"))
        if first_seen is None or first_seen < trend_hours[0] or first_seen > generated_at:
            continue
        bucket = first_seen.replace(minute=0, second=0, microsecond=0)
        if bucket in trend_counts:
            trend_counts[bucket] += 1

    workflow_counts = _candidate_workflow_counts(candidates)
    priority_candidates = sorted(
        (
            candidate
            for candidate in candidates
            if _candidate_workflow_status(candidate)
            in {"NEEDS_REVIEW", "IN_REVIEW", "ACTION_REQUIRED", "ACTION_IN_PROGRESS"}
        ),
        key=lambda candidate: str(candidate.get("last_seen", "")),
        reverse=True,
    )[:5]
    recent_analyses = sorted(
        jobs,
        key=lambda job: str(job.get("created_at", "")),
        reverse=True,
    )[:5]

    sensor_attention: list[dict[str, Any]] = []
    analysis_attention: list[dict[str, Any]] = []
    candidate_attention: list[dict[str, Any]] = []
    for sensor in sensors:
        status = sensor_status_by_id[str(sensor["sensor_id"])]
        if status not in {"OFFLINE", "DEGRADED"}:
            continue
        status_label = "오프라인" if status == "OFFLINE" else "성능 저하"
        sensor_attention.append(
            {
                "kind": f"{status}_SENSOR",
                "severity": "HIGH" if status == "OFFLINE" else "MEDIUM",
                "title": f"{sensor.get('name') or sensor['sensor_id']} {status_label}",
                "detail": f"마지막 heartbeat: {sensor.get('last_heartbeat_at') or '확인되지 않음'}",
                "href": f"/sensors/{sensor['sensor_id']}",
            }
        )
    for job in recent_analyses:
        status = str(job.get("status"))
        if status not in {"FAILED", "PARTIALLY_COMPLETED"}:
            continue
        partial = status == "PARTIALLY_COMPLETED"
        status_label = "부분 완료" if partial else "분석 실패"
        analysis_attention.append(
            {
                "kind": "PARTIALLY_COMPLETED_ANALYSIS" if partial else "FAILED_ANALYSIS",
                "severity": "MEDIUM" if partial else "HIGH",
                "title": f"{job.get('name') or job['id']} {status_label}",
                "detail": str(job.get("error") or "분석 로그를 확인하세요"),
                "href": f"/analyses/{job['id']}",
            }
        )
    for candidate in priority_candidates:
        if candidate.get("severity") != "CRITICAL":
            continue
        candidate_attention.append(
            {
                "kind": "CRITICAL_CANDIDATE",
                "severity": "CRITICAL",
                "title": f"{candidate['candidate_ip']} 조사 필요",
                "detail": f"점수 {candidate.get('score', 0)} · CRITICAL",
                "href": f"/candidates/{candidate['id']}",
            }
        )

    attention = (
        sensor_attention[:3]
        + analysis_attention[:3]
        + candidate_attention[:2]
        + sensor_attention[3:]
        + analysis_attention[3:]
        + candidate_attention[2:]
    )[:8]

    return {
        "generated_at": generated_at.isoformat(),
        "fleet": {
            "total": len(sensors),
            "online": sensor_statuses.count("ONLINE"),
            "offline": sensor_statuses.count("OFFLINE"),
            "degraded": sensor_statuses.count("DEGRADED"),
            "dropped_packets": sum(
                int(sensor.get("dropped_packets", 0) or 0) for sensor in sensors
            ),
        },
        "analyses": {
            "total": len(jobs),
            "active": sum(str(job.get("status")) in active_statuses for job in jobs),
            "by_status": {
                status: sum(job.get("status") == status for job in jobs)
                for status in active_statuses
            },
            "completed_24h": sum(
                job.get("status") == "COMPLETED"
                and (_utc_datetime(job.get("completed_at")) or datetime.min.replace(tzinfo=UTC))
                >= window_start
                for job in jobs
            ),
            "failed_24h": sum(
                job.get("status") == "FAILED"
                and (_utc_datetime(job.get("completed_at")) or datetime.min.replace(tzinfo=UTC))
                >= window_start
                for job in jobs
            ),
            "partially_completed_24h": sum(
                job.get("status") == "PARTIALLY_COMPLETED"
                and (_utc_datetime(job.get("completed_at")) or datetime.min.replace(tzinfo=UTC))
                >= window_start
                for job in jobs
            ),
        },
        "candidates": {
            "total": len(candidates),
            "critical": severity_counts["CRITICAL"],
            "high": severity_counts["HIGH"],
            "medium": severity_counts["MEDIUM"],
            "low": severity_counts["LOW"],
            "new_24h": sum(
                (_utc_datetime(candidate.get("first_seen")) or datetime.min.replace(tzinfo=UTC))
                >= window_start
                for candidate in candidates
            ),
            **workflow_counts,
        },
        "candidate_trend": [
            {"hour": hour.isoformat(), "count": trend_counts[hour]} for hour in trend_hours
        ],
        "priority_candidates": [
            {
                "id": candidate["id"],
                "job_id": candidate["job_id"],
                "candidate_ip": candidate["candidate_ip"],
                "score": candidate.get("score", 0),
                "severity": candidate.get("severity", "LOW"),
                "last_seen": candidate.get("last_seen"),
                "evidence_count": candidate.get("evidence_count", 0),
                "workflow_status": _candidate_workflow_status(candidate),
            }
            for candidate in priority_candidates
        ],
        "recent_analyses": [
            {
                key: job.get(key)
                for key in (
                    "id",
                    "name",
                    "status",
                    "created_at",
                    "candidate_count",
                    "packet_count",
                    "flow_count",
                )
            }
            for job in recent_analyses
        ],
        "sensor_quality": sensor_quality,
        "attention": attention[:8],
    }


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _metrics_path(path: str) -> str:
    prefix = "/api/v1/sensor-enrollments/"
    if path.startswith(prefix) and path.endswith("/claim"):
        return "/api/v1/sensor-enrollments/{token}/claim"
    return path


def _public_enrollment(enrollment: dict[str, Any], now: datetime) -> dict[str, Any]:
    public = {key: value for key, value in enrollment.items() if key != "token_hash"}
    if enrollment.get("revoked_at"):
        status = "REVOKED"
    elif enrollment.get("claimed_at"):
        status = "CLAIMED"
    elif datetime.fromisoformat(enrollment["expires_at"]) <= now:
        status = "EXPIRED"
    else:
        status = "PENDING"
    return {**public, "status": status}


def create_app(
    settings: Settings | None = None,
    repository: Repository | None = None,
    *,
    flow_store: FlowStore | None = None,
    queue: ControllerQueue | None = None,
    threat_intel_service: ThreatIntelLookup | None = None,
    misp_client: MispPublisher | None = None,
    ai_gateway: ModelGateway | None = None,
    ai_task_queue: AIAnalysisTaskQueue | None = None,
) -> FastAPI:
    config = settings or Settings()
    if repository is not None:
        repo = repository
    elif config.database_url == "memory://":
        repo = MemoryRepository()
    elif config.database_url.startswith(("postgresql://", "postgres://")):
        if config.s3_endpoint == "memory://":
            raise RuntimeError("PostgreSQL operation requires configured MinIO/S3 storage")
        repo = PostgresRepository(
            config.database_url,
            MinioBlobStore(
                config.s3_endpoint,
                config.s3_access_key,
                config.s3_secret_key,
                config.s3_bucket,
            ),
        )
    else:
        raise RuntimeError(f"unsupported database URL: {config.database_url.split(':', 1)[0]}")
    if flow_store is not None:
        flows = flow_store
    elif config.clickhouse_url == "memory://":
        flows = MemoryFlowStore()
    else:
        flows = ClickHouseFlowStore(
            config.clickhouse_url,
            database=config.clickhouse_database,
            username=config.clickhouse_user,
            password=config.clickhouse_password,
        )
    if queue is not None:
        work_queue = queue
    elif config.redis_url == "memory://":
        work_queue = MemoryControllerQueue()
    else:
        work_queue = RedisControllerQueue(
            config.redis_url,
            visibility_timeout=config.queue_visibility_timeout_seconds,
        )
    virustotal_key = config.virustotal_api_key.get_secret_value()
    abuseipdb_key = config.abuseipdb_api_key.get_secret_value()
    if threat_intel_service is not None:
        threat_intel = threat_intel_service
    elif virustotal_key or abuseipdb_key:
        threat_intel = ThreatIntelService(
            virustotal_api_key=virustotal_key,
            abuseipdb_api_key=abuseipdb_key,
            abuseipdb_max_age_days=config.abuseipdb_max_age_days,
            http_client=JsonHttpClient(config.threat_intel_timeout_seconds),
        )
    else:
        threat_intel = None
    misp_key = config.misp_api_key.get_secret_value()
    if misp_client is not None:
        misp = misp_client
    elif config.misp_url and misp_key:
        misp = MispClient(
            config.misp_url,
            misp_key,
            http_client=JsonHttpClient(
                config.threat_intel_timeout_seconds,
                verify_tls=config.misp_verify_tls,
            ),
        )
    else:
        misp = None
    gateway = ai_gateway or (
        create_model_gateway(
            provider=config.ai_model_provider,
            base_url=config.ai_model_base_url,
            model=config.ai_model_name,
            api_key=config.ai_model_api_key.get_secret_value(),
            timeout_seconds=config.ai_model_timeout_seconds,
            retries=config.ai_model_retries,
            temperature=config.ai_model_temperature,
            context_tokens=config.ai_model_context_tokens,
            max_output_tokens=config.ai_model_max_output_tokens,
        )
        if config.ai_analysis_enabled
        else None
    )
    ai_service = AIAnalysisService(repo, gateway) if gateway is not None else None
    if ai_task_queue is not None:
        ai_tasks = ai_task_queue
    elif ai_service is not None and config.redis_url == "memory://":
        ai_tasks = InlineAIAnalysisTaskQueue(ai_service.execute)
    elif ai_service is not None:
        ai_tasks = RedisAIAnalysisTaskQueue(config.redis_url)
    else:
        ai_tasks = None
    app = FastAPI(title="C2Hunter Controller", version="0.1.0")
    app.state.settings = config
    app.state.repository = repo
    app.state.flow_store = flows
    app.state.queue = work_queue
    app.state.threat_intel_service = threat_intel
    app.state.misp_client = misp
    app.state.ai_analysis_service = ai_service
    app.state.ai_analysis_queue = ai_tasks
    candidate_action_lock = threading.Lock()
    misp_export_lock = threading.Lock()
    enrichment_executor = ThreadPoolExecutor(
        max_workers=config.candidate_auto_enrichment_workers,
        thread_name_prefix="candidate-ti",
    )
    enrichment_futures: set[Future[Any]] = set()
    enrichment_lock = threading.Lock()
    enrichment_lifecycle_lock = threading.Lock()
    enrichment_stopping = threading.Event()
    enrichment_repository_lock = threading.Lock()
    enrichment_repositories: list[PostgresRepository] = []
    enrichment_repository_local = threading.local()
    enrichment_capacity = threading.BoundedSemaphore(
        config.candidate_auto_enrichment_queue_capacity
    )
    sessions = SessionStore()
    authenticator = TokenAuthenticator(
        sessions,
        viewer_token_sha256=config.viewer_token_sha256,
        analyst_token_sha256=config.analyst_token_sha256,
        admin_token_sha256=config.admin_token_sha256,
    )
    rate_limiter = FixedWindowRateLimiter(config.rate_limit_window_seconds)
    registry = CollectorRegistry()
    requests = Counter(
        "c2hunter_api_requests_total",
        "API requests",
        ["method", "path", "status"],
        registry=registry,
    )
    latency = Histogram(
        "c2hunter_api_request_duration_seconds", "API request latency", ["path"], registry=registry
    )
    ai_enqueue_latency = Histogram(
        "c2hunter_ai_enqueue_duration_seconds",
        "Controller AI Run enqueue duration",
        ["provider"],
        buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
        registry=registry,
    )
    ai_queue_waiting_depth = Gauge(
        "c2hunter_ai_queue_waiting_depth",
        "AI Runs waiting for a worker",
        registry=registry,
    )
    ai_enqueue_failures = Counter(
        "c2hunter_ai_enqueue_failures_total",
        "Controller AI enqueue failures",
        ["reason"],
        registry=registry,
    )
    ai_feedback = Counter(
        "c2hunter_ai_feedback_total",
        "Immutable analyst feedback records",
        ["verdict"],
        registry=registry,
    )
    ai_queue_waiting_depth.set(0)

    def safe_ai_metric(operation: Callable[[], None]) -> None:
        try:
            operation()
        except Exception:
            # Telemetry must not alter a persisted Run, feedback record, or original exception.
            pass

    app.state.ai_metrics = {
        "enqueue_latency": ai_enqueue_latency,
        "queue_waiting_depth": ai_queue_waiting_depth,
        "enqueue_failures": ai_enqueue_failures,
        "feedback": ai_feedback,
    }

    @app.middleware("http")
    async def security(request: Request, call_next: Any) -> Response:
        path = request.url.path
        client_key = request.client.host if request.client is not None else "unknown"
        try:
            if request.method == "POST" and path == "/api/v1/auth/dev-login":
                rate_limiter.check("dev-login", client_key, config.dev_login_rate_limit)
            if is_enrollment_claim(request.method, path):
                rate_limiter.check(
                    "enrollment-claim", client_key, config.enrollment_claim_rate_limit
                )
            minimum_role = required_role(request.method, path)
            if config.api_auth_required and minimum_role is not None:
                principal = authenticator.authenticate(request.headers.get("authorization"))
                require_role(principal, minimum_role)
                request.state.principal = principal
                if request.method == "POST" and path in {
                    "/api/v1/analysis-jobs",
                    "/api/v1/pcap-analysis-jobs",
                }:
                    rate_limiter.check(
                        "analysis-job", principal.subject, config.analysis_job_rate_limit
                    )
        except SecurityError as exc:
            response = _error(request, exc.status, exc.code, exc.message)
            if exc.retry_after is not None:
                response.headers["retry-after"] = str(exc.retry_after)
            return response
        return cast(Response, await call_next(request))

    @app.middleware("http")
    async def observability(request: Request, call_next: Any) -> Response:
        request.state.request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        metric_path = _metrics_path(request.url.path)
        with latency.labels(metric_path).time():
            response = await call_next(request)
        requests.labels(request.method, metric_path, str(response.status_code)).inc()
        response.headers["x-request-id"] = request.state.request_id
        return cast(Response, response)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        if any(
            item.get("type") == "missing"
            and tuple(item.get("loc", ())) == ("header", "X-Sensor-Token")
            for item in exc.errors()
        ):
            return _error(request, 401, "SENSOR_TOKEN_REQUIRED", "X-Sensor-Token 헤더가 필요합니다")
        safe_errors = []
        for item in exc.errors():
            safe = {k: v for k, v in item.items() if k not in {"input", "ctx"}}
            if "ctx" in item:
                safe["context"] = {key: str(value) for key, value in item["ctx"].items()}
            safe_errors.append(safe)
        return _error(request, 422, "VALIDATION_ERROR", "요청 값이 유효하지 않습니다", safe_errors)

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _error(request, exc.status, exc.code, exc.message, exc.details)

    @app.get("/api/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/v1/ready")
    def ready() -> JSONResponse:
        if isinstance(repo, PostgresRepository):
            dependencies = {
                "postgres": repo.database_ready(),
                "object_storage": repo.blob_store.ready(),
                "clickhouse": flows.ready(),
                "redis": work_queue.ready(),
            }
        else:
            dependencies = {
                "repository": repo.ready(),
                "flow_store": flows.ready(),
                "queue": work_queue.ready(),
            }
        is_ready = all(dependencies.values())
        return JSONResponse(
            status_code=200 if is_ready else 503,
            content={
                "status": "ready" if is_ready else "not_ready",
                "dependencies": dependencies,
            },
        )

    @app.get("/api/v1/metrics")
    def metrics() -> Response:
        return Response(generate_latest(registry), media_type=CONTENT_TYPE_LATEST)

    @app.post(
        "/api/v1/auth/dev-login",
        summary="Mint a short-lived development token",
        description=(
            "Disabled unless C2HUNTER_DEV_LOGIN_ENABLED=true. The opaque token is a local "
            "development convenience with server-side expiry and ADMIN authorization. It does "
            "not provide production identity, refresh, revocation, OIDC, or MFA."
        ),
    )
    def development_login(payload: DevLoginRequest) -> dict[str, Any]:
        if not config.dev_login_enabled:
            # Keep the disabled surface indistinguishable from an unavailable optional feature.
            raise ApiError(404, "DEV_LOGIN_DISABLED", "개발 로그인이 활성화되지 않았습니다")
        token = secrets.token_urlsafe(32)
        sessions.add(token, payload.username, Role.ADMIN, config.dev_token_ttl_seconds)
        return {
            "access_token": token,
            "token_type": "bearer",
            "expires_in": config.dev_token_ttl_seconds,
            "username": payload.username,
            "role": Role.ADMIN.name,
            "limitations": (
                "Development-only in-memory session; no production identity, refresh, OIDC, "
                "MFA, or cross-process session semantics are provided."
            ),
        }

    def enrollment_for_token(token: str) -> dict[str, Any] | None:
        candidate = _token_hash(token)
        for enrollment in repo.list_enrollments():
            if hmac.compare_digest(str(enrollment["token_hash"]), candidate):
                return enrollment
        return None

    def require_sensor_token(sensor_id: str, token: str | None) -> dict[str, Any]:
        if not token:
            raise ApiError(401, "SENSOR_TOKEN_REQUIRED", "X-Sensor-Token 헤더가 필요합니다")
        credential = repo.get_sensor_credential(sensor_id)
        if credential is None or not hmac.compare_digest(
            str(credential["token_hash"]), _token_hash(token)
        ):
            raise ApiError(401, "INVALID_SENSOR_TOKEN", "센서 토큰이 유효하지 않습니다")
        if credential.get("revoked_at") is not None:
            raise ApiError(403, "SENSOR_REVOKED", "폐기된 센서입니다")
        sensor = repo.get_sensor(sensor_id)
        if sensor is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        return sensor

    def capture_participant_sensor_ids(job: dict[str, Any]) -> set[str]:
        capture = job.get("capture", {})
        sensor_ids = sorted({str(value) for value in job.get("sensor_ids", [])})
        participants: set[str] = set()
        for candidate_sensor_id in sensor_ids:
            max_packets = allocate_sensor_limit(
                capture.get("max_packets"), sensor_ids, candidate_sensor_id
            )
            max_bytes = allocate_sensor_limit(
                capture.get("max_bytes"), sensor_ids, candidate_sensor_id
            )
            if max_packets == 0 or max_bytes == 0:
                continue
            participants.add(candidate_sensor_id)
        return participants

    def active_capture_jobs(sensor_id: str) -> list[dict[str, Any]]:
        active: list[dict[str, Any]] = []
        for job in repo.list_active_live_jobs():
            if job.get("status") != JobState.CAPTURING or sensor_id not in job.get(
                "sensor_ids", []
            ):
                continue
            capture = job.get("capture", {})
            sensor_ids = [str(value) for value in job.get("sensor_ids", [])]
            max_packets = allocate_sensor_limit(capture.get("max_packets"), sensor_ids, sensor_id)
            max_bytes = allocate_sensor_limit(capture.get("max_bytes"), sensor_ids, sensor_id)
            # A zero quota means the analysis-wide limit is smaller than the
            # number of selected sensors. Do not send the job to this sensor;
            # zero has historically meant "unlimited" in the agent protocol.
            if max_packets == 0 or max_bytes == 0:
                continue
            active.append(
                {
                    "job_id": str(job["id"]),
                    "start_time": job["start_time"],
                    "end_time": job["end_time"],
                    "store_pcap": bool(capture.get("store_pcap")),
                    "max_packets": max_packets,
                    "max_bytes": max_bytes,
                    "bpf_filter": str(capture.get("bpf_filter", "")),
                }
            )
        return active

    def normalized_capture_bpf(value: object) -> str:
        normalized = str(value or "").strip().lower()
        normalized = normalized.replace("(", " ( ").replace(")", " ) ")
        return " ".join(normalized.split())

    def ensure_live_capture_bpf_compatible(payload: AnalysisJobCreate) -> None:
        from .jobs import JobState

        if payload.mode != "LIVE" or payload.flow_records:
            return
        requested_filter = normalized_capture_bpf(payload.capture.bpf_filter)
        requested_sensors = set(payload.sensor_ids)
        conflicts: list[dict[str, Any]] = []
        for active_job in repo.list_active_live_jobs():
            if active_job.get("status") != JobState.CAPTURING:
                continue
            if active_job.get("idempotency_key") == payload.idempotency_key:
                continue
            shared_sensors = sorted(requested_sensors & set(active_job.get("sensor_ids", [])))
            if not shared_sensors:
                continue
            active_filter = normalized_capture_bpf(
                active_job.get("capture", {}).get("bpf_filter", "")
            )
            if active_filter == requested_filter:
                continue
            conflicts.append(
                {
                    "job_id": str(active_job["id"]),
                    "sensor_ids": shared_sensors,
                    "bpf_filter": active_filter,
                }
            )
        if conflicts:
            raise ApiError(
                409,
                "CAPTURE_BPF_CONFLICT",
                "같은 Sensor에서 동시에 실행되는 LIVE 분석은 동일한 BPF filter가 필요합니다",
                {"requested_bpf_filter": requested_filter, "conflicts": conflicts},
            )

    @app.post(
        "/api/v1/sensor-enrollments",
        status_code=201,
        response_model=EnrollmentCreateResponse,
    )
    def create_sensor_enrollment(payload: EnrollmentCreate) -> dict[str, Any]:
        now = datetime.now(UTC)
        token = secrets.token_urlsafe(32)
        enrollment_id = str(uuid.uuid4())
        enrollment = {
            "enrollment_id": enrollment_id,
            "name": payload.name,
            "token_hash": _token_hash(token),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=payload.expires_in_seconds)).isoformat(),
            "claimed_at": None,
            "revoked_at": None,
            "sensor_id": None,
            "capture_sources": [
                source.model_dump(mode="json") for source in payload.capture_sources
            ],
            "internal_networks": payload.internal_networks,
        }
        repo.create_enrollment(enrollment)
        return {
            "enrollment_id": enrollment_id,
            "enrollment_token": token,
            "install_command": (
                "sudo ./install-sensor.sh --controller-url <CONTROLLER_URL> "
                f"--enrollment-token {token}"
            ),
            "expires_at": enrollment["expires_at"],
        }

    @app.get("/api/v1/sensor-enrollments")
    def list_sensor_enrollments(
        page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200)
    ) -> dict[str, Any]:
        now = datetime.now(UTC)
        items = [_public_enrollment(item, now) for item in repo.list_enrollments()]
        items.sort(key=lambda item: item["created_at"], reverse=True)
        return _page(items, page, page_size)

    @app.get("/api/v1/sensor-enrollments/{enrollment_id}")
    def get_sensor_enrollment(enrollment_id: str) -> dict[str, Any]:
        enrollment = repo.get_enrollment(enrollment_id)
        if enrollment is None:
            raise ApiError(404, "ENROLLMENT_NOT_FOUND", "등록 요청을 찾을 수 없습니다")
        return _public_enrollment(enrollment, datetime.now(UTC))

    @app.delete("/api/v1/sensor-enrollments/{enrollment_id}")
    def revoke_sensor_enrollment(enrollment_id: str) -> dict[str, Any]:
        enrollment = repo.get_enrollment(enrollment_id)
        if enrollment is None:
            raise ApiError(404, "ENROLLMENT_NOT_FOUND", "등록 요청을 찾을 수 없습니다")
        enrollment["revoked_at"] = enrollment.get("revoked_at") or datetime.now(UTC).isoformat()
        return _public_enrollment(repo.save_enrollment(enrollment), datetime.now(UTC))

    @app.post(
        "/api/v1/sensor-enrollments/{token}/claim",
        status_code=201,
        response_model=EnrollmentClaimResponse,
    )
    def claim_sensor_enrollment(token: str, payload: EnrollmentClaim) -> dict[str, Any]:
        preview = enrollment_for_token(token)
        if preview is None:
            raise ApiError(404, "ENROLLMENT_NOT_FOUND", "등록 토큰이 유효하지 않습니다")
        discovered = {item.name for item in payload.discovered_interfaces}
        missing = [
            source["interface"]
            for source in preview["capture_sources"]
            if source["enabled"] and source["interface"] not in discovered
        ]
        if missing:
            raise ApiError(
                422,
                "DESIRED_INTERFACE_NOT_FOUND",
                "설정된 캡처 인터페이스가 센서에서 발견되지 않았습니다",
                {"interfaces": missing},
            )
        now = datetime.now(UTC)
        enrollment, status = repo.claim_enrollment(_token_hash(token), now)
        errors = {
            "NOT_FOUND": (404, "ENROLLMENT_NOT_FOUND", "등록 토큰이 유효하지 않습니다"),
            "REVOKED": (410, "ENROLLMENT_REVOKED", "등록 토큰이 폐기되었습니다"),
            "EXPIRED": (410, "ENROLLMENT_EXPIRED", "등록 토큰이 만료되었습니다"),
            "CLAIMED": (409, "ENROLLMENT_ALREADY_CLAIMED", "이미 사용된 등록 토큰입니다"),
        }
        if status != "OK" or enrollment is None:
            http_status, code, message = errors[status]
            raise ApiError(http_status, code, message)
        sensor_id = enrollment.get("sensor_id") or str(uuid.uuid4())
        agent_token = secrets.token_urlsafe(48)
        capture_sources = [
            {**source, "validation_status": "VALID"} for source in enrollment["capture_sources"]
        ]
        sensor = {
            "sensor_id": sensor_id,
            "name": enrollment["name"],
            **payload.model_dump(mode="json", exclude={"discovered_interfaces"}),
            "observed_interfaces": [
                item.model_dump(mode="json") for item in payload.discovered_interfaces
            ],
            "interfaces": [],
            "capture_sources": capture_sources,
            "internal_networks": enrollment["internal_networks"],
            "config_version": 1,
            "reported_status": "OFFLINE",
            "derived_status": "OFFLINE",
            "enabled": True,
            "tags": {},
            "enrollment_id": enrollment["enrollment_id"],
        }
        repo.upsert_sensor(sensor)
        repo.save_sensor_credential(
            {
                "sensor_id": sensor_id,
                "token_hash": _token_hash(agent_token),
                "created_at": now.isoformat(),
                "rotated_at": None,
                "revoked_at": None,
            }
        )
        enrollment["sensor_id"] = sensor_id
        repo.save_enrollment(enrollment)
        return {
            "sensor_id": sensor_id,
            "agent_token": agent_token,
            "config_version": 1,
            "capture_sources": capture_sources,
            "internal_networks": enrollment["internal_networks"],
            "heartbeat_interval_seconds": 15,
            "config_poll_interval_seconds": 1,
        }

    @app.get(
        "/api/v1/sensors/{sensor_id}/configuration",
        response_model=SensorConfigurationResponse,
    )
    def get_sensor_configuration(sensor_id: str) -> dict[str, Any]:
        sensor = repo.get_sensor(sensor_id)
        if sensor is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        return {
            "config_version": sensor["config_version"],
            "capture_sources": sensor["capture_sources"],
            "capture_jobs": active_capture_jobs(sensor_id),
            "internal_networks": sensor["internal_networks"],
        }

    @app.put(
        "/api/v1/sensors/{sensor_id}/configuration",
        response_model=SensorConfigurationResponse,
    )
    def update_sensor_configuration(
        sensor_id: str, payload: SensorConfigurationUpdate
    ) -> dict[str, Any]:
        sensor = repo.get_sensor(sensor_id)
        if sensor is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        observed = {item["name"] for item in sensor.get("observed_interfaces", [])}
        missing = [
            source.interface
            for source in payload.capture_sources
            if source.enabled and source.interface not in observed
        ]
        if missing:
            raise ApiError(
                422,
                "DESIRED_INTERFACE_NOT_FOUND",
                "설정된 캡처 인터페이스가 센서에서 발견되지 않았습니다",
                {"interfaces": missing},
            )
        configuration = payload.model_dump(mode="json", exclude={"config_version"})
        configuration["capture_sources"] = [
            {**source, "validation_status": "VALID"} for source in configuration["capture_sources"]
        ]
        updated, status = repo.update_sensor_configuration(
            sensor_id, payload.config_version, configuration
        )
        if status == "CONFLICT":
            raise ApiError(
                409,
                "CONFIG_VERSION_CONFLICT",
                "설정 버전이 최신 버전과 일치하지 않습니다",
                {"current_version": updated["config_version"] if updated else None},
            )
        if updated is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        return {
            "config_version": updated["config_version"],
            "capture_sources": updated["capture_sources"],
            "capture_jobs": active_capture_jobs(sensor_id),
            "internal_networks": updated["internal_networks"],
        }

    @app.get("/api/v1/sensors/{sensor_id}/agent-config")
    def get_agent_configuration(
        sensor_id: str,
        sensor_token: str | None = Header(alias="X-Sensor-Token"),
    ) -> dict[str, Any]:
        sensor = require_sensor_token(sensor_id, sensor_token)
        return {
            "sensor_id": sensor_id,
            "config_version": sensor["config_version"],
            "capture_sources": sensor["capture_sources"],
            "capture_jobs": active_capture_jobs(sensor_id),
            "internal_networks": sensor["internal_networks"],
            "heartbeat_interval_seconds": 15,
            "config_poll_interval_seconds": 1,
        }

    @app.post("/api/v1/sensors/{sensor_id}/credentials/rotate")
    def rotate_sensor_credential(sensor_id: str) -> dict[str, Any]:
        credential = repo.get_sensor_credential(sensor_id)
        if credential is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        now = datetime.now(UTC)
        token = secrets.token_urlsafe(48)
        credential.update(
            {"token_hash": _token_hash(token), "rotated_at": now.isoformat(), "revoked_at": None}
        )
        repo.save_sensor_credential(credential)
        return {"sensor_id": sensor_id, "agent_token": token, "rotated_at": now.isoformat()}

    @app.post("/api/v1/sensors/{sensor_id}/revoke")
    def revoke_sensor_credential(sensor_id: str) -> dict[str, Any]:
        credential = repo.get_sensor_credential(sensor_id)
        if credential is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        credential["revoked_at"] = credential.get("revoked_at") or datetime.now(UTC).isoformat()
        repo.save_sensor_credential(credential)
        return {"sensor_id": sensor_id, "revoked_at": credential["revoked_at"]}

    @app.post("/api/v1/sensors/register", status_code=201)
    def register_sensor(
        payload: SensorRegistration,
        sensor_token: str | None = Header(alias="X-Sensor-Token"),
    ) -> dict[str, Any]:
        existing = require_sensor_token(payload.sensor_id, sensor_token)
        now = datetime.now(UTC)
        sensor = payload.model_dump(mode="json")
        offset = (now - payload.current_time).total_seconds() * 1000
        sensor.update(
            {
                "reported_status": "ONLINE",
                "derived_status": "DEGRADED"
                if abs(offset) > config.clock_skew_threshold_seconds * 1000
                else "ONLINE",
                "clock_offset_ms": offset,
                "last_heartbeat_at": now.isoformat(),
                "enabled": True,
                "tags": {},
            }
        )
        for field in (
            "config_version",
            "capture_sources",
            "internal_networks",
            "enrollment_id",
        ):
            if field in existing:
                sensor[field] = existing[field]
        sensor["observed_interfaces"] = sensor["interfaces"]
        return repo.upsert_sensor(sensor)

    @app.post("/api/v1/sensors/{sensor_id}/heartbeat")
    def heartbeat(
        sensor_id: str,
        payload: Heartbeat,
        sensor_token: str | None = Header(alias="X-Sensor-Token"),
    ) -> dict[str, Any]:
        require_sensor_token(sensor_id, sensor_token)
        now = datetime.now(UTC)
        offset = (now - payload.reported_at).total_seconds() * 1000
        fields = payload.model_dump(mode="json", exclude={"discovered_interfaces"})
        if payload.discovered_interfaces is not None:
            fields["observed_interfaces"] = [
                item.model_dump(mode="json") for item in payload.discovered_interfaces
            ]
        fields.update(
            {
                "reported_status": payload.status.value,
                "derived_status": "DEGRADED"
                if abs(offset) > config.clock_skew_threshold_seconds * 1000
                else payload.status.value,
                "clock_offset_ms": offset,
                "last_heartbeat_at": now.isoformat(),
            }
        )
        sensor = repo.update_sensor_heartbeat(sensor_id, fields)
        if sensor is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        record_capture_completions(sensor_id, payload, now)
        return sensor

    @app.post("/api/v1/sensors/{sensor_id}/flow-batches", status_code=202)
    def ingest_flow_batch(
        sensor_id: str,
        payload: FlowBatchCreate,
        sensor_token: str | None = Header(alias="X-Sensor-Token"),
    ) -> dict[str, Any]:
        require_sensor_token(sensor_id, sensor_token)
        if any(record.sensor_id != sensor_id for record in payload.records):
            raise ApiError(422, "SENSOR_ID_MISMATCH", "flow record sensor_id가 경로와 다릅니다")
        accepted, count = flows.ingest_batch(
            sensor_id,
            payload.batch_id,
            [record.model_dump(mode="json") for record in payload.records],
        )
        return {
            "batch_id": payload.batch_id,
            "accepted": accepted,
            "duplicate": not accepted,
            "record_count": count,
        }

    @app.put("/api/v1/sensors/{sensor_id}/pcap-segments/{segment_id}", status_code=201)
    async def upload_sensor_pcap(
        sensor_id: str,
        segment_id: str,
        request: Request,
        filename: str = Query(min_length=6, max_length=200),
        analysis_job_id: str | None = Query(default=None, min_length=1, max_length=128),
        sensor_token: str | None = Header(alias="X-Sensor-Token"),
    ) -> dict[str, Any]:
        sensor = require_sensor_token(sensor_id, sensor_token)
        analysis_job: dict[str, Any] | None = None
        analysis_pcap_limit: int | None = None
        stored_analysis_bytes = 0
        if analysis_job_id is not None:
            analysis_job = repo.get_job(analysis_job_id)
            if (
                analysis_job is None
                or sensor_id not in analysis_job.get("sensor_ids", [])
                or not bool(analysis_job.get("capture", {}).get("store_pcap"))
            ):
                raise ApiError(
                    422,
                    "INVALID_PCAP_ANALYSIS_JOB",
                    "PCAP 분석 작업이 sensor 할당과 일치하지 않습니다",
                )
            configured_limit = analysis_job.get("capture", {}).get("max_bytes")
            if isinstance(configured_limit, int) and configured_limit > 0:
                analysis_pcap_limit = configured_limit
                stored_analysis_bytes = sum(
                    int(segment.get("size_bytes", 0) or 0)
                    for segment in repo.list_sensor_pcaps()
                    if segment.get("analysis_job_id") == analysis_job_id
                    and segment.get("id") != segment_id
                )
        safe_characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
        if not filename.endswith(".pcap") or any(
            character not in safe_characters for character in filename
        ):
            raise ApiError(422, "INVALID_PCAP_FILENAME", "PCAP 파일명이 유효하지 않습니다")
        expected_id = hashlib.sha256(f"{sensor_id}\0{filename}".encode()).hexdigest()
        if not hmac.compare_digest(segment_id, expected_id):
            raise ApiError(
                422,
                "INVALID_PCAP_SEGMENT_ID",
                "PCAP segment ID가 파일명과 일치하지 않습니다",
            )
        content_type = request.headers.get("content-type", "").split(";", 1)[0]
        if content_type != "application/vnd.tcpdump.pcap":
            raise ApiError(
                415,
                "UNSUPPORTED_PCAP_MEDIA_TYPE",
                "classic PCAP content type이 필요합니다",
            )
        announced = request.headers.get("content-length")
        announced_size: int | None = None
        if announced is not None:
            try:
                announced_size = int(announced)
            except ValueError as exc:
                raise ApiError(
                    400, "INVALID_CONTENT_LENGTH", "Content-Length가 유효하지 않습니다"
                ) from exc
            if announced_size > config.pcap_upload_max_bytes:
                raise ApiError(413, "PCAP_TOO_LARGE", "PCAP segment가 허용 크기를 초과합니다")
            if (
                analysis_pcap_limit is not None
                and stored_analysis_bytes + announced_size > analysis_pcap_limit
            ):
                raise ApiError(
                    413,
                    "PCAP_ANALYSIS_LIMIT_REACHED",
                    "분석 작업의 PCAP 저장 크기 제한에 도달했습니다",
                    {"limit_bytes": analysis_pcap_limit, "stored_bytes": stored_analysis_bytes},
                )
        uploaded = bytearray()
        async for chunk in request.stream():
            if len(uploaded) + len(chunk) > config.pcap_upload_max_bytes:
                raise ApiError(413, "PCAP_TOO_LARGE", "PCAP segment가 허용 크기를 초과합니다")
            uploaded.extend(chunk)
        content = bytes(uploaded)
        if announced_size is not None and announced_size != len(content):
            raise ApiError(400, "CONTENT_LENGTH_MISMATCH", "Content-Length와 실제 크기가 다릅니다")
        if len(content) < 24 or content[:4] not in {
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
        }:
            raise ApiError(422, "INVALID_PCAP", "유효한 classic PCAP header가 필요합니다")
        digest = hashlib.sha256(content).hexdigest()
        existing = repo.get_sensor_pcap(segment_id)
        if existing is not None:
            metadata, _ = existing
            if (
                metadata["sensor_id"] != sensor_id
                or metadata["sha256"] != digest
                or metadata.get("analysis_job_id") != analysis_job_id
            ):
                raise ApiError(
                    409,
                    "PCAP_SEGMENT_CONFLICT",
                    "동일 segment ID에 다른 PCAP이 저장되어 있습니다",
                )
            public = {key: value for key, value in metadata.items() if key != "object_key"}
            return {**public, "segment_id": segment_id}
        if (
            analysis_pcap_limit is not None
            and stored_analysis_bytes + len(content) > analysis_pcap_limit
        ):
            raise ApiError(
                413,
                "PCAP_ANALYSIS_LIMIT_REACHED",
                "분석 작업의 PCAP 저장 크기 제한에 도달했습니다",
                {"limit_bytes": analysis_pcap_limit, "stored_bytes": stored_analysis_bytes},
            )
        metadata = {
            "id": segment_id,
            "sensor_id": sensor_id,
            "sensor_name": sensor.get("name", sensor_id),
            "analysis_job_id": analysis_job_id,
            "filename": filename,
            "size_bytes": len(content),
            "sha256": digest,
            "uploaded_at": datetime.now(UTC).isoformat(),
        }
        stored, save_status = repo.save_sensor_pcap_limited(metadata, content, analysis_pcap_limit)
        if save_status == "LIMIT":
            raise ApiError(
                413,
                "PCAP_ANALYSIS_LIMIT_REACHED",
                "분석 작업의 PCAP 저장 크기 제한에 도달했습니다",
                {"limit_bytes": analysis_pcap_limit},
            )
        if save_status == "CONFLICT":
            raise ApiError(
                409,
                "PCAP_SEGMENT_CONFLICT",
                "동일 segment ID에 다른 PCAP이 저장되어 있습니다",
            )
        if stored is None:
            raise RuntimeError(f"unexpected sensor PCAP save status: {save_status}")
        public = {key: value for key, value in stored.items() if key != "object_key"}
        return {**public, "segment_id": segment_id}

    @app.get("/api/v1/sensor-pcaps")
    def list_sensor_pcaps(
        sensor_id: str | None = None,
        analysis_job_id: str | None = None,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        segments = repo.list_sensor_pcaps()
        if sensor_id is not None:
            segments = [segment for segment in segments if segment["sensor_id"] == sensor_id]
        if analysis_job_id is not None:
            segments = [
                segment for segment in segments if segment.get("analysis_job_id") == analysis_job_id
            ]
        segments.sort(key=lambda segment: str(segment["uploaded_at"]), reverse=True)
        public = [
            {key: value for key, value in segment.items() if key != "object_key"}
            for segment in segments
        ]
        return _page(public, page, page_size)

    @app.get("/api/v1/sensor-pcaps/{segment_id}/download")
    def download_sensor_pcap(segment_id: str) -> Response:
        stored = repo.get_sensor_pcap(segment_id)
        if stored is None:
            raise ApiError(404, "SENSOR_PCAP_NOT_FOUND", "sensor PCAP을 찾을 수 없습니다")
        metadata, content = stored
        return Response(
            content,
            media_type="application/vnd.tcpdump.pcap",
            headers={
                "Content-Disposition": f'attachment; filename="{metadata["filename"]}"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/api/v1/dashboard")
    def dashboard() -> dict[str, Any]:
        return _dashboard_snapshot(
            repo,
            heartbeat_timeout_seconds=config.heartbeat_timeout_seconds,
        )

    @app.get("/api/v1/sensors")
    def list_sensors(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        status: str | None = None,
        enabled: bool | None = None,
        sort: str = "sensor_id",
    ) -> dict[str, Any]:
        items = repo.list_sensors()
        if status:
            items = [item for item in items if item.get("derived_status") == status]
        if enabled is not None:
            items = [item for item in items if item.get("enabled") is enabled]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"sensor_id", "name", "last_heartbeat_at", "derived_status"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        return _page(items, page, page_size)

    @app.get("/api/v1/sensors/{sensor_id}")
    def get_sensor(sensor_id: str) -> dict[str, Any]:
        sensor = repo.get_sensor(sensor_id)
        if sensor is None:
            raise ApiError(404, "SENSOR_NOT_FOUND", "센서를 찾을 수 없습니다")
        return sensor

    @app.post("/api/v1/sensor-groups", status_code=201)
    def create_group(payload: SensorGroupCreate) -> dict[str, Any]:
        missing = [
            sensor_id for sensor_id in payload.sensor_ids if repo.get_sensor(sensor_id) is None
        ]
        if missing:
            raise ApiError(
                404,
                "SENSOR_NOT_FOUND",
                "그룹 멤버 센서를 찾을 수 없습니다",
                {"sensor_ids": missing},
            )
        group = {"id": str(uuid.uuid4()), **payload.model_dump()}
        return repo.create_group(group)

    @app.get("/api/v1/sensor-groups")
    def list_groups(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        name: str | None = None,
        sort: str = "name",
    ) -> dict[str, Any]:
        items = repo.list_groups()
        if name:
            items = [item for item in items if name.lower() in item["name"].lower()]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"name", "id"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: item[field], reverse=descending)
        return _page(items, page, page_size)

    machine = StateMachine()

    def record_capture_completions(sensor_id: str, payload: Heartbeat, now: datetime) -> None:
        for completion in payload.completed_capture_jobs:
            current = repo.get_job_summary(completion.job_id)
            if current is None or current.get("status") != JobState.CAPTURING:
                continue
            capture = current.get("capture", {})
            limit_field = "max_packets" if completion.stop_reason == "MAX_PACKETS" else "max_bytes"
            configured_limit = capture.get(limit_field)
            if not isinstance(configured_limit, int) or configured_limit <= 0:
                continue
            participants = capture_participant_sensor_ids(current)
            if sensor_id not in participants:
                continue
            completions = dict(current.get("capture_completions", {}))
            completions[sensor_id] = {
                "stop_reason": completion.stop_reason,
                "reported_at": payload.reported_at.isoformat(),
            }
            current["capture_completions"] = completions
            if participants and participants.issubset(completions):
                capture = dict(current.get("capture", {}))
                capture.setdefault("requested_end_time", current.get("end_time"))
                current["capture"] = capture
                current["end_time"] = now.isoformat()
                current["capture_stopped_at"] = now.isoformat()
                machine.transition(
                    current,
                    JobState.UPLOADING,
                    "all assigned sensors reached the capture packet/byte limit",
                )
            repo.save_job_metadata(current)

    def payload_signature_snapshot() -> list[dict[str, Any]]:
        return [
            dict(signature)
            for signature in repo.list_payload_signatures()
            if signature.get("enabled") is True
        ]

    def allowlist_snapshot() -> list[dict[str, Any]]:
        return [dict(entry) for entry in repo.list_allowlist()]

    def default_detector_weights() -> dict[str, float] | None:
        preset = next(
            (
                preset
                for preset in repo.list_detector_weight_presets()
                if preset.get("is_default") is True
            ),
            None,
        )
        return dict(preset["detector_weights"]) if preset is not None else None

    def apply_job_packet_limit(job: dict[str, Any]) -> None:
        capture = job.get("capture", {})
        records, summary = limit_flow_records(
            list(job.get("flow_records", [])), capture.get("max_packets")
        )
        job["flow_records"] = records
        if summary["discarded_packets"] <= 0:
            return
        job["capture_limit"] = summary
        warning = (
            "capture.max_packets 제한으로 분석 데이터셋을 "
            f"{summary['retained_packets']} packets로 절단했습니다 "
            f"({summary['discarded_packets']} packets 제외)"
        )
        warnings = job.setdefault("warnings", [])
        if warning not in warnings:
            warnings.append(warning)

    def enqueue_worker_job(job: dict[str, Any]) -> None:
        envelope: dict[str, Any] = {"id": job["id"]}
        if isinstance(work_queue, MemoryControllerQueue):
            envelope["payload"] = job
        work_queue.enqueue(envelope)

    def begin_live_capture(job: dict[str, Any]) -> dict[str, Any]:
        machine.transition(job, JobState.WAITING_FOR_SENSOR, "sensor selection validated")
        machine.transition(job, JobState.CAPTURING, "waiting for live capture range")
        return repo.save_job_metadata(job)

    def enqueue_analysis(job: dict[str, Any]) -> dict[str, Any]:
        job.setdefault("payload_signatures", payload_signature_snapshot())
        snapshot = flows.snapshot(
            list(job["sensor_ids"]),
            datetime.fromisoformat(job["start_time"]),
            datetime.fromisoformat(job["end_time"]),
        )
        job["dataset_id"] = snapshot.dataset_id
        job["flow_records"] = [dict(record) for record in snapshot.records]
        apply_job_packet_limit(job)
        job["flow_count"] = len(job["flow_records"])
        job["packet_count"] = sum(
            int(record.get("packet_count", 1)) for record in job["flow_records"]
        )
        transitions: list[tuple[JobState, str]] = []
        current_state = JobState(job["status"])
        if current_state == JobState.CREATED:
            transitions.extend(
                [
                    (JobState.WAITING_FOR_SENSOR, "sensor selection validated"),
                    (JobState.CAPTURING, "stored capture range selected"),
                ]
            )
        if current_state != JobState.UPLOADING:
            transitions.append((JobState.UPLOADING, "persisted flow batches selected"))
        transitions.extend(
            [
                (JobState.INGESTING, "immutable dataset snapshot created"),
                (JobState.ANALYZING, "durable analysis job enqueued"),
            ]
        )
        for state, reason in transitions:
            machine.transition(job, state, reason)
        saved = repo.save_job(job)
        enqueue_worker_job(job)
        return saved

    def enrich_candidate(
        job_id: str,
        candidate: dict[str, Any],
        *,
        origin: Literal["AUTO", "MANUAL"],
        pending_record: dict[str, Any] | None = None,
        persistence_repository: Repository | None = None,
    ) -> dict[str, Any]:
        target_repository = persistence_repository or repo
        candidate_id = str(candidate["id"])
        candidate_ip = str(candidate["candidate_ip"])
        base_record = pending_record or {
            "id": str(uuid.uuid4()),
            "candidate_id": candidate_id,
            "job_id": job_id,
            "candidate_ip": candidate_ip,
            "origin": origin,
            "status": "PENDING",
            "fetched_at": datetime.now(UTC).isoformat(),
            "providers": {},
            "summary": {},
        }
        target_repository.save_candidate_ti_lookup(base_record)
        providers: dict[str, dict[str, Any]] = {}
        summary: dict[str, Any] = {}
        try:
            if threat_intel is not None:
                result = threat_intel.lookup_ip(candidate_ip)
                raw_providers = result.get("providers", {})
                if isinstance(raw_providers, dict):
                    providers.update(
                        {
                            str(name): cast(dict[str, Any], value)
                            for name, value in raw_providers.items()
                            if isinstance(value, dict)
                        }
                    )
                raw_summary = result.get("summary", {})
                if isinstance(raw_summary, dict):
                    summary.update(raw_summary)
            if misp is not None:
                try:
                    providers["misp"] = misp.lookup_ip(candidate_ip)
                except IntegrationError as exc:
                    providers["misp"] = {
                        "status": "ERROR",
                        "provider": exc.provider,
                        "error": exc.message,
                    }
            summary["misp_attribute_count"] = int(
                providers.get("misp", {}).get("attribute_count", 0) or 0
            )
            summary["misp_event_count"] = int(providers.get("misp", {}).get("event_count", 0) or 0)
            failed = any(
                provider.get("status") in {"ERROR", "AUTH_ERROR", "RATE_LIMITED"}
                for provider in providers.values()
            )
            completed = {
                **base_record,
                "status": "PARTIAL" if failed else "COMPLETED",
                "fetched_at": datetime.now(UTC).isoformat(),
                "providers": providers,
                "summary": summary,
            }
        except IntegrationError as exc:
            completed = {
                **base_record,
                "status": "FAILED",
                "fetched_at": datetime.now(UTC).isoformat(),
                "providers": {
                    exc.provider: {
                        "status": "ERROR",
                        "provider": exc.provider,
                        "error": exc.message,
                    }
                },
                "summary": summary,
            }
        except Exception:
            logger.exception(
                "Unexpected candidate enrichment failure candidate_id=%s candidate_ip=%s origin=%s",
                candidate_id,
                candidate_ip,
                origin,
            )
            completed = {
                **base_record,
                "status": "FAILED",
                "fetched_at": datetime.now(UTC).isoformat(),
                "providers": {
                    "internal": {
                        "status": "ERROR",
                        "error": "candidate enrichment failed",
                    }
                },
                "summary": summary,
            }
        target_repository.save_candidate_ti_lookup(completed)
        return completed

    def automatic_enrichment_repository() -> Repository:
        if not isinstance(repo, PostgresRepository):
            return repo
        worker_repository = getattr(enrichment_repository_local, "repository", None)
        if isinstance(worker_repository, PostgresRepository):
            return worker_repository
        worker_repository = repo.for_background_worker()
        enrichment_repository_local.repository = worker_repository
        with enrichment_repository_lock:
            enrichment_repositories.append(worker_repository)
        return worker_repository

    def run_automatic_enrichment(
        job_id: str,
        candidate: dict[str, Any],
        pending_record: dict[str, Any],
    ) -> dict[str, Any]:
        return enrich_candidate(
            job_id,
            candidate,
            origin="AUTO",
            pending_record=pending_record,
            persistence_repository=automatic_enrichment_repository(),
        )

    def schedule_candidate_enrichment(job_id: str, candidates: list[dict[str, Any]]) -> None:
        if (threat_intel is None and misp is None) or config.candidate_auto_enrichment_limit == 0:
            return
        selected = sorted(candidates, key=lambda item: int(item.get("score", 0)), reverse=True)[
            : config.candidate_auto_enrichment_limit
        ]
        for candidate in selected:
            pending_record = {
                "id": str(uuid.uuid4()),
                "candidate_id": str(candidate["id"]),
                "job_id": job_id,
                "candidate_ip": str(candidate["candidate_ip"]),
                "origin": "AUTO",
                "status": "PENDING",
                "fetched_at": datetime.now(UTC).isoformat(),
                "providers": {},
                "summary": {},
            }
            repo.save_candidate_ti_lookup(pending_record)
            if not enrichment_capacity.acquire(blocking=False):
                repo.save_candidate_ti_lookup(
                    {
                        **pending_record,
                        "status": "FAILED",
                        "providers": {
                            "internal": {
                                "status": "ERROR",
                                "error": "automatic enrichment queue capacity exceeded",
                            }
                        },
                    }
                )
                continue
            with enrichment_lifecycle_lock:
                if enrichment_stopping.is_set():
                    enrichment_capacity.release()
                    repo.save_candidate_ti_lookup(
                        {
                            **pending_record,
                            "status": "FAILED",
                            "providers": {
                                "internal": {
                                    "status": "ERROR",
                                    "error": "automatic enrichment is shutting down",
                                }
                            },
                        }
                    )
                    continue
                future = enrichment_executor.submit(
                    run_automatic_enrichment,
                    job_id,
                    candidate,
                    pending_record,
                )
            with enrichment_lock:
                enrichment_futures.add(future)

            def discard_completed(completed: Future[Any]) -> None:
                enrichment_capacity.release()
                with enrichment_lock:
                    enrichment_futures.discard(completed)

            future.add_done_callback(discard_completed)

    def wait_for_candidate_enrichment() -> None:
        with enrichment_lock:
            pending = set(enrichment_futures)
        if pending:
            wait(pending)

    app.state.schedule_candidate_enrichment = schedule_candidate_enrichment
    app.state.wait_for_candidate_enrichment = wait_for_candidate_enrichment

    def persist_claimed_result(result: dict[str, Any]) -> None:
        receipt = str(result.get("receipt", ""))
        job = repo.get_job_summary(str(result.get("job_id", "")))
        if job is None:
            work_queue.ack_result(receipt)
            return
        if JobState(job["status"]) in {
            JobState.COMPLETED,
            JobState.PARTIALLY_COMPLETED,
            JobState.FAILED,
            JobState.CANCELLED,
        }:
            work_queue.ack_result(receipt)
            return
        if result.get("status") == "COMPLETED":
            candidates = list(result.get("result", {}).get("candidates", []))
            for candidate in candidates:
                candidate.setdefault("id", str(uuid.uuid4()))
            repo.save_candidates(job["id"], candidates)
            schedule_candidate_enrichment(str(job["id"]), candidates)
            job["candidate_count"] = len(candidates)
            machine.transition(job, JobState.COMPLETED, "worker result persisted")
        else:
            job["error"] = str(result.get("error", "worker analysis failed"))
            machine.transition(job, JobState.FAILED, "worker returned an error")
        repo.save_job_metadata(job)
        work_queue.ack_result(receipt)

    def process_results_once() -> bool:
        result = work_queue.claim_result(timeout=0)
        if result is None:
            return False
        persist_claimed_result(result)
        return True

    app.state.process_results_once = process_results_once

    def process_due_live_jobs_once() -> bool:
        now = datetime.now(UTC)
        processed = False
        for candidate in repo.list_active_live_jobs():
            status = candidate.get("status")
            end_time = datetime.fromisoformat(str(candidate["end_time"]))
            if end_time > now:
                continue
            current = repo.get_job(str(candidate["id"]))
            if current is None or current.get("status") != status:
                continue
            if status == "CAPTURING":
                machine.transition(
                    current,
                    JobState.UPLOADING,
                    "capture ended; waiting for sensor flow batches",
                )
                repo.save_job_metadata(current)
            elif end_time + timedelta(seconds=config.flow_ingestion_grace_seconds) <= now:
                enqueue_analysis(current)
            else:
                continue
            processed = True
        return processed

    app.state.process_due_live_jobs_once = process_due_live_jobs_once
    result_stop = threading.Event()
    result_consumer_thread: threading.Thread | None = None

    def consume_results() -> None:
        while not result_stop.is_set():
            try:
                process_due_live_jobs_once()
                result = work_queue.claim_result(timeout=1)
                if result is not None:
                    persist_claimed_result(result)
            except Exception:
                result_stop.wait(1)

    @app.on_event("startup")
    def start_result_consumer() -> None:
        nonlocal result_consumer_thread
        if config.environment != "test":
            result_consumer_thread = threading.Thread(target=consume_results, daemon=True)
            result_consumer_thread.start()

    @app.on_event("shutdown")
    def stop_result_consumer() -> None:
        with enrichment_lifecycle_lock:
            enrichment_stopping.set()
        result_stop.set()
        if result_consumer_thread is not None:
            result_consumer_thread.join()
        enrichment_executor.shutdown(wait=True, cancel_futures=False)
        with enrichment_repository_lock:
            for worker_repository in enrichment_repositories:
                worker_repository.close()

    def execute_analysis(job: dict[str, Any]) -> dict[str, Any]:
        apply_job_packet_limit(job)
        for state, reason in (
            (JobState.WAITING_FOR_SENSOR, "sensors selected"),
            (JobState.CAPTURING, "dataset selected"),
            (JobState.UPLOADING, "flow records received"),
            (JobState.INGESTING, "flow records validated"),
            (JobState.ANALYZING, "detectors started"),
        ):
            machine.transition(job, state, reason)
        candidates = calculate(job, job.get("allowlist", []))
        repo.save_candidates(job["id"], candidates)
        schedule_candidate_enrichment(str(job["id"]), candidates)
        job["candidate_count"] = len(candidates)
        job["flow_count"] = len(job.get("flow_records", []))
        job["packet_count"] = sum(
            int(record.get("packet_count", 1)) for record in job.get("flow_records", [])
        )
        machine.transition(job, JobState.COMPLETED, "analysis completed")
        return repo.save_job_metadata(job)

    @app.get("/api/v1/detector-weight-presets")
    def list_detector_weight_presets() -> dict[str, Any]:
        presets = repo.list_detector_weight_presets()
        presets.sort(key=lambda preset: (not bool(preset.get("is_default")), preset["name"]))
        return {"items": presets, "total": len(presets)}

    @app.post("/api/v1/detector-weight-presets", status_code=201)
    def create_detector_weight_preset(
        payload: DetectorWeightPresetCreate,
    ) -> dict[str, Any]:
        now = datetime.now(UTC).isoformat()
        data = payload.model_dump(exclude={"set_as_default"})
        preset = repo.save_detector_weight_preset(
            {
                **data,
                "id": str(uuid.uuid4()),
                "is_default": payload.set_as_default,
                "created_at": now,
                "updated_at": now,
            }
        )
        return preset

    @app.patch("/api/v1/detector-weight-presets/{preset_id}")
    def update_detector_weight_preset(
        preset_id: str, payload: DetectorWeightPresetUpdate
    ) -> dict[str, Any]:
        updates = payload.model_dump(exclude_unset=True, exclude={"set_as_default"})
        updates["updated_at"] = datetime.now(UTC).isoformat()
        preset = repo.update_detector_weight_preset(
            preset_id, updates, set_as_default=payload.set_as_default is True
        )
        if preset is None:
            raise ApiError(
                404,
                "DETECTOR_WEIGHT_PRESET_NOT_FOUND",
                "가중치 preset을 찾을 수 없습니다",
            )
        return preset

    @app.delete("/api/v1/detector-weight-presets/{preset_id}")
    def delete_detector_weight_preset(preset_id: str) -> dict[str, Any]:
        if not repo.delete_detector_weight_preset(preset_id):
            raise ApiError(
                404, "DETECTOR_WEIGHT_PRESET_NOT_FOUND", "가중치 preset을 찾을 수 없습니다"
            )
        return {"deleted": True, "preset_id": preset_id}

    @app.post("/api/v1/analysis-jobs", status_code=201)
    def create_analysis_job(payload: AnalysisJobCreate) -> dict[str, Any]:
        missing = [
            sensor_id for sensor_id in payload.sensor_ids if repo.get_sensor(sensor_id) is None
        ]
        if missing:
            raise ApiError(
                404, "SENSOR_NOT_FOUND", "분석 센서를 찾을 수 없습니다", {"sensor_ids": missing}
            )
        if payload.flow_records and not config.inline_flow_records_enabled:
            raise ApiError(
                409,
                "INLINE_FLOWS_DISABLED",
                "flow_records inline 입력은 테스트/호환 모드에서만 허용됩니다",
            )
        if "detector_weights" not in payload.analysis.model_fields_set:
            configured_default = default_detector_weights()
            if configured_default is not None:
                payload.analysis.detector_weights = configured_default
        ensure_live_capture_bpf_compatible(payload)
        requested_job = build_job(payload)
        requested_job["payload_signatures"] = payload_signature_snapshot()
        requested_job["allowlist"] = allowlist_snapshot()
        job, created = repo.create_job(requested_job)
        if not created:
            return _public_job(job)
        if payload.flow_records:
            job = execute_analysis(job)
        elif not config.inline_flow_records_enabled:
            job = begin_live_capture(job) if payload.mode == "LIVE" else enqueue_analysis(job)
        return _public_job(job)

    @app.post("/api/v1/pcap-analysis-jobs", status_code=201)
    async def create_pcap_analysis_job(
        request: Request,
        name: str = Query(min_length=1, max_length=200),
        filename: str = Query(min_length=1, max_length=255),
        internal_networks: str = Query(default="10.0.0.0/8", min_length=1, max_length=10000),
        description: str = Query(default="", max_length=5000),
        idempotency_key: str | None = Query(default=None, min_length=1, max_length=200),
        minimum_candidate_score: int = Query(default=0, ge=0, le=100),
        minimum_distinct_clients: int = Query(default=3, ge=2, le=100000),
        periodicity_min_samples: int = Query(default=5, ge=3, le=100000),
        detector_weights: str | None = Query(default=None, max_length=2000),
        ml_anomaly_enabled: bool = Query(default=False),
        ml_anomaly_allow_standalone: bool = Query(default=False),
        ml_anomaly_min_population: int = Query(default=30, ge=8, le=100000),
        ml_anomaly_min_candidate_samples: int = Query(default=5, ge=3, le=100000),
        ml_anomaly_z_threshold: float = Query(default=3.5, ge=2.0, le=20.0),
        ml_anomaly_feature_z_floor: float = Query(default=1.0, ge=0.0, le=10.0),
        ml_anomaly_min_directional_features: int = Query(default=2, ge=1, le=6),
        ml_anomaly_contribution_cap: float = Query(default=5.0, ge=0.0, le=5.0),
    ) -> dict[str, Any]:
        try:
            if detector_weights is None:
                normalized_detector_weights = (
                    default_detector_weights() or AnalysisParameters().detector_weights
                )
            else:
                raw_detector_weights = json.loads(detector_weights)
                normalized_detector_weights = AnalysisParameters(
                    detector_weights=raw_detector_weights
                ).detector_weights
        except (json.JSONDecodeError, ValidationError) as exc:
            raise ApiError(
                422,
                "INVALID_DETECTOR_WEIGHTS",
                "탐지 가중치는 알려진 detector 이름과 0~2 사이 숫자를 가진 JSON object여야 합니다",
            ) from exc
        media_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
        supported_media_types = {
            "application/octet-stream",
            "application/vnd.tcpdump.pcap",
            "application/x-pcap",
            "application/x-pcapng",
        }
        if media_type not in supported_media_types:
            raise ApiError(
                415,
                "UNSUPPORTED_PCAP_MEDIA_TYPE",
                "PCAP 업로드는 binary PCAP/PCAPNG content type이어야 합니다",
            )
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                announced_size = int(content_length)
            except ValueError as exc:
                raise ApiError(
                    400, "INVALID_CONTENT_LENGTH", "Content-Length가 유효하지 않습니다"
                ) from exc
            if announced_size > config.pcap_upload_max_bytes:
                raise ApiError(
                    413,
                    "PCAP_TOO_LARGE",
                    f"PCAP 파일은 {config.pcap_upload_max_bytes} bytes 이하여야 합니다",
                )
        uploaded = bytearray()
        async for chunk in request.stream():
            if len(uploaded) + len(chunk) > config.pcap_upload_max_bytes:
                raise ApiError(
                    413,
                    "PCAP_TOO_LARGE",
                    f"PCAP 파일은 {config.pcap_upload_max_bytes} bytes 이하여야 합니다",
                )
            uploaded.extend(chunk)
        if not uploaded:
            raise ApiError(422, "EMPTY_PCAP", "업로드된 PCAP 파일이 비어 있습니다")
        uploaded_bytes = bytes(uploaded)
        del uploaded

        normalized_name = name.strip()
        if not normalized_name:
            raise ApiError(422, "INVALID_ANALYSIS_NAME", "분석 이름은 공백일 수 없습니다")
        safe_filename = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
        if not safe_filename:
            raise ApiError(422, "INVALID_FILENAME", "PCAP 파일명이 유효하지 않습니다")
        cidrs = [value.strip() for value in internal_networks.split(",") if value.strip()]
        digest = hashlib.sha256(uploaded_bytes).hexdigest()
        sensor_id = f"pcap-upload:{digest[:12]}"
        try:
            parsed = await run_in_threadpool(
                parse_pcap,
                uploaded_bytes,
                sensor_id=sensor_id,
                internal_networks=cidrs,
                max_packets=config.pcap_upload_max_packets,
                retain_packet_bytes=False,
            )
        except PcapParseError as exc:
            status = 413 if exc.code == "PCAP_PACKET_LIMIT_EXCEEDED" else 422
            raise ApiError(status, exc.code, str(exc)) from exc

        end_time = parsed.end_time
        if end_time <= parsed.start_time:
            end_time = parsed.start_time + timedelta(microseconds=1)
        payload = AnalysisJobCreate.model_validate(
            {
                "name": normalized_name,
                "idempotency_key": idempotency_key or f"pcap-{digest}-{uuid.uuid4()}",
                "sensor_ids": [sensor_id],
                "mode": "PCAP_UPLOAD",
                "start_time": parsed.start_time,
                "end_time": end_time,
                "capture": {
                    "max_packets": parsed.captured_packet_count,
                    "directions": ["INBOUND", "OUTBOUND", "UNKNOWN"],
                    "store_pcap": True,
                },
                "analysis": {
                    "profile": "ddos_botnet",
                    "minimum_candidate_score": minimum_candidate_score,
                    "minimum_distinct_clients": minimum_distinct_clients,
                    "periodicity_min_samples": periodicity_min_samples,
                    "detector_weights": normalized_detector_weights,
                    "ml_anomaly_enabled": ml_anomaly_enabled,
                    "ml_anomaly_allow_standalone": ml_anomaly_allow_standalone,
                    "ml_anomaly_min_population": ml_anomaly_min_population,
                    "ml_anomaly_min_candidate_samples": ml_anomaly_min_candidate_samples,
                    "ml_anomaly_z_threshold": ml_anomaly_z_threshold,
                    "ml_anomaly_feature_z_floor": ml_anomaly_feature_z_floor,
                    "ml_anomaly_min_directional_features": ml_anomaly_min_directional_features,
                    "ml_anomaly_contribution_cap": ml_anomaly_contribution_cap,
                },
                "internal_networks": cidrs,
                "flow_records": list(parsed.records),
            }
        )
        job = build_job(payload, dataset_id=f"pcap:{digest}")
        job["payload_signatures"] = payload_signature_snapshot()
        job["allowlist"] = allowlist_snapshot()
        job["description"] = description
        job["source"] = {
            "filename": safe_filename,
            "capture_format": parsed.capture_format,
            "size_bytes": len(uploaded_bytes),
            "sha256": digest,
            "packet_bytes_retained": True,
            "captured_packet_count": parsed.captured_packet_count,
            "parsed_packet_count": parsed.parsed_packet_count,
            "skipped_packet_count": parsed.skipped_packet_count,
            "link_types": list(parsed.link_types),
        }
        job, created = repo.create_job(job)
        if not created:
            return _public_job(job)
        try:
            repo.save_job_capture(job["id"], uploaded_bytes)
        except Exception as exc:
            repo.delete_job(job["id"])
            raise ApiError(
                503,
                "PCAP_STORAGE_UNAVAILABLE",
                "업로드한 PCAP 원본을 저장하지 못했습니다",
            ) from exc
        del uploaded_bytes
        if isinstance(work_queue, MemoryControllerQueue):
            return _public_job(execute_analysis(job))
        for state, reason in (
            (JobState.WAITING_FOR_SENSOR, "uploaded capture accepted"),
            (JobState.CAPTURING, "uploaded immutable capture selected"),
            (JobState.UPLOADING, "uploaded packet records decoded"),
            (JobState.INGESTING, "uploaded flow records validated"),
            (JobState.ANALYZING, "uploaded capture analysis enqueued"),
        ):
            machine.transition(job, state, reason)
        saved = repo.save_job_metadata(job)
        enqueue_worker_job(job)
        return _public_job(saved)

    @app.get("/api/v1/analysis-jobs")
    def list_analysis_jobs(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        status: str | None = None,
        source_type: str | None = None,
        search: str | None = Query(default=None, max_length=200),
        sort: str = "-created_at",
    ) -> dict[str, Any]:
        items = repo.list_jobs()
        if status:
            items = [item for item in items if item["status"] == status]
        if source_type:
            items = [item for item in items if item.get("source_type") == source_type]
        if search:
            normalized = search.casefold()
            items = [
                item
                for item in items
                if normalized in str(item.get("name", "")).casefold()
                or normalized in str(item.get("description", "")).casefold()
            ]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"created_at", "updated_at", "name", "status", "source_type"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        summaries = []
        for item in items:
            summary = {
                key: value
                for key, value in item.items()
                if key not in {"flow_records", "transitions"}
            }
            candidate_count = item.get("candidate_count")
            if candidate_count is None:
                candidate_count = len(repo.get_candidates(item["id"]))
            summary["candidate_count"] = int(candidate_count)
            summaries.append(summary)
        return _page(summaries, page, page_size)

    @app.get("/api/v1/analysis-jobs/{job_id}")
    def get_analysis_job(job_id: str) -> dict[str, Any]:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        return _public_job(job)

    @app.post("/api/v1/analysis-jobs/{job_id}/ai-runs", status_code=201)
    def create_ai_analysis_run(
        job_id: str,
        payload: AIAnalysisRunCreate,
        request: Request,
        response: Response,
    ) -> dict[str, Any]:
        if not config.ai_analysis_enabled or ai_service is None or ai_tasks is None:
            raise ApiError(503, "AI_ANALYSIS_DISABLED", "AI 분석 기능이 비활성화되어 있습니다")
        principal = getattr(request.state, "principal", None)
        created_by = str(getattr(principal, "subject", "anonymous"))
        try:
            run, created = ai_service.create_run(
                analysis_job_id=job_id,
                idempotency_key=payload.idempotency_key,
                candidate_limit=payload.candidate_limit,
                created_by=created_by,
            )
        except AIAnalysisError as exc:
            message = str(exc)
            if message == "analysis job not found":
                raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다") from exc
            raise ApiError(409, "AI_RUN_NOT_ALLOWED", message) from exc
        if not created:
            response.status_code = 200
        else:
            started = perf_counter()
            try:
                ai_tasks.enqueue(run["id"])
            except Exception as exc:
                reason = type(exc).__name__
                safe_ai_metric(lambda: ai_enqueue_failures.labels(reason=reason).inc())
                raise
            finally:
                waiting_depth: int | None
                try:
                    waiting_depth = ai_tasks.depth()
                except Exception:
                    waiting_depth = None
                if waiting_depth is not None:
                    safe_ai_metric(lambda: ai_queue_waiting_depth.set(waiting_depth))
                safe_ai_metric(
                    lambda: ai_enqueue_latency.labels(provider=config.ai_model_provider).observe(
                        perf_counter() - started
                    )
                )
            stored_run = repo.get_ai_run(run["id"])
            if stored_run is None:
                raise ApiError(
                    500,
                    "AI_RUN_PERSISTENCE_ERROR",
                    "AI Run 저장 상태를 읽을 수 없습니다",
                )
            run = stored_run
        repo.append_audit_event(
            "ai-run-create",
            run["id"],
            {
                "analysis_job_id": job_id,
                "created_by": created_by,
                "created": created,
                "status": run["status"],
            },
        )
        return {**run, "candidate_count": len(run.get("candidate_ids", []))}

    @app.get("/api/v1/analysis-jobs/{job_id}/ai-runs")
    def list_ai_analysis_runs(
        job_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        if repo.get_job_summary(job_id) is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        runs = [
            {**run, "candidate_count": len(run.get("candidate_ids", []))}
            for run in repo.list_ai_runs(job_id)
        ]
        return _page(runs, page, page_size)

    @app.get("/api/v1/ai-runs/{run_id}")
    def get_ai_analysis_run(run_id: str) -> dict[str, Any]:
        run = repo.get_ai_run(run_id)
        if run is None:
            raise ApiError(404, "AI_RUN_NOT_FOUND", "AI 분석 Run을 찾을 수 없습니다")
        return {**run, "candidate_count": len(run.get("candidate_ids", []))}

    @app.get("/api/v1/ai-runs/{run_id}/assessments")
    def list_ai_analysis_assessments(
        run_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        if repo.get_ai_run(run_id) is None:
            raise ApiError(404, "AI_RUN_NOT_FOUND", "AI 분석 Run을 찾을 수 없습니다")
        assessments = sorted(
            repo.list_ai_assessments(run_id),
            key=lambda item: (
                -int(item.get("review_priority", 0)),
                str(item.get("created_at", "")),
            ),
        )
        return _page(assessments, page, page_size)

    @app.get("/api/v1/ai-assessments/{assessment_id}")
    def get_ai_analysis_assessment(assessment_id: str) -> dict[str, Any]:
        assessment = repo.get_ai_assessment(assessment_id)
        if assessment is None:
            raise ApiError(404, "AI_ASSESSMENT_NOT_FOUND", "AI 후보 판정을 찾을 수 없습니다")
        return assessment

    @app.get("/api/v1/ai-assessments/{assessment_id}/feedback")
    def list_ai_feedback(assessment_id: str) -> dict[str, Any]:
        try:
            feedback = AIFeedbackService(repo).list(assessment_id)
        except AIFeedbackError as exc:
            raise ApiError(404, "AI_ASSESSMENT_NOT_FOUND", str(exc)) from exc
        return {"items": feedback, "total": len(feedback)}

    @app.post("/api/v1/ai-assessments/{assessment_id}/feedback", status_code=201)
    def create_ai_feedback(
        assessment_id: str, payload: AIFeedbackCreate, request: Request
    ) -> dict[str, Any]:
        principal = getattr(request.state, "principal", None)
        created_by = str(getattr(principal, "subject", "anonymous"))
        try:
            feedback = AIFeedbackService(repo).append(
                assessment_id=assessment_id,
                verdict=payload.verdict,
                corrected_confidence=payload.corrected_confidence,
                note=payload.note,
                created_by=created_by,
            )
        except AIFeedbackError as exc:
            raise ApiError(404, "AI_ASSESSMENT_NOT_FOUND", str(exc)) from exc
        repo.append_audit_event(
            "ai-feedback-create",
            feedback["id"],
            {
                "assessment_id": assessment_id,
                "verdict": payload.verdict,
                "created_by": created_by,
            },
        )
        safe_ai_metric(lambda: ai_feedback.labels(verdict=payload.verdict).inc())
        return feedback

    @app.get("/api/v1/ai-assessments/{assessment_id}/evidence-bundle")
    def get_ai_analysis_evidence_bundle(assessment_id: str, request: Request) -> dict[str, Any]:
        assessment = repo.get_ai_assessment(assessment_id)
        if assessment is None:
            raise ApiError(404, "AI_ASSESSMENT_NOT_FOUND", "AI 후보 판정을 찾을 수 없습니다")
        bundle = assessment.get("evidence_bundle")
        if not isinstance(bundle, dict):
            raise ApiError(404, "EVIDENCE_BUNDLE_NOT_FOUND", "Evidence Bundle을 찾을 수 없습니다")
        principal = getattr(request.state, "principal", None)
        repo.append_audit_event(
            "ai-evidence-bundle-view",
            assessment_id,
            {"viewed_by": str(getattr(principal, "subject", "anonymous"))},
        )
        return bundle

    @app.get("/api/v1/ai-assessments/{assessment_id}/artifacts")
    def list_ai_artifacts(
        assessment_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        if repo.get_ai_assessment(assessment_id) is None:
            raise ApiError(404, "AI_ASSESSMENT_NOT_FOUND", "AI 후보 판정을 찾을 수 없습니다")
        return _page(repo.list_ai_artifacts(assessment_id), page, page_size)

    @app.get("/api/v1/ai-artifacts/{artifact_id}")
    def get_ai_artifact(artifact_id: str) -> dict[str, Any]:
        artifact = repo.get_ai_artifact(artifact_id)
        if artifact is None:
            raise ApiError(404, "AI_ARTIFACT_NOT_FOUND", "AI 생성 초안을 찾을 수 없습니다")
        return artifact

    @app.post("/api/v1/ai-assessments/{assessment_id}/artifacts/regenerate", status_code=201)
    def regenerate_ai_artifacts(assessment_id: str, request: Request) -> dict[str, Any]:
        stored = repo.get_ai_assessment(assessment_id)
        if stored is None:
            raise ApiError(404, "AI_ASSESSMENT_NOT_FOUND", "AI 후보 판정을 찾을 수 없습니다")
        try:
            assessment = CandidateAssessment.model_validate(stored.get("assessment"))
            bundle = CandidateEvidenceBundle.model_validate(stored.get("evidence_bundle"))
            artifacts = build_ai_artifacts(
                assessment_id=assessment_id,
                ai_run_id=str(stored["ai_run_id"]),
                analysis_job_id=str(stored["analysis_job_id"]),
                assessment=assessment,
                bundle=bundle,
            )
        except (AIArtifactError, ValidationError, KeyError, TypeError, ValueError) as exc:
            raise ApiError(409, "AI_ARTIFACT_REGENERATION_FAILED", str(exc)) from exc
        for artifact in artifacts:
            repo.save_ai_artifact(artifact)
        principal = getattr(request.state, "principal", None)
        repo.append_audit_event(
            "ai-artifacts-regenerate",
            assessment_id,
            {
                "regenerated_by": str(getattr(principal, "subject", "anonymous")),
                "artifact_ids": [artifact["id"] for artifact in artifacts],
            },
        )
        return {"items": artifacts, "total": len(artifacts)}

    def review_ai_artifact(
        artifact_id: str,
        payload: AIArtifactReview,
        request: Request,
        status: Literal["APPROVED", "REJECTED"],
    ) -> dict[str, Any]:
        principal = getattr(request.state, "principal", None)
        reviewed_by = str(getattr(principal, "subject", "anonymous"))
        try:
            artifact = AIArtifactService(repo).review(
                artifact_id,
                status=status,
                reviewed_by=reviewed_by,
                note=payload.note,
            )
        except AIArtifactError as exc:
            code = (
                "AI_ARTIFACT_NOT_FOUND"
                if str(exc) == "AI artifact not found"
                else "AI_ARTIFACT_REVIEW_CONFLICT"
            )
            status_code = 404 if code == "AI_ARTIFACT_NOT_FOUND" else 409
            raise ApiError(status_code, code, str(exc)) from exc
        repo.append_audit_event(
            f"ai-artifact-{status.lower()}",
            artifact_id,
            {"reviewed_by": reviewed_by, "note": payload.note},
        )
        return artifact

    @app.post("/api/v1/ai-artifacts/{artifact_id}/approve")
    def approve_ai_artifact(
        artifact_id: str, payload: AIArtifactReview, request: Request
    ) -> dict[str, Any]:
        return review_ai_artifact(artifact_id, payload, request, "APPROVED")

    @app.post("/api/v1/ai-artifacts/{artifact_id}/reject")
    def reject_ai_artifact(
        artifact_id: str, payload: AIArtifactReview, request: Request
    ) -> dict[str, Any]:
        return review_ai_artifact(artifact_id, payload, request, "REJECTED")

    @app.post("/api/v1/ai-runs/{run_id}/cancel")
    def cancel_ai_analysis_run(
        run_id: str, payload: AIAnalysisRunCancel, request: Request
    ) -> dict[str, Any]:
        if ai_service is None:
            raise ApiError(503, "AI_ANALYSIS_DISABLED", "AI 분석 기능이 비활성화되어 있습니다")
        try:
            run = ai_service.cancel(run_id, payload.reason)
        except AIAnalysisError as exc:
            raise ApiError(404, "AI_RUN_NOT_FOUND", "AI 분석 Run을 찾을 수 없습니다") from exc
        principal = getattr(request.state, "principal", None)
        repo.append_audit_event(
            "ai-run-cancel",
            run_id,
            {
                "cancelled_by": str(getattr(principal, "subject", "anonymous")),
                "reason": payload.reason,
                "status": run["status"],
            },
        )
        return {**run, "candidate_count": len(run.get("candidate_ids", []))}

    @app.get("/api/v1/analysis-jobs/{job_id}/flows")
    def list_analysis_flows(
        job_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        candidate_ip: str | None = Query(default=None, max_length=49),
        direction: str | None = Query(
            default=None, pattern=r"^(INBOUND|OUTBOUND|BIDIRECTIONAL|UNKNOWN)$"
        ),
        protocol: str | None = Query(default=None, min_length=1, max_length=32),
        port: int | None = Query(default=None, ge=0, le=65535),
        source_port: int | None = Query(default=None, ge=0, le=65535),
        destination_port: int | None = Query(default=None, ge=0, le=65535),
        has_payload: bool | None = None,
        exclude_matches: bool = False,
        include_filter: Annotated[list[str] | None, Query(max_length=512)] = None,
        exclude_filter: Annotated[list[str] | None, Query(max_length=512)] = None,
    ) -> dict[str, Any]:
        job = repo.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        try:
            matched = filter_flows(
                job,
                labels=repo.list_flow_labels(job_id),
                candidate_ip=candidate_ip,
                direction=direction,
                protocol=protocol,
                port=port,
                source_port=source_port,
                destination_port=destination_port,
                has_payload=has_payload,
                exclude_matches=exclude_matches,
                include_filters=[json.loads(value) for value in include_filter or []],
                exclude_filters=[json.loads(value) for value in exclude_filter or []],
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            if exclude_matches and "exclusion condition" in str(exc):
                raise ApiError(
                    422,
                    "INVALID_FLOW_EXCLUSION",
                    "제외 모드에는 하나 이상의 flow 조건이 필요합니다",
                ) from exc
            raise ApiError(
                422,
                "INVALID_ENDPOINT_FILTER",
                "Endpoint IP 또는 CIDR 형식이 올바르지 않습니다",
            ) from exc
        return _page(matched, page, page_size)

    @app.get("/api/v1/analysis-jobs/{job_id}/flows/{requested_flow_id}/payload-preview")
    def get_flow_payload_preview(job_id: str, requested_flow_id: str) -> dict[str, Any]:
        job = repo.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        record = next(
            (
                dict(item)
                for item in job.get("flow_records", [])
                if flow_id(job_id, dict(item)) == requested_flow_id
            ),
            None,
        )
        if record is None:
            raise ApiError(404, "FLOW_NOT_FOUND", "분석 작업에서 Flow를 찾을 수 없습니다")

        sample = str(record.get("payload_sample_hex") or "")
        if not sample:
            retained_capture = repo.get_job_capture(job_id)
            if retained_capture is None:
                raise ApiError(
                    409,
                    "PAYLOAD_PREVIEW_UNAVAILABLE",
                    (
                        "보존된 source PCAP 또는 Sensor payload sample이 없습니다. "
                        "Sensor capture.payload_preview_bytes를 1~256으로 설정한 뒤 "
                        "새 트래픽을 수집해야 합니다"
                    ),
                )
            try:
                decoded = find_pcap_record(
                    retained_capture,
                    sensor_id=str(job["sensor_ids"][0]),
                    internal_networks=list(job["internal_networks"]),
                    max_packets=config.pcap_upload_max_packets,
                    retain_payload_sample_bytes=256,
                    predicate=lambda item: flow_id(job_id, item) == requested_flow_id,
                )
            except PcapParseError as exc:
                raise ApiError(422, exc.code, str(exc)) from exc
            if decoded is None:
                raise ApiError(404, "FLOW_NOT_FOUND", "분석 작업에서 Flow를 찾을 수 없습니다")
            record = decoded
            sample = str(record.get("payload_sample_hex") or "")
        if not sample:
            raise ApiError(
                409,
                "PAYLOAD_PREVIEW_UNAVAILABLE",
                "선택한 Flow에 미리볼 Payload가 없습니다",
            )
        try:
            sample_bytes = bytes.fromhex(sample)
        except ValueError as exc:
            raise ApiError(
                409,
                "PAYLOAD_PREVIEW_CORRUPT",
                "저장된 Payload sample 형식이 올바르지 않습니다",
            ) from exc
        return {
            "flow_id": requested_flow_id,
            "payload_hex": sample,
            "payload_ascii": payload_ascii(sample),
            "sample_bytes": len(sample_bytes),
            "payload_length": record.get("payload_length"),
            "truncated": int(record.get("payload_length", 0)) > len(sample_bytes),
            "payload_hash": record.get("payload_hash"),
        }

    @app.get("/api/v1/analysis-jobs/{job_id}/flow-labels")
    def list_job_flow_labels(
        job_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
    ) -> dict[str, Any]:
        if repo.get_job_summary(job_id) is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        labels = repo.list_flow_labels(job_id)
        return _page(labels, page, page_size)

    @app.post("/api/v1/analysis-jobs/{job_id}/flow-labels", status_code=201)
    def create_flow_label(job_id: str, payload: FlowLabelCreate) -> dict[str, Any]:
        job = repo.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        selected = next(
            (
                item
                for item in filter_flows(job, labels=repo.list_flow_labels(job_id))
                if item["flow_id"] == payload.flow_id
            ),
            None,
        )
        if selected is None:
            raise ApiError(404, "FLOW_NOT_FOUND", "분석 작업에서 Flow를 찾을 수 없습니다")
        if payload.create_signature and not selected.get("payload_hash"):
            raise ApiError(
                422,
                "PAYLOAD_FEATURES_UNAVAILABLE",
                "Payload hash가 없는 Flow에서는 signature를 만들 수 없습니다",
            )
        if payload.create_signature:
            latest: dict[tuple[str, str], dict[str, Any]] = {}
            for stored_label in repo.list_flow_labels():
                key = (
                    str(stored_label["job_id"]),
                    str(stored_label["flow_id"]),
                )
                if str(stored_label.get("created_at", "")) >= str(
                    latest.get(key, {}).get("created_at", "")
                ):
                    latest[key] = stored_label
            conflict = next(
                (
                    label
                    for label in latest.values()
                    if label.get("verdict") == "BENIGN"
                    and label.get("flow_snapshot", {}).get("payload_hash")
                    == selected.get("payload_hash")
                ),
                None,
            )
            if conflict is not None:
                raise ApiError(
                    409,
                    "BENIGN_SIGNATURE_CONFLICT",
                    "동일 Payload hash에 대한 최신 BENIGN 라벨이 있습니다",
                    {
                        "job_id": conflict["job_id"],
                        "flow_id": conflict["flow_id"],
                    },
                )
        now = datetime.now(UTC).isoformat()
        label = repo.save_flow_label(
            {
                "id": str(uuid.uuid4()),
                "job_id": job_id,
                "flow_id": payload.flow_id,
                "verdict": payload.verdict,
                "confidence": payload.confidence,
                "note": payload.note,
                "flow_snapshot": label_snapshot(selected),
                "created_by": "analyst",
                "created_at": now,
            }
        )
        signature = None
        if payload.create_signature:
            feature_fields = (
                "payload_hash",
                "payload_prefix_hash",
                "payload_length",
                "payload_entropy",
                "payload_printable_ratio",
                "payload_simhash",
                "payload_feature_version",
            )
            signature = {
                "id": str(uuid.uuid4()),
                "name": payload.signature_name
                or f"{selected.get('protocol', 'payload')} {str(selected['payload_hash'])[:12]}",
                "description": payload.signature_description or payload.note,
                "version": 1,
                "enabled": True,
                "source_job_id": job_id,
                "source_flow_id": payload.flow_id,
                "source_label_id": label["id"],
                "protocol": selected.get("protocol"),
                "direction": selected.get("direction"),
                "service_port": selected.get("service_port"),
                "length_tolerance_ratio": 0.15,
                "entropy_tolerance": 0.75,
                "simhash_max_distance": 8,
                "created_by": "analyst",
                "created_at": now,
                "updated_at": now,
                **{
                    field: selected[field]
                    for field in feature_fields
                    if selected.get(field) is not None
                },
            }
            signature = repo.save_payload_signature(signature)
        return {"label": label, "signature": signature}

    @app.get("/api/v1/analysis-jobs/{job_id}/flows/{requested_flow_id}/detection-guidance")
    def get_detection_guidance(job_id: str, requested_flow_id: str) -> dict[str, Any]:
        job = repo.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        labels = [
            label
            for label in repo.list_flow_labels(job_id)
            if str(label.get("flow_id")) == requested_flow_id
        ]
        latest = max(labels, key=lambda item: str(item.get("created_at", "")), default=None)
        if latest is None or latest.get("verdict") != "C2":
            raise ApiError(
                409,
                "C2_LABEL_REQUIRED",
                "최신 수동 판정이 C2인 Flow에서만 탐지 조정 가이드를 만들 수 있습니다",
            )
        try:
            return build_detection_guidance(
                job,
                requested_flow_id,
                allowlist=list(job.get("allowlist", [])),
            )
        except LookupError as exc:
            raise ApiError(404, "FLOW_NOT_FOUND", "분석 작업에서 Flow를 찾을 수 없습니다") from exc
        except ValueError as exc:
            raise ApiError(
                422,
                "EXTERNAL_ENDPOINT_UNAVAILABLE",
                "내부·외부 endpoint를 구분할 수 없는 Flow입니다",
            ) from exc

    @app.patch("/api/v1/analysis-jobs/{job_id}")
    def update_analysis_job(job_id: str, payload: AnalysisJobUpdate) -> dict[str, Any]:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        changes: dict[str, dict[str, Any]] = {}
        for field in payload.model_fields_set:
            value = getattr(payload, field)
            if job.get(field) != value:
                changes[field] = {"from": job.get(field), "to": value}
                job[field] = value
        if changes:
            occurred_at = datetime.now(UTC).isoformat()
            job["updated_at"] = occurred_at
            job.setdefault("metadata_updates", []).append(
                {"occurred_at": occurred_at, "changes": changes}
            )
            return _public_job(repo.save_job_metadata(job))
        return _public_job(job)

    @app.delete("/api/v1/analysis-jobs/{job_id}", status_code=204)
    def delete_analysis_job(job_id: str) -> Response:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        if JobState(job["status"]) not in {
            JobState.COMPLETED,
            JobState.PARTIALLY_COMPLETED,
            JobState.FAILED,
            JobState.CANCELLED,
        }:
            raise ApiError(409, "JOB_NOT_TERMINAL", "진행 중인 분석 작업은 삭제할 수 없습니다")
        if not repo.delete_job(job_id):
            if repo.get_job_summary(job_id) is not None:
                raise ApiError(
                    409,
                    "AI_RUN_ACTIVE",
                    "진행 중인 AI 분석 Run이 있는 작업은 삭제할 수 없습니다",
                )
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        return Response(status_code=204)

    @app.post("/api/v1/analysis-jobs/{job_id}/cancel")
    def cancel_analysis_job(job_id: str, payload: CancelRequest) -> dict[str, Any]:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        if job["status"] == JobState.CANCELLED:
            return _public_job(job)
        if JobState(job["status"]) in {
            JobState.COMPLETED,
            JobState.PARTIALLY_COMPLETED,
            JobState.FAILED,
        }:
            raise ApiError(409, "INVALID_JOB_STATE", "종료된 작업은 취소할 수 없습니다")
        machine.transition(job, JobState.CANCELLED, payload.reason)
        return _public_job(repo.save_job_metadata(job))

    @app.post("/api/v1/analysis-jobs/{job_id}/reanalyze", status_code=201)
    def reanalyze(job_id: str, payload: ReanalysisRequest) -> dict[str, Any]:
        source = repo.get_job(job_id)
        if source is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        source_capture = source.get("capture", {})
        if not isinstance(source_capture, dict):
            raise ApiError(
                409,
                "REANALYSIS_SOURCE_INVALID",
                "저장된 분석 작업의 capture 설정이 올바르지 않습니다",
            )
        try:
            capture_parameters = CaptureParameters.model_validate(
                {
                    field: source_capture[field]
                    for field in CaptureParameters.model_fields
                    if field in source_capture
                }
            ).model_dump(mode="json")
        except ValidationError as exc:
            raise ApiError(
                409,
                "REANALYSIS_SOURCE_INVALID",
                "저장된 분석 작업의 capture 설정이 올바르지 않습니다",
            ) from exc
        parameters = dict(source["analysis"])
        for field in ("minimum_candidate_score", "minimum_distinct_clients"):
            value = getattr(payload, field)
            if value is not None:
                parameters[field] = value
        if payload.detector_weights is not None:
            parameters["detector_weights"] = payload.detector_weights
        request = AnalysisJobCreate.model_validate(
            {
                "name": f"{source['name']}-reanalyze",
                "idempotency_key": payload.idempotency_key,
                "sensor_ids": source["sensor_ids"],
                "mode": "REANALYSIS",
                "start_time": source["start_time"],
                "end_time": source["end_time"],
                "capture": capture_parameters,
                "analysis": parameters,
                "internal_networks": source["internal_networks"],
                "flow_records": source["flow_records"],
            }
        )
        reanalysis_job = build_job(request, parent_job_id=job_id, dataset_id=source["dataset_id"])
        reanalysis_job["payload_signatures"] = payload_signature_snapshot()
        reanalysis_job["allowlist"] = allowlist_snapshot()
        reanalysis_job["source_type"] = source.get("source_type", "SENSOR_CAPTURE")
        if source.get("source"):
            reanalysis_job["source"] = dict(source["source"])
        job, created = repo.create_job(reanalysis_job)
        if not created:
            return _public_job(job)
        if not config.inline_flow_records_enabled:
            for state, reason in (
                (JobState.WAITING_FOR_SENSOR, "source sensors reused"),
                (JobState.CAPTURING, "source immutable dataset reused"),
                (JobState.UPLOADING, "source flow snapshot selected"),
                (JobState.INGESTING, "reanalysis parameters validated"),
                (JobState.ANALYZING, "durable reanalysis job enqueued"),
            ):
                machine.transition(job, state, reason)
            saved = repo.save_job_metadata(job)
            enqueue_worker_job(job)
            return _public_job(saved)
        return _public_job(execute_analysis(job) if job["flow_records"] else job)

    @app.get("/api/v1/analysis-jobs/{job_id}/candidates")
    def list_candidates(
        job_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        severity: str | None = None,
        verdict: Annotated[
            str | None,
            Query(pattern=r"^(UNREVIEWED|UNDER_REVIEW|CONFIRMED_C2|FALSE_POSITIVE)$"),
        ] = None,
        workflow_status: Annotated[
            str | None,
            Query(
                pattern=r"^(NEEDS_REVIEW|IN_REVIEW|ACTION_REQUIRED|ACTION_IN_PROGRESS|ACTION_COMPLETED|FALSE_POSITIVE)$"
            ),
        ] = None,
        minimum_score: int = Query(0, ge=0, le=100),
        include_suppressed: bool = False,
        sort: str = "-score",
    ) -> dict[str, Any]:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        workflow = _candidate_workflow_index(repo)
        items = [
            _public_candidate(_with_candidate_workflow(item, workflow), job)
            for item in repo.get_candidates(job_id)
            if item["score"] >= minimum_score
            and (
                include_suppressed or verdict == "FALSE_POSITIVE" or not item.get("excluded", False)
            )
        ]
        workflow_counts = _candidate_workflow_counts(items)
        if severity:
            items = [item for item in items if item["severity"] == severity]
        if verdict:
            items = [item for item in items if _candidate_verdict(item) == verdict]
        if workflow_status:
            items = [item for item in items if _candidate_workflow_status(item) == workflow_status]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"score", "candidate_ip", "first_seen", "last_seen", "severity"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        response = _page(items, page, page_size)
        response["workflow_counts"] = workflow_counts
        return response

    @app.get("/api/v1/analysis-jobs/{job_id}/candidates/{candidate_id}")
    def get_candidate(job_id: str, candidate_id: str) -> dict[str, Any]:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        candidate = next(
            (item for item in repo.get_candidates(job_id) if item["id"] == candidate_id), None
        )
        if candidate is None:
            raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
        if "traffic_buckets" not in candidate:
            job = repo.get_job(job_id) or job
        workflow = _candidate_workflow_index(repo, candidate_id)
        return _public_candidate(
            _with_candidate_workflow(candidate, workflow), job, include_traffic=True
        )

    @app.get("/api/v1/candidates")
    def list_all_candidates(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        severity: str | None = None,
        verdict: Annotated[
            str | None,
            Query(pattern=r"^(UNREVIEWED|UNDER_REVIEW|CONFIRMED_C2|FALSE_POSITIVE)$"),
        ] = None,
        workflow_status: Annotated[
            str | None,
            Query(
                pattern=r"^(NEEDS_REVIEW|IN_REVIEW|ACTION_REQUIRED|ACTION_IN_PROGRESS|ACTION_COMPLETED|FALSE_POSITIVE)$"
            ),
        ] = None,
        minimum_score: int = Query(0, ge=0, le=100),
        include_suppressed: bool = False,
        sort: str = "-score",
    ) -> dict[str, Any]:
        jobs = {str(job["id"]): job for job in repo.list_jobs()}
        workflow = _candidate_workflow_index(repo)
        items: list[dict[str, Any]] = []
        for job_id, candidates in repo.list_candidate_sets().items():
            job = jobs.get(job_id)
            if job is None:
                continue
            items.extend(
                _public_candidate(_with_candidate_workflow(candidate, workflow), job)
                for candidate in candidates
                if candidate["score"] >= minimum_score
                and (
                    include_suppressed
                    or verdict == "FALSE_POSITIVE"
                    or not candidate.get("excluded", False)
                )
            )
        workflow_counts = _candidate_workflow_counts(items)
        if severity:
            items = [item for item in items if item["severity"] == severity]
        if verdict:
            items = [item for item in items if _candidate_verdict(item) == verdict]
        if workflow_status:
            items = [item for item in items if _candidate_workflow_status(item) == workflow_status]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"score", "candidate_ip", "first_seen", "last_seen", "severity"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        response = _page(items, page, page_size)
        response["workflow_counts"] = workflow_counts
        return response

    @app.get("/api/v1/candidates/{candidate_id}")
    def get_global_candidate(candidate_id: str) -> dict[str, Any]:
        jobs = {str(job["id"]): job for job in repo.list_jobs()}
        workflow = _candidate_workflow_index(repo, candidate_id)
        for job_id, candidates in repo.list_candidate_sets().items():
            candidate = next(
                (item for item in candidates if item["id"] == candidate_id),
                None,
            )
            if candidate is not None:
                job = jobs.get(job_id)
                if job is None:
                    break
                if "traffic_buckets" not in candidate:
                    job = repo.get_job(job_id) or job
                return _public_candidate(
                    _with_candidate_workflow(candidate, workflow), job, include_traffic=True
                )
        raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")

    @app.patch("/api/v1/candidates/{candidate_id}")
    def update_candidate(candidate_id: str, payload: CandidateUpdate) -> dict[str, Any]:
        """Update a candidate's metadata (score adjustment or exclusion)."""
        # Find which job contains this candidate by searching all jobs
        for job in repo.list_jobs():
            candidates = repo.get_candidates(str(job["id"]))
            for candidate in candidates:
                if candidate.get("id") == candidate_id:
                    updates: dict[str, Any] = {}
                    if payload.score_adjustment is not None:
                        updates["score_adjustment"] = payload.score_adjustment
                    if payload.exclude_reason is not None:
                        updates["exclude_reason"] = payload.exclude_reason

                    updated = repo.update_candidate(candidate_id, updates)
                    if updated is not None:
                        return _public_candidate(updated, job)
        raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")

    @app.post("/api/v1/candidates/{candidate_id}/verdicts")
    def create_candidate_verdict(
        candidate_id: str, payload: CandidateVerdictCreate, request: Request
    ) -> dict[str, Any]:
        found = _find_candidate(repo, candidate_id)
        if found is None:
            raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
        job, candidate = found
        decision = {
            "id": str(uuid.uuid4()),
            "candidate_id": candidate_id,
            "job_id": str(job["id"]),
            "candidate_ip": str(candidate["candidate_ip"]),
            **payload.model_dump(),
            "created_by": _request_actor(request),
            "created_at": datetime.now(UTC).isoformat(),
        }
        with candidate_action_lock:
            repo.save_candidate_decision(decision)
            if payload.verdict == "CONFIRMED_C2":
                repo.save_candidate_action(
                    {
                        "id": str(uuid.uuid4()),
                        "candidate_id": candidate_id,
                        "verdict_id": decision["id"],
                        "job_id": str(job["id"]),
                        "candidate_ip": str(candidate["candidate_ip"]),
                        "status": "PENDING",
                        "note": "CONFIRMED_C2 판정으로 후속 조치가 생성되었습니다",
                        "created_by": _request_actor(request),
                        "created_at": decision["created_at"],
                    }
                )
        refreshed = _find_candidate(repo, candidate_id)
        if refreshed is None:
            raise ApiError(409, "CANDIDATE_UPDATE_CONFLICT", "후보 판정을 저장하지 못했습니다")
        return _public_candidate(refreshed[1], job, include_traffic=True)

    @app.post("/api/v1/candidates/{candidate_id}/actions")
    def create_candidate_action(
        candidate_id: str, payload: CandidateActionCreate, request: Request
    ) -> dict[str, Any]:
        with candidate_action_lock:
            found = _find_candidate(repo, candidate_id)
            if found is None:
                raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
            job, candidate = found
            current_verdict = candidate.get("current_verdict")
            if (
                not isinstance(current_verdict, dict)
                or current_verdict.get("verdict") != "CONFIRMED_C2"
            ):
                raise ApiError(
                    409,
                    "CANDIDATE_NOT_CONFIRMED",
                    "CONFIRMED_C2 판정 후에만 대응 조치 상태를 변경할 수 있습니다",
                )
            current_action = candidate.get("current_action")
            if isinstance(current_action, dict) and current_action.get("status") == "COMPLETED":
                raise ApiError(409, "CANDIDATE_ACTION_COMPLETED", "이미 완료된 대응 조치입니다")
            if isinstance(current_action, dict) and current_action.get("status") == payload.status:
                raise ApiError(409, "CANDIDATE_ACTION_UNCHANGED", "현재 조치 상태와 동일합니다")
            created_at = datetime.now(UTC).isoformat()
            action = {
                "id": str(uuid.uuid4()),
                "candidate_id": candidate_id,
                "verdict_id": str(current_verdict["id"]),
                "job_id": str(job["id"]),
                "candidate_ip": str(candidate["candidate_ip"]),
                **payload.model_dump(),
                "created_by": _request_actor(request),
                "created_at": created_at,
                "completed_at": created_at if payload.status == "COMPLETED" else None,
            }
            repo.save_candidate_action(action)
            refreshed = _find_candidate(repo, candidate_id)
            if refreshed is None:
                raise ApiError(409, "CANDIDATE_UPDATE_CONFLICT", "조치 상태를 저장하지 못했습니다")
            return _public_candidate(refreshed[1], job, include_traffic=True)

    @app.post("/api/v1/candidates/{candidate_id}/threat-intelligence/lookups")
    def lookup_candidate_threat_intelligence(candidate_id: str) -> dict[str, Any]:
        if threat_intel is None and misp is None:
            raise ApiError(
                503,
                "THREAT_INTELLIGENCE_NOT_CONFIGURED",
                "VirusTotal, AbuseIPDB 또는 MISP 연동이 설정되지 않았습니다",
            )
        found = _find_candidate(repo, candidate_id)
        if found is None:
            raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
        job, candidate = found
        return enrich_candidate(str(job["id"]), candidate, origin="MANUAL")

    @app.post("/api/v1/candidates/{candidate_id}/misp-exports")
    def export_candidate_to_misp(
        candidate_id: str, payload: MispExportCreate, request: Request
    ) -> dict[str, Any]:
        if misp is None:
            raise ApiError(503, "MISP_NOT_CONFIGURED", "MISP URL과 API 키가 설정되지 않았습니다")
        event_id = payload.event_id or config.misp_default_event_id
        if not event_id:
            raise ApiError(422, "MISP_EVENT_REQUIRED", "MISP Event ID가 필요합니다")
        with misp_export_lock:
            found = _find_candidate(repo, candidate_id)
            if found is None:
                raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
            job, candidate = found
            current_verdict = candidate.get("current_verdict")
            if (
                not isinstance(current_verdict, dict)
                or current_verdict.get("verdict") != "CONFIRMED_C2"
            ):
                raise ApiError(
                    409,
                    "CANDIDATE_NOT_CONFIRMED",
                    "CONFIRMED_C2 판정 후에만 MISP로 전송할 수 있습니다",
                )
            exports = [item for item in candidate.get("misp_exports", []) if isinstance(item, dict)]
            duplicate = next(
                (
                    item
                    for item in exports
                    if item.get("event_id") == event_id and item.get("status") == "EXPORTED"
                ),
                None,
            )
            if duplicate is not None:
                return {**duplicate, "status": "ALREADY_EXPORTED"}
            exported_at = datetime.now(UTC).isoformat()
            base_record = {
                "id": str(uuid.uuid4()),
                "candidate_id": candidate_id,
                "job_id": str(job["id"]),
                "event_id": event_id,
                "candidate_ip": str(candidate["candidate_ip"]),
                "attribute_type": "ip-src",
                "idempotency_key": f"{candidate_id}:{event_id}",
                "comment": payload.comment,
                "created_by": _request_actor(request),
                "created_at": exported_at,
            }
            try:
                external = misp.add_ip_attribute(
                    event_id,
                    str(candidate["candidate_ip"]),
                    payload.comment,
                )
            except IntegrationError as exc:
                logger.exception(
                    "MISP export failed candidate_id=%s candidate_ip=%s event_id=%s "
                    "provider=%s http_status=%s",
                    candidate_id,
                    candidate["candidate_ip"],
                    event_id,
                    exc.provider,
                    exc.http_status,
                )
                failed = {**base_record, "status": "FAILED", "error": exc.message}
                repo.save_candidate_misp_action(failed)
                raise ApiError(502, "MISP_EXPORT_FAILED", exc.message) from exc
            exported = {**base_record, **external, "status": "EXPORTED"}
            repo.save_candidate_misp_action(exported)
            return exported

    @app.delete("/api/v1/candidates/{candidate_id}")
    def delete_candidate(candidate_id: str) -> dict[str, Any]:
        """Delete a candidate by ID."""
        deleted = repo.delete_candidate(candidate_id)
        if not deleted:
            raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
        return {"deleted": True, "candidate_id": candidate_id}

    @app.get("/api/v1/payload-signatures")
    def list_payload_signatures(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        signatures = repo.list_payload_signatures()
        if enabled is not None:
            signatures = [
                signature for signature in signatures if signature.get("enabled") is enabled
            ]
        signatures.sort(key=lambda item: str(item["created_at"]), reverse=True)
        return _page(signatures, page, page_size)

    @app.patch("/api/v1/payload-signatures/{signature_id}")
    def update_payload_signature(
        signature_id: str, payload: PayloadSignatureUpdate
    ) -> dict[str, Any]:
        signature = repo.get_payload_signature(signature_id)
        if signature is None:
            raise ApiError(404, "SIGNATURE_NOT_FOUND", "서명을 찾을 수 없습니다")
        updated = {**signature, **payload.model_dump(exclude_unset=True)}
        current_version = signature.get("version", 1)
        # version이 명시적으로 전달되지 않았다면 자동으로 증가
        if "version" not in payload.model_dump(exclude_unset=True):
            updated["version"] = int(current_version) + 1
        saved = repo.save_payload_signature(updated)
        return saved

    @app.delete("/api/v1/payload-signatures/{signature_id}")
    def delete_payload_signature(signature_id: str) -> dict[str, Any]:
        signature = repo.get_payload_signature(signature_id)
        if signature is None:
            raise ApiError(404, "SIGNATURE_NOT_FOUND", "서명을 찾을 수 없습니다")
        deleted = repo.delete_payload_signature(signature_id)
        if not deleted:
            raise ApiError(404, "SIGNATURE_NOT_FOUND", "서명을 찾을 수 없습니다")
        return {"deleted": True, "signature_id": signature_id}

    @app.post("/api/v1/allowlist", status_code=201)
    def create_allowlist_entry(payload: AllowlistCreate) -> dict[str, Any]:
        created_at = datetime.now(UTC)
        entry = {
            "id": str(uuid.uuid4()),
            **payload.model_dump(mode="json"),
            "created_at": created_at.isoformat(),
        }
        saved = repo.save_allowlist(entry)
        policy = AllowlistEntry.from_mapping(saved)
        for job_id, candidates in repo.list_candidate_sets().items():
            changed = False
            for candidate in candidates:
                metrics = [
                    evidence.get("metrics", {})
                    for evidence in candidate.get("evidence", [])
                    if isinstance(evidence, dict)
                ]
                if policy.matches_metrics(str(candidate["candidate_ip"]), metrics, created_at):
                    candidate.update(
                        {
                            "excluded": True,
                            "exclude_reason": f"Allowlist: {saved['description']}",
                            "suppressed_at": created_at.isoformat(),
                            "suppressed_by_allowlist_id": saved["id"],
                            "updated_at": created_at.isoformat(),
                        }
                    )
                    changed = True
            if changed:
                repo.save_candidates(job_id, candidates)
                job = repo.get_job(job_id)
                if job is not None:
                    job["candidate_count"] = sum(
                        not candidate.get("excluded", False) for candidate in candidates
                    )
                    repo.save_job_metadata(job)
        return saved

    @app.get("/api/v1/allowlist")
    def list_allowlist(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        type: str | None = None,
        enabled: bool | None = None,
        sort: str = "value",
    ) -> dict[str, Any]:
        items = repo.list_allowlist()
        if type:
            items = [item for item in items if item["type"] == type]
        if enabled is not None:
            items = [item for item in items if item["enabled"] is enabled]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"value", "type", "created_at", "expires_at"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        return _page(items, page, page_size)

    @app.delete("/api/v1/allowlist/{entry_id}", status_code=204)
    def delete_allowlist_entry(entry_id: str) -> Response:
        if not repo.delete_allowlist(entry_id):
            raise ApiError(404, "ALLOWLIST_NOT_FOUND", "allowlist 항목을 찾을 수 없습니다")
        return Response(status_code=204)

    @app.post("/api/v1/pcap-exports", status_code=201)
    def create_pcap_export(payload: PcapExportCreate) -> dict[str, Any]:
        job = repo.get_job(payload.job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        candidate_ip = None
        if payload.candidate_id:
            candidate = next(
                (
                    item
                    for item in repo.get_candidates(payload.job_id)
                    if item["id"] == payload.candidate_id
                ),
                None,
            )
            if candidate is None:
                raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")
            candidate_ip = candidate["candidate_ip"]
        normalized = payload.model_dump(mode="json")
        normalized["candidate_ip"] = candidate_ip
        source_records = job["flow_records"]
        if source_records and not any(record.get("raw_packet_hex") for record in source_records):
            retained_capture = repo.get_job_capture(payload.job_id)
            if retained_capture is not None:
                parsed = parse_pcap(
                    retained_capture,
                    sensor_id=str(job["sensor_ids"][0]),
                    internal_networks=list(job["internal_networks"]),
                    max_packets=config.pcap_upload_max_packets,
                    retain_packet_bytes=True,
                )
                source_records = list(parsed.records)
        records = filter_records(source_records, normalized)
        content, packet_count = build_pcap(records)
        export_id = str(uuid.uuid4())
        status = "COMPLETED" if packet_count else "FAILED"
        metadata = {
            "id": export_id,
            "job_id": payload.job_id,
            "candidate_id": payload.candidate_id,
            "status": status,
            "matched_packet_count": packet_count,
            "size_bytes": len(content),
            "filter": normalized,
            "created_at": datetime.now(UTC).isoformat(),
            "error": None if packet_count else "matching source packet bytes are unavailable",
        }
        return repo.save_export(metadata, content)

    @app.get("/api/v1/pcap-exports/{export_id}")
    def get_pcap_export(export_id: str) -> dict[str, Any]:
        stored = repo.get_export(export_id)
        if stored is None:
            raise ApiError(404, "PCAP_EXPORT_NOT_FOUND", "PCAP export를 찾을 수 없습니다")
        return stored[0]

    @app.get("/api/v1/pcap-exports/{export_id}/download")
    def download_pcap_export(export_id: str) -> Response:
        stored = repo.get_export(export_id)
        if stored is None:
            raise ApiError(404, "PCAP_EXPORT_NOT_FOUND", "PCAP export를 찾을 수 없습니다")
        metadata, content = stored
        if metadata["status"] != "COMPLETED":
            raise ApiError(409, "PCAP_NOT_AVAILABLE", "PCAP export가 사용 가능하지 않습니다")
        return Response(
            content,
            media_type="application/vnd.tcpdump.pcap",
            headers={"Content-Disposition": f'attachment; filename="c2hunter-{export_id}.pcap"'},
        )

    return app


app = create_app()
