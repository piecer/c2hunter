from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from c2hunter_analysis.pcap import PcapParseError, find_pcap_record, parse_pcap
from fastapi import FastAPI, Header, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.concurrency import run_in_threadpool

from .config import Settings
from .flow_review import (
    filter_flows,
    flow_id,
    label_snapshot,
    payload_ascii,
)
from .jobs import JobState, StateMachine, build_job, calculate, summarize_candidate_traffic
from .pcap import build_pcap, filter_records
from .production import MinioBlobStore, PostgresRepository
from .queueing import ControllerQueue, MemoryControllerQueue, RedisControllerQueue
from .repositories import MemoryRepository, Repository
from .schemas import (
    AllowlistCreate,
    AnalysisJobCreate,
    AnalysisJobUpdate,
    CancelRequest,
    DevLoginRequest,
    EnrollmentClaim,
    EnrollmentClaimResponse,
    EnrollmentCreate,
    EnrollmentCreateResponse,
    FlowBatchCreate,
    FlowLabelCreate,
    Heartbeat,
    PayloadSignatureUpdate,
    PcapExportCreate,
    ReanalysisRequest,
    SensorConfigurationResponse,
    SensorConfigurationUpdate,
    SensorGroupCreate,
    SensorRegistration,
)
from .storage import ClickHouseFlowStore, FlowStore, MemoryFlowStore


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
    app = FastAPI(title="C2Hunter Controller", version="0.1.0")
    app.state.settings = config
    app.state.repository = repo
    app.state.flow_store = flows
    app.state.queue = work_queue
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
            "development convenience only; this endpoint does not provide production identity, "
            "token verification, authorization, refresh, revocation, OIDC, or MFA."
        ),
    )
    def development_login(payload: DevLoginRequest) -> dict[str, Any]:
        if not config.dev_login_enabled:
            # Keep the disabled surface indistinguishable from an unavailable optional feature.
            raise ApiError(404, "DEV_LOGIN_DISABLED", "개발 로그인이 활성화되지 않았습니다")
        return {
            "access_token": secrets.token_urlsafe(32),
            "token_type": "bearer",
            "expires_in": config.dev_token_ttl_seconds,
            "username": payload.username,
            "limitations": (
                "Development-only opaque token; no production authentication or authorization "
                "semantics are provided."
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
            "config_poll_interval_seconds": 30,
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
            "internal_networks": sensor["internal_networks"],
            "heartbeat_interval_seconds": 15,
            "config_poll_interval_seconds": 30,
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
        sensor = require_sensor_token(sensor_id, sensor_token)
        now = datetime.now(UTC)
        offset = (now - payload.reported_at).total_seconds() * 1000
        sensor.update(payload.model_dump(mode="json"))
        sensor.update(
            {
                "reported_status": payload.status.value,
                "derived_status": "DEGRADED"
                if abs(offset) > config.clock_skew_threshold_seconds * 1000
                else payload.status.value,
                "clock_offset_ms": offset,
                "last_heartbeat_at": now.isoformat(),
            }
        )
        return repo.upsert_sensor(sensor)

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
        return {"batch_id": payload.batch_id, "accepted": accepted, "record_count": count}

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

    def payload_signature_snapshot() -> list[dict[str, Any]]:
        return [
            dict(signature)
            for signature in repo.list_payload_signatures()
            if signature.get("enabled") is True
        ]

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
        if config.environment != "test":
            threading.Thread(target=consume_results, daemon=True).start()

    @app.on_event("shutdown")
    def stop_result_consumer() -> None:
        result_stop.set()

    def execute_analysis(job: dict[str, Any]) -> dict[str, Any]:
        for state, reason in (
            (JobState.WAITING_FOR_SENSOR, "sensors selected"),
            (JobState.CAPTURING, "dataset selected"),
            (JobState.UPLOADING, "flow records received"),
            (JobState.INGESTING, "flow records validated"),
            (JobState.ANALYZING, "detectors started"),
        ):
            machine.transition(job, state, reason)
        candidates = calculate(job, repo.list_allowlist())
        repo.save_candidates(job["id"], candidates)
        job["candidate_count"] = len(candidates)
        job["flow_count"] = len(job.get("flow_records", []))
        job["packet_count"] = sum(
            int(record.get("packet_count", 1)) for record in job.get("flow_records", [])
        )
        machine.transition(job, JobState.COMPLETED, "analysis completed")
        return repo.save_job_metadata(job)

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
        requested_job = build_job(payload)
        requested_job["payload_signatures"] = payload_signature_snapshot()
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
    ) -> dict[str, Any]:
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
                },
                "internal_networks": cidrs,
                "flow_records": list(parsed.records),
            }
        )
        job = build_job(payload, dataset_id=f"pcap:{digest}")
        job["payload_signatures"] = payload_signature_snapshot()
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

    @app.get("/api/v1/analysis-jobs/{job_id}/flows")
    def list_analysis_flows(
        job_id: str,
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        candidate_ip: str | None = Query(default=None, max_length=45),
        direction: str | None = Query(
            default=None, pattern=r"^(INBOUND|OUTBOUND|BIDIRECTIONAL|UNKNOWN)$"
        ),
        protocol: str | None = Query(default=None, min_length=1, max_length=32),
        port: int | None = Query(default=None, ge=0, le=65535),
        has_payload: bool | None = None,
    ) -> dict[str, Any]:
        job = repo.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        matched = filter_flows(
            job,
            labels=repo.list_flow_labels(job_id),
            candidate_ip=candidate_ip,
            direction=direction,
            protocol=protocol,
            port=port,
            has_payload=has_payload,
        )
        return _page(matched, page, page_size)

    @app.get("/api/v1/analysis-jobs/{job_id}/flows/{requested_flow_id}/payload-preview")
    def get_flow_payload_preview(job_id: str, requested_flow_id: str) -> dict[str, Any]:
        job = repo.get_job(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        retained_capture = repo.get_job_capture(job_id)
        if retained_capture is None:
            raise ApiError(
                409,
                "PAYLOAD_PREVIEW_UNAVAILABLE",
                "보존된 source PCAP이 없어 Payload 미리보기를 제공할 수 없습니다",
            )
        try:
            record = find_pcap_record(
                retained_capture,
                sensor_id=str(job["sensor_ids"][0]),
                internal_networks=list(job["internal_networks"]),
                max_packets=config.pcap_upload_max_packets,
                retain_payload_sample_bytes=256,
                predicate=lambda item: flow_id(job_id, item) == requested_flow_id,
            )
        except PcapParseError as exc:
            raise ApiError(422, exc.code, str(exc)) from exc
        if record is None:
            raise ApiError(404, "FLOW_NOT_FOUND", "분석 작업에서 Flow를 찾을 수 없습니다")
        sample = str(record.get("payload_sample_hex", ""))
        if not sample:
            raise ApiError(
                409,
                "PAYLOAD_PREVIEW_UNAVAILABLE",
                "선택한 Flow에 미리볼 Payload가 없습니다",
            )
        sample_bytes = bytes.fromhex(sample)
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
        parameters = dict(source["analysis"])
        for field in ("minimum_candidate_score", "minimum_distinct_clients"):
            value = getattr(payload, field)
            if value is not None:
                parameters[field] = value
        request = AnalysisJobCreate.model_validate(
            {
                "name": f"{source['name']}-reanalyze",
                "idempotency_key": payload.idempotency_key,
                "sensor_ids": source["sensor_ids"],
                "mode": "REANALYSIS",
                "start_time": source["start_time"],
                "end_time": source["end_time"],
                "capture": source["capture"],
                "analysis": parameters,
                "internal_networks": source["internal_networks"],
                "flow_records": source["flow_records"],
            }
        )
        reanalysis_job = build_job(request, parent_job_id=job_id, dataset_id=source["dataset_id"])
        reanalysis_job["payload_signatures"] = payload_signature_snapshot()
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
        minimum_score: int = Query(0, ge=0, le=100),
        sort: str = "-score",
    ) -> dict[str, Any]:
        job = repo.get_job_summary(job_id)
        if job is None:
            raise ApiError(404, "JOB_NOT_FOUND", "분석 작업을 찾을 수 없습니다")
        items = [
            _public_candidate(item, job)
            for item in repo.get_candidates(job_id)
            if item["score"] >= minimum_score
        ]
        if severity:
            items = [item for item in items if item["severity"] == severity]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"score", "candidate_ip", "first_seen", "last_seen", "severity"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        return _page(items, page, page_size)

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
        return _public_candidate(candidate, job, include_traffic=True)

    @app.get("/api/v1/candidates")
    def list_all_candidates(
        page: int = Query(1, ge=1),
        page_size: int = Query(50, ge=1, le=200),
        severity: str | None = None,
        minimum_score: int = Query(0, ge=0, le=100),
        sort: str = "-score",
    ) -> dict[str, Any]:
        jobs = {str(job["id"]): job for job in repo.list_jobs()}
        items = []
        for job_id, candidates in repo.list_candidate_sets().items():
            job = jobs.get(job_id)
            if job is None:
                continue
            items.extend(
                _public_candidate(candidate, job)
                for candidate in candidates
                if candidate["score"] >= minimum_score
            )
        if severity:
            items = [item for item in items if item["severity"] == severity]
        descending = sort.startswith("-")
        field = sort.removeprefix("-")
        if field not in {"score", "candidate_ip", "first_seen", "last_seen", "severity"}:
            raise ApiError(422, "INVALID_SORT", "허용되지 않은 정렬 필드")
        items.sort(key=lambda item: str(item.get(field, "")), reverse=descending)
        return _page(items, page, page_size)

    @app.get("/api/v1/candidates/{candidate_id}")
    def get_global_candidate(candidate_id: str) -> dict[str, Any]:
        jobs = {str(job["id"]): job for job in repo.list_jobs()}
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
                return _public_candidate(candidate, job, include_traffic=True)
        raise ApiError(404, "CANDIDATE_NOT_FOUND", "후보를 찾을 수 없습니다")

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
            raise ApiError(
                404,
                "PAYLOAD_SIGNATURE_NOT_FOUND",
                "Payload signature를 찾을 수 없습니다",
            )
        changed = False
        for field in payload.model_fields_set:
            value = getattr(payload, field)
            if signature.get(field) != value:
                signature[field] = value
                changed = True
        if not changed:
            return signature
        signature["version"] = int(signature.get("version", 1)) + 1
        signature["updated_at"] = datetime.now(UTC).isoformat()
        return repo.save_payload_signature(signature)

    @app.post("/api/v1/allowlist", status_code=201)
    def create_allowlist_entry(payload: AllowlistCreate) -> dict[str, Any]:
        entry = {
            "id": str(uuid.uuid4()),
            **payload.model_dump(mode="json"),
            "created_at": datetime.now(UTC).isoformat(),
        }
        return repo.save_allowlist(entry)

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
