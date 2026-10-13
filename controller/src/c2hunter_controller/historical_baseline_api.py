"""Closed baseline-management HTTP adapter."""

from __future__ import annotations

import asyncio
import json
import math
from datetime import UTC, datetime
from typing import Any, Literal

import anyio
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from pydantic import TypeAdapter
from starlette.concurrency import run_in_threadpool

from ._baseline_storage import BaselineStorageError
from .api_errors import ApiError
from .baseline_admission import BaselineAdmission, BaselineLease
from .historical_baseline import FrozenDTO, Identifier, Nonnegative, ScopeConfig, UUIDString
from .historical_generation import ApprovalRequest, ControlRequest, ScopeView
from .historical_read import HistoricalReadError
from .repositories import Repository

BASE = "/api/v1/historical-baselines"
_SCOPE_FIELDS = frozenset(
    {
        "config",
        "config_sha256",
        "control_revision",
        "frozen",
        "state",
        "accepted_event_end",
        "active",
        "previous",
        "created_by",
        "created_at",
    }
)


def _scope(value: ScopeView) -> dict[str, Any]:
    return value.model_dump(mode="json", include=set(_SCOPE_FIELDS))


def _invalid() -> ApiError:
    return ApiError(422, "VALIDATION_ERROR", "요청 값이 유효하지 않습니다")


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate member")
        result[key] = value
    return result


def _number(value: str) -> float:
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("nonfinite")
    return result


async def _body(request: Request) -> dict[str, Any]:
    lengths = request.headers.getlist("content-length")
    if lengths:
        if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
            raise _invalid()
        if len(lengths[0]) > 5 or int(lengths[0]) > 16384:
            raise ApiError(413, "BASELINE_BODY_LIMIT", "요청 본문 제한을 초과했습니다")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > 16384:
            raise ApiError(413, "BASELINE_BODY_LIMIT", "요청 본문 제한을 초과했습니다")
        data.extend(chunk)
    try:
        # Check container depth before the JSON decoder allocates nested values.
        depth = 0
        quoted = escaped = False
        for byte in data:
            if quoted:
                if escaped:
                    escaped = False
                elif byte == 92:
                    escaped = True
                elif byte == 34:
                    quoted = False
            elif byte == 34:
                quoted = True
            elif byte in (91, 123):
                depth += 1
                if depth > 16:
                    raise ValueError("depth")
            elif byte in (93, 125):
                depth -= 1
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_pairs,
            parse_float=_number,
            parse_constant=_number,
        )
        if type(value) is not dict:
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError):
        raise _invalid() from None


def _decode[T: FrozenDTO](kind: type[T], body: dict[str, Any]) -> T:
    try:
        return kind.from_mapping(body)
    except ValueError:
        raise _invalid() from None


def _identifier(value: str) -> str:
    try:
        return TypeAdapter(UUIDString).validate_python(value, strict=True)
    except ValueError:
        raise _invalid() from None


def _page_args(request: Request, maximum: int = 16) -> tuple[int, int]:
    values = {"offset": 0, "limit": 20}
    seen: set[str] = set()
    for key, value in request.query_params.multi_items():
        if key not in values or key in seen or not value.isascii() or not value.isdigit():
            raise _invalid()
        if len(value) > 2 or (len(value) > 1 and value.startswith("0")):
            raise _invalid()
        seen.add(key)
        values[key] = int(value)
    if not 0 <= values["offset"] <= maximum or not 1 <= values["limit"] <= 20:
        raise _invalid()
    return values["offset"], values["limit"]


def _no_query(request: Request) -> None:
    if request.query_params:
        raise _invalid()


_ERROR_STATUS = {
    "BASELINE_SCOPE_NOT_FOUND": 404,
    "BASELINE_SOURCE_NOT_FOUND": 404,
    "BASELINE_SCOPE_EXISTS": 409,
    "BASELINE_REVISION_CONFLICT": 409,
    "BASELINE_IDEMPOTENCY_CONFLICT": 409,
    "BASELINE_FROZEN": 409,
    "BASELINE_SOURCE_CHANGED": 409,
    "BASELINE_SOURCE_STATE": 409,
    "BASELINE_SOURCE_LINEAGE_INVALID": 409,
    "BASELINE_SOURCE_QUALITY": 409,
    "BASELINE_SCOPE_MISMATCH": 409,
    "BASELINE_SOURCE_DUPLICATE": 409,
    "BASELINE_EVENT_ORDER": 409,
    "BASELINE_ROLLBACK_UNAVAILABLE": 409,
    "BASELINE_GENERATION_MISMATCH": 409,
    "BASELINE_GENERATION_RETIRED": 410,
    "BASELINE_SOURCE_LIMIT": 413,
    "BASELINE_CANDIDATE_LIMIT": 413,
    "BASELINE_PROFILE_LIMIT": 413,
    "BASELINE_GENERATION_LIMIT": 413,
    "BASELINE_CONTROL_LIMIT": 413,
    "BASELINE_SOURCE_INVALID": 422,
    "BASELINE_SCOPE_LIMIT": 429,
    "BASELINE_BUSY": 503,
    "BASELINE_STORAGE_UNAVAILABLE": 503,
}

_SOURCE_FIELDS = frozenset(
    {
        "source_receipt_id",
        "source_job_id",
        "root_job_id",
        "dataset_id",
        "root_identity",
        "ancestry_job_ids",
        "root_content_sha256",
        "source_binding_sha256",
        "observation_sha256",
        "feature_observation_sha256",
        "actual_sensor_id",
        "sensor_key",
        "event_start",
        "event_end",
        "origin",
        "origin_assurance",
        "normality",
        "approved_by",
        "approved_at",
        "reason",
        "quality_review",
        "producer_completeness",
        "known_partial",
        "limitations",
    }
)

_CONTROL_RECEIPT_FIELDS = frozenset(
    {"operation_id", "action", "revision", "actor", "occurred_at", "generation_id"}
)

_APPROVAL_RECEIPT_FIELDS = frozenset(
    {
        "operation_id",
        "action",
        "revision",
        "actor",
        "occurred_at",
        "generation_id",
        "source_job_id",
        "source_binding_sha256",
    }
)


class _PreviewRequest(FrozenDTO):
    source_job_id: Identifier
    expected_revision: Nonnegative
    purpose: Literal["APPROVAL", "COMPARISON"]


_PREVIEW_FIELDS = frozenset(
    {
        "scope_id",
        "scope_revision",
        "scope_config_sha256",
        "source_job_id",
        "root_job_id",
        "dataset_id",
        "source_binding_sha256",
        "observation_sha256",
        "feature_observation_sha256",
        "origin",
        "origin_assurance",
        "actual_sensor_id",
        "event_start",
        "event_end",
        "flow_count",
        "profile_count",
        "eligible_profile_count",
        "excluded_profile_count",
        "admissible",
        "reasons",
        "required_review",
        "producer_completeness",
        "known_partial",
        "stored_clock_offset_ms",
    }
)


class BaselineTransport:
    """At most two submitted baseline invocations per controller instance."""

    def __init__(self) -> None:
        from threading import BoundedSemaphore

        self._slots = BoundedSemaphore(2)
        self._pending: set[asyncio.Task[Any]] = set()
        self._closing = False

    async def call(self, function: Any, *args: Any, **kwargs: Any) -> Any:
        if self._closing or not self._slots.acquire(blocking=False):
            raise ApiError(503, "BASELINE_BUSY", "기준선 작업이 사용 중입니다")

        async def invoke() -> Any:
            try:
                with anyio.CancelScope(shield=True):
                    try:
                        return await run_in_threadpool(function, *args, **kwargs)
                    except (BaselineStorageError, HistoricalReadError) as error:
                        status = _ERROR_STATUS[error.code]
                        raise ApiError(
                            status, error.code, "기준선 요청을 처리할 수 없습니다"
                        ) from None
            finally:
                self._slots.release()

        invocation = invoke()
        try:
            task = asyncio.create_task(invocation)
        except BaseException:
            invocation.close()
            self._slots.release()
            raise
        self._pending.add(task)
        task.add_done_callback(self._finished)
        return await asyncio.shield(task)

    def _finished(self, task: asyncio.Task[Any]) -> None:
        self._pending.discard(task)
        if not task.cancelled():
            task.exception()  # retrieve abandoned failures, never publish a false success

    async def shutdown(self) -> None:
        self._closing = True
        cancelled: asyncio.CancelledError | None = None
        with anyio.CancelScope(shield=True):
            if self._pending:
                drain = asyncio.gather(*self._pending, return_exceptions=True)
                while not drain.done():
                    try:
                        await asyncio.shield(drain)
                    except asyncio.CancelledError as error:
                        cancelled = error
        if cancelled is not None:
            raise cancelled


def baseline_router(
    repository: Repository, transport: BaselineTransport, admission: BaselineAdmission
) -> APIRouter:
    router = APIRouter(prefix=BASE)

    @router.put("/scopes/{scope_id}")
    async def create(scope_id: str, request: Request) -> JSONResponse:
        body = await _body(request)
        if "scope_id" in body:
            raise _invalid()
        config = _decode(ScopeConfig, dict(body, scope_id=scope_id))
        _no_query(request)
        value, created = await transport.call(
            repository.create_baseline_scope,
            config,
            request.state.principal.subject,
            datetime.now(UTC),
        )
        return JSONResponse(_scope(value), status_code=201 if created else 200)

    @router.get("/scopes/{scope_id}")
    async def get(scope_id: str, request: Request) -> JSONResponse:
        _no_query(request)
        value = await transport.call(repository.get_baseline_scope, _identifier(scope_id))
        if value is None:
            raise ApiError(404, "BASELINE_SCOPE_NOT_FOUND", "기준선을 찾을 수 없습니다")
        return JSONResponse(_scope(value))

    @router.get("/scopes")
    async def scopes(request: Request) -> JSONResponse:
        offset, limit = _page_args(request)
        value = await transport.call(repository.page_baseline_scopes, offset, limit)
        return JSONResponse(
            {
                "items": [_scope(item) for item in value.items],
                "total": value.total,
                "offset": value.offset,
                "limit": value.limit,
                "next_offset": value.next_offset,
            }
        )

    @router.post("/scopes/{scope_id}/preview")
    async def preview(scope_id: str, request: Request) -> JSONResponse:
        body = _decode(_PreviewRequest, await _body(request))
        _no_query(request)
        identifier = _identifier(scope_id)

        def invoke() -> Any:
            with BaselineLease(admission) as lease:
                if not lease.acquire():
                    raise BaselineStorageError("BASELINE_BUSY")
                return repository.preview_baseline_source(
                    identifier, body.source_job_id, body.expected_revision, body.purpose
                )

        value = await transport.call(invoke)
        return JSONResponse(value.model_dump(mode="json", include=_PREVIEW_FIELDS))

    @router.post("/scopes/{scope_id}/approvals")
    async def approve(scope_id: str, request: Request) -> JSONResponse:
        body = _decode(ApprovalRequest, await _body(request))
        _no_query(request)
        identifier = _identifier(scope_id)
        value = await transport.call(
            repository.publish_baseline_source,
            identifier,
            body,
            request.state.principal.subject,
            datetime.now(UTC),
            admission=admission,
        )
        return JSONResponse(
            {
                "scope": _scope(value.scope),
                "receipt": value.receipt.model_dump(mode="json", include=_APPROVAL_RECEIPT_FIELDS),
            },
            status_code=201 if value.created else 200,
        )

    @router.post("/scopes/{scope_id}/control")
    async def control(scope_id: str, request: Request) -> JSONResponse:
        body = _decode(ControlRequest, await _body(request))
        _no_query(request)
        identifier = _identifier(scope_id)
        value = await transport.call(
            repository.control_baseline_scope,
            identifier,
            body,
            request.state.principal.subject,
            datetime.now(UTC),
        )
        return JSONResponse(
            {
                "scope": _scope(value.scope),
                "receipt": value.receipt.model_dump(mode="json", include=_CONTROL_RECEIPT_FIELDS),
            }
        )

    @router.get("/scopes/{scope_id}/generations/{generation_id}/sources")
    async def sources(scope_id: str, generation_id: str, request: Request) -> JSONResponse:
        identifier, generation = _identifier(scope_id), _identifier(generation_id)
        offset, limit = _page_args(request)
        value = await transport.call(
            repository.page_baseline_sources, identifier, generation, offset, limit
        )
        return JSONResponse(
            {
                "items": [
                    item.model_dump(mode="json", include=_SOURCE_FIELDS) for item in value.items
                ],
                "total": value.total,
                "offset": value.offset,
                "limit": value.limit,
                "next_offset": value.next_offset,
            }
        )

    @router.get("/scopes/{scope_id}/control-events")
    async def events(scope_id: str, request: Request) -> JSONResponse:
        identifier = _identifier(scope_id)
        offset, limit = _page_args(request, 64)
        value = await transport.call(
            repository.page_baseline_control_events, identifier, offset, limit
        )
        return JSONResponse(
            {
                "items": [
                    item.model_dump(
                        mode="json",
                        include=(
                            _APPROVAL_RECEIPT_FIELDS
                            if item.action == "APPROVE"
                            else _CONTROL_RECEIPT_FIELDS
                        ),
                    )
                    for item in value.items
                ],
                "total": value.total,
                "offset": value.offset,
                "limit": value.limit,
                "next_offset": value.next_offset,
                "earliest_retained_revision": value.earliest_retained_revision,
            }
        )

    return router
