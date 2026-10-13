"""Private historical run custody. No repository imports or public DTO shortcuts."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from copy import deepcopy
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, cast
from uuid import UUID

from . import historical_ai as dto
from . import historical_baseline as h
from . import historical_generation as g
from ._baseline_storage import BaselineStorageError
from .historical_read import HistoricalAITargetSnapshot

if TYPE_CHECKING:
    from .ai_analysis import CandidateEvidenceBundle

Builder = Callable[
    [
        dto.HistoricalAdmissionRequest,
        HistoricalAITargetSnapshot,
        g.ScopeView,
        g.GenerationDocument | None,
    ],
    dto.HistoricalRunSnapshot,
]

OWNER_KEY = "_historical_admission"
OWNER_FIELDS = (
    "version",
    "request_canonical_json",
    "request_byte_size",
    "snapshot_canonical_json",
    "snapshot_byte_size",
    "expected_snapshot_sha256",
)
PRIVATE_FIELDS = frozenset(OWNER_FIELDS) | {
    OWNER_KEY,
    "baseline_summary",
    "baseline_request",
    "baseline_request_fingerprint",
    "baseline_comparisons",
    "baseline_sources",
    "admitted_bundles",
    "historical_owner_version",
    "historical_request_json",
    "historical_request_byte_size",
    "historical_snapshot_json",
    "historical_snapshot_byte_size",
    "historical_expected_snapshot_sha256",
}


def historical_marker(run: dict[str, Any]) -> bool:
    if run.get("baseline_mode", "off") != "off" or PRIVATE_FIELDS.intersection(run):
        return True
    for name in ("candidate_snapshots", "selection_inventory"):
        rows = run.get(name)
        if isinstance(rows, list | tuple) and any(
            isinstance(row, dict) and row.get("historical_reference") is not None for row in rows
        ):
            return True
    return False


def reject_generic_historical(run: dict[str, Any]) -> None:
    if historical_marker(run):
        raise ValueError("historical admission requires atomic owner")


class HistoricalStorageError(ValueError):
    def __init__(self, code: str = "BASELINE_STORAGE_UNAVAILABLE") -> None:
        self.code = code
        super().__init__(code)


class HistoricalStorageOutcomeUnknown(HistoricalStorageError):
    """Publication may be durable. Never convert this into FAILED or queue ACK."""


# Worker consumers must propagate these before their generic ValueError/Exception
# handlers. Both definite storage failures and unknown outcomes require no ACK;
# the latter additionally fence off the writer until a fresh connection replays.
HISTORICAL_STORAGE_ERRORS = (HistoricalStorageError, BaselineStorageError)


def require(ok: bool, code: str = "BASELINE_STORAGE_UNAVAILABLE") -> None:
    if not ok:
        raise HistoricalStorageError(code)


LIFECYCLE_KEYS = frozenset(
    {
        "id",
        "analysis_job_id",
        "idempotency_key",
        "created_at",
        "baseline_mode",
        "status",
        "progress_percent",
        "updated_at",
        "transitions",
    }
)
IDENTITY_KEYS = ("id", "analysis_job_id", "idempotency_key", "created_at")


def stage_admission(
    request: dto.HistoricalAdmissionRequest,
    target: HistoricalAITargetSnapshot,
    scope: g.ScopeView,
    generation: g.GenerationDocument | None,
    builder: Builder,
) -> dict[str, Any]:
    # Capture independent request bytes BEFORE invoking the no-I/O builder.
    request_text = h.canonical_json(request.to_mapping())
    snapshot = builder(request, target, scope, generation)
    require(type(snapshot) is dto.HistoricalRunSnapshot)
    text = h.canonical_json(snapshot.to_mapping())
    digest = hashlib.sha256(text.encode()).hexdigest()
    original = dto.HistoricalAdmissionRequest.model_validate_json(request_text)
    dto.decode_historical_snapshot(text, request=original, expected_snapshot_sha256=digest)
    raw = snapshot.to_mapping()
    return {
        **{key: raw[key] for key in LIFECYCLE_KEYS},
        OWNER_KEY: {
            "version": "historical-ai-owner-v1",
            "request_canonical_json": request_text,
            "request_byte_size": len(request_text.encode()),
            "snapshot_canonical_json": text,
            "snapshot_byte_size": len(text.encode()),
            "expected_snapshot_sha256": digest,
        },
    }


def replay_matches(run: dict[str, Any], request: dto.HistoricalAdmissionRequest) -> None:
    require(OWNER_KEY in run, "BASELINE_IDEMPOTENCY_CONFLICT")
    owner = historical_header(run)
    materialize_historical_run(run)
    original = _original_request(owner)
    require(
        original.request_fingerprint == request.request_fingerprint, "BASELINE_IDEMPOTENCY_CONFLICT"
    )


def memory_internal(
    runs: dict[str, dict[str, Any]],
    owners: dict[str, dict[str, Any]],
    keys: dict[tuple[str, str], str],
    run_id: str,
    *,
    compact: bool = False,
) -> dict[str, Any] | None:
    from .historical_ai_descendants import guard, native_meta

    raw = runs.get(run_id)
    guard([native_meta("R", raw, identity=run_id, owner=owners.get(run_id))], compact=compact)
    if raw is None:
        require(run_id not in owners)
        return None
    if run_id not in owners:
        require(not historical_marker(raw))
        return deepcopy(raw)
    internal = {**raw, OWNER_KEY: owners[run_id]}
    historical_header(internal)
    require(raw.get("id") == run_id)
    key = (raw["analysis_job_id"], raw["idempotency_key"])
    require(keys.get(key) == run_id and [k for k, v in keys.items() if v == run_id] == [key])
    return deepcopy(internal)


TERMINAL = frozenset({"COMPLETED", "FAILED", "CANCELLED"})
PROGRESS = {"QUEUED": 0, "PREPARING": 10, "ANALYZING": 40, "VALIDATING": 80, "COMPLETED": 100}
EDGES = {
    "QUEUED": {"PREPARING", "FAILED", "CANCELLED"},
    "PREPARING": {"ANALYZING", "FAILED", "CANCELLED"},
    "ANALYZING": {"VALIDATING", "FAILED", "CANCELLED"},
    "VALIDATING": {"ANALYZING", "COMPLETED", "FAILED", "CANCELLED"},
}
FAILURES = {
    "MODEL_TIMEOUT": "Model request timed out.",
    "MODEL_OUTPUT_INVALID": "Model output failed validation.",
    "AI_ANALYSIS_FAILED": "AI analysis failed.",
    "HISTORICAL_SNAPSHOT_INVALID": "Saved historical snapshot failed validation.",
}


def _time(value: Any) -> str:
    require(
        type(value) is str
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", value) is not None
    )
    datetime.fromisoformat(value.replace("Z", "+00:00"))
    return cast(str, value)


def _identifier(value: Any) -> None:
    require(type(value) is str and 1 <= len(value) <= 200)
    require(
        len(value.encode()) <= 800 and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)
    )


class _Pairs(list[tuple[str, Any]]):
    pass


def _depth(value: Any, depth: int = 0) -> None:
    require(depth <= 16)
    if type(value) is _Pairs:
        for _, child in value:
            _depth(child, depth + 1)
    elif type(value) is list:
        for child in value:
            _depth(child, depth + 1)


def _one(value: Any, key: str) -> Any:
    require(type(value) is _Pairs)
    items = [v for k, v in value if k == key]
    require(len(items) == 1)
    return items[0]


def historical_header(
    internal: dict[str, Any],
    identity: tuple[Any, ...] | None = None,
) -> dict[str, Any]:
    """Validate bounded owner shape + independent identity, NOT body semantics."""
    try:
        require(type(internal) is dict)
        status = internal.get("status")
        require(type(status) is str and status in PROGRESS.keys() | TERMINAL)
        expected = LIFECYCLE_KEYS | {OWNER_KEY}
        if status in TERMINAL:
            expected |= {"completed_at"}
        if status == "FAILED":
            expected |= {"error_code", "error_message"}
        require(internal.keys() == expected and internal["baseline_mode"] == "historical")
        for key in IDENTITY_KEYS[:3]:
            _identifier(internal[key])
        require(str(UUID(internal["id"])) == internal["id"])
        if identity is not None:
            require(tuple(internal[k] for k in IDENTITY_KEYS) == identity)
        created, updated = _time(internal["created_at"]), _time(internal["updated_at"])
        require(created <= updated and type(internal["progress_percent"]) is int)
        transitions = internal["transitions"]
        require(
            type(transitions) is list
            and 1 <= len(transitions) <= (16 if status in TERMINAL else 15)
        )
        require(
            transitions[0] == {"to_status": "QUEUED", "occurred_at": created, "reason": "requested"}
        )
        previous, stamp, progress = "QUEUED", created, 0
        for i, step in enumerate(transitions):
            require(type(step) is dict and step.keys() == {"to_status", "occurred_at", "reason"})
            require(type(step["reason"]) is str and len(step["reason"]) <= 500)
            require(stamp <= _time(step["occurred_at"]) <= updated)
            state = step["to_status"]
            require(type(state) is str)
            if i:
                require(state in EDGES.get(previous, set()))
            progress = PROGRESS.get(state, progress)
            previous, stamp = state, step["occurred_at"]
        require(
            previous == status and stamp == updated and internal["progress_percent"] == progress
        )
        if status in TERMINAL:
            require(internal["completed_at"] == updated)
        if status == "FAILED":
            require(type(internal["error_code"]) is str)
            require(internal["error_message"] == FAILURES.get(internal["error_code"], object()))
        require(
            len(h.canonical_json({k: v for k, v in internal.items() if k != OWNER_KEY}).encode())
            <= 65536
        )
        owner = internal[OWNER_KEY]
        require(type(owner) is dict and owner.keys() == set(OWNER_FIELDS))
        require(owner["version"] == "historical-ai-owner-v1")
        for name, limit in (("request", 16384), ("snapshot", 4194304)):
            raw, size = owner[name + "_canonical_json"], owner[name + "_byte_size"]
            require(type(raw) is str and 1 <= len(raw) <= limit)
            require(type(size) is int and 1 <= size <= limit and len(raw.encode()) == size)
        digest = owner["expected_snapshot_sha256"]
        require(type(digest) is str and re.fullmatch("[0-9a-f]{64}", digest) is not None)
        original = json.loads(owner["request_canonical_json"], object_pairs_hook=_Pairs)
        _depth(original)
        require(_one(original, "run_id") == internal["id"])
        require(_one(original, "analysis_job_id") == internal["analysis_job_id"])
        require(_one(_one(original, "payload"), "idempotency_key") == internal["idempotency_key"])
        admitted = _one(original, "admitted_at")
        require(type(admitted) is str and len(admitted) <= 64)
        instant = datetime.fromisoformat(admitted.replace("Z", "+00:00"))
        require(
            instant.tzinfo is not None
            and instant.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ") == created
        )
        return cast(dict[str, Any], owner)
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise HistoricalStorageError() from None


def _original_request(owner: dict[str, Any]) -> dto.HistoricalAdmissionRequest:
    try:
        raw = h.thaw_original_json(
            h.decode_original_json(owner["request_canonical_json"], max_bytes=16384)
        )
        request = dto.checked_request(dto.HistoricalAdmissionRequest.model_validate(raw))
        if h.canonical_json(request.to_mapping()) != owner["request_canonical_json"]:
            raise ValueError("noncanonical request")
        return request
    except (ValueError, TypeError, KeyError, OverflowError, RecursionError):
        raise dto.HistoricalAIError("HISTORICAL_SNAPSHOT_INVALID") from None


def materialize_historical_run(
    internal: dict[str, Any],
) -> tuple[dict[str, Any], tuple[CandidateEvidenceBundle, ...]]:
    """Return a separate validated view and bundles; never save the view."""
    owner = historical_header(internal)
    request = _original_request(owner)
    bundles = dto.decode_historical_snapshot(
        owner["snapshot_canonical_json"],
        request=request,
        expected_snapshot_sha256=owner["expected_snapshot_sha256"],
    )
    view = json.loads(owner["snapshot_canonical_json"])
    view.update(deepcopy({k: v for k, v in internal.items() if k != OWNER_KEY}))
    return view, bundles


def lifecycle_save(existing: dict[str, Any], submitted: dict[str, Any]) -> dict[str, Any]:
    owner = historical_header(existing)
    incoming = historical_header(submitted, tuple(existing[k] for k in IDENTITY_KEYS))
    require(incoming == owner)  # BEFORE every terminal shortcut, even a no-op.
    try:
        materialize_historical_run(existing)
    except dto.HistoricalAIError:
        require(
            _safe_failure_receipt(existing)
            if existing["status"] in TERMINAL
            else _safe_failure_receipt(submitted)
        )
    old, new = existing["transitions"], submitted["transitions"]
    if existing == submitted:
        return deepcopy(existing)
    if existing["status"] in TERMINAL:
        require(len(new) > 1 and new[:-1] == old[: len(new) - 1])
        return deepcopy(existing)
    require(len(new) == len(old) + 1 and new[:-1] == old)
    return deepcopy(submitted)


def _safe_failure_receipt(run: dict[str, Any]) -> bool:
    return (
        run["status"] == "FAILED"
        and run.get("error_code") == "HISTORICAL_SNAPSHOT_INVALID"
        and run.get("error_message") == FAILURES["HISTORICAL_SNAPSHOT_INVALID"]
        and run["transitions"][-1]["reason"] == "historical snapshot rejected"
    )


def safe_historical_failure(internal: dict[str, Any], now: datetime) -> dict[str, Any]:
    """Build only the fixed semantic-failure suffix; repository still owns its fence."""
    historical_header(internal)
    try:
        materialize_historical_run(internal)
    except dto.HistoricalAIError:
        if internal["status"] in TERMINAL:
            require(_safe_failure_receipt(internal))
            return deepcopy(internal)
    else:
        raise HistoricalStorageError()  # Not a semantic failure.
    require(type(now) is datetime and now.tzinfo is not None)
    stamp = max(internal["updated_at"], now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    result = deepcopy(internal)
    result.update(
        status="FAILED",
        updated_at=stamp,
        completed_at=stamp,
        error_code="HISTORICAL_SNAPSHOT_INVALID",
        error_message=FAILURES["HISTORICAL_SNAPSHOT_INVALID"],
    )
    result["transitions"].append(
        {"to_status": "FAILED", "occurred_at": stamp, "reason": "historical snapshot rejected"}
    )
    historical_header(result)
    return result
