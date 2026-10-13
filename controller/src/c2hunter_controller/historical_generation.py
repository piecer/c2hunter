"""Deterministic approved-generation values; no authentication or persistence.

Caller-supplied actors and times describe authority established elsewhere, not
proof of human approval. No repository, gateway, clock, IDs or queue are acquired.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import fields
from datetime import datetime, timedelta
from functools import lru_cache
from types import UnionType
from typing import Annotated, Any, Literal, Self, Union, get_args, get_origin, get_type_hints

from c2hunter_analysis import behavior_baseline as b
from c2hunter_analysis.domain import Flow
from pydantic import Field, PlainSerializer, PlainValidator, model_validator

from . import historical_baseline as h
from .historical_read import HistoricalReadSnapshot
from .historical_source import SourceProjection, source_build_input
from .schemas import DEFAULT_DETECTOR_WEIGHTS


def _require(condition: bool, code: str = "BASELINE_GENERATION_MISMATCH") -> None:
    if not condition:
        raise ValueError(code)


def _unmodel(value: Any, *, _depth: int = 0) -> Any:
    # Unlike model_dump this retains unknown fields in forged/model_copy values.
    # Bound collection admission before copying or invoking a member decoder.
    _require(_depth <= 16, "BASELINE_GENERATION_LIMIT")
    if isinstance(value, h.FrozenDTO):
        _require(not value.__pydantic_extra__)
        _require(set(vars(value)) == set(type(value).model_fields))
        value = vars(value)
    if type(value) is dict:
        _require(all(type(k) is str for k in value))
        for key, limit in (("windows", 2048), ("sources", 16), ("ancestry_job_ids", 16)):
            if key in value:
                _require(
                    type(value[key]) in (list, tuple) and len(value[key]) <= limit,
                    "BASELINE_GENERATION_LIMIT",
                )
        return {k: _unmodel(v, _depth=_depth + 1) for k, v in value.items()}
    if type(value) is tuple:
        return tuple(_unmodel(v, _depth=_depth + 1) for v in value)
    if type(value) is list:
        return [_unmodel(v, _depth=_depth + 1) for v in value]
    return value


@lru_cache(maxsize=32)
def _shape(kind: type[Any]) -> dict[str, Any]:
    # Only the generation closure uses this preflight; no general source parser.
    if issubclass(kind, h.FrozenDTO):
        return {name: field.rebuild_annotation() for name, field in kind.model_fields.items()}
    _require(kind in (b.BehaviorWindow, b.ProfileKey))
    shape = get_type_hints(kind)
    # Pure dataclasses carry their scalar bounds in validators, not annotations.
    limits = (
        {
            "scope_config_sha256": 64,
            "sensor_key": 200,
            "internal_host_ip": 45,
            "host_epoch": 64,
            "peer_ip": 45,
            "protocol": 256,
        }
        if kind is b.ProfileKey
        else {"source_receipt_id": 36, "event_start": 27, "event_end": 27}
    )
    for name, maximum in limits.items():
        shape[name] = Annotated[shape[name], Field(max_length=maximum)]
    return shape


def _preflight(value: Any, kind: Any, *, nodes: list[int] | None = None, depth: int = 0) -> None:
    """Bounded read-only shape/type admission, before any recursive value copy.

    Semantic validators remain authoritative. JSON parsing has its own byte cap;
    this is not a pre-parse CPU bound or a sandbox for arbitrary Python objects.
    """
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    _require(depth <= 16 and nodes[0] <= 262144, "BASELINE_GENERATION_LIMIT")
    origin, args = get_origin(kind), get_args(kind)
    maximum = None
    if origin is Annotated:
        kind, *metadata = args
        for item in metadata:
            for constraint in (item, *getattr(item, "metadata", ())):
                bound = getattr(constraint, "max_length", None)
                pattern = getattr(constraint, "pattern", None)
                if pattern == r"^[0-9a-f]{64}$":
                    bound = 64
                elif pattern == (
                    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
                ):
                    bound = 36
                if bound is not None:
                    maximum = bound if maximum is None else min(maximum, bound)
        origin, args = get_origin(kind), get_args(kind)
    if origin in (UnionType, Union):
        if args == (ApprovalReceipt, ControlReceipt):
            # Only this closed mixed receipt union is action-discriminated.
            if type(value) in (ApprovalReceipt, ControlReceipt):
                _require(not value.__pydantic_extra__)
                value = vars(value)
            _require(type(value) is dict and len(value) <= 8)
            _require(all(type(name) is str for name in value))
            action = value.get("action")
            _require(type(action) is str)
            if action == "APPROVE":
                receipt_kind: type[ApprovalReceipt] | type[ControlReceipt] = ApprovalReceipt
            else:
                _require(action in get_args(ControlAction))
                receipt_kind = ControlReceipt
            _preflight(value, receipt_kind, nodes=nodes, depth=depth)
            return
        # Generation's unions are nullable scalars/records, never competing shapes.
        if value is None and type(None) in args:
            return
        choices = [item for item in args if item is not type(None)]
        _require(len(choices) == 1)
        choice = (
            Annotated[choices[0], Field(max_length=maximum)] if maximum is not None else choices[0]
        )
        _preflight(value, choice, nodes=nodes, depth=depth)
        return
    if origin is tuple:
        _require(type(value) in (list, tuple))
        # DTO bounds come from their fields; the only pure tuple is reasons.
        limit = maximum if maximum is not None else len(get_args(b.ReasonCode))
        _require(len(value) <= limit, "BASELINE_GENERATION_LIMIT")
        _require(nodes[0] + len(value) <= 262144, "BASELINE_GENERATION_LIMIT")
        for item in value:
            _preflight(item, args[0], nodes=nodes, depth=depth + 1)
        return
    if isinstance(kind, type) and (
        issubclass(kind, h.FrozenDTO) or kind in (b.BehaviorWindow, b.ProfileKey)
    ):
        if type(value) is kind:
            if isinstance(value, h.FrozenDTO):
                _require(not value.__pydantic_extra__)
            value = vars(value)
        _require(type(value) is dict)
        shape = _shape(kind)
        # Width before key iteration; closed names before visiting any values.
        _require(len(value) <= len(shape))
        _require(all(type(name) is str and name in shape for name in value))
        for name, item in value.items():
            _preflight(item, shape[name], nodes=nodes, depth=depth + 1)
        return
    if origin is Literal:
        _require(any(type(value) is type(item) and value == item for item in args))
        return
    if kind is str:
        _require(type(value) is str)
        _require(len(value) <= (maximum or 2097152), "BASELINE_GENERATION_LIMIT")
    elif kind is datetime:
        _require(type(value) in (str, datetime))
        if type(value) is str:
            _require(len(value) <= (maximum or 2097152), "BASELINE_GENERATION_LIMIT")
    elif kind is float:
        _require(type(value) in (int, float))
    else:
        _require(kind in (bool, int, type(None)) and type(value) is kind)


class _Value(h.FrozenDTO):
    @classmethod
    def from_mapping(cls, value: object) -> Self:
        _require(type(value) is dict)
        return cls.model_validate(value)

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        from_attributes: bool | None = None,
        context: Any = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        _require(strict is not False and not from_attributes)
        _preflight(obj, cls)
        return super().model_validate(
            _unmodel(obj),
            strict=True,
            from_attributes=False,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        context: Any = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        _require(strict is not False)
        _require(isinstance(json_data, str | bytes | bytearray))
        _require(len(json_data) <= 2097152, "BASELINE_GENERATION_LIMIT")
        if isinstance(json_data, bytes | bytearray):
            json_data = json_data.decode("utf-8")
        if not isinstance(json_data, str):
            raise ValueError("BASELINE_GENERATION_MISMATCH")
        _require(len(json_data.encode("utf-8")) <= 2097152, "BASELINE_GENERATION_LIMIT")

        def pairs(entries: list[tuple[str, Any]]) -> dict[str, Any]:
            result = dict(entries)
            _require(len(result) == len(entries))
            return result

        try:
            parsed = json.loads(json_data, object_pairs_hook=pairs)
        except (RecursionError, json.JSONDecodeError) as error:
            raise ValueError("BASELINE_GENERATION_MISMATCH") from error
        return cls.model_validate(
            parsed, strict=True, context=context, by_alias=by_alias, by_name=by_name
        )

    @model_validator(mode="before")
    @classmethod
    def revalidate_nested(cls, value: Any) -> Any:
        _preflight(value, cls)
        return _unmodel(value)


def _snapshot_items(value: Any) -> Any:
    """Borrow entries without thawing, reordering or losing original JSON kind."""
    if type(value) is h.FrozenObject:
        _require(type(value.entries) is tuple and len(value.entries) <= 262144)
        _require(all(type(pair) is tuple and len(pair) == 2 for pair in value.entries))
        return value.entries
    _require(type(value) is dict)
    return value.items()


def _snapshot_raw(
    value: Any, role: str = "", *, depth: int = 0, nodes: list[int] | None = None
) -> None:
    """Read-only original-cell shapes; domain validators still own semantics."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    _require(depth <= 16 and nodes[0] <= 262144, "BASELINE_GENERATION_LIMIT")
    if role == "scalar":
        _require(value is None or type(value) in (str, bool, int, float))
        if type(value) is str:
            _require(len(value) <= 8 * 1024 * 1024)
        return
    arrays = {
        "sizes": (128, "scalar"),
        "syns": (256, "syn"),
        "strings": (128, "scalar"),
        "evidence_rows": (262144, "evidence"),
        "factor_rows": (128, "factor"),
    }
    if role in arrays:
        limit, child = arrays[role]
        _require(type(value) in (list, tuple) and len(value) <= limit)
        for item in value:
            _snapshot_raw(item, child, depth=depth + 1, nodes=nodes)
        return
    if role == "syn" and type(value) in (list, tuple):
        _require(len(value) == 2)
        for item in value:
            _require(type(item) is int)
        return
    shapes = {
        "flow": h.FLOW_FIELDS,
        "candidate": h.CANDIDATE_FIELDS,
        "allowlist": h.ALLOWLIST_FIELDS,
        "operations": h.OPERATIONS_FIELDS,
        "sensor": h.SENSOR_OPERATION_FIELDS,
        "evidence": h.EVIDENCE_FIELDS,
        "factor": h.FACTOR_FIELDS,
        "syn": frozenset(("offset_us", "sequence")),
        "analysis": h.AnalysisParameters.model_fields,
        "weights": DEFAULT_DETECTOR_WEIGHTS,
    }
    if role in shapes or role in ("sensors", "flags") or type(value) in (dict, h.FrozenObject):
        entries = _snapshot_items(value)
        allowed = shapes.get(role)
        limit = len(allowed) if allowed is not None else (128 if role == "sensors" else 262144)
        if role == "flags":
            limit = 16
        _require(len(entries) <= limit)
        # Close every key before looking at even the first (possibly poison) value.
        seen = set()
        for key, _ in entries:
            _require(type(key) is str and key not in seen)
            _require(allowed is None or key in allowed)
            seen.add(key)
        for key, item in entries:
            child = "scalar" if role else ""
            if role == "analysis":
                if key == "detector_weights":
                    _snapshot_raw(item, "weights", depth=depth + 1, nodes=nodes)
                else:
                    _snapshot_preflight(
                        item, h.AnalysisParameters.model_fields[key].rebuild_annotation()
                    )
                continue
            if role == "flow":
                child = {
                    "packet_sizes": "sizes",
                    "tcp_flags": "flags",
                    "tcp_syn_only_observations": "syns",
                }.get(key, "scalar")
            elif role == "candidate":
                child = {
                    "internal_hosts": "strings",
                    "hosts": "strings",
                    "protocols": "strings",
                    "ports": "strings",
                    "evidence": "evidence_rows",
                    "prefilter_factors": "factor_rows",
                }.get(key, "scalar")
            elif role in ("evidence", "factor") and key == "metrics":
                child = ""
            elif role == "operations":
                child = "sensors" if key == "sensors" else "strings"
            elif role == "sensors":
                child = "sensor"
            if (
                item is None
                and role in ("flow", "candidate")
                and key not in ("evidence", "prefilter_factors")
            ):
                continue
            _snapshot_raw(item, child, depth=depth + 1, nodes=nodes)
        return
    if type(value) in (tuple, list):
        _require(len(value) + nodes[0] <= 262144)
        for item in value:
            _snapshot_raw(item, depth=depth + 1, nodes=nodes)
    else:
        _require(value is None or type(value) in (str, bool, int, float))
    if type(value) is str:
        _require(len(value) <= 8 * 1024 * 1024)


@lru_cache(maxsize=64)
def _snapshot_shape(kind: Any) -> dict[str, Any]:
    if kind is Flow:
        return get_type_hints(Flow)
    shape = _shape(kind).copy()
    if kind is HistoricalReadSnapshot:
        shape["candidates"] = Annotated[tuple[h.CandidateProjection, ...], Field(max_length=2048)]
    if kind is h.OriginalFlowProjection:
        shape["fields"] = Annotated[h.FrozenObject, "flow"]
    elif kind is h.CandidateProjection:
        shape["fields"] = Annotated[h.FrozenObject, "candidate"]
    elif kind is h.OriginalJobProjection:
        shape["analysis"] = Annotated[h.FrozenObject, "analysis"]
        shape["allowlist"] = h.Observed[
            Annotated[tuple[Annotated[h.FrozenObject, "allowlist"], ...], Field(max_length=128)]
        ]
        shape["operations"] = h.Observed[Annotated[h.FrozenObject, "operations"]]
    return shape


def _snapshot_preflight(value: Any, kind: Any, *, depth: int = 0) -> None:
    """Snapshot closure has original cells, tagged observations and opaque Flows.

    These are not generation reason tuples. Their own existing cell budgets and
    collection caps apply, independently of the generation document node meter.
    No validator below is replaced, and no source value is normalized here.
    """
    _require(depth <= 16, "BASELINE_GENERATION_LIMIT")
    origin, args = get_origin(kind), get_args(kind)
    maximum = 262144
    role = ""
    if origin is Annotated:
        kind, *metadata = args
        for item in metadata:
            if type(item) is str:
                role = item
            for constraint in (item, *getattr(item, "metadata", ())):
                bound = getattr(constraint, "max_length", None)
                if bound is not None:
                    maximum = min(maximum, bound)
        origin, args = get_origin(kind), get_args(kind)
    if origin is h.Observed:
        raw = vars(value) if isinstance(value, h.FrozenDTO) else value
        _require(type(raw) is dict)
        present = raw.get("present")
        # Defaults are accepted by the existing tagged DTO decoder.
        if present is None and isinstance(value, h.Present):
            present = True
        _require(type(present) is bool)
        kind = h.Present.__class_getitem__(args[0]) if present else h.Absent
    elif origin in (Union, UnionType):
        if value is None and type(None) in args:
            return
        choices = [item for item in args if item is not type(None)]
        if set(choices) == {int, float}:
            _require(type(value) in (int, float))
            return
        _require(len(choices) == 1)
        _snapshot_preflight(value, choices[0], depth=depth)
        return
    elif origin in (tuple, list):
        _require(type(value) in (tuple, list) and len(value) <= maximum)
        for item in value:
            _snapshot_preflight(item, args[0], depth=depth + 1)
        return
    elif origin is dict:
        entries = _snapshot_items(value)
        _require(len(entries) <= maximum)
        for key, item in entries:
            _snapshot_preflight(key, args[0], depth=depth + 1)
            _snapshot_preflight(item, args[1], depth=depth + 1)
        return
    if kind is h.FrozenObject:
        _snapshot_raw(value, role)
        h._validate_original(
            value,
            frozen=type(value) is h.FrozenObject,
            max_bytes=65536 if role in ("flow", "candidate") else 8 * 1024 * 1024,
        )
        return
    if kind is Flow:
        raw = vars(value) if type(value) is Flow else value
        _require(type(raw) is dict and set(raw) == {field.name for field in fields(Flow)})
        # Keep all measurements; admission reads their declared scalar kinds,
        # never projects a Flow onto the smaller original-row field allowlist.
        for name, limit in (("packet_sizes", 128), ("tcp_syn_only_observations", 256)):
            items = raw[name]
            if items is None and name == "tcp_syn_only_observations":
                continue
            _require(type(items) in (tuple, list) and len(items) <= limit)
        flags = raw["tcp_flags"]
        _require(flags is None or (isinstance(flags, Mapping) and len(flags) <= 16))
        for name, item in raw.items():
            if name == "tcp_flags":
                if item is not None:
                    for key, number in item.items():
                        _require(type(key) is str and type(number) in (int, float))
            elif name == "tcp_syn_only_observations":
                if item is not None:
                    _snapshot_raw(item, "syns")
            else:
                _snapshot_preflight(item, _snapshot_shape(Flow)[name])
        return
    if isinstance(kind, type) and issubclass(kind, h.FrozenDTO):
        if isinstance(value, h.FrozenDTO):
            _require(not value.__pydantic_extra__)
            _require(set(vars(value)) == set(type(value).model_fields))
            value = vars(value)
        _require(type(value) is dict)
        shape = _snapshot_shape(kind)
        _require(len(value) <= len(shape))
        _require(all(type(name) is str and name in shape for name in value))
        if kind is SourceProjection:
            # The authoritative counter borrows original row entries. Bound and
            # close those containers before it scans keys, but never visit SYN
            # members until the source-wide count (not just each row) is admitted.
            original = value.get("original")
            if type(original) is h.OriginalJobProjection:
                original = vars(original)
            _require(type(original) is dict)
            _require(len(original) <= len(h.OriginalJobProjection.model_fields))
            _require(
                all(type(k) is str and k in h.OriginalJobProjection.model_fields for k in original)
            )
            rows = original.get("flow_records")
            _require(type(rows) in (list, tuple) and len(rows) <= 8192)
            for row in rows:
                if type(row) is h.OriginalFlowProjection:
                    row = vars(row)
                _require(
                    type(row) is dict and len(row) <= len(h.OriginalFlowProjection.model_fields)
                )
                _require(
                    all(type(k) is str and k in h.OriginalFlowProjection.model_fields for k in row)
                )
                cell = row.get("fields")
                if type(cell) is h.FrozenObject:
                    _require(
                        type(cell.entries) is tuple and len(cell.entries) <= len(h.FLOW_FIELDS)
                    )
                else:
                    _require(type(cell) is dict and len(cell) <= len(h.FLOW_FIELDS))
                entries = _snapshot_items(cell)
                seen = set()
                for key, _ in entries:
                    _require(type(key) is str and key in h.FLOW_FIELDS and key not in seen)
                    seen.add(key)
            admit_collections: Any = SourceProjection.strict_collection_caps
            admit_collections(value)
        for name, item in value.items():
            _snapshot_preflight(item, shape[name], depth=depth + 1)
        if kind is h.OriginalJobProjection:
            h._admit_original_job(value, projected=True)
        return
    # Keep unbounded source Text's existing 8MiB envelope, not generation's 2MiB.
    if kind in (str, datetime):
        _require(type(value) in ((str, datetime) if kind is datetime else (str,)))
        if type(value) is str:
            _require(len(value) <= (8 * 1024 * 1024 if maximum == 262144 else maximum))
        return
    _preflight(value, kind)


def _checked[T: h.FrozenDTO](cls: type[T], value: T) -> T:
    _require(type(value) is cls)
    if issubclass(cls, _Value):
        return cls.model_validate(value)
    if cls is h.ScopeConfig:
        _preflight(value, cls)
    if cls is HistoricalReadSnapshot:
        _snapshot_preflight(value, cls)
    return cls.model_validate(_unmodel(value))


class SourceReceipt(_Value):
    source_receipt_id: h.UUIDString
    source_job_id: h.Identifier
    root_job_id: h.Identifier
    dataset_id: h.Identifier
    root_identity: Annotated[h.Text, Field(min_length=1, max_length=420)]
    ancestry_job_ids: Annotated[tuple[h.Identifier, ...], Field(min_length=1, max_length=16)]
    root_content_sha256: h.Digest | None
    source_binding_sha256: h.Digest
    observation_sha256: h.Digest
    feature_observation_sha256: h.Digest
    actual_sensor_id: h.Identifier
    sensor_key: h.Identifier
    event_start: h.UTCDateTime
    event_end: h.UTCDateTime
    origin: h.Origin
    origin_assurance: Literal["STORED_LINEAGE_ONLY"]
    normality: Literal["APPROVED_NORMAL"]
    approved_by: h.Identifier
    approved_at: h.UTCDateTime
    reason: h.ReasonText
    quality_review: h.QualityReview
    producer_completeness: Literal["UNKNOWN"]
    known_partial: Literal[False]
    limitations: Annotated[tuple[b.ReasonCode, ...], Field(max_length=30)]

    @model_validator(mode="after")
    def receipt_links(self) -> Self:
        _require(self.event_start < self.event_end)
        _require(len(set(self.ancestry_job_ids)) == len(self.ancestry_job_ids))
        _require(
            self.source_job_id in self.ancestry_job_ids
            and self.root_job_id in self.ancestry_job_ids
        )
        if self.origin == "SENSOR_CAPTURE":
            _require(not self.dataset_id.startswith("pcap:"))
            _require(self.root_content_sha256 is None)
            _require(self.root_identity == h.canonical_json([self.root_job_id, self.dataset_id]))
        else:
            _require(self.root_content_sha256 is not None)
            _require(
                self.root_identity == self.dataset_id == "pcap:" + str(self.root_content_sha256)
            )
        _require(tuple(sorted(set(self.limitations))) == self.limitations)
        _require(
            len(h.canonical_json(self.to_mapping()).encode("utf-8")) <= 8192,
            "BASELINE_GENERATION_LIMIT",
        )
        return self


class ApprovalRequest(_Value):
    expected_revision: h.Nonnegative
    idempotency_key: h.Identifier
    source_job_id: h.Identifier
    source_binding_sha256: h.Digest
    normality: Literal["APPROVED_NORMAL"]
    quality_review: h.QualityReview
    reason: h.ReasonText


class ApprovalReceipt(_Value):
    operation_id: h.UUIDString
    action: Literal["APPROVE"]
    revision: Annotated[int, Field(ge=1, le=2**63 - 1)]
    actor: h.Identifier
    occurred_at: h.UTCDateTime
    generation_id: h.UUIDString
    source_job_id: h.Identifier
    source_binding_sha256: h.Digest


ControlAction = Literal["FREEZE", "UNFREEZE", "ROLLBACK", "REVOKE", "RETIRE"]


class ControlRequest(_Value):
    expected_revision: h.Nonnegative
    idempotency_key: h.Identifier
    action: ControlAction
    reason: h.ReasonText
    generation_id: h.UUIDString | None

    @model_validator(mode="after")
    def target_links(self) -> Self:
        _require((self.action == "ROLLBACK") == (self.generation_id is not None))
        return self


class ControlReceipt(_Value):
    operation_id: h.UUIDString
    action: ControlAction
    revision: Annotated[int, Field(ge=1, le=2**63 - 1)]
    actor: h.Identifier
    occurred_at: h.UTCDateTime
    generation_id: h.UUIDString | None

    @model_validator(mode="after")
    def target_links(self) -> Self:
        _require((self.action == "ROLLBACK") == (self.generation_id is not None))
        return self


OperationReceipt = ApprovalReceipt | ControlReceipt


class _Authority(_Value):
    """Internal closed input record; caller-established authority, not authentication."""

    operation_id: h.UUIDString
    generation_id: h.UUIDString
    actor: h.Identifier
    now: h.UTCDateTime
    accepted_event_end: h.UTCDateTime | None


class GenerationView(_Value):
    generation_id: h.UUIDString
    content_sha256: h.Digest
    feature_version: Literal["behavior-window-v1"]
    published_at: h.UTCDateTime
    published_by: h.Identifier
    source_window_count: Annotated[int, Field(ge=1, le=16)]
    profile_count: Annotated[int, Field(ge=1, le=128)]
    oldest_event_start: h.UTCDateTime
    newest_event_end: h.UTCDateTime
    byte_size: Annotated[int, Field(ge=1, le=2097152)]
    identity_assurance: Literal["ADMIN_ASSERTED"]
    producer_completeness: Literal["UNKNOWN"]

    @model_validator(mode="after")
    def event_extrema(self) -> Self:
        _require(self.oldest_event_start < self.newest_event_end)
        return self


class ScopeView(_Value):
    config: h.ScopeConfig
    config_sha256: h.Digest
    control_revision: h.Nonnegative
    frozen: bool
    state: Literal["EMPTY", "HAS_REFERENCE", "REVOKED", "RETIRED"]
    accepted_event_end: h.UTCDateTime | None
    active: GenerationView | None
    previous: GenerationView | None
    created_by: h.Identifier
    created_at: h.UTCDateTime

    @model_validator(mode="after")
    def scope_links(self) -> Self:
        _require(self.config_sha256 == h.scope_config_sha256(self.config))
        _require((self.state == "HAS_REFERENCE") == (self.active is not None))
        _require(self.active is not None or self.previous is None)
        if self.state == "EMPTY":
            _require(self.accepted_event_end is None)
        if self.active is not None and self.previous is not None:
            _require(self.active.generation_id != self.previous.generation_id)
        for view in (self.active, self.previous):
            if view is not None:
                _require(
                    self.accepted_event_end is not None
                    and view.newest_event_end <= self.accepted_event_end
                )
        return self


class ScopePage(_Value):
    items: Annotated[tuple[ScopeView, ...], Field(max_length=16)]
    total: Annotated[int, Field(ge=0, le=16)]
    offset: Annotated[int, Field(ge=0, le=16)]
    limit: Annotated[int, Field(ge=1, le=20)]
    next_offset: Annotated[int, Field(ge=0, le=16)] | None

    @model_validator(mode="after")
    def page_links(self) -> Self:
        _require(len(self.items) == min(self.limit, max(0, self.total - self.offset)))
        expected = self.offset + len(self.items)
        _require(self.next_offset == (expected if expected < self.total else None))
        identifiers = tuple(item.config.scope_id for item in self.items)
        _require(identifiers == tuple(sorted(set(identifiers))))
        return self


class PublicationResult(_Value):
    scope: ScopeView
    receipt: ApprovalReceipt
    created: bool

    @model_validator(mode="after")
    def publication_links(self) -> Self:
        _require(self.receipt.revision <= self.scope.control_revision)
        return self


class ControlResult(_Value):
    scope: ScopeView
    receipt: ControlReceipt

    @model_validator(mode="after")
    def control_links(self) -> Self:
        _require(self.receipt.revision <= self.scope.control_revision)
        return self


class ControlPage(_Value):
    items: Annotated[tuple[OperationReceipt, ...], Field(max_length=20)]
    total: Annotated[int, Field(ge=0, le=64)]
    offset: Annotated[int, Field(ge=0, le=64)]
    limit: Annotated[int, Field(ge=1, le=20)]
    next_offset: Annotated[int, Field(ge=0, le=64)] | None
    earliest_retained_revision: Annotated[int, Field(ge=1, le=2**63 - 1)] | None

    @model_validator(mode="after")
    def page_links(self) -> Self:
        _require(len(self.items) == min(self.limit, max(0, self.total - self.offset)))
        end = self.offset + len(self.items)
        _require(self.next_offset == (end if end < self.total else None))
        _require((self.total == 0) == (self.earliest_retained_revision is None))
        revisions = tuple(item.revision for item in self.items)
        _require(revisions == tuple(sorted(set(revisions), reverse=True)))
        if revisions:
            _require(
                self.earliest_retained_revision is not None
                and revisions[-1] >= self.earliest_retained_revision
            )
            if end == self.total:
                _require(revisions[-1] == self.earliest_retained_revision)
        return self


class SourcePage(_Value):
    items: Annotated[tuple[SourceReceipt, ...], Field(max_length=16)]
    total: Annotated[int, Field(ge=0, le=16)]
    offset: Annotated[int, Field(ge=0, le=16)]
    limit: Annotated[int, Field(ge=1, le=20)]
    next_offset: Annotated[int, Field(ge=0, le=16)] | None

    @model_validator(mode="after")
    def page_links(self) -> Self:
        _require(len(self.items) == min(self.limit, max(0, self.total - self.offset)))
        end = self.offset + len(self.items)
        _require(self.next_offset == (end if end < self.total else None))
        keys = tuple((item.event_end, item.source_receipt_id) for item in self.items)
        _require(keys == tuple(sorted(set(keys))))
        return self


class SourcePreview(_Value):
    scope_id: h.UUIDString
    scope_revision: h.Nonnegative
    scope_config_sha256: h.Digest
    source_job_id: h.Identifier
    root_job_id: h.Identifier
    dataset_id: h.Identifier
    source_binding_sha256: h.Digest
    observation_sha256: h.Digest
    feature_observation_sha256: h.Digest
    origin: Literal["SENSOR_CAPTURE", "PCAP_UPLOAD"]
    origin_assurance: Literal["STORED_LINEAGE_ONLY"]
    actual_sensor_id: h.Identifier
    event_start: h.UTCDateTime
    event_end: h.UTCDateTime
    flow_count: Annotated[int, Field(ge=0, le=8192)]
    profile_count: Annotated[int, Field(ge=0, le=128)]
    eligible_profile_count: Annotated[int, Field(ge=0, le=128)]
    excluded_profile_count: Annotated[int, Field(ge=0, le=128)]
    admissible: bool
    reasons: Annotated[tuple[b.ReasonCode, ...], Field(max_length=30)]
    required_review: Literal["EXPLICIT_NORMAL_AND_QUALITY_ASSERTION"]
    producer_completeness: Literal["UNKNOWN"]
    known_partial: bool
    # The numerical preflight admits int/float; the shared observed-number
    # validator and identity serializer preserve the original scalar exactly.
    stored_clock_offset_ms: (
        Annotated[float, PlainValidator(h._number), PlainSerializer(lambda value: value)] | None
    )

    @model_validator(mode="after")
    def preview_links(self) -> Self:
        _require(self.event_start < self.event_end)
        _require(self.eligible_profile_count + self.excluded_profile_count == self.profile_count)
        _require(self.reasons == tuple(sorted(set(self.reasons))))
        _require(self.profile_count <= self.flow_count)
        _require(
            self.admissible
            == (
                self.eligible_profile_count > 0
                and not self.known_partial
                and "SOURCE_CLOCK_UNCERTAIN" not in self.reasons
            )
        )
        return self


def _window(value: object) -> b.BehaviorWindow:
    if type(value) is b.BehaviorWindow:
        _require(set(vars(value)) == {f.name for f in fields(b.BehaviorWindow)})
        _require(set(vars(value.key)) == {f.name for f in fields(b.ProfileKey)})
        value = b.behavior_window_to_mapping(value)
    window = b.behavior_window_from_mapping(value)
    _require(
        len(h.canonical_json(b.behavior_window_to_mapping(window)).encode("utf-8")) <= 1024,
        "BASELINE_GENERATION_LIMIT",
    )
    return window


Window = Annotated[
    b.BehaviorWindow, PlainValidator(_window), PlainSerializer(b.behavior_window_to_mapping)
]


class GenerationDocument(_Value):
    schema_version: Literal["historical-baseline-v1"]
    generation_id: h.UUIDString
    scope_id: h.UUIDString
    scope_config_sha256: h.Digest
    feature_version: Literal["behavior-window-v1"]
    publication_revision: Annotated[int, Field(ge=1, le=2**63 - 1)]
    published_at: h.UTCDateTime
    published_by: h.Identifier
    sources: Annotated[tuple[SourceReceipt, ...], Field(min_length=1, max_length=16)]
    windows: Annotated[tuple[Window, ...], Field(min_length=1, max_length=2048)]

    @model_validator(mode="after")
    def wrapper_budget(self) -> Self:
        # Domain windows have their own exact pure serializer, not asdict.
        sources = {s.source_receipt_id: s for s in self.sources}
        _require(len(sources) == len(self.sources))
        _require(len({s.root_identity for s in self.sources}) == len(self.sources))
        _require(len({s.feature_observation_sha256 for s in self.sources}) == len(self.sources))
        _require(
            self.sources
            == tuple(sorted(self.sources, key=lambda s: (s.event_end, s.source_receipt_id)))
        )
        _require(self.windows == tuple(sorted(self.windows, key=_window_order)))
        _require(self.publication_revision >= len(self.sources))
        newest = self.sources[-1]
        _require((newest.approved_at, newest.approved_by) == (self.published_at, self.published_by))
        for index, source in enumerate(self.sources):
            _require(newest.event_end - source.event_end <= timedelta(days=30))
            if index:
                _require(source.event_start > self.sources[index - 1].event_end)
        records: dict[str, int] = {}
        pairs = set()
        linked = set()
        for window in self.windows:
            b._window(window, publication=True)
            _require(window.source_receipt_id in sources)
            source = sources[str(window.source_receipt_id)]
            records[source.source_receipt_id] = (
                records.get(source.source_receipt_id, 0) + window.outbound_record_count
            )
            _require(records[source.source_receipt_id] <= 8192)
            _require(
                (window.event_start, window.event_end) == (source.event_start, source.event_end)
            )
            _require(
                (window.key.scope_config_sha256, window.key.sensor_key, window.key.feature_version)
                == (self.scope_config_sha256, source.sensor_key, self.feature_version)
            )
            pair = (window.key, window.source_receipt_id)
            _require(pair not in pairs)
            pairs.add(pair)
            linked.add(window.source_receipt_id)
        _require(linked == set(sources))
        _require(len({w.key for w in self.windows}) <= 128, "BASELINE_PROFILE_LIMIT")
        b._reference(_reference_value(self))
        _require(
            len(h.canonical_json(self.to_mapping()).encode("utf-8")) <= 2097152,
            "BASELINE_GENERATION_LIMIT",
        )
        return self


def _reference_value(document: GenerationDocument) -> b.BaselineReference:
    # Call only after document receipt/window links have been validated.
    sources = {s.source_receipt_id: s for s in document.sources}
    return b.BaselineReference(
        tuple(
            b.ReferenceWindow(
                w,
                b.ObservationIdentity(
                    sources[str(w.source_receipt_id)].root_identity,
                    sources[str(w.source_receipt_id)].dataset_id,
                    sources[str(w.source_receipt_id)].feature_observation_sha256,
                ),
            )
            for w in document.windows
        )
    )


def _window_order(window: b.BehaviorWindow) -> str:
    return h.canonical_json([b.behavior_window_to_mapping(window)["key"], window.source_receipt_id])


def generation_json(document: GenerationDocument) -> str:
    return h.canonical_json(_checked(GenerationDocument, document).to_mapping())


def generation_view(document: GenerationDocument) -> GenerationView:
    raw = generation_json(document).encode("utf-8")
    return GenerationView(
        generation_id=document.generation_id,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        feature_version=document.feature_version,
        published_at=document.published_at,
        published_by=document.published_by,
        source_window_count=len(document.sources),
        profile_count=len({w.key for w in document.windows}),
        oldest_event_start=min(s.event_start for s in document.sources),
        newest_event_end=max(s.event_end for s in document.sources),
        byte_size=len(raw),
        identity_assurance="ADMIN_ASSERTED",
        producer_completeness="UNKNOWN",
    )


def decode_generation(
    raw: str, *, content_sha256: str, byte_size: int, scope: h.ScopeConfig
) -> GenerationDocument:
    _require(type(raw) is str and len(raw) <= 2097152, "BASELINE_GENERATION_LIMIT")
    _require(type(byte_size) is int and 1 <= byte_size <= 2097152)
    data = raw.encode("utf-8")
    _require(len(data) <= 2097152, "BASELINE_GENERATION_LIMIT")
    if len(data) != byte_size or hashlib.sha256(data).hexdigest() != content_sha256:
        raise ValueError("BASELINE_GENERATION_MISMATCH")
    document = GenerationDocument.model_validate_json(raw)
    generation_reference(document, scope=scope)
    if generation_json(document) != raw:
        raise ValueError("BASELINE_GENERATION_MISMATCH")
    return document


def generation_reference(
    document: GenerationDocument, *, scope: h.ScopeConfig
) -> b.BaselineReference:
    document = _checked(GenerationDocument, document)
    scope = _checked(h.ScopeConfig, scope)
    _require(
        document.scope_id == scope.scope_id
        and document.scope_config_sha256 == h.scope_config_sha256(scope)
    )
    reference = _reference_value(document)
    identity = b.BaselineScopeIdentity(
        h.scope_config_sha256(scope),
        scope.kind,
        scope.sensor_key,
        scope.stored_sensor_id,
        scope.internal_networks,
        scope.window_seconds,
        tuple(b.HostEpoch(host.ip, host.epoch) for host in scope.hosts),
        "behavior-window-v1",
    )
    for source in document.sources:
        h.validate_sensor_assertion(
            scope,
            actual_sensor_id=source.actual_sensor_id,
            review=source.quality_review,
            origin=source.origin,
        )
    b._reference(reference, identity)
    return b.baseline_reference_from_mapping(b.baseline_reference_to_mapping(reference))


def approval_receipt(document: GenerationDocument, *, operation_id: str) -> ApprovalReceipt:
    """Derive the exact approval receipt; does not persist an operation or replay."""
    document = _checked(GenerationDocument, document)
    source = document.sources[-1]
    _require(source.source_receipt_id == operation_id)
    return ApprovalReceipt(
        operation_id=operation_id,
        action="APPROVE",
        revision=document.publication_revision,
        actor=document.published_by,
        occurred_at=document.published_at,
        generation_id=document.generation_id,
        source_job_id=source.source_job_id,
        source_binding_sha256=source.source_binding_sha256,
    )


def produce_generation(
    *,
    snapshot: HistoricalReadSnapshot,
    scope: ScopeView,
    current_generation: GenerationDocument | None,
    accepted_event_end: datetime | None,
    request: ApprovalRequest,
    operation_id: str,
    generation_id: str,
    actor: str,
    now: datetime,
) -> GenerationDocument:
    """Closed keyword inputs are immutable values only; returns a document, not a commit.

    accepted_event_end is the durable caller-supplied watermark, never inferred
    from the selected generation. Retained replay and final fenced reread belong
    to the future repository operation, not this deterministic value function.
    """
    authority = _Authority(
        operation_id=operation_id,
        generation_id=generation_id,
        actor=actor,
        now=now,
        accepted_event_end=accepted_event_end,
    )
    now, accepted_event_end = authority.now, authority.accepted_event_end
    snapshot = _checked(HistoricalReadSnapshot, snapshot)
    scope = _checked(ScopeView, scope)
    request = _checked(ApprovalRequest, request)
    source = snapshot.source
    if source.original.status != "COMPLETED":
        raise ValueError("BASELINE_SOURCE_STATE")
    if request.expected_revision != scope.control_revision:
        raise ValueError("BASELINE_REVISION_CONFLICT")
    _require((scope.active is None) == (current_generation is None))
    if current_generation is not None:
        current_generation = _checked(GenerationDocument, current_generation)
        generation_reference(current_generation, scope=scope.config)
        _require(generation_view(current_generation) == scope.active)
        _require(current_generation.publication_revision <= scope.control_revision)
    if scope.frozen:
        raise ValueError("BASELINE_FROZEN")
    binding = h.source_binding_sha256(source.source_binding(), purpose="APPROVAL", candidates=())
    if (
        snapshot.candidates
        or request.source_job_id != source.original.id
        or binding != snapshot.source_binding_sha256
        or binding != request.source_binding_sha256
    ):
        raise ValueError("BASELINE_SOURCE_CHANGED")
    build_input = source_build_input(
        source,
        scope=scope.config,
        quality_review=request.quality_review,
        source_receipt_id=operation_id,
    )
    if source.quality.known_partial or source.quality.clock_uncertain:
        raise ValueError("BASELINE_SOURCE_QUALITY")
    if accepted_event_end != scope.accepted_event_end:
        raise ValueError("BASELINE_EVENT_ORDER")
    if current_generation is not None and any(
        s.root_identity == source.root_identity
        or s.feature_observation_sha256 == source.feature_observation_sha256
        or s.source_receipt_id == operation_id
        for s in current_generation.sources
    ):
        raise ValueError("BASELINE_SOURCE_DUPLICATE")
    if accepted_event_end is not None and source.event_start <= accepted_event_end:
        raise ValueError("BASELINE_EVENT_ORDER")
    _require(
        all(
            view is None or view.generation_id != generation_id
            for view in (scope.active, scope.previous)
        )
    )
    # Event admission above makes the new receipt newest. Reserve its global
    # slot before deriving the retained key union, including old-only key eviction.
    retained_sources = tuple(
        s
        for s in (current_generation.sources if current_generation else ())
        if source.event_end - s.event_end <= timedelta(days=30)
    )[-15:]
    retained = {s.source_receipt_id for s in retained_sources}
    retained_windows = tuple(
        w
        for w in (current_generation.windows if current_generation else ())
        if w.source_receipt_id in retained
    )
    try:
        built = b.build_behavior_windows_with_retained_keys(
            build_input, retained_keys=tuple(dict.fromkeys(w.key for w in retained_windows))
        )
    except b.BaselineInputError as error:
        if error.code == "BASELINE_PROFILE_LIMIT":
            raise ValueError("BASELINE_PROFILE_LIMIT") from error
        raise
    if not built.eligible_profile_count:
        raise ValueError("BASELINE_SOURCE_QUALITY")
    reasons: set[b.ReasonCode] = {
        "ADMIN_ASSERTED_IDENTITY",
        "HUMAN_ASSERTED_CLOCK_BOUND",
        "PRODUCER_COMPLETENESS_UNKNOWN",
    }
    if scope.config.kind == "EVALUATION":
        reasons.add("EVALUATION_SENSOR_ALIAS")
    receipt = SourceReceipt(
        source_receipt_id=operation_id,
        source_job_id=source.original.id,
        root_job_id=source.root_job_id,
        dataset_id=source.original.dataset_id,
        root_identity=source.root_identity,
        ancestry_job_ids=tuple(n.id for n in source.lineage),
        root_content_sha256=source.root_content_sha256,
        source_binding_sha256=snapshot.source_binding_sha256,
        observation_sha256=source.observation_sha256,
        feature_observation_sha256=source.feature_observation_sha256,
        actual_sensor_id=source.actual_sensor_id,
        sensor_key=scope.config.sensor_key,
        event_start=source.event_start,
        event_end=source.event_end,
        origin=source.origin,
        origin_assurance=source.origin_assurance,
        normality=request.normality,
        approved_by=actor,
        approved_at=now,
        reason=request.reason,
        quality_review=request.quality_review,
        producer_completeness="UNKNOWN",
        known_partial=False,
        limitations=tuple(sorted(reasons)),
    )
    sources = retained_sources + (receipt,)
    windows = retained_windows + tuple(
        p.window for p in built.profiles if p.eligible_for_reference and p.window is not None
    )
    return GenerationDocument(
        schema_version="historical-baseline-v1",
        generation_id=generation_id,
        scope_id=scope.config.scope_id,
        scope_config_sha256=scope.config_sha256,
        feature_version="behavior-window-v1",
        publication_revision=scope.control_revision + 1,
        published_at=now,
        published_by=actor,
        sources=tuple(sorted(sources, key=lambda s: (s.event_end, s.source_receipt_id))),
        windows=tuple(sorted(windows, key=_window_order)),
    )
