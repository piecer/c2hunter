"""Immutable, no-I/O historical-baseline handoff values.

Original objects retain order and JSON kind. These in-memory validators do not
establish backend pre-transfer admission or sandbox arbitrary Python callbacks.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from ipaddress import ip_address, ip_network
from typing import Annotated, Any, Literal, Self, cast, get_args, get_origin

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    PlainSerializer,
    PlainValidator,
    field_validator,
    model_validator,
)

from .schemas import AnalysisParameters


@dataclass(frozen=True, slots=True)
class FrozenObject:
    """An original JSON object, distinct from an array of key/value pairs."""

    entries: tuple[tuple[str, FrozenJSON], ...]

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or any(
            type(pair) is not tuple or len(pair) != 2 for pair in self.entries
        ):
            raise ValueError("BASELINE_SOURCE_INVALID")
        _validate_original(self, frozen=True)


type FrozenJSON = None | bool | int | float | str | tuple[FrozenJSON, ...] | FrozenObject


@dataclass
class _OriginalBudget:
    """One incremental JSON meter, reusable across an admitted cell's parts."""

    max_bytes: int
    frozen: bool | None = False
    wrappers: bool = False
    nodes: int = 0
    size: int = 0

    def add(self, amount: int) -> None:
        self.size += amount
        if self.size > self.max_bytes:
            raise ValueError("BASELINE_SOURCE_LIMIT")

    def node(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > 262144 or depth > 16:
            raise ValueError("BASELINE_SOURCE_LIMIT")

    def object_items(self, entries: Iterable[tuple[object, object]], depth: int) -> None:
        self.node(depth)
        self.add(2)
        seen: set[str] = set()
        for key, child in entries:
            if type(key) is not str or key in seen:
                raise ValueError("BASELINE_SOURCE_INVALID")
            self.add(1 + bool(seen))  # colon and all but the first comma
            seen.add(key)
            self.visit(key, depth + 1)
            self.visit(child, depth + 1)

    def visit(self, item: object, depth: int = 0) -> None:
        # Children have their own validated boundary. DTO structure is not raw
        # source JSON and must not spend a child's byte/depth allowance again.
        if self.wrappers and isinstance(item, FrozenObject | FrozenDTO):
            item = None
        elif self.wrappers and isinstance(item, datetime):
            item = item.isoformat()
        if (self.frozen is not False and type(item) is FrozenObject) or (
            self.frozen is not True and type(item) is dict
        ):
            entries = (
                item.entries
                if isinstance(item, FrozenObject)
                else cast("dict[object, object]", item).items()
            )
            self.object_items(entries, depth)
            return
        self.node(depth)
        if type(item) is str:
            if len(item) > self.max_bytes - self.size:
                raise ValueError("BASELINE_SOURCE_LIMIT")
            if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in item):
                raise ValueError("BASELINE_SOURCE_INVALID")
            try:
                self.add(len(json.dumps(item, ensure_ascii=False).encode("utf-8")))
            except UnicodeError as exc:
                raise ValueError("BASELINE_SOURCE_INVALID") from exc
        elif item is None or type(item) is bool:
            self.add(len(json.dumps(item)))
        elif type(item) is int:
            if not -(2**63) <= item < 2**63:
                raise ValueError("BASELINE_SOURCE_INVALID")
            self.add(len(str(item)))
        elif type(item) is float:
            if not math.isfinite(item):
                raise ValueError("BASELINE_SOURCE_INVALID")
            self.add(len(json.dumps(item)))
        elif (self.frozen is not False and type(item) is tuple) or (
            self.frozen is not True and type(item) is list
        ):
            items = cast("tuple[object, ...] | list[object]", item)
            if len(items) + self.nodes > 262144:
                raise ValueError("BASELINE_SOURCE_LIMIT")
            self.add(2 + max(0, len(items) - 1))
            for child in items:
                self.visit(child, depth + 1)
        else:
            raise ValueError("BASELINE_SOURCE_INVALID")


def _validate_original(
    value: object, *, frozen: bool = False, max_bytes: int = 8 * 1024 * 1024
) -> int:
    budget = _OriginalBudget(max_bytes, frozen=frozen)
    budget.visit(value)
    return budget.size


def freeze_original_json(value: object, *, max_bytes: int = 8 * 1024 * 1024) -> FrozenJSON:
    """Copy admitted JSON without sorting, default filling or kind erasure."""
    _validate_original(value, max_bytes=max_bytes)
    return _freeze(value)


def _freeze(value: object) -> FrozenJSON:
    if isinstance(value, dict):
        return FrozenObject(tuple((key, _freeze(item)) for key, item in value.items()))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return cast("FrozenJSON", value)


def decode_original_json(raw: str, *, max_bytes: int = 8 * 1024 * 1024) -> FrozenJSON:
    """Decode an already-transferred bounded cell; reject duplicate object keys."""
    if len(raw) > max_bytes or len(raw.encode("utf-8")) > max_bytes:
        raise ValueError("BASELINE_SOURCE_LIMIT")

    def pairs(entries: list[tuple[str, object]]) -> dict[str, object]:
        result = dict(entries)
        if len(result) != len(entries):
            raise ValueError("BASELINE_SOURCE_INVALID")
        return result

    try:
        value = json.loads(raw, object_pairs_hook=pairs)
    except (RecursionError, json.JSONDecodeError) as exc:
        raise ValueError("BASELINE_SOURCE_INVALID") from exc
    return freeze_original_json(value, max_bytes=max_bytes)


def thaw_original_json(value: FrozenJSON) -> object:
    if isinstance(value, FrozenObject):
        return {key: thaw_original_json(item) for key, item in value.entries}
    if isinstance(value, tuple):
        return [thaw_original_json(item) for item in value]
    return value


def original_binding_value(value: FrozenJSON) -> dict[str, object]:
    if isinstance(value, FrozenObject):
        return {
            "kind": "object",
            "entries": [[key, original_binding_value(item)] for key, item in value.entries],
        }
    if isinstance(value, tuple):
        return {"kind": "array", "items": [original_binding_value(item) for item in value]}
    return {"kind": "scalar", "value": value}


def canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def original_binding_sha256(value: FrozenJSON) -> str:
    return hashlib.sha256(canonical_json(original_binding_value(value)).encode("utf-8")).hexdigest()


def _text(value: object) -> str:
    if type(value) is not str or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise ValueError("BASELINE_SOURCE_INVALID")
    return value


def _utc(value: object) -> datetime:
    if type(value) is str:
        try:
            value = datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError("BASELINE_SOURCE_INVALID") from exc
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("BASELINE_SOURCE_INVALID")
    return value.astimezone(UTC)


def _number(value: object) -> int | float:
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            raise ValueError("BASELINE_SOURCE_INVALID")
        return value
    if type(value) is not float or not math.isfinite(value):
        raise ValueError("BASELINE_SOURCE_INVALID")
    return value


Text = Annotated[str, BeforeValidator(_text)]
Identifier = Annotated[Text, Field(min_length=1, max_length=200)]
Nonnegative = Annotated[int, Field(ge=0, le=2**63 - 1)]
FiniteNumber = Annotated[int | float, BeforeValidator(_number)]
UTCDateTime = Annotated[
    datetime,
    BeforeValidator(_utc),
    PlainSerializer(
        lambda v: v.strftime("%Y-%m-%dT%H:%M:%S.%fZ"), return_type=str, when_used="json"
    ),
]
StopReason = Literal["MAX_PACKETS", "MAX_BYTES"]


class FrozenDTO(BaseModel):
    """Closed immutable value; all collection fields must be immutable too."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    @classmethod
    def from_mapping(cls, value: object) -> Self:
        return cls.model_validate(_mapping(value))

    @model_validator(mode="after")
    def wrapper_budget(self) -> Self:
        budget = _OriginalBudget(8 * 1024 * 1024, frozen=None, wrappers=True)
        budget.object_items(((key, getattr(self, key)) for key in type(self).model_fields), 0)
        return self

    def to_mapping(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @model_validator(mode="before")
    @classmethod
    def literal_bool_is_strict(cls, value: object) -> object:
        # Pydantic Literal[True/False] otherwise accepts the equal integers 1/0.
        if isinstance(value, dict):
            value = dict(value)
            for key, item in value.items():
                field = cls.model_fields.get(key)
                if (
                    field
                    and get_origin(field.annotation) is Literal
                    and any(type(v) is bool for v in get_args(field.annotation))
                    and type(item) is not bool
                ):
                    raise ValueError("BASELINE_SOURCE_INVALID")
                annotation = field.annotation if field else None
                while get_origin(annotation) is Annotated:
                    annotation = get_args(annotation)[0]
                if get_origin(annotation) is tuple and type(item) is list:
                    value[key] = tuple(item)
        return value


class Absent(FrozenDTO):
    present: Literal[False] = False


class Present[T](FrozenDTO):
    present: Literal[True] = True
    value: T


type Observed[T] = Annotated[Absent | Present[T], Field(discriminator="present")]


class CaptureCompletion(FrozenDTO):
    sensor_id: Identifier
    stop_reason: StopReason
    reported_at: UTCDateTime


class SensorOffset(FrozenDTO):
    sensor_id: Identifier
    clock_offset_ms: FiniteNumber


class SourceQualityFacts(FrozenDTO):
    capture_incomplete: Observed[bool]
    error_code: Observed[Text | None]
    skipped_packet_count: Observed[Nonnegative]
    dropped_packet_count: Observed[Nonnegative]
    clock_skew_detected: Observed[bool]
    discarded_packets: Observed[Nonnegative]
    requested_end_time: Observed[UTCDateTime]
    capture_stopped_at: Observed[UTCDateTime]
    capture_completions: Observed[Annotated[tuple[CaptureCompletion, ...], Field(max_length=128)]]
    failed_sensors: Observed[Annotated[tuple[Identifier, ...], Field(max_length=128)]]
    sensor_offsets: Annotated[tuple[SensorOffset, ...], Field(max_length=128)]


def _mapping(value: object) -> dict[str, Any]:
    if type(value) is not dict or any(type(k) is not str for k in value):
        raise ValueError("BASELINE_SOURCE_INVALID")
    return cast("dict[str, Any]", value)


def _observed_path(raw: dict[str, Any], *path: str) -> dict[str, object]:
    current = raw
    for index, key in enumerate(path):
        if key not in current:
            return {"present": False}
        if index == len(path) - 1:
            return {"present": True, "value": current[key]}
        current = _mapping(current[key])
    raise AssertionError("empty stored path")


def project_source_quality(raw: dict[str, Any]) -> SourceQualityFacts:
    """Read only named persisted paths, never heartbeat/default measurements."""
    _validate_original(raw, max_bytes=256 * 1024)
    paths = {
        "capture_incomplete": ("capture_incomplete",),
        "error_code": ("error_code",),
        "skipped_packet_count": ("source", "skipped_packet_count"),
        "dropped_packet_count": ("capture_quality", "dropped_packet_count"),
        "clock_skew_detected": ("capture_quality", "clock_skew_detected"),
        "discarded_packets": ("capture_limit", "discarded_packets"),
        "requested_end_time": ("capture", "requested_end_time"),
        "capture_stopped_at": ("capture_stopped_at",),
        "failed_sensors": ("operations", "failed_sensors"),
        "capture_completions": ("capture_completions",),
    }
    data: dict[str, Any] = {key: _observed_path(raw, *path) for key, path in paths.items()}
    failures = data["failed_sensors"]
    if failures["present"]:
        values = failures["value"]
        if type(values) is not list or len(values) > 128 or any(type(v) is not str for v in values):
            raise ValueError("BASELINE_SOURCE_INVALID")
        failures["value"] = sorted(set(values))
    completions = data["capture_completions"]
    if completions["present"]:
        mapping = _mapping(completions["value"])
        if len(mapping) > 128:
            raise ValueError("BASELINE_SOURCE_LIMIT")
        rows = []
        for sensor_id, item in sorted(mapping.items()):
            item = _mapping(item)
            if not {"stop_reason", "reported_at"} <= item.keys():
                raise ValueError("BASELINE_SOURCE_INVALID")
            rows.append(
                {
                    "sensor_id": sensor_id,
                    "stop_reason": item["stop_reason"],
                    "reported_at": item["reported_at"],
                }
            )
        completions["value"] = rows
    sensors = _observed_path(raw, "operations", "sensors")
    offsets = []
    if sensors["present"]:
        mapping = _mapping(sensors["value"])
        if len(mapping) > 128:
            raise ValueError("BASELINE_SOURCE_LIMIT")
        for sensor_id, item in sorted(mapping.items()):
            item = _mapping(item)
            if "clock_offset_ms" in item:
                offsets.append({"sensor_id": sensor_id, "clock_offset_ms": item["clock_offset_ms"]})
    data["sensor_offsets"] = offsets
    return SourceQualityFacts.from_mapping(data)


class SensorOffsetBounds(FrozenDTO):
    sensor_id: Identifier
    minimum_ms: FiniteNumber
    maximum_ms: FiniteNumber

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.minimum_ms > self.maximum_ms:
            raise ValueError("BASELINE_SOURCE_INVALID")
        return self


class SourceObservationQuality(FrozenDTO):
    schema_version: Literal["source-observation-quality-v1"]
    original_start: UTCDateTime
    original_end: UTCDateTime
    original_requested_end: Observed[UTCDateTime]
    effective_start: UTCDateTime
    effective_end: UTCDateTime
    requested_end: Observed[UTCDateTime]
    capture_stopped_at: Observed[UTCDateTime]
    capture_incomplete: Observed[bool]
    restart_incomplete: bool
    skipped_packet_count: Observed[Nonnegative]
    dropped_packet_count: Observed[Nonnegative]
    discarded_packets: Observed[Nonnegative]
    clock_skew_detected: Observed[bool]
    stop_reasons: Annotated[tuple[StopReason, ...], Field(max_length=128)]
    failed_sensors: Annotated[tuple[Identifier, ...], Field(max_length=128)]
    sensor_offset_bounds: Annotated[tuple[SensorOffsetBounds, ...], Field(max_length=128)]
    known_partial: bool
    clock_uncertain: bool
    producer_completeness: Literal["UNKNOWN"]

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.original_start >= self.original_end or self.effective_start >= self.effective_end:
            raise ValueError("BASELINE_SOURCE_INVALID")
        for values in (
            self.stop_reasons,
            self.failed_sensors,
            tuple(v.sensor_id for v in self.sensor_offset_bounds),
        ):
            if tuple(sorted(set(values))) != values:
                raise ValueError("BASELINE_SOURCE_INVALID")
        if _quality_partial(self) and not self.known_partial:
            raise ValueError("BASELINE_SOURCE_INVALID")
        if _quality_clock(self) and not self.clock_uncertain:
            raise ValueError("BASELINE_SOURCE_INVALID")
        return self


def _quality_partial(quality: SourceObservationQuality) -> bool:
    return bool(
        quality.restart_incomplete
        or quality.stop_reasons
        or quality.failed_sensors
        or any(
            isinstance(v, Present) and bool(v.value)
            for v in (
                quality.capture_incomplete,
                quality.skipped_packet_count,
                quality.dropped_packet_count,
                quality.discarded_packets,
            )
        )
        or (
            isinstance(quality.requested_end, Present)
            and quality.requested_end.value > quality.effective_end
        )
        or (
            isinstance(quality.original_requested_end, Present)
            and quality.original_requested_end.value > quality.original_end
        )
    )


def _quality_clock(quality: SourceObservationQuality) -> bool:
    return bool(
        (isinstance(quality.clock_skew_detected, Present) and quality.clock_skew_detected.value)
        or any(
            max(abs(v.minimum_ms), abs(v.maximum_ms)) > 2000 for v in quality.sensor_offset_bounds
        )
    )


def _reduce_observed(values: list[Any], *, minimum: bool = False) -> dict[str, Any]:
    observed = [v.value for v in values if isinstance(v, Present)]
    if not observed:
        return {"present": False}
    value = min(observed) if minimum else max(observed)
    if isinstance(value, datetime):
        value = value.isoformat()
    return {"present": True, "value": value}


def merge_source_quality(
    *,
    original_start: datetime | str,
    original_end: datetime | str,
    effective_start: datetime | str,
    effective_end: datetime | str,
    facts: tuple[SourceQualityFacts, ...],
    inherited: tuple[SourceObservationQuality, ...],
    partial_status: bool,
) -> SourceObservationQuality:
    """Union root-first retained facts. Callers supply every prior envelope projection.

    This is negative-evidence aggregation, not a producer completeness claim.
    Ancestry resolution and status/module validation belong to the bounded reader.
    """
    if type(partial_status) is not bool or not 1 <= len(facts) <= 16 or len(inherited) > 16:
        raise ValueError("BASELINE_SOURCE_INVALID")
    start, end = _utc(original_start), _utc(original_end)
    current_start, current_end = _utc(effective_start), _utc(effective_end)
    if any(q.original_start != start or q.original_end != end for q in inherited):
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    all_quality: tuple[SourceQualityFacts | SourceObservationQuality, ...] = (*facts, *inherited)
    data: dict[str, Any] = {
        "schema_version": "source-observation-quality-v1",
        "original_start": start.isoformat(),
        "original_end": end.isoformat(),
        "effective_start": current_start.isoformat(),
        "effective_end": current_end.isoformat(),
        "original_requested_end": _reduce_observed(
            [facts[0].requested_end_time, *(q.original_requested_end for q in inherited)]
        ),
        "requested_end": _reduce_observed(
            [*(f.requested_end_time for f in facts), *(q.requested_end for q in inherited)]
        ),
        "capture_stopped_at": _reduce_observed(
            [q.capture_stopped_at for q in all_quality], minimum=True
        ),
        "restart_incomplete": any(
            isinstance(f.error_code, Present)
            and f.error_code.value == "LIVE_CAPTURE_RESTART_INCOMPLETE"
            for f in facts
        )
        or any(q.restart_incomplete for q in inherited),
        "producer_completeness": "UNKNOWN",
    }
    for name in (
        "capture_incomplete",
        "skipped_packet_count",
        "dropped_packet_count",
        "discarded_packets",
        "clock_skew_detected",
    ):
        data[name] = _reduce_observed([getattr(q, name) for q in all_quality])
    failed: set[str] = set()
    reasons: set[str] = set()
    offsets: dict[str, tuple[int | float, int | float]] = {}

    def retain(sensor: str, low: int | float, high: int | float) -> None:
        previous = offsets.get(sensor, (low, high))
        offsets[sensor] = (min(previous[0], low), max(previous[1], high))

    for f in facts:
        if isinstance(f.failed_sensors, Present):
            failed.update(f.failed_sensors.value)
        if isinstance(f.capture_completions, Present):
            reasons.update(c.stop_reason for c in f.capture_completions.value)
        for offset in f.sensor_offsets:
            retain(offset.sensor_id, offset.clock_offset_ms, offset.clock_offset_ms)
    for q in inherited:
        failed.update(q.failed_sensors)
        reasons.update(q.stop_reasons)
        for bound in q.sensor_offset_bounds:
            retain(bound.sensor_id, bound.minimum_ms, bound.maximum_ms)
    if max(len(failed), len(reasons), len(offsets)) > 128:
        raise ValueError("BASELINE_SOURCE_LIMIT")
    data["failed_sensors"] = sorted(failed)
    data["stop_reasons"] = sorted(reasons)
    data["sensor_offset_bounds"] = [
        {"sensor_id": sensor, "minimum_ms": low, "maximum_ms": high}
        for sensor, (low, high) in sorted(offsets.items())
    ]
    # Validate structure before deriving the flags; true never certifies completeness.
    structural = SourceObservationQuality.from_mapping(
        dict(data, known_partial=True, clock_uncertain=True)
    )
    data["known_partial"] = (
        partial_status
        or _quality_partial(structural)
        or any(q.known_partial or _quality_partial(q) for q in inherited)
    )
    data["clock_uncertain"] = _quality_clock(structural) or any(
        q.clock_uncertain for q in inherited
    )
    return SourceObservationQuality.from_mapping(data)


def stored_clock_offset_ms(quality: SourceObservationQuality) -> int | float | None:
    values = [
        v for bound in quality.sensor_offset_bounds for v in (bound.minimum_ms, bound.maximum_ms)
    ]
    return min(values, key=lambda v: (-abs(v), v)) if values else None


# Exact existing vocabulary; parity with ai_analysis is regression-tested without
# introducing an import cycle into its future historical builder.
SENSITIVE_ORIGINAL_KEYS = frozenset(
    {
        "packet_hex",
        "payload",
        "payload_ascii",
        "payload_hex",
        "payload_preview",
        "pcap",
        "raw_packet_hex",
        "raw_payload",
    }
)
FLOW_FIELDS = frozenset(
    (
        "sensor_id timestamp source_ip destination_ip source_port destination_port protocol "
        "direction packet_count total_bytes payload_hash payload_prefix_hash payload_length "
        "payload_entropy payload_printable_ratio payload_simhash payload_feature_version "
        "tls_fingerprint certificate_fingerprint domain packet_sizes duration_seconds "
        "last_payload_hash tcp_flags tcp_flags_observed tcp_syn_count tcp_ack_count tcp_rst_count "
        "tcp_syn_only_count tcp_syn_ack_count tcp_ack_only_count tcp_syn_only_observations "
        "tcp_syn_only_observations_truncated bidirectional"
    ).split()
)
CANDIDATE_FIELDS = frozenset(
    (
        "id candidate_ip candidate_kind score prefilter_score prefilter_score_version severity "
        "internal_hosts hosts protocols ports first_seen last_seen source prefilter_factors "
        "discovery_origin behavior_anomaly_score evidence excluded"
    ).split()
)
EVIDENCE_FIELDS = frozenset("type detector description contribution metrics".split())
FACTOR_FIELDS = frozenset("name points explanation metrics".split())


def _frozen_object(value: object) -> FrozenObject:
    if isinstance(value, FrozenObject):
        _validate_original(value, frozen=True)
        return value
    frozen = freeze_original_json(value)
    if not isinstance(frozen, FrozenObject):
        raise ValueError("BASELINE_SOURCE_INVALID")
    return frozen


OriginalFrozenObject = Annotated[
    FrozenObject,
    PlainValidator(_frozen_object),
    PlainSerializer(thaw_original_json, when_used="json"),
]


def _row_frozen_object(value: object) -> FrozenObject:
    _validate_original(value, frozen=isinstance(value, FrozenObject), max_bytes=65536)
    return _frozen_object(value)


RowFrozenObject = Annotated[
    FrozenObject,
    PlainValidator(_row_frozen_object),
    PlainSerializer(thaw_original_json, when_used="json"),
]


class RowProjection(FrozenDTO):
    fields: RowFrozenObject

    @classmethod
    def from_mapping(cls, value: object) -> Self:
        _validate_original(_mapping(value).get("fields"), max_bytes=65536)
        return super().from_mapping(value)


def _integer(value: object, *, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError("BASELINE_SOURCE_INVALID")
    return value


def _array(value: object, limit: int = 128) -> list[Any]:
    if type(value) is not list:
        raise ValueError("BASELINE_SOURCE_INVALID")
    if len(value) > limit:
        raise ValueError("BASELINE_SOURCE_LIMIT")
    return value


def _validate_flow_fields(fields: FrozenObject) -> None:
    raw = _mapping(thaw_original_json(fields))
    if (
        not set(raw) <= FLOW_FIELDS
        or not {
            "sensor_id",
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "direction",
            "packet_count",
            "total_bytes",
            "duration_seconds",
        }
        <= raw.keys()
    ):
        raise ValueError("BASELINE_SOURCE_INVALID")
    for name in ("sensor_id", "protocol", "direction"):
        if not _text(raw[name]) or len(raw[name]) > 200:
            raise ValueError("BASELINE_SOURCE_INVALID")
    _utc(raw["timestamp"])
    for name in ("source_ip", "destination_ip"):
        ip_address(_text(raw[name]))
    for name in ("source_port", "destination_port"):
        if raw.get(name) is not None:
            _integer(raw[name], maximum=65535)
    _integer(raw["packet_count"], minimum=1)
    _integer(raw["total_bytes"])
    duration = _number(raw["duration_seconds"])
    micros = Decimal(str(duration)) * 1000000
    if micros < 0 or micros != micros.to_integral_value():
        raise ValueError("BASELINE_SOURCE_INVALID")
    for name, value in raw.items():
        if name in {"tcp_flags_observed", "tcp_syn_only_observations_truncated", "bidirectional"}:
            if type(value) is not bool:
                raise ValueError("BASELINE_SOURCE_INVALID")
        elif name.startswith("tcp_") and name.endswith("_count"):
            _integer(value)
        elif name in {"payload_length"} and value is not None:
            _integer(value)
        elif name in {"payload_entropy", "payload_printable_ratio"} and value is not None:
            _number(value)
        elif (
            name
            in {
                "payload_hash",
                "payload_prefix_hash",
                "payload_simhash",
                "payload_feature_version",
                "tls_fingerprint",
                "certificate_fingerprint",
                "domain",
                "last_payload_hash",
            }
            and value is not None
        ):
            _text(value)
        elif name == "packet_sizes" and value is not None:
            for size in _array(value):
                _integer(size)
        elif name == "tcp_flags" and value is not None:
            flags = _mapping(value)
            if len(flags) > 128:
                raise ValueError("BASELINE_SOURCE_LIMIT")
            for count in flags.values():
                _number(count)
        elif name == "tcp_syn_only_observations" and value is not None:
            for row in _array(value, 256):
                if isinstance(row, dict) and set(row) == {"offset_us", "sequence"}:
                    pair = [row["offset_us"], row["sequence"]]
                else:
                    pair = _array(row, 2)
                if len(pair) != 2:
                    raise ValueError("BASELINE_SOURCE_INVALID")
                _integer(pair[0])
                _integer(pair[1], maximum=2**32 - 1)


class OriginalFlowProjection(RowProjection):
    sensitive_keys_present: tuple[Text, ...]

    @model_validator(mode="after")
    def valid_fields(self) -> Self:
        _validate_flow_fields(self.fields)
        if tuple(sorted(set(self.sensitive_keys_present))) != self.sensitive_keys_present or any(
            k.lower() not in SENSITIVE_ORIGINAL_KEYS for k in self.sensitive_keys_present
        ):
            raise ValueError("BASELINE_SOURCE_INVALID")
        return self


def project_original_flow(raw: dict[str, Any]) -> OriginalFlowProjection:
    _validate_original(raw, max_bytes=65536)
    return OriginalFlowProjection(
        fields=_frozen_object({k: v for k, v in raw.items() if k in FLOW_FIELDS}),
        sensitive_keys_present=tuple(
            sorted(k for k in raw if k.lower() in SENSITIVE_ORIGINAL_KEYS)
        ),
    )


def projected_payload_fields_excluded(flows: tuple[OriginalFlowProjection, ...]) -> int:
    return sum(bool(flow.sensitive_keys_present) for flow in flows)


def _scrub_metrics(value: Any) -> Any:
    # Keep keys/positions to preserve the legacy first-30-before-filter cutoff.
    if isinstance(value, dict):
        return {
            k: None if k.lower() in SENSITIVE_ORIGINAL_KEYS else _scrub_metrics(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_scrub_metrics(v) for v in value]
    return value


def _validate_candidate_fields(fields: FrozenObject) -> None:
    raw = _mapping(thaw_original_json(fields))
    if not set(raw) <= CANDIDATE_FIELDS or not {"id", "candidate_ip", "score"} <= raw.keys():
        raise ValueError("BASELINE_SOURCE_INVALID")
    if not _text(raw["id"]) or len(raw["id"]) > 200:
        raise ValueError("BASELINE_SOURCE_INVALID")
    ip_address(_text(raw["candidate_ip"]))
    for key in ("score", "prefilter_score", "behavior_anomaly_score"):
        if key in raw and (key == "score" or raw[key] is not None):
            if not 0 <= _number(raw[key]) <= 100:
                raise ValueError("BASELINE_SOURCE_INVALID")
    if "excluded" in raw and type(raw["excluded"]) is not bool:
        raise ValueError("BASELINE_SOURCE_INVALID")
    for key in ("internal_hosts", "hosts", "protocols", "ports"):
        if key in raw and raw[key] is not None:
            for item in _array(raw[key]):
                if key == "ports":
                    _integer(item, maximum=65535)
                else:
                    _text(item)
    for key in ("evidence", "prefilter_factors"):
        if key in raw:
            allowed = EVIDENCE_FIELDS if key == "evidence" else FACTOR_FIELDS
            for row in _array(raw[key], 262144 if key == "evidence" else 128):
                if not set(_mapping(row)) <= allowed:
                    raise ValueError("BASELINE_SOURCE_INVALID")
                if "metrics" in row and _scrub_metrics(row["metrics"]) != row["metrics"]:
                    raise ValueError("BASELINE_SOURCE_INVALID")
                for name, value in row.items():
                    if value is None or name == "metrics":
                        continue
                    if name in {"contribution", "points"}:
                        _number(value)
                    else:
                        _text(value)
    for key in (
        "candidate_kind",
        "prefilter_score_version",
        "severity",
        "first_seen",
        "last_seen",
        "source",
        "discovery_origin",
    ):
        if key in raw and raw[key] is not None:
            _text(raw[key])


class CandidateProjection(RowProjection):
    position: Nonnegative

    @model_validator(mode="after")
    def valid_fields(self) -> Self:
        _validate_candidate_fields(self.fields)
        return self


def project_candidate(raw: dict[str, Any], *, position: int) -> CandidateProjection:
    _validate_original(raw, max_bytes=65536)
    fields = {k: v for k, v in raw.items() if k in CANDIDATE_FIELDS}
    for key in ("evidence", "prefilter_factors"):
        if key in fields:
            allowed = EVIDENCE_FIELDS if key == "evidence" else FACTOR_FIELDS
            fields[key] = [
                {
                    name: _scrub_metrics(value) if name == "metrics" else value
                    for name, value in _mapping(row).items()
                    if name in allowed
                }
                for row in _array(fields[key], 262144 if key == "evidence" else 128)
            ]
    return CandidateProjection(position=position, fields=_frozen_object(fields))


UUIDString = Annotated[
    Text,
    Field(pattern=r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
]
Digest = Annotated[Text, Field(pattern=r"^[0-9a-f]{64}$")]
ReasonText = Annotated[Text, Field(min_length=1, max_length=512)]
ScopeKind = Literal["OPERATIONAL", "EVALUATION"]
Origin = Literal["SENSOR_CAPTURE", "PCAP_UPLOAD"]


class HostEpoch(FrozenDTO):
    ip: Text
    epoch: Annotated[Text, Field(min_length=1, max_length=64)]

    @field_validator("ip")
    @classmethod
    def canonical_ip(cls, value: str) -> str:
        return str(ip_address(value))


class ScopeConfig(FrozenDTO):
    scope_id: UUIDString
    name: Annotated[Text, Field(min_length=1, max_length=100)]
    kind: ScopeKind
    sensor_key: Identifier
    stored_sensor_id: Identifier | None
    internal_networks: Annotated[tuple[Text, ...], Field(min_length=1, max_length=128)]
    window_seconds: Annotated[int, Field(ge=60, le=21600)]
    hosts: Annotated[tuple[HostEpoch, ...], Field(min_length=1, max_length=128)]
    identity_assertion: Literal["STABLE_SINGLE_HOST_NO_SHARED_NAT"]
    reason: ReasonText

    @field_validator("internal_networks")
    @classmethod
    def canonical_networks(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        networks = tuple(str(ip_network(value, strict=False)) for value in values)
        if len(set(networks)) != len(networks):
            raise ValueError("BASELINE_SOURCE_INVALID")
        return tuple(sorted(networks))

    @field_validator("hosts")
    @classmethod
    def canonical_hosts(cls, values: tuple[HostEpoch, ...]) -> tuple[HostEpoch, ...]:
        if len({h.ip for h in values}) != len(values):
            raise ValueError("BASELINE_SOURCE_INVALID")
        return tuple(sorted(values, key=lambda h: (h.ip, h.epoch)))

    @model_validator(mode="after")
    def identity(self) -> Self:
        if (self.kind == "OPERATIONAL") != (self.stored_sensor_id is not None):
            raise ValueError("BASELINE_SCOPE_MISMATCH")
        networks = [ip_network(n) for n in self.internal_networks]
        if any(not any(ip_address(h.ip) in n for n in networks) for h in self.hosts):
            raise ValueError("BASELINE_SCOPE_MISMATCH")
        if len(canonical_json(self.to_mapping()).encode("utf-8")) > 65536:
            raise ValueError("BASELINE_SOURCE_LIMIT")
        return self


def scope_config_sha256(config: ScopeConfig) -> str:
    value = config.to_mapping()
    identity = {
        key: value[key]
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
    return hashlib.sha256(canonical_json(identity).encode("utf-8")).hexdigest()


class QualityReview(FrozenDTO):
    representative_window_asserted: Literal[True]
    stable_host_attribution_asserted: Literal[True]
    clock_offset_bound_ms: Annotated[int, Field(ge=0, le=2000)]
    sensor_alias_asserted: bool
    note: ReasonText


def validate_sensor_assertion(
    config: ScopeConfig, *, actual_sensor_id: str, review: QualityReview, origin: Origin
) -> None:
    if (
        not _text(actual_sensor_id)
        or len(actual_sensor_id) > 200
        or origin not in ("SENSOR_CAPTURE", "PCAP_UPLOAD")
    ):
        raise ValueError("BASELINE_SCOPE_MISMATCH")
    if config.kind == "OPERATIONAL":
        if (
            actual_sensor_id != config.stored_sensor_id
            or review.sensor_alias_asserted
            or origin != "SENSOR_CAPTURE"
        ):
            raise ValueError("BASELINE_SCOPE_MISMATCH")
    elif not review.sensor_alias_asserted:
        raise ValueError("BASELINE_SCOPE_MISMATCH")


ALLOWLIST_FIELDS = frozenset("type value description expires_at enabled".split())
OPERATIONS_FIELDS = frozenset("warnings failed_sensors sensors".split())
SENSOR_OPERATION_FIELDS = frozenset("status clock_offset_ms observed_packets loss_reason".split())


def _allowlist_fields(value: FrozenObject) -> None:
    raw = _mapping(thaw_original_json(value))
    if not set(raw) <= ALLOWLIST_FIELDS or not {"type", "value", "description"} <= raw.keys():
        raise ValueError("BASELINE_SOURCE_INVALID")
    for key in ("type", "value", "description"):
        _text(raw[key])
    kind = raw["type"].upper()
    if kind == "IP":
        ip_address(raw["value"])
    elif kind == "CIDR":
        ip_network(raw["value"], strict=False)
    elif kind not in {"DOMAIN_SUFFIX", "TLS_FINGERPRINT", "CERT_FINGERPRINT"}:
        raise ValueError("BASELINE_SOURCE_INVALID")
    if "enabled" in raw and type(raw["enabled"]) is not bool:
        raise ValueError("BASELINE_SOURCE_INVALID")
    if raw.get("expires_at") is not None:
        _utc(raw["expires_at"])


def _operations_fields(value: FrozenObject) -> None:
    raw = _mapping(thaw_original_json(value))
    if not set(raw) <= OPERATIONS_FIELDS:
        raise ValueError("BASELINE_SOURCE_INVALID")
    for key in ("warnings", "failed_sensors"):
        if key in raw:
            for item in _array(raw[key]):
                _text(item)
    if "sensors" in raw:
        sensors = _mapping(raw["sensors"])
        if len(sensors) > 128:
            raise ValueError("BASELINE_SOURCE_LIMIT")
        for sensor, item in sensors.items():
            if (
                not _text(sensor)
                or len(sensor) > 200
                or not set(_mapping(item)) <= SENSOR_OPERATION_FIELDS
            ):
                raise ValueError("BASELINE_SOURCE_INVALID")
            for key, val in item.items():
                if key == "clock_offset_ms":
                    _number(val)
                elif key == "observed_packets" and val is not None:
                    _integer(val)
                elif val is not None:
                    _text(val)


def _original_job_metadata(
    raw: dict[str, Any], *, projected: bool
) -> Iterable[tuple[object, object]]:
    for key, value in raw.items():
        if key == "flow_records":
            continue
        if projected and key in {"operations", "allowlist"}:
            if isinstance(value, Absent):
                continue
            if isinstance(value, Present):
                value = value.value
            else:
                observed = _mapping(value)
                if observed == {"present": False} and type(observed["present"]) is bool:
                    continue
                if set(observed) != {"present", "value"} or observed["present"] is not True:
                    raise ValueError("BASELINE_SOURCE_INVALID")
                value = observed["value"]
        yield key, value


def _admit_original_job(value: object, *, projected: bool) -> list[Any] | tuple[Any, ...]:
    """Meter original metadata and the flow array before any projection/copy.

    DTO tags/fields are not stored-cell bytes. Already-frozen children are read
    directly; neither thawing nor whole-document serialization is needed.
    """
    raw = _mapping(value)
    required = set(OriginalJobProjection.model_fields)
    if not projected:
        required -= {"allowlist", "operations"}
    if not required <= raw.keys() or (projected and not raw.keys() <= required):
        raise ValueError("BASELINE_SOURCE_INVALID")
    metadata = _OriginalBudget(256 * 1024, frozen=None if projected else False)
    metadata.object_items(_original_job_metadata(raw, projected=projected), 0)
    rows = raw["flow_records"]
    if type(rows) is not list and not (projected and type(rows) is tuple):
        raise ValueError("BASELINE_SOURCE_INVALID")
    if len(rows) > 8192:
        raise ValueError("BASELINE_SOURCE_LIMIT")
    flows = _OriginalBudget(8 * 1024 * 1024, frozen=None if projected else False)
    flows.node(0)
    flows.add(2 + max(0, len(rows) - 1))
    for row in rows:
        if projected:
            row = (
                row.fields
                if isinstance(row, OriginalFlowProjection)
                else _mapping(row).get("fields")
            )
        # The same meter retains array-level node/byte accounting. A temporary
        # tighter ceiling enforces the row cap before encoding any long string.
        flows.max_bytes = min(8 * 1024 * 1024, flows.size + 65536)
        flows.visit(row, 1)
    return rows


class OriginalJobProjection(FrozenDTO):
    id: Identifier
    dataset_id: Identifier
    parent_job_id: Identifier | None
    source_type: Identifier
    mode: Identifier
    status: Identifier
    start_time: Text
    end_time: Text
    sensor_ids: Annotated[tuple[Identifier, ...], Field(min_length=1, max_length=128)]
    internal_networks: Annotated[tuple[Text, ...], Field(min_length=1, max_length=128)]
    analysis: OriginalFrozenObject
    allowlist: Observed[Annotated[tuple[OriginalFrozenObject, ...], Field(max_length=128)]]
    operations: Observed[OriginalFrozenObject]
    flow_records: Annotated[tuple[OriginalFlowProjection, ...], Field(max_length=8192)]

    @model_validator(mode="before")
    @classmethod
    def admit_original_cells(cls, value: object) -> object:
        if not isinstance(value, cls):
            _admit_original_job(value, projected=True)
        return value

    @model_validator(mode="after")
    def valid_original(self) -> Self:
        if _utc(self.start_time) >= _utc(self.end_time):
            raise ValueError("BASELINE_SOURCE_INVALID")
        for network in self.internal_networks:
            ip_network(network, strict=False)
        analysis = _mapping(thaw_original_json(self.analysis))
        # Validate without using the default-filled/normalized dump as input.
        AnalysisParameters.model_validate(analysis, strict=True)
        if isinstance(self.allowlist, Present):
            for entry in self.allowlist.value:
                _allowlist_fields(entry)
        if isinstance(self.operations, Present):
            _operations_fields(self.operations.value)
        return self


def project_original_job(raw: dict[str, Any]) -> OriginalJobProjection:
    """In-memory admission only; storage must gate complete cells before transfer."""
    rows = _admit_original_job(raw, projected=False)
    required = set(OriginalJobProjection.model_fields) - {"allowlist", "operations"}
    data = {k: raw[k] for k in required if k not in {"flow_records", "analysis"}}
    data["analysis"] = {
        k: v for k, v in _mapping(raw["analysis"]).items() if k in AnalysisParameters.model_fields
    }
    data["flow_records"] = [project_original_flow(_mapping(row)).to_mapping() for row in rows]
    data["allowlist"] = {"present": False}
    if "allowlist" in raw:
        data["allowlist"] = {
            "present": True,
            "value": [
                {k: v for k, v in _mapping(row).items() if k in ALLOWLIST_FIELDS}
                for row in _array(raw["allowlist"])
            ],
        }
    data["operations"] = {"present": False}
    if "operations" in raw:
        operations = {
            k: v for k, v in _mapping(raw["operations"]).items() if k in OPERATIONS_FIELDS
        }
        if "sensors" in operations:
            sensors = _mapping(operations["sensors"])
            if len(sensors) > 128:
                raise ValueError("BASELINE_SOURCE_LIMIT")
            operations["sensors"] = {
                sensor: {k: v for k, v in _mapping(item).items() if k in SENSOR_OPERATION_FIELDS}
                for sensor, item in sensors.items()
            }
        data["operations"] = {"present": True, "value": operations}
    return OriginalJobProjection.from_mapping(data)


def thaw_original_job(job: OriginalJobProjection) -> dict[str, Any]:
    """A private local copy. Payload presence count is supplied separately."""
    value = job.to_mapping()
    value["flow_records"] = [thaw_original_json(flow.fields) for flow in job.flow_records]
    for key in ("allowlist", "operations"):
        observed = value.pop(key)
        if observed["present"]:
            value[key] = observed["value"]
    return value


class LineageSource(FrozenDTO):
    sha256: Observed[Digest]
    capture_format: Observed[Text]
    captured_packet_count: Observed[Nonnegative]


class LineageNode(FrozenDTO):
    id: Identifier
    dataset_id: Identifier
    parent_job_id: Identifier | None
    source_type: Identifier
    mode: Identifier
    status: Identifier
    start_time: UTCDateTime
    end_time: UTCDateTime
    source: Observed[LineageSource]
    quality: SourceQualityFacts
    inherited_quality: Observed[SourceObservationQuality]

    @model_validator(mode="after")
    def envelope(self) -> Self:
        if self.start_time >= self.end_time:
            raise ValueError("BASELINE_SOURCE_INVALID")
        return self


def project_lineage_node(raw: dict[str, Any]) -> LineageNode:
    _validate_original(raw, max_bytes=256 * 1024)
    keys = (
        "id",
        "dataset_id",
        "parent_job_id",
        "source_type",
        "mode",
        "status",
        "start_time",
        "end_time",
    )
    if not set(keys) <= raw.keys():
        raise ValueError("BASELINE_SOURCE_INVALID")
    data = {key: raw[key] for key in keys}
    data["quality"] = project_source_quality(raw).to_mapping()
    data["inherited_quality"] = _observed_path(raw, "source_observation_quality")
    data["source"] = {"present": False}
    if "source" in raw:
        source = _mapping(raw["source"])
        data["source"] = {
            "present": True,
            "value": {key: _observed_path(source, key) for key in LineageSource.model_fields},
        }
    return LineageNode.from_mapping(data)


def _ordered_lineage(
    lineage: tuple[LineageNode, ...], selected_job_id: str
) -> tuple[LineageNode, ...]:
    if not 1 <= len(lineage) <= 16:
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    nodes = {node.id: node for node in lineage}
    if len(nodes) != len(lineage):
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    selected = nodes.get(selected_job_id)
    if selected is None:
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    reverse: list[LineageNode] = []
    seen: set[str] = set()
    current: str | None = selected_job_id
    while current is not None:
        if current in seen or current not in nodes:
            raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        seen.add(current)
        node = nodes[current]
        if node.dataset_id != selected.dataset_id or node.source_type != selected.source_type:
            raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        reverse.append(node)
        current = node.parent_job_id
    if len(reverse) != len(lineage):
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    return tuple(reversed(reverse))


def aggregate_lineage_quality(
    lineage: tuple[LineageNode, ...], *, selected_job_id: str
) -> SourceObservationQuality:
    """Fold every retained envelope before advancing to the selected one."""
    ordered = _ordered_lineage(lineage, selected_job_id)
    root = ordered[0]
    start, end = root.start_time, root.end_time
    if isinstance(root.inherited_quality, Present):
        start, end = (
            root.inherited_quality.value.original_start,
            root.inherited_quality.value.original_end,
        )
    accumulated: SourceObservationQuality | None = None
    for index, node in enumerate(ordered):
        inherited = [] if accumulated is None else [accumulated]
        if isinstance(node.inherited_quality, Present):
            inherited.append(node.inherited_quality.value)
        accumulated = merge_source_quality(
            original_start=start,
            original_end=end,
            effective_start=node.start_time,
            effective_end=node.end_time,
            facts=tuple(n.quality for n in ordered[: index + 1]),
            inherited=tuple(inherited),
            partial_status=node.status == "PARTIALLY_COMPLETED",
        )
    if accumulated is None:
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    return accumulated


class SourceBindingProjection(FrozenDTO):
    """Exact amendment 3.2 source binding subset, not strict feature input.

    Lineage acquisition/fencing, normalized Flow construction, observation hashes
    and historical admission remain separate integration responsibilities.
    """

    original: OriginalJobProjection
    lineage: Annotated[tuple[LineageNode, ...], Field(min_length=1, max_length=16)]
    root_job_id: Identifier
    root_identity: Annotated[Text, Field(min_length=1, max_length=420)]
    root_content_sha256: Digest | None
    origin: Origin
    origin_assurance: Literal["STORED_LINEAGE_ONLY"]
    actual_sensor_id: Identifier
    event_start: UTCDateTime
    event_end: UTCDateTime
    internal_networks: Annotated[tuple[Text, ...], Field(min_length=1, max_length=128)]
    quality: SourceObservationQuality

    @model_validator(mode="after")
    def selected_identity(self) -> Self:
        ordered = _ordered_lineage(self.lineage, self.original.id)
        root, selected = ordered[0], ordered[-1]
        if root.id != self.root_job_id:
            raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        for key in ("id", "dataset_id", "parent_job_id", "source_type", "mode", "status"):
            if getattr(selected, key) != getattr(self.original, key):
                raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        if selected.start_time != _utc(self.original.start_time) or selected.end_time != _utc(
            self.original.end_time
        ):
            raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        operations = self.original.operations
        overlapping = project_source_quality(
            {"operations": thaw_original_json(operations.value)}
            if isinstance(operations, Present)
            else {}
        )
        left, right = overlapping.failed_sensors, selected.quality.failed_sensors
        if (
            isinstance(left, Present) != isinstance(right, Present)
            or (
                isinstance(left, Present)
                and isinstance(right, Present)
                and set(left.value) != set(right.value)
            )
            or {(v.sensor_id, v.clock_offset_ms) for v in overlapping.sensor_offsets}
            != {(v.sensor_id, v.clock_offset_ms) for v in selected.quality.sensor_offsets}
        ):
            raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        upload = any(
            n.source_type == "PCAP_UPLOAD"
            or n.mode == "PCAP_UPLOAD"
            or n.dataset_id.startswith("pcap:")
            or (
                isinstance(n.source, Present)
                and any(
                    isinstance(v, Present)
                    for v in (
                        n.source.value.sha256,
                        n.source.value.capture_format,
                        n.source.value.captured_packet_count,
                    )
                )
            )
            for n in ordered
        )
        if upload:
            if (
                self.origin != "PCAP_UPLOAD"
                or not isinstance(root.source, Present)
                or not isinstance(root.source.value.sha256, Present)
            ):
                raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
            digest = root.source.value.sha256.value
            if (
                self.root_content_sha256 != digest
                or root.dataset_id != "pcap:" + digest
                or self.root_identity != "pcap:" + digest
                or any(
                    isinstance(node.source, Present)
                    and isinstance(node.source.value.sha256, Present)
                    and node.source.value.sha256.value != digest
                    for node in ordered
                )
            ):
                raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        elif self.origin != "SENSOR_CAPTURE" or self.root_content_sha256 is not None:
            raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
        if (
            aggregate_lineage_quality(self.lineage, selected_job_id=self.original.id)
            != self.quality
        ):
            raise ValueError("BASELINE_SOURCE_INVALID")
        if (
            self.event_start != _utc(self.original.start_time)
            or self.event_end != _utc(self.original.end_time)
            or self.quality.effective_start != self.event_start
            or self.quality.effective_end != self.event_end
        ):
            raise ValueError("BASELINE_SOURCE_INVALID")
        if self.original.sensor_ids != (self.actual_sensor_id,):
            raise ValueError("BASELINE_SCOPE_MISMATCH")
        if (
            tuple(sorted(str(ip_network(n, strict=False)) for n in self.original.internal_networks))
            != self.internal_networks
        ):
            raise ValueError("BASELINE_SCOPE_MISMATCH")
        return self


def _binding_dto(value: object) -> object:
    if isinstance(value, FrozenObject):
        return original_binding_value(value)
    if isinstance(value, FrozenDTO):
        return {key: _binding_dto(getattr(value, key)) for key in type(value).model_fields}
    if isinstance(value, tuple):
        return [_binding_dto(v) for v in value]
    if isinstance(value, datetime):
        return _utc(value).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return value


def source_binding_value(source: SourceBindingProjection) -> dict[str, Any]:
    return cast("dict[str, Any]", _binding_dto(source))


def source_binding_sha256(
    source: SourceBindingProjection,
    *,
    purpose: Literal["APPROVAL", "COMPARISON"],
    candidates: tuple[CandidateProjection, ...] = (),
) -> str:
    if purpose not in ("APPROVAL", "COMPARISON") or (purpose == "APPROVAL" and candidates):
        raise ValueError("BASELINE_SOURCE_INVALID")
    if len(candidates) > 2048:
        raise ValueError("BASELINE_CANDIDATE_LIMIT")
    ids = [dict(c.fields.entries)["id"] for c in candidates]
    positions = [c.position for c in candidates]
    if len(set(ids)) != len(ids) or len(set(positions)) != len(positions):
        raise ValueError("BASELINE_SOURCE_INVALID")
    value: dict[str, Any] = {"purpose": purpose, "source": source_binding_value(source)}
    if purpose == "COMPARISON":
        ordered = sorted(candidates, key=lambda c: (c.position, str(dict(c.fields.entries)["id"])))
        value["candidates"] = [_binding_dto(c) for c in ordered]
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
