"""Value-only stored source to the accepted all-stream baseline producer.

No source acquisition, storage fence, approval authority or producer completeness
is established here. The original local-input projection is never normalized.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, fields, replace
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from functools import lru_cache, wraps
from ipaddress import ip_address, ip_network
from types import MappingProxyType
from typing import Annotated, Any, Self, cast, get_args, get_type_hints

from c2hunter_analysis import behavior_baseline as b
from c2hunter_analysis.domain import AllowlistEntry, Flow, normalize_tcp_syn_observations
from pydantic import Field, PlainSerializer, PlainValidator, ValidationError, model_validator

from . import historical_baseline as h

SOURCE_ERROR_CODES = frozenset(
    {
        "BASELINE_SOURCE_INVALID",
        "BASELINE_SOURCE_LIMIT",
        "BASELINE_PROFILE_LIMIT",
        "BASELINE_SCOPE_MISMATCH",
        "BASELINE_SOURCE_STATE",
        "BASELINE_SOURCE_LINEAGE_INVALID",
    }
)


class SourceInputError(ValueError):
    """Safe domain boundary; no raw values, paths or Pydantic input excerpts."""

    def __init__(self, code: str = "BASELINE_SOURCE_INVALID") -> None:
        self.code = code if code in SOURCE_ERROR_CODES else "BASELINE_SOURCE_INVALID"
        super().__init__(self.code)


def _safe[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return function(*args, **kwargs)
        except b.BaselineInputError as exc:
            raise SourceInputError(exc.code) from None
        except ValidationError as exc:
            code = "BASELINE_SOURCE_INVALID"
            for error in exc.errors(include_input=False):
                cause = error.get("ctx", {}).get("error")
                if (
                    isinstance(cause, ValueError)
                    and cause.args
                    and type(cause.args[0]) is str
                    and cause.args[0] in SOURCE_ERROR_CODES
                ):
                    code = cause.args[0]
                    break
            raise SourceInputError(code) from None
        except (ValueError, TypeError, KeyError, OverflowError) as exc:
            code = (
                exc.args[0] if exc.args and type(exc.args[0]) is str else "BASELINE_SOURCE_INVALID"
            )
            raise SourceInputError(code) from None

    return wrapped


def _utc(value: object) -> datetime:
    if type(value) is str:
        value = datetime.fromisoformat(value)
    if type(value) is not datetime or value.utcoffset() is None:
        raise b.BaselineInputError()
    return value.astimezone(UTC)


def _strict_syn(value: object) -> None:
    """Validate closed pairs/objects before the legacy normalizer drops keys."""
    if value is None:
        return
    if type(value) not in (list, tuple):
        raise b.BaselineInputError()
    items = cast("list[object] | tuple[object, ...]", value)
    if len(items) > 256:
        raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
    for item in items:
        if type(item) is dict and len(item) == 2 and set(item) == {"offset_us", "sequence"}:
            offset, sequence = item["offset_us"], item["sequence"]
        elif (type(item) is list or type(item) is tuple) and len(item) == 2:
            offset, sequence = item
        else:
            raise b.BaselineInputError()
        b._integer(offset, 31_536_000_000_000)
        b._integer(sequence, 2**32 - 1)


def _flow_value(value: object) -> Flow:
    if type(value) is dict:
        raw = cast("dict[str, Any]", value)
        if set(raw) != {f.name for f in fields(Flow)}:
            raise b.BaselineInputError()
        _strict_syn(raw["tcp_syn_only_observations"])
        value = Flow(**dict(raw, timestamp=_utc(raw["timestamp"])))
    elif type(value) is Flow:
        _strict_syn(value.tcp_syn_only_observations)
    if type(value) is not Flow:
        raise b.BaselineInputError()
    return replace(
        value,
        timestamp=_utc(value.timestamp),
        tcp_flags=None if value.tcp_flags is None else MappingProxyType(dict(value.tcp_flags)),
        packet_sizes=tuple(value.packet_sizes),
        tcp_syn_only_observations=normalize_tcp_syn_observations(value.tcp_syn_only_observations),
    )


def _flow_mapping(value: Flow) -> dict[str, Any]:
    result = {field.name: getattr(value, field.name) for field in fields(Flow)}
    result["timestamp"] = value.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    result["tcp_flags"] = None if value.tcp_flags is None else dict(value.tcp_flags)
    result["packet_sizes"] = list(value.packet_sizes)
    result["tcp_syn_only_observations"] = (
        None
        if value.tcp_syn_only_observations is None
        else [list(p) for p in value.tcp_syn_only_observations]
    )
    return result


StrictFlow = Annotated[
    Flow, PlainValidator(_flow_value), PlainSerializer(_flow_mapping, when_used="json")
]


def _original_syn_cap(value: object, *, projected: bool) -> None:
    """Count raw items before copying; leave all content validation to the core.

    Only known container fields are read. In particular, no SYN member or
    ignored array is walked, normalized, deduplicated or serialized here.
    """
    rows: Any
    observations: Any
    array_type: type
    if projected and type(value) is h.OriginalJobProjection:
        rows = value.flow_records
    elif type(value) is dict:
        rows = value.get("flow_records")
    else:
        raise b.BaselineInputError()
    if type(rows) is not list and not (projected and type(rows) is tuple):
        raise b.BaselineInputError()
    if len(rows) > 8192:
        raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
    total = 0
    for row in rows:
        if projected:
            if type(row) is h.OriginalFlowProjection:
                row = row.fields
            elif type(row) is dict:
                row = row.get("fields")
            else:
                raise b.BaselineInputError()
        if projected and type(row) is h.FrozenObject:
            observations = next(
                (v for k, v in row.entries if k == "tcp_syn_only_observations"), None
            )
            array_type = tuple
        elif type(row) is dict:
            observations = row.get("tcp_syn_only_observations")
            array_type = list
        else:
            raise b.BaselineInputError()
        if observations is not None:
            if type(observations) is not array_type:
                raise b.BaselineInputError()
            total += len(observations)
            if total > 256:
                raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")


class SourceProjection(h.SourceBindingProjection):
    """Full original binding plus separate immutable normalized observations."""

    strict_flows: Annotated[tuple[StrictFlow, ...], Field(max_length=8192)]
    trusted_peers: Annotated[tuple[h.Text, ...], Field(max_length=128)]
    observation_sha256: h.Digest
    feature_observation_sha256: h.Digest

    @model_validator(mode="before")
    @classmethod
    def strict_collection_caps(cls, value: object) -> object:
        if isinstance(value, dict) and "original" in value:
            _original_syn_cap(value["original"], projected=True)
        if isinstance(value, dict) and "strict_flows" in value:
            rows = value["strict_flows"]
            if type(rows) not in (tuple, list) or len(rows) > 8192:
                raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
            total_syn = 0
            sizes: Any
            for row in rows:
                if type(row) is Flow:
                    observations, flags, sizes = (
                        row.tcp_syn_only_observations,
                        row.tcp_flags,
                        row.packet_sizes,
                    )
                elif type(row) is dict:
                    observations, flags, sizes = (
                        row.get("tcp_syn_only_observations"),
                        row.get("tcp_flags"),
                        row.get("packet_sizes"),
                    )
                else:
                    raise b.BaselineInputError()
                if observations is not None:
                    if type(observations) not in (list, tuple):
                        raise b.BaselineInputError()
                    total_syn += len(observations)
                    if total_syn > 256:
                        raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
                if flags is not None and (not isinstance(flags, Mapping) or len(flags) > 16):
                    raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
                if type(sizes) not in (list, tuple) or len(sizes) > 128:
                    raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
        return value

    @model_validator(mode="after")
    def wrapper_budget(self) -> Self:
        # The inherited meter understands original DTOs, not domain.Flow.
        # Reuse the exact accepted binding validation; row caps are inherited.
        binding = self.source_binding()
        _source_state(binding)
        expected = _flows(binding)
        if len(expected) != len(self.strict_flows) or any(
            h.canonical_json(_flow_mapping(left)) != h.canonical_json(_flow_mapping(right))
            for left, right in zip(expected, self.strict_flows, strict=True)
        ):
            raise b.BaselineInputError()
        if self.trusted_peers != _trusted(binding, expected):
            raise b.BaselineInputError()
        return self

    def source_binding(self) -> h.SourceBindingProjection:
        return h.SourceBindingProjection(
            **{name: getattr(self, name) for name in h.SourceBindingProjection.model_fields}
        )


def _source_state(binding: h.SourceBindingProjection) -> None:
    if dict(binding.original.analysis.entries).get("module") != "c2":
        raise b.BaselineInputError()
    if binding.original.status not in {"COMPLETED", "PARTIALLY_COMPLETED"}:
        raise SourceInputError("BASELINE_SOURCE_STATE")
    if any(node.source_type not in {"SENSOR_CAPTURE", "PCAP_UPLOAD"} for node in binding.lineage):
        raise SourceInputError("BASELINE_SOURCE_LINEAGE_INVALID")
    if binding.origin == "SENSOR_CAPTURE":
        root = next(node for node in binding.lineage if node.id == binding.root_job_id)
        if binding.root_identity != h.canonical_json([root.id, root.dataset_id]):
            raise SourceInputError("BASELINE_SOURCE_LINEAGE_INVALID")


def _preflight(binding: h.SourceBindingProjection) -> None:
    """Accepted raw-presence/type checks already ran; close pure raw budgets
    before constructing or normalizing any Flow, not after the first prefix."""
    total_syn = 0
    networks = tuple(ip_network(n) for n in binding.internal_networks)
    for original in binding.original.flow_records:
        raw = dict(original.fields.entries)
        observations = raw.get("tcp_syn_only_observations")
        if observations is not None:
            total_syn += len(cast("tuple[object, ...]", observations))
            if total_syn > 256:
                raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
        flags = raw.get("tcp_flags")
        if isinstance(flags, h.FrozenObject):
            if len(flags.entries) > 16:
                raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
            for name, value in flags.entries:
                b._text(name, 256)
                b._number(value)
        for name in (
            "packet_count",
            "total_bytes",
            "tcp_syn_count",
            "tcp_ack_count",
            "tcp_rst_count",
            "tcp_syn_only_count",
            "tcp_syn_ack_count",
            "tcp_ack_only_count",
            "payload_length",
        ):
            if raw.get(name) is not None:
                b._integer(raw[name], minimum=1 if name == "packet_count" else 0)
        b._number(raw["duration_seconds"], 31_536_000)
        stamp = _utc(raw["timestamp"])
        micros = Decimal(str(raw["duration_seconds"])) * 1_000_000
        if not binding.event_start <= stamp <= binding.event_end or micros > (
            binding.event_end - stamp
        ) // timedelta(microseconds=1):
            raise b.BaselineInputError()
        if raw["sensor_id"] != binding.actual_sensor_id:
            raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
        b._text(cast("str", raw["protocol"]).upper(), 256)
        direction = cast("str", raw["direction"]).upper()
        if direction not in {"UNKNOWN", "INBOUND", "OUTBOUND"}:
            raise b.BaselineInputError()
        outgoing = any(ip_address(cast("str", raw["source_ip"])) in n for n in networks)
        incoming = any(ip_address(cast("str", raw["destination_ip"])) in n for n in networks)
        if outgoing != incoming and direction not in {
            "UNKNOWN",
            "OUTBOUND" if outgoing else "INBOUND",
        }:
            raise b.BaselineInputError()
        for pair in cast("tuple[object, ...]", observations or ()):
            offset = (
                dict(pair.entries)["offset_us"]
                if isinstance(pair, h.FrozenObject)
                else cast("tuple[int, int]", pair)[0]
            )
            b._integer(offset, 31_536_000_000_000)
            if cast("int", offset) > (binding.event_end - stamp) // timedelta(microseconds=1):
                raise b.BaselineInputError()
        for name in ("payload_hash", "last_payload_hash", "payload_prefix_hash", "payload_simhash"):
            if raw.get(name) is not None:
                b._text(raw[name], 256)


def _flows(binding: h.SourceBindingProjection) -> tuple[Flow, ...]:
    _preflight(binding)
    result = []
    for original in binding.original.flow_records:
        raw = cast("dict[str, Any]", h.thaw_original_json(original.fields))
        raw["timestamp"] = _utc(raw["timestamp"])
        raw["source_ip"] = str(ip_address(raw["source_ip"]))
        raw["destination_ip"] = str(ip_address(raw["destination_ip"]))
        raw["source_port"] = raw.get("source_port")
        raw["destination_port"] = raw.get("destination_port")
        raw["protocol"] = raw["protocol"].upper()
        raw["direction"] = raw["direction"].upper()
        raw["packet_sizes"] = tuple(raw.get("packet_sizes") or ())
        raw["tcp_syn_only_observations"] = normalize_tcp_syn_observations(
            raw.get("tcp_syn_only_observations")
        )
        result.append(_flow_value(Flow(**raw)))
    return tuple(result)


def _trusted(binding: h.SourceBindingProjection, flows: tuple[Flow, ...]) -> tuple[str, ...]:
    if not isinstance(binding.original.allowlist, h.Present):
        return ()
    # OriginalJob validates raw context cardinality and every enabled/expiry/IP
    # scalar before dedupe. Use existing absent-field semantics only afterward.
    entries = []
    for frozen in binding.original.allowlist.value:
        raw = cast("dict[str, Any]", h.thaw_original_json(frozen))
        if raw["type"].upper() not in {"IP", "CIDR"}:
            continue
        entries.append(
            AllowlistEntry(
                raw["type"],
                raw["value"],
                raw["description"],
                None if raw.get("expires_at") is None else _utc(raw["expires_at"]),
                raw.get("enabled", True),
            )
        )
    networks = tuple(ip_network(n) for n in binding.internal_networks)
    trusted: set[str] = set()
    for flow in flows:
        outgoing = any(ip_address(flow.source_ip) in n for n in networks)
        incoming = any(ip_address(flow.destination_ip) in n for n in networks)
        if outgoing == incoming:
            continue
        peer = flow.destination_ip if outgoing else flow.source_ip
        if any(entry.matches_metrics(peer, [], binding.event_end) for entry in entries):
            trusted.add(peer)
            if len(trusted) > 128:
                raise b.BaselineInputError("BASELINE_SOURCE_LIMIT")
    return tuple(sorted(trusted))


# Closed positional schema, traced to behavior_baseline._flow_order/build,
# traffic_suppression._tcp_flag_count/_payload_observed/control flood and
# tcp_sessions._connection_key/TCPConnectionProfile/periodic_syn_retries.
# Payload digests/length contribute ONLY the consumed presence predicate.
# packet_sizes/entropy/domain/TLS/etc are not read by this pure call graph.
# UNKNOWN is retained (uppercase) to preserve DERIVED_FROM_CIDR provenance;
# the accepted builder derives orientation only for one-internal-endpoint rows.
OBSERVATION_FIELDS = (
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
)


def _microseconds(value: datetime) -> int:
    return (_utc(value) - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(microseconds=1)


def _observation(flow: Flow, sensor_key: str) -> tuple[object, ...]:
    return (
        sensor_key,
        _microseconds(flow.timestamp),
        flow.source_ip,
        flow.destination_ip,
        flow.source_port,
        flow.destination_port,
        flow.protocol,
        flow.direction,
        flow.packet_count,
        flow.total_bytes,
        int(Decimal(str(flow.duration_seconds)) * 1_000_000),
        flow.tcp_syn_only_observations,
        flow.tcp_syn_only_observations_truncated,
        flow.tcp_flags_observed,
        flow.tcp_syn_count,
        flow.tcp_ack_count,
        flow.tcp_rst_count,
        flow.tcp_syn_only_count,
        flow.tcp_syn_ack_count,
        flow.tcp_ack_only_count,
        tuple(
            (key, "0" if value == 0 else format(Decimal(str(value)).normalize(), "f"))
            for key, value in sorted((flow.tcp_flags or {}).items())
        ),
        flow.bidirectional,
        bool(
            flow.payload_hash
            or flow.last_payload_hash
            or flow.payload_prefix_hash
            or flow.payload_simhash
            or (flow.payload_length or 0) > 0
        ),
    )


def _hashes(
    binding: h.SourceBindingProjection,
    flows: tuple[Flow, ...],
    trusted: tuple[str, ...],
    sensor_key: str,
) -> tuple[str, str]:
    # UTF-8 tuple-byte sorting, NEVER a set: duplicate observations stay counted.
    rows = sorted(
        (_observation(row, sensor_key) for row in flows),
        key=lambda v: h.canonical_json(v).encode("utf-8"),
    )
    content: dict[str, object] = {
        "schema_version": "source-observation-v1",
        "fields": OBSERVATION_FIELDS,
        "observations": rows,
        "event_start_us": _microseconds(binding.event_start),
        "event_end_us": _microseconds(binding.event_end),
        "internal_networks": binding.internal_networks,
        "trusted_peers": trusted,
    }
    feature = hashlib.sha256(h.canonical_json(content).encode("utf-8")).hexdigest()
    content["root_identity"] = binding.root_identity
    observation = hashlib.sha256(h.canonical_json(content).encode("utf-8")).hexdigest()
    return observation, feature


@_safe
def source_build_input(
    source: SourceProjection,
    *,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
    source_receipt_id: str | None,
) -> b.BaselineBuildInput:
    """Receipt provenance and approval eligibility belong to the caller."""
    if (
        type(scope) is not h.ScopeConfig
        or type(source) is not SourceProjection
        or (quality_review is not None and type(quality_review) is not h.QualityReview)
    ):
        raise b.BaselineInputError()
    if source_receipt_id is not None and quality_review is None:
        raise b.BaselineInputError()
    if source.internal_networks != scope.internal_networks:
        raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
    if scope.kind == "OPERATIONAL" and source.origin != "SENSOR_CAPTURE":
        raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
    if quality_review is not None:
        h.validate_sensor_assertion(
            scope,
            actual_sensor_id=source.actual_sensor_id,
            review=quality_review,
            origin=source.origin,
        )
    elif scope.kind == "EVALUATION":
        raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
    networks = tuple(ip_network(n) for n in scope.internal_networks)
    hosts = {host.ip for host in scope.hosts}
    for row in source.strict_flows:
        source_internal = any(ip_address(row.source_ip) in n for n in networks)
        destination_internal = any(ip_address(row.destination_ip) in n for n in networks)
        if (source_internal and row.source_ip not in hosts) or (
            destination_internal and row.destination_ip not in hosts
        ):
            raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
        if source_internal != destination_internal and row.direction not in (
            "UNKNOWN",
            "OUTBOUND" if source_internal else "INBOUND",
        ):
            raise b.BaselineInputError()
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
    request = b.BaselineBuildInput(
        identity,
        source.actual_sensor_id,
        quality_review.sensor_alias_asserted if quality_review is not None else False,
        source.event_start,
        source.event_end,
        source.strict_flows,
        source.trusted_peers,
        source_receipt_id,
    )
    # Use the accepted validator, not a second approximation of pure admission.
    b._build_input(request)
    if _hashes(
        source.source_binding(), source.strict_flows, source.trusted_peers, scope.sensor_key
    ) != (source.observation_sha256, source.feature_observation_sha256):
        raise b.BaselineInputError()
    return request


def target_vetoes(
    source: SourceProjection, *, quality_review: h.QualityReview | None
) -> tuple[b.ReasonCode, ...]:
    """Explicit review absence is a veto, never an invented clock assertion."""
    reasons: set[b.ReasonCode] = set()
    if quality_review is None:
        reasons.add("TARGET_REVIEW_REQUIRED")
    elif type(quality_review) is not h.QualityReview:
        raise b.BaselineInputError()
    if source.quality.known_partial:
        reasons.add("TARGET_PARTIAL_CAPTURE")
    if source.quality.clock_uncertain:
        reasons.add("SOURCE_CLOCK_UNCERTAIN")
    return tuple(sorted(reasons))


@_safe
def project_source(
    raw: dict[str, Any],
    *,
    ancestors: tuple[dict[str, Any], ...],
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> SourceProjection:
    """Project already-read JSON values; never fetch missing ancestors."""
    if type(ancestors) is not tuple or len(ancestors) > 15:
        raise SourceInputError("BASELINE_SOURCE_LINEAGE_INVALID")
    if any(type(node) is not dict for node in ancestors):
        raise SourceInputError()
    _original_syn_cap(raw, projected=False)
    original = h.project_original_job(raw)
    lineage = tuple(
        h.project_lineage_node({k: v for k, v in node.items() if k != "flow_records"})
        for node in (*ancestors, raw)
    )
    roots = [node for node in lineage if node.parent_job_id is None]
    if len(roots) != 1:
        raise ValueError("BASELINE_SOURCE_LINEAGE_INVALID")
    root = roots[0]
    digest = (
        root.source.value.sha256.value
        if isinstance(root.source, h.Present) and isinstance(root.source.value.sha256, h.Present)
        else None
    )
    binding = h.SourceBindingProjection(
        original=original,
        lineage=lineage,
        root_job_id=root.id,
        root_identity="pcap:" + digest if digest else h.canonical_json([root.id, root.dataset_id]),
        root_content_sha256=digest,
        origin="PCAP_UPLOAD" if digest else "SENSOR_CAPTURE",
        origin_assurance="STORED_LINEAGE_ONLY",
        actual_sensor_id=original.sensor_ids[0],
        event_start=_utc(original.start_time),
        event_end=_utc(original.end_time),
        internal_networks=tuple(
            sorted(str(ip_network(n, strict=False)) for n in original.internal_networks)
        ),
        quality=h.aggregate_lineage_quality(lineage, selected_job_id=original.id),
    )
    return source_from_binding(binding, scope=scope, quality_review=quality_review)


@_safe
def source_from_binding(
    binding: h.SourceBindingProjection,
    *,
    scope: h.ScopeConfig,
    quality_review: h.QualityReview | None,
) -> SourceProjection:
    """Complete the accepted no-I/O binding with scoped deterministic derivatives.

    This verifies origin/scope/alias, NOT normality or authenticated approval.
    A missing OPERATIONAL target review is retained as unreviewed; EVALUATION
    cannot acquire an implicit alias. Hashes become authoritative only with this
    explicit scope or source_build_input, not an unscoped DTO decode.
    """
    if type(binding) is not h.SourceBindingProjection or type(scope) is not h.ScopeConfig:
        raise b.BaselineInputError()
    _source_state(binding)
    flows = _flows(binding)
    trusted = _trusted(binding, flows)
    observation, feature = _hashes(binding, flows, trusted, scope.sensor_key)
    source = SourceProjection(
        **{name: getattr(binding, name) for name in h.SourceBindingProjection.model_fields},
        strict_flows=flows,
        trusted_peers=trusted,
        observation_sha256=observation,
        feature_observation_sha256=feature,
    )
    source_build_input(source, scope=scope, quality_review=quality_review, source_receipt_id=None)
    return source


@dataclass(frozen=True, slots=True)
class StructuralPreviewInput:
    """Private calculation facts, not a reviewed source or publication authority."""

    scope: h.ScopeConfig
    source: h.SourceBindingProjection
    strict_flows: tuple[StrictFlow, ...]
    trusted_peers: tuple[str, ...]

    def __post_init__(self) -> None:
        _preview_flow_caps(self.strict_flows, self.trusted_peers)
        _preview_source_caps(self.source, self.scope)
        _preview_shape(self.scope)
        _preview_shape(self.source)
        _preview_flow_values(self.strict_flows)
        b._structural_input(_preview_facts(self))


@dataclass(frozen=True, slots=True)
class StructuralPreviewCounts:
    """Conditional eligibility only; no normality, readiness or approval claim."""

    profile_count: int
    eligible_profile_count: int
    excluded_profile_count: int
    reasons: tuple[b.ReasonCode, ...]

    def __post_init__(self) -> None:
        for count in (self.profile_count, self.eligible_profile_count, self.excluded_profile_count):
            b._integer(count, 128)
        b._require(self.eligible_profile_count + self.excluded_profile_count == self.profile_count)
        b._tuple(self.reasons, 30)
        b._reasons(self.reasons)


def _preview_facts(request: StructuralPreviewInput) -> b._StructuralBuildInput:
    scope = request.scope
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
    return b._StructuralBuildInput(
        identity,
        request.source.actual_sensor_id,
        request.source.event_start,
        request.source.event_end,
        request.strict_flows,
        request.trusted_peers,
    )


def _preview_closed(value: h.FrozenDTO, kind: type[h.FrozenDTO]) -> None:
    b._require(type(value) is kind)
    b._require(not value.__pydantic_extra__ and vars(value).keys() == kind.model_fields.keys())


def _preview_entries(value: h.FrozenObject, allowed: Any = None, limit: int = 128) -> Any:
    b._require(type(value) is h.FrozenObject)
    b._tuple(value.entries, limit)
    seen: set[str] = set()
    for pair in value.entries:
        b._require(type(pair) is tuple and len(pair) == 2)
        key = pair[0]
        b._require(type(key) is str and key not in seen)
        b._require(allowed is None or key in allowed)
        seen.add(key)
    return value.entries


def _preview_source_caps(binding: h.SourceBindingProjection, scope: h.ScopeConfig) -> None:
    """Borrow only closed containers before any original-cell member walk."""
    _preview_closed(binding, h.SourceBindingProjection)
    _preview_closed(scope, h.ScopeConfig)
    b._tuple(scope.hosts, 128)
    b._tuple(scope.internal_networks, 128)
    b._require(type(binding.lineage) is tuple)
    if not 1 <= len(binding.lineage) <= 16:
        raise SourceInputError("BASELINE_SOURCE_LINEAGE_INVALID")
    _preview_closed(binding.original, h.OriginalJobProjection)
    b._tuple(binding.original.flow_records, 8192)
    for row in binding.original.flow_records:
        _preview_closed(row, h.OriginalFlowProjection)
        entries = _preview_entries(row.fields, h.FLOW_FIELDS, len(h.FLOW_FIELDS))
        for name, value in entries:
            if name in ("packet_sizes", "tcp_syn_only_observations") and value is not None:
                b._tuple(value, 128 if name == "packet_sizes" else 256)
            if name == "tcp_flags" and value is not None:
                _preview_entries(value, limit=16)
    # Count all raw SYN entries, even duplicates, BEFORE the first pair visit.
    _original_syn_cap(binding.original, projected=True)


def _preview_flow_caps(flows: tuple[Flow, ...], trusted: tuple[str, ...]) -> None:
    b._tuple(flows, 8192)
    b._tuple(trusted, 128)
    total = 0
    for row in flows:
        b._require(type(row) is Flow and vars(row).keys() == {f.name for f in fields(Flow)})
        b._tuple(row.packet_sizes, 128)
        if row.tcp_flags is not None:
            b._require(isinstance(row.tcp_flags, Mapping))
            b._require(len(row.tcp_flags) <= 16, "BASELINE_SOURCE_LIMIT")
        if row.tcp_syn_only_observations is not None:
            b._tuple(row.tcp_syn_only_observations, 256)
            total += len(row.tcp_syn_only_observations)
            b._require(total <= 256, "BASELINE_SOURCE_LIMIT")


@lru_cache(maxsize=1)
def _preview_flow_types() -> dict[str, Any]:
    return get_type_hints(Flow)


def _preview_flow_values(flows: tuple[Flow, ...]) -> None:
    for row in flows:
        for name, kind in _preview_flow_types().items():
            value = getattr(row, name)
            if name == "packet_sizes":
                for size in value:
                    b._integer(size)
            elif name == "tcp_syn_only_observations":
                _strict_syn(value)
            elif name == "tcp_flags":
                if value is not None:
                    b._require(type(value) is MappingProxyType)
                    for key, number in value.items():
                        b._text(key, 256)
                        b._number(number)
            else:
                kinds = get_args(kind) or (kind,)
                # Existing Flow normalizes neither integer durations nor other
                # finite JSON numbers to float; keep that accepted distinction.
                b._require(type(value) in kinds or (float in kinds and type(value) is int))
                if type(value) in (int, float):
                    h._number(value)
                elif type(value) is str:
                    h._text(value)
                elif type(value) is datetime:
                    b._utc(value)


def _preview_shape(
    value: Any, role: str = "", *, depth: int = 0, nodes: list[int] | None = None
) -> None:
    """Typed-only readmission, before copying; domain validators own meaning."""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    b._require(depth <= 16 and nodes[0] <= 262144, "BASELINE_SOURCE_LIMIT")
    if isinstance(value, h.FrozenDTO):
        b._require(type(value).__module__ == h.__name__)
        _preview_closed(value, type(value))
        for name, item in vars(value).items():
            if type(item) is tuple:
                b._tuple(item, 8192 if name == "flow_records" else 16 if name == "lineage" else 128)
        for name, item in vars(value).items():
            child = name if name in {"analysis", "allowlist", "operations"} else role
            if type(value) is h.OriginalFlowProjection and name == "fields":
                child = "flow"
            _preview_shape(item, child, depth=depth + 1, nodes=nodes)
        return
    if type(value) is h.FrozenObject:
        shapes = {
            "flow": h.FLOW_FIELDS,
            "analysis": h.AnalysisParameters.model_fields,
            "allowlist": h.ALLOWLIST_FIELDS,
            "operations": h.OPERATIONS_FIELDS,
            "sensor": h.SENSOR_OPERATION_FIELDS,
            "syn": {"offset_us", "sequence"},
        }
        allowed = shapes.get(role)
        entries = _preview_entries(value, allowed, 16 if role == "flags" else 128)
        for name, item in entries:
            if type(item) is tuple:
                b._tuple(item, 256 if name == "tcp_syn_only_observations" else 128)
        for name, item in entries:
            child = {
                "packet_sizes": "sizes",
                "tcp_syn_only_observations": "syn",
                "tcp_flags": "flags",
                "sensors": "sensors",
            }.get(name, "")
            if role == "sensors":
                child = "sensor"
            _preview_shape(item, child, depth=depth + 1, nodes=nodes)
        return
    if type(value) is tuple:
        b._require(len(value) + nodes[0] <= 262144, "BASELINE_SOURCE_LIMIT")
        for item in value:
            _preview_shape(item, role, depth=depth + 1, nodes=nodes)
        return
    b._require(value is None or type(value) in (str, bool, int, float, datetime))
    if type(value) is str:
        b._require(len(value) <= 8 * 1024 * 1024, "BASELINE_SOURCE_LIMIT")


def _preview_rebuild(value: Any) -> Any:
    # Only after whole-source and shape admission. FrozenObject kind/order stays.
    if isinstance(value, h.FrozenDTO):
        return {name: _preview_rebuild(item) for name, item in vars(value).items()}
    if type(value) is tuple:
        return tuple(_preview_rebuild(item) for item in value)
    return value


@_safe
def structural_preview_input(
    binding: h.SourceBindingProjection, *, scope: h.ScopeConfig
) -> StructuralPreviewInput:
    """Derive local facts from an admitted binding; never manufacture a review."""
    if type(binding) is not h.SourceBindingProjection or type(scope) is not h.ScopeConfig:
        raise b.BaselineInputError()
    _preview_source_caps(binding, scope)
    _preview_shape(scope)
    _preview_shape(binding)
    h._admit_original_job(vars(binding.original), projected=True)
    scope = h.ScopeConfig.model_validate(_preview_rebuild(scope))
    binding = h.SourceBindingProjection.model_validate(_preview_rebuild(binding))
    _source_state(binding)
    if binding.internal_networks != scope.internal_networks or (
        scope.kind == "OPERATIONAL" and binding.origin != "SENSOR_CAPTURE"
    ):
        raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
    flows = _flows(binding)
    networks = tuple(ip_network(n) for n in scope.internal_networks)
    hosts = {host.ip for host in scope.hosts}
    for row in flows:
        for endpoint in (row.source_ip, row.destination_ip):
            if any(ip_address(endpoint) in n for n in networks) and endpoint not in hosts:
                raise b.BaselineInputError("BASELINE_SCOPE_MISMATCH")
    result = StructuralPreviewInput(scope, binding, flows, _trusted(binding, flows))
    b._structural_input(_preview_facts(result))
    return result


@_safe
def calculate_structural_preview(request: StructuralPreviewInput) -> StructuralPreviewCounts:
    """No I/O or publishable window escapes this conditional calculation."""
    _checked_structural_preview(request)
    return StructuralPreviewCounts(*b._structural_counts(_preview_facts(request)))


def _checked_structural_preview(request: StructuralPreviewInput) -> None:
    if type(request) is not StructuralPreviewInput:
        raise b.BaselineInputError()
    request.__post_init__()
    expected = structural_preview_input(request.source, scope=request.scope)
    if (
        len(request.strict_flows) != len(expected.strict_flows)
        or any(
            h.canonical_json(_flow_mapping(left)) != h.canonical_json(_flow_mapping(right))
            for left, right in zip(request.strict_flows, expected.strict_flows, strict=True)
        )
        or request.trusted_peers != expected.trusted_peers
    ):
        raise b.BaselineInputError()


@dataclass(frozen=True, slots=True)
class UnreviewedEvaluationTarget:
    """Private target-only facts; not a SourceProjection or approval receipt."""

    structural: StructuralPreviewInput
    observation_sha256: str
    feature_observation_sha256: str


@_safe
def unreviewed_evaluation_target(
    binding: h.SourceBindingProjection, *, scope: h.ScopeConfig
) -> UnreviewedEvaluationTarget:
    request = structural_preview_input(binding, scope=scope)
    b._require(request.scope.kind == "EVALUATION", "BASELINE_SCOPE_MISMATCH")
    observation, feature = _hashes(
        request.source, request.strict_flows, request.trusted_peers, request.scope.sensor_key
    )
    return UnreviewedEvaluationTarget(request, observation, feature)


@_safe
def checked_evaluation_target(value: UnreviewedEvaluationTarget) -> UnreviewedEvaluationTarget:
    b._require(type(value) is UnreviewedEvaluationTarget)
    _checked_structural_preview(value.structural)
    b._require(value.structural.scope.kind == "EVALUATION", "BASELINE_SCOPE_MISMATCH")
    b._digest(value.observation_sha256)
    b._digest(value.feature_observation_sha256)
    request = value.structural
    b._require(
        _hashes(
            request.source, request.strict_flows, request.trusted_peers, request.scope.sensor_key
        )
        == (value.observation_sha256, value.feature_observation_sha256)
    )
    return value


@_safe
def compare_evaluation_target(
    value: UnreviewedEvaluationTarget, *, reference: b.BaselineReference | None
) -> b.BaselineComparisonResult:
    request = checked_evaluation_target(value).structural
    binding = request.source
    vetoes: set[b.ReasonCode] = {"TARGET_REVIEW_REQUIRED"}
    if binding.quality.known_partial:
        vetoes.add("TARGET_PARTIAL_CAPTURE")
    if binding.quality.clock_uncertain:
        vetoes.add("SOURCE_CLOCK_UNCERTAIN")
    return b.compare_unreviewed_evaluation_target(
        _preview_facts(request),
        reference=reference,
        target_observation=b.ObservationIdentity(
            binding.root_identity, binding.original.dataset_id, value.feature_observation_sha256
        ),
        target_vetoes=tuple(sorted(vetoes)),
    )
