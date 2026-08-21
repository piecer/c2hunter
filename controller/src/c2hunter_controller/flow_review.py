from __future__ import annotations

import hashlib
import json
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any

_FLOW_ID_FIELDS = (
    "sensor_id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "direction",
    "payload_hash",
    "packet_count",
    "total_bytes",
)
_SNAPSHOT_FIELDS = _FLOW_ID_FIELDS + (
    "last_payload_hash",
    "payload_prefix_hash",
    "payload_length",
    "payload_entropy",
    "payload_printable_ratio",
    "payload_simhash",
    "payload_feature_version",
    "tls_fingerprint",
    "certificate_fingerprint",
    "domain",
    "packet_sizes",
)


def flow_id(job_id: str, record: dict[str, Any]) -> str:
    canonical = {
        "job_id": job_id,
        **{
            field: _canonical_timestamp(record.get(field))
            if field == "timestamp"
            else _json_value(record.get(field))
            for field in _FLOW_ID_FIELDS
        },
    }
    encoded = json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()
    return hashlib.sha256(encoded).hexdigest()[:24]


def decorate_flow(
    job_id: str,
    record: dict[str, Any],
    internal_networks: list[str],
    current_label: dict[str, Any] | None = None,
) -> dict[str, Any]:
    source_ip = str(record["source_ip"])
    destination_ip = str(record["destination_ip"])
    direction = str(record.get("direction", "UNKNOWN")).upper()
    external_ip = None
    internal_ip = None
    service_port = None
    role_source = None
    if direction == "OUTBOUND":
        internal_ip = source_ip
        external_ip = destination_ip
        service_port = record.get("destination_port")
        role_source = "DIRECTION"
    elif direction == "INBOUND":
        internal_ip = destination_ip
        external_ip = source_ip
        service_port = record.get("source_port")
        role_source = "DIRECTION"
    else:
        source_internal = _is_internal(source_ip, internal_networks)
        destination_internal = _is_internal(destination_ip, internal_networks)
        if source_internal and not destination_internal:
            internal_ip = source_ip
            external_ip = destination_ip
            service_port = record.get("destination_port")
            role_source = "CIDR_FALLBACK"
        elif destination_internal and not source_internal:
            internal_ip = destination_ip
            external_ip = source_ip
            service_port = record.get("source_port")
            role_source = "CIDR_FALLBACK"
    result = {
        field: _json_value(record.get(field))
        for field in _SNAPSHOT_FIELDS
        if record.get(field) is not None
    }
    result.update(
        {
            "flow_id": flow_id(job_id, record),
            "job_id": job_id,
            "internal_ip": internal_ip,
            "external_ip": external_ip,
            "service_port": service_port,
            "role_source": role_source,
            "has_payload": bool(record.get("payload_hash")),
            "current_label": current_label,
        }
    )
    return result


def filter_flows(
    job: dict[str, Any],
    *,
    labels: list[dict[str, Any]] | None = None,
    candidate_ip: str | None = None,
    direction: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    source_port: int | None = None,
    destination_port: int | None = None,
    has_payload: bool | None = None,
    exclude_matches: bool = False,
    include_filters: list[dict[str, Any]] | None = None,
    exclude_filters: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    candidate_ip = candidate_ip.strip() if candidate_ip and candidate_ip.strip() else None
    direction = direction.strip() if direction and direction.strip() else None
    protocol = protocol.strip() if protocol and protocol.strip() else None
    if exclude_matches and all(
        value is None
        for value in (
            candidate_ip,
            direction,
            protocol,
            port,
            source_port,
            destination_port,
            has_payload,
        )
    ):
        raise ValueError("at least one exclusion condition is required")
    legacy_filter = {
        "candidate_ip": candidate_ip,
        "direction": direction,
        "protocol": protocol,
        "port": port,
        "source_port": source_port,
        "destination_port": destination_port,
        "has_payload": has_payload,
    }
    legacy_filter = {key: value for key, value in legacy_filter.items() if value is not None}
    normalized_includes = [_normalize_filter(item) for item in include_filters or []]
    normalized_excludes = [_normalize_filter(item) for item in exclude_filters or []]
    if legacy_filter:
        (normalized_excludes if exclude_matches else normalized_includes).append(
            _normalize_filter(legacy_filter)
        )
    latest_labels: dict[str, dict[str, Any]] = {}
    if labels is None:
        labels = []
    for label in sorted(labels, key=lambda item: str(item.get("created_at", ""))):
        latest_labels[str(label["flow_id"])] = label
    result: list[dict[str, Any]] = []
    for raw in job.get("flow_records", []):
        record = dict(raw)
        identifier = flow_id(str(job["id"]), record)
        decorated = decorate_flow(
            str(job["id"]),
            record,
            list(job["internal_networks"]),
            latest_labels.get(identifier),
        )
        include_match = not normalized_includes or any(
            _matches_filter(decorated, **flow_filter) for flow_filter in normalized_includes
        )
        exclude_match = any(
            _matches_filter(decorated, **flow_filter) for flow_filter in normalized_excludes
        )
        if not include_match or exclude_match:
            continue
        result.append(decorated)
    result.sort(key=lambda item: (str(item.get("timestamp", "")), item["flow_id"]))
    return result


def filter_packet_records(
    records: list[dict[str, Any]],
    *,
    internal_networks: list[str],
    include_filters: list[dict[str, Any]] | None = None,
    exclude_filters: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Apply flow-review groups to decoded packets while returning raw records."""
    normalized_includes = [_normalize_filter(item) for item in include_filters or []]
    normalized_excludes = [_normalize_filter(item) for item in exclude_filters or []]
    result: list[dict[str, Any]] = []
    for raw in records:
        decorated = decorate_flow("packet-export", raw, internal_networks)
        include_match = not normalized_includes or any(
            _matches_filter(decorated, **packet_filter) for packet_filter in normalized_includes
        )
        exclude_match = any(
            _matches_filter(decorated, **packet_filter) for packet_filter in normalized_excludes
        )
        if include_match and not exclude_match:
            result.append(raw)
    return result


def _normalize_filter(flow_filter: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "candidate_ip",
        "direction",
        "protocol",
        "port",
        "source_port",
        "destination_port",
        "has_payload",
    }
    if not flow_filter or set(flow_filter) - allowed:
        raise ValueError("flow filter must contain supported conditions")
    candidate_ip = str(flow_filter.get("candidate_ip", "")).strip() or None
    direction = str(flow_filter.get("direction", "")).strip() or None
    protocol = str(flow_filter.get("protocol", "")).strip() or None
    ports = {key: flow_filter.get(key) for key in ("port", "source_port", "destination_port")}
    if direction and direction.upper() not in {
        "INBOUND",
        "OUTBOUND",
        "BIDIRECTIONAL",
        "UNKNOWN",
    }:
        raise ValueError("unsupported flow direction")
    if protocol and len(protocol) > 32:
        raise ValueError("flow protocol is too long")
    if any(
        value is not None
        and (not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 65535)
        for value in ports.values()
    ):
        raise ValueError("flow port must be between 0 and 65535")
    has_payload = flow_filter.get("has_payload")
    if has_payload is not None and not isinstance(has_payload, bool):
        raise ValueError("has_payload must be boolean")
    normalized = {
        "endpoint_network": ip_network(candidate_ip, strict=False) if candidate_ip else None,
        "direction": direction,
        "protocol": protocol,
        **ports,
        "has_payload": has_payload,
    }
    if all(value is None for value in normalized.values()):
        raise ValueError("flow filter must contain an active condition")
    return normalized


def _matches_filter(
    flow: dict[str, Any],
    *,
    endpoint_network: Any,
    direction: str | None,
    protocol: str | None,
    port: int | None,
    source_port: int | None,
    destination_port: int | None,
    has_payload: bool | None,
) -> bool:
    if endpoint_network and not any(
        ip_address(str(flow[field])) in endpoint_network
        for field in ("source_ip", "destination_ip")
    ):
        return False
    if direction and str(flow.get("direction", "")).upper() != direction.upper():
        return False
    if protocol and str(flow.get("protocol", "")).upper() != protocol.upper():
        return False
    if port is not None and flow.get("service_port") != port:
        return False
    if source_port is not None and flow.get("source_port") != source_port:
        return False
    if destination_port is not None and flow.get("destination_port") != destination_port:
        return False
    return has_payload is None or flow["has_payload"] is has_payload


def label_snapshot(flow: dict[str, Any]) -> dict[str, Any]:
    return {
        field: flow[field]
        for field in _SNAPSHOT_FIELDS
        if field in flow and flow[field] is not None
    } | {
        "external_ip": flow.get("external_ip"),
        "internal_ip": flow.get("internal_ip"),
        "service_port": flow.get("service_port"),
    }


def payload_ascii(payload_hex: str) -> str:
    payload = bytes.fromhex(payload_hex)
    return "".join(
        chr(value)
        if 0x20 <= value <= 0x7E
        else "\\r"
        if value == 13
        else "\\n"
        if value == 10
        else "\\t"
        if value == 9
        else "."
        for value in payload
    )


def _is_internal(value: str, networks: list[str]) -> bool:
    address = ip_address(value)
    return any(address in ip_network(network, strict=False) for network in networks)


def _json_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, tuple):
        return list(value)
    return value


def _canonical_timestamp(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).isoformat()
        except ValueError:
            return value
    return value
