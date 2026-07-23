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
    source_internal = _is_internal(str(record["source_ip"]), internal_networks)
    destination_internal = _is_internal(str(record["destination_ip"]), internal_networks)
    external_ip = None
    internal_ip = None
    service_port = None
    if source_internal and not destination_internal:
        internal_ip = str(record["source_ip"])
        external_ip = str(record["destination_ip"])
        service_port = record.get("destination_port")
    elif destination_internal and not source_internal:
        internal_ip = str(record["destination_ip"])
        external_ip = str(record["source_ip"])
        service_port = record.get("source_port")
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
            "has_payload": bool(record.get("payload_hash")),
            "current_label": current_label,
        }
    )
    return result


def filter_flows(
    job: dict[str, Any],
    *,
    labels: list[dict[str, Any]] = (),
    candidate_ip: str | None = None,
    direction: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    has_payload: bool | None = None,
) -> list[dict[str, Any]]:
    latest_labels: dict[str, dict[str, Any]] = {}
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
        if candidate_ip and candidate_ip not in {
            decorated.get("source_ip"),
            decorated.get("destination_ip"),
        }:
            continue
        if direction and str(decorated.get("direction", "")).upper() != direction.upper():
            continue
        if protocol and str(decorated.get("protocol", "")).upper() != protocol.upper():
            continue
        if port is not None and decorated.get("service_port") != port:
            continue
        if has_payload is not None and decorated["has_payload"] is not has_payload:
            continue
        result.append(decorated)
    result.sort(key=lambda item: (str(item.get("timestamp", "")), item["flow_id"]))
    return result


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
