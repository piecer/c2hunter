"""Bounded ICMP event metadata, separate from detection and legacy facts."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from typing import TYPE_CHECKING, Literal, TypedDict

if TYPE_CHECKING:
    from .network_report import Example

VERSION = "network-icmp-details-v1"
MAX_SAMPLES = 2048
MAX_BYTES = 262144
PER_OBSERVATION = 4


class Quote(TypedDict):
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None


class Sample(TypedDict):
    reporter_ip: str
    protocol: str
    type: int
    code: int
    quoted_flow: Quote | None
    time: str
    packet_reference: None


class Details(TypedDict):
    version: Literal["network-icmp-details-v1"]
    samples: list[Sample]
    omitted_event_details: int


class Envelope(TypedDict):
    icmp_details: Details


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _ip(value: object) -> str | None:
    if type(value) is not str or not 1 <= len(value) <= 45 or "%" in value:
        return None
    try:
        ip_address(value)
    except ValueError:
        return None
    return value


def _port(value: object) -> int | None:
    return value if type(value) is int and 0 <= value <= 65535 else None


def sample(record: Mapping[str, object], time: float) -> Sample | None:
    # Validate scalars before copying/encoding; never retain source mappings.
    reporter = _ip(record.get("source_ip"))
    protocol = record.get("protocol")
    kind, code = record.get("icmp_type"), record.get("icmp_code")
    if (
        reporter is None
        or type(protocol) is not str
        or len(protocol) > 6
        or protocol.upper() not in {"ICMP", "ICMPV6"}
        or type(kind) is not int
        or not 0 <= kind <= 255
        or type(code) is not int
        or not 0 <= code <= 255
    ):
        return None
    quote = record.get("icmp_quoted_flow")
    quoted: Quote | None = None
    if isinstance(quote, Mapping):
        qp = quote.get("protocol")
        quoted = {
            "source_ip": _ip(quote.get("source_ip")),
            "destination_ip": _ip(quote.get("destination_ip")),
            "source_port": _port(quote.get("source_port")),
            "destination_port": _port(quote.get("destination_port")),
            "protocol": qp.upper()
            if type(qp) is str and len(qp) <= 6 and qp.upper() in {"TCP", "UDP", "ICMP", "ICMPV6"}
            else None,
        }
    return {
        "reporter_ip": reporter,
        "protocol": protocol.upper(),
        "type": kind,
        "code": code,
        "quoted_flow": quoted,
        "time": datetime.fromtimestamp(time, UTC).isoformat(),
        "packet_reference": None,
    }


@dataclass(slots=True)
class Retained:
    ordinal: int
    value: Sample
    size: int


@dataclass(slots=True)
class DetailBudget:
    count: int = 0
    size: int = 0
    ordinal: int = 0

    def add(self, owner: list[Retained], record: Mapping[str, object], time: float) -> None:
        self.ordinal += 1
        if len(owner) >= PER_OBSERVATION or self.count >= MAX_SAMPLES:
            return
        value = sample(record, time)
        if value is None:
            return
        size = len(canonical(value)) + 1
        if self.size + size > MAX_BYTES:
            return
        owner.append(Retained(self.ordinal, value, size))
        self.count += 1
        self.size += size

    def release(self, owner: list[Retained]) -> None:
        self.count -= len(owner)
        self.size -= sum(s.size for s in owner)
        owner.clear()

    def merge(self, target: list[Retained], source: list[Retained]) -> None:
        merged = sorted((*target, *source), key=lambda s: s.ordinal)
        discarded = merged[PER_OBSERVATION:]
        self.release(discarded)
        target[:] = merged[:PER_OBSERVATION]
        source.clear()


def publish(owners: list[tuple[Example, int, list[Retained]]]) -> None:
    """Exact bounded contributions; no repeated whole-report serialization."""
    envelopes: list[Envelope] = [
        {
            "icmp_details": {
                "version": "network-icmp-details-v1",
                "samples": [],
                "omitted_event_details": count,
            }
        }
        for _, count, _ in owners
    ]
    sizes = [len(canonical(e)) for e in envelopes]
    size = 2 + max(0, len(envelopes) - 1) + sum(sizes)
    if size > MAX_BYTES:
        raise ValueError("ICMP detail byte budget cannot represent omission qualifiers")
    for index, (example, count, samples) in enumerate(owners):
        detail = envelopes[index]["icmp_details"]
        for retained in samples:
            candidate: Envelope = {
                "icmp_details": {
                    "version": "network-icmp-details-v1",
                    "samples": [*detail["samples"], retained.value],
                    "omitted_event_details": count - len(detail["samples"]) - 1,
                }
            }
            candidate_size = len(canonical(candidate))
            if size - sizes[index] + candidate_size > MAX_BYTES:
                break
            size += candidate_size - sizes[index]
            sizes[index] = candidate_size
            detail = candidate["icmp_details"]
        if not validate_details(detail, count):
            raise ValueError("Invalid producer ICMP details")
        example["icmp_details"] = detail


def _closed(value: object, keys: tuple[str, ...]) -> bool:
    # No custom key equality callbacks, container subclass hooks or coercion.
    return (
        type(value) is dict
        and len(value) == len(keys)
        and all(type(k) is str for k in value)
        and set(value) == set(keys)
    )


def _integer_value(value: object, maximum: int) -> bool:
    # Validation only: exact builtins prevent callbacks; range rejects nonfinite
    # floats without converting potentially huge Python integers to float.
    if type(value) is int:
        return 0 <= value <= maximum
    return type(value) is float and 0 <= value <= maximum and value.is_integer()


def _count(value: object) -> bool:
    return _integer_value(value, 9007199254740991)


def _time(value: object) -> bool:
    if (
        type(value) is not str
        or len(value) > 32
        or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{6})?\+00:00", value
        )
        is None
    ):
        return False
    try:
        datetime.fromisoformat(value)
    except ValueError:
        return False
    return True


def validate_details(value: object, event_count: int | float) -> bool:
    """Validate decoded integer values; producer TypedDicts remain int-only.

    This does not change source admission or rewrite stored reports. Standard
    JSON decoder precision applies; original numeric lexemes are not retained.
    """
    if not _closed(value, ("version", "samples", "omitted_event_details")):
        return False
    if not isinstance(value, dict):
        return False
    rows = value["samples"]
    if (
        type(value["version"]) is not str
        or value["version"] != VERSION
        or type(rows) is not list
        or len(rows) > PER_OBSERVATION
        or not _count(value["omitted_event_details"])
        or not _count(event_count)
        or event_count - len(rows) != value["omitted_event_details"]
    ):
        return False
    for s in rows:
        if not _closed(
            s,
            ("reporter_ip", "protocol", "type", "code", "quoted_flow", "time", "packet_reference"),
        ):
            return False
        if (
            _ip(s["reporter_ip"]) is None
            or type(s["protocol"]) is not str
            or s["protocol"] not in {"ICMP", "ICMPV6"}
            or any(not _integer_value(s[k], 255) for k in ("type", "code"))
            or not _time(s["time"])
            or s["packet_reference"] is not None
        ):
            return False
        q = s["quoted_flow"]
        if q is not None:
            if not _closed(
                q, ("source_ip", "destination_ip", "source_port", "destination_port", "protocol")
            ):
                return False
            if (
                any(q[k] is not None and _ip(q[k]) is None for k in ("source_ip", "destination_ip"))
                or any(
                    q[k] is not None and not _integer_value(q[k], 65535)
                    for k in ("source_port", "destination_port")
                )
                or (
                    q["protocol"] is not None
                    and (
                        type(q["protocol"]) is not str
                        or q["protocol"] not in {"TCP", "UDP", "ICMP", "ICMPV6"}
                    )
                )
            ):
                return False
    return True
