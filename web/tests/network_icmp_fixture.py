"""Checksum-valid router errors through the real parser and public worker path."""

from __future__ import annotations

import json
import copy
import struct
import sys
from datetime import UTC, datetime
from pathlib import Path
from ipaddress import ip_address

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / p) for p in ("analysis/tests", "web/tests")]
import test_network_anomaly as packets  # noqa: E402
from network_epoch_fixture import _public_case, canonical  # noqa: E402


def router_error(router=1, code=1, quote=None):
    if quote is None:
        quote = packets.frame(protocol=17, payload=b"query")[14:42]
    wire = bytearray(packets.frame(protocol=1, reverse=True, payload=quote))
    wire[26:30] = bytes((192, 0, 2, router))
    wire[35] = code
    wire[24:26] = b"\0\0"
    wire[36:38] = b"\0\0"
    wire[24:26] = struct.pack("!H", packets.internet_checksum(bytes(wire[14:34])))
    wire[36:38] = struct.pack("!H", packets.internet_checksum(bytes(wire[34:])))
    assert packets.internet_checksum(bytes(wire[14:34])) == 0
    assert packets.internet_checksum(bytes(wire[34:])) == 0
    return bytes(wire)


def capture():
    return packets.capture(
        packets.frame(protocol=17, payload=b"query"),
        router_error(1, 1),
        router_error(2, 3),
        start_time=datetime.fromtimestamp(1700000000, UTC),
    )


def records(content=None, *, retain_packet_bytes=False):
    from c2hunter_analysis.pcap import parse_pcap
    from c2hunter_controller.schemas import FlowRecord

    parsed = parse_pcap(
        content or capture(),
        sensor_id="icmp-fixture",
        internal_networks=["10.0.0.0/8"],
        retain_network_evidence=True,
        retain_packet_bytes=retain_packet_bytes,
    )
    if retain_packet_bytes:
        return parsed.records
    return [
        FlowRecord.model_validate(r).model_dump(mode="json") for r in parsed.records
    ]


def build_bundle():
    value = _public_case("icmp-two-routers", capture())
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in list(sys.modules.items())
        if name.startswith(
            ("c2hunter_analysis", "c2hunter_controller", "c2hunter_worker")
        )
        and getattr(module, "__file__", None)
    }
    assert origins and all(Path(p).is_relative_to(ROOT) for p in origins.values())
    from c2hunter_controller.network_ai import build_network_input

    maximum = maximum_report()
    return {
        "case": value,
        "origins": origins,
        "ipv6": _public_case("icmp-v6", packets.capture(*ipv6_frames())),
        "maximum": maximum,
        "maximum_ai": build_network_input(maximum),
        "mutations": mutation_corpus(value["report"]),
        "numeric_wires": numeric_wire_corpus(value["report"]),
    }


def ipv6_frames():
    src, dst = ip_address("2001:db8::1").packed, ip_address("2001:db8::2").packed

    def frame(source, destination, protocol, transport):
        offset = 6 if protocol == 17 else 2
        pseudo = source + destination + struct.pack("!I3xB", len(transport), protocol)
        checksum = packets.internet_checksum(pseudo + transport)
        transport = (
            transport[:offset]
            + struct.pack("!H", checksum or 65535)
            + transport[offset + 2 :]
        )
        assert packets.internet_checksum(pseudo + transport) == 0
        ip = struct.pack(
            "!IHBB16s16s", 6 << 28, len(transport), protocol, 64, source, destination
        )
        return bytes.fromhex("00112233445566778899aabb86dd") + ip + transport

    target = frame(src, dst, 17, struct.pack("!HHHH", 50000, 443, 13, 0) + b"query")
    errors = [
        frame(
            ip_address(f"2001:db8:1::{i}").packed,
            src,
            58,
            bytes((1, code, 0, 0, 0, 0, 0, 0)) + target[14:62],
        )
        for i, code in [(1, 0), (2, 4)]
    ]
    return [target, *errors]


def maximum_report():
    # Analyzer-only 100x10; production API still defaults to 20x3.
    from c2hunter_analysis.network_report import analyze_network_report
    from c2hunter_controller.schemas import FlowRecord

    base = records()
    rows = []
    for group in range(100):
        for host in range(10):
            source, destination = f"10.0.{group}.{host + 1}", f"203.0.113.{group + 1}"
            target = {**base[0], "source_ip": source, "destination_ip": destination}
            rows.append(FlowRecord.model_validate(target).model_dump(mode="json"))
            for code in range(4):
                row = copy.deepcopy(base[1])
                row.update(
                    destination_ip=source,
                    source_ip=f"192.0.2.{code + 1}",
                    icmp_code=code,
                )
                row["icmp_quoted_flow"].update(
                    source_ip=source, destination_ip=destination
                )
                rows.append(FlowRecord.model_validate(row).model_dump(mode="json"))
    return analyze_network_report(rows, max_issues=100, max_examples=10)


def mutation_corpus(report):
    from c2hunter_analysis.network_icmp_details import validate_details

    base = report["issues"][0]["examples"][0]
    cases = []
    for fault in (
        "valid",
        "null",
        "extra",
        "missing",
        "version",
        "overflow",
        "omission",
        "bool",
        "unsafe",
        "sample-extra",
        "ip",
        "escaped-ip",
        "protocol",
        "type",
        "code",
        "quote-extra",
        "quote-null",
        "quote-partial",
        "quote-port",
        "quote-protocol",
        "time",
        "reference",
    ):
        e = copy.deepcopy(base)
        d = e["icmp_details"]
        s = d["samples"][0]
        if fault == "null":
            e["icmp_details"] = None
        if fault == "extra":
            d["extra"] = None
        if fault == "missing":
            del d["version"]
        if fault == "version":
            d["version"] = [d["version"]]
        if fault == "overflow":
            d["samples"] *= 3
        if fault == "omission":
            d["omitted_event_details"] += 1
        if fault == "bool":
            d["omitted_event_details"] = False
        if fault == "unsafe":
            d["omitted_event_details"] = 2**53
        if fault == "sample-extra":
            s["extra"] = None
        if fault == "ip":
            s["reporter_ip"] = "999.1.1.1"
        if fault == "escaped-ip":
            s["reporter_ip"] = 'a\\"\u2028' * 100
        if fault == "protocol":
            s["protocol"] = ["ICMP"]
        if fault == "type":
            s["type"] = -1
        if fault == "code":
            s["code"] = 256
        if fault == "quote-extra":
            s["quoted_flow"]["extra"] = None
        if fault == "quote-null":
            s["quoted_flow"] = None
        if fault == "quote-partial":
            s["quoted_flow"]["source_ip"] = None
        if fault == "quote-port":
            s["quoted_flow"]["source_port"] = 65536
        if fault == "quote-protocol":
            s["quoted_flow"]["protocol"] = {}
        if fault == "time":
            s["time"] = "2023-02-30T00:00:00+00:00"
        if fault == "reference":
            s["packet_reference"] = {"raw_packet_index": 1}
        cases.append(
            {
                "name": fault,
                "example": e,
                "accepted": validate_details(e["icmp_details"], e["event_count"]),
            }
        )
    return cases


def numeric_wire_corpus(report):
    """Keep number spellings inside wire strings across the Python/JS boundary."""
    from c2hunter_analysis.network_icmp_details import validate_details

    base = report["issues"][0]["examples"][0]
    cases = []
    for name, path, value in (
        ("code", ("icmp_details", "samples", 0, "code"), 1.0),
        ("type", ("icmp_details", "samples", 0, "type"), 3.0),
        ("omission", ("icmp_details", "omitted_event_details"), 0.0),
        ("event_count", ("event_count",), 2.0),
        ("source_port", ("icmp_details", "samples", 0, "quoted_flow", "source_port"), 50000.0),
    ):
        example = copy.deepcopy(base)
        owner = example
        for key in path[:-1]:
            owner = owner[key]
        owner[path[-1]] = value
        wire = canonical(example)
        decoded = json.loads(wire)
        cases.append({
            "name": name,
            "wire": wire,
            "python": validate_details(decoded["icmp_details"], decoded["event_count"]),
            "expected": True,
        })
    # The first five cases intentionally reproduce the original review bytes.
    # Other cases replace a unique string marker, never JS-reserialize a number.
    paths = {
        "code": ("icmp_details", "samples", 0, "code"),
        "type": ("icmp_details", "samples", 0, "type"),
        "omission": ("icmp_details", "omitted_event_details"),
        "event_count": ("event_count",),
        "source_port": ("icmp_details", "samples", 0, "quoted_flow", "source_port"),
        "destination_port": ("icmp_details", "samples", 0, "quoted_flow", "destination_port"),
    }
    common = [
        ("zero", "0", True), ("integer", "1", True),
        ("float-zero", "0.0", True), ("negative-zero", "-0.0", True),
        ("exponent", "1e0", True), ("fraction", "1.5", False),
        ("negative", "-1", False), ("negative-fraction", "-0.5", False),
        ("true", "true", False), ("false", "false", False),
        ("null", "null", False), ("string", '"1"', False),
        ("huge-exponent", "1e400", False), ("negative-huge-exponent", "-1e400", False),
    ]
    for field, path in paths.items():
        count = field in {"omission", "event_count"}
        port = field in {"source_port", "destination_port"}
        maximum = 9007199254740991 if count else 65535 if port else 255
        tokens = common + [
            ("maximum", str(maximum), True),
            ("maximum-float", f"{maximum}.0", True),
            ("maximum-exponent", f"{maximum}e0", True),
            ("above-maximum", str(maximum + 1), False),
            ("above-maximum-float", f"{maximum + 1}.0", False),
        ]
        for label, token, expected in tokens:
            example = copy.deepcopy(base)
            if count:
                example["icmp_details"]["samples"] = []
                other = int(json.loads(token)) if expected else 0
                example["event_count"] = other
                example["icmp_details"]["omitted_event_details"] = other
            owner = example
            for key in path[:-1]:
                owner = owner[key]
            owner[path[-1]] = "NUMERIC_WIRE_TOKEN"
            wire = canonical(example).replace('"NUMERIC_WIRE_TOKEN"', token)
            decoded = json.loads(wire)
            cases.append({
                "name": f"{field}-{label}", "wire": wire,
                "python": validate_details(decoded["icmp_details"], decoded["event_count"]),
                "expected": expected or (port and label == "null"),
            })
    for token in ("NaN", "Infinity", "-Infinity"):
        wire = cases[0]["wire"].replace('"code":1.0', f'"code":{token}', 1)
        decoded = json.loads(wire)  # Python permits these extensions; Web JSON does not.
        cases.append({
            "name": f"syntax-{token}", "wire": wire, "syntax_error": True,
            "python": validate_details(decoded["icmp_details"], decoded["event_count"]),
            "expected": False,
        })
    return cases


if __name__ == "__main__":
    value = build_bundle()
    if len(sys.argv) == 2:
        Path(sys.argv[1]).write_text(canonical(value["case"]["report"]) + "\n")
    else:
        print(json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False))
