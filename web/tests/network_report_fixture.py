"""Emit real parser → network report scenarios for frontend parity tests.

Run from the repository: .venv/bin/python web/tests/network_report_fixture.py
No generated timestamps, random values, network, or controller state.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "analysis/src"), str(ROOT / "analysis/tests")]
from test_network_anomaly import frame, records
from c2hunter_analysis.network_report import analyze_network_report


def scenarios():
    data = frame(flags=24, seq=101, payload=b"abc")
    ack = frame(flags=16, seq=500, ack=101, reverse=True)
    udp = frame(protocol=17, payload=b"query")
    # Real parser records with deliberately absent optional metadata model older
    # evidence records; reports themselves always come from the actual analyzer.
    missing_metadata = records(
        frame(), frame(), frame(flags=18, seq=500, ack=101, reverse=True)
    )
    for record in missing_metadata:
        record.pop("ip_ttl", None)
    import struct
    from ipaddress import IPv6Address
    from test_network_anomaly import internet_checksum

    def ipv6_udp(hop_limit):
        src, dst = IPv6Address("2001:db8::1").packed, IPv6Address("2001:db8::2").packed
        payload = b"query"
        udp6 = struct.pack("!HHHH", 50000, 443, 8 + len(payload), 0) + payload
        pseudo = src + dst + struct.pack("!I3xB", len(udp6), 17)
        checksum = internet_checksum(pseudo + udp6)
        udp6 = udp6[:6] + struct.pack("!H", checksum or 65535) + udp6[8:]
        ip6 = struct.pack("!IHBB16s16s", 6 << 28, len(udp6), 17, hop_limit, src, dst)
        return bytes.fromhex("00112233445566778899aabb86dd") + ip6 + udp6

    from datetime import timedelta
    from unittest.mock import patch

    handshake_only = records(
        frame(),
        frame(flags=18, seq=500, ack=101, reverse=True),
        data,
        data,
        frame(flags=16, seq=501, ack=104, reverse=True),
    )
    clock_gap = [dict(record) for record in handshake_only]
    clock_gap[-1]["timestamp"] = clock_gap[0]["timestamp"] - timedelta(seconds=1)
    cap_packets = records(data, data, frame(flags=24, seq=104, payload=b"def"))
    with patch("c2hunter_analysis.network_report.MAX_FLOW_CORRELATIONS", 1):
        cap_at = analyze_network_report(cap_packets[:2])
        cap_plus = analyze_network_report(cap_packets)
    return {
        "handshake_only": analyze_network_report(handshake_only),
        "clock_gap": analyze_network_report(clock_gap),
        "cap_at": cap_at,
        "cap_plus": cap_plus,
        "supporting": analyze_network_report(
            records(
                frame(),
                frame(flags=18, seq=500, ack=101, reverse=True),
                data,
                frame(flags=16, seq=501, ack=104, reverse=True),
                frame(flags=24, seq=104, payload=b"def"),
                frame(flags=24, seq=104, payload=b"def"),
                frame(flags=16, seq=501, ack=107, reverse=True),
            )
        ),
        "ambiguous_rtt": analyze_network_report(
            records(data, data, frame(flags=16, seq=500, ack=104, reverse=True))
        ),
        "missing_metadata": analyze_network_report(missing_metadata),
        "ipv6_hop_limit": analyze_network_report(
            records(ipv6_udp(64), ipv6_udp(63), ipv6_udp(0))
        ),
        "normal": analyze_network_report(
            records(frame(), frame(flags=18, seq=500, ack=101, reverse=True))
        ),
        "syn_reset": analyze_network_report(
            records(frame(), frame(), frame(flags=20, ack=101, reverse=True))
        ),
        "data_ack": analyze_network_report(records(data, data, ack, ack)),
        "udp": analyze_network_report(records(udp, udp)),
        "icmp": analyze_network_report(
            records(udp, frame(protocol=1, reverse=True, payload=udp[14:42]))
        ),
        "missing": analyze_network_report([]),
        "incomplete": analyze_network_report([{"packet_count": 10}]),
    }


def quality_contract():
    """Identical serialized measurement bytes for AI validation and UI presentation."""
    from copy import deepcopy

    sys.path.insert(0, str(ROOT / "controller/src"))
    from c2hunter_controller.network_ai import build_network_input

    reports = scenarios()
    # Explicit compatibility/malformed variants; never labeled producer witnesses.
    legacy = deepcopy(reports["handshake_only"])
    m = legacy["issues"][0]["examples"][0]["measurements"]
    del m["metric_quality"]
    reports["legacy_quality_absent"] = legacy
    legacy_zero = deepcopy(legacy)
    legacy_zero["issues"][0]["examples"][0]["measurements"]["observed_rtt_ms"][
        "stddev"
    ] = 0
    reports["legacy_singleton_zero"] = legacy_zero
    for mutation in (
        "status",
        "reason",
        "extra",
        "null",
        "missing",
        "count",
        "selection",
        "order",
    ):
        bad = deepcopy(reports["handshake_only"])
        m = bad["issues"][0]["examples"][0]["measurements"]
        q = m["metric_quality"]["observed_rtt_ms"]
        if mutation == "status":
            q["status"] = "POISON"
        elif mutation == "reason":
            q["reasons"] = ["POISON"]
        elif mutation == "extra":
            q["confidence"] = "POISON"
        elif mutation == "null":
            m["metric_quality"] = None
        elif mutation == "missing":
            del m["metric_quality"]["ttl_observed"]
        elif mutation == "count":
            q["status"] = "observed_samples"
        elif mutation == "selection":
            q["reasons"].remove("SELECTION_BIAS_POSSIBLE")
        else:
            q["reasons"].reverse()
        reports[f"invalid_{mutation}"] = bad
    output = {}
    for name, report in reports.items():
        if not report["issues"]:
            continue
        measurement = report["issues"][0]["examples"][0]["measurements"]
        try:
            bundle = build_network_input(report, "en")
            projected = bundle["issues"][0]["observed_measurements"][0]
            assert projected == measurement
            accepted = True
        except ValueError:
            projected, accepted = None, False
        assert accepted is not name.startswith("invalid_"), name
        output[name] = {
            "measurement": measurement,
            "projected": projected,
            "accepted": accepted,
        }
    return json.dumps(output, sort_keys=True, indent=2, allow_nan=False) + "\n"


if __name__ == "__main__":
    if "--quality-contract" in sys.argv:
        print(quality_contract(), end="")
    elif "--legacy" in sys.argv or "--legacy-limited" in sys.argv:
        from c2hunter_analysis.network_anomaly import analyze_network_anomalies

        packets = (
            [frame(protocol=17, payload=str(index).encode()) for index in range(257)]
            if "--legacy-limited" in sys.argv
            else [frame(), frame()]
        )
        print(json.dumps(analyze_network_anomalies(records(*packets)), sort_keys=True))
    elif "--pagination" in sys.argv:
        from c2hunter_analysis.pcap import parse_pcap
        from test_network_anomaly import capture

        def grouped_report(size):
            # Genuine repeated-SYN PCAP bytes at distinct observation points.
            evidence = []
            for index in range(size):
                evidence.extend(
                    parse_pcap(
                        capture(frame(), frame()),
                        sensor_id=f"page-sensor-{index:02d}",
                        internal_networks=["10.0.0.0/8"],
                        retain_packet_bytes=False,
                        retain_network_evidence=True,
                    ).records
                )
            return analyze_network_report(evidence)

        print(
            json.dumps(
                {str(size): grouped_report(size) for size in (0, 8, 9, 20, 23)},
                sort_keys=True,
            )
        )
    elif "--contract" in sys.argv:
        import ast
        from c2hunter_analysis import network_report

        tree = ast.parse(Path(network_report.__file__).read_text())
        warning_codes = sorted(
            {
                node.args[0].value
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add"
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "warnings"
                and node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
            }
        )
        print(
            json.dumps(
                {
                    "diagnostics": network_report._DIAGNOSTICS,
                    "patterns": sorted(network_report._TITLES),
                    "facts": network_report._FACT_FIELDS,
                    "warnings": warning_codes,
                },
                sort_keys=True,
            )
        )
    else:
        print(json.dumps(scenarios(), sort_keys=True, indent=2))
