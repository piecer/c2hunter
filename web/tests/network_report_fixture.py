"""Emit real parser → network report scenarios for frontend parity tests.

Run from the repository: .venv/bin/python web/tests/network_report_fixture.py
No generated timestamps, random values, network, or controller state.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'analysis/src'), str(ROOT / 'analysis/tests')]
from test_network_anomaly import frame, records
from c2hunter_analysis.network_report import analyze_network_report


def scenarios():
    data = frame(flags=24, seq=101, payload=b'abc')
    ack = frame(flags=16, seq=500, ack=101, reverse=True)
    udp = frame(protocol=17, payload=b'query')
    # Real parser records with deliberately absent optional metadata model older
    # evidence records; reports themselves always come from the actual analyzer.
    missing_metadata = records(frame(), frame(), frame(flags=18, seq=500, ack=101, reverse=True))
    for record in missing_metadata:
        record.pop('ip_ttl', None)
    import struct
    from ipaddress import IPv6Address
    from test_network_anomaly import internet_checksum

    def ipv6_udp(hop_limit):
        src, dst = IPv6Address('2001:db8::1').packed, IPv6Address('2001:db8::2').packed
        payload = b'query'
        udp6 = struct.pack('!HHHH', 50000, 443, 8 + len(payload), 0) + payload
        pseudo = src + dst + struct.pack('!I3xB', len(udp6), 17)
        checksum = internet_checksum(pseudo + udp6)
        udp6 = udp6[:6] + struct.pack('!H', checksum or 65535) + udp6[8:]
        ip6 = struct.pack('!IHBB16s16s', 6 << 28, len(udp6), 17, hop_limit, src, dst)
        return bytes.fromhex('00112233445566778899aabb86dd') + ip6 + udp6

    return {
        'supporting': analyze_network_report(records(frame(), frame(flags=18, seq=500, ack=101, reverse=True), data, frame(flags=16, seq=501, ack=104, reverse=True), frame(flags=24, seq=104, payload=b'def'), frame(flags=24, seq=104, payload=b'def'), frame(flags=16, seq=501, ack=107, reverse=True))),
        'ambiguous_rtt': analyze_network_report(records(data, data, frame(flags=16, seq=500, ack=104, reverse=True))),
        'missing_metadata': analyze_network_report(missing_metadata),
        'ipv6_hop_limit': analyze_network_report(records(ipv6_udp(64), ipv6_udp(63), ipv6_udp(0))),
        'normal': analyze_network_report(records(frame(), frame(flags=18, seq=500, ack=101, reverse=True))),
        'syn_reset': analyze_network_report(records(frame(), frame(), frame(flags=20, ack=101, reverse=True))),
        'data_ack': analyze_network_report(records(data, data, ack, ack)),
        'udp': analyze_network_report(records(udp, udp)),
        'icmp': analyze_network_report(records(udp, frame(protocol=1, reverse=True, payload=udp[14:42]))),
        'missing': analyze_network_report([]),
        'incomplete': analyze_network_report([{'packet_count': 10}]),
    }


if __name__ == '__main__':
    if '--legacy' in sys.argv or '--legacy-limited' in sys.argv:
        from c2hunter_analysis.network_anomaly import analyze_network_anomalies
        packets = (
            [frame(protocol=17, payload=str(index).encode()) for index in range(257)]
            if '--legacy-limited' in sys.argv else [frame(), frame()]
        )
        print(json.dumps(analyze_network_anomalies(records(*packets)), sort_keys=True))
    elif '--contract' in sys.argv:
        import ast
        from c2hunter_analysis import network_report
        tree = ast.parse(Path(network_report.__file__).read_text())
        warning_codes = sorted({
            node.args[0].value for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == 'add' and isinstance(node.func.value, ast.Name)
            and node.func.value.id == 'warnings' and node.args
            and isinstance(node.args[0], ast.Constant)
            and isinstance(node.args[0].value, str)
        })
        print(json.dumps({'diagnostics': network_report._DIAGNOSTICS,
                          'patterns': sorted(network_report._TITLES),
                          'facts': network_report._FACT_FIELDS,
                          'warnings': warning_codes}, sort_keys=True))
    else:
        print(json.dumps(scenarios(), sort_keys=True, indent=2))
