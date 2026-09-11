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
    return {
        'normal': analyze_network_report(records(frame(), frame(flags=18, seq=500, ack=101, reverse=True))),
        'syn_reset': analyze_network_report(records(frame(), frame(), frame(flags=20, ack=101, reverse=True))),
        'data_ack': analyze_network_report(records(data, data, ack, ack)),
        'udp': analyze_network_report(records(udp, udp)),
        'icmp': analyze_network_report(records(udp, frame(protocol=1, reverse=True, payload=udp[14:42]))),
        'missing': analyze_network_report([]),
        'incomplete': analyze_network_report([{'packet_count': 10}]),
    }


if __name__ == '__main__':
    print(json.dumps(scenarios(), sort_keys=True, indent=2))
