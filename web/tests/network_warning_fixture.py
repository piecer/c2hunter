"""Real parser/producer witness for all nine original coverage warnings.

Budgets are reduced; absent metadata and a clock discontinuity are deliberate.
This is not a live capture or a production-size stress test.
"""

import json
import sys
from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "analysis/src"), str(ROOT / "analysis/tests")]
from test_network_anomaly import frame, records
from c2hunter_analysis.network_report import analyze_network_report


def warning_report():
    packets = list(records(frame(), frame(), frame(protocol=1, reverse=True, payload=frame()[14:42])))
    second = records(frame(protocol=1, reverse=True, payload=frame(protocol=17, payload=b"x")[14:42]))[0]
    second["sensor_id"] = "quote2"
    packets.append(second)
    bad = records(frame(protocol=1, reverse=True, payload=frame()[14:42]))[0]
    bad["sensor_id"] = "badquote"
    bad["icmp_quoted_flow"]["protocol"] = "BAD"
    packets.append(bad)
    incomplete = records(frame())[0]
    incomplete["sensor_id"] = "incomplete"
    incomplete.pop("tcp_sequence", None)
    packets.append(incomplete)
    clock = records(frame(), frame())
    clock[1]["timestamp"] = clock[0]["timestamp"] - timedelta(seconds=1)
    for packet in clock:
        packet["sensor_id"] = "clock"
    packets.extend(clock)
    correlations = records(frame(protocol=17, payload=b"first"), frame(protocol=17, payload=b"second"))
    for packet in correlations:
        packet["sensor_id"] = "correlation"
    packets.extend(correlations)
    packets.append({})
    for index in range(10):
        packet = records(frame())[0]
        packet["sensor_id"] = f"fill{index}"
        packets.append(packet)
    with patch.multiple(
        "c2hunter_analysis.network_report", MAX_TRACKED_FLOWS=8,
        MAX_FLOW_CORRELATIONS=1, MAX_PENDING_QUOTES=1, MAX_FLOW_OBSERVATIONS=1,
    ):
        return analyze_network_report(packets)


if __name__ == "__main__":
    report = warning_report()
    origins = {
        name: module.__file__ for name, module in sys.modules.copy().items()
        if name.startswith("c2hunter_") and getattr(module, "__file__", None)
    }
    assert origins
    assert all(Path(path).is_relative_to(ROOT) for path in origins.values()), origins
    print(json.dumps({"report": report, "origins": origins}, default=str))
