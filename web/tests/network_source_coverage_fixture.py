"""Real native parser -> worker -> AI witnesses; no model or capture process."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT / p)
    for p in ("analysis/src", "analysis/tests", "controller/src", "sensor/worker/src")
]


def witnesses():
    from test_network_anomaly import frame, records

    from c2hunter_analysis.network_coverage import attach_network_coverage_context
    from c2hunter_controller.network_ai import build_network_input
    from c2hunter_worker.analysis import execute_analysis

    rows = list(
        records(
            frame(),
            frame(flags=18, seq=500, ack=101, reverse=True),
            frame(flags=16, seq=101, ack=501),
            frame(flags=24, seq=101, ack=501, payload=b"abc"),
            frame(flags=24, seq=101, ack=501, payload=b"abc"),
        )
    )
    base = {"analysis": {"module": "network_anomaly"}, "flow_records": rows}
    # Unknown quality is inherited rather than rewritten as observed-clean.
    attach_network_coverage_context(base)
    qualified = {
        **base,
        "source": {
            "captured_packet_count": 6,
            "parsed_packet_count": 5,
            "skipped_packet_count": 1,
        },
        "capture_quality": {"dropped_packet_count": 2, "clock_skew_detected": True},
        "capture_limit": {"discarded_packets": 1},
        "capture_incomplete": True,
    }
    output = {}
    for name, job in {
        "positive_partial": qualified,
        "quiet_partial": {**qualified, "flow_records": rows[:3]},
        "normal": {
            "analysis": {"module": "network_anomaly"},
            "flow_records": rows[:3],
            "source": {
                "captured_packet_count": 3,
                "parsed_packet_count": 3,
                "skipped_packet_count": 0,
            },
        },
    }.items():
        report = execute_analysis(job)["network_anomaly"]
        ai = build_network_input(report, "en")
        assert len(json.dumps(ai, ensure_ascii=False).encode()) <= 24000
        assert ai["warnings"] == report["warnings"]
        output[name] = {"report": report, "ai": ai}
    origins = {
        name: str(Path(module.__file__).resolve())
        for name, module in list(sys.modules.items())
        if name.startswith(
            ("c2hunter_analysis", "c2hunter_controller", "c2hunter_worker")
        )
        and getattr(module, "__file__", None)
    }
    assert all(Path(path).is_relative_to(ROOT) for path in origins.values())
    return {"cases": output, "origins": origins}


if __name__ == "__main__":
    print(json.dumps(witnesses(), sort_keys=True, ensure_ascii=False))
