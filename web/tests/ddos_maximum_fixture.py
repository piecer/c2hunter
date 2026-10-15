"""Produce the real 100-finding report for the Web DOM resource regression."""

import contextlib
import io
import json
import runpy
from pathlib import Path

from c2hunter_analysis.ddos_attack import analyze_ddos_attack

with contextlib.redirect_stdout(io.StringIO()):
    fixture = runpy.run_path(str(Path(__file__).with_name("ddos_report_fixture.py")))
records = [
    dict(row, destination_ip=f"10.0.1.{target}")
    for target in range(1, 101)
    for row in fixture["records"]
]
report = analyze_ddos_attack(
    records,
    parameters={
        "ddos_min_duration_seconds": 2,
        "ddos_min_source_count": 20,
        "ddos_min_packet_count": 1000,
        "ddos_min_packets_per_second": 10,
        "ddos_min_bits_per_second": 1_000_000_000,
    },
)
assert len(report["findings"]) == 100
print(json.dumps(report, sort_keys=True, separators=(",", ":")))
