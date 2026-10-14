"""Producer-generated shared JSON cases; tests compare frozen bytes, never regenerate."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import sys

from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from c2hunter_analysis.ddos_evidence import COUNTERS, assess
from c2hunter_controller.app import _validated_ddos_report
from c2hunter_controller.schemas import AnalysisParameters, FlowRecord

C = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(C / "analysis/tests"))
packet_cases = importlib.import_module("test_ddos_stage1")
packet_rows, PARAMETERS = packet_cases.packet_rows, packet_cases.PARAMETERS

corpus = []


def add(name, report):
    expected = (
        not name.startswith("mutation/")
        or name == "mutation/ordinary-udp-with-reflector-label"
    )
    reason = None
    if name in {
        "mutation/reflection-with-zero-observed-responses",
        "mutation/reflection-all-responses-matched",
    }:
        reason = "DDoS reflection requires unmatched response samples"
    if name == "mutation/nonmulti-component-count":
        reason = "DDoS axis evidence disagrees with finding metrics"
    corpus.append(
        {
            "name": name,
            "report": json.loads(json.dumps(report)),
            "accepted": expected,
            "reason": reason,
        }
    )


base = analyze_ddos_attack(packet_rows(), parameters=PARAMETERS)
add("producer/coordinated", base)
for name, rows in [
    (
        "missing",
        [
            {k: v for k, v in r.items() if k != "ddos_packet_evidence"}
            for r in packet_rows()
        ],
    ),
    ("null", [dict(r, ddos_packet_evidence=None) for r in packet_rows()]),
    (
        "mixed",
        [
            dict(r, ddos_packet_evidence=None) if i == 0 else r
            for i, r in enumerate(packet_rows())
        ],
    ),
    ("omitted", packet_rows(count=33)),
    ("multicast", packet_rows(multicast=True)),
    ("uncoordinated", packet_rows(distinct_payload=True)),
]:
    r = analyze_ddos_attack(rows, parameters=PARAMETERS)
    add("producer/" + name, r)
    add("serializer/" + name, _validated_ddos_report(r))
for field in ["classification", "common_patterns", "signature_candidates"]:
    for action in ["absent", "null"]:
        r = copy.deepcopy(base)
        if action == "absent":
            del r["findings"][0][field]
        else:
            r["findings"][0][field] = None
        add("mutation/" + field + "/" + action, r)
for field in ["evidence", "axes"]:
    for action in ["absent", "null"]:
        r = copy.deepcopy(base)
        if action == "absent":
            del r["findings"][0]["classification"][field]
        else:
            r["findings"][0]["classification"][field] = None
        add("mutation/" + field + "/" + action, r)
for field in sorted(COUNTERS):
    for label, value in [
        ("bool", True),
        ("null", None),
        ("string", "1"),
        ("fraction", 1.5),
        ("negative", -1),
        ("unsafe", 2**53),
    ]:
        r = copy.deepcopy(base)
        r["findings"][0]["classification"]["evidence"][field] = value
        add("mutation/" + field + "/" + label, r)
for axis in ["delivery_mechanism", "source_population", "source_authenticity"]:
    for codes in ["supporting_codes", "counter_codes", "unknown_codes"]:
        for value in [["FUTURE"], [None], [1], None]:
            r = copy.deepcopy(base)
            r["findings"][0]["classification"]["axes"][axis][codes] = value
            add("mutation/" + axis + "/" + codes + "/" + str(value), r)
r = copy.deepcopy(base)
f = r["findings"][0]
f["classification"]["evidence"]["component_count"] = 1
f["classification"] = assess(f["classification"]["evidence"])
f["uncertainty_codes"].remove("BOTNET_ATTRIBUTION_UNCONFIRMED")
add("mutation/nonmulti-component-count", r)
reflection = analyze_ddos_attack(
    packet_rows(bytes.fromhex("12348180000100010000000001610000010001"), 53),
    parameters=PARAMETERS,
)
add("producer/reflection", reflection)
r = copy.deepcopy(reflection)
f = r["findings"][0]
e = f["classification"]["evidence"]
e["unobserved_packets"] = e["sample_count"]
e["sample_count"] = 0
e["response_samples"] = 0
f["classification"] = assess(e)
add("mutation/reflection-with-zero-observed-responses", r)
# Test a wire-equivalent contradiction, preserving original IDs/metrics/signature references.
r = copy.deepcopy(base)
f = r["findings"][0]
e = f["classification"]["evidence"]
e.update(
    response_samples=9,
    direct_samples=0,
    coordinated_sources=0,
    eligible_sources=0,
    shared_buckets=0,
)
f["classification"] = assess(e)
f["uncertainty_codes"].remove("BOTNET_ATTRIBUTION_UNCONFIRMED")
add("mutation/ordinary-udp-with-reflector-label", r)
for suffix in ["contract", "scenarios"]:
    p = C / f"web/tests/fixtures/ddos-report-{suffix}-v2.json"
    wire = p.read_bytes()
    values = json.loads(wire)
    values = {suffix: values} if suffix == "contract" else values
    for name, r in values.items():
        add("legacy/" + name, r)
        assert _validated_ddos_report(r)["version"] == "ddos-attack-report-v2"

spec = importlib.util.spec_from_file_location(
    "correction_worker", C / "sensor/worker/src/c2hunter_worker/analysis.py"
)
assert spec is not None and spec.loader is not None
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
for fixture in [
    "ddos-live-dns_response.json",
    "ddos-live-ntp_response.json",
    "ddos-pcap-coordination.json",
]:
    data = json.loads((C / "analysis/tests/fixtures" / fixture).read_text())
    rows = data["flows"] if isinstance(data, dict) else data
    rows = [FlowRecord.model_validate(row).model_dump(mode="json") for row in rows]
    job = {
        "id": fixture,
        "dataset_id": "correction-corpus",
        "start_time": "2026-07-20T00:00:00+00:00",
        "end_time": "2026-07-21T00:00:00+00:00",
        "sensor_ids": ["fixture"],
        "flow_records": rows,
        "analysis": AnalysisParameters(module="ddos_attack", **PARAMETERS).model_dump(
            mode="json"
        ),
        "internal_networks": ["10.0.0.0/8"],
        "status": "QUEUED",
    }
    add(
        "sqlite-worker/" + fixture,
        _validated_ddos_report(worker.execute_analysis(job)["ddos_attack"]),
    )
add(
    "producer/many-targets",
    analyze_ddos_attack(
        [row for i in range(25) for row in packet_rows(target=f"10.0.1.{i + 1}")],
        parameters=PARAMETERS,
    ),
)
r = copy.deepcopy(reflection)
e = r["findings"][0]["classification"]["evidence"]
e["matched_response_samples"] = e["response_samples"]
r["findings"][0]["classification"] = assess(e)
add("mutation/reflection-all-responses-matched", r)
rows = json.loads(
    (C / "analysis/tests/fixtures/ddos-live-reverse-requests.json").read_text()
)["1000"]["flows"]
add("producer/reverse-request-loss", analyze_ddos_attack(rows))

if __name__ == "__main__":
    print(json.dumps(corpus, sort_keys=True, separators=(",", ":")))
