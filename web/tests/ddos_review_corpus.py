"""Exact producer bytes for reviewer-reproduced v4 regressions."""

import contextlib
import copy
import io
import json
import runpy
from pathlib import Path
from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from c2hunter_analysis.ddos_signatures import EvidenceSample, digest

ROOT = Path(__file__).resolve().parents[2]


def build():
    t = runpy.run_path(str(ROOT / "analysis/tests/test_ddos_attack.py"))
    rows = t["distributed_tcp"]({"syn": 1, "ack": 0, "rst": 0, "fin": 0})
    parameters = t["PARAMETERS"]
    cases = []

    def add(name, report, expected=True):
        # Exact JSON bytes are used for all consumers.
        report = json.loads(json.dumps(report, default=str))
        out = {"name": name, "expected": expected, "report": report}
        cases.append(out)

    base = analyze_ddos_attack(rows, parameters=parameters)
    add("packet-positive", base)
    # A second real producer report has a different target, then transplant its valid signature.
    foreign = analyze_ddos_attack(
        t["distributed_tcp"](
            {"syn": 1, "ack": 0, "rst": 0, "fin": 0}, target="10.0.0.20"
        ),
        parameters=parameters,
    )
    add("foreign-positive", foreign)
    bad = copy.deepcopy(base)
    bad["findings"][0]["signature_candidates"] = copy.deepcopy(
        foreign["findings"][0]["signature_candidates"]
    )
    add("foreign-finding-target", bad, False)
    # Preserve valid standalone candidate, but make target direction foreign.
    bad = copy.deepcopy(base)
    sig = bad["findings"][0]["signature_candidates"][0]
    sig["evaluation"]["predicate"]["direction"] = "OUTBOUND"
    sig["id"] = "ddos-sig-" + digest(sig["evaluation"]["predicate"])[:16]
    add("rehashed-foreign-direction", bad, False)
    # Actual second protocol/port finding, same target.
    udp = [
        t["record"](
            second,
            f"198.51.100.{source}",
            protocol="UDP",
            destination_port=53,
            packet_count=10,
            size=1000,
        )
        for second in range(25)
        for source in range(1, 5)
    ]
    udpreport = analyze_ddos_attack(udp, parameters=parameters)
    add("aggregate-udp-positive", udpreport)
    bad = copy.deepcopy(base)
    bad["findings"][0]["signature_candidates"] = copy.deepcopy(
        udpreport["findings"][0]["signature_candidates"]
    )
    add("foreign-finding-protocol-port", bad, False)
    # Matched all records but only some of their packets: impossible conjunction result.
    bad = copy.deepcopy(udpreport)
    counts = bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
    counts["matched_packets"] -= 1
    counts["packet_match_rate"] = counts["matched_packets"] / counts["eligible_packets"]
    add("all-records-some-packets", bad, False)
    # Real mixed target/control records: exactly half are matching.
    mixed = analyze_ddos_attack(
        rows
        + t["distributed_tcp"](
            {"syn": 1, "ack": 0, "rst": 0, "fin": 0}, target="10.0.0.20"
        ),
        parameters=parameters,
    )
    add("mixed-target-positive", mixed)
    bad = copy.deepcopy(mixed)
    counts = bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
    counts["matched_packets"] = counts["eligible_packets"]
    counts["packet_match_rate"] = 1.0
    add("some-records-all-packets", bad, False)
    # Duplicate integer evidence index spelled differently.
    bad = copy.deepcopy(base)
    counts = bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
    first = counts["evidence_refs"][0]
    idx, hash_ = first.split(":")
    counts["evidence_refs"][1] = "0" + idx + ":" + hash_
    add("duplicate-reference-index-leading-zero", bad, False)
    # Publication must not admit arbitrary internally coherent sample counts unrelated to summary.
    bad = copy.deepcopy(base)
    counts = bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
    counts["omitted_records"] = 1000000
    add("attack-observed-count-over-summary", bad, False)
    # Selected reference with no eligible records retains null, not false-positive 0.
    sample = EvidenceSample()
    for row in rows:
        sample.add(dict(row, tcp_flags=None, tcp_flags_observed=False))
    snapshot = {
        "version": "ddos-normal-reference-v1",
        "records": sample.records,
        "reference": {
            "job_id": "normal",
            "dataset_id": "normal-dataset",
            "content_digest": digest(sample.records),
            "record_count": len(sample.records),
            "selected_by": "reviewer",
            "selected_at": "2026-10-15T00:00:00Z",
            "coverage_limited": True,
        },
    }
    normal = analyze_ddos_attack(rows, parameters=parameters, normal_reference=snapshot)
    assert (
        normal["findings"][0]["signature_candidates"][0]["evaluation"]["normal"][
            "result"
        ]["record_match_rate"]
        is None
    )
    add("all-unknown-normal-positive", normal)
    # Independent zero/false/null matrix at the new count/boolean surface.
    for field in [
        "matched_records",
        "eligible_records",
        "unknown_records",
        "matched_packets",
        "eligible_packets",
        "unknown_packets",
        "sampled_records",
        "omitted_records",
        "sample_bytes",
        "record_limit",
        "byte_limit",
    ]:
        for value in [False, None]:
            bad = copy.deepcopy(base)
            bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"][
                field
            ] = value
            add(f"type/{field}/{value}", bad, False)
    # Explicit genuinely observed zero is a valid match rate, not missing evidence.
    normal_sample = EvidenceSample()
    for row in rows:
        normal_sample.add(dict(row, destination_port=80))
    snapshot["records"] = normal_sample.records
    snapshot["reference"]["content_digest"] = digest(normal_sample.records)
    zero = analyze_ddos_attack(rows, parameters=parameters, normal_reference=snapshot)
    assert (
        zero["findings"][0]["signature_candidates"][0]["evaluation"]["normal"][
            "result"
        ]["record_match_rate"]
        == 0
    )
    add("measured-zero-normal-positive", zero)
    for name, field, value in [
        ("global-sample-digest", "evidence_digest", "f" * 64),
        ("global-sample-bytes", "sample_bytes", 12345),
    ]:
        bad = copy.deepcopy(mixed)
        bad["findings"][-1]["signature_candidates"][0]["evaluation"]["attack"][
            field
        ] = value
        add(name, bad, False)
    bad = copy.deepcopy(base)
    refs = bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"][
        "evidence_refs"
    ]
    refs[1] = "0" + refs[1]
    add("noncanonical-distinct-index", bad, False)
    for value in [None, {}, {"arbitrary": "private"}]:
        bad = copy.deepcopy(normal)
        bad["normal_reference"] = value
        add("report-reference/" + str(value), bad, False)
    bad = copy.deepcopy(base)
    del bad["normal_reference"]
    add("missing-report-reference", bad, False)
    with contextlib.redirect_stdout(io.StringIO()):
        scenarios = runpy.run_path(str(ROOT / "web/tests/ddos_report_scenarios.py"))[
            "scenarios"
        ]
        old_corpus = runpy.run_path(str(ROOT / "web/tests/ddos_correction_corpus.py"))[
            "corpus"
        ]
    multi = scenarios["multi_vector"]
    assert any(f["attack_type"] == "MULTI_VECTOR" for f in multi["findings"])
    add("multi-vector-component-positive", multi)
    spoof = next(c["report"] for c in old_corpus if c["name"] == "producer/multicast")
    assert any(
        s["kind"] == "SPOOFING_HEURISTIC"
        for f in spoof["findings"]
        for s in f["signature_candidates"]
    )
    add("spoofing-heuristic-positive", spoof)
    for delta in (-1, 1):
        bad = copy.deepcopy(udpreport)
        counters = bad["findings"][0]["signature_candidates"][0]["evaluation"]["attack"]
        counters["eligible_packets"] += delta
        counters["matched_packets"] += delta
        add(f"sample-packets-versus-summary/{delta}", bad, False)
    zero_report = analyze_ddos_attack(
        [], parameters=parameters, normal_reference=snapshot
    )
    add("zero-findings-reference-positive", zero_report)
    for count in (0, 513):
        bad = copy.deepcopy(zero_report)
        bad["normal_reference"]["record_count"] = count
        add(f"zero-findings-reference-count/{count}", bad, False)
    return cases


if __name__ == "__main__":
    print(json.dumps(build(), sort_keys=True, separators=(",", ":")))
