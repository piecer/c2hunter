"""Emit actual API response bytes, not a hand-written browser run."""
import json
import sys
import tempfile
from pathlib import Path

root = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(root / p) for p in ("controller/tests", "analysis/tests", "controller/src", "analysis/src", "sensor/worker/src")]
from test_network_numeric_lifecycle import numeric_fixture

with tempfile.TemporaryDirectory(prefix="numeric-fixture-") as directory:
    f = numeric_fixture(Path(directory))
    from copy import deepcopy
    from c2hunter_controller.network_numeric_evidence import EvidenceIdentity, validate_output

    cases = []
    def case(name, mutate, accepted):
        run = deepcopy(f["run"])
        mutate(run)
        try:
            _, envelope = validate_output(run["network_interpretation"], run["network_input"], EvidenceIdentity.from_run(run))
            valid = True
            run["network_numeric_evidence"] = envelope
        except (ValueError, TypeError, KeyError):
            valid = False
        assert valid == accepted, name
        cases.append({"name": name, "accepted": accepted, "raw": json.dumps(run, ensure_ascii=True, separators=(",", ":"))})

    ref = f["run"]["network_interpretation"]["summary_numeric_refs"][0]
    def selected(run, value):
        run["network_interpretation"]["summary_numeric_refs"] = [value]
    allowed = {"observed_rtt_ms": {"count", "min", "max", "mean"}, "interarrival_variation_ms": {"count", "min", "max", "mean", "stddev"}, "ttl_observed": {"count", "min", "max", "changes", "missing"}, "rtt_sources": {"syn_ack", "data_ack"}, "rtt_excluded": {"ambiguous", "nonpositive_time", "nonexact_ack"}}
    for metric in allowed:
        for direction in (None, "a_to_b", "b_to_a"):
            for statistic in ("count", "min", "max", "mean", "stddev", "changes", "missing", "syn_ack", "data_ack", "ambiguous", "nonpositive_time", "nonexact_ack"):
                valid = statistic in allowed[metric] and (direction is not None if metric in ("interarrival_variation_ms", "ttl_observed") else direction is None)
                if metric == "interarrival_variation_ms" and direction == "b_to_a" and statistic != "count": valid = False
                case(f"{metric}-{direction}-{statistic}", lambda r, m=metric, d=direction, s=statistic: selected(r, {**ref, "metric": m, "direction": d, "statistic": s}), valid)
    for text, name, valid in (("한" * 1200, "bmp-limit", True), ("한" * 1201, "bmp-over", False), ("😀" * 1200, "scalar-limit", True), ("😀" * 1201, "scalar-over", False), ("\ud800", "unpaired-high", False), ("\udfff", "unpaired-low", False), ('a\n\t\\"😀', "escaped", True)):
        case(name, lambda r, t=text: r["network_interpretation"].update(summary=t), valid)
    for field in ("event_count", "affected_flow_count", "affected_host_count"):
        case("max63-" + field, lambda r, k=field: (r["network_input"]["issues"][0].update({k: "9223372036854775807"}), selected(r, {"kind": "issue_count", "issue_id": ref["issue_id"], "field": k})), True)
    from c2hunter_controller.network_ai import canonical_network_input
    for target in (23999, 24000, 24001):
        source = deepcopy(f["run"]["network_input"])
        source.update(warnings=[""] * 4, limitations=[""] * 4)
        base = len(canonical_network_input(source).encode())
        escaped, remainder = divmod(target - base, 6)
        padding = "\x00" * escaped + "x" * remainder
        assert len(padding) <= 3200
        chunks = [padding[i * 400:(i + 1) * 400] for i in range(8)]
        source.update(warnings=chunks[:4], limitations=chunks[4:])
        assert len(canonical_network_input(source).encode()) == target
        case("input-bytes-" + str(target), lambda r, b=source: r.update(network_input=b), target <= 24000)
    for number in (-0.0, 0.00001, 1e16, 1.7976931348623157e308):
        case("float-repr-" + repr(number), lambda r, n=number: r["network_input"]["issues"][0]["observed_measurements"][0]["measurements"]["observed_rtt_ms"].update(min=n, max=n, mean=n), True)
    case("input-escaped-byte-overflow", lambda r: r["network_input"].update(warnings=["\x00" * 400] * 4, limitations=["\x00" * 400] * 4), False)
    for n in ("0", "0.0", "0e0", "-0"):
        run = deepcopy(f["run"])
        raw = json.dumps(run, separators=(",", ":")).replace('"example_index":0', '"example_index":' + n)
        parsed = json.loads(raw)
        validate_output(parsed["network_interpretation"], parsed["network_input"], EvidenceIdentity.from_run(parsed))
        cases.append({"name": "selector-" + n, "accepted": True, "raw": raw})
    import subprocess
    maximum_report = json.loads(subprocess.check_output([sys.executable, str(root / "web/tests/network_report_fixture.py"), "--maximum"]))["many"]
    maximum_dir = Path(directory) / "maximum"
    maximum_dir.mkdir()
    maximum = numeric_fixture(maximum_dir, report_override=maximum_report, maximum=True)
    import hashlib
    import c2hunter_controller.network_ai as source_input
    import c2hunter_controller.network_numeric_evidence as source_evidence
    import c2hunter_controller.ai_gateway as source_gateway
    import c2hunter_controller.ai_analysis as source_service
    import c2hunter_analysis.network_report as source_report
    origins = {}
    for module in (source_input, source_evidence, source_gateway, source_service, source_report):
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(root), path
        origins[module.__name__] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
    print('{"provenance":' + json.dumps({"origins": origins, "prefix": sys.prefix}) + ',"report":' + json.dumps(f["report"]) + ',"job":' + json.dumps(f["job"]) + ',"run":' + f["raw"] + ',"cases":' + json.dumps(cases) + ',"maximum":{"report":' + json.dumps(maximum["report"]) + ',"job":' + json.dumps(maximum["job"]) + ',"run":' + maximum["raw"] + '}}')
