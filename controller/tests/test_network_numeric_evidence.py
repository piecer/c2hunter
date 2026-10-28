"""Closed v2 sources, semantic references, and byte-budget regression corpus."""

import json
from copy import deepcopy

import pytest
from test_network_input_budget import rich_report

from c2hunter_controller.network_ai import build_network_input_v2, canonical_network_input
from c2hunter_controller.network_numeric_evidence import (
    EvidenceIdentity,
    NetworkInterpretationV2,
    validate_input,
    validate_output,
)

IDENTITY = EvidenceIdentity("run", "job", None)


def output(bundle, refs=None):
    return {
        "schema_version": "network-interpretation-v2",
        "kind": "MODEL_INTERPRETATION",
        "language": bundle["language"],
        "summary": "1100 ms is unverified prose",
        "summary_numeric_refs": refs or [],
        "possible_causes": [],
        "prioritized_checks": [],
        "correlations": [],
        "limitations": ["Unknown baseline"],
    }


def reference(bundle, **changes):
    return {
        "kind": "measurement",
        "issue_id": bundle["issues"][0]["id"],
        "example_index": 0,
        "metric": "observed_rtt_ms",
        "direction": None,
        "statistic": "mean",
        **changes,
    }


@pytest.fixture
def bundle(monkeypatch):
    return build_network_input_v2(rich_report(monkeypatch, peers=1), "en")


@pytest.mark.parametrize("value", [True, "0", 0.5, 2, -1, None, float("nan"), float("inf")])
def test_invalid_selector_is_numeric_diagnostic(bundle, value):
    from c2hunter_controller.network_ai import NetworkSemanticError

    with pytest.raises(NetworkSemanticError) as error:
        validate_output(output(bundle, [reference(bundle, example_index=value)]), bundle, IDENTITY)
    assert error.value.category == "INVALID_NUMERIC_REFERENCE"


@pytest.mark.parametrize("target", ["evidence", "issue_cause", "summary_cause"])
def test_unpaired_surrogate_in_clipped_bounded_candidate_rejected(monkeypatch, target):
    report = rich_report(monkeypatch, peers=1)
    text = "a" * 401 + "\ud800"
    if target == "evidence":
        report["issues"][0]["evidence"] = [text]
    elif target == "issue_cause":
        report["issues"][0]["suspected_cause"]["summary"] = text
    else:
        report["summary"]["suspected_cause"]["summary"] = text
    with pytest.raises(ValueError):
        build_network_input_v2(report)


def test_public_qualifier_schema_is_closed():
    schema = NetworkInterpretationV2.model_json_schema()
    assert schema["additionalProperties"] is False
    from c2hunter_controller.network_numeric_evidence import NumericEvidence

    definitions = NumericEvidence.model_json_schema()["$defs"]
    qualifiers = definitions["Qualifiers"]["properties"]
    for key in ("rtt_sources", "rtt_excluded"):
        assert "$ref" in qualifiers[key]["anyOf"][0]


@pytest.mark.parametrize("token", ["0", "0.0", "0e0", "-0"])
def test_decoded_selector_values(bundle, token):
    raw = json.dumps(output(bundle, [reference(bundle)])).replace(
        '"example_index": 0', '"example_index": ' + token
    )
    result, evidence = validate_output(json.loads(raw), bundle, IDENTITY)
    assert result.summary_numeric_refs[0].example_index == 0
    assert evidence["items"][0]["value"] == "100.0"


@pytest.mark.parametrize(
    "changes",
    [
        {"value": "999"},
        {"unit": "ms"},
        {"direction": "a_to_b"},
        {"statistic": "missing"},
        {"metric": "rtt_sources", "statistic": "mean"},
        {"metric": "ttl_observed", "direction": None},
        {"issue_id": "unknown"},
        {"example_index": 1},
        {"statistic": "stddev"},
    ],
)
def test_bad_reference_never_publishes(bundle, changes):
    with pytest.raises(ValueError):
        validate_output(output(bundle, [reference(bundle, **changes)]), bundle, IDENTITY)


def test_duplicate_semantics_and_owner_issue_ids(bundle):
    ref = reference(bundle)
    with pytest.raises(ValueError):
        validate_output(output(bundle, [ref, {**ref, "example_index": -0.0}]), bundle, IDENTITY)
    out = output(bundle)
    out["prioritized_checks"] = [
        {"priority": "LOW", "check": "Check", "issue_ids": [], "numeric_refs": [ref]}
    ]
    with pytest.raises(ValueError):
        validate_output(out, bundle, IDENTITY)


def test_original_example_ordinal_not_compact_position(monkeypatch):
    report = rich_report(monkeypatch, peers=1)
    original = deepcopy(report["issues"][0]["examples"][0])
    report["issues"][0]["examples"] = [{"facts": {}}, original]
    b = build_network_input_v2(report)
    assert b["issues"][0]["observed_measurements"][0]["example_index"] == 1
    _, e = validate_output(output(b, [reference(b, example_index=1.0)]), b, IDENTITY)
    assert e["items"][0]["value"] == "100.0"
    with pytest.raises(ValueError):
        validate_output(output(b, [reference(b)]), b, IDENTITY)


@pytest.mark.parametrize("field", ["event_count", "affected_flow_count", "affected_host_count"])
def test_exact_63bit_source_strings(bundle, field):
    b = deepcopy(bundle)
    b["issues"][0][field] = "9223372036854775807"
    ref = {"kind": "issue_count", "issue_id": b["issues"][0]["id"], "field": field}
    _, e = validate_output(output(b, [ref]), b, IDENTITY)
    assert e["items"][0]["value"] == "9223372036854775807"
    assert e["items"][0]["qualifiers"]["measurement_status"] is None


@pytest.mark.parametrize("bad", ["00", "01", "-0", "1.0", "9223372036854775808", 1, True])
def test_source_strings_closed(bundle, bad):
    bundle["issues"][0]["event_count"] = bad
    with pytest.raises(ValueError):
        validate_input(bundle)


def test_null_zero_quality_and_sample_qualifiers(bundle):
    refs = [
        reference(bundle, metric="rtt_excluded", statistic="nonpositive_time"),
        reference(bundle, metric="rtt_sources", statistic="syn_ack"),
    ]
    _, e = validate_output(output(bundle, refs), bundle, IDENTITY)
    assert e["items"][0]["value"] == "0"
    q = e["items"][0]["qualifiers"]
    assert q["sample_count"] == "1" and q["quality_status"] == "limited_samples"
    assert "HANDSHAKE_ONLY" in q["quality_reasons"]
    b = deepcopy(bundle)
    del b["issues"][0]["observed_measurements"][0]["measurements"]["metric_quality"]
    assert (
        validate_output(output(b, refs), b, IDENTITY)[1]["items"][0]["qualifiers"]["quality_status"]
        == "not_provided"
    )
    b["issues"][0]["observed_measurements"][0]["measurements"]["metric_quality"] = None
    with pytest.raises(ValueError):
        validate_input(b)


def test_late_invalid_measurement_cannot_hide_behind_budget(monkeypatch):
    report = rich_report(monkeypatch)
    for issue in report["issues"]:
        issue["evidence"] = ["😀" * 400] * 4
    report["issues"][-1]["examples"][0]["measurements"]["rtt_sources"]["syn_ack"] = 9
    with pytest.raises(ValueError):
        build_network_input_v2(report)


def test_actual_input_24000_boundary(monkeypatch):
    from test_network_input_budget import MINIMUM

    report = rich_report(monkeypatch)
    del report["summary"]["suspected_cause"]
    report["issues"] = [{k: i[k] for k in MINIMUM} for i in report["issues"]]
    report["warnings"] = [""] * 4
    report["limitations"] = [""] * 4
    base = len(canonical_network_input(build_network_input_v2(report)).encode())
    escaped, remainder = divmod(24000 - base, 6)
    text = "\x00" * escaped + "x" * remainder
    chunks = [text[i * 400 : (i + 1) * 400] for i in range(8)]
    report["warnings"], report["limitations"] = chunks[:4], chunks[4:]
    assert len(canonical_network_input(build_network_input_v2(report)).encode()) == 24000
    report["limitations"][-1] += "x"
    with pytest.raises(ValueError):
        build_network_input_v2(report)
    report["limitations"][-1] = report["limitations"][-1][:-1]
    report["warnings"][0] = report["warnings"][0].replace("\x00", "\t", 1)
    report["limitations"][-1] += "xxx"
    assert len(canonical_network_input(build_network_input_v2(report)).encode()) == 23999


def test_full_envelope_actual_identifier_exact_boundary(bundle):
    from c2hunter_controller.network_numeric_evidence import envelope

    size = len(canonical_network_input(envelope(bundle, IDENTITY, [])).encode())
    exact = EvidenceIdentity("run" + "x" * (32768 - size), "job", None)
    assert len(canonical_network_input(envelope(bundle, exact, [])).encode()) == 32768
    with pytest.raises(ValueError):
        envelope(bundle, EvidenceIdentity(exact.run_id + "x", "job", None), [])
    assert (
        len(
            canonical_network_input(
                envelope(bundle, EvidenceIdentity(exact.run_id[:-1], "job", None), [])
            ).encode()
        )
        == 32767
    )
