"""Actual parser-backed ICMP detail boundaries and owner conservation."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "web/tests"))
from network_icmp_fixture import numeric_wire_corpus, packets, records, router_error  # noqa: E402

from c2hunter_analysis import network_icmp_details as details  # noqa: E402
from c2hunter_analysis import network_report as report  # noqa: E402


def example(value):
    return next(i for i in value["issues"] if i["pattern"] == "icmp_errors")["examples"][0]


def test_integer_value_original_code_wire():
    from network_icmp_fixture import numeric_wire_corpus

    case = numeric_wire_corpus(report.analyze_network_report(records()))[0]
    assert '"code":1.0' in case["wire"]
    value = json.loads(case["wire"])
    assert details.validate_details(value["icmp_details"], value["event_count"]) is True


@pytest.mark.parametrize(
    "case", numeric_wire_corpus(report.analyze_network_report(records())), ids=lambda c: c["name"]
)
def test_integer_value_paired_wire_corpus(case):
    wire = case["wire"]
    value = json.loads(wire)
    before = copy.deepcopy(value)
    assert details.validate_details(value["icmp_details"], value["event_count"]) is case["expected"]
    assert case["python"] is case["expected"]
    assert value == before and case["wire"] == wire


NUMERIC_FIELDS = ("code", "type", "omission", "event_count", "source_port", "destination_port")


def numeric_example(field, value):
    e = example(report.analyze_network_report(records()))
    if field == "event_count":
        e[field] = value
    elif field == "omission":
        e["icmp_details"]["omitted_event_details"] = value
    elif field in {"code", "type"}:
        e["icmp_details"]["samples"][0][field] = value
    else:
        e["icmp_details"]["samples"][0]["quoted_flow"][field] = value
    return e


@pytest.mark.parametrize("field", NUMERIC_FIELDS)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 10**1000])
def test_numeric_nonfinite_and_large_int_reject_without_overflow(field, value):
    e = numeric_example(field, value)
    assert details.validate_details(e["icmp_details"], e["event_count"]) is False


@pytest.mark.parametrize("field", NUMERIC_FIELDS)
@pytest.mark.parametrize("base", [int, float, object])
def test_numeric_custom_types_never_invoke_hooks(field, base):
    calls = []

    class Custom(base):
        def hook(self, *args):
            calls.append(args)
            raise AssertionError("numeric callback invoked")

        __eq__ = __lt__ = __le__ = __gt__ = __ge__ = hook
        __int__ = __float__ = __sub__ = __rsub__ = is_integer = hook

    value = Custom() if base is object else Custom(1)
    e = numeric_example(field, value)
    assert details.validate_details(e["icmp_details"], e["event_count"]) is False
    assert not calls


@pytest.mark.parametrize("field", ["icmp_type", "icmp_code", "source_port", "destination_port"])
def test_integer_value_dto_does_not_relax_source_admission(field):
    row = records()[1]
    if field in {"icmp_type", "icmp_code"}:
        row[field] = float(row[field])
        assert details.sample(row, 1.0) is None
    else:
        row["icmp_quoted_flow"][field] = float(row["icmp_quoted_flow"][field])
        assert details._port(row["icmp_quoted_flow"][field]) is None
        result = details.sample(row, 1.0)
        assert result is not None and result["quoted_flow"][field] is None


def test_actual_producer_metadata_has_closed_python_validator():
    e = example(report.analyze_network_report(records()))
    validator = getattr(details, "validate_details", None)
    assert callable(validator), "producer detail validator is missing"
    assert validator(e["icmp_details"], e["event_count"])
    invalid = copy.deepcopy(e["icmp_details"])
    invalid["samples"][0]["packet_reference"] = {"raw_packet_index": 2}
    assert not validator(invalid, e["event_count"])


@pytest.mark.parametrize("order", ["before", "after", "absent"])
def test_target_order_and_fallback_keep_actual_outer_reporters(order):
    target = packets.frame(protocol=17, payload=b"query")
    errors = [router_error(1, 1), router_error(2, 3)]
    frames = (
        [target] + errors
        if order == "before"
        else errors + [target]
        if order == "after"
        else errors
    )
    result = report.analyze_network_report(records(packets.capture(*frames)))
    issues = [i for i in result["issues"] if i["pattern"] == "icmp_errors"]
    samples = [s for i in issues for e in i["examples"] for s in e["icmp_details"]["samples"]]
    assert {s["reporter_ip"] for s in samples} == {"192.0.2.1", "192.0.2.2"}
    assert sum(i["event_count"] for i in issues) == 2
    assert {i["scope"]["protocol"] for i in issues} == ({"ICMP"} if order == "absent" else {"UDP"})
    assert all(s["quoted_flow"]["source_ip"] == "10.0.0.1" for s in samples)


@pytest.mark.parametrize("quote", [b"", b"short", packets.frame(protocol=17)[14:34]])
def test_unavailable_or_truncated_quote_keeps_reporter(quote):
    e = example(report.analyze_network_report(records(packets.capture(router_error(2, 3, quote)))))
    s = e["icmp_details"]["samples"][0]
    assert s["reporter_ip"] == "192.0.2.2" and s["quoted_flow"] is None


@pytest.mark.parametrize("n", [4, 5])
def test_per_observation_cap_counts_events_not_details(n):
    rows = records(
        packets.capture(packets.frame(protocol=17), *[router_error(1, i) for i in range(n)])
    )
    value = report.analyze_network_report(rows)
    e = example(value)
    assert e["event_count"] == n
    assert [s["code"] for s in e["icmp_details"]["samples"]] == list(range(min(n, 4)))
    assert e["icmp_details"]["omitted_event_details"] == max(0, n - 4)
    assert value["summary"]["tracking_limited_records"] == 0
    assert value["summary"]["evaluated_records"] == n + 1


def test_interleaved_pending_merge_conserves_real_owners_and_capture_order(monkeypatch):
    instances = []
    original = report.Flow

    def make(*args, **kwargs):
        instance = original(*args, **kwargs)
        instances.append(instance)
        return instance

    monkeypatch.setattr(report, "Flow", make)
    rows = records(
        packets.capture(
            packets.frame(protocol=17), *[router_error(1 + i % 2, i) for i in range(10)]
        )
    )
    # Cross-router clocks do not establish capture order; each scope stays monotonic.
    for i, row in enumerate(rows[1:]):
        row["timestamp"] = f"2023-11-14T22:13:{20 + i // 2 + (10 if i % 2 == 0 else 0):02d}+00:00"
    result = report.analyze_network_report(rows)
    e = example(result)
    assert e["event_count"] == 10
    assert [s["code"] for s in e["icmp_details"]["samples"]] == [0, 1, 2, 3]
    owners = [o.icmp_samples for f in instances for o in f.observations.values()]
    retained = [s for owner in owners for s in owner]
    budget = instances[0].budget.icmp
    assert len(retained) == len({id(s) for s in retained}) == budget.count == 4
    assert budget.size == sum(s.size for s in retained)
    assert sum(bool(f.observations) for f in instances) == 1
    assert e["icmp_details"]["omitted_event_details"] == 6


def test_exact_store_byte_admission_and_credit_return(monkeypatch):
    row = records()[1]
    value = details.sample(row, 1.0)
    size = len(details.canonical(value)) + 1
    for limit, expected in [(size, 1), (size - 1, 0)]:
        monkeypatch.setattr(details, "MAX_BYTES", limit)
        budget = details.DetailBudget()
        owner = []
        budget.add(owner, row, 1.0)
        assert budget.count == len(owner) == expected
        assert budget.size == sum(s.size for s in owner)
        budget.release(owner)
        assert not owner and budget.count == budget.size == 0


def test_global_limits_simultaneous_with_real_2049_admissions():
    row = records(packets.capture(router_error(1, 1, b"")))[0]
    budget = details.DetailBudget()
    owners = [[] for _ in range(2049)]
    for owner in owners:
        budget.add(owner, row, 1.0)
    retained = [s for owner in owners for s in owner]
    assert budget.count == len(retained) <= 2048
    assert budget.size == sum(s.size for s in retained) <= 262144
    assert not owners[-1]  # Byte cap may bind before the sample ceiling.
    for owner in owners:
        budget.release(owner)
    assert budget.count == budget.size == 0


def test_injected_sample_limit_uses_real_owner_admission(monkeypatch):
    monkeypatch.setattr(details, "MAX_SAMPLES", 4)
    row = records()[1]
    owners = [[] for _ in range(5)]
    budget = details.DetailBudget()
    for owner in owners:
        budget.add(owner, row, 1.0)
    assert [len(o) for o in owners] == [1, 1, 1, 1, 0]
    budget.release(owners[0])
    budget.add(owners[-1], row, 1.0)
    assert budget.count == 4 and len(owners[-1]) == 1 and not owners[0]


def test_publication_budget_includes_qualifiers_and_exact_bytes(monkeypatch):
    row = records()[1]
    budget = details.DetailBudget()
    owner = []
    budget.add(owner, row, 1.0)
    e = {}
    details.publish([(e, 1, owner)])
    exact = len(details.canonical([e]))
    for limit, retained in [(exact, 1), (exact - 1, 0)]:
        monkeypatch.setattr(details, "MAX_BYTES", limit)
        e = {}
        details.publish([(e, 1, owner)])
        assert len(details.canonical([e])) <= limit
        assert len(e["icmp_details"]["samples"]) == retained
        assert e["icmp_details"]["omitted_event_details"] == 1 - retained
    monkeypatch.setattr(details, "MAX_BYTES", 1)
    with pytest.raises(ValueError, match="omission qualifiers"):
        details.publish([({}, 1, owner)])


@pytest.mark.parametrize("raw", [False, True])
def test_raw_packet_index_never_becomes_capture_bound_reference(raw):
    unsupported = bytes.fromhex("00112233445566778899aabb88b5") + bytes(28)
    rows = records(packets.capture(unsupported, router_error(1, 1, b"")), retain_packet_bytes=raw)
    if raw:
        assert rows[0]["raw_packet_index"] == 1
    else:
        assert "raw_packet_index" not in rows[0]
    s = example(report.analyze_network_report(rows))["icmp_details"]["samples"][0]
    assert s["packet_reference"] is None
    assert "packet_index" not in json.dumps(s)


@pytest.mark.parametrize("field", ["sensor_id", "capture_interface_id"])
def test_sensor_interface_scope_cannot_merge(field):
    rows = records()
    other = copy.deepcopy(rows)
    for row in other:
        row[field] = "other" if field == "sensor_id" else 8
    result = report.analyze_network_report(rows + other)
    assert len(result["issues"]) == 2
    assert [i["event_count"] for i in result["issues"]] == [2, 2]


@pytest.mark.parametrize("order", ["before", "after", "absent"])
def test_ipv6_reporters_and_directional_quote(order):
    from network_icmp_fixture import ipv6_frames

    frames = ipv6_frames()
    if order == "after":
        frames = frames[1:] + frames[:1]
    if order == "absent":
        frames = frames[1:]
    result = report.analyze_network_report(records(packets.capture(*frames)))
    samples = [
        s for i in result["issues"] for e in i["examples"] for s in e["icmp_details"]["samples"]
    ]
    assert {s["reporter_ip"] for s in samples} == {"2001:db8:1::1", "2001:db8:1::2"}
    assert {s["code"] for s in samples} == {0, 4}
    assert all(
        s["protocol"] == "ICMPV6" and s["quoted_flow"]["source_ip"] == "2001:db8::1"
        for s in samples
    )
    assert sum(i["event_count"] for i in result["issues"]) == 2


def test_detail_caps_do_not_change_any_legacy_detector_fact(monkeypatch):
    rows = records(
        packets.capture(
            packets.frame(protocol=17), *[router_error(1 + i % 2, i) for i in range(20)]
        )
    )
    first = report.analyze_network_report(rows)
    monkeypatch.setattr(details, "MAX_SAMPLES", 0)
    second = report.analyze_network_report(rows)
    assert example(second)["icmp_details"]["omitted_event_details"] == 20
    for value in (first, second):
        for issue in value["issues"]:
            for e in issue["examples"]:
                del e["icmp_details"]
    assert first == second


def test_observation_limit_returns_real_pending_credits_and_clears_aliases(monkeypatch):
    instances = []
    original = report.Flow

    def make(*args, **kwargs):
        instance = original(*args, **kwargs)
        instances.append(instance)
        return instance

    monkeypatch.setattr(report, "Flow", make)
    base = records()[1]
    rows = []
    for port in range(17):
        row = copy.deepcopy(base)
        row["icmp_quoted_flow"]["destination_port"] = port
        rows.append(row)
    result = report.analyze_network_report(rows)
    budget = instances[0].budget.icmp
    retained = [s for f in instances for o in f.observations.values() for s in o.icmp_samples]
    assert budget.count == len(retained) == len({id(s) for s in retained}) == 16
    assert budget.size == sum(s.size for s in retained)
    assert len(instances[0].observations) == 16
    assert all(not f.observations for f in instances[1:])
    assert result["summary"]["tracking_limited_records"] == 1
    assert result["summary"]["counts_are_lower_bounds"] is True
    assert "OBSERVATION_LIMIT_REACHED" in result["warnings"]


def test_many_pending_merge_returns_slot_and_byte_credit_once(monkeypatch):
    instances = []
    original = report.Flow

    def make(*args, **kwargs):
        instance = original(*args, **kwargs)
        instances.append(instance)
        return instance

    monkeypatch.setattr(report, "Flow", make)
    rows = records(
        packets.capture(packets.frame(protocol=17), *[router_error(i, i) for i in range(1, 101)])
    )
    result = report.analyze_network_report(rows)
    e = example(result)
    retained = [s for f in instances for o in f.observations.values() for s in o.icmp_samples]
    budget = instances[0].budget.icmp
    assert e["event_count"] == 100 and e["icmp_details"]["omitted_event_details"] == 96
    assert budget.count == len(retained) == 4
    assert budget.size == sum(s.size for s in retained)
    assert [s.value["code"] for s in retained] == [1, 2, 3, 4]
    fresh = []
    budget.add(fresh, rows[1], 100.0)
    assert budget.count == 5
    budget.release(fresh)
    assert budget.count == 4 and not fresh


def test_invalid_quote_scalars_are_bounded_before_encoding():
    row = records()[1]
    row["icmp_quoted_flow"] = {
        "source_ip": "x" * 1000000,
        "destination_ip": "203.0.113.1",
        "source_port": True,
        "destination_port": 443,
        "protocol": "x" * 1000000,
    }
    result = report.analyze_network_report([row])
    detail = example(result)["icmp_details"]
    assert detail["samples"][0]["quoted_flow"] == {
        "source_ip": None,
        "destination_ip": "203.0.113.1",
        "source_port": None,
        "destination_port": 443,
        "protocol": None,
    }
    assert len(details.canonical(detail)) < 1000
    assert "INCOMPLETE_ICMP_QUOTE" in result["warnings"]


def test_python_validator_does_not_coerce_version_objects():
    value = copy.deepcopy(example(report.analyze_network_report(records()))["icmp_details"])
    calls = []

    class Version:
        def __eq__(self, other):
            calls.append(other)
            return False

    value["version"] = Version()
    assert not details.validate_details(value, 2)
    assert not calls


def test_maximum_publication_is_exact_bounded_and_linear(monkeypatch):
    from network_icmp_fixture import maximum_report

    original = details.canonical
    calls = []

    def encode(value):
        result = original(value)
        calls.append(len(result))
        return result

    monkeypatch.setattr(details, "canonical", encode)
    result = maximum_report()
    assert len(result["issues"]) == 100
    examples = [e for i in result["issues"] for e in i["examples"]]
    assert len(examples) == 1000
    metadata = [{"icmp_details": e["icmp_details"]} for e in examples]
    assert len(original(metadata)) <= 262144
    assert len(original(result)) < 4 * 1024 * 1024
    assert sum(len(e["icmp_details"]["samples"]) for e in examples) <= 2048
    assert all(
        e["event_count"]
        == len(e["icmp_details"]["samples"]) + e["icmp_details"]["omitted_event_details"]
        == 4
        for e in examples
    )
    assert len(calls) <= 9000 and max(calls) < 3000
    assert sum(calls) < 4 * 1024 * 1024
