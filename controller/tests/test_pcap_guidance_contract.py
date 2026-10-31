from __future__ import annotations

import copy
import importlib.util

import pytest
from c2hunter_analysis.ddos_job import analyze_ddos_job
from test_ddos_attack_api import syn_records


def producer():
    rows = syn_records()[:4] * 40
    job = {
        "id": "schema-job",
        "dataset_id": "schema-dataset",
        "source_type": "PCAP_UPLOAD",
        "analysis": {"module": "ddos_attack"},
        "internal_networks": ["10.0.0.0/8"],
        "flow_records": rows,
    }
    result = analyze_ddos_job(job)
    return {**job, **result}


def validator():
    assert importlib.util.find_spec("c2hunter_controller.pcap_attack_guidance_schema") is not None
    from c2hunter_controller.pcap_attack_guidance_schema import validate_job_guidance

    return validate_job_guidance


def test_generated_packet_fixtures_are_frozen_exact_bytes():
    from pcap_guidance_fixture_builder import FIXTURES, generated

    values = generated()
    assert sorted(path.name for path in FIXTURES.glob("*.json")) == sorted(values)
    for name, expected in values.items():
        assert (FIXTURES / name).read_bytes() == expected, name


def test_frozen_cases_have_independent_semantic_expectations():
    import json

    from pcap_guidance_fixture_builder import FIXTURES

    expectations = {
        "positive": "SYN_CONCENTRATION",
        "mixed": "SYN_CONCENTRATION",
        "low_source": "SYN_CONCENTRATION",
        "short": "SYN_CONCENTRATION",
        "relative_udp": "UDP_BURST",
        "partial": "SYN_CONCENTRATION",
        "ack": "PAYLOAD_FREE_ACK_BURST",
        "rst": "RST_BURST",
        "icmp": "ICMP_BURST",
    }
    for name, family in expectations.items():
        job = json.loads((FIXTURES / f"{name}.job.json").read_bytes())
        guide = validator()(job)
        assert guide["candidates"][0]["family"] == family
    for name in ("clean_payload", "clean_handshake", "stable_udp", "unsupported"):
        job = json.loads((FIXTURES / f"{name}.job.json").read_bytes())
        assert validator()(job)["candidates"] == []
    mixed = json.loads((FIXTURES / "mixed.job.json").read_bytes())
    assert mixed["ddos_attack"]["findings"] == []
    overflow = json.loads((FIXTURES / "overflow.job.json").read_bytes())
    assert len(validator()(overflow)["candidates"]) == 32
    assert overflow["pcap_attack_guidance"]["summary"]["omitted_candidate_count"] == 224


@pytest.mark.parametrize(
    "token,accepted",
    [
        ("4.0", True),
        ("4e0", True),
        ("4", True),
        ("true", False),
        ('"4"', False),
        ("4.01", False),
        ("9007199254740992", False),
        ("NaN", False),
        ("Infinity", False),
    ],
)
def test_json_numeric_value_policy_preserves_raw_token(token, accepted):
    import json

    from c2hunter_analysis.pcap_attack_guidance import canonical_bytes

    job = producer()
    wire = canonical_bytes(job["pcap_attack_guidance"]).replace(
        b'"source_count":4', b'"source_count":' + token.encode()
    )
    job["pcap_attack_guidance"] = json.loads(wire)
    if accepted:
        assert validator()(job)["candidates"][0]["source_count"] == 4
    else:
        with pytest.raises(ValueError):
            validator()(job)


@pytest.mark.parametrize("path", [(), ("summary",), ("candidates", 0), ("candidates", 0, "target")])
def test_every_structural_key_is_required_and_unknown_keys_reject(path):
    job = producer()
    target = job["pcap_attack_guidance"]
    for part in path:
        target = target[part]
    for removed in [*target, "extra"]:
        changed = copy.deepcopy(job)
        obj = changed["pcap_attack_guidance"]
        for part in path:
            obj = obj[part]
        if removed == "extra":
            obj["extra"] = 1
        else:
            del obj[removed]
        with pytest.raises(ValueError):
            validator()(changed)


def test_guidance_counters_cannot_exceed_enclosing_job_counts():
    job = producer()
    for field in ("packet_count", "flow_count"):
        with pytest.raises(ValueError):
            validator()({**job, field: 1})
    assert validator()({**job, "packet_count": 160, "flow_count": 160}) is not None


def test_guidance_closed_contract_owner_report_binding_and_integer_value_semantics():
    validate = validator()
    job = producer()
    assert validate(job) == job["pcap_attack_guidance"]
    integral = copy.deepcopy(job)
    integral["pcap_attack_guidance"]["candidates"][0]["source_count"] = 4.0
    assert validate(integral)["candidates"][0]["source_count"] == 4
    for value in (None, {}, [], "bad"):
        with pytest.raises(ValueError):
            validate({**job, "pcap_attack_guidance": value})
    assert (
        validate({key: value for key, value in job.items() if key != "pcap_attack_guidance"})
        is None
    )
    for field, value in (
        ("id", "foreign"),
        ("dataset_id", "foreign"),
        ("source_type", "SENSOR_CAPTURE"),
        ("analysis", {"module": "c2"}),
    ):
        with pytest.raises(ValueError):
            validate({**job, field: value})
    mutations = [
        ((), "unexpected", True),
        (("summary",), "packet_count", 1),
        (("candidates", 0), "packet_count", True),
        (("candidates", 0), "packet_count", "160"),
        (("candidates", 0), "packet_count", 160.5),
        (("candidates", 0), "packet_count", 2**53),
        (("candidates", 0), "family", "ATTACK"),
        (("candidates", 0), "reason_codes", ["UNKNOWN"]),
        (("candidates", 0, "target"), "ip", "not-ip"),
        (("candidates", 0), "last_seen", "2026-09-15T00:00:05.000000Z"),
        (("candidates", 0), "window_end", "2026-09-15T00:00:06.000000Z"),
    ]
    for path, key, value in mutations:
        poisoned = copy.deepcopy(job)
        target = poisoned["pcap_attack_guidance"]
        for part in path:
            target = target[part]
        target[key] = value
        with pytest.raises(ValueError):
            validate(poisoned)
