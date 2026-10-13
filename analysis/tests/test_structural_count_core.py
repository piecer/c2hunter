"""Private review-free structural arithmetic, preserving the public entry policy."""

from dataclasses import fields, replace
from types import MappingProxyType

import pytest
from test_behavior_baseline import request

from c2hunter_analysis import behavior_baseline as b


def structural():
    reviewed = request(inbound=False)
    return b._StructuralBuildInput(
        replace(reviewed.scope, kind="EVALUATION", sensor_key="logical", stored_sensor_id=None),
        reviewed.actual_sensor_id,
        reviewed.event_start,
        reviewed.event_end,
        reviewed.flows,
        reviewed.trusted_peers,
    )


def test_pure_structural_facts_have_no_assertion_or_receipt():
    value = structural()
    assert {f.name for f in fields(value)} == {
        "scope",
        "actual_sensor_id",
        "event_start",
        "event_end",
        "flows",
        "trusted_peers",
    }
    assert b._structural_counts(value) == (1, 1, 0, ())
    with pytest.raises(b.BaselineInputError):
        b.build_behavior_windows(value)
    with pytest.raises(b.BaselineInputError):
        b.build_behavior_windows_with_retained_keys(value, retained_keys=())


@pytest.mark.parametrize(
    "field,value",
    [
        ("packet_sizes", (object(),) * 129),
        ("tcp_syn_only_observations", (object(),) * 257),
        ("tcp_flags", MappingProxyType({str(i): object() for i in range(17)})),
    ],
)
def test_structural_private_caps_before_scalar_work(field, value, monkeypatch):
    facts = structural()
    facts = replace(facts, flows=(replace(facts.flows[0], **{field: value}),))

    def poison(*args, **kwargs):
        raise AssertionError("scalar/feature work visited before raw cap")

    monkeypatch.setattr(b, "_flow", poison)
    monkeypatch.setattr(b, "_dispersion", poison)
    with pytest.raises(b.BaselineInputError) as exc:
        b._structural_counts(facts)
    assert exc.value.code == "BASELINE_SOURCE_LIMIT"


def test_structural_calculation_has_no_publishable_intermediates(monkeypatch):
    facts = structural()

    def poison(*args, **kwargs):
        raise AssertionError("reviewed publication wrapper constructed")

    for name in (
        "BaselineBuildInput",
        "BehaviorWindow",
        "ProfileBuildRecord",
        "BaselineBuildResult",
        "BaselineReference",
    ):
        monkeypatch.setattr(b, name, poison)
    assert b._structural_counts(facts) == (1, 1, 0, ())


def test_nonfinite_forged_window_is_not_finite_admission():
    window = b.build_behavior_windows(request()).profiles[0].window
    window = replace(window, recurrence=None, size_dispersion=float("inf"), outbound_share=None)
    assert b._eligible(window)
    with pytest.raises(b.BaselineInputError):
        b._window(window)
