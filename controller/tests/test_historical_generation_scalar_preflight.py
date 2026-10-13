"""Additional pre-copy scalar/shape controls using original code-object observers."""

import sys
from typing import Any

import pytest

from c2hunter_controller import historical_generation as g
from tests.test_historical_generation import producer_args, receipt_data
from tests.test_historical_generation_raw_preflight import admit


@pytest.mark.parametrize("route", ["constructor", "model_validate", "from_mapping", "json"])
@pytest.mark.parametrize("field,limit", [("source_receipt_id", 36), ("source_binding_sha256", 64)])
def test_fixed_format_text_limit_before_copy(route: str, field: str, limit: int) -> None:
    raw = receipt_data()
    raw[field] = "x" * (limit + 1)
    visits = []
    code = g._unmodel.__code__

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code is code and frame.f_locals["value"] == raw[field]:
            visits.append(True)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError):
            admit(g.SourceReceipt, raw, route)
    finally:
        sys.setprofile(previous)
    assert visits == []


@pytest.mark.parametrize("route", ["constructor", "model_validate", "from_mapping", "json"])
def test_pure_window_text_limit_before_copy(route: str) -> None:
    raw = g.produce_generation(**producer_args()).to_mapping()
    text = "Q" * 257
    raw["windows"][0]["key"]["protocol"] = text
    visits = []
    code = g._unmodel.__code__

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code is code and frame.f_locals["value"] == text:
            visits.append(True)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError):
            admit(g.GenerationDocument, raw, route)
    finally:
        sys.setprofile(previous)
    assert visits == []


@pytest.mark.parametrize("value", [None, 1, True])
def test_json_route_rejects_nontext_as_value_error(value: Any) -> None:
    with pytest.raises(ValueError):
        g.SourceReceipt.model_validate_json(value)
