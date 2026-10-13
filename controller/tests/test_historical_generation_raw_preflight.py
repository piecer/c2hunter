"""Raw schema admission precedes the real recursive copy on every value route."""

import json
import sys
from typing import Any

import pytest

from c2hunter_controller import historical_generation as g
from tests.test_historical_generation import producer_args, receipt_data


@pytest.fixture(scope="module")
def document() -> Any:
    return g.produce_generation(**producer_args())


def reject_without_copy(call: Any) -> None:
    visits = []
    code = g._unmodel.__code__

    def observe(frame: Any, event: str, arg: Any) -> None:
        if event == "call" and frame.f_code is code:
            item = frame.f_locals["value"]
            if type(item) is int and item == 10001:
                visits.append(item)

    previous = sys.getprofile()
    sys.setprofile(observe)
    try:
        with pytest.raises(ValueError):
            call()
    finally:
        sys.setprofile(previous)
    assert visits == []


def admit(cls: Any, raw: Any, route: str) -> Any:
    if route == "constructor":
        return cls(**raw)
    if route == "json":
        return cls.model_validate_json(json.dumps(raw))
    return getattr(cls, route)(raw)


@pytest.mark.parametrize("route", ["constructor", "model_validate", "from_mapping", "json"])
@pytest.mark.parametrize(
    "location,cap",
    [
        ("ancestry_job_ids", 16),
        ("limitations", 30),
        ("config.hosts", 128),
        ("config.internal_networks", 128),
        ("sources", 16),
        ("windows", 2048),
        ("windows.0.limitations", 30),
    ],
)
def test_every_collection_limit_before_member_copy(
    document: Any, route: str, location: str, cap: int
) -> None:
    if location.startswith("config"):
        cls, raw = g.ScopeView, producer_args()["scope"].to_mapping()
    elif location.startswith(("sources", "windows")):
        cls, raw = g.GenerationDocument, document.to_mapping()
    else:
        cls, raw = g.SourceReceipt, receipt_data()
    target = raw
    parts = location.split(".")
    for part in parts[:-1]:
        target = target[int(part)] if part.isdecimal() else target[part]
    target[parts[-1]] = [10001] * (cap + 1)
    reject_without_copy(lambda: admit(cls, raw, route))


@pytest.mark.parametrize("route", ["constructor", "model_validate", "from_mapping", "json"])
@pytest.mark.parametrize("location", ["document", "source", "review", "window", "key"])
def test_unknown_shapes_are_closed_before_value_copy(
    document: Any, route: str, location: str
) -> None:
    raw = document.to_mapping()
    targets = {
        "document": raw,
        "source": raw["sources"][0],
        "review": raw["sources"][0]["quality_review"],
        "window": raw["windows"][0],
        "key": raw["windows"][0]["key"],
    }
    targets[location]["unknown"] = [10001] * 4096
    reject_without_copy(lambda: admit(g.GenerationDocument, raw, route))


@pytest.mark.parametrize("route", ["constructor", "model_validate", "from_mapping"])
@pytest.mark.parametrize("case", ["unknown", "oversize"])
def test_nested_existing_dto_is_not_trusted(route: str, case: str) -> None:
    raw = receipt_data()
    review = g.SourceReceipt(**raw).quality_review
    update = {"unknown": [10001] * 4096} if case == "unknown" else {"note": [10001] * 4096}
    raw["quality_review"] = review.model_copy(update=update)
    reject_without_copy(lambda: admit(g.SourceReceipt, raw, route))


@pytest.mark.parametrize("route", ["constructor", "model_validate", "from_mapping", "json"])
def test_wrong_scalar_shape_rejects_without_recursive_copy(route: str) -> None:
    raw = receipt_data()
    raw["reason"] = {"nested": [10001] * 4096}
    reject_without_copy(lambda: admit(g.SourceReceipt, raw, route))
