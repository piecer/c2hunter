"""The same semantic mutations must fail every generation value route."""

import copy
import hashlib
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from tests.test_historical_generation import generation_module, producer_args, uid
from tests.test_historical_source import config


@pytest.fixture
def document() -> Any:
    g = generation_module()
    return g.produce_generation(**producer_args())


def admit(value: dict[str, Any], route: str) -> Any:
    g = generation_module()
    if route == "constructor":
        return g.GenerationDocument(**value)
    if route == "mapping":
        return g.GenerationDocument.from_mapping(value)
    raw = h.canonical_json(value)
    if route == "json":
        return g.GenerationDocument.model_validate_json(raw)
    return g.decode_generation(
        raw,
        byte_size=len(raw.encode()),
        content_sha256=hashlib.sha256(raw.encode()).hexdigest(),
        scope=config(),
    )


@pytest.mark.parametrize("route", ["constructor", "mapping", "json", "storage"])
@pytest.mark.parametrize(
    "case",
    [
        "root_identity",
        "root_digest",
        "ancestry",
        "reasons",
        "receipt_envelope",
        "dangling",
        "duplicate_window",
        "duplicate_receipt",
        "window_envelope",
        "window_hash",
        "window_sensor",
        "window_feature",
        "no_eligible",
        "receipt_without_window",
        "window_order",
        "unknown",
        "unknown_receipt",
        "unknown_review",
        "unknown_window",
        "unknown_key",
        "bool_count",
        "bool_revision",
        "bad_version",
        "nonfinite",
    ],
)
def test_semantic_mutations_reject_all_routes(document: Any, case: str, route: str) -> None:
    value = document.to_mapping()
    receipt, window = value["sources"][0], value["windows"][0]
    if case == "root_identity":
        receipt["root_identity"] = '["foreign","dataset-0"]'
    elif case == "root_digest":
        receipt["root_content_sha256"] = "a" * 64
    elif case == "ancestry":
        receipt["ancestry_job_ids"] = ["foreign"]
    elif case == "reasons":
        receipt["limitations"].append(receipt["limitations"][0])
    elif case == "receipt_envelope":
        receipt["event_end"] = receipt["event_start"]
    elif case == "dangling":
        window["source_receipt_id"] = uid(99)
    elif case == "duplicate_window":
        value["windows"].append(copy.deepcopy(window))
    elif case == "duplicate_receipt":
        value["sources"].append(copy.deepcopy(receipt))
    elif case == "window_envelope":
        window["event_end"] = "2026-01-01T00:02:00.000000Z"
    elif case == "window_hash":
        window["key"]["scope_config_sha256"] = "d" * 64
    elif case == "window_sensor":
        window["key"]["sensor_key"] = "foreign"
    elif case == "window_feature":
        window["key"]["feature_version"] = "future"
    elif case == "no_eligible":
        window.update(recurrence=None, size_dispersion=None, outbound_share=None)
    elif case == "receipt_without_window":
        foreign = copy.deepcopy(receipt)
        foreign.update(
            source_receipt_id=uid(99),
            root_job_id="foreign",
            source_job_id="foreign",
            root_identity=h.canonical_json(["foreign", "dataset-0"]),
            ancestry_job_ids=["foreign"],
            feature_observation_sha256="e" * 64,
        )
        value["sources"].append(foreign)
    elif case == "window_order":
        value["windows"].reverse()
    elif case == "unknown":
        value["unknown"] = None
    elif case == "unknown_receipt":
        receipt["unknown"] = None
    elif case == "unknown_review":
        receipt["quality_review"]["unknown"] = None
    elif case == "unknown_window":
        window["unknown"] = None
    elif case == "unknown_key":
        window["key"]["unknown"] = None
    elif case == "bool_count":
        window["outbound_record_count"] = True
    elif case == "bool_revision":
        value["publication_revision"] = True
    elif case == "bad_version":
        value["schema_version"] = "future"
    elif case == "nonfinite":
        window["size_dispersion"] = float("inf")
    with pytest.raises(ValueError):
        admit(value, route)


@pytest.mark.parametrize(
    "case", ["hash", "count", "oldest", "newest", "size", "scope", "missing_head", "foreign_head"]
)
def test_current_head_and_derived_view_are_checked(document: Any, case: str) -> None:
    from tests.test_historical_generation import advance, publish, snapshot_for, source_job

    g = generation_module()
    args = producer_args()
    scope = advance(args["scope"], document)
    data = scope.to_mapping()
    if case == "hash":
        data["active"]["content_sha256"] = "a" * 64
    elif case == "count":
        data["active"]["source_window_count"] = 2
    elif case == "oldest":
        data["active"]["oldest_event_start"] = "2025-01-01T00:00:00.000000Z"
    elif case == "newest":
        data["active"]["newest_event_end"] = "2026-01-01T00:00:59.000000Z"
    elif case == "size":
        data["active"]["byte_size"] += 1
    elif case == "scope":
        data["config_sha256"] = "a" * 64
    elif case == "missing_head":
        document = None
    elif case == "foreign_head":
        data["active"]["generation_id"] = uid(99)
    with pytest.raises(ValueError):
        scope = g.ScopeView.from_mapping(data)
        publish(snapshot_for(source_job(1)), scope, document, index=2)


@pytest.mark.parametrize("case", ["receipt", "review", "request", "scope", "window", "nested_key"])
def test_forged_instances_cannot_bypass_consumption(document: Any, case: str) -> None:
    from dataclasses import replace

    g = generation_module()
    args = producer_args()
    if case == "request":
        args["request"] = args["request"].model_copy(update={"unknown": 1})
    elif case == "scope":
        args["scope"] = args["scope"].model_copy(update={"frozen": 0})
    elif case == "review":
        args["request"] = args["request"].model_copy(
            update={
                "quality_review": args["request"].quality_review.model_copy(
                    update={"sensor_alias_asserted": 0}
                )
            }
        )
    else:
        if case == "receipt":
            document = document.model_copy(
                update={"sources": (document.sources[0].model_copy(update={"unknown": 1}),)}
            )
        elif case == "window":
            document = document.model_copy(
                update={"windows": (replace(document.windows[0], outbound_record_count=True),)}
            )
        else:
            key = replace(document.windows[0].key)
            object.__setattr__(key, "unknown", 1)
            document = document.model_copy(
                update={"windows": (replace(document.windows[0], key=key),)}
            )
        with pytest.raises(ValueError):
            g.generation_view(document)
        with pytest.raises(ValueError):
            g.generation_reference(document, scope=config())
        return
    with pytest.raises(ValueError):
        g.produce_generation(**args)
