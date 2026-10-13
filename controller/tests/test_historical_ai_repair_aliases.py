"""R6: normal model_copy/dataclass replacement cannot retain caller aliases."""

import warnings
from dataclasses import replace

import pytest

from c2hunter_controller import historical_ai as dto
from c2hunter_controller import historical_ai_builder as producer
from c2hunter_controller import historical_baseline as h
from tests.historical_ai_fixtures import job, rule, world


@pytest.fixture(scope="module")
def clean():
    target = job()
    target["flow_records"][0]["tcp_flags"] = {"SYN": 1}
    return dto.HistoricalAdmissionInput(**world(target=target, candidates=[rule()]))


@pytest.mark.parametrize("boundary", ["reference", "payload", "request", "input", "snapshot"])
@pytest.mark.parametrize("entry", ["constructor", "mapping", "instance"])
def test_nested_copied_review_is_revalidated(clean, boundary, entry):
    mutable = ["not a valid note"]
    review = clean.request.payload.baseline_reference.quality_review.model_copy(
        update={"note": mutable}
    )
    reference = clean.request.payload.baseline_reference.model_copy(
        update={"quality_review": review}
    )
    payload = clean.request.payload.model_copy(update={"baseline_reference": reference})
    fingerprint = dto.request_fingerprint(
        clean.request.analysis_job_id, clean.request.actor, payload
    )
    request = clean.request.model_copy(
        update={"payload": payload, "request_fingerprint": fingerprint}
    )
    if boundary == "reference":
        value = reference
    elif boundary == "payload":
        value = payload
    elif boundary == "request":
        value = request
    elif boundary == "input":
        value = clean.model_copy(update={"request": request})
    else:
        value = producer.build_historical_snapshot(clean).model_copy(
            update={"baseline_request": payload, "baseline_request_fingerprint": fingerprint}
        )
    cls = type(value)
    fields = {name: getattr(value, name) for name in cls.model_fields}
    with pytest.raises(ValueError):
        if entry == "constructor":
            cls(**fields)
        else:
            cls.model_validate(value if entry == "instance" else fields)
    assert mutable == ["not a valid note"]  # noqa: S101 - pytest assertion, not an authorization guard.


@pytest.mark.parametrize("entry", ["constructor", "mapping", "instance"])
def test_replaced_flow_flags_detach_without_changing_original_kind_or_numbers(clean, entry):
    flags = dict(clean.target.strict_flows[0].tcp_flags)
    flow = replace(clean.target.strict_flows[0], tcp_flags=flags)
    target = clean.target.model_copy(
        update={"strict_flows": (flow, *clean.target.strict_flows[1:])}
    )
    value = clean.model_copy(update={"target": target})
    fields = {name: getattr(value, name) for name in dto.HistoricalAdmissionInput.model_fields}
    if entry == "constructor":
        admitted = dto.HistoricalAdmissionInput(**fields)
    else:
        admitted = dto.HistoricalAdmissionInput.model_validate(
            value if entry == "instance" else fields
        )
    before = admitted.model_dump_json()
    assert admitted == clean  # noqa: S101 - pytest assertion, not an authorization guard.
    flags["SYN"] = 99
    assert admitted.target.strict_flows[0].tcp_flags["SYN"] == 1  # noqa: S101 - pytest assertion, not an authorization guard.
    assert admitted.model_dump_json() == before  # noqa: S101 - pytest assertion, not an authorization guard.
    assert h.thaw_original_json(admitted.candidates[0].fields) == rule()  # noqa: S101 - pytest assertion, not an authorization guard.
    assert tuple(  # noqa: S101 - pytest assertion, not an authorization guard.
        h.thaw_original_json(admitted.candidates[0].fields)["evidence"][0]["metrics"]["ordered"]
    ) == ("z", "a")


@pytest.mark.parametrize("axis", ["scope_hosts", "generation_ancestry", "generation_review"])
def test_reused_scope_and_generation_are_not_trusted_aliases(clean, axis):
    if axis == "scope_hosts":
        mutable = list(clean.scope.config.hosts)
        config = clean.scope.config.model_copy(update={"hosts": mutable})
        value = clean.model_copy(
            update={"scope": clean.scope.model_copy(update={"config": config})}
        )
    else:
        source = clean.generation.sources[0]
        if axis == "generation_review":
            mutable = ["invalid note"]
            source = source.model_copy(
                update={
                    "quality_review": source.quality_review.model_copy(update={"note": mutable})
                }
            )
        else:
            mutable = list(source.ancestry_job_ids)
            source = source.model_copy(update={"ancestry_job_ids": mutable})
        value = clean.model_copy(
            update={
                "generation": clean.generation.model_copy(
                    update={"sources": (source, *clean.generation.sources[1:])}
                )
            }
        )
    fields = {name: getattr(value, name) for name in dto.HistoricalAdmissionInput.model_fields}
    if axis == "generation_review":
        with pytest.raises(ValueError):
            dto.HistoricalAdmissionInput(**fields)
    else:
        admitted = dto.HistoricalAdmissionInput(**fields)
        before = admitted.model_dump_json()
        mutable.clear()
        assert admitted.model_dump_json() == before  # noqa: S101 - pytest assertion, not an authorization guard.


@pytest.mark.parametrize("boundary", ["request", "input", "snapshot"])
def test_valid_nested_serialization_has_no_type_fallback_warnings(clean, boundary):
    value = (
        clean.request
        if boundary == "request"
        else clean
        if boundary == "input"
        else producer.build_historical_snapshot(clean)
    )
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        value.to_mapping()
        value.model_dump_json()
    assert caught == []  # noqa: S101 - pytest assertion, not an authorization guard.


def test_valid_review_mapping_is_detached_without_coercion(clean):
    raw = clean.request.to_mapping()
    request = dto.HistoricalAdmissionRequest(**raw)
    raw["payload"]["baseline_reference"]["quality_review"]["note"] = "changed"
    assert request == clean.request  # noqa: S101 - pytest assertion, not an authorization guard.
    assert type(request.payload.baseline_reference.quality_review.clock_offset_bound_ms) is int  # noqa: S101 - pytest assertion, not an authorization guard.
