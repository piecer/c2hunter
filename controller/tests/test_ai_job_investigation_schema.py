"""Closed producer contracts and portable pool commitments."""

import json
import struct
from copy import deepcopy

import pytest

from c2hunter_controller.ai_investigation_contract import canonical_bytes, digest
from c2hunter_controller.ai_job_investigation_schema import JobPool, JobPreparation
from c2hunter_controller.repositories import MemoryRepository
from tests.test_ai_job_investigation_source import behavior_job, flow, job, read


def prepared(raw=None):
    repo = MemoryRepository()
    repo.save_job(job() if raw is None else raw)
    return read(repo)


def portable_digest(data):
    value = deepcopy(data)
    value.pop("pool_sha256", None)
    for peer in value["entries"]:
        if peer["behavior_score"] is not None:
            number = float(peer["behavior_score"])
            peer["behavior_score"] = struct.pack(">d", number if number else 0.0).hex()
    return digest(value)


@pytest.mark.parametrize(
    "mutation",
    [
        "counts",
        "score_state",
        "peer_id",
        "order",
        "duplicate",
        "omission",
        "digest",
        "coverage",
        "limits",
        "foreign",
    ],
)
def test_closed_pool_semantics_even_with_rehashed_content(mutation):
    value = prepared().pool.model_dump()
    if mutation == "counts":
        value["entries"][0]["eligible_rows"] = 0
    elif mutation == "score_state":
        value["entries"][0]["behavior_score"] = 2
    elif mutation == "peer_id":
        value["entries"][0]["peer_id"] = "f" * 64
    elif mutation == "order":
        value["entries"] = value["entries"][::-1]
    elif mutation == "duplicate":
        value["entries"] = (value["entries"][0], value["entries"][0])
    elif mutation == "omission":
        value["omitted_peers"] = 1
    elif mutation == "coverage":
        value["discovery"]["examined_peers"] = 2
    elif mutation == "limits":
        value["limitations"] = ("INVENTED_NORMAL",)
    elif mutation == "foreign":
        value["source_sha256"] = "a" * 64
    value["pool_sha256"] = portable_digest(value) if mutation != "digest" else "0" * 64
    with pytest.raises(ValueError):
        JobPool.model_validate(value)


@pytest.mark.parametrize("mutation", ["observed", "rows", "binding", "nested_copy"])
def test_preparation_validates_snapshot_pool_agreement(mutation):
    result = prepared()
    value = result.pool.model_dump()
    if mutation == "observed":
        value.update(observed_peers=3, omitted_peers=1, omitted_identities="NOT_RETAINED")
    elif mutation == "rows":
        value["entries"][0].update(matched_rows=2, eligible_rows=2)
    elif mutation == "binding":
        result = prepared(job([flow(total_bytes=99)]))
    else:
        broken = result.pool.entries[0].model_copy(update={"matched_rows": True})
        copied = result.pool.model_copy(update={"entries": (broken, *result.pool.entries[1:])})
        with pytest.raises(ValueError):
            JobPreparation(snapshot=result.snapshot, pool=copied)
        return
    value["pool_sha256"] = portable_digest(value)
    with pytest.raises(ValueError):
        JobPreparation(snapshot=result.snapshot, pool=value)


@pytest.mark.parametrize("count", [32, 33])
def test_pool_complete_prefix_count_cap(count):
    raw = job([flow(destination_ip=f"192.0.2.{i}") for i in range(1, count)])
    result = prepared(raw)
    assert result.pool.observed_peers == count
    assert len(result.pool.entries) == min(count, 32)
    assert result.pool.omitted_peers == max(0, count - 32)
    assert result.pool.omitted_identities == ("NOT_RETAINED" if count > 32 else "NONE")
    assert len(canonical_bytes(result.pool.model_dump())) <= 16384
    assert len(result.snapshot.rows) == count - 1
    assert JobPreparation.model_validate_json(result.model_dump_json()) == result


def test_pool_byte_boundary_and_bounded_complete_rollback(monkeypatch):
    from c2hunter_controller import ai_job_investigation_pool as producer
    from c2hunter_controller.ai_job_investigation_schema import DiscoveryCoverage

    snapshot = prepared().snapshot
    coverage = DiscoveryCoverage(
        state="UNAVAILABLE", examined_peers=None, excluded_peers=None, warnings=("é" * 1000,) * 7
    )
    # Public warning envelope plus two entries; exact-size lower test policy.
    control = producer.build_pool(snapshot, {}, coverage)
    size = len(canonical_bytes(control.model_dump()))
    calls = []
    encode = producer.canonical_bytes if hasattr(producer, "canonical_bytes") else canonical_bytes

    def counted(value):
        calls.append(1)
        return encode(value)

    monkeypatch.setattr(producer, "canonical_bytes", counted, raising=False)
    monkeypatch.setattr(producer, "POOL_BYTES", size, raising=False)
    assert producer.build_pool(snapshot, {}, coverage) == control
    monkeypatch.setattr(producer, "POOL_BYTES", size - 1)
    limited = producer.build_pool(snapshot, {}, coverage)
    assert len(limited.entries) == 1
    assert limited.entries == control.entries[:1]
    assert limited.omitted_peers == 1
    assert len(canonical_bytes(limited.model_dump())) <= size - 1
    assert len(calls) <= 16


@pytest.mark.parametrize("extra", [0, 1])
def test_preparation_exact_bytes_and_no_source_prefix(extra):
    raw = job([flow(sensor_id="s", domain="x") for _ in range(128)])
    base = prepared(raw)
    missing = 131072 + extra - len(canonical_bytes(base.model_dump()))
    assert missing > 0
    for row in raw["flow_records"]:
        for key, limit in (("sensor_id", 200), ("domain", 253)):
            amount = min(missing, limit - len(row[key]))
            row[key] += "x" * amount
            missing -= amount
    assert missing == 0
    if extra:
        with pytest.raises(ValueError, match="SOURCE_LIMIT"):
            prepared(raw)
    else:
        result = prepared(raw)
        assert len(canonical_bytes(result.model_dump())) == 131072
        assert len(result.snapshot.rows) == 128


def test_preparation_huge_snapshot_refuses_before_detector(monkeypatch):
    from c2hunter_controller import ai_job_investigation_read as reader

    monkeypatch.setattr(reader, "discover", lambda *a: pytest.fail("detector before cap"))
    with pytest.raises(ValueError, match="SOURCE_LIMIT"):
        prepared(job([flow()] * 8192))


def test_required_null_intent_closed_request_and_selection():
    from c2hunter_controller import ai_job_investigation_schema as schema

    assert hasattr(schema, "JobRequest"), "JOB request contract missing"
    value = dict(
        version="job-investigation-v1",
        mode="JOB",
        experimental=True,
        question="현재 작업의 관측 피어 조사",
        language="ko",
        idempotency_key="key",
        expected_source_sha256=None,
        allow_remote=False,
        baseline_mode="off",
    )
    request = schema.JobRequest.model_validate(value)
    assert request.expected_source_sha256 is None
    for name in value:
        with pytest.raises(ValueError):
            schema.JobRequest.model_validate({k: v for k, v in value.items() if k != name})
    for update in (
        {"experimental": 1},
        {"baseline_mode": "on"},
        {"target_ip": "10.0.0.1"},
        {"expected_source_sha256": "A" * 64},
        {"question": "\ud800"},
    ):
        with pytest.raises(ValueError):
            schema.JobRequest.model_validate(value | update)
    assert hasattr(schema, "Selection"), "selection value contract missing"
    assert schema.Selection(state="PENDING", peer_ids=()).peer_ids == ()
    for state, ids in [
        ("PENDING", ("a" * 64,)),
        ("COMMITTED", ()),
        ("COMMITTED", ("a" * 64, "a" * 64)),
    ]:
        with pytest.raises(ValueError):
            schema.Selection(state=state, peer_ids=ids)


def test_duplicate_json_and_raw_envelope_limit_reject_before_decode():
    pool = prepared().pool
    wire = pool.model_dump_json()
    with pytest.raises(ValueError):
        JobPool.model_validate_json('{"observed_peers":2,' + wire[1:])
    with pytest.raises(ValueError):
        JobPool.model_validate_json(" " * 16384 + wire)


def test_reason_registry_and_every_retained_reference_reaches_evidence():
    from pydantic import TypeAdapter

    from c2hunter_controller import ai_job_investigation_schema as schema
    from c2hunter_controller.ai_investigation_evidence import EvidenceService

    assert hasattr(schema, "Reason"), "closed reason primitive missing"
    reason = TypeAdapter(schema.Reason)
    for code in schema.REASON_CODES:
        assert reason.validate_python(code) == code
    with pytest.raises(ValueError):
        reason.validate_python("MADE_UP_NORMAL")
    result = prepared()
    assert callable(getattr(result, "scope_for_peer", None)), (
        "retained peer reference resolver missing"
    )
    for peer in result.pool.entries:
        scope = result.scope_for_peer(peer.peer_id)
        assert scope.target_ip == peer.ip and scope.endpoint_side == "either"
        assert (
            EvidenceService(result.snapshot, scope).call("peer_overview", {}).counts.matched
            == peer.matched_rows
        )
    with pytest.raises(ValueError, match="PEER_OUT_OF_POOL"):
        result.scope_for_peer("0" * 64)


@pytest.mark.parametrize("value", [10**400, -(10**400), True, "1", 1.5, float("inf")])
def test_integral_primitive_never_overflows(value):
    from c2hunter_controller.ai_job_investigation_schema import integral

    with pytest.raises(ValueError):
        integral(value)


def test_default_pool_exact_16k_and_plus_one_complete_omission():
    from c2hunter_controller.ai_job_investigation_pool import build_pool
    from c2hunter_controller.ai_job_investigation_schema import DiscoveryCoverage

    snapshot = prepared().snapshot
    warnings = ("é" * 1000,) * 7 + ("",)

    def coverage(w):
        return DiscoveryCoverage(
            state="UNAVAILABLE", examined_peers=None, excluded_peers=None, warnings=w
        )

    control = build_pool(snapshot, {}, coverage(warnings))
    remaining = 16384 - len(canonical_bytes(control.model_dump()))
    last = "é" * (remaining // 2) + "x" * (remaining % 2)
    assert len(last) < 1000
    exact = build_pool(snapshot, {}, coverage(warnings[:-1] + (last,)))
    assert len(exact.entries) == 2
    assert len(canonical_bytes(exact.model_dump())) == 16384
    extra = build_pool(snapshot, {}, coverage(warnings[:-1] + (last + "x",)))
    assert extra.entries == exact.entries[:1]
    assert extra.omitted_peers == 1
    assert len(canonical_bytes(extra.model_dump())) <= 16384
    with pytest.raises(ValueError, match="SOURCE_LIMIT"):
        build_pool(snapshot, {}, coverage(("é" * 1000,) * 32))


def test_maximum_observed_endpoint_inventory_without_preparation_claim(monkeypatch):
    from c2hunter_controller import ai_job_investigation_pool as producer
    from c2hunter_controller.ai_investigation_read import _project
    from c2hunter_controller.ai_job_investigation_schema import DiscoveryCoverage

    rows = [
        flow(source_ip=f"2001:db8::{2 * i + 1:x}", destination_ip=f"2001:db8::{2 * i + 2:x}")
        for i in range(8192)
    ]
    raw = job(rows)
    snapshot = _project({k: v for k, v in raw.items() if k != "flow_records"}, rows)
    counts = []
    original = producer.canonical_bytes

    def observe(value):
        encoded = original(value)
        counts.append(len(encoded))
        return encoded

    monkeypatch.setattr(producer, "canonical_bytes", observe)
    coverage = DiscoveryCoverage(
        state="UNAVAILABLE",
        examined_peers=None,
        excluded_peers=None,
        warnings=("BEHAVIOR_CONTEXT_UNAVAILABLE",),
    )
    result = producer.build_pool(snapshot, {}, coverage)
    assert result.observed_peers == 16384 and len(result.entries) == 32
    assert result.omitted_peers == 16352
    assert len(counts) <= 8 and sum(counts) <= 8 * 16384
    with pytest.raises(ValueError, match="SOURCE_LIMIT"):
        JobPreparation(snapshot=snapshot, pool=result)


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("pool",),
        ("pool", "discovery"),
        ("pool", "entries", 0),
        ("snapshot", "binding"),
        ("snapshot", "rows", 0),
    ],
)
def test_unknown_nested_fields_reject_in_constructors_and_json(path):
    value = prepared().model_dump(mode="json")
    target = value
    for key in path:
        target = target[key]
    target["unknown"] = None
    with pytest.raises(ValueError):
        JobPreparation.model_validate_json(json.dumps(value))


def test_detached_copied_snapshot_revalidates_and_score_zero_is_portable():
    from c2hunter_controller.ai_job_investigation_schema import pool_digest

    result = prepared()
    row = result.snapshot.rows[0].model_copy(update={"packet_count": True})
    bad = result.snapshot.model_copy(update={"rows": (row,)})
    with pytest.raises(ValueError):
        JobPreparation(snapshot=bad, pool=result.pool)
    wire = prepared(behavior_job()).pool.model_dump()
    wire["entries"][0]["behavior_score"] = -0.0
    wire["pool_sha256"] = pool_digest(wire)
    normalized = JobPool.model_validate(wire)
    assert struct.pack(">d", normalized.entries[0].behavior_score).hex() == "0000000000000000"
    assert normalized.pool_sha256 == portable_digest(wire)


def test_score_primitive_refuses_overflow_and_custom_numbers():
    from c2hunter_controller.ai_job_investigation_schema import finite_score

    class CustomFloat(float):
        pass

    for value in (10**400, True, CustomFloat(1), float("nan")):
        with pytest.raises(ValueError):
            finite_score(value)


def test_producer_portable_hash_not_python_float_spelling():
    pool = prepared(behavior_job()).pool
    wire = pool.model_dump(mode="json")
    assert pool.pool_sha256 == portable_digest(wire)
    assert pool.pool_sha256 != digest({k: v for k, v in wire.items() if k != "pool_sha256"})


@pytest.mark.parametrize("token", ["1.0", "1e0", "1"])
def test_job_integral_wire_tokens_normalize_without_relaxing_raw(token):
    pool = prepared().pool
    encoded = canonical_bytes(pool.model_dump(mode="json")).decode()
    encoded = encoded.replace('"matched_rows":1', '"matched_rows":' + token)
    assert JobPool.model_validate_json(encoded) == pool
    if token != "1":
        with pytest.raises(ValueError, match="SOURCE_INVALID"):
            prepared(job([flow(packet_count=json.loads(token))]))


@pytest.mark.parametrize(
    "field,value",
    [
        ("matched_rows", True),
        ("matched_rows", 1.5),
        ("matched_rows", "1"),
        ("eligible_rows", -1),
        ("behavior_score", True),
        ("behavior_score", float("inf")),
        ("behavior_score", float("nan")),
    ],
)
def test_bad_numeric_leaves(field, value):
    data = prepared().pool.model_dump()
    data["entries"][0][field] = value
    with pytest.raises(ValueError):
        JobPool.model_validate(data)
