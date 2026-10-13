"""Exact quotas and scoped readmission, using producer-owned values."""

import hashlib
from typing import Any

import pytest

from c2hunter_controller import historical_baseline as h
from tests.test_historical_generation import (
    generation_module,
    producer_args,
    snapshot_for,
    source_job,
    uid,
)
from tests.test_historical_generation_validation import admit
from tests.test_historical_source import config


@pytest.fixture
def document() -> Any:
    return generation_module().produce_generation(**producer_args())


@pytest.mark.parametrize(
    "case", ["host", "epoch", "peer", "duration", "actual_sensor", "alias", "scope_id"]
)
def test_scoped_decode_rejects_rehashed_foreign_facts(document: Any, case: str) -> None:
    g = generation_module()
    data = document.to_mapping()
    if case == "host":
        data["windows"][0]["key"]["internal_host_ip"] = "10.0.0.99"
    elif case == "epoch":
        data["windows"][0]["key"]["host_epoch"] = "other"
    elif case == "peer":
        data["windows"][0]["key"]["peer_ip"] = "10.0.0.2"
    elif case == "scope_id":
        data["scope_id"] = uid(99)
    elif case == "duration":
        data["sources"][0]["event_end"] = "2026-01-01T00:02:00.000000Z"
        for w in data["windows"]:
            w["event_end"] = data["sources"][0]["event_end"]
    elif case == "actual_sensor":
        data["sources"][0]["actual_sensor_id"] = "other"
    elif case == "alias":
        data["sources"][0]["quality_review"]["sensor_alias_asserted"] = True
    data["windows"].sort(key=lambda w: h.canonical_json([w["key"], w["source_receipt_id"]]))
    raw = h.canonical_json(data)
    with pytest.raises(ValueError):
        g.decode_generation(
            raw,
            content_sha256=hashlib.sha256(raw.encode()).hexdigest(),
            byte_size=len(raw.encode()),
            scope=config(),
        )


@pytest.mark.parametrize("route", ["constructor", "mapping", "json", "storage"])
@pytest.mark.parametrize("extra", [0, 1])
def test_rollup_exact_utf8_cap(document: Any, extra: int, route: str) -> None:
    data = document.to_mapping()
    data["windows"] = [data["windows"][0]]
    w = data["windows"][0]
    # Fill allowed uppercase protocol and host epoch fields, not invented padding keys.
    w["key"]["protocol"] = "Q" * 256
    w["key"]["host_epoch"] = "界" * 64
    w["key"]["sensor_key"] = "S" * 200
    data["sources"][0]["sensor_key"] = "S" * 200
    size = len(h.canonical_json(w).encode())
    assert size > 1025
    w["key"]["protocol"] = "Q" * (256 - size + 1024 + extra)
    assert len(h.canonical_json(w).encode()) == 1024 + extra
    # Non-storage DTO validates linked shape; storage additionally validates configured identity.
    if extra or route == "storage":
        with pytest.raises(ValueError):
            admit(data, route)
    else:
        assert len(admit(data, route).windows) == 1


@pytest.mark.parametrize("extra", [0, 1])
def test_receipt_exact_utf8_cap(document: Any, extra: int) -> None:
    g = generation_module()
    value = document.sources[0].to_mapping()
    value["reason"] = "界" * 512
    value["quality_review"]["note"] = "界" * 512
    value["ancestry_job_ids"] = ["root-0"] + [str(i) + "x" * 197 for i in range(1, 16)]
    value["approved_by"] = "界" * 200
    value["actual_sensor_id"] = "界" * 200
    value["sensor_key"] = "界" * 200
    size = len(h.canonical_json(value).encode())
    # Bounded reduction using only existing text fields; no padding member.
    for field in ("actual_sensor_id", "approved_by", "sensor_key", "reason"):
        while size - 8192 - extra >= 2 and "界" in value[field]:
            value[field] = value[field].replace("界", "x", 1)
            size = len(h.canonical_json(value).encode())
    if size == 8193 + extra:
        value["ancestry_job_ids"][-1] = value["ancestry_job_ids"][-1][:-1]
        size -= 1
    assert size == 8192 + extra
    if extra:
        with pytest.raises(ValueError):
            g.SourceReceipt(**value)
    else:
        assert g.SourceReceipt(**value).root_job_id == "root-0"


@pytest.mark.parametrize(
    "case", ["duplicate", "noncanonical", "bool_size", "size", "hash", "oversize"]
)
def test_original_storage_bytes_checked_before_use(document: Any, case: str) -> None:
    g = generation_module()
    raw = g.generation_json(document)
    if case == "duplicate":
        raw = raw.replace(
            '"schema_version":', '"schema_version":"historical-baseline-v1","schema_version":'
        )
    if case == "noncanonical":
        raw += " "
    if case == "oversize":
        raw = " " * (2097152 + 1)
    digest, size = hashlib.sha256(raw.encode()).hexdigest(), len(raw.encode())
    if case == "hash":
        digest = "a" * 64
    if case == "size":
        size += 1
    if case == "bool_size":
        size = True
    with pytest.raises(ValueError):
        g.decode_generation(raw, content_sha256=digest, byte_size=size, scope=config())
    if case == "duplicate":
        with pytest.raises(ValueError):
            g.GenerationDocument.model_validate_json(raw)


@pytest.mark.parametrize("extra", [0, 1])
def test_union_profile_cap_128_129_before_publication(extra: int) -> None:
    from tests.test_historical_generation import advance, empty_scope, publish

    raw = source_job(0)
    template = raw["flow_records"][:8]
    raw["flow_records"] = [
        dict(row, destination_port=1000 + i) for i in range(128) for row in template
    ]
    scope = empty_scope()
    current = publish(snapshot_for(raw), scope)
    assert len(current.windows) == 128
    scope = advance(scope, current)
    raw = source_job(1)
    raw["flow_records"] = [
        dict(row, destination_port=1127 + extra) for row in raw["flow_records"][:8]
    ]
    if extra:
        with pytest.raises(ValueError, match="BASELINE_PROFILE_LIMIT"):
            publish(snapshot_for(raw), scope, current, index=2)
    else:
        assert (
            generation_module()
            .generation_view(publish(snapshot_for(raw), scope, current, index=2))
            .profile_count
            == 128
        )


def capacity_document(document: Any, target_bytes: int) -> dict[str, Any]:
    """Structural capacity fixture derived from one real rollup, not capture evidence."""
    import copy
    from datetime import timedelta

    from tests.test_historical_source import START

    data = document.to_mapping()
    template = data["windows"][0]
    key = template["key"]
    key.update(protocol="Q" * 256, host_epoch="界" * 64, sensor_key="S" * 200)
    key["service_port"] = 1000
    template["recurrence"] = 0.0
    template["size_dispersion"] = 0.0
    template["outbound_share"] = 1.0
    excess = len(h.canonical_json(template).encode()) - 1024
    assert 0 <= excess < 200
    key["protocol"] = "Q" * (256 - excess)
    sources, windows = [], []
    for index in range(16):
        source = copy.deepcopy(data["sources"][0])
        source.update(
            source_receipt_id=uid(index + 1),
            source_job_id=f"r{index}",
            root_job_id=f"r{index}",
            dataset_id=f"d{index}",
            root_identity=h.canonical_json([f"r{index}", f"d{index}"]),
            ancestry_job_ids=[f"r{index}"],
            feature_observation_sha256=f"{index:064x}",
            sensor_key="S" * 200,
            reason="x",
            event_start=h._utc((START + timedelta(hours=12 * index)).isoformat()),
            event_end=h._utc((START + timedelta(hours=12 * index, seconds=60)).isoformat()),
        )
        source = generation_module().SourceReceipt(**source).to_mapping()
        sources.append(source)
        for port in range(1000, 1128):
            window = copy.deepcopy(template)
            window.update(
                source_receipt_id=source["source_receipt_id"],
                event_start=source["event_start"],
                event_end=source["event_end"],
            )
            window["key"]["service_port"] = port
            windows.append(window)
    data.update(sources=sources, windows=windows, publication_revision=16)
    size = len(h.canonical_json(data).encode())
    assert size > target_bytes
    # Each key's protocol changes all its sixteen windows together: union remains128.
    remove = (size - target_bytes + 15) // 16
    for port in range(1000, 1128):
        count = min(remove, 20)
        if count:
            for w in windows:
                if w["key"]["service_port"] == port:
                    w["key"]["protocol"] = w["key"]["protocol"][:-count]
            remove -= count
    assert remove == 0
    remaining = target_bytes - len(h.canonical_json(data).encode())
    assert 0 <= remaining < 16
    sources[-1]["reason"] += "x" * remaining
    windows.sort(key=lambda w: h.canonical_json([w["key"], w["source_receipt_id"]]))
    assert len(h.canonical_json(data).encode()) == target_bytes
    assert max(len(h.canonical_json(w).encode()) for w in windows) <= 1024
    return data


@pytest.mark.parametrize("extra", [0, 1])
def test_document_exact_2mib_and_2048_windows(document: Any, extra: int) -> None:
    g = generation_module()
    value = capacity_document(document, 2097152 + extra)
    if extra:
        with pytest.raises(ValueError, match="BASELINE_GENERATION_LIMIT"):
            g.GenerationDocument.from_mapping(value)
    else:
        result = g.GenerationDocument.from_mapping(value)
        assert len(result.windows) == 2048
        assert len(g.generation_json(result).encode()) == 2097152
        value["windows"].append(value["windows"][0])
        with pytest.raises(ValueError):
            g.GenerationDocument.from_mapping(value)
