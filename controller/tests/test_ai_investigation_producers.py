"""Actual serializers, not invented normalized rows, at the evidence boundary."""

import json
import struct
from pathlib import Path

import pytest

from c2hunter_controller.ai_investigation_contract import (
    InvestigationError,
    InvestigationScope,
    SourceSnapshot,
    canonical_bytes,
    digest,
)
from c2hunter_controller.ai_investigation_evidence import EvidenceService
from c2hunter_controller.ai_investigation_store import (
    InvestigationRunStore,
    initialize_investigation_store,
)
from c2hunter_controller.schemas import AnalysisParameters, FlowRecord
from tests import test_ai_investigation_evidence as fixtures
from tests.test_ai_investigation_evidence import read

repo = fixtures.repo


def producer_row(**updates):
    data = dict(
        sensor_id="s1",
        timestamp="2026-01-01T00:00:00Z",
        source_ip="10.0.0.1",
        destination_ip="203.0.113.1",
        protocol="UDP",
        direction="OUTBOUND",
        total_bytes=80,
    )
    data.update(updates)
    return FlowRecord.model_validate(data).model_dump(mode="json")


def producer_job(rows, module="c2"):
    return dict(
        id="job",
        dataset_id="dataset",
        parent_job_id=None,
        status="COMPLETED",
        analysis=AnalysisParameters(module=module).model_dump(mode="json"),
        flow_records=rows,
    )


def go_rows():
    path = Path(__file__).parent / "fixtures/ai_investigation_producers/go-producer-wire.json"
    return [
        FlowRecord.model_validate(row).model_dump(mode="json")
        for row in json.loads(path.read_text())["flows"]
    ]


def pcap_row(*, protocol=6, flags=2, payload=b"", inbound=False, dport=443, truncated=0):
    from c2hunter_analysis.pcap import parse_pcap

    if protocol == 6:
        transport = (
            struct.pack("!HHIIBBHHH", 50000, dport, 1, 0, 5 << 4, flags, 8192, 0, 0) + payload
        )
    elif protocol == 17:
        transport = struct.pack("!HHHH", 50000, dport, 8 + len(payload), 0) + payload
    else:
        transport = payload
    src, dst = bytes((10, 0, 0, 1)), bytes((203, 0, 113, 1))
    if inbound:
        src, dst = dst, src
    frame = (
        bytes.fromhex("00112233445566778899aabb0800")
        + struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 1, 0, 64, protocol, 0, src, dst
        )
        + transport
    )
    captured = frame[:-truncated] if truncated else frame
    wire = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    wire += struct.pack("<IIII", 1767225600, 0, len(captured), len(frame)) + captured
    parsed = parse_pcap(
        wire,
        sensor_id="s1",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_network_evidence=True,
    )
    assert len(parsed.records) == 1
    return FlowRecord.model_validate(parsed.records[0]).model_dump(mode="json")


def test_actual_pcap_protocol_and_optional_text_projection(repo):
    dns = (
        b"\x00\x01\x01\x00\x00\x01" + b"\x00" * 6 + b"\x01*\x07example\x04test\x00\x00\x01\x00\x01"
    )
    rows = [
        pcap_row(protocol=47, payload=b"\x00" * 8),
        pcap_row(protocol=17, dport=53, payload=dns),
        producer_row(protocol="udp", direction="BIDIRECTIONAL"),
        producer_row(domain="outside/text-policy", tls_fingerprint="x" * 129),
    ]
    assert rows[0]["protocol"] == "IP_47" and rows[1]["domain"] == "*.example.test"
    repo.save_job(producer_job(rows))
    snapshot = read(repo)
    assert snapshot.rows[0].protocol == "OTHER"
    assert "protocol" in snapshot.rows[0].unavailable_fields
    assert snapshot.rows[1].domain is None
    assert "domain" in snapshot.rows[1].unavailable_fields
    assert snapshot.rows[2].protocol == "UDP" and snapshot.rows[2].direction == "UNKNOWN"
    assert "direction" in snapshot.rows[2].unavailable_fields
    assert snapshot.rows[3].unavailable_fields == ("domain", "tls_fingerprint")
    for original, projected in zip(rows, snapshot.rows, strict=True):
        assert projected.row_sha256 == digest(original)
        assert "domain" in projected.present_fields
    service = EvidenceService(snapshot, InvestigationScope(target_ip="10.0.0.1"))
    overview = service.call("peer_overview", {})
    metrics = {m.name: m.value for m in overview.metrics}
    assert metrics["internal_rows"] is None and metrics["unknown_rows"] == 1
    assert "SOURCE_FIELDS_UNAVAILABLE" in overview.limitations
    assert len(service.call("peer_flow_samples", {}).samples) == len(rows)


def test_internal_is_legacy_not_flowrecord_direction(repo):
    with pytest.raises(ValueError):
        producer_row(direction="INTERNAL")
    raw = producer_row(direction="UNKNOWN")
    raw["direction"] = "INTERNAL"  # retained legacy compact-row convention only
    repo.save_job(producer_job([raw]))
    assert read(repo).rows[0].direction == "INTERNAL"


def test_actual_complete_packet_control_suppression(repo):
    rows = [
        pcap_row(flags=2),
        pcap_row(flags=1),
        pcap_row(flags=4),
        pcap_row(flags=2, inbound=True),
        pcap_row(flags=16),
        pcap_row(flags=2, payload=b"data"),
        pcap_row(protocol=17, payload=b"hi"),
    ]
    assert all(
        r["payload_length"] is None
        and r["transport_payload_length"] == 0
        and r["packet_evidence_complete"] is True
        for r in rows[:3]
    )
    repo.save_job(producer_job(rows))
    snapshot = read(repo)
    service = EvidenceService(snapshot, InvestigationScope(target_ip="10.0.0.1"))
    evidence = service.call("peer_flow_samples", {})
    assert [s.c2_eligibility for s in evidence.samples] == ["SUPPRESSED_OUTBOUND_CONTROL"] * 3 + [
        "ELIGIBLE"
    ] * 4
    for raw, projected in zip(rows, snapshot.rows, strict=True):
        assert projected.row_sha256 == digest(raw)
    assert all(
        r.payload_length == 0 and r.payload_length_source == "complete_transport_packet"
        for r in snapshot.rows[:3]
    )
    protocols = service.call("peer_protocol_observations", {})
    assert protocols.protocols[0].payload_length_source == "complete_transport_packet"


@pytest.mark.parametrize(
    "update",
    [
        {"packet_evidence_complete": False},
        {"packet_evidence_complete": None},
        {"transport_payload_length": None},
        {"packet_count": 2},
        {"duration_seconds": 1.0},
        {"tcp_flags_observed": False},
    ],
)
def test_transport_zero_requires_complete_single_packet_observation(repo, update):
    raw = pcap_row(flags=2)
    raw.update(update)  # negative consumer witnesses keep all other real fields
    if update.get("packet_evidence_complete", True) is None:
        del raw["packet_evidence_complete"]
    repo.save_job(producer_job([raw]))
    assert read(repo).rows[0].c2_eligibility == "UNAVAILABLE"


def test_actual_truncated_packet_zero_is_not_observed_zero(repo):
    raw = pcap_row(flags=2, payload=b"data", truncated=4)
    assert raw["packet_evidence_complete"] is False and raw["transport_payload_length"] == 0
    repo.save_job(producer_job([raw]))
    assert read(repo).rows[0].c2_eligibility == "UNAVAILABLE"


@pytest.mark.parametrize(
    "field,bad",
    [
        ("transport_payload_length", True),
        ("transport_payload_length", 0.5),
        ("transport_payload_length", "0"),
        ("transport_payload_length", -1),
        ("packet_evidence_complete", 1),
    ],
)
def test_transport_projection_never_coerces_scalars(repo, field, bad):
    raw = pcap_row(flags=2)
    raw[field] = bad
    repo.save_job(producer_job([raw]))
    with pytest.raises(InvestigationError, match="SOURCE_INVALID"):
        read(repo)


def test_rejects_invented_and_unrelated_analysis_modules(repo):
    for module in ("network", "ddos", "other"):
        with pytest.raises(ValueError):
            AnalysisParameters(module=module)
        raw = producer_job([producer_row()])
        raw["analysis"]["module"] = module
        repo.save_job(raw)
        with pytest.raises(InvestigationError, match="SOURCE_UNAVAILABLE"):
            read(repo)


@pytest.mark.parametrize(
    "field,value",
    [
        ("protocol", "IP_256"),
        ("protocol", "IP_047"),
        ("protocol", 17),
        ("protocol", "SQL"),
        ("direction", "inbound"),
        ("domain", True),
        ("tls_fingerprint", 17),
        ("certificate_fingerprint", {}),
    ],
)
def test_projection_retains_strict_scalar_admission(repo, field, value):
    raw = producer_row()
    raw[field] = value
    repo.save_job(producer_job([raw]))
    with pytest.raises(InvestigationError, match="SOURCE_INVALID"):
        read(repo)


def test_raw_presence_and_commitment_survive_redaction(repo):
    raw = producer_row(domain="*.example.test")
    del raw["certificate_fingerprint"]
    repo.save_job(producer_job([raw]))
    snapshot = read(repo)
    projected = snapshot.rows[0]
    assert projected.domain is None and "domain" in projected.present_fields
    assert projected.tls_fingerprint is None and "tls_fingerprint" in projected.present_fields
    assert "certificate_fingerprint" not in projected.present_fields
    raw["domain"] = "*.different.test"
    repo.save_job(producer_job([raw]))
    with pytest.raises(InvestigationError, match="SOURCE_CHANGED"):
        read(repo, expected_source_sha256=snapshot.binding.source_sha256)
    assert projected.row_sha256 != digest(raw)


def test_payload_fallback_does_not_invent_original_presence(repo):
    raw = pcap_row(flags=2)
    del raw["payload_length"]
    repo.save_job(producer_job([raw]))
    projected = read(repo).rows[0]
    assert projected.payload_length == 0
    assert projected.payload_length_source == "complete_transport_packet"
    assert "payload_length" not in projected.present_fields
    assert projected.row_sha256 == digest(raw)


def test_actual_go_wire_flags_projection(repo):
    rows = go_rows()
    assert [len(row["tcp_flags"]) for row in rows] == [10, 9]
    repo.save_job(producer_job(rows))
    snapshot = read(repo)
    tcp, udp = snapshot.rows
    assert {f.name: f.count for f in tcp.tcp_flags} == {
        k: rows[0]["tcp_flags"][k] for k in ("syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr")
    }
    assert udp.tcp_flags is None
    for raw, projected in zip(rows, snapshot.rows, strict=True):
        assert projected.row_sha256 == digest(raw)
        assert "tcp_flags" in projected.present_fields


def test_schema_auxiliary_flags_are_not_packet_counters(repo):
    raw = producer_row(
        protocol="TCP",
        tcp_flags_observed=True,
        tcp_flags={
            "syn": 1,
            "ns": 1,
            "rst_ratio": 0.5,
            "connection_count": 1,
            "syn_ack_ratio": 0.25,
            "future_counter": 2,
        },
    )
    repo.save_job(producer_job([raw]))
    projected = read(repo).rows[0]
    assert [(f.name, f.count) for f in projected.tcp_flags] == [("syn", 1)]
    assert projected.row_sha256 == digest(raw)
    raw["tcp_flags_observed"] = False
    repo.save_job(producer_job([raw]))
    assert read(repo).rows[0].tcp_flags is None


@pytest.mark.parametrize("bad", [True, 0.5, 1.0, "1", -1, 2**40])
def test_raw_flag_counts_never_coerced(repo, bad):
    raw = producer_row(protocol="TCP", tcp_flags_observed=True, tcp_flags={"syn": 1})
    raw["tcp_flags"]["syn"] = bad  # corrupt after actual serializer
    repo.save_job(producer_job([raw]))
    with pytest.raises(InvestigationError, match="SOURCE_INVALID"):
        read(repo)


def test_persisted_actual_source_roundtrip_and_deleted_source_replay(repo):
    repo.save_job(producer_job(go_rows()))
    original = read(repo)
    wire = canonical_bytes(original.model_dump(mode="json"))
    assert len(wire) <= 131072
    initialize_investigation_store(repo)
    store = InvestigationRunStore(repo, clock=lambda: 1000.0)
    run, created = store.admit(
        owner_id="alice",
        job_id="job",
        idempotency_key="producer",
        request_json=b"{}",
        binding_json=canonical_bytes(original.binding.model_dump(mode="json")),
        snapshot_json=wire,
    )
    assert created
    saved = store.saved_input("alice", "job", run["id"])
    restored = SourceSnapshot.model_validate_json(saved["snapshot_json"])
    assert restored == original
    assert canonical_bytes(restored.model_dump(mode="json")) == wire
    assert type(restored.rows) is tuple and type(restored.rows[0].tcp_flags) is tuple
    assert type(restored.rows[0].present_fields) is tuple
    with pytest.raises(ValueError):
        SourceSnapshot.model_validate(json.loads(wire))
    scope = InvestigationScope(target_ip="10.0.0.1")
    service = EvidenceService(restored, scope)
    evidence = service.call("peer_flow_samples", {})
    claim = store.reserve(store.claim("worker"), tool_calls=1)
    store.save_evidence(claim, "samples", canonical_bytes(evidence.model_dump(mode="json")))
    repo.delete_job("job")
    assert repo.get_job("job") is None
    replay = store.lookup(
        owner_id="alice", job_id="job", idempotency_key="producer", request_json=b"{}"
    )
    assert replay["id"] == run["id"]
    again = SourceSnapshot.model_validate_json(
        store.saved_input("alice", "job", run["id"])["snapshot_json"]
    )
    assert EvidenceService(again, scope).call("peer_flow_samples", {}) == evidence
    assert store.evidence("alice", "job", run["id"], "samples") == evidence.model_dump(mode="json")
    for value in (True, "1", 1.5, -1):
        bad = json.loads(wire)
        bad["rows"][0]["tcp_flags"][0]["count"] = value
        with pytest.raises(ValueError):
            SourceSnapshot.model_validate_json(canonical_bytes(bad))
    for changed in (
        restored.model_copy(update={"rows": tuple(reversed(restored.rows))}),
        restored.model_copy(
            update={
                "rows": (
                    restored.rows[0].model_copy(update={"total_bytes": True}),
                    *restored.rows[1:],
                )
            }
        ),
        restored.model_copy(
            update={
                "rows": (
                    restored.rows[0].model_copy(update={"total_bytes": 999}),
                    *restored.rows[1:],
                )
            }
        ),
    ):
        with pytest.raises(ValueError):
            EvidenceService(changed, scope)
