from __future__ import annotations

import ast
import hashlib
import io
import ipaddress
import struct
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from c2hunter_analysis.pcap_export import open_export_capture
from c2hunter_analysis.pcap_index import scan_structural_packet_index
from c2hunter_analysis.pcap_postings import PostingQueryLimits

from c2hunter_controller.api_errors import ApiError
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap import CompiledPacketPredicate, compile_packet_predicate
from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    IndexAvailability,
    SourceIndexBinding,
    StructuralIndexLookup,
    StructuralIndexSnapshot,
    structural_index_digest,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexIdentityLookup,
    PostingIndexLookup,
    PostingIndexSnapshot,
    build_source_posting_index,
    posting_index_identity,
)
from c2hunter_controller.pcap_posting_selection import (
    AnalysisPostingCandidateSet,
    PostingPacketCandidate,
    select_analysis_posting_candidates,
)


def _udp_packet(source: str, destination: str, source_port: int, destination_port: int) -> bytes:
    payload = b"same-payload"
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return bytes.fromhex("0200000000020200000000010800") + ipv4 + udp


def _capture(
    *packets: bytes,
    timestamps: tuple[tuple[int, int], ...] | None = None,
) -> bytes:
    header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1)
    record_timestamps = timestamps or ((1_700_000_000, 123),) * len(packets)
    assert len(record_timestamps) == len(packets)
    records = b"".join(
        struct.pack("<IIII", seconds, micros, len(packet), len(packet)) + packet
        for packet, (seconds, micros) in zip(packets, record_timestamps, strict=True)
    )
    return header + records


@dataclass
class _IndexedSource:
    version: CaptureSourceVersion
    parent: StructuralIndexSnapshot
    posting: PostingIndexSnapshot
    capture: bytes


class _VersionedCapture(io.BytesIO):
    def __init__(self, content: bytes, version_id: str) -> None:
        super().__init__(content)
        self.version_id = version_id


def _indexed_source(source_kind: str, source_id: str, capture: bytes) -> _IndexedSource:
    digest = hashlib.sha256(capture).hexdigest()
    version = CaptureSourceVersion(
        source_kind,
        source_id,
        f"objects/{source_id}.pcap",
        f"version:{source_id}",
        len(capture),
        digest,
    )
    scan = scan_structural_packet_index(io.BytesIO(capture), max_packets=100, max_interfaces=4)
    binding = SourceIndexBinding(
        source_kind,
        source_id,
        version.source_version_id,
        len(capture),
        digest,
        "PCAP",
    )
    parent = StructuralIndexSnapshot(
        f"structural:{source_id}",
        binding,
        datetime.now(UTC),
        structural_index_digest(binding, scan.interfaces, scan.packets),
        scan.interfaces,
        scan.packets,
    )
    posting = build_source_posting_index(
        _VersionedCapture(capture, version.source_version_id),
        source_version=version,
        parent=parent,
        internal_networks=["10.0.0.0/8"],
        build_id=f"posting:{source_id}",
    )
    return _IndexedSource(version, parent, posting, capture)


class _FacadeRepository:
    def __init__(self, job: dict[str, Any], sources: list[tuple[_IndexedSource, str]]) -> None:
        self.jobs = {str(job["id"]): job}
        self.sources = {item.version.source_id: item for item, _sensor in sources}
        self.sensors = {item.version.source_id: sensor for item, sensor in sources}
        self.candidates: dict[str, tuple[str, dict[str, Any]]] = {}
        self.snapshot_calls: list[tuple[str, dict[str, Any], dict[str, int]]] = []
        self.source_lookup_calls = 0
        self.posting_lookup_limits: list[PostingQueryLimits | None] = []
        self.posting_identity_lookup_calls: list[
            tuple[CaptureSourceVersion, StructuralIndexSnapshot]
        ] = []
        manifest = [
            {
                "order": order,
                "id": item.version.source_id,
                "sensor_id": sensor,
                "version_id": item.version.source_version_id,
                "size_bytes": item.version.source_size_bytes,
                "sha256": item.version.source_sha256,
            }
            for order, (item, sensor) in enumerate(sources)
        ]
        self.snapshot = {
            "source_job_id": str(job["id"]),
            "provenance_job_ids": [str(job["id"])],
            "source_generation": "f" * 64,
            "source_kind": (
                "canonical_capture" if job["mode"] == "PCAP_UPLOAD" else "segment_manifest"
            ),
            "source_manifest": manifest,
        }

    def get_job_summary(self, job_id: str) -> dict[str, Any] | None:
        return self.jobs.get(job_id)

    def get_candidate(self, candidate_id: str) -> tuple[str, dict[str, Any]] | None:
        return self.candidates.get(candidate_id)

    def snapshot_pcap_export_source(
        self,
        job_id: str,
        canonical_request: dict[str, Any],
        effective_limits: dict[str, int],
    ) -> dict[str, Any] | None:
        self.snapshot_calls.append((job_id, canonical_request, effective_limits))
        return self.snapshot

    def get_capture_source_version(self, source_id: str) -> CaptureSourceVersion | None:
        self.source_lookup_calls += 1
        source = self.sources.get(source_id)
        return source.version if source else None

    def get_live_capture_source_version(self, source_id: str) -> CaptureSourceVersion | None:
        return self.get_capture_source_version(source_id)

    def get_structural_index(self, binding: SourceIndexBinding) -> StructuralIndexLookup:
        source = self.sources.get(binding.source_id)
        if source is None:
            return StructuralIndexLookup(IndexAvailability.MISSING)
        if binding != source.parent.binding:
            return StructuralIndexLookup(IndexAvailability.MISSING)
        return StructuralIndexLookup(IndexAvailability.READY, source.parent)

    def get_posting_index(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        limits: PostingQueryLimits | None = None,
    ) -> PostingIndexLookup:
        self.posting_lookup_limits.append(limits)
        source = self.sources.get(source_version.source_id)
        if source is None:
            return PostingIndexLookup(PostingIndexAvailability.MISSING)
        if source_version != source.version or parent != source.parent:
            return PostingIndexLookup(PostingIndexAvailability.STALE)
        return PostingIndexLookup(PostingIndexAvailability.READY, source.posting)

    def get_posting_index_identity(
        self,
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
    ) -> PostingIndexIdentityLookup:
        self.posting_identity_lookup_calls.append((source_version, parent))
        source = self.sources.get(source_version.source_id)
        if source is None:
            return PostingIndexIdentityLookup(PostingIndexAvailability.MISSING)
        if source_version != source.version or parent != source.parent:
            return PostingIndexIdentityLookup(PostingIndexAvailability.STALE)
        return PostingIndexIdentityLookup(
            PostingIndexAvailability.READY,
            posting_index_identity(source.posting),
        )


def _job(job_id: str = "upload") -> dict[str, Any]:
    return {
        "id": job_id,
        "mode": "PCAP_UPLOAD",
        "status": "COMPLETED",
        "internal_networks": ["10.0.0.0/8"],
    }


def _sequential_matches(
    source: _IndexedSource,
    predicate: CompiledPacketPredicate,
    *,
    source_order: int,
    sensor_id: str,
) -> tuple[int, ...]:
    decoder = open_export_capture(
        io.BytesIO(source.capture),
        source_id=source.version.source_id,
        source_order=source_order,
        internal_networks=["10.0.0.0/8"],
    )
    return tuple(
        packet.locator.packet_index
        for packet in decoder.iter_packets()
        if predicate.matches(packet, sensor_id=sensor_id)
    )


def _assert_sequential_oracle_is_covered(
    selected: AnalysisPostingCandidateSet,
    sources: list[tuple[_IndexedSource, str]],
    request: dict[str, Any],
) -> None:
    predicate = compile_packet_predicate(request, internal_networks=["10.0.0.0/8"])
    assert isinstance(predicate, CompiledPacketPredicate)
    actual = [(item.source_order, item.packet_index) for item in selected.candidates]
    assert actual == sorted(set(actual))
    for source_order, (source, sensor_id) in enumerate(sources):
        source_actual = {
            item.packet_index for item in selected.candidates if item.source_order == source_order
        }
        assert all(
            0 <= ordinal < source.posting.generation.packet_count for ordinal in source_actual
        )
        expected = _sequential_matches(
            source,
            predicate,
            source_order=source_order,
            sensor_id=sensor_id,
        )
        assert set(expected) <= source_actual


def test_upload_returns_typed_offset_free_candidates_and_exact_settings_limits() -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "upload",
        _capture(
            _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
            _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 53),
        ),
    )
    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    settings = Settings(
        environment="test",
        pcap_posting_index_query_max_operations=101,
        pcap_posting_index_query_max_result_ordinals=102,
        pcap_posting_index_query_max_decoded_memberships=103,
        pcap_posting_index_query_max_directory_chunks=104,
        pcap_posting_index_query_max_dictionary_terms=105,
    )

    selected = select_analysis_posting_candidates(
        repository,
        settings,
        job_id="upload",
        canonical_request={"port": 443},
    )

    assert selected == AnalysisPostingCandidateSet(
        source_generation="f" * 64,
        candidates=(
            PostingPacketCandidate(
                source_order=0,
                source_kind="PCAP_UPLOAD",
                source_id="upload",
                parent_structural_build_id="structural:upload",
                packet_index=0,
            ),
        ),
    )
    assert set(PostingPacketCandidate.__dataclass_fields__) == {
        "source_order",
        "source_kind",
        "source_id",
        "parent_structural_build_id",
        "packet_index",
    }
    assert repository.snapshot_calls == [
        (
            "upload",
            {"port": 443},
            {
                "scan_max_bytes": settings.pcap_export_scan_max_bytes,
                "scan_max_packets": settings.pcap_export_scan_max_packets,
            },
        )
    ]


def test_missing_job_and_incomplete_live_raise_export_stable_errors() -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "missing",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    repository = _FacadeRepository(_job("known"), [(source, "uploaded")])
    with pytest.raises(ApiError) as missing:
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="absent",
            canonical_request={},
        )
    assert (missing.value.status, missing.value.code) == (404, "JOB_NOT_FOUND")

    live = {**_job("live"), "mode": "LIVE", "status": "RUNNING"}
    live_repository = _FacadeRepository(live, [])
    with pytest.raises(ApiError) as incomplete:
        select_analysis_posting_candidates(
            live_repository,
            Settings(environment="test"),
            job_id="live",
            canonical_request={},
        )
    assert (incomplete.value.status, incomplete.value.code) == (409, "PCAP_SOURCE_NOT_FINAL")
    assert live_repository.snapshot_calls == []


def test_candidate_owner_is_requested_job_and_candidate_ip_is_compiled_and_snapshotted() -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "upload",
        _capture(
            _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
            _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 443),
        ),
    )
    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    repository.candidates["owned"] = ("upload", {"candidate_ip": "203.0.113.9"})
    repository.candidates["foreign"] = ("other", {"candidate_ip": "203.0.113.8"})

    for candidate_id in ("missing", "foreign"):
        with pytest.raises(ApiError) as raised:
            select_analysis_posting_candidates(
                repository,
                Settings(environment="test"),
                job_id="upload",
                canonical_request={"port": 443},
                candidate_id=candidate_id,
            )
        assert (raised.value.status, raised.value.code) == (404, "CANDIDATE_NOT_FOUND")

    selected = select_analysis_posting_candidates(
        repository,
        Settings(environment="test"),
        job_id="upload",
        canonical_request={"port": 443},
        candidate_id="owned",
    )
    assert selected is not None
    assert [(item.source_order, item.packet_index) for item in selected.candidates] == [(0, 1)]
    assert repository.snapshot_calls[-1][1] == {
        "port": 443,
        "candidate_ip": "203.0.113.9",
    }


def test_upload_sequential_oracle_covers_scalar_groups_candidate_and_exact_empty() -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "upload-oracle",
        _capture(
            _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
            _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 53),
            _udp_packet("198.51.100.7", "10.0.0.3", 8443, 50_002),
        ),
    )
    sources = [(source, "uploaded")]
    cases = [
        ({"port": 443}, None, {"port": 443}),
        (
            {
                "include_filters": [{"candidate_ip": "203.0.113.0/24", "protocol": "udp"}],
                "exclude_filters": [{"destination_port": 53}],
            },
            None,
            {
                "include_filters": [{"candidate_ip": "203.0.113.0/24", "protocol": "udp"}],
                "exclude_filters": [{"destination_port": 53}],
            },
        ),
        (
            {"protocol": "udp"},
            "owned",
            {"protocol": "udp", "candidate_ip": "203.0.113.8"},
        ),
        ({"port": 1}, None, {"port": 1}),
    ]
    for request, candidate_id, oracle_request in cases:
        repository = _FacadeRepository(_job("upload-oracle"), sources)
        repository.candidates["owned"] = (
            "upload-oracle",
            {"candidate_ip": "203.0.113.8"},
        )
        selected = select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="upload-oracle",
            canonical_request=request,
            candidate_id=candidate_id,
        )
        assert selected is not None
        _assert_sequential_oracle_is_covered(selected, sources, oracle_request)
        if request == {"port": 1}:
            assert selected.candidates == ()


def test_live_multisegment_sequential_oracle_preserves_local_ordinals_despite_timestamps() -> None:
    first = _indexed_source(
        "LIVE_SEGMENT",
        "segment-first",
        _capture(
            _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
            _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 443),
            _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
            timestamps=((1_700_000_003, 7), (1_700_000_003, 7), (1_700_000_002, 9)),
        ),
    )
    second = _indexed_source(
        "LIVE_SEGMENT",
        "segment-second",
        _capture(
            _udp_packet("10.0.0.3", "203.0.113.10", 50_002, 443),
            _udp_packet("10.0.0.4", "203.0.113.8", 50_003, 443),
            timestamps=((1_700_000_002, 9), (1_700_000_004, 1)),
        ),
    )
    sources = [(first, "sensor-a"), (second, "sensor-b")]
    request = {
        "port": 443,
        "include_filters": [{"protocol": "udp"}],
        "exclude_filters": [{"candidate_ip": "203.0.113.9"}],
    }
    job = {**_job("live-oracle"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _FacadeRepository(job, sources)

    selected = select_analysis_posting_candidates(
        repository,
        Settings(environment="test"),
        job_id="live-oracle",
        canonical_request=request,
    )

    assert selected is not None
    _assert_sequential_oracle_is_covered(selected, sources, request)


def test_live_manifest_order_sensor_scope_and_segment_local_index_reset() -> None:
    duplicate = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "segment-z", _capture(duplicate, duplicate))
    second = _indexed_source("LIVE_SEGMENT", "segment-a", _capture(duplicate, duplicate))
    job = {**_job("live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _FacadeRepository(job, [(first, "sensor-a"), (second, "sensor-b")])

    selected = select_analysis_posting_candidates(
        repository,
        Settings(environment="test"),
        job_id="live",
        canonical_request={"sensor_id": "sensor-b"},
    )

    assert selected is not None
    assert [
        (item.source_order, item.source_id, item.packet_index) for item in selected.candidates
    ] == [(1, "segment-a", 0), (1, "segment-a", 1)]
    assert all(item.source_kind == "LIVE_SEGMENT" for item in selected.candidates)


def test_historical_and_reanalysis_depth_two_use_retained_ancestor_without_child_refs() -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "ancestor",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    for mode in ("HISTORICAL", "REANALYSIS"):
        requested = {**_job(f"child-{mode}"), "mode": mode, "parent_job_id": "middle"}
        repository = _FacadeRepository(requested, [(source, "uploaded")])
        repository.snapshot.update(
            {
                "source_job_id": "ancestor",
                "provenance_job_ids": [f"child-{mode}", "middle", "ancestor"],
                "source_kind": "canonical_capture",
            }
        )

        selected = select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id=f"child-{mode}",
            canonical_request={},
        )

        assert selected is not None
        assert {item.source_id for item in selected.candidates} == {"ancestor"}
        assert all(
            item.source_id not in {f"child-{mode}", "middle"} for item in selected.candidates
        )


def test_snapshot_cycle_and_missing_ancestor_are_typed_provenance_errors() -> None:
    repository = _FacadeRepository(_job(), [])

    for cause in ("source_provenance_cycle", "source_provenance_missing"):

        def invalid_snapshot(*_args: Any, _cause: str = cause, **_kwargs: Any) -> None:
            raise ValueError(_cause)

        repository.snapshot_pcap_export_source = invalid_snapshot  # type: ignore[method-assign]
        with pytest.raises(ApiError) as raised:
            select_analysis_posting_candidates(
                repository,
                Settings(environment="test"),
                job_id="upload",
                canonical_request={},
            )
        assert (raised.value.status, raised.value.code) == (
            409,
            "PCAP_SOURCE_PROVENANCE_INVALID",
        )


def test_missing_stale_corrupt_and_unsupported_structural_or_posting_fall_back_whole_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _indexed_source(
        "LIVE_SEGMENT",
        "first",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    second = _indexed_source(
        "LIVE_SEGMENT",
        "second",
        _capture(_udp_packet("10.0.0.2", "203.0.113.9", 50_001, 443)),
    )
    job = {**_job("live"), "mode": "LIVE", "status": "COMPLETED"}

    for structural_availability in (
        IndexAvailability.MISSING,
        IndexAvailability.STALE,
        IndexAvailability.CORRUPT,
        IndexAvailability.UNSUPPORTED_SCHEMA,
    ):
        repository = _FacadeRepository(job, [(first, "one"), (second, "two")])
        original = repository.get_structural_index

        def structural(
            binding: SourceIndexBinding,
            _availability: IndexAvailability = structural_availability,
            _original: Any = original,
        ) -> StructuralIndexLookup:
            if binding.source_id == "second":
                return StructuralIndexLookup(_availability)
            return _original(binding)

        monkeypatch.setattr(repository, "get_structural_index", structural)
        assert (
            select_analysis_posting_candidates(
                repository,
                Settings(environment="test"),
                job_id="live",
                canonical_request={},
            )
            is None
        )

    for posting_availability in (
        PostingIndexAvailability.MISSING,
        PostingIndexAvailability.STALE,
        PostingIndexAvailability.CORRUPT,
        PostingIndexAvailability.UNSUPPORTED_SCHEMA,
    ):
        repository = _FacadeRepository(job, [(first, "one"), (second, "two")])
        original_posting = repository.get_posting_index

        def posting(
            source_version: CaptureSourceVersion,
            parent: StructuralIndexSnapshot,
            limits: PostingQueryLimits | None = None,
            _availability: PostingIndexAvailability = posting_availability,
            _original: Any = original_posting,
        ) -> PostingIndexLookup:
            if source_version.source_id == "second":
                return PostingIndexLookup(_availability)
            return _original(source_version, parent, limits)

        monkeypatch.setattr(repository, "get_posting_index", posting)
        assert (
            select_analysis_posting_candidates(
                repository,
                Settings(environment="test"),
                job_id="live",
                canonical_request={},
            )
            is None
        )

    repository = _FacadeRepository(job, [(first, "one"), (second, "two")])
    corrupt = replace(
        second.posting,
        generation=replace(second.posting.generation, digest="0" * 64),
    )
    original_posting = repository.get_posting_index

    def ready_but_invalid(
        source_version: CaptureSourceVersion,
        parent: StructuralIndexSnapshot,
        limits: PostingQueryLimits | None = None,
    ) -> PostingIndexLookup:
        if source_version.source_id == "second":
            return PostingIndexLookup(PostingIndexAvailability.READY, corrupt)
        return original_posting(source_version, parent, limits)

    monkeypatch.setattr(repository, "get_posting_index", ready_but_invalid)
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="live",
            canonical_request={},
        )
        is None
    )


@pytest.mark.parametrize("field", ["version_id", "size_bytes", "sha256"])
def test_manifest_mismatch_and_source_deletion_fall_back(field: str) -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "upload",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    repository.snapshot["source_manifest"][0][field] = (
        "0" * 64 if field == "sha256" else 0 if field == "size_bytes" else "replacement"
    )
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="upload",
            canonical_request={},
        )
        is None
    )


def test_exact_empty_is_not_fallback_but_empty_or_unsupported_source_view_is() -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "upload",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    selected = select_analysis_posting_candidates(
        repository,
        Settings(environment="test"),
        job_id="upload",
        canonical_request={"port": 1},
    )
    assert selected is not None and selected.candidates == ()

    for source_kind in ("legacy_inline", "unknown"):
        unavailable = _FacadeRepository(_job(), [])
        unavailable.snapshot["source_kind"] = source_kind
        assert (
            select_analysis_posting_candidates(
                unavailable,
                Settings(environment="test"),
                job_id="upload",
                canonical_request={},
            )
            is None
        )


def test_manifest_source_count_bound_rejects_before_any_per_source_work() -> None:
    repository = _FacadeRepository(
        {**_job("bounded-live"), "mode": "LIVE", "status": "COMPLETED"},
        [],
    )
    repository.snapshot["source_manifest"] = [
        {"order": order, "id": f"segment-{order}"} for order in range(3)
    ]

    selected = select_analysis_posting_candidates(
        repository,
        Settings(environment="test", pcap_export_scan_max_packets=1_000),
        job_id="bounded-live",
        canonical_request={},
        max_sources=2,
    )

    assert selected is None
    assert repository.source_lookup_calls == 0


def test_multisource_global_candidate_budget_never_returns_per_source_product() -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "budget-first", _capture(packet, packet, packet))
    second = _indexed_source("LIVE_SEGMENT", "budget-second", _capture(packet, packet, packet))
    repository = _FacadeRepository(
        {**_job("budget-live"), "mode": "LIVE", "status": "COMPLETED"},
        [(first, "one"), (second, "two")],
    )

    selected = select_analysis_posting_candidates(
        repository,
        Settings(
            environment="test",
            pcap_posting_index_query_max_operations=100,
            pcap_posting_index_query_max_result_ordinals=3,
            pcap_posting_index_query_max_decoded_memberships=100,
            pcap_posting_index_query_max_directory_chunks=100,
            pcap_posting_index_query_max_dictionary_terms=100,
        ),
        job_id="budget-live",
        canonical_request={},
    )

    assert selected is None or len(selected.candidates) <= 3
    assert selected is None, "unsafe truncation must fall back instead of looking exact"


def test_multisource_query_budgets_are_preallocated_once_and_globally_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _indexed_source(
        "LIVE_SEGMENT",
        "allocated-first",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    second = _indexed_source(
        "LIVE_SEGMENT",
        "allocated-second",
        _capture(_udp_packet("10.0.0.2", "203.0.113.9", 50_001, 443)),
    )
    repository = _FacadeRepository(
        {**_job("allocated-live"), "mode": "LIVE", "status": "COMPLETED"},
        [(first, "one"), (second, "two")],
    )
    selector_limits: list[PostingQueryLimits] = []

    def exact_empty(*_args: Any, **kwargs: Any) -> tuple[int, ...]:
        selector_limits.append(kwargs["limits"])
        return ()

    monkeypatch.setattr(
        "c2hunter_controller.pcap_posting_selection.select_posting_candidates", exact_empty
    )
    global_limits = {
        "max_operations": 11,
        "max_result_ordinals": 7,
        "max_decoded_memberships": 9,
        "max_directory_chunks": 5,
        "max_dictionary_terms": 3,
    }
    settings = Settings(
        environment="test",
        **{f"pcap_posting_index_query_{name}": value for name, value in global_limits.items()},
    )

    selected = select_analysis_posting_candidates(
        repository,
        settings,
        job_id="allocated-live",
        canonical_request={"port": 1},
    )

    assert selected is not None and selected.candidates == ()
    assert len(selector_limits) == 2
    assert repository.posting_lookup_limits == selector_limits
    assert [limits.max_directory_chunks for limits in repository.posting_lookup_limits] == [3, 2]
    assert len(repository.posting_identity_lookup_calls) == 2
    assert (
        sum(
            limits.max_directory_chunks
            for limits in repository.posting_lookup_limits
            if limits is not None
        )
        <= 5
    )
    for field, ceiling in global_limits.items():
        assigned = [getattr(limits, field) for limits in selector_limits]
        assert all(value > 0 for value in assigned)
        assert sum(assigned) <= ceiling
    assert [limits.max_dictionary_terms for limits in selector_limits] == [2, 1]


@pytest.mark.parametrize(
    "setting",
    [
        "pcap_posting_index_query_max_operations",
        "pcap_posting_index_query_max_result_ordinals",
        "pcap_posting_index_query_max_decoded_memberships",
        "pcap_posting_index_query_max_directory_chunks",
        "pcap_posting_index_query_max_dictionary_terms",
    ],
)
def test_indivisible_global_budget_rejects_before_any_source_lookup(setting: str) -> None:
    repository = _FacadeRepository(
        {**_job("indivisible-live"), "mode": "LIVE", "status": "COMPLETED"}, []
    )
    repository.snapshot["source_manifest"] = [
        {"order": order, "id": f"segment-{order}"} for order in range(2)
    ]

    selected = select_analysis_posting_candidates(
        repository,
        Settings(environment="test", **{setting: 1}),
        job_id="indivisible-live",
        canonical_request={},
    )

    assert selected is None
    assert repository.source_lookup_calls == 0


def test_selector_receives_exact_query_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "limits",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    repository = _FacadeRepository(_job("limits"), [(source, "uploaded")])
    observed: list[Any] = []

    def bounded_selector(*_args: Any, **kwargs: Any) -> tuple[int, ...]:
        observed.append(kwargs["limits"])
        return ()

    monkeypatch.setattr(
        "c2hunter_controller.pcap_posting_selection.select_posting_candidates",
        bounded_selector,
    )
    settings = Settings(
        environment="test",
        pcap_posting_index_query_max_operations=201,
        pcap_posting_index_query_max_result_ordinals=202,
        pcap_posting_index_query_max_decoded_memberships=203,
        pcap_posting_index_query_max_directory_chunks=204,
        pcap_posting_index_query_max_dictionary_terms=205,
    )

    selected = select_analysis_posting_candidates(
        repository,
        settings,
        job_id="limits",
        canonical_request={},
    )

    assert selected is not None
    assert len(observed) == 1
    assert observed[0].max_operations == 201
    assert observed[0].max_result_ordinals == 202
    assert observed[0].max_decoded_memberships == 203
    assert observed[0].max_directory_chunks == 204
    assert observed[0].max_dictionary_terms == 205


def test_source_count_and_selector_query_caps_return_fallback() -> None:
    first = _indexed_source(
        "LIVE_SEGMENT",
        "first",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    second = _indexed_source(
        "LIVE_SEGMENT",
        "second",
        _capture(_udp_packet("10.0.0.2", "203.0.113.9", 50_001, 443)),
    )
    job = {**_job("live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _FacadeRepository(job, [(first, "one"), (second, "two")])
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test", pcap_export_scan_max_packets=1),
            job_id="live",
            canonical_request={},
        )
        is None
    )

    # Use the regular upload fixture for a real selector budget rejection.
    upload = _indexed_source(
        "PCAP_UPLOAD",
        "upload",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )
    one = _FacadeRepository(_job(), [(upload, "uploaded")])
    assert (
        select_analysis_posting_candidates(
            one,
            Settings(environment="test", pcap_posting_index_query_max_operations=1),
            job_id="upload",
            canonical_request={},
        )
        is None
    )


def test_source_parent_and_posting_replacement_during_selection_invalidate_frozen_view(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _indexed_source(
        "PCAP_UPLOAD",
        "upload",
        _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)),
    )

    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    source_reads = 0

    def deleted_after_snapshot(_source_id: str) -> CaptureSourceVersion | None:
        nonlocal source_reads
        source_reads += 1
        return source.version if source_reads == 1 else None

    monkeypatch.setattr(repository, "get_capture_source_version", deleted_after_snapshot)
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="upload",
            canonical_request={},
        )
        is None
    )

    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    parent_reads = 0
    original_parent = repository.get_structural_index

    def replaced_parent(binding: SourceIndexBinding) -> StructuralIndexLookup:
        nonlocal parent_reads
        parent_reads += 1
        if parent_reads == 1:
            return original_parent(binding)
        return StructuralIndexLookup(IndexAvailability.MISSING)

    monkeypatch.setattr(repository, "get_structural_index", replaced_parent)
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="upload",
            canonical_request={},
        )
        is None
    )

    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    replacement = replace(source.posting, build_id="posting:replacement")

    def replaced_posting_identity(
        _source_version: CaptureSourceVersion,
        _parent: StructuralIndexSnapshot,
    ) -> PostingIndexIdentityLookup:
        return PostingIndexIdentityLookup(
            PostingIndexAvailability.READY,
            posting_index_identity(replacement),
        )

    monkeypatch.setattr(repository, "get_posting_index_identity", replaced_posting_identity)
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="upload",
            canonical_request={},
        )
        is None
    )

    repository = _FacadeRepository(_job(), [(source, "uploaded")])
    monkeypatch.setattr(
        repository,
        "get_posting_index_identity",
        lambda *_args: PostingIndexIdentityLookup(PostingIndexAvailability.MISSING),
    )
    assert (
        select_analysis_posting_candidates(
            repository,
            Settings(environment="test"),
            job_id="upload",
            canonical_request={},
        )
        is None
    )


def test_ast_guards_keep_facade_out_of_export_app_writer_and_artifact_modules() -> None:
    source_root = Path(__file__).parents[1] / "src" / "c2hunter_controller"
    protected = sorted(
        path
        for path in source_root.glob("*.py")
        if path.name == "app.py"
        or path.stem.startswith("pcap_export")
        or "writer" in path.stem
        or "artifact" in path.stem
    )
    forbidden_calls = {
        "pcap_posting_selection",
        "select_analysis_posting_candidates",
    }
    violations: list[str] = []
    for path in protected:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.endswith("pcap_posting_selection"):
                        violations.append(f"{path.name}:{node.lineno}:import")
            elif isinstance(node, ast.ImportFrom):
                if (node.module or "").endswith("pcap_posting_selection"):
                    violations.append(f"{path.name}:{node.lineno}:from-import")
                if any(alias.name in forbidden_calls for alias in node.names):
                    violations.append(f"{path.name}:{node.lineno}:symbol-import")
            elif isinstance(node, ast.Call):
                call_name = (
                    node.func.id
                    if isinstance(node.func, ast.Name)
                    else node.func.attr
                    if isinstance(node.func, ast.Attribute)
                    else ""
                )
                if call_name in forbidden_calls:
                    violations.append(f"{path.name}:{node.lineno}:call")
    assert protected
    assert violations == []


def test_facade_candidate_schema_is_content_and_random_access_free() -> None:
    facade = Path(__file__).parents[1] / "src" / "c2hunter_controller" / "pcap_posting_selection.py"
    tree = ast.parse(facade.read_text(encoding="utf-8"), filename=str(facade))
    dataclass_fields: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        if not any(
            (isinstance(decorator, ast.Name) and decorator.id == "dataclass")
            or (
                isinstance(decorator, ast.Call)
                and isinstance(decorator.func, ast.Name)
                and decorator.func.id == "dataclass"
            )
            for decorator in node.decorator_list
        ):
            continue
        dataclass_fields[node.name] = {
            child.target.id
            for child in node.body
            if isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name)
        }
    forbidden_field_fragments = {
        "offset",
        "length",
        "byte_range",
        "raw_content",
        "raw_payload",
        "content_hash",
        "payload_hash",
    }
    assert dataclass_fields == {
        "PostingPacketCandidate": {
            "source_order",
            "source_kind",
            "source_id",
            "parent_structural_build_id",
            "packet_index",
        },
        "AnalysisPostingCandidateSet": {"source_generation", "candidates"},
    }
    assert not {
        field
        for fields in dataclass_fields.values()
        for field in fields
        if any(fragment in field.lower() for fragment in forbidden_field_fragments)
    }
    random_access_names = {
        node.id.lower() for node in ast.walk(tree) if isinstance(node, ast.Name)
    } | {node.attr.lower() for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert random_access_names.isdisjoint({"seek", "range", "coalesce"})


def test_facade_has_no_public_rest_schema_or_openapi_surface() -> None:
    repository_root = Path(__file__).parents[2]
    public_surfaces = [
        repository_root / "controller" / "src" / "c2hunter_controller" / "app.py",
        repository_root / "controller" / "src" / "c2hunter_controller" / "schemas.py",
        repository_root / "web" / "tests" / "controller-openapi.test.ts",
    ]
    forbidden = {
        "analysispostingcandidateset",
        "postingpacketcandidate",
        "select_analysis_posting_candidates",
        "pcap_posting_selection",
        "posting_candidate",
        "posting-candidate",
    }
    references = {
        token
        for path in public_surfaces
        for token in forbidden
        if token in path.read_text(encoding="utf-8").lower()
    }
    assert all(path.is_file() for path in public_surfaces)
    assert references == set()
