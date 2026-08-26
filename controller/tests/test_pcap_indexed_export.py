from __future__ import annotations

import struct
from dataclasses import replace

import pytest
from c2hunter_analysis.pcap import PcapParseError
from test_pcap_posting_selection import (
    _capture,
    _FacadeRepository,
    _indexed_source,
    _job,
    _sequential_matches,
    _udp_packet,
)

from c2hunter_controller import pcap_indexed_export
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap import compile_packet_predicate
from c2hunter_controller.pcap_indexed_export import (
    CaptureRangeMissing,
    CaptureRangeShortRead,
    CaptureRangeUnavailable,
    CaptureRangeVersionDrift,
    IndexedFallback,
    IndexedFallbackReason,
    RangePlanLimits,
    collect_indexed_matches,
    create_indexed_match_factory,
)
from c2hunter_controller.pcap_offset_index import (
    IndexAvailability,
    StructuralIndexIdentityLookup,
)
from c2hunter_controller.pcap_posting_index import (
    PostingIndexAvailability,
    PostingIndexIdentityLookup,
    posting_index_identity,
)
from c2hunter_controller.pcap_posting_selection import (
    _select_analysis_posting_plan_from_snapshot,
)


class _RangeRepository(_FacadeRepository):
    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self.range_calls: list[tuple[str, int, int]] = []

    def read_capture_range(self, source: object, byte_range: object) -> bytes:
        source_id = source.source_id  # type: ignore[attr-defined]
        offset = byte_range.offset  # type: ignore[attr-defined]
        length = byte_range.length  # type: ignore[attr-defined]
        self.range_calls.append((source_id, offset, length))
        return self.sources[source_id].capture[offset : offset + length]


def _limits() -> RangePlanLimits:
    return RangePlanLimits(
        max_gap_bytes=64,
        max_range_bytes=1024,
        max_ranges=8,
        max_total_fetched_bytes=4096,
        max_amplification_numerator=4,
        max_amplification_denominator=1,
        max_source_fraction_numerator=9,
        max_source_fraction_denominator=10,
    )


def test_run_checks_invokes_one_shared_durable_guard_once() -> None:
    calls = 0

    def guard() -> None:
        nonlocal calls
        calls += 1

    pcap_indexed_export._run_checks(guard, guard)

    assert calls == 1


def test_factory_rechecks_shared_guard_after_snapshot_posting_selection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    armed = False

    class StopExport(RuntimeError):
        pass

    def select(*_args: object, **_kwargs: object) -> None:
        nonlocal armed
        armed = True
        return None

    def guard() -> None:
        if armed:
            raise StopExport("selection guard")

    repository = object()
    monkeypatch.setattr(pcap_indexed_export, "_select_analysis_posting_plan_from_snapshot", select)
    factory = create_indexed_match_factory(
        repository,  # type: ignore[arg-type]
        range_limits=_limits(),
        max_sources=1,
    )

    with pytest.raises(StopExport, match="selection guard"):
        factory(
            repository=repository,
            settings=Settings(environment="test"),
            requested_job={},
            source_snapshot={},
            canonical_request={},
            candidate_id=None,
            predicate=compile_packet_predicate({}, internal_networks=[]),
            internal_networks=[],
            scan_max_bytes=1,
            scan_max_packets=1,
            checkpoint=lambda **_progress: None,
            check_cancelled=guard,
            check_deadline=guard,
        )


def _pcapng(*packets: bytes) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * (-len(body) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)

    section = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65_535))
    timestamp = 1_700_000_000_000_123
    enhanced = b"".join(
        block(
            6,
            struct.pack(
                "<IIIII",
                0,
                (timestamp + index) >> 32,
                (timestamp + index) & 0xFFFFFFFF,
                len(packet),
                len(packet),
            )
            + packet,
        )
        for index, packet in enumerate(packets)
    )
    return section + interface + enhanced


def _raw_ipv4_udp_packet(payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", 50_000, 443, 8 + len(payload), 0) + payload
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
        bytes((10, 0, 0, 1)),
        bytes((203, 0, 113, 8)),
    )
    return ipv4 + udp


def _raw_ip_capture(packet: bytes) -> bytes:
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 101)
        + struct.pack("<IIII", 1_700_000_000, 123, len(packet), len(packet))
        + packet
    )


def _live_two_source_case(
    first_packet: bytes, second_packet: bytes
) -> tuple[_RangeRepository, object, dict[str, object]]:
    return _live_two_source_packets_case((first_packet,), (second_packet,))


def _live_two_source_packets_case(
    first_packets: tuple[bytes, ...], second_packets: tuple[bytes, ...]
) -> tuple[_RangeRepository, object, dict[str, object]]:
    def capture(packets: tuple[bytes, ...]) -> bytes:
        header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 101)
        records = b"".join(
            struct.pack("<IIII", 1_700_000_000, index, len(packet), len(packet)) + packet
            for index, packet in enumerate(packets)
        )
        return header + records

    first = _indexed_source("LIVE_SEGMENT", "aggregate-first", capture(first_packets))
    second = _indexed_source("LIVE_SEGMENT", "aggregate-second", capture(second_packets))
    job = {**_job("aggregate-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, [(first, "a"), (second, "b")])
    selection = _select_analysis_posting_plan_from_snapshot(
        repository,
        Settings(environment="test"),
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert selection is not None
    return repository, selection, job


def _collect_live_case(
    repository: _RangeRepository,
    selection: object,
    job: dict[str, object],
    limits: RangePlanLimits,
) -> object:
    return collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=selection,  # type: ignore[arg-type]
        predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),  # type: ignore[arg-type]
        internal_networks=job["internal_networks"],  # type: ignore[arg-type]
        scan_max_bytes=1_000_000,
        scan_max_packets=100,
        range_limits=limits,
    )


@pytest.mark.parametrize(("max_ranges", "accepted"), [(2, True), (1, False)])
def test_request_wide_max_ranges_accepts_exact_two_and_rejects_plus_one_before_any_read(
    max_ranges: int, accepted: bool
) -> None:
    packet = _raw_ipv4_udp_packet(b"aa")
    repository, selection, job = _live_two_source_case(packet, packet)

    if accepted:
        batch = _collect_live_case(
            repository, selection, job, replace(_limits(), max_ranges=max_ranges)
        )
        assert batch.range_count == 2  # type: ignore[attr-defined]
        assert len(repository.range_calls) == 2
    else:
        with pytest.raises(IndexedFallback) as caught:
            _collect_live_case(
                repository, selection, job, replace(_limits(), max_ranges=max_ranges)
            )
        assert caught.value.reason is IndexedFallbackReason.RESOURCE_LIMIT
        assert repository.range_calls == []


@pytest.mark.parametrize(
    ("second_payload", "expected_fetched", "accepted"),
    [(b"bb", 60, True), (b"bbb", 61, False)],
)
def test_request_wide_fetched_bytes_accepts_exact_60_and_rejects_61_before_any_read(
    second_payload: bytes, expected_fetched: int, accepted: bool
) -> None:
    repository, selection, job = _live_two_source_case(
        _raw_ipv4_udp_packet(b"aa"), _raw_ipv4_udp_packet(second_payload)
    )
    limits = replace(_limits(), max_total_fetched_bytes=60)

    if accepted:
        batch = _collect_live_case(repository, selection, job, limits)
        assert batch.fetched_bytes == expected_fetched  # type: ignore[attr-defined]
        assert sum(length for _source, _offset, length in repository.range_calls) == 60
    else:
        with pytest.raises(IndexedFallback) as caught:
            _collect_live_case(repository, selection, job, limits)
        assert caught.value.reason is IndexedFallbackReason.RESOURCE_LIMIT
        assert repository.range_calls == []


@pytest.mark.parametrize("per_source_cap", ["max_range", "source_fraction"])
def test_later_source_per_source_planner_cap_fails_before_first_source_read(
    per_source_cap: str,
) -> None:
    repository, selection, job = _live_two_source_case(
        _raw_ipv4_udp_packet(b"aa"), _raw_ipv4_udp_packet(b"bbb")
    )
    limits = (
        replace(_limits(), max_range_bytes=30)
        if per_source_cap == "max_range"
        else replace(
            _limits(),
            max_source_fraction_numerator=43,
            max_source_fraction_denominator=100,
        )
    )

    with pytest.raises(IndexedFallback) as caught:
        _collect_live_case(repository, selection, job, limits)

    assert caught.value.reason is IndexedFallbackReason.RESOURCE_LIMIT
    assert repository.range_calls == []


@pytest.mark.parametrize(("second_payload", "accepted"), [(b"bb", True), (b"b", False)])
def test_request_wide_amplification_uses_exact_aggregate_rational_without_per_source_rejection(
    second_payload: bytes, accepted: bool
) -> None:
    thirty_byte_packet = _raw_ipv4_udp_packet(b"aa")
    repository, selection, job = _live_two_source_packets_case(
        (thirty_byte_packet, thirty_byte_packet),
        (_raw_ipv4_udp_packet(second_payload),),
    )
    limits = replace(
        _limits(),
        max_amplification_numerator=53,
        max_amplification_denominator=45,
    )

    if accepted:
        batch = _collect_live_case(repository, selection, job, limits)
        assert (batch.fetched_bytes, batch.selected_payload_bytes) == (106, 90)  # type: ignore[attr-defined]
    else:
        with pytest.raises(IndexedFallback) as caught:
            _collect_live_case(repository, selection, job, limits)
        assert caught.value.reason is IndexedFallbackReason.RESOURCE_LIMIT
        assert repository.range_calls == []


@pytest.mark.parametrize("capture_builder", [_capture, _pcapng])
@pytest.mark.parametrize(
    "filters",
    [
        {"candidate_ip": "203.0.113.8"},
        {"internal_host_ip": "10.0.0.2"},
        {"port": 443},
        {"protocol": "udp"},
        {"direction": "OUTBOUND"},
        {"sensor_id": "uploaded"},
        {
            "start_time": "2023-11-14T22:13:20.000123+00:00",
            "end_time": "2023-11-14T22:13:20.000124+00:00",
        },
        {
            "include_filters": [
                {"source_port": 50_000, "protocol": "udp"},
                {"destination_port": 53},
            ],
            "exclude_filters": [{"candidate_ip": "203.0.113.9", "destination_port": 53}],
        },
    ],
)
def test_pcap_and_pcapng_filter_matrix_matches_exact_sequential_oracle(
    capture_builder: object, filters: dict[str, object]
) -> None:
    packets = (
        _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
        _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 53),
    )
    capture = capture_builder(*packets)  # type: ignore[operator]
    source = _indexed_source("PCAP_UPLOAD", "upload", capture)
    job = _job()
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    predicate = compile_packet_predicate(filters, internal_networks=job["internal_networks"])
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=filters,
        candidate_id=None,
    )
    assert plan is not None

    batch = collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=plan,
        predicate=predicate,
        internal_networks=job["internal_networks"],
        scan_max_bytes=settings.pcap_export_scan_max_bytes,
        scan_max_packets=settings.pcap_export_scan_max_packets,
        range_limits=_limits(),
    )

    expected = _sequential_matches(source, predicate, source_order=0, sensor_id="uploaded")
    assert tuple(record.packet_index for record in batch.records) == expected
    assert batch.scanned_packet_count == 2


def test_collects_selected_ranges_and_rechecks_exact_predicate_without_full_reads() -> None:
    capture = _capture(
        _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443),
        _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 53),
    )
    source = _indexed_source("PCAP_UPLOAD", "upload", capture)
    job = _job()
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    request = {"port": 443}
    selected = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=request,
        candidate_id=None,
    )
    assert selected is not None

    batch = collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=selected,
        predicate=compile_packet_predicate(request, internal_networks=job["internal_networks"]),
        internal_networks=job["internal_networks"],
        scan_max_bytes=settings.pcap_export_scan_max_bytes,
        scan_max_packets=settings.pcap_export_scan_max_packets,
        range_limits=_limits(),
    )

    assert [(record.source_order, record.packet_index) for record in batch.records] == [(0, 0)]
    assert batch.scanned_packet_count == 2
    assert batch.scanned_source_bytes == len(capture)
    assert batch.range_count == 1
    assert repository.range_calls == [
        (
            "upload",
            source.parent.packets[0].data_offset,
            source.parent.packets[0].captured_length,
        )
    ]


@pytest.mark.parametrize(
    ("indexed_stage", "expected_range_calls"),
    [("locator_before_range", 0), ("after_ranges", 1), ("predicate_loop", 1)],
)
def test_collector_guard_loss_propagates_at_real_indexed_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    indexed_stage: str,
    expected_range_calls: int,
) -> None:
    capture = _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443))
    source = _indexed_source("PCAP_UPLOAD", "guard-stage", capture)
    job = _job("guard-stage")
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    request = {"port": 443}
    selection = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=request,
        candidate_id=None,
    )
    assert selection is not None
    assert isinstance(settings.pcap_export_scan_max_bytes, int)
    assert isinstance(settings.pcap_export_scan_max_packets, int)
    armed = False

    class StopExport(RuntimeError):
        pass

    def guard() -> None:
        if armed:
            raise StopExport(indexed_stage)

    original_locate = pcap_indexed_export.locate_selected_packets
    original_read = repository.read_capture_range
    compiled = compile_packet_predicate(request, internal_networks=job["internal_networks"])

    def locate(*args: object, **kwargs: object) -> object:
        nonlocal armed
        result = original_locate(*args, **kwargs)  # type: ignore[arg-type]
        if indexed_stage == "locator_before_range":
            armed = True
        return result

    def read(*args: object, **kwargs: object) -> bytes:
        nonlocal armed
        result = original_read(*args, **kwargs)  # type: ignore[arg-type]
        if indexed_stage == "after_ranges":
            armed = True
        return result

    class Predicate:
        def matches(self, *args: object, **kwargs: object) -> bool:
            nonlocal armed
            result = compiled.matches(*args, **kwargs)  # type: ignore[arg-type]
            if indexed_stage == "predicate_loop":
                armed = True
            return result

    monkeypatch.setattr(pcap_indexed_export, "locate_selected_packets", locate)
    monkeypatch.setattr(repository, "read_capture_range", read)

    with pytest.raises(StopExport, match=indexed_stage):
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=selection,
            predicate=Predicate(),  # type: ignore[arg-type]
            internal_networks=job["internal_networks"],
            scan_max_bytes=settings.pcap_export_scan_max_bytes,
            scan_max_packets=settings.pcap_export_scan_max_packets,
            range_limits=_limits(),
            check_cancelled=guard,
            check_deadline=guard,
        )

    assert len(repository.range_calls) == expected_range_calls


def test_no_selected_postings_performs_zero_range_reads() -> None:
    capture = _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443))
    source = _indexed_source("PCAP_UPLOAD", "upload", capture)
    job = _job()
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    request = {"port": 1}
    selected = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=request,
        candidate_id=None,
    )
    assert selected is not None and not selected.candidates.candidates

    batch = collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=selected,
        predicate=compile_packet_predicate(request, internal_networks=job["internal_networks"]),
        internal_networks=job["internal_networks"],
        scan_max_bytes=settings.pcap_export_scan_max_bytes,
        scan_max_packets=settings.pcap_export_scan_max_packets,
        range_limits=_limits(),
    )

    assert batch.records == ()
    assert repository.range_calls == []
    assert batch.scanned_packet_count == 1


def test_internal_factory_uses_only_admitted_snapshot_and_returns_complete_batch() -> None:
    capture = _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443))
    source = _indexed_source("PCAP_UPLOAD", "factory-upload", capture)
    job = _job("factory-upload")
    repository = _RangeRepository(job, [(source, "uploaded")])
    factory = pcap_indexed_export.create_indexed_match_factory(
        repository,
        range_limits=_limits(),
        max_sources=2,
    )

    batch = factory(
        repository=repository,
        settings=Settings(environment="test"),
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={"port": 443, "candidate_ip": None},
        candidate_id=None,
        predicate=compile_packet_predicate(
            {"port": 443, "candidate_ip": None},
            internal_networks=job["internal_networks"],
        ),
        internal_networks=job["internal_networks"],
        scan_max_bytes=1_000_000,
        scan_max_packets=100,
        checkpoint=lambda **_progress: None,
    )

    assert [(record.source_order, record.packet_index) for record in batch.records] == [(0, 0)]
    assert repository.snapshot_calls == []


def test_internal_factory_has_one_fixed_fallback_for_unavailable_private_plan() -> None:
    repository = _RangeRepository(_job("factory-empty"), [])
    factory = pcap_indexed_export.create_indexed_match_factory(
        repository,
        range_limits=_limits(),
        max_sources=2,
    )

    with pytest.raises(IndexedFallback) as caught:
        factory(
            repository=repository,
            settings=Settings(environment="test"),
            requested_job=_job("factory-empty"),
            source_snapshot=repository.snapshot,
            canonical_request={},
            candidate_id=None,
            predicate=compile_packet_predicate({}, internal_networks=["10.0.0.0/8"]),
            internal_networks=["10.0.0.0/8"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            checkpoint=lambda **_progress: None,
        )

    assert caught.value.reason is IndexedFallbackReason.INDEX_UNAVAILABLE
    assert repository.snapshot_calls == []


def test_internal_factory_maps_planner_resource_exhaustion_to_fixed_fallback() -> None:
    capture = _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443))
    source = _indexed_source("PCAP_UPLOAD", "factory-resource", capture)
    job = _job("factory-resource")
    repository = _RangeRepository(job, [(source, "uploaded")])
    factory = pcap_indexed_export.create_indexed_match_factory(
        repository,
        range_limits=_limits(),
        max_sources=1,
    )

    with pytest.raises(IndexedFallback) as caught:
        factory(
            repository=repository,
            settings=Settings(environment="test", pcap_posting_index_query_max_operations=1),
            requested_job=job,
            source_snapshot=repository.snapshot,
            canonical_request={},
            candidate_id=None,
            predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            checkpoint=lambda **_progress: None,
        )

    assert caught.value.reason is IndexedFallbackReason.INDEX_UNAVAILABLE
    assert repository.range_calls == []


@pytest.mark.parametrize(
    "filters",
    [
        {"candidate_ip": "203.0.113.8"},
        {"internal_host_ip": "10.0.0.2"},
        {"port": 443},
        {"protocol": "udp"},
        {"direction": "OUTBOUND"},
        {"sensor_id": "sensor-b"},
        {
            "start_time": "2023-11-14T22:13:22.000009+00:00",
            "end_time": "2023-11-14T22:13:23.000007+00:00",
        },
        {
            "include_filters": [
                {"source_port": 50_000, "protocol": "udp"},
                {"destination_port": 53},
            ],
            "exclude_filters": [{"candidate_ip": "203.0.113.9", "destination_port": 53}],
        },
        {"port": 1},
    ],
)
def test_final_live_two_source_collector_matches_full_sequential_oracle(
    filters: dict[str, object],
) -> None:
    duplicate = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source(
        "LIVE_SEGMENT",
        "manifest-first",
        _capture(
            duplicate,
            _udp_packet("10.0.0.2", "203.0.113.9", 50_001, 53),
            duplicate,
            timestamps=((1_700_000_003, 7), (1_700_000_003, 7), (1_700_000_002, 9)),
        ),
    )
    second = _indexed_source(
        "LIVE_SEGMENT",
        "manifest-second",
        _capture(
            duplicate,
            _udp_packet("10.0.0.3", "203.0.113.10", 50_002, 443),
            timestamps=((1_700_000_002, 9), (1_700_000_004, 1)),
        ),
    )
    sources = [(first, "sensor-a"), (second, "sensor-b")]
    job = {**_job("final-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, sources)
    settings = Settings(environment="test")
    predicate = compile_packet_predicate(filters, internal_networks=job["internal_networks"])
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=filters,
        candidate_id=None,
    )
    assert plan is not None

    batch = collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=plan,
        predicate=predicate,
        internal_networks=job["internal_networks"],
        scan_max_bytes=settings.pcap_export_scan_max_bytes,
        scan_max_packets=settings.pcap_export_scan_max_packets,
        range_limits=_limits(),
    )

    expected = tuple(
        (source_order, packet_index)
        for source_order, (source, sensor_id) in enumerate(sources)
        for packet_index in _sequential_matches(
            source,
            predicate,
            source_order=source_order,
            sensor_id=sensor_id,
        )
    )
    assert tuple((record.source_order, record.packet_index) for record in batch.records) == expected
    assert batch.source_manifest == (
        ("manifest-first", first.version.source_sha256),
        ("manifest-second", second.version.source_sha256),
    )
    assert batch.scanned_packet_count == 5
    if filters == {"port": 443}:
        assert {source_id for source_id, _offset, _length in repository.range_calls} == {
            "manifest-first",
            "manifest-second",
        }
        assert batch.range_count >= 2
    if filters == {"port": 1}:
        assert batch.records == ()
        assert repository.range_calls == []


def test_collector_applies_request_wide_packet_cap_in_manifest_order() -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "cap-first", _capture(packet, packet))
    second = _indexed_source("LIVE_SEGMENT", "cap-second", _capture(packet, packet))
    job = {**_job("cap-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, [(first, "a"), (second, "b")])
    settings = Settings(environment="test")
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert plan is not None

    batch = collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=plan,
        predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
        internal_networks=job["internal_networks"],
        scan_max_bytes=1_000_000,
        scan_max_packets=3,
        range_limits=_limits(),
    )

    assert [(record.source_order, record.packet_index) for record in batch.records] == [
        (0, 0),
        (0, 1),
        (1, 0),
    ]
    assert batch.scanned_packet_count == 3
    assert batch.truncation_reasons == ("SOURCE_PACKET_LIMIT",)


def test_collector_rejects_proof_order_mismatch_even_for_zero_candidates() -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "proof-first", _capture(packet))
    second = _indexed_source("LIVE_SEGMENT", "proof-second", _capture(packet))
    job = {**_job("proof-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, [(first, "a"), (second, "b")])
    settings = Settings(environment="test")
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={"port": 1},
        candidate_id=None,
    )
    assert plan is not None and plan.candidates.candidates == ()
    repository.source_lookup_calls = 0

    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan._replace(source_proofs=tuple(reversed(plan.source_proofs))),
            predicate=compile_packet_predicate(
                {"port": 1}, internal_networks=job["internal_networks"]
            ),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            range_limits=_limits(),
        )

    assert caught.value.reason is IndexedFallbackReason.OWNERSHIP_CHANGED
    assert repository.source_lookup_calls == 0
    assert repository.range_calls == []


@pytest.mark.parametrize(
    ("range_error", "reason"),
    [
        (CaptureRangeMissing("missing"), IndexedFallbackReason.RANGE_MISSING),
        (CaptureRangeShortRead("short"), IndexedFallbackReason.RANGE_SHORT),
        (CaptureRangeUnavailable("outage"), IndexedFallbackReason.RANGE_UNAVAILABLE),
        (CaptureRangeVersionDrift("drift"), IndexedFallbackReason.VERSION_DRIFT),
    ],
)
def test_second_range_failure_discards_whole_provisional_batch(
    range_error: Exception,
    reason: IndexedFallbackReason,
) -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    source = _indexed_source("PCAP_UPLOAD", "range-race", _capture(packet, packet))
    job = _job("range-race")
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert plan is not None
    reads = 0
    original_read = repository.read_capture_range

    def fail_second(source_value: object, byte_range: object) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 2:
            raise range_error
        return original_read(source_value, byte_range)

    repository.read_capture_range = fail_second  # type: ignore[method-assign]
    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan,
            predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            range_limits=replace(_limits(), max_gap_bytes=0),
        )

    assert reads == 2
    assert caught.value.reason is reason


@pytest.mark.parametrize("race_point", ["after_first_source", "after_all_sources"])
def test_multisource_deletion_races_before_final_fence_discard_whole_batch(
    race_point: str,
) -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "race-first", _capture(packet))
    second = _indexed_source("LIVE_SEGMENT", "race-second", _capture(packet))
    job = {**_job("race-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, [(first, "a"), (second, "b")])
    settings = Settings(environment="test")
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert plan is not None
    original_read = repository.read_capture_range

    def delete_after_read(source_value: object, byte_range: object) -> bytes:
        content = original_read(source_value, byte_range)
        source_id = source_value.source_id  # type: ignore[attr-defined]
        if race_point == "after_first_source" and source_id == "race-first":
            repository.sources.pop("race-second")
        if race_point == "after_all_sources" and source_id == "race-second":
            repository.sources.pop("race-first")
        return content

    repository.read_capture_range = delete_after_read  # type: ignore[method-assign]
    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan,
            predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            range_limits=_limits(),
        )

    assert caught.value.reason is IndexedFallbackReason.OWNERSHIP_CHANGED


def test_early_source_metadata_race_during_later_source_planning_performs_zero_reads() -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "early-race-first", _capture(packet))
    second = _indexed_source("LIVE_SEGMENT", "early-race-second", _capture(packet))
    job = {**_job("early-race-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, [(first, "a"), (second, "b")])
    selection = _select_analysis_posting_plan_from_snapshot(
        repository,
        Settings(environment="test"),
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert selection is not None
    original_identity = repository.get_posting_index_identity

    def race_during_second_plan(source: object, parent: object) -> object:
        result = original_identity(source, parent)  # type: ignore[arg-type]
        if source.source_id == "early-race-second":  # type: ignore[attr-defined]
            repository.sources.pop("early-race-first", None)
        return result

    repository.get_posting_index_identity = race_during_second_plan  # type: ignore[method-assign]
    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=selection,
            predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            range_limits=_limits(),
        )

    assert caught.value.reason is IndexedFallbackReason.OWNERSHIP_CHANGED
    assert repository.range_calls == []


def test_collector_loads_each_full_structural_snapshot_once_and_fences_with_compact_identity() -> (
    None
):
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    first = _indexed_source("LIVE_SEGMENT", "compact-first", _capture(packet))
    second = _indexed_source("LIVE_SEGMENT", "compact-second", _capture(packet))
    job = {**_job("compact-live"), "mode": "LIVE", "status": "COMPLETED"}
    repository = _RangeRepository(job, [(first, "a"), (second, "b")])
    selection = _select_analysis_posting_plan_from_snapshot(
        repository,
        Settings(environment="test"),
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert selection is not None
    assert len(repository.structural_lookup_calls) == 2

    collect_indexed_matches(
        repository,
        source_snapshot=repository.snapshot,
        selection_plan=selection,
        predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
        internal_networks=job["internal_networks"],
        scan_max_bytes=1_000_000,
        scan_max_packets=100,
        range_limits=_limits(),
    )

    assert len(repository.structural_lookup_calls) == 2
    assert len(repository.structural_identity_lookup_calls) == 12
    assert {source.source_id for source in repository.structural_identity_lookup_calls} == {
        "compact-first",
        "compact-second",
    }


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("source_delete", IndexedFallbackReason.OWNERSHIP_CHANGED),
        ("source_replace", IndexedFallbackReason.OWNERSHIP_CHANGED),
        ("parent_delete", IndexedFallbackReason.INDEX_UNAVAILABLE),
        ("parent_replace", IndexedFallbackReason.INDEX_CORRUPT),
        ("parent_corrupt", IndexedFallbackReason.INDEX_CORRUPT),
        ("posting_delete", IndexedFallbackReason.OWNERSHIP_CHANGED),
        ("posting_replace", IndexedFallbackReason.OWNERSHIP_CHANGED),
        ("posting_corrupt", IndexedFallbackReason.OWNERSHIP_CHANGED),
    ],
)
def test_source_parent_posting_fault_matrix_maps_only_expected_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
    fault: str,
    reason: IndexedFallbackReason,
) -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    indexed = _indexed_source("PCAP_UPLOAD", "fault-source", _capture(packet))
    job = _job("fault-source")
    repository = _RangeRepository(job, [(indexed, "uploaded")])
    settings = Settings(environment="test")
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert plan is not None
    if fault == "source_delete":
        repository.sources.clear()
    elif fault == "source_replace":
        indexed.version = replace(indexed.version, object_key="objects/replaced.pcap")
    elif fault == "parent_delete":
        monkeypatch.setattr(
            repository,
            "get_structural_index_identity",
            lambda _source: StructuralIndexIdentityLookup(IndexAvailability.MISSING),
        )
    elif fault == "parent_replace":
        indexed.parent = replace(indexed.parent, build_id="structural:replacement")
    elif fault == "parent_corrupt":
        indexed.parent = replace(indexed.parent, index_sha256="0" * 64)
    elif fault == "posting_delete":
        monkeypatch.setattr(
            repository,
            "get_posting_index_identity",
            lambda *_args: PostingIndexIdentityLookup(PostingIndexAvailability.MISSING),
        )
    elif fault == "posting_replace":
        replacement = replace(indexed.posting, build_id="posting:replacement")
        monkeypatch.setattr(
            repository,
            "get_posting_index_identity",
            lambda *_args: PostingIndexIdentityLookup(
                PostingIndexAvailability.READY,
                posting_index_identity(replacement),
            ),
        )
    else:
        monkeypatch.setattr(
            repository,
            "get_posting_index_identity",
            lambda *_args: PostingIndexIdentityLookup(PostingIndexAvailability.CORRUPT),
        )

    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan,
            predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            range_limits=_limits(),
        )

    assert caught.value.reason is reason
    assert repository.range_calls == []


@pytest.mark.parametrize(
    "fault",
    ["source_delete", "source_replace", "parent_delete", "parent_replace", "parent_corrupt"],
)
def test_source_and_parent_faults_after_ranges_are_rejected_by_compact_final_fence(
    monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    indexed = _indexed_source("PCAP_UPLOAD", "final-fault", _capture(packet))
    job = _job("final-fault")
    repository = _RangeRepository(job, [(indexed, "uploaded")])
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        Settings(environment="test"),
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert plan is not None
    original_read = repository.read_capture_range
    original_identity = repository.get_structural_index_identity
    after_range = False

    def identity_after_range(source: object) -> object:
        if after_range and fault == "parent_delete":
            return StructuralIndexIdentityLookup(IndexAvailability.MISSING)
        return original_identity(source)  # type: ignore[arg-type]

    monkeypatch.setattr(repository, "get_structural_index_identity", identity_after_range)

    def mutate_after_range(source: object, byte_range: object) -> bytes:
        nonlocal after_range
        content = original_read(source, byte_range)
        after_range = True
        if fault == "source_delete":
            repository.sources.clear()
        elif fault == "source_replace":
            indexed.version = replace(indexed.version, object_key="objects/replaced.pcap")
        elif fault == "parent_replace":
            indexed.parent = replace(indexed.parent, build_id="structural:replacement")
        elif fault == "parent_corrupt":
            indexed.parent = replace(indexed.parent, index_sha256="not-a-digest")
        return content

    monkeypatch.setattr(repository, "read_capture_range", mutate_after_range)
    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan,
            predicate=compile_packet_predicate({}, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=1_000_000,
            scan_max_packets=100,
            range_limits=_limits(),
        )

    assert repository.range_calls
    assert caught.value.reason is IndexedFallbackReason.OWNERSHIP_CHANGED


def test_unknown_range_runtime_and_deadline_exceptions_propagate_unchanged() -> None:
    packet = _udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443)
    source = _indexed_source("PCAP_UPLOAD", "unknown-fault", _capture(packet))
    job = _job("unknown-fault")
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request={},
        candidate_id=None,
    )
    assert plan is not None
    arguments = {
        "source_snapshot": repository.snapshot,
        "selection_plan": plan,
        "predicate": compile_packet_predicate({}, internal_networks=job["internal_networks"]),
        "internal_networks": job["internal_networks"],
        "scan_max_bytes": 1_000_000,
        "scan_max_packets": 100,
        "range_limits": _limits(),
    }

    repository.read_capture_range = lambda *_args: (_ for _ in ()).throw(  # type: ignore[method-assign]
        RuntimeError("unknown range failure")
    )
    with pytest.raises(RuntimeError, match="unknown range failure"):
        collect_indexed_matches(repository, **arguments)  # type: ignore[arg-type]

    class Deadline(RuntimeError):
        pass

    with pytest.raises(Deadline):
        collect_indexed_matches(
            repository,
            **arguments,  # type: ignore[arg-type]
            check_deadline=lambda: (_ for _ in ()).throw(Deadline()),
        )


def test_decoder_parse_error_is_index_corrupt_but_programmer_error_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    capture = _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443))
    source = _indexed_source("PCAP_UPLOAD", "upload", capture)
    job = _job()
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    request = {"port": 443}
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=request,
        candidate_id=None,
    )
    assert plan is not None
    arguments = {
        "source_snapshot": repository.snapshot,
        "selection_plan": plan,
        "predicate": compile_packet_predicate(request, internal_networks=job["internal_networks"]),
        "internal_networks": job["internal_networks"],
        "scan_max_bytes": settings.pcap_export_scan_max_bytes,
        "scan_max_packets": settings.pcap_export_scan_max_packets,
        "range_limits": _limits(),
    }

    def malformed(*_args: object, **_kwargs: object) -> object:
        raise PcapParseError("bad structural metadata")

    monkeypatch.setattr(pcap_indexed_export, "export_packet_from_structural_locator", malformed)
    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(repository, **arguments)  # type: ignore[arg-type]
    assert caught.value.reason is IndexedFallbackReason.INDEX_CORRUPT

    def programmer_bug(*_args: object, **_kwargs: object) -> object:
        raise ValueError("unexpected programmer failure")

    monkeypatch.setattr(
        pcap_indexed_export, "export_packet_from_structural_locator", programmer_bug
    )
    with pytest.raises(ValueError, match="unexpected programmer failure"):
        collect_indexed_matches(repository, **arguments)  # type: ignore[arg-type]


def test_short_range_and_cancellation_have_distinct_atomic_semantics() -> None:
    capture = _capture(_udp_packet("10.0.0.1", "203.0.113.8", 50_000, 443))
    source = _indexed_source("PCAP_UPLOAD", "upload", capture)
    job = _job()
    repository = _RangeRepository(job, [(source, "uploaded")])
    settings = Settings(environment="test")
    request = {"port": 443}
    plan = _select_analysis_posting_plan_from_snapshot(
        repository,
        settings,
        requested_job=job,
        source_snapshot=repository.snapshot,
        canonical_request=request,
        candidate_id=None,
    )
    assert plan is not None
    original_read = repository.read_capture_range

    def short(source_value: object, byte_range: object) -> bytes:
        return original_read(source_value, byte_range)[:-1]

    repository.read_capture_range = short  # type: ignore[method-assign]
    with pytest.raises(IndexedFallback) as caught:
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan,
            predicate=compile_packet_predicate(request, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=settings.pcap_export_scan_max_bytes,
            scan_max_packets=settings.pcap_export_scan_max_packets,
            range_limits=_limits(),
        )
    assert caught.value.reason is IndexedFallbackReason.RANGE_SHORT

    class Cancelled(RuntimeError):
        pass

    with pytest.raises(Cancelled):
        collect_indexed_matches(
            repository,
            source_snapshot=repository.snapshot,
            selection_plan=plan,
            predicate=compile_packet_predicate(request, internal_networks=job["internal_networks"]),
            internal_networks=job["internal_networks"],
            scan_max_bytes=settings.pcap_export_scan_max_bytes,
            scan_max_packets=settings.pcap_export_scan_max_packets,
            range_limits=_limits(),
            check_cancelled=lambda: (_ for _ in ()).throw(Cancelled()),
        )
