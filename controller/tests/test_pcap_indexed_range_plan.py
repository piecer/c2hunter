from __future__ import annotations

import struct
from dataclasses import replace
from datetime import UTC, datetime

import pytest
from c2hunter_analysis.pcap import bounded_pcap_prefix
from c2hunter_analysis.pcap_export import CaptureInterface
from c2hunter_analysis.pcap_index import StructuralInterfaceEntry, StructuralPacketEntry

from c2hunter_controller.pcap_indexed_export import (
    IndexedLocatorError,
    IndexedRangeFallback,
    RangePlanLimits,
    SelectedPacketLocator,
    locate_selected_packets,
    plan_packet_ranges,
)
from c2hunter_controller.pcap_offset_index import (
    CaptureSourceVersion,
    SourceIndexBinding,
    StructuralIndexSnapshot,
    structural_index_digest,
)

SHA = "a" * 64


def _snapshot(fmt: str = "PCAP") -> tuple[CaptureSourceVersion, StructuralIndexSnapshot]:
    source = CaptureSourceVersion("PCAP_UPLOAD", "s", "captures/s.pcap", "v1", 100, SHA)
    binding = SourceIndexBinding("PCAP_UPLOAD", "s", "v1", 100, SHA, fmt)  # type: ignore[arg-type]
    interface = StructuralInterfaceEntry(0, 0, 0, 1, 65_535, 1, 1_000_000, 0)
    if fmt == "PCAP":
        packets = (
            StructuralPacketEntry(0, 24, 40, 10, 10, 26, 0, 0, 0, 1),
            StructuralPacketEntry(1, 50, 66, 0, 0, 16, 0, 0, 0, 2),
            StructuralPacketEntry(2, 66, 82, 10, 12, 26, 0, 0, 0, 3),
        )
    else:
        packets = (
            StructuralPacketEntry(0, 28, 56, 8, 8, 40, 0, 0, 0, 1),
            StructuralPacketEntry(1, 68, 96, 0, 0, 32, 0, 0, 0, 2),
        )
    snapshot = StructuralIndexSnapshot(
        "build", binding, datetime.now(UTC), "", (interface,), packets
    )
    return source, replace(
        snapshot,
        index_sha256=structural_index_digest(binding, snapshot.interfaces, packets),
    )


def _limits(**changes: int) -> RangePlanLimits:
    values = {
        "max_gap_bytes": 100,
        "max_range_bytes": 100,
        "max_ranges": 10,
        "max_total_fetched_bytes": 1_000,
        "max_amplification_numerator": 100,
        "max_amplification_denominator": 1,
        "max_source_fraction_numerator": 99,
        "max_source_fraction_denominator": 100,
    }
    values.update(changes)
    return RangePlanLimits(**values)


def _locator(
    packet_index: int,
    data_offset: int,
    captured_length: int,
    *,
    source_id: str = "s",
    version: str = "v1",
    source_order: int = 0,
    source_size: int = 100,
    build: str = "build",
) -> SelectedPacketLocator:
    return SelectedPacketLocator(
        "PCAP_UPLOAD",
        source_id,
        f"captures/{source_id}/{version}.pcap",
        version,
        source_size,
        SHA,
        build,
        source_order,
        packet_index,
        max(0, data_offset - 16),
        data_offset,
        captured_length,
        captured_length,
        16 + captured_length,
        packet_index,
        CaptureInterface(0, 0, 0, 1, 65_535, 1, 1_000_000, 0),
    )


def test_classic_prefix_exact_byte_and_packet_boundaries_and_plus_one() -> None:
    source, snapshot = _snapshot()
    exact = locate_selected_packets(
        source,
        snapshot,
        expected_parent_build_id="build",
        selected_ordinals=(0, 1, 2),
        source_order=4,
        remaining_byte_budget=92,
        remaining_packet_limit=3,
    )
    assert [item.packet_index for item in exact.locators] == [0, 1, 2]
    assert (exact.admitted_packet_count, exact.scanned_bytes) == (3, 92)
    assert exact.byte_limited is True and exact.packet_limited is False

    one_byte_short = locate_selected_packets(
        source,
        snapshot,
        expected_parent_build_id="build",
        selected_ordinals=(0, 1, 2),
        source_order=0,
        remaining_byte_budget=91,
        remaining_packet_limit=3,
    )
    assert [item.packet_index for item in one_byte_short.locators] == [0, 1]
    assert (one_byte_short.admitted_packet_count, one_byte_short.scanned_bytes) == (2, 66)

    exact_packet_cap = locate_selected_packets(
        source,
        snapshot,
        expected_parent_build_id="build",
        selected_ordinals=(0, 1, 2),
        source_order=0,
        remaining_byte_budget=100,
        remaining_packet_limit=2,
    )
    assert [item.packet_index for item in exact_packet_cap.locators] == [0, 1]
    assert (exact_packet_cap.admitted_packet_count, exact_packet_cap.scanned_bytes) == (2, 66)
    assert exact_packet_cap.packet_limited is True

    cap_plus_one = locate_selected_packets(
        source,
        snapshot,
        expected_parent_build_id="build",
        selected_ordinals=(0, 1, 2),
        source_order=0,
        remaining_byte_budget=100,
        remaining_packet_limit=3,
    )
    assert cap_plus_one.admitted_packet_count == 3
    assert cap_plus_one.scanned_bytes == source.source_size_bytes


@pytest.mark.parametrize("packet_limit", [1, 2, 3, 100])
def test_classic_prefix_matches_materialized_oracle_for_every_byte_budget(
    packet_limit: int,
) -> None:
    payloads = (b"a" * 10, b"", b"c" * 10)
    capture = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65_535, 1) + b"".join(
        struct.pack("<IIII", index, 0, len(payload), len(payload)) + payload
        for index, payload in enumerate(payloads)
    )
    source, snapshot = _snapshot()
    source = replace(source, source_size_bytes=len(capture))
    binding = replace(snapshot.binding, source_size_bytes=len(capture))
    snapshot = replace(
        snapshot,
        binding=binding,
        index_sha256=structural_index_digest(binding, snapshot.interfaces, snapshot.packets),
    )

    for budget in range(len(capture) + 1):
        actual = locate_selected_packets(
            source,
            snapshot,
            expected_parent_build_id="build",
            selected_ordinals=(0, 1, 2),
            source_order=0,
            remaining_byte_budget=budget,
            remaining_packet_limit=packet_limit,
        )
        if budget == 0:
            expected = (0, 0, True, False)
        else:
            oracle = bounded_pcap_prefix(capture, budget, max_packets=packet_limit)
            expected = (
                oracle.packet_count,
                oracle.scanned_bytes,
                oracle.byte_limited,
                oracle.packet_limited,
            )
        assert (
            actual.admitted_packet_count,
            actual.scanned_bytes,
            actual.byte_limited,
            actual.packet_limited,
        ) == expected, f"budget={budget}, packet_limit={packet_limit}"
        assert all(
            item.data_offset + item.captured_length <= actual.scanned_bytes
            for item in actual.locators
        )
        if budget < 24:
            assert actual.scanned_bytes == 0
            assert actual.locators == ()


def test_pcapng_partial_budget_falls_back_and_full_budget_preserves_packet_prefix() -> None:
    source, snapshot = _snapshot("PCAPNG")
    with pytest.raises(IndexedRangeFallback, match="unsupported_scan_semantics"):
        locate_selected_packets(
            source,
            snapshot,
            expected_parent_build_id="build",
            selected_ordinals=(0,),
            source_order=0,
            remaining_byte_budget=99,
            remaining_packet_limit=2,
        )
    for budget in (100, 101):
        result = locate_selected_packets(
            source,
            snapshot,
            expected_parent_build_id="build",
            selected_ordinals=(0, 1),
            source_order=0,
            remaining_byte_budget=budget,
            remaining_packet_limit=1,
        )
        assert [item.packet_index for item in result.locators] == [0]
        assert (result.admitted_packet_count, result.scanned_bytes) == (1, 68)
        assert result.packet_limited is True and result.byte_limited is False


def test_selected_ordinals_must_be_sorted_unique_in_range_and_structurally_aligned() -> None:
    source, snapshot = _snapshot()
    for ordinals in ((-1,), (1, 1), (2, 1), (3,), (0, True)):
        with pytest.raises(IndexedLocatorError):
            locate_selected_packets(
                source,
                snapshot,
                expected_parent_build_id="build",
                selected_ordinals=ordinals,
                source_order=0,
                remaining_byte_budget=100,
                remaining_packet_limit=3,
            )

    corrupt_packets = (replace(snapshot.packets[0], packet_index=1), *snapshot.packets[1:])
    corrupt = replace(
        snapshot,
        packets=corrupt_packets,
        index_sha256=structural_index_digest(
            snapshot.binding, snapshot.interfaces, corrupt_packets
        ),
    )
    with pytest.raises(IndexedLocatorError):
        locate_selected_packets(
            source,
            corrupt,
            expected_parent_build_id="build",
            selected_ordinals=(0,),
            source_order=0,
            remaining_byte_budget=100,
            remaining_packet_limit=3,
        )


def test_coalescing_gap_and_combined_range_exact_boundaries() -> None:
    selected = (_locator(0, 0, 10), _locator(1, 19, 10))
    assert len(plan_packet_ranges(selected, limits=_limits(max_gap_bytes=8)).ranges) == 2
    assert len(plan_packet_ranges(selected, limits=_limits(max_gap_bytes=9)).ranges) == 1
    assert len(plan_packet_ranges(selected, limits=_limits(max_gap_bytes=10)).ranges) == 1

    assert len(plan_packet_ranges(selected, limits=_limits(max_range_bytes=28)).ranges) == 2
    exact = plan_packet_ranges(selected, limits=_limits(max_range_bytes=29))
    assert [(item.offset, item.length) for item in exact.ranges] == [(0, 29)]
    assert len(plan_packet_ranges(selected, limits=_limits(max_range_bytes=30)).ranges) == 1


def test_range_count_total_amplification_and_source_fraction_exact_and_plus_one() -> None:
    separated = (_locator(0, 0, 10), _locator(2, 20, 10))
    assert len(plan_packet_ranges(separated, limits=_limits(max_ranges=2)).ranges) == 2
    with pytest.raises(IndexedRangeFallback, match="resource_limit"):
        plan_packet_ranges(separated, limits=_limits(max_ranges=1))

    assert (
        plan_packet_ranges(separated, limits=_limits(max_total_fetched_bytes=20)).fetched_bytes
        == 20
    )
    with pytest.raises(IndexedRangeFallback, match="resource_limit"):
        plan_packet_ranges(separated, limits=_limits(max_total_fetched_bytes=19))

    with_gap = (_locator(0, 0, 10), _locator(1, 20, 10))
    assert (
        plan_packet_ranges(
            with_gap,
            limits=_limits(
                max_amplification_numerator=3,
                max_amplification_denominator=2,
            ),
        ).fetched_bytes
        == 30
    )
    with pytest.raises(IndexedRangeFallback, match="resource_limit"):
        plan_packet_ranges(
            with_gap,
            limits=_limits(
                max_amplification_numerator=149,
                max_amplification_denominator=100,
            ),
        )

    assert (
        plan_packet_ranges(
            separated,
            limits=_limits(
                max_source_fraction_numerator=1,
                max_source_fraction_denominator=5,
            ),
        ).fetched_bytes
        == 20
    )
    with pytest.raises(IndexedRangeFallback, match="resource_limit"):
        plan_packet_ranges(
            separated,
            limits=_limits(
                max_source_fraction_numerator=19,
                max_source_fraction_denominator=100,
            ),
        )


def test_zero_length_needs_no_range_and_dense_or_oversized_plans_fall_back() -> None:
    zero = plan_packet_ranges((_locator(0, 10, 0),), limits=_limits())
    assert zero.ranges == ()
    assert (zero.selected_payload_bytes, zero.fetched_bytes, zero.amplification) == (0, 0, 0.0)

    with pytest.raises(IndexedRangeFallback, match="resource_limit"):
        plan_packet_ranges(
            (_locator(0, 0, 100),),
            limits=_limits(max_range_bytes=100, max_total_fetched_bytes=100),
        )
    with pytest.raises(IndexedRangeFallback, match="resource_limit"):
        plan_packet_ranges((_locator(0, 0, 11),), limits=_limits(max_range_bytes=10))


def test_different_sources_versions_and_skipped_ordinals_never_coalesce() -> None:
    different_sources = (
        _locator(0, 0, 10, source_id="a", source_order=0),
        _locator(0, 10, 10, source_id="b", source_order=1),
    )
    assert len(plan_packet_ranges(different_sources, limits=_limits()).ranges) == 2

    different_versions = (
        _locator(0, 0, 10, version="v1", source_order=0),
        _locator(0, 10, 10, version="v2", source_order=1),
    )
    assert len(plan_packet_ranges(different_versions, limits=_limits()).ranges) == 2

    skipped = (_locator(0, 0, 10), _locator(2, 10, 10))
    assert len(plan_packet_ranges(skipped, limits=_limits()).ranges) == 2


def test_planner_orders_physical_packets_rejects_duplicates_and_invalid_arithmetic() -> None:
    selected = (_locator(2, 30, 5), _locator(0, 10, 5), _locator(1, 20, 5))
    planned = plan_packet_ranges(selected, limits=_limits(max_gap_bytes=5))
    assert [packet.packet_index for item in planned.ranges for packet in item.packet_slices] == [
        0,
        1,
        2,
    ]
    with pytest.raises(IndexedLocatorError):
        plan_packet_ranges((selected[0], selected[0]), limits=_limits())
    with pytest.raises(IndexedLocatorError):
        plan_packet_ranges(
            (_locator(0, (1 << 63) - 1, 1, source_size=(1 << 63) - 1),),
            limits=_limits(),
        )
    with pytest.raises(ValueError):
        RangePlanLimits(True, 1, 1, 1, 1, 1, 1, 2)  # type: ignore[arg-type]
