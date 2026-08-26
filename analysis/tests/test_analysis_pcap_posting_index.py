from __future__ import annotations

import hashlib
import io
import ipaddress
import struct

import pytest

from c2hunter_analysis.pcap_export import open_export_capture
from c2hunter_analysis.pcap_index import scan_structural_packet_index


def test_stage11_posting_api_exists() -> None:
    from c2hunter_analysis.pcap_postings import (
        PCAP_FILTER_CONTRACT_VERSION,
        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        PCAP_POSTING_INDEX_SCHEMA_VERSION,
        PostingDimension,
    )

    assert (
        PCAP_POSTING_INDEX_SCHEMA_VERSION,
        PCAP_POSTING_INDEX_PARSER_CONTRACT_VERSION,
        PCAP_FILTER_CONTRACT_VERSION,
    ) == (1, 1, 1)
    assert PostingDimension.ALL_PACKET.value == "ALL_PACKET"


def _udp(
    payload: bytes = b"x",
    *,
    source: str = "10.0.0.8",
    destination: str = "203.0.113.8",
    source_port: int = 50000,
    destination_port: int = 443,
) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ip = struct.pack(
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
    return bytes.fromhex("0200000000020200000000010800") + ip + udp


def _udp6(
    payload: bytes = b"v6",
    *,
    source: str = "2001:db8::8",
    destination: str = "2001:db8:1::9",
    source_port: int = 50000,
    destination_port: int = 443,
) -> bytes:
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    ipv6 = struct.pack(
        "!IHBB16s16s",
        6 << 28,
        len(udp),
        17,
        64,
        ipaddress.ip_address(source).packed,
        ipaddress.ip_address(destination).packed,
    )
    return bytes.fromhex("02000000000202000000000186dd") + ipv6 + udp


def _classic(packets: list[bytes], *, link_type: int = 1) -> bytes:
    result = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, link_type))
    for packet in packets:
        result.extend(struct.pack("<IIII", 7, 11, len(packet), len(packet)))
        result.extend(packet)
    return bytes(result)


def test_delta_varints_are_uint64_canonical_strict_and_round_trip() -> None:
    from c2hunter_analysis.pcap_postings import (
        MAX_POSTING_ORDINAL,
        PostingCodecError,
        decode_ordinals,
        encode_ordinals,
    )

    values = (0, 127, 128, MAX_POSTING_ORDINAL)
    encoded = encode_ordinals(values)
    assert decode_ordinals(encoded) == values
    assert MAX_POSTING_ORDINAL == 2**64 - 1

    for invalid in (
        (False,),
        (-1,),
        (1, 1),
        (2, 1),
        (MAX_POSTING_ORDINAL + 1,),
        (0, MAX_POSTING_ORDINAL + 1),
    ):
        with pytest.raises(PostingCodecError) as raised:
            encode_ordinals(invalid)
        assert raised.value.code == "POSTING_CODEC_INVALID"


@pytest.mark.parametrize(
    "encoded",
    [
        b"\x80\x00",  # redundant zero group
        b"\x81\x00",  # redundant one group
        b"\x80",  # trailing incomplete
        b"\x80" * 9 + b"\x02",  # terminal payload exceeds uint64
        b"\xff" * 9 + b"\x02",  # reviewer overflow probe
        b"\x80" * 10 + b"\x00",  # continuation in byte ten / over ten bytes
        b"\x81\x00" + b"\x01",  # non-minimal first delta before another value
    ],
)
def test_delta_varint_decoder_rejects_noncanonical_overflow_and_truncation(
    encoded: bytes,
) -> None:
    from c2hunter_analysis.pcap_postings import PostingCodecError, decode_ordinals

    with pytest.raises(PostingCodecError) as raised:
        decode_ordinals(encoded)
    assert raised.value.code == "POSTING_CODEC_INVALID"


def test_delta_varint_decoder_enforces_packet_universe_and_zero_delta() -> None:
    from c2hunter_analysis.pcap_postings import PostingCodecError, decode_ordinals

    assert decode_ordinals(b"\x01\x7f", max_ordinal=127) == (0, 127)
    with pytest.raises(PostingCodecError, match="packet universe"):
        decode_ordinals(b"\x01\x7f\x01", max_ordinal=127)
    with pytest.raises(PostingCodecError, match="strictly increasing"):
        decode_ordinals(b"\x01\x00")


def test_sequential_build_binds_structure_and_keeps_unsupported_ordinal() -> None:
    from c2hunter_analysis.pcap_postings import (
        PostingBuildLimits,
        PostingDimension,
        build_packet_postings,
        canonical_address,
        canonical_payload,
        canonical_port,
        canonical_protocol,
        posting_values,
        validate_posting_generation,
    )

    supported = _udp(b"same")
    capture = _classic([supported, supported])
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=10, max_interfaces=2)
    decoder = open_export_capture(
        io.BytesIO(capture),
        source_id="version-1",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )
    generation = build_packet_postings(
        decoder,
        structural_packets=structural.packets,
        structural_interfaces=structural.interfaces,
        limits=PostingBuildLimits(batch_size=1),
    )

    assert posting_values(generation, PostingDimension.ALL_PACKET, b"") == (0, 1)
    assert posting_values(generation, PostingDimension.SUPPORTED, b"") == (0, 1)
    assert posting_values(
        generation, PostingDimension.SRC_ADDRESS, canonical_address("10.0.0.8")
    ) == (0, 1)
    assert posting_values(generation, PostingDimension.SRC_PORT, canonical_port(50000)) == (
        0,
        1,
    )
    assert posting_values(generation, PostingDimension.PROTOCOL, canonical_protocol("udp")) == (
        0,
        1,
    )
    assert posting_values(generation, PostingDimension.HAS_PAYLOAD, canonical_payload(True)) == (
        0,
        1,
    )
    assert validate_posting_generation(generation)
    assert len(generation.chunks) > 1
    assert generation.digest == hashlib.sha256(generation.digest_document()).hexdigest()

    unsupported_capture = _classic([b"same", b"same"], link_type=999)
    unsupported_structural = scan_structural_packet_index(
        io.BytesIO(unsupported_capture), max_packets=2, max_interfaces=1
    )
    unsupported = build_packet_postings(
        open_export_capture(
            io.BytesIO(unsupported_capture),
            source_id="v",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ),
        structural_packets=unsupported_structural.packets,
        structural_interfaces=unsupported_structural.interfaces,
    )
    assert posting_values(unsupported, PostingDimension.ALL_PACKET, b"") == (0, 1)
    assert posting_values(unsupported, PostingDimension.SUPPORTED, b"") == ()


def _filter_generation():
    from c2hunter_analysis.pcap_postings import build_packet_postings

    capture = _classic(
        [
            _udp(b"yes"),
            _udp(
                b"",
                source="198.51.100.9",
                destination="10.0.0.9",
                source_port=53,
                destination_port=60000,
            ),
            _udp(
                b"other",
                source="10.0.0.10",
                destination="192.0.2.7",
                source_port=1234,
                destination_port=8080,
            ),
        ]
    )
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=3, max_interfaces=1)
    decoder = open_export_capture(
        io.BytesIO(capture),
        source_id="filter-v1",
        source_order=0,
        internal_networks=["10.0.0.0/8"],
    )
    packets = list(
        open_export_capture(
            io.BytesIO(capture),
            source_id="oracle-v1",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ).iter_packets()
    )
    return (
        build_packet_postings(
            decoder,
            structural_packets=structural.packets,
            structural_interfaces=structural.interfaces,
            limits=__import__(
                "c2hunter_analysis.pcap_postings", fromlist=["PostingBuildLimits"]
            ).PostingBuildLimits(batch_size=1),
        ),
        packets,
    )


@pytest.mark.parametrize(
    "filters",
    [
        {"candidate_ip": "203.0.113.8"},
        {"internal_host_ip": "10.0.0.9"},
        {"port": 443},
        {"protocol": "udp"},
        {"start_time": "2099-01-01T00:00:00+00:00"},
        {"direction": "INBOUND"},
        {"sensor_id": "sensor-a"},
        {"include_filters": [{"candidate_ip": "203.0.113.0/24"}]},
        {
            "include_filters": [
                {"source_port": 53, "has_payload": False},
                {"destination_port": 8080},
            ]
        },
        {"exclude_filters": [{"source_port": 53}]},
        {"exclude_filters": [{"direction": "OUTBOUND", "source_port": 50000}]},
        {"exclude_filters": [{"port": 443}]},
    ],
)
def test_selector_is_sorted_unique_conservative_oracle(filters: dict[str, object]) -> None:
    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import select_posting_candidates

    generation, packets = _filter_generation()
    predicate = compile_packet_predicate(filters, internal_networks=["10.0.0.0/8"])
    candidates = select_posting_candidates(
        generation, predicate, sensor_id="sensor-a", max_query_work=100
    )
    full_scan = {
        packet.locator.packet_index
        for packet in packets
        if predicate.matches(packet, sensor_id="sensor-a")
    }

    assert candidates is not None
    assert candidates == tuple(sorted(set(candidates)))
    assert full_scan <= set(candidates)


def test_compiled_endpoint_network_include_and_exact_exclude_use_endpoint_dictionary() -> None:
    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import select_posting_candidates

    generation, packets = _filter_generation()
    included = compile_packet_predicate(
        {"include_filters": [{"candidate_ip": "203.0.113.99/24"}]},
        internal_networks=["10.0.0.0/8"],
    )
    assert set(included.include_filters[0]) == {
        "endpoint_network",
        "direction",
        "protocol",
        "port",
        "source_port",
        "destination_port",
        "has_payload",
    }
    assert select_posting_candidates(generation, included, max_query_work=1_000) == (0,)

    excluded = compile_packet_predicate(
        {"exclude_filters": [{"candidate_ip": "203.0.113.99/24"}]},
        internal_networks=["10.0.0.0/8"],
    )
    selected = select_posting_candidates(generation, excluded, max_query_work=1_000)
    assert selected == (1, 2)
    full_scan = {
        packet.locator.packet_index
        for packet in packets
        if excluded.matches(packet, sensor_id="sensor-a")
    }
    assert full_scan <= set(selected)


def test_ipv4_ipv6_canonicalization_and_universal_cidrs_are_family_exact() -> None:
    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import build_packet_postings, select_posting_candidates

    capture = _classic([_udp(), _udp6()])
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=2, max_interfaces=1)
    generation = build_packet_postings(
        open_export_capture(
            io.BytesIO(capture),
            source_id="dual-stack",
            source_order=0,
            internal_networks=["10.0.0.0/8", "2001:db8::/32"],
        ),
        structural_packets=structural.packets,
        structural_interfaces=structural.interfaces,
    )

    def selected(cidr: str) -> tuple[int, ...] | None:
        predicate = compile_packet_predicate(
            {"include_filters": [{"candidate_ip": cidr}]},
            internal_networks=["10.0.0.0/8", "2001:db8::/32"],
        )
        return select_posting_candidates(generation, predicate, max_query_work=1_000)

    assert selected("203.0.113.99/24") == (0,)
    assert selected("2001:0db8:0001::ffff/64") == (1,)
    assert selected("0.0.0.0/0") == (0,)
    assert selected("::/0") == (1,)


def test_query_limits_use_none_for_unavailable_and_exact_empty_only_for_sensor_mismatch() -> None:
    from dataclasses import replace

    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import PostingQueryLimits, select_posting_candidates

    generation, _ = _filter_generation()
    predicate = compile_packet_predicate({}, internal_networks=["10.0.0.0/8"])
    generous = {
        "max_directory_chunks": 1_000,
        "max_dictionary_terms": 1_000,
        "max_operations": 100,
        "max_result_ordinals": 100,
        "max_decoded_memberships": 100,
    }
    for field, exact in (
        ("max_operations", 9),
        ("max_result_ordinals", 3),
        ("max_decoded_memberships", 3),
    ):
        for value, expected in ((exact - 1, None), (exact, (0, 1, 2)), (exact + 1, (0, 1, 2))):
            limits = PostingQueryLimits(**(generous | {field: value}))
            assert select_posting_candidates(generation, predicate, limits=limits) == expected

    wrong_sensor = compile_packet_predicate(
        {"sensor_id": "sensor-b"}, internal_networks=["10.0.0.0/8"]
    )
    assert select_posting_candidates(generation, wrong_sensor, sensor_id="sensor-a") == ()
    assert (
        select_posting_candidates(
            replace(generation, schema_version=999),
            predicate,
            limits=PostingQueryLimits(**generous),
        )
        is None
    )


def test_query_cap_trips_during_compiled_address_dictionary_enumeration() -> None:
    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import PostingQueryLimits, select_posting_candidates

    generation, _ = _filter_generation()
    predicate = compile_packet_predicate(
        {"include_filters": [{"candidate_ip": "0.0.0.0/0"}]},
        internal_networks=["10.0.0.0/8"],
    )
    assert (
        select_posting_candidates(
            generation,
            predicate,
            limits=PostingQueryLimits(
                max_operations=3,
                max_result_ordinals=100,
                max_decoded_memberships=100,
                max_directory_chunks=1_000,
                max_dictionary_terms=1_000,
            ),
        )
        is None
    )


def test_selector_does_not_decode_irrelevant_high_cardinality_dimensions() -> None:
    from dataclasses import replace

    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import PostingDimension, select_posting_candidates

    generation, _ = _filter_generation()
    chunks = list(generation.chunks)
    irrelevant = next(
        index for index, chunk in enumerate(chunks) if chunk.dimension is PostingDimension.SRC_PORT
    )
    chunks[irrelevant] = replace(chunks[irrelevant], encoded_ordinals=b"\x80")
    generation = replace(generation, chunks=tuple(chunks))
    predicate = compile_packet_predicate({"protocol": "udp"}, internal_networks=["10.0.0.0/8"])

    assert select_posting_candidates(generation, predicate, max_query_work=1_000) == (0, 1, 2)


def test_query_cap_and_corrupt_generation_return_unavailable_not_empty() -> None:
    from dataclasses import replace

    from c2hunter_controller.pcap import compile_packet_predicate

    from c2hunter_analysis.pcap_postings import select_posting_candidates

    generation, _ = _filter_generation()
    predicate = compile_packet_predicate(
        {"include_filters": [{"candidate_ip": "0.0.0.0/0"}]},
        internal_networks=["10.0.0.0/8"],
    )
    assert select_posting_candidates(generation, predicate, max_query_work=1) is None
    corrupt = replace(generation, schema_version=999)
    assert select_posting_candidates(corrupt, predicate) is None


@pytest.mark.parametrize(
    ("magic", "endian"),
    [
        (b"\xd4\xc3\xb2\xa1", "<"),
        (b"\xa1\xb2\xc3\xd4", ">"),
        (b"\x4d\x3c\xb2\xa1", "<"),
        (b"\xa1\xb2\x3c\x4d", ">"),
    ],
)
def test_postings_cover_all_classic_endian_and_resolution_variants(
    magic: bytes, endian: str
) -> None:
    from test_pcap_offset_index import _classic

    from c2hunter_analysis.pcap_postings import (
        PostingDimension,
        build_packet_postings,
        posting_values,
    )

    capture = _classic(
        magic,
        endian=endian,
        packets=((9, 7, _udp(b"a"), len(_udp(b"a"))), (8, 7, _udp(b"b"), len(_udp(b"b")))),
    )
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=2, max_interfaces=1)
    generation = build_packet_postings(
        open_export_capture(
            io.BytesIO(capture),
            source_id="classic",
            source_order=0,
            internal_networks=["10.0.0.0/8"],
        ),
        structural_packets=structural.packets,
        structural_interfaces=structural.interfaces,
    )
    assert posting_values(generation, PostingDimension.ALL_PACKET, b"") == (0, 1)


def test_postings_cover_pcapng_sections_interfaces_endian_padding_and_unknown_blocks() -> None:
    from test_pcap_offset_index import _ng_block, _ng_idb, _ng_packet, _ng_section

    from c2hunter_analysis.pcap_postings import (
        PostingDimension,
        build_packet_postings,
        posting_values,
    )

    first = _ng_packet("<", 6, _udp(b"a"), (3 << 32) | 4)
    second = _ng_packet(">", 2, _udp(b"bb"), 3)
    capture = (
        _ng_section("<")
        + _ng_idb("<", snaplen=65_535, exponent=0x8A, offset=-7)
        + _ng_block("<", 0xBAD, b"unknown" + b"\0")
        + first
        + _ng_section(">")
        + _ng_idb(">", snaplen=65_535, exponent=7, offset=11)
        + second
    )
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=2, max_interfaces=2)
    generation = build_packet_postings(
        open_export_capture(
            io.BytesIO(capture), source_id="ng", source_order=0, internal_networks=["10.0.0.0/8"]
        ),
        structural_packets=structural.packets,
        structural_interfaces=structural.interfaces,
    )
    assert posting_values(generation, PostingDimension.ALL_PACKET, b"") == (0, 1)
    assert [item.interface_ordinal for item in structural.packets] == [0, 1]


def test_generation_validation_is_streaming_and_does_not_materialize_posting_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import c2hunter_analysis.pcap_postings as postings

    generation, _ = _filter_generation()

    def forbidden(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("validation must stream chunks without tuple materialization")

    monkeypatch.setattr(postings, "decode_ordinals", forbidden)
    monkeypatch.setattr(postings, "posting_values", forbidden)
    monkeypatch.setattr(postings.PostingGeneration, "digest_document", forbidden)
    assert postings.validate_posting_generation(generation)


def test_generation_validation_preflights_declared_limits_before_decoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dataclasses import replace

    import c2hunter_analysis.pcap_postings as postings

    generation, _ = _filter_generation()
    decoded = 0
    original = postings._iter_decoded_ordinals

    def spy(*args: object, **kwargs: object):
        nonlocal decoded
        decoded += 1
        return original(*args, **kwargs)

    monkeypatch.setattr(postings, "_iter_decoded_ordinals", spy)
    limits = postings.PostingBuildLimits(
        max_packets=generation.packet_count,
        max_memberships=generation.membership_count - 1,
        max_distinct_keys=generation.distinct_key_count,
        max_encoded_bytes=generation.encoded_byte_count,
        batch_size=1,
    )
    assert not postings.validate_posting_generation(generation, limits=limits)
    assert decoded == 0
    assert not postings.validate_posting_generation(
        replace(generation, packet_count=postings.MAX_POSTING_ORDINAL + 2)
    )
    assert decoded == 0


def test_generation_validation_limits_accept_exact_and_plus_one_reject_minus_one() -> None:
    from c2hunter_analysis.pcap_postings import PostingBuildLimits, validate_posting_generation

    generation, _ = _filter_generation()
    exact = {
        "max_packets": generation.packet_count,
        "max_memberships": generation.membership_count,
        "max_distinct_keys": generation.distinct_key_count,
        "max_encoded_bytes": generation.encoded_byte_count,
        "batch_size": 1,
    }
    assert validate_posting_generation(generation, limits=PostingBuildLimits(**exact))
    for field in (
        "max_packets",
        "max_memberships",
        "max_distinct_keys",
        "max_encoded_bytes",
    ):
        assert not validate_posting_generation(
            generation, limits=PostingBuildLimits(**(exact | {field: exact[field] - 1}))
        )
        assert validate_posting_generation(
            generation, limits=PostingBuildLimits(**(exact | {field: exact[field] + 1}))
        )


def test_generation_validation_keeps_cross_chunk_ordering_strict() -> None:
    from dataclasses import replace

    from c2hunter_analysis.pcap_postings import (
        PostingDimension,
        encode_ordinals,
        validate_posting_generation,
    )

    generation, _ = _filter_generation()
    chunks = list(generation.chunks)
    index = next(
        index
        for index, chunk in enumerate(chunks)
        if chunk.dimension is PostingDimension.ALL_PACKET and chunk.chunk_ordinal == 1
    )
    chunks[index] = replace(
        chunks[index],
        first_packet_index=0,
        last_packet_index=0,
        encoded_ordinals=encode_ordinals((0,)),
    )
    assert not validate_posting_generation(replace(generation, chunks=tuple(chunks)))


def test_digest_is_deterministic_across_staging_batch_sizes() -> None:
    from c2hunter_analysis.pcap_postings import PostingBuildLimits, build_packet_postings

    capture = _classic([_udp(bytes([index])) for index in range(6)])
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=6, max_interfaces=1)

    def build(batch_size: int):
        return build_packet_postings(
            open_export_capture(
                io.BytesIO(capture),
                source_id="digest",
                source_order=0,
                internal_networks=["10.0.0.0/8"],
            ),
            structural_packets=structural.packets,
            structural_interfaces=structural.interfaces,
            limits=PostingBuildLimits(batch_size=batch_size),
        )

    assert build(1).digest == build(2).digest == build(6).digest


@pytest.mark.parametrize(
    "limits",
    [
        {"max_packets": 1},
        {"max_memberships": 1},
        {"max_distinct_keys": 1},
        {"max_encoded_bytes": 1},
    ],
)
def test_all_posting_build_resource_bounds_fail_closed(limits: dict[str, int]) -> None:
    from c2hunter_analysis.pcap_postings import (
        PostingBuildLimits,
        PostingResourceLimitError,
        build_packet_postings,
    )

    capture = _classic([_udp(b"a"), _udp(b"b")])
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=2, max_interfaces=1)
    with pytest.raises(PostingResourceLimitError):
        build_packet_postings(
            open_export_capture(
                io.BytesIO(capture),
                source_id="limits",
                source_order=0,
                internal_networks=["10.0.0.0/8"],
            ),
            structural_packets=structural.packets,
            structural_interfaces=structural.interfaces,
            limits=PostingBuildLimits(**limits),
        )


def test_exact_locator_and_interface_mismatches_are_rejected() -> None:
    from dataclasses import replace

    from c2hunter_analysis.pcap_postings import (
        PostingStructuralMismatchError,
        build_packet_postings,
    )

    capture = _classic([_udp()])
    structural = scan_structural_packet_index(io.BytesIO(capture), max_packets=1, max_interfaces=1)
    for packets, interfaces in (
        ((replace(structural.packets[0], data_offset=41),), structural.interfaces),
        (structural.packets, (replace(structural.interfaces[0], link_type=101),)),
    ):
        with pytest.raises(PostingStructuralMismatchError):
            build_packet_postings(
                open_export_capture(
                    io.BytesIO(capture),
                    source_id="mismatch",
                    source_order=0,
                    internal_networks=["10.0.0.0/8"],
                ),
                structural_packets=packets,
                structural_interfaces=interfaces,
            )


def test_seeded_valid_filter_shapes_never_drop_full_predicate_matches() -> None:
    import random

    from c2hunter_controller.pcap import CompiledPacketPredicate, compile_packet_predicate

    from c2hunter_analysis.pcap_postings import select_posting_candidates

    generation, packets = _filter_generation()
    nested_atoms: list[dict[str, object]] = [
        {"candidate_ip": "203.0.113.0/24"},
        {"candidate_ip": "0.0.0.0/0"},
        {"protocol": "udp"},
        {"source_port": 53},
        {"destination_port": 8080},
        {"has_payload": False},
        {"direction": "INBOUND"},
        {"port": 443},
    ]
    rng = random.Random(0xC2A11)
    non_subtractable: dict[str, object] = {
        "exclude_filters": [{"direction": "OUTBOUND", "port": 443}]
    }
    top_level_time_shapes: list[dict[str, object]] = [
        {"start_time": "1969-01-01T00:00:00+00:00"},
        {"end_time": "2099-01-01T00:00:00+00:00"},
        {
            "start_time": "1969-01-01T00:00:00+00:00",
            "end_time": "2099-01-01T00:00:00+00:00",
        },
    ]
    shapes: list[dict[str, object]] = [
        {"include_filters": [{"candidate_ip": "0.0.0.0/0"}]},
        {"include_filters": [{"source_port": 53}, {"destination_port": 8080}]},
        {"exclude_filters": [{"source_port": 53, "protocol": "udp"}]},
        {"exclude_filters": [{"direction": "OUTBOUND", "source_port": 53}]},
        {"include_filters": [{"port": 443, "protocol": "udp"}]},
        non_subtractable,
        *top_level_time_shapes,
    ]
    for _ in range(80):
        include = [dict(rng.choice(nested_atoms)) for _ in range(rng.randint(0, 3))]
        exclude = [dict(rng.choice(nested_atoms)) for _ in range(rng.randint(0, 2))]
        shape: dict[str, object] = {}
        if include:
            shape["include_filters"] = include
        if exclude:
            shape["exclude_filters"] = exclude
        shapes.append(shape)

    for shape in shapes:
        predicate = compile_packet_predicate(shape, internal_networks=["10.0.0.0/8"])
        assert isinstance(predicate, CompiledPacketPredicate)
        selected = select_posting_candidates(generation, predicate, max_query_work=1_000)
        assert selected is not None
        candidates = set(selected)
        matches = {
            packet.locator.packet_index
            for packet in packets
            if predicate.matches(packet, sensor_id="sensor-a")
        }
        assert matches <= candidates, shape
        if shape == non_subtractable or shape in top_level_time_shapes:
            assert candidates == {0, 1, 2}, shape
