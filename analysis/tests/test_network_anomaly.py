"""Small genuine PCAP byte fixtures; no packet library or network required."""

import struct

from c2hunter_analysis.pcap import parse_pcap


def internet_checksum(data):
    data += b"\x00" * (len(data) % 2)
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(flags=2, seq=100, ack=0, payload=b"", reverse=False, protocol=6, window=8192):
    src, dst = bytes((10, 0, 0, 1)), bytes((203, 0, 113, 1))
    sport, dport = 50000, 443
    if reverse:
        src, dst, sport, dport = dst, src, dport, sport
    if protocol == 6:
        transport = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 80, flags, window, 0, 0)
    elif protocol == 17:
        transport = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    else:
        transport = bytes((3, 1, 0, 0, 0, 0, 0, 0))
    transport += payload
    checksum_offset = {6: 16, 17: 6}.get(protocol, 2)
    pseudo = (
        src + dst + struct.pack("!BBH", 0, protocol, len(transport)) if protocol in (6, 17) else b""
    )
    checksum = internet_checksum(pseudo + transport)
    transport = (
        transport[:checksum_offset]
        + struct.pack("!H", checksum or 65535)
        + transport[checksum_offset + 2 :]
    )
    ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(transport), 1, 0, 64, protocol, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", internet_checksum(ip)) + ip[12:]
    return bytes.fromhex("00112233445566778899aabb0800") + ip + transport


def capture(*frames):
    result = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for index, packet in enumerate(frames):
        seconds, micros = divmod(index * 100000, 1000000)
        result += struct.pack("<IIII", 1 + seconds, micros, len(packet), len(packet)) + packet
    return result


def records(*frames):
    return parse_pcap(
        capture(*frames),
        sensor_id="s1",
        internal_networks=["10.0.0.0/8"],
        retain_packet_bytes=False,
        retain_network_evidence=True,
    ).records


def test_parser_preserves_exact_packet_evidence_without_raw_bytes():
    record = records(frame(flags=16, seq=101, ack=501, payload=b"abc"))[0]
    assert record.get("tcp_sequence") == 101
    assert record["tcp_acknowledgment"] == 501
    assert record["tcp_window"] == 8192
    assert record["packet_evidence_complete"] is True
    assert record["ip_ttl"] == 64
    assert record["capture_interface_id"] == 0
    assert "raw_packet_bytes" not in record


def analyze(*frames, **kwargs):
    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    return analyze_network_anomalies(records(*frames), **kwargs)


def test_matched_handshake_and_syn_retransmission_with_reset():
    from importlib.util import find_spec

    assert find_spec("c2hunter_analysis.network_anomaly") is not None
    good = analyze(frame(), frame(flags=18, seq=500, ack=101, reverse=True))
    assert good["flows"][0]["metrics"]["observed_rtt_ms"]["mean"] == 100.0
    retried = analyze(frame(), frame(), frame(flags=20, ack=101, reverse=True))
    flow = retried["flows"][0]
    assert flow["metrics"]["syn_retransmissions"] == 1
    assert flow["metrics"]["matched_resets"] == 1
    assert flow["metrics"]["observed_rtt_ms"]["count"] == 0
    assert flow["observed_directions"]["a_to_b"]["packets"] == 2
    assert flow["observed_directions"]["b_to_a"]["packets"] == 1


def test_data_repeats_strict_duplicate_ack_and_karn_rtt():
    data = frame(flags=24, seq=101, payload=b"abc")
    ack = frame(flags=16, seq=500, ack=101, reverse=True)
    result = analyze(
        data,
        data,
        ack,
        ack,
        frame(flags=16, seq=500, ack=101, reverse=True, window=100),
        frame(flags=16, seq=500, ack=104, reverse=True),
    )
    metric = result["flows"][0]["metrics"]
    assert metric["data_retransmissions"] == 1
    assert metric["duplicate_acks"] == 1
    assert metric["observed_rtt_ms"]["count"] == 0
    clean = analyze(data, frame(flags=16, seq=500, ack=104, reverse=True))
    assert clean["flows"][0]["metrics"]["observed_rtt_ms"]["mean"] == 100.0
    ack_only = analyze(ack, ack)
    assert ack_only["flows"][0]["metrics"]["duplicate_acks"] == 0
    different = analyze(data, frame(flags=24, seq=101, payload=b"xyz"))
    assert different["flows"][0]["metrics"]["data_retransmissions"] == 0


def test_udp_duplicate_candidates_and_directional_variation():
    packet = frame(protocol=17, payload=b"dns-id-123-query")
    result = analyze(packet, packet, packet)
    flow = result["flows"][0]
    assert flow["metrics"]["udp_duplicate_candidates"] == 2
    assert flow["metrics"]["interarrival_variation_ms"]["a_to_b"]["stddev"] == 0
    assert flow["metrics"]["interarrival_variation_ms"]["a_to_b"]["mean"] == 100
    assert flow["metrics"]["ttl_observed"]["a_to_b"] == {"min": 64, "max": 64}
    assert "ONE_DIRECTION_OBSERVED" in flow["warnings"]
    assert "routing" in " ".join(result["limitations"])


def test_icmp_error_quotes_original_udp_flow():
    udp = frame(protocol=17, payload=b"query")
    error = frame(protocol=1, reverse=True, payload=udp[14:42])
    parsed = records(udp, error)
    assert parsed[1].get("icmp_type") == 3
    assert parsed[1]["icmp_quoted_flow"]["destination_port"] == 443
    result = analyze(udp, error)
    flow = next(f for f in result["flows"] if f["protocol"] == "UDP")
    assert flow["metrics"]["icmp_errors"] == 1
    assert flow["metrics"]["icmp_error_details"][0]["type"] == 3
    assert flow["observed_directions"]["b_to_a"]["packets"] == 0
    short = records(frame(protocol=1, payload=b"short"))[0]
    assert short.get("icmp_quoted_flow") is None


def test_incomplete_packets_do_not_support_timing_or_transport_inference():
    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    base = records(frame(flags=24, payload=b"abc"))[0]
    incomplete = {**base, "packet_evidence_complete": False, "packet_count": 10}
    result = analyze_network_anomalies([incomplete, incomplete, {}, {**base, "total_bytes": None}])
    flow = result["flows"][0]
    assert flow["metrics"]["data_retransmissions"] == 0
    assert flow["metrics"]["interarrival_variation_ms"]["a_to_b"]["count"] == 0
    assert "INCOMPLETE_PACKET_EVIDENCE" in flow["warnings"]
    assert result["summary"]["skipped_records"] == 2


def test_limits_and_vantage_isolation():
    import json

    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    packet = records(frame())[0]
    limited = analyze_network_anomalies([packet] * 4, max_packets=2)
    assert limited["summary"]["truncated"] is True
    assert limited["summary"]["scanned_records"] == 2
    limited = analyze_network_anomalies([packet, {**packet, "sensor_id": "other"}], max_flows=1)
    assert limited["summary"]["truncated"] is True
    separated = analyze_network_anomalies([packet, {**packet, "capture_interface_id": 1}])
    assert len(separated["flows"]) == 2
    json.dumps(separated, allow_nan=False)
    many = records(*(frame(flags=24, seq=i * 10, payload=b"x") for i in range(260)))
    bounded = analyze_network_anomalies(many)
    assert "FLOW_STATE_LIMIT_REACHED" in bounded["flows"][0]["warnings"]


def test_snaplen_and_fragment_evidence_is_incomplete():
    short = frame(payload=b"abcdef")[:-3]
    assert records(short)[0]["packet_evidence_complete"] is False
    fragment = bytearray(frame(payload=b"abc"))
    fragment[20:22] = b"\x20\x00"
    assert records(bytes(fragment))[0]["packet_evidence_complete"] is False


def test_clock_reversal_disables_correlations_and_connection_reuse_clears_data():
    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    data = frame(flags=24, seq=101, payload=b"abc")
    items = records(data, data)
    backwards = analyze_network_anomalies([items[1], items[0]])
    assert backwards["flows"][0]["metrics"]["data_retransmissions"] == 0
    assert "NON_MONOTONIC_TIMESTAMPS" in backwards["flows"][0]["warnings"]
    reused = analyze(data, frame(flags=4, reverse=True), frame(), data)
    assert reused["flows"][0]["metrics"]["data_retransmissions"] == 0


def test_missing_ack_window_and_partial_overlaps_never_make_rtt():
    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    data, ack = records(
        frame(flags=24, seq=101, payload=b"abc"), frame(flags=16, seq=500, ack=104, reverse=True)
    )
    missing = {**ack, "tcp_window": None}
    result = analyze_network_anomalies([data, missing])
    assert result["flows"][0]["metrics"]["observed_rtt_ms"]["count"] == 0
    overlap = analyze(
        frame(flags=24, seq=101, payload=b"abc"),
        frame(flags=24, seq=102, payload=b"bc"),
        frame(flags=16, seq=500, ack=104, reverse=True),
    )
    assert overlap["flows"][0]["metrics"]["observed_rtt_ms"]["count"] == 0


def test_duplicate_ack_excludes_payload_control_zero_window_and_missing_metadata():
    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    data = frame(flags=24, seq=101, payload=b"abc")
    for flags, payload, window in (
        (16, b"x", 8192),
        (17, b"", 8192),
        (48, b"", 8192),
        (16, b"", 0),
    ):
        ack = frame(flags=flags, seq=500, ack=101, reverse=True, payload=payload, window=window)
        metric = analyze(data, ack, ack)["flows"][0]["metrics"]
        assert metric["duplicate_acks"] == 0
    for field in ("tcp_sequence", "tcp_acknowledgment", "tcp_window", "transport_payload_length"):
        items = records(data, frame(flags=16, seq=500, ack=101, reverse=True))
        incomplete = {**items[1], field: None}
        flow = analyze_network_anomalies([items[0], incomplete, incomplete])["flows"][0]
        assert flow["metrics"]["duplicate_acks"] == 0
        assert "INCOMPLETE_PACKET_EVIDENCE" in flow["warnings"]


def test_retried_syn_and_cross_interface_response_never_make_rtt():
    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    response = frame(flags=18, seq=500, ack=101, reverse=True)
    retried = analyze(frame(), frame(), response)["flows"][0]["metrics"]
    assert retried["syn_retransmissions"] == 1
    assert retried["observed_rtt_ms"]["count"] == 0
    items = records(frame(), response)
    items[1]["capture_interface_id"] = 1
    isolated = analyze_network_anomalies(items)
    assert len(isolated["flows"]) == 2
    for flow in isolated["flows"]:
        assert flow["metrics"]["observed_rtt_ms"]["count"] == 0
        assert "ONE_DIRECTION_OBSERVED" in flow["warnings"]


def test_idle_connection_reuse_is_not_udp_duplicate_or_tcp_retransmission():
    from datetime import timedelta

    from c2hunter_analysis.network_anomaly import analyze_network_anomalies

    for protocol in (6, 17):
        packet = records(frame(flags=24, protocol=protocol, payload=b"abc"))[0]
        later = {**packet, "timestamp": packet["timestamp"] + timedelta(seconds=61)}
        flow = analyze_network_anomalies([packet, later])["flows"][0]
        assert flow["metrics"]["data_retransmissions"] == 0
        assert flow["metrics"]["udp_duplicate_candidates"] == 0
