from datetime import timedelta

import pytest
from test_network_anomaly import frame, records
from test_network_report import report


def measured(items):
    return report(items)["issues"][0]["examples"][0]["measurements"]


def test_supporting_handshake_rtt_is_not_a_standalone_anomaly():
    items = records(
        frame(),
        frame(flags=18, seq=500, ack=101, reverse=True),
        frame(flags=24, seq=101, payload=b"abc"),
        frame(flags=24, seq=101, payload=b"abc"),
    )
    result = report(items)
    measurement = result["issues"][0]["examples"][0]["measurements"]
    assert measurement["observed_rtt_ms"]["count"] == 1
    assert measurement["observed_rtt_ms"]["mean"] == pytest.approx(100)
    assert measurement["rtt_sources"] == {"syn_ack": 1, "data_ack": 0}
    assert result["measurement_version"] == "network-supporting-measurements-v1"
    assert result["summary"]["suspected_cause"]["confidence"] == "low"
    assert result["issues"][0]["detailed_analysis"]
    assert report(items[:2])["issues"] == []


def test_data_ack_online_statistics_and_karn_exclusions():
    items = records(
        frame(flags=24, seq=100, payload=b"abc"),
        frame(flags=16, seq=500, ack=103, reverse=True),
        frame(flags=24, seq=103, payload=b"abc"),
        frame(flags=16, seq=500, ack=106, reverse=True),
        frame(flags=24, seq=106, payload=b"abc"),
        frame(flags=24, seq=106, payload=b"abc"),
        frame(flags=16, seq=500, ack=109, reverse=True),
    )
    items[3]["timestamp"] = items[2]["timestamp"] + timedelta(milliseconds=200)
    items[4]["timestamp"] = items[3]["timestamp"]
    m = measured(items)
    assert m["rtt_sources"] == {"syn_ack": 0, "data_ack": 2}
    assert m["observed_rtt_ms"] == {"count": 2, "min": 100, "max": 200, "mean": 150, "stddev": 50}
    assert m["rtt_excluded"]["ambiguous"] == 1


@pytest.mark.parametrize("variant", ["overlap", "cumulative", "nonexact", "wrap", "equal_time"])
def test_ambiguous_data_ack_never_becomes_rtt(variant):
    first = frame(flags=24, seq=100, payload=b"abc")
    second = frame(flags=24, seq=101 if variant == "overlap" else 103, payload=b"abc")
    ack = frame(flags=16, seq=500, ack=106 if variant == "cumulative" else 104, reverse=True)
    items = records(first, second, ack)
    if variant == "nonexact":
        items = records(first, ack)
    elif variant == "wrap":
        items = records(
            frame(flags=24, seq=2**32 - 2, payload=b"abc"), frame(flags=16, ack=1, reverse=True)
        )
    elif variant == "equal_time":
        items = records(first, frame(flags=16, ack=103, reverse=True))
        items[1]["timestamp"] = items[0]["timestamp"]
    # A later repeated SYN produces an issue without changing previous samples.
    more = records(frame(seq=1000), frame(seq=1000))
    for item in more:
        item["timestamp"] = items[-1]["timestamp"] + timedelta(seconds=1)
    m = measured(items + more)
    assert m["observed_rtt_ms"]["count"] == 0
    assert m["observed_rtt_ms"]["mean"] is None


def test_directional_spacing_ttl_zero_and_missing_are_not_path_proof():
    items = records(*(frame(protocol=17, payload=b"x") for _ in range(4)))
    for item, milliseconds, ttl in zip(items, (0, 100, 400, 900), (0, 63, 63, None), strict=True):
        item["timestamp"] = items[0]["timestamp"] + timedelta(milliseconds=milliseconds)
        item["ip_ttl"] = ttl
    m = measured(items)
    assert m["interarrival_variation_ms"]["a_to_b"] == {
        "count": 3,
        "min": 100,
        "max": 500,
        "mean": 300,
        "stddev": pytest.approx(163.299316),
    }
    assert m["ttl_observed"]["a_to_b"] == {
        "count": 3,
        "min": 0,
        "max": 63,
        "changes": 1,
        "missing": 1,
    }
    assert m["ttl_observed"]["b_to_a"]["min"] is None
    assert m["observed_rtt_ms"]["mean"] is None
    assert "NOT_TCP" in m["reasons"]
    assert "MISSING_TTL" in m["reasons"]


@pytest.mark.parametrize(
    "invalid", [{"packet_count": 4}, {"tcp_window": None}, {"packet_evidence_complete": False}]
)
def test_metadata_gap_clears_matching_and_spacing(invalid):
    items = records(
        frame(),
        frame(),
        frame(flags=24, seq=101, payload=b"abc"),
        frame(flags=16, ack=104, reverse=True),
        frame(flags=16, ack=104, reverse=True),
    )
    items[3].update(invalid)
    m = measured(items)
    assert m["observed_rtt_ms"]["count"] == 0
    assert m["interarrival_variation_ms"]["b_to_a"]["count"] == 0
    assert "INCOMPLETE_PACKET_EVIDENCE" in m["reasons"]
    assert m["coverage_complete"] is False
    assert report([{**items[0], **invalid}])["summary"]["verdict"] == "insufficient_evidence"


@pytest.mark.parametrize("response", [18, 20])
def test_repeated_syn_and_reset_response_are_not_rtt(response):
    items = records(frame(), frame(), frame(flags=response, ack=101, reverse=True))
    m = measured(items)
    assert m["observed_rtt_ms"]["count"] == 0
    assert m["rtt_excluded"]["ambiguous"] == (1 if response == 18 else 0)


def test_reversed_clock_stops_measurements_without_erasing_prior_facts():
    items = records(frame(), frame(), frame(flags=18, ack=101, reverse=True))
    items[2]["timestamp"] = items[0]["timestamp"]
    m = measured(items)
    assert m["observed_rtt_ms"]["mean"] is None
    assert "NON_MONOTONIC_TIMESTAMPS" in m["reasons"]
    assert m["ttl_observed"]["a_to_b"]["count"] == 2


def test_ipv6_hop_limit_and_icmp_outer_ttl_are_not_quoted_endpoint_ttl():
    import ipaddress
    import struct

    transport = frame(protocol=17, payload=b"x")[34:]
    ethernet = bytes.fromhex("00112233445566778899aabb86dd")
    ip6 = struct.pack("!IHBB", 6 << 28, len(transport), 17, 23)
    ip6 += ipaddress.ip_address("2001:db8::1").packed
    ip6 += ipaddress.ip_address("2001:db8::2").packed
    parsed = records(ethernet + ip6 + transport, ethernet + ip6 + transport)
    assert parsed[0]["ip_ttl"] == 23
    assert measured(parsed)["ttl_observed"]["a_to_b"]["min"] == 23
    udp = frame(protocol=17, payload=b"query")
    error = bytearray(frame(protocol=1, reverse=True, payload=udp[14:42]))
    error[22] = 11
    parsed = records(udp, bytes(error))
    m = measured(parsed)
    assert m["ttl_observed"]["a_to_b"]["min"] == 64
    assert m["ttl_observed"]["b_to_a"]["min"] is None


def test_time_gap_does_not_claim_bidirectional_coverage_was_absent():
    items = records(frame(), frame(flags=18, ack=101, reverse=True), frame(), frame())
    items = [*items, {**items[-1], "packet_evidence_complete": False}]
    m = measured(items)
    assert "INCOMPLETE_PACKET_EVIDENCE" in m["reasons"]
    assert "ONE_DIRECTION_OBSERVED" not in m["reasons"]


def test_online_measurements_stay_constant_space_and_consume_once():
    import json
    import tracemalloc

    packet = records(frame(protocol=17, payload=b"x"))[0]

    class Once:
        def __init__(self, count):
            self.count = count
            self.iterated = False

        def __iter__(self):
            assert not self.iterated
            self.iterated = True
            for _ in range(self.count):
                yield packet

    peaks = []
    for count in (1000, 20000):
        tracemalloc.start()
        result = report(Once(count))
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        peaks.append(peak)
        m = result["issues"][0]["examples"][0]["measurements"]
        assert m["interarrival_variation_ms"]["a_to_b"]["count"] == count - 1
        assert m["ttl_observed"]["a_to_b"]["count"] == count
        assert len(json.dumps(result, allow_nan=False).encode()) < 10000
    assert peaks[1] < peaks[0] + 100000


def test_ttl_variation_alone_is_observation_not_new_anomaly():
    items = records(frame(flags=16), frame(flags=16, reverse=True), frame(flags=16))
    items[-1]["ip_ttl"] = 12
    result = report(items)
    assert result["issues"] == []
    assert result["summary"]["verdict"] == "no_clear_anomaly"


def test_budget_limit_marks_representative_measurements_incomplete(monkeypatch):
    from c2hunter_analysis import network_report

    monkeypatch.setattr(network_report, "MAX_FLOW_CORRELATIONS", 1)
    items = records(
        frame(flags=24, payload=b"a"),
        frame(flags=24, payload=b"a"),
        frame(flags=24, seq=200, payload=b"b"),
    )
    m = measured(items)
    assert "CORRELATION_LIMIT_REACHED" in m["reasons"]
    assert m["coverage_complete"] is False
