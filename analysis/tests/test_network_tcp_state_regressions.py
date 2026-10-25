"""Native TCP sequence/lifetime regressions through parser, schema and worker."""

import sys
from datetime import timedelta
from pathlib import Path

import pytest
from test_network_anomaly import capture, frame

from c2hunter_analysis.network_anomaly import analyze_network_anomalies
from c2hunter_analysis.network_report import analyze_network_report
from c2hunter_analysis.pcap import parse_pcap

MODULUS = 2**32
ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(params=["worker", "legacy"])
def analyze(request, monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "sensor/worker/src"))
    monkeypatch.syspath_prepend(str(ROOT / "controller/src"))
    from c2hunter_controller.schemas import FlowRecord
    from c2hunter_worker.analysis import execute_analysis

    def run(frames, *, interval=timedelta(milliseconds=100)):
        source = parse_pcap(
            capture(*frames, interval=interval),
            sensor_id="s1",
            internal_networks=["10.0.0.0/8"],
            retain_packet_bytes=False,
            retain_network_evidence=True,
        )
        parsed = source.records
        assert len(parsed) == len(frames)
        assert all(row["packet_evidence_complete"] for row in parsed)
        rows = [FlowRecord.model_validate(row).model_dump(mode="json") for row in parsed]
        if request.param == "worker":
            report = execute_analysis(
                {
                    "analysis": {"module": "network_anomaly"},
                    "flow_records": rows,
                    "source": {
                        "captured_packet_count": source.captured_packet_count,
                        "skipped_packet_count": source.skipped_packet_count,
                    },
                }
            )["network_anomaly"]
            assert report == analyze_network_report(rows)
            assert report["summary"]["evaluated_records"] == len(rows)
            counts = {}
            for issue in report["issues"]:
                counts[issue["pattern"]] = counts.get(issue["pattern"], 0) + issue["event_count"]
        else:
            report = analyze_network_anomalies(rows)
            assert report["summary"]["scanned_records"] == len(rows)
            counts = {
                key: value
                for key, value in report["flows"][0]["metrics"].items()
                if key in {"duplicate_acks", "data_retransmissions", "syn_retransmissions"}
                and value
            }
        for name, module in list(sys.modules.items()):
            if name.startswith(("c2hunter_analysis", "c2hunter_controller", "c2hunter_worker")):
                origin = getattr(module, "__file__", None)
                if origin:
                    assert Path(origin).resolve().is_relative_to(ROOT), (name, origin)
        return counts, report

    return run


def handshake(seq, reverse=False):
    return [
        frame(seq=(seq - 1) % MODULUS, reverse=reverse),
        frame(flags=18, seq=499, ack=seq, reverse=not reverse),
        frame(flags=16, seq=seq, ack=500, reverse=reverse),
    ]


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 3, MODULUS - 2, MODULUS - 1, 0])
def test_fully_acknowledged_data_is_not_outstanding(analyze, reverse, seq):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    ack = frame(flags=16, seq=500, ack=(seq + 3) % MODULUS, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data, ack, ack])
    assert counts == {}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 2])
def test_wrapped_gap_preserves_real_duplicate_ack_and_exact_repeat(analyze, reverse, seq):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    later = frame(flags=24, seq=(seq + 6) % MODULUS, ack=500, payload=b"xyz", reverse=reverse)
    ack = frame(flags=16, seq=500, ack=(seq + 3) % MODULUS, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data, later, ack, ack, later])
    assert counts == {"duplicate_acks": 1, "data_retransmissions": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 2])
@pytest.mark.parametrize("ack_offset", [-1, 2**31, 2**31 + 3])
def test_stale_or_ambiguous_ack_never_creates_duplicate_evidence(analyze, reverse, seq, ack_offset):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    later = frame(flags=24, seq=(seq + 6) % MODULUS, ack=500, payload=b"xyz", reverse=reverse)
    ack = frame(flags=16, seq=500, ack=(seq + 3) % MODULUS, reverse=not reverse)
    stale = frame(flags=16, seq=500, ack=(seq + ack_offset) % MODULUS, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data, later, ack, stale, stale, ack, ack])
    assert counts == {"duplicate_acks": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 2])
@pytest.mark.parametrize("fin_repeats", [1, 2])
def test_half_close_preserves_other_direction_exact_repeat(analyze, reverse, seq, fin_repeats):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    fin = frame(flags=17, seq=500, ack=seq, reverse=not reverse)
    fin_ack = frame(flags=16, seq=(seq + 3) % MODULUS, ack=501, reverse=reverse)
    repeat = frame(flags=24, seq=seq, ack=501, payload=b"abc", reverse=reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data] + [fin] * fin_repeats + [fin_ack, repeat])
    assert counts == {"data_retransmissions": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 2])
def test_both_fins_without_both_acks_preserve_closing_data_repeats(analyze, reverse, seq):
    first = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    second = frame(flags=24, seq=500, ack=seq, payload=b"xyz", reverse=not reverse)
    fins = [
        frame(flags=17, seq=(seq + 3) % MODULUS, ack=500, reverse=reverse),
        frame(flags=17, seq=503, ack=seq, reverse=not reverse),
    ]
    counts, _ = analyze(handshake(seq, reverse) + [first, second] + fins + [first, second])
    assert counts == {"data_retransmissions": 2}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 3])
@pytest.mark.parametrize("boundary", ["rst", "new_syn", "full_close"])
def test_connection_retirement_does_not_join_same_payload(analyze, reverse, seq, boundary):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    if boundary == "rst":
        ending = [frame(flags=4, seq=500, reverse=not reverse)]
    elif boundary == "new_syn":
        ending = handshake(seq, reverse)
    else:
        ending = [
            frame(flags=17, seq=(seq + 3) % MODULUS, ack=500, reverse=reverse),
            frame(flags=17, seq=500, ack=(seq + 4) % MODULUS, reverse=not reverse),
            frame(flags=16, seq=(seq + 4) % MODULUS, ack=501, reverse=reverse),
        ]
    counts, _ = analyze(handshake(seq, reverse) + [data] + ending + [data])
    assert counts == {}


@pytest.mark.parametrize("reverse", [False, True])
def test_fin_payload_does_not_erase_prior_unacknowledged_data(analyze, reverse):
    data = frame(flags=24, seq=101, ack=500, payload=b"abc", reverse=reverse)
    fin = frame(flags=17, seq=500, ack=101, payload=b"bye", reverse=not reverse)
    counts, _ = analyze(handshake(101, reverse) + [data, fin, fin, data])
    assert counts == {"data_retransmissions": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 3])
@pytest.mark.parametrize("fin_sender", ["sender", "receiver"])
def test_fin_ack_progress_retires_data_before_stale_acks(analyze, reverse, seq, fin_sender):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    end = (seq + 3) % MODULUS
    if fin_sender == "sender":
        closing = [
            frame(flags=17, seq=end, ack=500, reverse=reverse),
            frame(flags=16, seq=500, ack=(end + 1) % MODULUS, reverse=not reverse),
        ]
        peer_seq = 500
    else:
        closing = [frame(flags=17, seq=500, ack=end, reverse=not reverse)]
        peer_seq = 501
    stale = frame(flags=16, seq=peer_seq, ack=seq, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data] + closing + [stale, stale])
    assert counts == {}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seq", [101, MODULUS - 2])
@pytest.mark.parametrize("offset", [-1, -(2**31) + 4])
def test_handshake_ack_frontier_rejects_stale_first_data_ack(analyze, reverse, seq, offset):
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    stale = frame(flags=16, seq=500, ack=(seq + offset) % MODULUS, reverse=not reverse)
    valid = frame(flags=16, seq=500, ack=seq, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data, stale, stale, valid, valid])
    assert counts == {"duplicate_acks": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("offset", [2**31 + 3, 2**31 - 1])
def test_ambiguous_data_coordinates_do_not_erase_exact_or_unrelated_evidence(
    analyze, reverse, offset
):
    seq = MODULUS - 2
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    uncertain = frame(
        flags=24, seq=(seq + offset) % MODULUS, ack=500, payload=b"xyz", reverse=reverse
    )
    ack = frame(flags=16, seq=500, ack=seq, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data, uncertain, uncertain, ack, ack])
    assert counts == {"data_retransmissions": 1, "duplicate_acks": 1}


@pytest.mark.parametrize("reverse", [False, True])
def test_half_closed_peer_can_receive_new_data_after_repeated_acknowledged_fin(analyze, reverse):
    fin = frame(flags=17, seq=500, ack=101, reverse=not reverse)
    ack = frame(flags=16, seq=101, ack=501, reverse=reverse)
    data = frame(flags=24, seq=101, ack=501, payload=b"abc", reverse=reverse)
    gap = frame(flags=16, seq=501, ack=101, reverse=not reverse)
    counts, _ = analyze(handshake(101, reverse) + [fin, ack, data, fin, data, gap, gap])
    assert counts == {"data_retransmissions": 1, "duplicate_acks": 1}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("window", [0, 100, 8192])
def test_wrapped_duplicate_ack_requires_positive_unchanged_window(analyze, reverse, window):
    seq = MODULUS - 2
    data = frame(flags=24, seq=seq, ack=500, payload=b"abc", reverse=reverse)
    first = frame(flags=16, seq=500, ack=seq, window=8192, reverse=not reverse)
    second = frame(flags=16, seq=500, ack=seq, window=window, reverse=not reverse)
    counts, _ = analyze(handshake(seq, reverse) + [data, first, second])
    assert counts == ({"duplicate_acks": 1} if window == 8192 else {})


@pytest.mark.parametrize("reverse", [False, True])
def test_repeated_acknowledged_fin_does_not_prevent_full_retirement(analyze, reverse):
    data = frame(flags=24, seq=101, ack=500, payload=b"abc", reverse=reverse)
    fin = frame(flags=17, seq=500, ack=104, reverse=not reverse)
    ack = frame(flags=16, seq=104, ack=501, reverse=reverse)
    other_fin = frame(flags=17, seq=104, ack=501, reverse=reverse)
    final_ack = frame(flags=16, seq=501, ack=105, reverse=not reverse)
    counts, _ = analyze(handshake(101, reverse) + [data, fin, ack, fin, other_fin, final_ack, data])
    assert counts == {}


@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("seconds", [60, 61])
def test_half_close_does_not_extend_idle_epoch(analyze, reverse, seconds):
    data = frame(flags=24, seq=101, ack=500, payload=b"abc", reverse=reverse)
    fin = frame(flags=17, seq=500, ack=101, reverse=not reverse)
    counts, _ = analyze(
        handshake(101, reverse) + [data, fin, data], interval=timedelta(seconds=seconds)
    )
    assert counts == ({"data_retransmissions": 1} if seconds == 60 else {})
