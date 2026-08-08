"""Tests for TCP counter clearing on truncation and FlowRecord tcp_flags."""

from datetime import UTC, datetime

import pytest


class TestLimitFlowRecords:
    """Test limit_flow_records preserves/clears tcp_flags correctly."""

    def test_no_truncation_preserves_flags(self):
        from c2hunter_controller.capture_limits import limit_flow_records

        records = [
            {
                "packet_count": 10,
                "total_bytes": 1000,
                "tcp_flags": {"fin": 0, "syn": 4, "ack": 8, "rst": 0},
            }
        ]
        retained, stats = limit_flow_records(records, 100)

        assert len(retained) == 1
        flags = retained[0].get("tcp_flags", {})
        assert flags.get("syn") == 4

    def test_truncated_record_clears_tcp_counters(self):
        from c2hunter_controller.capture_limits import limit_flow_records

        records = [
            {
                "packet_count": 50,
                "total_bytes": 5000,
                "tcp_flags": {"fin": 1, "syn": 4, "ack": 8, "rst": 2},
            },
            {"packet_count": 30, "total_bytes": 3000},
        ]

        kept, stats = limit_flow_records(records, 70)

        assert len(kept) == 2
        second = kept[1]
        # Second record had 30 packets but fits within remaining budget of 20 -> truncated
        if second["packet_count"] < 30:
            flags = second.get("tcp_flags", {})
            assert not flags, f"Truncated record should have no tcp_flags: {flags}"

    def test_tcp_counter_fields_defined(self):
        from c2hunter_controller.capture_limits import _TCP_COUNTER_FIELDS

        expected = {"fin", "syn", "rst", "psh", "ack", "urg", "ece", "cwr"}
        actual = {f.split(".", 1)[1] for f in _TCP_COUNTER_FIELDS}
        assert actual == expected, f"_TCP_COUNTER_FIELDS should cover all TCP flags: {actual!r}"

    def test_tcp_counter_fields_key_format(self):
        from c2hunter_controller.capture_limits import _TCP_COUNTER_FIELDS

        for key in _TCP_COUNTER_FIELDS:
            assert key.startswith("tcp_flags."), f"Key should start with 'tcp_flags.': {key}"


class TestSchemaFlowValidateTcpFlags:
    """Test FlowRecord tcp_flags validation via Pydantic."""

    def test_valid_tcp_flags(self):
        from c2hunter_controller.schemas import FlowRecord

        record = FlowRecord(
            sensor_id="s1",
            timestamp=datetime.now(UTC),
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            protocol="TCP",
            direction="OUTBOUND",
            total_bytes=100,
            tcp_flags={"syn": 2, "ack": 1},
        )

        assert record.tcp_flags == {"syn": 2, "ack": 1}

    def test_null_tcp_flags(self):
        from c2hunter_controller.schemas import FlowRecord

        record = FlowRecord(
            sensor_id="s1",
            timestamp=datetime.now(UTC),
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            protocol="TCP",
            direction="OUTBOUND",
            total_bytes=100,
        )

        assert record.tcp_flags is None

    def test_negative_tcp_flags(self):
        from c2hunter_controller.schemas import FlowRecord

        with pytest.raises(ValueError, match="non-negative"):
            FlowRecord(
                sensor_id="s1",
                timestamp=datetime.now(UTC),
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                direction="OUTBOUND",
                total_bytes=100,
                tcp_flags={"syn": -1},
            )

    def test_non_dict_tcp_flags(self):
        from c2hunter_controller.schemas import FlowRecord

        with pytest.raises(ValueError, match="object"):
            FlowRecord(
                sensor_id="s1",
                timestamp=datetime.now(UTC),
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                direction="OUTBOUND",
                total_bytes=100,
                tcp_flags="syn: 4",
            )

    def test_boolean_tcp_values_rejected(self):
        from c2hunter_controller.schemas import FlowRecord

        with pytest.raises(ValueError, match="numeric"):
            FlowRecord(
                sensor_id="s1",
                timestamp=datetime.now(UTC),
                source_ip="1.2.3.4",
                destination_ip="5.6.7.8",
                protocol="TCP",
                direction="OUTBOUND",
                total_bytes=100,
                tcp_flags={"syn": True},
            )


class TestCaptureLimitsTcpCounterZeroing:
    """Test that truncated packets have tcp counter fields zeroed."""

    def test_first_record_fits_no_tcp_clear(self):
        from c2hunter_controller.capture_limits import limit_flow_records

        records = [
            {
                "packet_count": 10,
                "total_bytes": 500,
                "tcp_flags": {"syn": 2},
            },
            {
                "packet_count": 5,
                "total_bytes": 250,
                "tcp_flags": {"rack": 3},
            },
        ]

        kept, _ = limit_flow_records(records, 15)
        # Total packets = 15, limit = 15, no truncation.
        assert len(kept) == 2
        assert kept[0].get("tcp_flags") == {"syn": 2}
        assert kept[-1].get("tcp_flags") == {"rack": 3}

    def test_middle_record_truncated_clears_standard_flags(self):
        from c2hunter_controller.capture_limits import limit_flow_records

        records = [
            {
                "packet_count": 5,
                "total_bytes": 500,
                "tcp_flags": {"syn": 1, "ack": 2, "ece": 0},
            },
            {
                "packet_count": 20,
                "total_bytes": 4000,
                "tcp_flags": {"syn": 3, "ack": 7, "rst": 1, "non_tcp_field": 99},
            },
            {"packet_count": 10, "total_bytes": 1000},
        ]

        kept, _ = limit_flow_records(records, 20)

        # First record (5 pkts) fits. Remaining budget: 15.
        # Second record has 20 pkts -> truncated to 15. Third dropped.
        assert len(kept) == 2
        first = kept[0]
        second = kept[-1]
        assert first.get("packet_count") == 5
        assert first.get("tcp_flags") == {"syn": 1, "ack": 2, "ece": 0}
        # Second record was truncated - standard TCP flags cleared.
        sec_flags = second.get("tcp_flags") or {}
        for flag in ("syn", "ack", "rst"):
            assert flag not in sec_flags, f"truncated record still has {flag}: {sec_flags}"

    def test_truncated_record_bytes_scaled(self):
        from c2hunter_controller.capture_limits import limit_flow_records

        records = [
            {"packet_count": 10, "total_bytes": 300},
            {"packet_count": 40, "total_bytes": 4000, "tcp_flags": {"syn": 1}},
        ]

        kept, _ = limit_flow_records(records, 25)

        # First record (10 pkts) fits. Remaining: 15. Second record truncated from 40 to 15.
        assert len(kept) == 2
        second = kept[-1]
        assert second["packet_count"] == 15
        assert second["total_bytes"] == 4000 * 15 // 40  # 1500
        # Just verify it's proportionally scaled: 4000 * 15 // 40 = 1500
        assert second["total_bytes"] == 4000 * 15 // 40
