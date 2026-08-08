"""Regression tests for TCP flag extraction and FlowRecord tcp_flags schema."""

import pytest


class TestPcapExtractsTcpFlags:
    def _build_tcp_pcap(self):
        import struct

        eth = b"\x00\x00\x00\x00\x00\x01" + b"\x01\x01\x01\x01\x01\x01" + b"\x08\x00"
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            40,
            0x1234,
            0x4000,
            64,
            6,
            0,
            b"\xc0\xa8\x01\x64",
            b"\xcb\x00\x71\x32",
        )
        tcp_flags_field = (5 << 12) | 0x012
        tcph = struct.pack("!HHIIHHHH", 50000, 80, 1000000, 1, tcp_flags_field, 65535, 0, 0)
        pkt = eth + ip_hdr + tcph
        pcap_h = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pkt_h = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
        return pcap_h + pkt_h + pkt

    def test_tcp_flags_extracted(self):
        from c2hunter_analysis.pcap import parse_pcap

        result = parse_pcap(
            self._build_tcp_pcap(), sensor_id="test", internal_networks=["192.168.0.0/16"]
        )
        assert len(result.records) >= 1
        tcp_flags_recs = [
            r for r in result.records if r.get("protocol") == "TCP" and "tcp_flags" in r
        ]
        assert len(tcp_flags_recs) > 0, "No TCP records with flags found"
        flags = tcp_flags_recs[0]["tcp_flags"]
        assert isinstance(flags, dict)
        assert "syn" in flags
        assert "ack" in flags

    def test_tcp_flags_not_on_udp(self):
        import struct

        udp_data = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        eth = b"\x00\x00\x00\x00\x00\x01" + b"\x01\x01\x01\x01\x01\x01" + b"\x08\x00"
        udp_len = 8 + len(udp_data)
        ip_total = 20 + udp_len
        ip_hdr = struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            ip_total,
            0x1234,
            0x4000,
            64,
            17,
            0,
            b"\xc0\xa8\x01\x64",
            b"\xcb\x00\x71\x32",
        )
        udp_hdr = struct.pack("!HHHH", 50000, 53, udp_len, 0)
        pkt = eth + ip_hdr + udp_hdr + udp_data
        pcap_h = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        pkt_h = struct.pack("<IIII", 0, 0, len(pkt), len(pkt))
        pcap_data = pcap_h + pkt_h + pkt
        from c2hunter_analysis.pcap import parse_pcap

        result = parse_pcap(pcap_data, sensor_id="test", internal_networks=["192.168.0.0/16"])
        assert len(result.records) >= 1
        rec = result.records[0]
        assert rec.get("protocol") == "UDP"
        assert "tcp_flags" not in rec


class TestFlowRecordTcpFlags:
    """Test FlowRecord tcp_flags validation via the Pydantic schema."""

    def test_valid_tcp_flags(self):
        from datetime import UTC, datetime

        from c2hunter_controller.schemas import FlowRecord

        rec = FlowRecord(
            sensor_id="s1",
            timestamp=datetime.now(UTC),
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            protocol="TCP",
            direction="OUTBOUND",
            total_bytes=100,
            tcp_flags={"syn": 2, "ack": 1},
        )
        assert rec.tcp_flags == {"syn": 2, "ack": 1}

    def test_null_tcp_flags(self):
        from datetime import UTC, datetime

        from c2hunter_controller.schemas import FlowRecord

        rec = FlowRecord(
            sensor_id="s1",
            timestamp=datetime.now(UTC),
            source_ip="1.2.3.4",
            destination_ip="5.6.7.8",
            protocol="TCP",
            direction="OUTBOUND",
            total_bytes=100,
        )
        assert rec.tcp_flags is None

    def test_negative_tcp_flags_rejected(self):
        from datetime import UTC, datetime

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

    def test_non_dict_tcp_flags_rejected(self):
        from datetime import UTC, datetime

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
        from datetime import UTC, datetime

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
