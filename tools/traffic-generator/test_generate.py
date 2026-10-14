import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from c2hunter_analysis.ddos_attack import analyze_ddos_attack
from c2hunter_analysis.pcap import parse_pcap

MODULE = Path(__file__).with_name("generate.py")
spec = importlib.util.spec_from_file_location("traffic_generator", MODULE)
assert spec is not None and spec.loader is not None  # noqa: S101 -- import loader invariant
generator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generator)


class TrafficGeneratorTest(unittest.TestCase):
    def test_scenarios_are_deterministic_valid_pcaps_with_oracles(self):
        with (
            tempfile.TemporaryDirectory() as first,
            tempfile.TemporaryDirectory() as second,
        ):
            one = generator.generate_all(Path(first), seed=20260720)
            generator.generate_all(Path(second), seed=20260720)
            ddos_names = {
                "DDOS_SYN",
                "DDOS_UDP",
                "DDOS_REFLECTION",
                "DDOS_ICMP",
                "DDOS_OUTBOUND",
                "DDOS_MULTI",
                "DDOS_NORMAL",
                "DDOS_SHORT",
            }
            self.assertEqual(set(one), set("ABCDEFG") | ddos_names)
            for name in one:
                pcap = Path(first, f"scenario-{name.lower()}.pcap")
                self.assertEqual(pcap.read_bytes()[:4], struct.pack("<I", 0xA1B2C3D4))
                self.assertEqual(
                    hashlib.sha256(pcap.read_bytes()).hexdigest(),
                    hashlib.sha256(Path(second, pcap.name).read_bytes()).hexdigest(),
                )
                self.assertGreater(one[name]["packet_count"], 0)
            self.assertEqual(one["A"]["oracle"]["distinct_internal_hosts"], 50)
            self.assertEqual(one["A"]["oracle"]["minimum_score"], 60)
            self.assertIn("COMMAND_ATTACK_CORRELATION", one["B"]["oracle"]["evidence"])
            self.assertLess(one["C"]["oracle"]["maximum_score"], 60)
            self.assertEqual(
                one["C"]["analysis_context"]["public_dns_ntp_servers"],
                ["192.0.2.53", "192.0.2.123"],
            )
            self.assertEqual(
                one["D"]["analysis_context"]["cdn_domain_suffixes"], ["cdn.test"]
            )
            self.assertEqual(one["E"]["oracle"]["sensor_observations"], 2)
            self.assertEqual(
                one["E"]["observations"]["packet_sensor_ids"], ["sensor-a", "sensor-b"]
            )
            self.assertEqual(one["F"]["oracle"]["clock_skew_seconds"], 3)
            self.assertEqual(
                one["F"]["operations"]["sensors"]["sensor-b"]["status"], "DEGRADED"
            )
            self.assertEqual(one["G"]["oracle"]["status"], "PARTIALLY_COMPLETED")
            self.assertEqual(one["G"]["operations"]["failed_sensors"], ["sensor-b"])
            self.assertEqual(
                json.loads(Path(first, "manifest.json").read_text())["seed"], 20260720
            )
            for name in sorted(ddos_names):
                parsed = parse_pcap(
                    Path(first, f"scenario-{name.lower()}.pcap").read_bytes(),
                    sensor_id="fixture-sensor",
                    internal_networks=["10.0.0.0/8"],
                    retain_network_evidence=True,
                )
                report = analyze_ddos_attack(
                    parsed.records,
                    internal_cidrs=("10.0.0.0/8",),
                )
                oracle = one[name]["oracle"]
                if "attack_type" in oracle:
                    finding = next(
                        item
                        for item in report["findings"]
                        if item["attack_type"] == oracle["attack_type"]
                    )
                    self.assertEqual(finding["attack_role"], oracle["attack_role"])
                else:
                    self.assertEqual(report["verdict"], oracle["verdict"])
                    self.assertIn(oracle["warning"], report["warnings"])

    def _reflection_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            generator.generate_all(Path(directory), seed=20260720)
            return Path(directory, "scenario-ddos_reflection.pcap").read_bytes()

    def _parse_capture(self, capture):
        return parse_pcap(
            capture,
            sensor_id="fixture-sensor",
            internal_networks=["10.0.0.0/8"],
            retain_network_evidence=True,
        )

    def test_reflection_capture_contains_complete_bounded_dns_responses(self):
        capture = self._reflection_capture()
        offset, count = 24, 0
        sources = Counter()
        while offset < len(capture):
            seconds, micros, captured, original = struct.unpack_from(
                "<IIII", capture, offset
            )
            offset += 16
            packet = capture[offset : offset + captured]
            offset += captured
            self.assertEqual((captured, original), (642, 642))
            when = generator.EPOCH + count / 120
            self.assertEqual(
                (seconds, micros), (int(when), round((when - int(when)) * 1_000_000))
            )
            self.assertEqual(packet[23], 17)
            self.assertEqual(packet[30:34], bytes([10, 20, 0, 10]))
            self.assertEqual(struct.unpack_from("!HHHH", packet, 34), (53, 443, 608, 0))
            sources[packet[26:30]] += 1
            payload = packet[42:]
            self.assertEqual(len(payload), 600)
            # Validate the complete wire message, not just the production parser's
            # bounded header/question subset: one TXT answer and an EDNS OPT RR.
            self.assertEqual(
                struct.unpack_from("!6H", payload), (0x1234, 0x8180, 1, 1, 0, 1)
            )
            position, labels = 12, []
            while payload[position]:
                length = payload[position]
                self.assertLessEqual(length, 63)
                position += 1
                labels.append(payload[position : position + length])
                position += length
            self.assertEqual(labels, [b"reflection", b"test"])
            position += 1
            self.assertEqual(struct.unpack_from("!HH", payload, position), (16, 1))
            position += 4
            owner, kind, dns_class, ttl, rdlength = struct.unpack_from(
                "!HHHIH", payload, position
            )
            self.assertEqual((owner, kind, dns_class, ttl), (0xC00C, 16, 1, 60))
            position += 12
            end = position + rdlength
            strings = []
            while position < end:
                length = payload[position]
                position += 1
                self.assertLessEqual(position + length, end)
                strings.append(payload[position : position + length])
                position += length
            self.assertEqual(position, end)
            self.assertEqual([len(value) for value in strings], [255, 255, 31])
            self.assertEqual(b"".join(strings), b"r" * 541)
            # Root owner, OPT, 1232-byte UDP capacity, no flags/options/trailing bytes.
            self.assertEqual(
                payload[position:], b"\0" + struct.pack("!HHIH", 41, 1232, 0, 0)
            )
            count += 1
        self.assertEqual(offset, len(capture))
        self.assertEqual(count, 1000)
        self.assertEqual(
            sources, Counter({bytes([198, 18, 0, n]): 4 for n in range(1, 251)})
        )
        rows = self._parse_capture(capture).records
        samples = [
            sample for row in rows for sample in row["ddos_packet_evidence"]["samples"]
        ]
        self.assertEqual(len(samples), 1000)
        self.assertTrue(all(sample["semantic"] == "DNS_RESPONSE" for sample in samples))
        self.assertTrue(all(sample["transaction"] is not None for sample in samples))

    def test_reflection_capture_has_real_analyzer_response_evidence(self):
        parsed = self._parse_capture(self._reflection_capture())
        report = analyze_ddos_attack(parsed.records, internal_cidrs=("10.0.0.0/8",))
        self.assertTrue(report["findings"])
        finding = report["findings"][0]
        self.assertEqual(finding["attack_type"], "POSSIBLE_REFLECTION_AMPLIFICATION")
        self.assertEqual(finding["attack_role"], "VICTIM_SIDE_INBOUND")
        self.assertEqual(finding["metrics"]["packet_count"], 1000)
        classification = finding["classification"]
        self.assertEqual(
            classification["delivery_mechanism"], "REFLECTION_AMPLIFICATION"
        )
        self.assertNotEqual(
            classification["source_population"], "BOTNET_LIKE_COORDINATION"
        )
        self.assertEqual(classification["source_authenticity"], "SPOOFING_UNCONFIRMED")
        evidence = classification["evidence"]
        self.assertEqual(evidence["sample_count"], 1000)
        self.assertEqual(evidence["response_samples"], 1000)
        self.assertEqual(evidence["matched_response_samples"], 0)
        self.assertIsNone(evidence["amplification_ratio"])

    def test_source_port_53_garbage_is_udp_not_reflection_or_botnet(self):
        # Preserve the old fixture as a negative control; the service port alone
        # must never substitute for response or client coordination evidence.
        packets = [
            (
                generator.EPOCH + index / 120,
                generator.udp_packet(
                    generator.ddos_source(index % 250),
                    "10.20.0.10",
                    53,
                    443,
                    b"r" * 600,
                    index,
                ),
            )
            for index in range(1000)
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "port-only.pcap")
            generator.write_pcap(path, packets)
            parsed = self._parse_capture(path.read_bytes())
        samples = [
            sample
            for row in parsed.records
            for sample in row["ddos_packet_evidence"]["samples"]
        ]
        self.assertEqual(len(samples), 1000)
        self.assertTrue(all(sample["semantic"] == "UNKNOWN" for sample in samples))
        report = analyze_ddos_attack(parsed.records, internal_cidrs=("10.0.0.0/8",))
        self.assertTrue(report["findings"])
        for finding in report["findings"]:
            self.assertEqual(finding["attack_type"], "UDP_FLOOD")
            self.assertEqual(finding["metrics"]["packet_count"], 1000)
            classification = finding["classification"]
            self.assertNotEqual(
                classification["delivery_mechanism"], "REFLECTION_AMPLIFICATION"
            )
            self.assertNotEqual(
                classification["source_population"], "BOTNET_LIKE_COORDINATION"
            )
            self.assertEqual(classification["evidence"]["response_samples"], 0)


if __name__ == "__main__":
    unittest.main()
