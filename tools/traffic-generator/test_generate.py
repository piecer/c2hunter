import hashlib
import importlib.util
import json
import struct
import tempfile
import unittest
from pathlib import Path

MODULE = Path(__file__).with_name("generate.py")
spec = importlib.util.spec_from_file_location("traffic_generator", MODULE)
assert spec is not None and spec.loader is not None
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
            self.assertEqual(set(one), set("ABCDEFG"))
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


if __name__ == "__main__":
    unittest.main()
