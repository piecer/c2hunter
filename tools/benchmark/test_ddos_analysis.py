from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / "tools/benchmark/ddos_analysis.py"
PYTHON = ROOT / ".venv/bin/python"


class DDoSBenchmarkTest(unittest.TestCase):
    def run_benchmark(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "analysis/src")
        return subprocess.run(  # noqa: S603 -- fixed test interpreter and local script
            [str(PYTHON), str(SCRIPT), *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_rejects_nonpositive_record_count_without_publishing_artifacts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="c2hunter-ddos-benchmark-"
        ) as directory:
            json_path = Path(directory) / "result.json"
            markdown_path = Path(directory) / "result.md"
            result = self.run_benchmark(
                "--records",
                "-1",
                "--iterations",
                "1",
                "--json",
                str(json_path),
                "--markdown",
                str(markdown_path),
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(json_path.exists())
            self.assertFalse(markdown_path.exists())

    def test_records_revision_runtime_parameters_and_repeated_samples(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="c2hunter-ddos-benchmark-"
        ) as directory:
            json_path = Path(directory) / "result.json"
            markdown_path = Path(directory) / "result.md"
            result = self.run_benchmark(
                "--records",
                "100",
                "--iterations",
                "2",
                "--json",
                str(json_path),
                "--markdown",
                str(markdown_path),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(json_path.read_text())
            self.assertEqual(payload["evaluated_records"], 100)
            self.assertEqual(len(payload["elapsed_seconds"]), 2)
            self.assertLessEqual(max(payload["elapsed_seconds"]), 180)
            self.assertLessEqual(payload["peak_rss_mib"], 8192)
            self.assertEqual(len(payload["source_revision"]), 40)
            self.assertEqual(
                set(payload["source_files_sha256"]),
                {
                    "analysis/src/c2hunter_analysis/ddos_attack.py",
                    "tools/benchmark/ddos_analysis.py",
                },
            )
            self.assertIn("ddos_bucket_seconds", payload["effective_parameters"])
            self.assertEqual(payload["limits"]["max_input_records"], 2_000_000)
            self.assertEqual(
                set(payload["boundary_probes"]),
                {
                    "input_limit_plus_one",
                    "target_limit_plus_one",
                    "bucket_limit_plus_one",
                    "finding_limit_plus_one",
                },
            )
            self.assertTrue(all(payload["boundary_probes"].values()))
            self.assertIn("Python", markdown_path.read_text())


if __name__ == "__main__":
    unittest.main()
