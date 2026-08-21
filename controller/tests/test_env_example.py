from pathlib import Path


def test_sample_env_does_not_override_export_limit_inheritance() -> None:
    sample = (Path(__file__).parents[2] / ".env.example").read_text()
    assignments = {
        line.partition("=")[0]
        for line in sample.splitlines()
        if line and not line.startswith("#") and "=" in line
    }

    assert "C2HUNTER_PCAP_EXPORT_MAX_BYTES" not in assignments
    assert "C2HUNTER_PCAP_EXPORT_SCAN_MAX_BYTES" not in assignments
    assert "C2HUNTER_PCAP_EXPORT_SCAN_MAX_PACKETS" not in assignments
