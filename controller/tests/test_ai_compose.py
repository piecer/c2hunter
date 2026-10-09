"""Linux Compose deployments must resolve the configured local model host."""

import re
from pathlib import Path

import pytest


@pytest.mark.parametrize("service", ["controller", "ai-worker"])
def test_local_model_consumers_have_linux_host_gateway(service: str) -> None:
    compose = Path(__file__).resolve().parents[2] / "docker-compose.yml"
    sections = re.split(r"(?m)^  (?=[a-z][a-z-]*:)", compose.read_text())
    block = next(section for section in sections if section.startswith(f"{service}:\n"))
    assert "http://host.docker.internal:11434" in block
    assert len(re.findall(r"(?m)^    extra_hosts:", block)) == 1
    assert re.search(
        r'(?m)^    extra_hosts:(?:\s*\[\s*|\n\s*-\s*)"host\.docker\.internal:host-gateway"',
        block,
    ), f"{service} cannot resolve its default local model hostname on Linux"
