from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from c2hunter_controller import app as app_module
from c2hunter_controller import pcap_export_worker as worker_module
from c2hunter_controller.app import create_app
from c2hunter_controller.config import Settings
from c2hunter_controller.pcap_export_service import (
    PcapExportDependencies,
    deterministic_shadow_sample,
)
from c2hunter_controller.pcap_indexed_export import (
    RangePlanLimits,
    create_indexed_match_factory_from_settings,
)
from c2hunter_controller.repositories import MemoryRepository

STAGE12_FIELDS = {name for name in Settings.model_fields if name.startswith("pcap_indexed_export_")}
ROOT = Path(__file__).parents[2]
STAGE12_ENV = {f"C2HUNTER_{name.upper()}" for name in STAGE12_FIELDS}


def _enabled(**changes: object) -> Settings:
    values: dict[str, object] = {
        "environment": "test",
        "pcap_posting_index_enabled": True,
        "pcap_indexed_export_mode": "active",
    }
    values.update(changes)
    return Settings(**values)  # type: ignore[arg-type]


def test_stage12_defaults_are_rollback_safe_and_settings_build_exact_limits() -> None:
    rollback = Settings(environment="test", pcap_posting_index_enabled=False)
    assert rollback.pcap_indexed_export_mode == "off"
    assert rollback.pcap_indexed_export_canary_basis_points == 0
    assert STAGE12_FIELDS <= Settings.model_fields.keys()

    settings = _enabled(
        pcap_indexed_export_max_sources=7,
        pcap_indexed_export_max_gap_bytes=11,
        pcap_indexed_export_max_range_bytes=101,
        pcap_indexed_export_max_ranges=13,
        pcap_indexed_export_max_total_fetched_bytes=1001,
        pcap_indexed_export_max_amplification_numerator=5,
        pcap_indexed_export_max_amplification_denominator=2,
        pcap_indexed_export_max_source_fraction_numerator=1,
        pcap_indexed_export_max_source_fraction_denominator=1,
    )
    factory = create_indexed_match_factory_from_settings(object(), settings)  # type: ignore[arg-type]
    assert factory is not None
    assert settings.pcap_indexed_export_max_sources == 7
    assert RangePlanLimits(11, 101, 13, 1001, 5, 2, 1, 1)


@pytest.mark.parametrize(
    "changes",
    [
        {
            "pcap_indexed_export_mode": "shadow",
            "pcap_posting_index_enabled": False,
            "pcap_indexed_export_canary_basis_points": 1,
        },
        {"pcap_indexed_export_mode": "active", "pcap_posting_index_enabled": False},
        {"pcap_indexed_export_mode": "shadow", "pcap_indexed_export_canary_basis_points": 0},
        {"pcap_indexed_export_mode": "active", "pcap_indexed_export_canary_basis_points": 1},
        {"pcap_indexed_export_mode": "off", "pcap_indexed_export_canary_basis_points": 1},
        {"pcap_indexed_export_max_sources": 0},
        {"pcap_indexed_export_max_sources": 1025},
        {"pcap_indexed_export_max_gap_bytes": 0},
        {"pcap_indexed_export_max_range_bytes": 0},
        {"pcap_indexed_export_max_ranges": 0},
        {"pcap_indexed_export_max_total_fetched_bytes": 0},
        {
            "pcap_indexed_export_max_range_bytes": 11,
            "pcap_indexed_export_max_total_fetched_bytes": 10,
        },
        {"pcap_indexed_export_max_amplification_denominator": 0},
        {
            "pcap_indexed_export_max_amplification_numerator": 1,
            "pcap_indexed_export_max_amplification_denominator": 2,
        },
        {"pcap_indexed_export_max_source_fraction_denominator": 0},
        {
            "pcap_indexed_export_max_source_fraction_numerator": 2,
            "pcap_indexed_export_max_source_fraction_denominator": 1,
        },
        {"pcap_indexed_export_max_total_fetched_bytes": 1 << 63},
        {"pcap_indexed_export_canary_basis_points": 10001},
    ],
)
def test_stage12_invalid_settings_are_rejected_without_clamping(changes: dict[str, object]) -> None:
    values: dict[str, object] = {"environment": "test"}
    values.update(changes)
    with pytest.raises(ValidationError):
        Settings(**values)  # type: ignore[arg-type]


def test_shadow_sampler_is_stable_and_has_exact_basis_point_boundaries() -> None:
    identities = [f"request-{index}" for index in range(30_000)]
    generation = "generation-a"
    buckets = {
        identity: int.from_bytes(
            hashlib.sha256(f"{identity}\0{generation}".encode()).digest()[:8], "big"
        )
        % 10_000
        for identity in identities
    }
    zero_identity = next(identity for identity, bucket in buckets.items() if bucket == 0)
    last_identity = next(identity for identity, bucket in buckets.items() if bucket == 9_999)

    assert deterministic_shadow_sample(zero_identity, generation, 0) is False
    assert deterministic_shadow_sample(zero_identity, generation, 1) is True
    assert deterministic_shadow_sample(last_identity, generation, 9_999) is False
    assert deterministic_shadow_sample(last_identity, generation, 10_000) is True
    assert deterministic_shadow_sample(zero_identity, generation, 1) is True
    assert deterministic_shadow_sample(
        zero_identity, "generation-b", 1
    ) == deterministic_shadow_sample(zero_identity, "generation-b", 1)


def test_env_and_rendered_compose_propagate_identical_stage12_contract() -> None:
    assignments = {
        key: value
        for line in (ROOT / ".env.example").read_text().splitlines()
        if line and not line.startswith("#") and "=" in line
        for key, _, value in (line.partition("="),)
    }
    assert STAGE12_ENV <= assignments.keys()
    defaults = Settings(environment="test").model_dump()
    expected_defaults = {
        f"C2HUNTER_{name.upper()}": str(defaults[name]).lower() for name in STAGE12_FIELDS
    }
    assert {key: assignments[key] for key in STAGE12_ENV} == expected_defaults

    rendered = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ROOT / ".env.example"),
            "-f",
            str(ROOT / "docker-compose.yml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    services = json.loads(rendered.stdout)["services"]
    controller_env = services["controller"]["environment"]
    worker_env = services["pcap-export-worker"]["environment"]
    assert controller_env.keys() & STAGE12_ENV == STAGE12_ENV
    assert worker_env.keys() & STAGE12_ENV == STAGE12_ENV
    assert {key: controller_env[key] for key in STAGE12_ENV} == {
        key: worker_env[key] for key in STAGE12_ENV
    }
    assert {key: str(controller_env[key]).lower() for key in STAGE12_ENV} == expected_defaults
    operations = (ROOT / "docs/operations.md").read_text()
    for key, default in expected_defaults.items():
        assert key in operations
        assert f"{key}={default}" in operations


def test_stage12_operations_metric_names_are_exactly_the_source_names() -> None:
    source = (ROOT / "controller/src/c2hunter_controller/pcap_export_metrics.py").read_text()
    operations = (ROOT / "docs/operations.md").read_text()
    metric_names = set(re.findall(r'"(c2hunter_pcap_indexed_export_[a-z_]+_total)"', source))
    documented = set(re.findall(r"`(c2hunter_pcap_indexed_export_[a-z_]+_total)", operations))
    assert documented == metric_names


@pytest.mark.parametrize("target", ["app", "worker"])
@pytest.mark.parametrize("mode", ["off", "shadow", "active"])
def test_production_wiring_constructs_indexed_dependencies_only_when_enabled(
    monkeypatch: pytest.MonkeyPatch, target: str, mode: str
) -> None:
    repository = MemoryRepository()
    calls: list[tuple[object, Settings]] = []

    def factory(repo: object, settings: Settings) -> object:
        calls.append((repo, settings))
        return lambda **_kwargs: None

    module = app_module if target == "app" else worker_module
    monkeypatch.setattr(module, "create_indexed_match_factory_from_settings", factory)
    settings = Settings(
        environment="test",
        pcap_posting_index_enabled=mode != "off",
        pcap_indexed_export_mode=mode,
        pcap_indexed_export_canary_basis_points=1 if mode == "shadow" else 0,
    )
    if target == "app":
        create_app(settings, repository)
    else:
        worker_module.create_pcap_export_worker(repository, settings)

    assert len(calls) == (0 if mode == "off" else 1)


@pytest.mark.parametrize("target", ["app", "worker"])
def test_explicit_indexed_dependency_wins_even_when_rollout_is_off(
    monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    repository = MemoryRepository()
    injected = PcapExportDependencies(indexed_match_factory=lambda **_kwargs: None)

    def reject(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("production indexed dependency constructed")

    module = app_module if target == "app" else worker_module
    monkeypatch.setattr(module, "create_indexed_match_factory_from_settings", reject)
    settings = Settings(environment="test")
    if target == "app":
        create_app(settings, repository, pcap_export_dependencies=injected)
    else:
        worker_module.create_pcap_export_worker(repository, settings, dependencies=injected)
