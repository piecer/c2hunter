"""Keep the local installer and isolated CI auditor in the same security scope."""

import re
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_installer_pin_is_patched_and_shared_by_lock_make_and_ci() -> None:
    lock = (ROOT / "requirements.lock").read_text()
    make = (ROOT / "Makefile").read_text()
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    pins = re.findall(r"^pip==([0-9.]+)$", lock, re.MULTILINE)
    assert len(pins) == 1, "Audit the installer as an exact lock pin"
    version = pins[0]
    assert tuple(map(int, version.split("."))) >= (26, 2)
    assert re.findall(r"\$\(PIP\) install --upgrade pip==([0-9.]+)", make) == [version]
    assert re.findall(r"-m pip install --upgrade pip==([0-9.]+)", ci) == [version]


def test_ci_audits_lock_and_its_own_isolated_installed_environment_strictly() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    step = ci.split("      - name: Audit Python dependencies", 1)
    assert len(step) == 2, "Use a dedicated isolated Python audit step"
    script = step[1].split("      - uses:", 1)[0]
    assert 'AUDIT_VENV="${RUNNER_TEMP}/c2hunter-pip-audit"' in script
    assert 'python -m venv "$AUDIT_VENV"' in script
    assert '"$AUDIT_VENV/bin/python" -m pip install pip-audit==2.9.0' in script
    audits = [line.strip() for line in script.splitlines() if " -m pip_audit " in line]
    assert len(audits) == 2
    assert all(line.startswith('"$AUDIT_VENV/bin/python" -m pip_audit ') for line in audits)
    assert all("--strict" in line for line in audits)
    assert "-r requirements.lock" in audits[0]
    assert "--disable-pip" in audits[0] and "--no-deps" in audits[0]
    assert " -r " not in audits[1], "Self-audit the actual auditor interpreter, not a resolver"
    assert "--path" not in audits[1]
    assert "--ignore" not in script
    assert "||" not in script
    assert "continue-on-error" not in script


def test_ci_report_validation_rejects_incomplete_or_dirty_inventories() -> None:
    ci = (ROOT / ".github/workflows/ci.yml").read_text()
    marker = "\"$AUDIT_VENV/bin/python\" - <<'PY'\n"
    assert marker in ci, "Compare audit reports against independent complete inventories"
    code = textwrap.dedent(ci.split(marker, 1)[1].split("          PY\n", 1)[0])
    namespace = {"__name__": "audit_config_test"}
    exec(compile(code, "ci-audit-validator", "exec"), namespace)
    validate = namespace["validate"]
    expected = {"pip": "26.3", "packaging": "26.3"}
    rows = [{"name": name, "version": version, "vulns": []} for name, version in expected.items()]
    validate({"dependencies": rows}, expected)
    bad_reports = [
        {"dependencies": rows[:1]},  # Resolver can silently omit packaging.
        {"dependencies": rows[1:]},  # Resolver can silently omit the installer.
        {"dependencies": rows + [rows[0]]},
        {"dependencies": []},
        {"dependencies": rows, "errors": ["advisory service unavailable"]},
    ]
    for change in (
        {"vulns": [{"id": "SYNTHETIC-BLOCKING-CONTROL"}]},
        {"skip_reason": "not found"},
        {"error": "failed"},
        {"version": "25.1.1"},
        {"vulns": None},
        {"name": "extra-package"},
    ):
        bad_reports.append({"dependencies": [rows[0] | change, rows[1]]})
    bad_reports.append({"dependencies": [{"name": "pip", "version": "26.3"}, rows[1]]})
    for report in bad_reports:
        with pytest.raises(SystemExit):
            validate(report, expected)
