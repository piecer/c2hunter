"""Optional test receipts must not depend on a campaign's TMPDIR layout."""

import json
from pathlib import Path

import pytest

from tests.test_baseline_scope_faults import receipt


@pytest.mark.parametrize("layout", ["unset", "missing-evidence", "existing-evidence"])
def test_receipt_without_opt_in_has_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, layout: str
) -> None:
    monkeypatch.delenv("C2HUNTER_TEST_RECEIPT_PATH", raising=False)
    monkeypatch.delenv("TMPDIR", raising=False)
    monkeypatch.chdir(tmp_path)
    if layout != "unset":
        temporary = tmp_path / "tmp"
        temporary.mkdir()
        monkeypatch.setenv("TMPDIR", str(temporary))
    if layout == "existing-evidence":
        (tmp_path / "evidence").mkdir()
    before = sorted(tmp_path.rglob("*"))

    receipt({"fault": "portable", "fired": 1})

    assert sorted(tmp_path.rglob("*")) == before


def test_receipt_explicit_path_creates_parents_and_appends_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("TMPDIR", raising=False)
    output = tmp_path / "missing" / "nested" / "chosen.jsonl"
    monkeypatch.setenv("C2HUNTER_TEST_RECEIPT_PATH", str(output))
    first = {"fault": "serialization", "fired": 1}
    second = {"fault": "readback", "fired": 1}

    receipt(first)
    original = output.read_bytes()
    receipt(second)

    assert original == (json.dumps(first, sort_keys=True) + "\n").encode("utf-8")
    assert output.read_bytes() == original + (json.dumps(second, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    assert [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()] == [
        first,
        second,
    ]


@pytest.mark.parametrize("blocked", ["parent-file", "destination-directory"])
def test_receipt_explicit_path_propagates_io_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, blocked: str
) -> None:
    monkeypatch.delenv("TMPDIR", raising=False)
    obstacle = tmp_path / "obstacle"
    if blocked == "parent-file":
        obstacle.write_text("preserve", encoding="utf-8")
        output = obstacle / "events.jsonl"
    else:
        obstacle.mkdir()
        output = obstacle
    monkeypatch.setenv("C2HUNTER_TEST_RECEIPT_PATH", str(output))

    # Structural failures work even as root; chmod-based permission tests do not.
    with pytest.raises(OSError):
        receipt({"fault": "portable", "fired": 1})

    if blocked == "parent-file":
        assert obstacle.read_text(encoding="utf-8") == "preserve"
    else:
        assert list(obstacle.iterdir()) == []
