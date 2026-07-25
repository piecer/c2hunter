from __future__ import annotations

import json

from c2hunter_controller.production import PostgresRepository


def test_json_replaces_nested_nul_with_visible_marker() -> None:
    encoded = PostgresRepository._json(
        {
            "domain": "pektbo.libre\x19.\x00",
            "nested": [
                {"value": "a\x00b"},
                ("c\x00d",),
            ],
        }
    )

    assert "\\u0000" not in encoded

    decoded = json.loads(encoded)
    assert decoded["domain"] == "pektbo.libre\x19.\\x00"
    assert decoded["nested"][0]["value"] == "a\\x00b"
    assert decoded["nested"][1][0] == "c\\x00d"


def test_json_preserves_non_nul_unicode_and_control_characters() -> None:
    encoded = PostgresRepository._json(
        {
            "korean": "도메인",
            "control": "before\x19after",
        }
    )

    assert "도메인" in encoded

    decoded = json.loads(encoded)
    assert decoded["korean"] == "도메인"
    assert decoded["control"] == "before\x19after"