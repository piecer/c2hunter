from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def check_health(
    path: Path,
    *,
    max_age_seconds: int,
    now: str | None = None,
) -> bool:
    try:
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("status") not in {"RUNNING", "DEGRADED"}:
            return False
        updated_at = datetime.fromisoformat(str(payload["updated_at"]))
        instant = datetime.fromisoformat(now) if now else datetime.now(UTC)
        if updated_at.tzinfo is None:
            return False
        age = (instant - updated_at).total_seconds()
        if age < 0 or age > max_age_seconds:
            return False
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        return False
    return True
