from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def render_json_log(
    level: str,
    component: str,
    message: str,
    *,
    service: str = "c2hunter-controller",
    job_id: str | None = None,
    sensor_id: str | None = None,
    request_id: str | None = None,
    error: Any = None,
) -> dict[str, Any]:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "level": level,
        "service": service,
        "component": component,
        "job_id": job_id,
        "sensor_id": sensor_id,
        "request_id": request_id,
        "message": message,
        "error": error,
    }
