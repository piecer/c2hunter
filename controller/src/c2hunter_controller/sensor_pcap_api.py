from __future__ import annotations

from typing import Any, Final

PUBLIC_SENSOR_PCAP_METADATA_FIELDS: Final = (
    "id",
    "sensor_id",
    "sensor_name",
    "analysis_job_id",
    "filename",
    "size_bytes",
    "sha256",
    "uploaded_at",
)


def public_sensor_pcap_metadata(
    metadata: dict[str, Any], *, segment_id: str | None = None
) -> dict[str, Any]:
    """Project durable sensor-PCAP metadata onto its public REST contract."""
    public = {
        field: metadata[field] for field in PUBLIC_SENSOR_PCAP_METADATA_FIELDS if field in metadata
    }
    if segment_id is not None:
        public["segment_id"] = segment_id
    return public
