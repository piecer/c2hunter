from __future__ import annotations

import hashlib
from collections import OrderedDict

from .domain import LogicalPacket, PacketObservation


def deduplicate_observations(
    observations: list[PacketObservation], timestamp_bucket_ms: int = 10
) -> list[LogicalPacket]:
    """논리 패킷은 하나로 세되 센서별 원 관찰은 모두 보존한다."""
    grouped: OrderedDict[str, list[PacketObservation]] = OrderedDict()
    for item in observations:
        bucket = int(item.timestamp.timestamp() * 1000) // timestamp_bucket_ms
        identity = (
            item.source_ip,
            item.destination_ip,
            item.source_port,
            item.destination_port,
            item.protocol,
            item.ip_id,
            item.tcp_sequence,
            item.payload_length,
            item.payload_hash,
            bucket,
        )
        fingerprint = hashlib.sha256(repr(identity).encode()).hexdigest()
        grouped.setdefault(fingerprint, []).append(item)
    return [LogicalPacket(key, tuple(values)) for key, values in grouped.items()]
