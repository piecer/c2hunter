from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta


@dataclass(frozen=True)
class RetentionPolicy:
    days: dict[str, int] = field(
        default_factory=lambda: {
            "pcap": 7,
            "flow": 30,
            "result": 180,
            "audit": 365,
            "heartbeat": 30,
        }
    )

    def cutoff(self, data_type: str, now: datetime) -> datetime:
        if data_type not in self.days:
            raise ValueError(f"unknown retention data type: {data_type}")
        return now - timedelta(days=self.days[data_type])

    def is_expired(self, data_type: str, created_at: datetime, now: datetime) -> bool:
        return created_at < self.cutoff(data_type, now)
