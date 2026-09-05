"""Payload data downlink / archival transfers."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime

from gsd.config import MissionProfile
from gsd.events import DOWNLINK, Event


@dataclass
class DownlinkPlane:
    profile: MissionProfile
    rng: random.Random = field(default_factory=lambda: random.Random(23))

    def transfer(
        self,
        ts: datetime,
        *,
        size_mb: float,
        destination: str,
        operator: str,
        source_ip: str,
        protocol: str = "s3-multipart",
        object_count: int = 1,
        truth: str | None = None,
    ) -> Event:
        return Event(
            type=DOWNLINK,
            ts=ts,
            station_id=self.profile.station_id,
            payload={
                "spacecraft": self.profile.spacecraft,
                "size_mb": round(size_mb, 2),
                "object_count": object_count,
                "destination": destination,
                "protocol": protocol,
                "operator": operator,
                "source_ip": source_ip,
                "product": "L0_RAW",
            },
            truth=truth,
        )

    def nominal(self, ts: datetime, operator: str, source_ip: str) -> Event:
        return self.transfer(
            ts,
            size_mb=self.rng.uniform(180.0, 900.0),
            destination=self.profile.downlink_destinations[0],
            operator=operator,
            source_ip=source_ip,
            object_count=self.rng.randint(4, 40),
        )
