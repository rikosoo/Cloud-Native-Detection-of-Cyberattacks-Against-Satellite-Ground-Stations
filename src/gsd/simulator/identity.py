"""CloudTrail-shaped identity and control-plane audit events.

The fields mirror the ones a real ``AWSCloudTrail`` record carries
(``eventName``, ``sourceIPAddress``, ``userIdentity``, ``additionalEventData``)
so that the same rules run unchanged against a real trail once the workload is
deployed.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from gsd.config import MissionProfile, Operator
from gsd.events import AUDIT, Event

READ_ACTIONS = (
    "DescribeSatellite",
    "ListContacts",
    "GetMissionProfile",
    "DescribeConfig",
)


@dataclass
class IdentityPlane:
    profile: MissionProfile
    rng: random.Random = field(default_factory=lambda: random.Random(11))

    def session_id(self) -> str:
        # Seeded rather than uuid4 so a scenario replays byte-for-byte.
        return f"sess-{self.rng.getrandbits(48):012x}"

    def home_ip(self, operator: Operator) -> str:
        base = operator.home_cidr.split("/")[0].rsplit(".", 2)[0]
        return f"{base}.{self.rng.randint(1, 250)}.{self.rng.randint(1, 250)}"

    def audit(
        self,
        ts: datetime,
        *,
        action: str,
        operator: str,
        source_ip: str,
        session_id: str,
        outcome: str = "Success",
        mfa: bool = True,
        geo: str = "BR",
        user_agent: str = "gsops-console/4.2",
        extra: dict[str, Any] | None = None,
        truth: str | None = None,
    ) -> Event:
        payload: dict[str, Any] = {
            "eventName": action,
            "eventSource": "groundstation.amazonaws.com",
            "sourceIPAddress": source_ip,
            "userIdentity": {
                "type": "IAMUser",
                "userName": operator,
                "sessionContext": {
                    "sessionIssuer": {"userName": operator},
                    "attributes": {"mfaAuthenticated": str(mfa).lower()},
                },
            },
            "userAgent": user_agent,
            "sessionId": session_id,
            "geo": geo,
            "outcome": outcome,
        }
        if extra:
            payload["additionalEventData"] = extra
        return Event(
            type=AUDIT,
            ts=ts,
            station_id=self.profile.station_id,
            payload=payload,
            truth=truth,
        )
