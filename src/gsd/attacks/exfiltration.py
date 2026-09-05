"""Bulk exfiltration of mission payload data."""

from __future__ import annotations

from datetime import timedelta

from gsd.attacks.base import Attack, AttackContext, resort
from gsd.events import Event

EXFIL_BUCKET = "s3://exfil-relay-77"
EXFIL_IP = "203.0.113.66"


class Exfiltration(Attack):
    name = "exfiltration"
    tactic = "TA0010"  # Exfiltration
    technique = "T1537 + T1567.002"  # Transfer to another account / cloud storage
    sparta = "SPARTA-EXF-0003"  # Exfiltrate mission data
    description = (
        "Using the hijacked session, the L0 archive is enumerated and copied out of the "
        "mission account: thousands of object reads followed by multi-gigabyte transfers "
        "to a bucket outside the approved destination list, at 03:00 UTC."
    )

    def apply(self, ctx: AttackContext, events: list[Event]) -> list[Event]:
        identity = ctx.station.identity
        downlink = ctx.station.downlink
        session_id, source_ip = ctx.station.sessions.get(
            "a.moreira@attacker", ("sess-exfil-0001", EXFIL_IP)
        )
        t0 = ctx.at(0.86)
        injected: list[Event] = []

        # 1. Discovery: enumerate the archive.
        for i, action in enumerate(("ListBuckets", "ListObjectsV2", "GetBucketPolicy")):
            injected.append(
                self.label(
                    identity.audit(
                        t0 + timedelta(seconds=20 * i),
                        action=action,
                        operator="a.moreira",
                        source_ip=source_ip,
                        session_id=session_id,
                        geo="RU",
                        user_agent="aws-cli/2.15.0",
                        extra={"bucket": "sentinel-mission-archive"},
                    )
                )
            )

        # 2. Collection: bulk reads well beyond any human workflow.
        injected.append(
            self.label(
                identity.audit(
                    t0 + timedelta(minutes=2),
                    action="GetObject",
                    operator="a.moreira",
                    source_ip=source_ip,
                    session_id=session_id,
                    geo="RU",
                    user_agent="aws-cli/2.15.0",
                    extra={
                        "bucket": "sentinel-mission-archive",
                        "objectCount": 8421,
                        "bytesTransferred": 6_442_450_944,
                    },
                )
            )
        )

        # 3. Exfiltration: transfers to an unapproved destination.
        for i in range(3):
            injected.append(
                self.label(
                    downlink.transfer(
                        t0 + timedelta(minutes=5 + 4 * i),
                        size_mb=3100.0 + 700 * i,
                        destination=EXFIL_BUCKET,
                        operator="a.moreira",
                        source_ip=source_ip,
                        protocol="s3-cross-account-copy",
                        object_count=2800 + 400 * i,
                    )
                )
            )

        return resort(events + injected)
