"""In-flight modification of authenticated telecommands."""

from __future__ import annotations

from datetime import timedelta

from gsd.attacks.base import Attack, AttackContext, resort
from gsd.crypto import sign
from gsd.events import TELECOMMAND, Event

FORGED_KEY = b"attacker-guessed-key-0000000000000"


class CommandTampering(Attack):
    name = "command_tampering"
    tactic = "TA0008/TA0040"  # Lateral Movement -> Impact
    technique = "T1565.002"  # Transmitted Data Manipulation
    sparta = "SPARTA-EX-0012"  # Modify command / malicious commanding
    description = (
        "A man-in-the-middle on the uplink path rewrites the opcode and parameters of "
        "legitimate telecommands. Three variants are injected: MAC left untouched "
        "(integrity failure), MAC recomputed with the wrong key, and a command that is "
        "syntactically valid but outside the issuing operator's role."
    )

    def apply(self, ctx: AttackContext, events: list[Event]) -> list[Event]:
        candidates = [
            e
            for e in events
            if e.type == TELECOMMAND
            and e.truth is None
            and ctx.at(0.45) <= e.ts <= ctx.at(0.70)
        ]
        if not candidates:
            return events

        # Variant A -- payload rewritten, original MAC kept.
        victim = candidates[0]
        victim.payload["opcode"] = "ATT_SLEW"
        victim.payload["apid"] = 0x10
        victim.payload["params"] = {"axis": "yaw", "rate_dps": 14.0, "duration_s": 900}
        self.label(victim)

        # Variant B -- attacker forges a MAC with a key they do not have.
        if len(candidates) > 1:
            forged = candidates[1]
            forged.payload["opcode"] = "PWR_BUS_OFF"
            forged.payload["apid"] = 0x20
            forged.payload["params"] = {"bus": "primary", "confirm": True}
            forged.payload["mac"] = sign(forged.payload, FORGED_KEY)
            self.label(forged)

        # Variant C -- a correctly signed command issued outside the operator's role,
        # from the session hijacked in the credential-compromise stage when available.
        hijacked = ctx.station.sessions.get("a.moreira@attacker")
        session_id, source_ip = hijacked or ("sess-mitm-0001", "203.0.113.66")
        ts = ctx.at(0.62)
        command = ctx.station.uplink.build(
            "DATA_DUMP",
            "a.moreira",  # an 'operator' role: DATA_DUMP is flight-director only
            ts,
            source_ip=source_ip,
            session_id=session_id,
            params={"window": "all", "destination": "s3://exfil-relay-77"},
        )
        events.append(self.label(ctx.station.uplink.event(command, ts)))

        # Variant D -- a burst of commands far above the nominal uplink rate.
        burst_start = ctx.at(0.66)
        for i in range(40):
            burst_ts = burst_start + timedelta(seconds=1.2 * i)
            cmd = ctx.station.uplink.build(
                "ATT_POINT",
                "a.moreira",
                burst_ts,
                source_ip=source_ip,
                session_id=session_id,
                params={"az": 10 * i % 360, "el": 45},
            )
            events.append(self.label(ctx.station.uplink.event(cmd, burst_ts)))

        return resort(events)
