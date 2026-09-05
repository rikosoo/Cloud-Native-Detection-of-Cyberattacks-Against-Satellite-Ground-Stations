"""Capture and replay of previously valid telecommand frames."""

from __future__ import annotations

import copy
from datetime import timedelta

from gsd.attacks.base import Attack, AttackContext, resort
from gsd.events import TELECOMMAND, Event


class ReplayAttack(Attack):
    name = "replay"
    tactic = "TA0009/TA0040"  # Collection -> Impact
    technique = "T1557 + T1497"  # Adversary-in-the-Middle, replayed traffic
    sparta = "SPARTA-EX-0013"  # Replay valid commands
    description = (
        "Frames recorded off the uplink are retransmitted verbatim hours later. The MAC "
        "still verifies -- the attacker never had the key -- so only sequence-counter "
        "reuse, MAC repetition and command staleness expose the replay."
    )

    def apply(self, ctx: AttackContext, events: list[Event]) -> list[Event]:
        captured = [
            e
            for e in events
            if e.type == TELECOMMAND
            and e.truth is None
            and e.payload.get("opcode") in {"ATT_POINT", "PAYLOAD_ON", "PWR_HEATER_ON"}
            and ctx.at(0.10) <= e.ts <= ctx.at(0.25)
        ][:4]
        if not captured:
            return events

        replay_at = ctx.at(0.78)
        injected: list[Event] = []
        for i, original in enumerate(captured):
            frame = copy.deepcopy(original.payload)  # identical bytes: seq, mac, issued_at
            ts = replay_at + timedelta(seconds=45 * i)
            replayed = ctx.station.uplink.event(frame, ts)
            replayed.payload["source_ip"] = "203.0.113.66"
            injected.append(self.label(replayed))

            # The same frame sent twice in quick succession -- classic jam-and-replay.
            twin_ts = ts + timedelta(seconds=3)
            twin = ctx.station.uplink.event(copy.deepcopy(frame), twin_ts)
            twin.payload["source_ip"] = "203.0.113.66"
            injected.append(self.label(twin))

        return resort(events + injected)
