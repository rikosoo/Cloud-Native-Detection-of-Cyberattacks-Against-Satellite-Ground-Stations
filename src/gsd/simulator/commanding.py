"""Telecommand generation and uplink bookkeeping."""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from gsd import crypto
from gsd.config import MissionProfile
from gsd.events import TELECOMMAND, Event, to_iso

#: Routine traffic, weighted towards housekeeping.
NOMINAL_OPCODES = (
    ("TLM_REQ", 0.45),
    ("PING", 0.20),
    ("ATT_POINT", 0.15),
    ("PWR_HEATER_ON", 0.07),
    ("PWR_HEATER_OFF", 0.07),
    ("PAYLOAD_ON", 0.03),
    ("PAYLOAD_OFF", 0.03),
)

APID_BY_SUBSYSTEM = {
    "TLM": 0x01,
    "PING": 0x02,
    "ATT": 0x10,
    "PWR": 0x20,
    "PAYLOAD": 0x30,
    "DATA": 0x40,
    "SEC": 0x50,
    "FSW": 0x60,
}


def apid_for(opcode: str) -> int:
    return APID_BY_SUBSYSTEM.get(opcode.split("_", 1)[0], 0xFF)


@dataclass
class Uplink:
    """Issues signed telecommands with a monotonic sequence counter."""

    profile: MissionProfile
    rng: random.Random = field(default_factory=lambda: random.Random(7))
    seq: int = 0

    def next_seq(self) -> int:
        self.seq = (self.seq + 1) % 65536
        return self.seq

    def build(
        self,
        opcode: str,
        operator: str,
        ts: datetime,
        *,
        source_ip: str,
        session_id: str,
        params: dict[str, Any] | None = None,
        seq: int | None = None,
        approvals: list[str] | None = None,
        sign: bool = True,
    ) -> dict[str, Any]:
        command: dict[str, Any] = {
            "spacecraft": self.profile.spacecraft,
            "apid": apid_for(opcode),
            "opcode": opcode,
            "params": params or {},
            "seq": self.next_seq() if seq is None else seq,
            "issued_at": to_iso(ts),
            "operator": operator,
            "session_id": session_id,
            "source_ip": source_ip,
            "approvals": approvals or [operator],
        }
        if sign:
            command["mac"] = crypto.sign(command, crypto.key_for(self.profile.station_id))
        return command

    def event(self, command: dict[str, Any], ts: datetime, truth: str | None = None) -> Event:
        return Event(
            type=TELECOMMAND,
            ts=ts,
            station_id=self.profile.station_id,
            payload=command,
            truth=truth,
        )

    def pick_opcode(self) -> str:
        roll = self.rng.random()
        cumulative = 0.0
        for opcode, weight in NOMINAL_OPCODES:
            cumulative += weight
            if roll <= cumulative:
                return opcode
        return "TLM_REQ"
