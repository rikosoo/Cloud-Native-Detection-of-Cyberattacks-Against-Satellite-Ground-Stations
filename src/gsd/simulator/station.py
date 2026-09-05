"""Nominal ground-station timeline generator.

``GroundStation.run`` produces a clean day of operations: continuous spacecraft
telemetry, operator sign-ins at shift boundaries, telecommands issued during
contact windows, and payload downlinks at the end of each pass.  Attacks are
layered on top of that timeline afterwards (see :mod:`gsd.attacks`), which keeps
"what normal looks like" in exactly one place.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from gsd.config import CRITICAL_OPCODES, DEFAULT_PROFILE, MissionProfile
from gsd.events import TELEMETRY, Event
from gsd.simulator.commanding import Uplink
from gsd.simulator.downlink import DownlinkPlane
from gsd.simulator.identity import READ_ACTIONS, IdentityPlane
from gsd.simulator.spacecraft import ORBIT_PERIOD_S, SpacecraftState

TELEMETRY_PERIOD_S = 30
PASS_DURATION_S = 11 * 60


@dataclass
class SimulationResult:
    events: list[Event]
    profile: MissionProfile
    start: datetime
    end: datetime

    def of_type(self, event_type: str) -> list[Event]:
        return [e for e in self.events if e.type == event_type]


@dataclass
class GroundStation:
    """Drives the spacecraft model and the three ground-segment planes."""

    profile: MissionProfile = DEFAULT_PROFILE
    seed: int = 42
    start: datetime = field(
        default_factory=lambda: datetime(2026, 3, 12, 6, 0, tzinfo=timezone.utc)
    )

    def __post_init__(self) -> None:
        self.rng = random.Random(self.seed)
        self.spacecraft = SpacecraftState(rng=random.Random(self.seed + 1))
        self.uplink = Uplink(self.profile, rng=random.Random(self.seed + 2))
        self.identity = IdentityPlane(self.profile, rng=random.Random(self.seed + 3))
        self.downlink = DownlinkPlane(self.profile, rng=random.Random(self.seed + 4))
        self.sessions: dict[str, tuple[str, str]] = {}  # operator -> (session_id, ip)

    # -- helpers --------------------------------------------------------
    def _sign_in(self, operator_name: str, ts: datetime) -> list[Event]:
        operator = self.profile.operator(operator_name)
        assert operator is not None
        session_id = self.identity.session_id()
        ip = self.identity.home_ip(operator)
        self.sessions[operator_name] = (session_id, ip)
        # Service identities federate through STS; humans use the console.
        action = "AssumeRole" if operator_name.startswith("svc-") else "ConsoleLogin"
        return [
            self.identity.audit(
                ts,
                action=action,
                operator=operator_name,
                source_ip=ip,
                session_id=session_id,
                mfa=operator.mfa_enrolled,
                user_agent="aws-sdk-go/1.50" if action == "AssumeRole" else "gsops-console/4.2",
            )
        ]

    def _is_day_shift(self, ts: datetime) -> bool:
        start_hour, end_hour = self.profile.duty_hours
        return start_hour <= ts.hour < end_hour

    def _on_duty(self, ts: datetime) -> list[str]:
        """Operators expected to be signed in at ``ts``."""
        if self._is_day_shift(ts):
            return ["a.moreira", "l.tanaka", "svc-scheduler"]
        return ["j.okafor", "svc-scheduler"]

    # -- main loop ------------------------------------------------------
    def run(self, minutes: int = 24 * 60) -> SimulationResult:
        end = self.start + timedelta(minutes=minutes)
        events: list[Event] = []
        ts = self.start
        shift_key: tuple[int, bool] | None = None

        while ts < end:
            elapsed_s = (ts - self.start).total_seconds()
            phase_s = elapsed_s % ORBIT_PERIOD_S
            in_pass = phase_s < PASS_DURATION_S

            # Shift handover: everybody on duty signs in.
            current_shift = (ts.date().toordinal(), self._is_day_shift(ts))
            if current_shift != shift_key:
                shift_key = current_shift
                for name in self._on_duty(ts):
                    events.extend(self._sign_in(name, ts))

            # Spacecraft dynamics.
            self.spacecraft.transmitting = in_pass
            self.spacecraft.payload_on = not in_pass and self.spacecraft.orbit_phase < 0.5
            self.spacecraft.slew_rate_dps = (
                abs(self.rng.gauss(0.4, 0.15)) if in_pass else abs(self.rng.gauss(0.05, 0.02))
            )
            self.spacecraft.step(TELEMETRY_PERIOD_S)

            events.append(
                Event(
                    type=TELEMETRY,
                    ts=ts,
                    station_id=self.profile.station_id,
                    payload={"spacecraft": self.profile.spacecraft, **self.spacecraft.telemetry()},
                )
            )

            if in_pass:
                events.extend(self._pass_activity(ts))

            # End of contact: dump the collected payload data.
            if in_pass and phase_s + TELEMETRY_PERIOD_S >= PASS_DURATION_S:
                operator = self.rng.choice(self._on_duty(ts))
                _session_id, ip = self.sessions[operator]
                events.append(self.downlink.nominal(ts, operator, ip))

            ts += timedelta(seconds=TELEMETRY_PERIOD_S)

        events.sort(key=lambda e: e.ts)
        return SimulationResult(events=events, profile=self.profile, start=self.start, end=end)

    def _pass_activity(self, ts: datetime) -> list[Event]:
        """Commands and read-only API calls issued while the spacecraft is visible."""
        out: list[Event] = []
        for _ in range(self.rng.randint(0, 3)):
            operator_name = self.rng.choice(self._on_duty(ts))
            operator = self.profile.operator(operator_name)
            session_id, ip = self.sessions[operator_name]
            opcode = self.uplink.pick_opcode()
            if operator is not None and opcode not in operator.allowed_opcodes:
                opcode = "TLM_REQ"
            # Mission rules: critical opcodes carry a second authorisation.
            approvals = [operator_name]
            if opcode in CRITICAL_OPCODES:
                approvals.append("l.tanaka" if operator_name != "l.tanaka" else "s.almeida")
            command = self.uplink.build(
                opcode,
                operator_name,
                ts,
                source_ip=ip,
                session_id=session_id,
                approvals=approvals,
            )
            out.append(self.uplink.event(command, ts))

        if self.rng.random() < 0.25:
            operator_name = self.rng.choice(self._on_duty(ts))
            session_id, ip = self.sessions[operator_name]
            out.append(
                self.identity.audit(
                    ts,
                    action=self.rng.choice(READ_ACTIONS),
                    operator=operator_name,
                    source_ip=ip,
                    session_id=session_id,
                )
            )
        return out
