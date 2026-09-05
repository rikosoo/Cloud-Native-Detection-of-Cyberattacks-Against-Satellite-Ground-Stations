"""Mission profile: the ground truth about *what normal looks like*.

Detection rules compare observed events against this profile, so it doubles as
the policy baseline an operator would keep in AWS Config / SSM Parameter Store.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# --------------------------------------------------------------------------- #
# Identities                                                                    #
# --------------------------------------------------------------------------- #

ROLE_OPCODES: dict[str, set[str]] = {
    "operator": {"TLM_REQ", "PING", "ATT_POINT", "PWR_HEATER_ON", "PWR_HEATER_OFF"},
    "flight_director": {
        "TLM_REQ",
        "PING",
        "ATT_POINT",
        "ATT_SLEW",
        "PWR_HEATER_ON",
        "PWR_HEATER_OFF",
        "PAYLOAD_ON",
        "PAYLOAD_OFF",
        "DATA_DUMP",
    },
    "security_admin": {"SEC_KEY_ROTATE", "TLM_REQ", "PING"},
    "read_only": {"TLM_REQ", "PING"},
}

#: Opcodes that can put the spacecraft in an unrecoverable state. Mission rules
#: require two-person authorisation before they are uplinked.
CRITICAL_OPCODES = {"ATT_SLEW", "PWR_BUS_OFF", "SEC_KEY_ROTATE", "PAYLOAD_OFF", "DATA_DUMP"}

#: Opcodes that must never appear from the operations console at all.
FORBIDDEN_OPCODES = {"PWR_BUS_OFF", "FSW_PATCH"}


@dataclass(frozen=True)
class Operator:
    username: str
    role: str
    home_cidr: str
    mfa_enrolled: bool = True

    @property
    def allowed_opcodes(self) -> set[str]:
        return ROLE_OPCODES.get(self.role, set())


OPERATORS: tuple[Operator, ...] = (
    Operator("a.moreira", "operator", "10.20.0.0/16"),
    Operator("j.okafor", "operator", "10.20.0.0/16"),
    Operator("l.tanaka", "flight_director", "10.20.0.0/16"),
    Operator("s.almeida", "security_admin", "10.20.0.0/16"),
    Operator("svc-scheduler", "operator", "10.30.0.0/16", mfa_enrolled=False),
)


@dataclass(frozen=True)
class MissionProfile:
    """Everything the detection layer treats as 'expected'."""

    station_id: str = "SENTINEL-GS"
    spacecraft: str = "SENTINEL-3X"

    # Network policy -----------------------------------------------------
    trusted_cidrs: tuple[str, ...] = ("10.20.0.0/16", "10.30.0.0/16", "198.51.100.0/24")
    trusted_geos: tuple[str, ...] = ("BR", "PT")

    # Operational windows (UTC hours) ------------------------------------
    duty_hours: tuple[int, int] = (7, 21)

    # Command policy -----------------------------------------------------
    max_commands_per_minute: int = 12
    max_command_age_s: int = 30
    seq_window: int = 256

    # Downlink policy ----------------------------------------------------
    downlink_destinations: tuple[str, ...] = (
        "s3://sentinel-mission-archive",
        "s3://sentinel-l0-staging",
    )
    max_downlink_mb: float = 2048.0

    # Telemetry limits (hard alarm thresholds from the spacecraft ICD) ----
    limits: dict[str, tuple[float, float]] = field(
        default_factory=lambda: {
            "bus_voltage_v": (26.0, 30.5),
            "bus_current_a": (0.5, 9.0),
            "battery_soc_pct": (45.0, 100.0),
            "temp_pa_c": (-20.0, 65.0),
            "temp_battery_c": (-5.0, 35.0),
            "snr_db": (8.0, 30.0),
            "ber": (0.0, 1e-5),
        }
    )

    #: Identities legitimately expected to work outside ``duty_hours``.
    night_roster: tuple[str, ...] = ("j.okafor", "svc-scheduler")

    operators: tuple[Operator, ...] = OPERATORS

    def operator(self, username: str) -> Operator | None:
        for op in self.operators:
            if op.username == username:
                return op
        return None


DEFAULT_PROFILE = MissionProfile()
