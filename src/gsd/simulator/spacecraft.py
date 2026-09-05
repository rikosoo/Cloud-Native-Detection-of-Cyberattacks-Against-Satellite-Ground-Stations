"""A deliberately small spacecraft bus model.

The point is not fidelity -- it is to produce telemetry whose channels are
*correlated* (illumination drives power, power drives thermal, transmit duty
drives the amplifier temperature).  Correlated channels are what make a
multivariate anomaly detector meaningfully better than per-channel thresholds:
an attacker who nudges one channel while leaving the others untouched breaks the
correlation long before it breaks any single red line.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

ORBIT_PERIOD_S = 95 * 60  # ~600 km sun-synchronous LEO
ECLIPSE_FRACTION = 0.35


@dataclass
class SpacecraftState:
    """Mutable bus state advanced one simulation step at a time."""

    epoch_s: float = 0.0
    battery_soc_pct: float = 87.0
    temp_pa_c: float = 22.0
    temp_battery_c: float = 14.0
    payload_on: bool = False
    transmitting: bool = False
    slew_rate_dps: float = 0.0
    rng: random.Random = field(default_factory=lambda: random.Random(1337))

    # -- environment ----------------------------------------------------
    @property
    def orbit_phase(self) -> float:
        return (self.epoch_s % ORBIT_PERIOD_S) / ORBIT_PERIOD_S

    @property
    def in_eclipse(self) -> bool:
        return self.orbit_phase > (1.0 - ECLIPSE_FRACTION)

    @property
    def solar_input_w(self) -> float:
        if self.in_eclipse:
            return 0.0
        # Cosine-shaped illumination across the sunlit arc.
        arc = self.orbit_phase / (1.0 - ECLIPSE_FRACTION)
        return 310.0 * max(0.0, math.sin(math.pi * arc)) ** 0.6

    # -- dynamics -------------------------------------------------------
    def load_w(self) -> float:
        load = 95.0  # housekeeping
        if self.payload_on:
            load += 130.0
        if self.transmitting:
            load += 70.0
        load += abs(self.slew_rate_dps) * 8.0
        return load

    def step(self, dt_s: float) -> None:
        jitter = self.rng.gauss

        net_w = self.solar_input_w - self.load_w()
        # 120 Ah @ 28 V battery, expressed as a percentage per joule.
        self.battery_soc_pct += net_w * dt_s / (120.0 * 28.0 * 36.0)
        self.battery_soc_pct = min(100.0, max(0.0, self.battery_soc_pct)) + jitter(0, 0.02)

        pa_target = 20.0 + (28.0 if self.transmitting else 0.0) + (6.0 if self.payload_on else 0.0)
        self.temp_pa_c += (pa_target - self.temp_pa_c) * min(1.0, dt_s / 240.0) + jitter(0, 0.15)

        batt_target = 8.0 if self.in_eclipse else 18.0
        batt_target += abs(net_w) / 90.0
        self.temp_battery_c += (batt_target - self.temp_battery_c) * min(1.0, dt_s / 900.0)
        self.temp_battery_c += jitter(0, 0.08)

        self.epoch_s += dt_s

    # -- observables ----------------------------------------------------
    def telemetry(self) -> dict[str, float | bool]:
        jitter = self.rng.gauss
        bus_voltage = 26.4 + 0.032 * self.battery_soc_pct + jitter(0, 0.05)
        bus_current = self.load_w() / max(bus_voltage, 1.0) + jitter(0, 0.04)
        snr = (18.5 if self.transmitting else 14.0) - abs(self.slew_rate_dps) * 0.4
        snr += jitter(0, 0.35)
        # Coherent-BPSK-ish curve: ~1e-7 at the nominal 14 dB link margin,
        # crossing the 1e-5 alarm limit once the link degrades below ~10 dB.
        ber = min(0.5, 10 ** (-snr / 2.0) + abs(jitter(0, 1e-11)))
        return {
            "bus_voltage_v": round(bus_voltage, 3),
            "bus_current_a": round(bus_current, 3),
            "battery_soc_pct": round(self.battery_soc_pct, 2),
            "temp_pa_c": round(self.temp_pa_c, 2),
            "temp_battery_c": round(self.temp_battery_c, 2),
            "snr_db": round(snr, 2),
            "ber": float(f"{ber:.3e}"),
            "slew_rate_dps": round(self.slew_rate_dps, 3),
            "payload_on": self.payload_on,
            "transmitting": self.transmitting,
            "in_eclipse": self.in_eclipse,
            "orbit_phase": round(self.orbit_phase, 4),
        }


#: Channels fed to the multivariate anomaly model, in a fixed order.
FEATURE_CHANNELS = (
    "bus_voltage_v",
    "bus_current_a",
    "battery_soc_pct",
    "temp_pa_c",
    "temp_battery_c",
    "snr_db",
    "slew_rate_dps",
)
