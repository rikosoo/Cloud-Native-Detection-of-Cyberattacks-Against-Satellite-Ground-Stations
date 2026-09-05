"""Sub-threshold spacecraft behaviour drift caused by malicious commanding."""

from __future__ import annotations

from gsd.attacks.base import Attack, AttackContext, resort
from gsd.events import TELEMETRY, Event


class AnomalousBehavior(Attack):
    name = "anomalous_behavior"
    tactic = "TA0040"  # Impact
    technique = "T1565.001"  # Stored Data Manipulation / degraded operations
    sparta = "SPARTA-IMP-0002"  # Disruption of spacecraft operations
    description = (
        "Following the tampered slew command the bus draws more current, the amplifier "
        "runs hot and the link degrades -- while every individual channel stays inside "
        "its ICD red line. Only the broken correlation between channels reveals it."
    )

    #: Fraction of the run where the drift starts / ends.
    window = (0.46, 0.60)

    def apply(self, ctx: AttackContext, events: list[Event]) -> list[Event]:
        t_start, t_end = ctx.at(self.window[0]), ctx.at(self.window[1])
        affected = [e for e in events if e.type == TELEMETRY and t_start <= e.ts <= t_end]
        if not affected:
            return events

        span = max(1, len(affected) - 1)
        for i, event in enumerate(affected):
            ramp = min(1.0, i / (span * 0.4))  # ramp in, then hold
            p = event.payload
            p["slew_rate_dps"] = round(p["slew_rate_dps"] + 6.8 * ramp, 3)
            p["bus_current_a"] = round(p["bus_current_a"] + 2.1 * ramp, 3)
            p["bus_voltage_v"] = round(p["bus_voltage_v"] - 0.45 * ramp, 3)
            p["temp_pa_c"] = round(p["temp_pa_c"] + 17.0 * ramp, 2)
            p["battery_soc_pct"] = round(p["battery_soc_pct"] - 6.0 * ramp, 2)
            p["snr_db"] = round(p["snr_db"] - 4.2 * ramp, 2)
            p["ber"] = float(f"{p['ber'] * (1 + 40 * ramp):.3e}")
            self.label(event)

        return resort(events)
