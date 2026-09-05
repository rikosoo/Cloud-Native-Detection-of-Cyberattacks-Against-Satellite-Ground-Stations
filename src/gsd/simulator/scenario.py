"""Compose a nominal timeline with a selection of injected attacks."""

from __future__ import annotations

import random
from datetime import datetime, timezone

from gsd.attacks import ALL_ATTACKS, REGISTRY, AttackContext
from gsd.config import DEFAULT_PROFILE, MissionProfile
from gsd.simulator.station import GroundStation, SimulationResult

DEFAULT_START = datetime(2026, 3, 12, 0, 0, tzinfo=timezone.utc)


def run_scenario(
    *,
    minutes: int = 24 * 60,
    seed: int = 42,
    attacks: list[str] | None = None,
    profile: MissionProfile = DEFAULT_PROFILE,
    start: datetime = DEFAULT_START,
) -> SimulationResult:
    """Run the ground station and weave in the requested attacks.

    ``attacks=None`` injects every scenario, in dependency order: the credential
    compromise establishes the hijacked session that the tampering and
    exfiltration stages reuse.
    """
    station = GroundStation(profile=profile, seed=seed, start=start)
    result = station.run(minutes=minutes)

    selected = ALL_ATTACKS if attacks is None else [REGISTRY[name] for name in attacks]
    # Preserve dependency order regardless of how the caller listed them.
    ordered = [cls for cls in ALL_ATTACKS if cls in selected]

    ctx = AttackContext(
        station=station,
        profile=profile,
        start=result.start,
        end=result.end,
        rng=random.Random(seed + 99),
    )
    events = result.events
    for cls in ordered:
        events = cls().apply(ctx, events)

    return SimulationResult(events=events, profile=profile, start=result.start, end=result.end)
