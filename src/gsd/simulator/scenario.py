"""Compose a nominal timeline with a selection of injected attacks."""

from __future__ import annotations

import random
import re
from datetime import datetime, timedelta, timezone

from gsd.attacks import ALL_ATTACKS, REGISTRY, AttackContext
from gsd.config import DEFAULT_PROFILE, MissionProfile
from gsd.simulator.station import GroundStation, SimulationResult

DEFAULT_START = datetime(2026, 3, 12, 0, 0, tzinfo=timezone.utc)

_RELATIVE = re.compile(r"^-?(\d+)([mhd])$")
_UNITS = {"m": "minutes", "h": "hours", "d": "days"}


def parse_start(value: str) -> datetime:
    """Resolve a ``--start`` argument to a UTC timestamp.

    Accepts an ISO 8601 timestamp, ``now``, or an offset into the past written
    as ``24h`` / ``90m`` / ``3d`` (a leading ``-`` is allowed but needs
    ``--start=-24h``, since argparse reads a bare ``-24h`` as a flag).
    Relative offsets matter for live pipelines:
    CloudWatch Logs rejects anything older than 14 days, and Firehose partitions
    the S3 archive by the event's own date.
    """
    value = value.strip()
    if value == "now":
        return datetime.now(timezone.utc)

    match = _RELATIVE.match(value)
    if match:
        amount, unit = int(match.group(1)), match.group(2)
        return datetime.now(timezone.utc) - timedelta(**{_UNITS[unit]: amount})

    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


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
