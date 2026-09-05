from __future__ import annotations

import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING

from gsd.config import MissionProfile
from gsd.events import Event

if TYPE_CHECKING:  # pragma: no cover
    from gsd.simulator.station import GroundStation


@dataclass
class AttackContext:
    """Everything an attack needs to weave itself into an existing timeline."""

    station: GroundStation
    profile: MissionProfile
    start: datetime
    end: datetime
    rng: random.Random

    def at(self, fraction: float) -> datetime:
        """A timestamp ``fraction`` of the way through the simulated window."""
        span = (self.end - self.start).total_seconds()
        return self.start + timedelta(seconds=span * fraction)


class Attack(ABC):
    """Base class for an injected attack scenario."""

    name: str = "attack"
    tactic: str = "TA0000"
    technique: str = "T0000"
    sparta: str = "SPARTA-XX-0000000"
    description: str = ""

    @abstractmethod
    def apply(self, ctx: AttackContext, events: list[Event]) -> list[Event]:
        """Return the timeline with this attack woven in (sorted by timestamp)."""

    def label(self, event: Event) -> Event:
        event.truth = self.name
        return event

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"<{type(self).__name__} {self.name}>"


def resort(events: list[Event]) -> list[Event]:
    events.sort(key=lambda e: e.ts)
    return events
