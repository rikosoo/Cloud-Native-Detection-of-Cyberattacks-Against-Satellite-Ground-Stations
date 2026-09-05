"""Canonical event envelope shared by the simulator, the detectors and the AWS glue.

Every artefact produced by the simulated ground station -- spacecraft telemetry,
uplinked telecommands, identity/audit records and downlink transfers -- is wrapped
in the same :class:`Event` envelope so that a single stream can be shipped to
CloudWatch Logs / Kinesis and consumed by one detection engine.

``truth`` carries the ground-truth label of the injected attack (``None`` for
nominal traffic).  It never leaves the lab: it exists so that ``gsd evaluate``
can compute precision/recall of the detections.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

TELEMETRY = "telemetry"
TELECOMMAND = "telecommand"
AUDIT = "audit"
DOWNLINK = "downlink"

EVENT_TYPES = (TELEMETRY, TELECOMMAND, AUDIT, DOWNLINK)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def to_iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def from_iso(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass
class Event:
    """A single observation emitted by the ground station."""

    type: str
    ts: datetime
    station_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    truth: str | None = None

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {self.type!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "ts": to_iso(self.ts),
            "station_id": self.station_id,
            "payload": self.payload,
            "truth": self.truth,
        }

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Event:
        return cls(
            id=raw["id"],
            type=raw["type"],
            ts=from_iso(raw["ts"]),
            station_id=raw["station_id"],
            payload=raw.get("payload", {}),
            truth=raw.get("truth"),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True)


def write_jsonl(events: Iterable[Event], path: str) -> int:
    count = 0
    with open(path, "w", encoding="utf-8") as fh:
        for event in events:
            fh.write(event.to_json())
            fh.write("\n")
            count += 1
    return count


def read_jsonl(path: str) -> Iterator[Event]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield Event.from_dict(json.loads(line))
