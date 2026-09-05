from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import IntEnum
from typing import Any

from gsd.events import to_iso


class Severity(IntEnum):
    """Normalised severity, aligned with the ASFF 0-100 scale."""

    INFORMATIONAL = 0
    LOW = 20
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 90

    @property
    def label(self) -> str:
        return self.name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    ts: datetime
    station_id: str
    event_id: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    technique: str = ""
    remediation: str = ""
    truth: str | None = None  # ground-truth label of the event, lab only

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "severity_score": int(self.severity),
            "ts": to_iso(self.ts),
            "station_id": self.station_id,
            "event_id": self.event_id,
            "description": self.description,
            "evidence": self.evidence,
            "technique": self.technique,
            "remediation": self.remediation,
            "truth": self.truth,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True, default=str)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> Finding:
        from gsd.events import from_iso

        return cls(
            rule_id=raw["rule_id"],
            title=raw["title"],
            severity=Severity[raw["severity"]],
            ts=from_iso(raw["ts"]),
            station_id=raw["station_id"],
            event_id=raw["event_id"],
            description=raw["description"],
            evidence=raw.get("evidence", {}),
            technique=raw.get("technique", ""),
            remediation=raw.get("remediation", ""),
            truth=raw.get("truth"),
        )
