"""Score the detection layer against the injected ground truth."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from gsd.detection.finding import Finding
from gsd.events import Event


@dataclass
class ScenarioScore:
    attack: str
    labelled_events: int = 0
    detected_events: int = 0
    findings: int = 0
    rules: dict[str, int] = field(default_factory=dict)
    time_to_detect_s: float | None = None

    @property
    def recall(self) -> float:
        return self.detected_events / self.labelled_events if self.labelled_events else 0.0

    @property
    def detected(self) -> bool:
        return self.detected_events > 0


@dataclass
class Report:
    scenarios: dict[str, ScenarioScore]
    true_positives: int
    false_positives: int
    benign_events: int

    @property
    def precision(self) -> float:
        total = self.true_positives + self.false_positives
        return self.true_positives / total if total else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.false_positives / self.benign_events if self.benign_events else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "precision": round(self.precision, 4),
            "false_positive_rate": round(self.false_positive_rate, 6),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "scenarios": {
                name: {
                    "detected": s.detected,
                    "recall": round(s.recall, 4),
                    "labelled_events": s.labelled_events,
                    "detected_events": s.detected_events,
                    "findings": s.findings,
                    "time_to_detect_s": s.time_to_detect_s,
                    "rules": dict(sorted(s.rules.items())),
                }
                for name, s in sorted(self.scenarios.items())
            },
        }


def evaluate(events: Iterable[Event], findings: Iterable[Finding]) -> Report:
    events = list(events)
    findings = list(findings)

    truth_by_event = {e.id: e.truth for e in events}
    first_event_ts: dict[str, Any] = {}
    scenarios: dict[str, ScenarioScore] = {}

    for event in sorted(events, key=lambda e: e.ts):
        if event.truth:
            score = scenarios.setdefault(event.truth, ScenarioScore(attack=event.truth))
            score.labelled_events += 1
            first_event_ts.setdefault(event.truth, event.ts)

    detected_ids: dict[str, set[str]] = {name: set() for name in scenarios}
    true_positives = false_positives = 0

    for finding in sorted(findings, key=lambda f: f.ts):
        truth = truth_by_event.get(finding.event_id, finding.truth)
        if truth:
            true_positives += 1
            score = scenarios.setdefault(truth, ScenarioScore(attack=truth))
            score.findings += 1
            score.rules[finding.rule_id] = score.rules.get(finding.rule_id, 0) + 1
            detected_ids.setdefault(truth, set()).add(finding.event_id)
            if score.time_to_detect_s is None and truth in first_event_ts:
                score.time_to_detect_s = (finding.ts - first_event_ts[truth]).total_seconds()
        else:
            false_positives += 1

    for name, ids in detected_ids.items():
        scenarios[name].detected_events = len(ids)

    benign = sum(1 for e in events if not e.truth)
    return Report(
        scenarios=scenarios,
        true_positives=true_positives,
        false_positives=false_positives,
        benign_events=benign,
    )
