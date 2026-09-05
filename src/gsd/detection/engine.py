"""Stateful detection engine.

The engine consumes the unified event stream in timestamp order and emits
:class:`~gsd.detection.finding.Finding` objects.  It is deliberately free of AWS
imports so the exact same class runs in three places: the local CLI, the unit
tests, and the Lambda function behind the Kinesis stream.

State is bounded by time windows rather than by event count, which keeps memory
flat for a long-running consumer.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from gsd import crypto
from gsd.config import CRITICAL_OPCODES, DEFAULT_PROFILE, FORBIDDEN_OPCODES, MissionProfile
from gsd.detection.finding import Finding, Severity
from gsd.detection.ml import TelemetryModel
from gsd.detection.state import InMemoryReplayMemory, ReplayMemory
from gsd.events import AUDIT, DOWNLINK, TELECOMMAND, TELEMETRY, Event, from_iso

RULES_PATH = Path(__file__).with_name("rules.yaml")

#: Coarse per-country coordinates, enough for an impossible-travel heuristic.
GEO_KM = {
    ("BR", "PT"): 7300,
    ("BR", "RU"): 11500,
    ("PT", "RU"): 3900,
}
MAX_TRAVEL_KMH = 900.0


def load_rules(path: Path | str = RULES_PATH) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _distance_km(a: str, b: str) -> float:
    if a == b:
        return 0.0
    return float(GEO_KM.get((a, b)) or GEO_KM.get((b, a)) or 8000)


@dataclass
class DetectionEngine:
    profile: MissionProfile = DEFAULT_PROFILE
    rules: dict[str, Any] = field(default_factory=load_rules)
    model: TelemetryModel | None = None
    replay_memory: ReplayMemory = field(default_factory=InMemoryReplayMemory)

    def __post_init__(self) -> None:
        self.defaults = self.rules.get("defaults", {})
        self.catalogue = self.rules["rules"]
        self._trusted = [ipaddress.ip_network(c) for c in self.profile.trusted_cidrs]
        self._failed_logins: deque[tuple[datetime, str, str]] = deque()
        self._last_login: dict[str, tuple[datetime, str]] = {}
        self._commands: deque[tuple[datetime, str]] = deque()
        self._anomaly_streak = 0

    # -- helpers --------------------------------------------------------
    def _meta(self, rule_id: str) -> dict[str, Any]:
        return self.catalogue[rule_id]

    def _params(self, rule_id: str) -> dict[str, Any]:
        return self._meta(rule_id).get("params", {}) or {}

    def _finding(
        self, rule_id: str, event: Event, description: str, evidence: dict[str, Any]
    ) -> Finding:
        meta = self._meta(rule_id)
        return Finding(
            rule_id=rule_id,
            title=meta["title"],
            severity=Severity[meta["severity"]],
            ts=event.ts,
            station_id=event.station_id,
            event_id=event.id,
            description=description,
            evidence=evidence,
            technique=meta.get("technique", ""),
            remediation=meta.get("remediation", ""),
            truth=event.truth,
        )

    def _trusted_ip(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in net for net in self._trusted)

    def _off_hours(self, ts: datetime, operator: str) -> bool:
        start, end = self.profile.duty_hours
        return not (start <= ts.hour < end) and operator not in self.profile.night_roster

    @staticmethod
    def _expire(window: deque, now: datetime, seconds: float) -> None:
        cutoff = now - timedelta(seconds=seconds)
        while window and window[0][0] < cutoff:
            window.popleft()

    # -- entry points ---------------------------------------------------
    def process(self, event: Event) -> list[Finding]:
        handler = {
            AUDIT: self._audit,
            TELECOMMAND: self._telecommand,
            TELEMETRY: self._telemetry,
            DOWNLINK: self._downlink,
        }[event.type]
        return handler(event)

    def run(self, events: Iterable[Event]) -> list[Finding]:
        findings: list[Finding] = []
        for event in sorted(events, key=lambda e: e.ts):
            findings.extend(self.process(event))
        return findings

    # -- identity plane -------------------------------------------------
    def _audit(self, event: Event) -> list[Finding]:
        out: list[Finding] = []
        p = event.payload
        action = p.get("eventName", "")
        ip = p.get("sourceIPAddress", "")
        geo = p.get("geo", "")
        operator = p.get("userIdentity", {}).get("userName", "unknown")
        mfa = (
            p.get("userIdentity", {})
            .get("sessionContext", {})
            .get("attributes", {})
            .get("mfaAuthenticated")
            == "true"
        )
        succeeded = p.get("outcome", "Success") == "Success"
        extra = p.get("additionalEventData", {}) or {}

        if succeeded and not self._trusted_ip(ip):
            out.append(
                self._finding(
                    "GS-AUTH-001",
                    event,
                    f"{operator} performed {action} from {ip} ({geo}), outside the "
                    f"approved operations netblocks.",
                    {"sourceIPAddress": ip, "geo": geo, "eventName": action},
                )
            )

        sensitive = set(self._params("GS-AUTH-004")["actions"])
        if succeeded and action in sensitive:
            out.append(
                self._finding(
                    "GS-AUTH-004",
                    event,
                    f"{operator} executed {action} on the ground-segment control plane.",
                    {"eventName": action, **extra},
                )
            )

        if succeeded and not mfa and (action in sensitive or action == "ConsoleLogin"):
            out.append(
                self._finding(
                    "GS-AUTH-002",
                    event,
                    f"{operator} completed {action} without multi-factor authentication.",
                    {"eventName": action, "sourceIPAddress": ip},
                )
            )

        # Spraying: one source, several distinct victims, short window.
        if action == "ConsoleLogin" and not succeeded:
            params = self._params("GS-AUTH-003")
            self._failed_logins.append((event.ts, ip, operator))
            self._expire(self._failed_logins, event.ts, params["window_s"])
            victims = {u for _, src, u in self._failed_logins if src == ip}
            if len(victims) >= params["distinct_users"]:
                out.append(
                    self._finding(
                        "GS-AUTH-003",
                        event,
                        f"{len(victims)} operator accounts failed authentication from {ip} "
                        f"within {params['window_s']}s.",
                        {"sourceIPAddress": ip, "targets": sorted(victims)},
                    )
                )

        if action == "ConsoleLogin" and succeeded:
            previous = self._last_login.get(operator)
            if previous:
                prev_ts, prev_geo = previous
                gap_h = max((event.ts - prev_ts).total_seconds(), 1.0) / 3600.0
                distance = _distance_km(prev_geo, geo)
                if distance and distance / gap_h > MAX_TRAVEL_KMH:
                    out.append(
                        self._finding(
                            "GS-AUTH-005",
                            event,
                            f"{operator} signed in from {geo} {gap_h:.1f}h after a sign-in "
                            f"from {prev_geo} ({distance:.0f} km apart).",
                            {"from": prev_geo, "to": geo, "hours": round(gap_h, 2)},
                        )
                    )
            self._last_login[operator] = (event.ts, geo)

        if succeeded and self._off_hours(event.ts, operator):
            out.append(
                self._finding(
                    "GS-AUTH-006",
                    event,
                    f"{operator} was active at {event.ts.hour:02d}:{event.ts.minute:02d}Z, "
                    f"outside duty hours {self.profile.duty_hours}.",
                    {"eventName": action, "hour_utc": event.ts.hour},
                )
            )

        # Bulk archive access.
        params = self._params("GS-EXF-003")
        objects = int(extra.get("objectCount", 0) or 0)
        transferred = int(extra.get("bytesTransferred", 0) or 0)
        if objects >= params["object_threshold"] or transferred >= params["bytes_threshold"]:
            out.append(
                self._finding(
                    "GS-EXF-003",
                    event,
                    f"{operator} read {objects} objects ({transferred / 1e9:.2f} GB) from "
                    f"{extra.get('bucket', 'the mission archive')} in a single call sequence.",
                    {"objectCount": objects, "bytesTransferred": transferred, **extra},
                )
            )
        return out

    # -- commanding plane -----------------------------------------------
    def _telecommand(self, event: Event) -> list[Finding]:
        out: list[Finding] = []
        cmd = event.payload
        opcode = cmd.get("opcode", "")
        operator_name = cmd.get("operator", "")
        source_ip = cmd.get("source_ip", "")
        spacecraft = cmd.get("spacecraft", "")

        if not crypto.verify(cmd, crypto.key_for(event.station_id)):
            out.append(
                self._finding(
                    "GS-CMD-001",
                    event,
                    f"Telecommand {opcode} (seq {cmd.get('seq')}) failed MAC verification; "
                    f"the frame was altered or signed with an unknown key.",
                    {"opcode": opcode, "seq": cmd.get("seq"), "mac": cmd.get("mac", "")[:16]},
                )
            )

        operator = self.profile.operator(operator_name)
        if operator and opcode not in operator.allowed_opcodes:
            out.append(
                self._finding(
                    "GS-CMD-002",
                    event,
                    f"{operator_name} ({operator.role}) issued {opcode}, which is not in the "
                    f"role's authorised opcode set.",
                    {"opcode": opcode, "role": operator.role},
                )
            )

        if opcode in FORBIDDEN_OPCODES:
            out.append(
                self._finding(
                    "GS-CMD-003",
                    event,
                    f"{opcode} is inhibited on the operations console for {spacecraft}.",
                    {"opcode": opcode, "params": cmd.get("params", {})},
                )
            )

        if opcode in CRITICAL_OPCODES and len(set(cmd.get("approvals", []))) < 2:
            out.append(
                self._finding(
                    "GS-CMD-005",
                    event,
                    f"Critical opcode {opcode} was uplinked with a single authorisation "
                    f"({cmd.get('approvals')}).",
                    {"opcode": opcode, "approvals": cmd.get("approvals", [])},
                )
            )

        if not self._trusted_ip(source_ip):
            out.append(
                self._finding(
                    "GS-CMD-006",
                    event,
                    f"Telecommand {opcode} originated from {source_ip}, outside the uplink "
                    f"gateway allowlist.",
                    {"opcode": opcode, "source_ip": source_ip},
                )
            )

        # Uplink rate.
        window_s = self.defaults["command_rate_window_s"]
        self._commands.append((event.ts, operator_name))
        self._expire(self._commands, event.ts, window_s)
        rate = sum(1 for _, who in self._commands if who == operator_name)
        if rate > self.profile.max_commands_per_minute:
            out.append(
                self._finding(
                    "GS-CMD-004",
                    event,
                    f"{operator_name} uplinked {rate} telecommands in {window_s}s "
                    f"(ceiling {self.profile.max_commands_per_minute}).",
                    {"rate": rate, "window_s": window_s},
                )
            )

        out.extend(self._replay_checks(event, cmd, spacecraft))
        return out

    def _replay_checks(self, event: Event, cmd: dict[str, Any], spacecraft: str) -> list[Finding]:
        out: list[Finding] = []
        memory_s = self.defaults["replay_memory_s"]

        seq = cmd.get("seq")
        if seq is not None:
            first_seen = self.replay_memory.check_and_record(
                f"seq#{spacecraft}#{int(seq)}", event.ts, memory_s
            )
            if first_seen:
                out.append(
                    self._finding(
                        "GS-RPL-001",
                        event,
                        f"Sequence counter {seq} for {spacecraft} was already accepted at "
                        f"{first_seen.isoformat()}; the frame is a replay.",
                        {"seq": seq, "first_seen": first_seen.isoformat()},
                    )
                )

        mac = cmd.get("mac")
        if mac:
            first_seen = self.replay_memory.check_and_record(f"mac#{mac}", event.ts, memory_s)
            if first_seen:
                out.append(
                    self._finding(
                        "GS-RPL-002",
                        event,
                        f"Authentication tag {mac[:16]}… was observed before at "
                        f"{first_seen.isoformat()}.",
                        {"mac": mac[:16], "first_seen": first_seen.isoformat()},
                    )
                )

        issued_at = cmd.get("issued_at")
        if issued_at:
            age = (event.ts - from_iso(issued_at)).total_seconds()
            max_age = self._params("GS-RPL-003")["max_age_s"]
            if age > max_age:
                out.append(
                    self._finding(
                        "GS-RPL-003",
                        event,
                        f"Telecommand {cmd.get('opcode')} was issued {age:.0f}s before uplink "
                        f"(freshness window {max_age}s).",
                        {"age_s": round(age, 1), "issued_at": issued_at},
                    )
                )
        return out

    # -- telemetry ------------------------------------------------------
    def _telemetry(self, event: Event) -> list[Finding]:
        out: list[Finding] = []
        p = event.payload
        breached = {}
        for channel, (low, high) in self.profile.limits.items():
            value = p.get(channel)
            if isinstance(value, (int, float)) and not (low <= value <= high):
                breached[channel] = {"value": value, "limit": [low, high]}
        if breached:
            out.append(
                self._finding(
                    "GS-TLM-001",
                    event,
                    "Telemetry channels outside ICD limits: " + ", ".join(sorted(breached)),
                    breached,
                )
            )

        if self.model is not None and self.model.is_fitted:
            score = self.model.score(p)
            if score > self.model.threshold:
                self._anomaly_streak += 1
                if self._anomaly_streak >= self._params("GS-TLM-002")["consecutive"]:
                    out.append(
                        self._finding(
                            "GS-TLM-002",
                            event,
                            f"Telemetry vector deviates from the learned baseline "
                            f"(score {score:.1f} > {self.model.threshold:.1f}); dominant "
                            f"channels: {', '.join(self.model.top_channels(p))}.",
                            {
                                "score": round(score, 2),
                                "threshold": round(self.model.threshold, 2),
                                "channels": self.model.top_channels(p),
                            },
                        )
                    )
            else:
                self._anomaly_streak = 0
        return out

    # -- downlink -------------------------------------------------------
    def _downlink(self, event: Event) -> list[Finding]:
        out: list[Finding] = []
        p = event.payload
        destination = p.get("destination", "")
        size_mb = float(p.get("size_mb", 0.0))
        operator = p.get("operator", "")

        if destination not in self.profile.downlink_destinations:
            out.append(
                self._finding(
                    "GS-EXF-001",
                    event,
                    f"{size_mb:.0f} MB of {p.get('product')} data was transferred to "
                    f"{destination}, which is not an approved archive.",
                    {"destination": destination, "size_mb": size_mb, "operator": operator},
                )
            )

        if size_mb > self.profile.max_downlink_mb:
            out.append(
                self._finding(
                    "GS-EXF-002",
                    event,
                    f"Transfer of {size_mb:.0f} MB exceeds the per-pass ceiling of "
                    f"{self.profile.max_downlink_mb:.0f} MB.",
                    {"size_mb": size_mb, "object_count": p.get("object_count")},
                )
            )

        if self._off_hours(event.ts, operator):
            out.append(
                self._finding(
                    "GS-EXF-004",
                    event,
                    f"Data transfer at {event.ts.hour:02d}:{event.ts.minute:02d}Z falls "
                    f"outside the scheduled contact windows.",
                    {"hour_utc": event.ts.hour, "destination": destination},
                )
            )
        return out
