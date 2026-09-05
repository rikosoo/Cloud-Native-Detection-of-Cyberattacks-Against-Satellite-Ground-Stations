"""Operator credential compromise followed by privilege escalation."""

from __future__ import annotations

from datetime import timedelta

from gsd.attacks.base import Attack, AttackContext, resort
from gsd.events import Event

ATTACKER_IP = "203.0.113.66"
ATTACKER_GEO = "RU"
ATTACKER_UA = "python-requests/2.31.0"


class CredentialCompromise(Attack):
    name = "credential_compromise"
    tactic = "TA0006/TA0004"  # Credential Access -> Privilege Escalation
    technique = "T1110.003 + T1078.004 + T1098.001"
    sparta = "SPARTA-IA-0004"  # Compromise ground system
    description = (
        "Password spraying from an untrusted netblock, a successful sign-in without MFA "
        "outside duty hours, then persistence via a new access key and an admin policy "
        "attachment. The stolen session is later used to command the spacecraft."
    )

    #: Operator whose credentials are stolen.
    victim = "a.moreira"

    def apply(self, ctx: AttackContext, events: list[Event]) -> list[Event]:
        identity = ctx.station.identity
        t0 = ctx.at(0.13)  # ~03:00 UTC: outside duty hours
        session_id = f"sess-{'ff' * 6}"
        injected: list[Event] = []

        # 1. Spray: six failures against distinct operators from one source.
        for i, victim in enumerate(op.username for op in ctx.profile.operators):
            injected.append(
                self.label(
                    identity.audit(
                        t0 + timedelta(seconds=9 * i),
                        action="ConsoleLogin",
                        operator=victim,
                        source_ip=ATTACKER_IP,
                        session_id=f"sess-spray-{i}",
                        outcome="Failure",
                        mfa=False,
                        geo=ATTACKER_GEO,
                        user_agent=ATTACKER_UA,
                        extra={"errorMessage": "Failed authentication"},
                    )
                )
            )

        # 2. One of them works. No MFA, untrusted CIDR, foreign geo.
        t_success = t0 + timedelta(minutes=2)
        injected.append(
            self.label(
                identity.audit(
                    t_success,
                    action="ConsoleLogin",
                    operator=self.victim,
                    source_ip=ATTACKER_IP,
                    session_id=session_id,
                    outcome="Success",
                    mfa=False,
                    geo=ATTACKER_GEO,
                    user_agent=ATTACKER_UA,
                )
            )
        )

        # 3. Persistence and privilege escalation.
        for offset, action, extra in (
            (3, "CreateAccessKey", {"targetUser": self.victim, "accessKeyId": "AKIAEXAMPLE0DEAD"}),
            (
                5,
                "AttachUserPolicy",
                {"targetUser": self.victim, "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"},
            ),
            (7, "UpdateMissionProfile", {"missionProfileId": "mp-01", "change": "trackingConfig"}),
            (9, "DeleteTrail", {"trailName": "gs-audit-trail"}),
        ):
            injected.append(
                self.label(
                    identity.audit(
                        t_success + timedelta(minutes=offset),
                        action=action,
                        operator=self.victim,
                        source_ip=ATTACKER_IP,
                        session_id=session_id,
                        geo=ATTACKER_GEO,
                        user_agent=ATTACKER_UA,
                        extra=extra,
                    )
                )
            )

        # 4. The stolen session is used to uplink a command it has no business issuing.
        command = ctx.station.uplink.build(
            "SEC_KEY_ROTATE",
            self.victim,
            t_success + timedelta(minutes=12),
            source_ip=ATTACKER_IP,
            session_id=session_id,
            params={"slot": 2},
        )
        injected.append(
            self.label(
                ctx.station.uplink.event(command, t_success + timedelta(minutes=12))
            )
        )

        # Record the hijacked session so later stages can reuse it.
        ctx.station.sessions[f"{self.victim}@attacker"] = (session_id, ATTACKER_IP)
        return resort(events + injected)
