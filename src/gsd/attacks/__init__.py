"""Adversary emulation against the simulated ground station.

Each scenario mirrors a technique from the SPARTA space-system matrix and its
MITRE ATT&CK enterprise counterpart, so detections can be mapped to a framework
rather than to ad-hoc labels.
"""

from gsd.attacks.anomalous_behavior import AnomalousBehavior
from gsd.attacks.base import Attack, AttackContext
from gsd.attacks.command_tampering import CommandTampering
from gsd.attacks.credential_compromise import CredentialCompromise
from gsd.attacks.exfiltration import Exfiltration
from gsd.attacks.replay import ReplayAttack

ALL_ATTACKS: tuple[type[Attack], ...] = (
    CredentialCompromise,
    CommandTampering,
    ReplayAttack,
    AnomalousBehavior,
    Exfiltration,
)

REGISTRY: dict[str, type[Attack]] = {cls.name: cls for cls in ALL_ATTACKS}

__all__ = [
    "ALL_ATTACKS",
    "REGISTRY",
    "AnomalousBehavior",
    "Attack",
    "AttackContext",
    "CommandTampering",
    "CredentialCompromise",
    "Exfiltration",
    "ReplayAttack",
]
