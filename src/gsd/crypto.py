"""Telecommand authentication.

Real ground segments authenticate telecommands with CCSDS SDLS (Space Data Link
Security).  The simulator uses the same *shape* -- a keyed MAC over a canonical
serialisation of the command, plus a monotonic sequence counter -- which is
enough to make integrity tampering and replay detectable without pulling in a
space-grade crypto stack.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

# Lab-only key material. Real deployments keep these in AWS KMS / CloudHSM and
# never materialise them in application memory.
MISSION_KEYS: dict[str, bytes] = {
    "SENTINEL-GS": b"lab-key-do-not-use-in-flight-0001",
    "ORION-GS": b"lab-key-do-not-use-in-flight-0002",
}

MAC_FIELDS = ("spacecraft", "apid", "opcode", "params", "seq", "issued_at", "operator")


def canonical_bytes(command: dict[str, Any]) -> bytes:
    """Serialise the authenticated portion of a telecommand deterministically."""
    subset = {k: command.get(k) for k in MAC_FIELDS}
    return json.dumps(subset, separators=(",", ":"), sort_keys=True).encode("utf-8")


def sign(command: dict[str, Any], key: bytes) -> str:
    return hmac.new(key, canonical_bytes(command), hashlib.sha256).hexdigest()


def verify(command: dict[str, Any], key: bytes) -> bool:
    expected = sign(command, key)
    return hmac.compare_digest(expected, command.get("mac", ""))


def key_for(station_id: str) -> bytes:
    return MISSION_KEYS.get(station_id, b"lab-key-unknown-station")
