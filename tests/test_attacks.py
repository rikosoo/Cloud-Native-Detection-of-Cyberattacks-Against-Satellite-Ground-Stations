from gsd.attacks import ALL_ATTACKS, REGISTRY
from gsd.events import TELECOMMAND
from gsd.simulator.scenario import run_scenario


def test_every_attack_labels_events():
    for name in REGISTRY:
        result = run_scenario(minutes=8 * 60, attacks=[name])
        assert any(e.truth == name for e in result.events), f"{name} injected nothing"


def test_attack_metadata_is_complete():
    for cls in ALL_ATTACKS:
        assert cls.name and cls.description
        assert cls.technique and cls.sparta


def test_replay_reuses_a_previously_seen_frame(attacked):
    commands = [e for e in attacked.events if e.type == TELECOMMAND]
    macs = [e.payload.get("mac") for e in commands if e.payload.get("mac")]
    assert len(macs) != len(set(macs)), "replay should duplicate at least one MAC"


def test_tampering_breaks_at_least_one_mac(attacked):
    from gsd import crypto

    key = crypto.key_for(attacked.profile.station_id)
    broken = [
        e
        for e in attacked.events
        if e.type == TELECOMMAND and not crypto.verify(e.payload, key)
    ]
    assert broken, "command tampering should invalidate a MAC"
