from gsd import crypto
from gsd.events import AUDIT, DOWNLINK, TELECOMMAND, TELEMETRY, Event
from gsd.simulator.scenario import run_scenario


def test_baseline_has_all_planes(baseline):
    types = {e.type for e in baseline.events}
    assert types == {TELEMETRY, TELECOMMAND, AUDIT, DOWNLINK}


def test_baseline_is_unlabelled(baseline):
    assert all(e.truth is None for e in baseline.events)


def test_events_are_ordered(attacked):
    timestamps = [e.ts for e in attacked.events]
    assert timestamps == sorted(timestamps)


def test_simulation_is_deterministic():
    a = run_scenario(minutes=120, seed=7)
    b = run_scenario(minutes=120, seed=7)
    assert [e.to_dict()["payload"] for e in a.events] == [e.to_dict()["payload"] for e in b.events]


def test_nominal_telecommands_are_authenticated(baseline):
    key = crypto.key_for(baseline.profile.station_id)
    commands = [e for e in baseline.events if e.type == TELECOMMAND]
    assert commands
    assert all(crypto.verify(e.payload, key) for e in commands)


def test_nominal_sequence_counters_are_unique(baseline):
    seqs = [e.payload["seq"] for e in baseline.events if e.type == TELECOMMAND]
    assert len(seqs) == len(set(seqs))


def test_event_roundtrip(baseline):
    event = baseline.events[0]
    assert Event.from_dict(event.to_dict()).to_dict() == event.to_dict()


def test_telemetry_stays_within_icd_limits(baseline):
    limits = baseline.profile.limits
    for event in baseline.events:
        if event.type != TELEMETRY:
            continue
        for channel, (low, high) in limits.items():
            assert low <= event.payload[channel] <= high, f"{channel} out of limits in baseline"
