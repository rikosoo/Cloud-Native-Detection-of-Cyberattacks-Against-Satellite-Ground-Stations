import pytest

from gsd.attacks import REGISTRY
from gsd.detection.asff import to_asff
from gsd.detection.engine import DetectionEngine, load_rules
from gsd.detection.evaluate import evaluate
from gsd.detection.finding import Finding, Severity
from gsd.detection.ml import TelemetryModel, fit_from_events
from gsd.simulator.scenario import run_scenario


def test_no_findings_on_a_clean_baseline(baseline, model):
    findings = DetectionEngine(model=model).run(baseline.events)
    noisy = [f for f in findings if f.rule_id != "GS-AUTH-005"]
    assert noisy == [], f"baseline should be quiet, got {[f.rule_id for f in noisy]}"


def test_every_attack_is_detected(attacked, findings):
    report = evaluate(attacked.events, findings)
    undetected = [name for name, s in report.scenarios.items() if not s.detected]
    assert undetected == []
    assert set(report.scenarios) == set(REGISTRY)


def test_precision_is_high(attacked, findings):
    report = evaluate(attacked.events, findings)
    assert report.precision > 0.95
    assert report.false_positive_rate < 0.005


@pytest.mark.parametrize(
    "attack,expected_rule",
    [
        ("credential_compromise", "GS-AUTH-004"),
        ("command_tampering", "GS-CMD-001"),
        ("replay", "GS-RPL-001"),
        ("exfiltration", "GS-EXF-001"),
    ],
)
def test_signature_rule_fires_for_each_attack(attack, expected_rule, model):
    result = run_scenario(minutes=12 * 60, attacks=[attack])
    findings = DetectionEngine(model=model).run(result.events)
    assert expected_rule in {f.rule_id for f in findings}


def test_multivariate_model_catches_subthreshold_drift(model):
    """The drift stays inside the ICD limits, so only GS-TLM-002 can see it."""
    result = run_scenario(minutes=12 * 60, attacks=["anomalous_behavior"])
    findings = DetectionEngine(model=model).run(result.events)
    tlm002 = [f for f in findings if f.rule_id == "GS-TLM-002"]
    assert tlm002
    first_ml = min(f.ts for f in tlm002)
    limit_breaches = [f for f in findings if f.rule_id == "GS-TLM-001"]
    if limit_breaches:
        assert first_ml <= min(f.ts for f in limit_breaches), "ML should fire no later than limits"


def test_engine_without_model_skips_ml_rule(attacked):
    findings = DetectionEngine().run(attacked.events)
    assert "GS-TLM-002" not in {f.rule_id for f in findings}


def test_rule_catalogue_matches_emitted_rules(findings):
    catalogue = load_rules()["rules"]
    for finding in findings:
        assert finding.rule_id in catalogue
        assert finding.remediation


def test_model_roundtrip(baseline, tmp_path):
    model = fit_from_events(baseline.events)
    path = tmp_path / "model.json"
    model.save(str(path))
    restored = TelemetryModel.load(str(path))
    sample = next(e.payload for e in baseline.events if e.type == "telemetry")
    assert restored.score(sample) == pytest.approx(model.score(sample))


def test_model_rejects_tiny_baselines():
    with pytest.raises(ValueError):
        TelemetryModel().fit([{"bus_voltage_v": 28.0}])


def test_finding_roundtrip(findings):
    finding = findings[0]
    assert Finding.from_dict(finding.to_dict()).to_dict() == finding.to_dict()


def test_asff_shape(findings):
    critical = next(f for f in findings if f.severity >= Severity.HIGH)
    asff = to_asff(critical, account_id="123456789012", region="sa-east-1")
    assert asff["SchemaVersion"] == "2018-10-08"
    assert asff["Severity"]["Normalized"] == int(critical.severity)
    assert asff["Severity"]["Label"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFORMATIONAL"}
    assert asff["AwsAccountId"] == "123456789012"
    assert asff["Resources"][0]["Region"] == "sa-east-1"
    assert asff["Id"].startswith(critical.rule_id)


def test_replay_memory_is_shared_across_batches(attacked):
    """Two engines sharing one memory still catch a frame replayed in a later batch."""
    from gsd.detection.state import InMemoryReplayMemory

    memory = InMemoryReplayMemory()
    events = sorted(attacked.events, key=lambda e: e.ts)
    half = len(events) // 2
    first = DetectionEngine(replay_memory=memory).run(events[:half])
    second = DetectionEngine(replay_memory=memory).run(events[half:])
    rules = {f.rule_id for f in first + second}
    assert {"GS-RPL-001", "GS-RPL-002"} <= rules
