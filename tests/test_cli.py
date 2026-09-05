import json

from gsd.cli import main


def test_pipeline_end_to_end(tmp_path, capsys):
    events = tmp_path / "events.jsonl"
    baseline = tmp_path / "baseline.jsonl"
    model = tmp_path / "model.json"
    findings = tmp_path / "findings.jsonl"
    asff = tmp_path / "asff.json"

    assert main(["simulate", "--minutes", "480", "--attacks", "none", "--out", str(baseline)]) == 0
    assert main(["simulate", "--minutes", "480", "--out", str(events)]) == 0
    assert main(["train", "--events", str(baseline), "--out", str(model)]) == 0
    assert (
        main(
            [
                "detect",
                "--events",
                str(events),
                "--model",
                str(model),
                "--out",
                str(findings),
            ]
        )
        == 0
    )
    assert main(["asff", "--findings", str(findings), "--out", str(asff)]) == 0

    exit_code = main(["evaluate", "--events", str(events), "--findings", str(findings)])
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["precision"] > 0.9
    assert json.loads(asff.read_text())[0]["SchemaVersion"] == "2018-10-08"


def test_demo_reports_every_scenario(capsys):
    assert main(["demo", "--minutes", "480"]) == 0
    out = capsys.readouterr().out
    for scenario in ("credential_compromise", "command_tampering", "replay", "exfiltration"):
        assert scenario in out
