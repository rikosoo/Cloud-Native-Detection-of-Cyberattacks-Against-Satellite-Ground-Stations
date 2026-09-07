"""``gsd`` command line: simulate -> train -> detect -> evaluate -> publish."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from gsd.attacks import REGISTRY
from gsd.detection.asff import batch as asff_batch
from gsd.detection.engine import DetectionEngine
from gsd.detection.evaluate import evaluate
from gsd.detection.finding import Finding
from gsd.detection.ml import TelemetryModel, fit_from_events
from gsd.events import read_jsonl
from gsd.simulator.scenario import DEFAULT_START, parse_start, run_scenario


def _write_findings(findings: list[Finding], path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(finding.to_json() + "\n" for finding in findings)


def _read_findings(path: str) -> list[Finding]:
    with open(path, encoding="utf-8") as fh:
        return [Finding.from_dict(json.loads(line)) for line in fh if line.strip()]


# --------------------------------------------------------------------------- #
# commands                                                                      #
# --------------------------------------------------------------------------- #


def cmd_simulate(args: argparse.Namespace) -> int:
    attacks = None
    if args.attacks:
        attacks = [] if args.attacks == ["none"] else args.attacks
    start = parse_start(args.start) if args.start else DEFAULT_START
    result = run_scenario(minutes=args.minutes, seed=args.seed, attacks=attacks, start=start)

    from gsd.emit import build_sink

    target = f"file:{args.out}" if args.out else args.sink
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    written = build_sink(target).emit(result.events)

    labels = Counter(e.truth for e in result.events if e.truth)
    print(
        f"simulated {written} events "
        f"({result.start:%Y-%m-%d %H:%M}Z -> {result.end:%Y-%m-%d %H:%M}Z), "
        f"attacks: {dict(labels) or 'none'}",
        file=sys.stderr,
    )
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    if args.events:
        events = list(read_jsonl(args.events))
    else:
        events = run_scenario(minutes=args.minutes, seed=args.seed, attacks=[]).events
    model = fit_from_events(events, quantile=args.quantile)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    model.save(args.out)
    print(
        f"model fitted on {model.trained_on} nominal samples, "
        f"threshold={model.threshold:.2f} (q={args.quantile}) -> {args.out}",
        file=sys.stderr,
    )
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    events = list(read_jsonl(args.events))
    model = TelemetryModel.load(args.model) if args.model else None
    engine = DetectionEngine(model=model)
    findings = engine.run(events)

    if args.out:
        _write_findings(findings, args.out)
    else:
        for finding in findings:
            print(finding.to_json())

    by_severity = Counter(f.severity.label for f in findings)
    print(
        f"{len(findings)} findings from {len(events)} events; severity={dict(by_severity)}",
        file=sys.stderr,
    )
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    events = list(read_jsonl(args.events))
    findings = _read_findings(args.findings)
    report = evaluate(events, findings)
    print(json.dumps(report.to_dict(), indent=2))
    missed = [name for name, s in report.scenarios.items() if not s.detected]
    if missed:
        print(f"undetected scenarios: {', '.join(missed)}", file=sys.stderr)
        return 1
    return 0


def cmd_asff(args: argparse.Namespace) -> int:
    findings = _read_findings(args.findings)
    batches = asff_batch(findings, account_id=args.account_id, region=args.region)

    if args.publish:
        from gsd.emit.sinks import publish_findings

        result = publish_findings(batches, region=args.region)
        print(json.dumps(result, indent=2))
        return 0 if result["failed"] == 0 else 1

    flat = [item for chunk in batches for item in chunk]
    if args.out:
        Path(args.out).write_text(json.dumps(flat, indent=2), encoding="utf-8")
        print(f"wrote {len(flat)} ASFF findings to {args.out}", file=sys.stderr)
    else:
        print(json.dumps(flat, indent=2))
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    baseline = run_scenario(minutes=args.minutes, seed=args.seed + 1, attacks=[])
    model = fit_from_events(baseline.events)
    result = run_scenario(minutes=args.minutes, seed=args.seed)
    findings = DetectionEngine(model=model).run(result.events)
    report = evaluate(result.events, findings)

    print(f"events        : {len(result.events)}")
    print(f"findings      : {len(findings)}")
    print(f"precision     : {report.precision:.3f}")
    print(f"false positives: {report.false_positives} over {report.benign_events} benign events")
    print()
    print(f"{'scenario':<24}{'detected':>10}{'recall':>9}{'MTTD':>9}  rules")
    for name, score in sorted(report.scenarios.items()):
        mttd = "-" if score.time_to_detect_s is None else f"{score.time_to_detect_s:.0f}s"
        print(
            f"{name:<24}{'yes' if score.detected else 'NO':>10}{score.recall:>9.2f}{mttd:>9}  "
            f"{', '.join(sorted(score.rules))}"
        )
    return 0 if all(s.detected for s in report.scenarios.values()) else 1


# --------------------------------------------------------------------------- #
# parser                                                                        #
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gsd",
        description="Cloud-native detection of cyberattacks against satellite ground stations",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sim = sub.add_parser("simulate", help="generate a ground-station event timeline")
    sim.add_argument("--minutes", type=int, default=24 * 60)
    sim.add_argument("--seed", type=int, default=42)
    sim.add_argument(
        "--attacks",
        nargs="*",
        choices=[*REGISTRY, "none"],
        help="attacks to inject (default: all; 'none' for a clean baseline)",
    )
    sim.add_argument(
        "--start",
        help=(
            "timeline start: ISO 8601, 'now', or an offset into the past (24h, 90m, 3d). "
            "Defaults to a fixed date so runs are reproducible; use a relative offset when "
            "feeding CloudWatch Logs, which rejects events older than 14 days."
        ),
    )
    sim.add_argument("--out", help="write JSONL to this path")
    sim.add_argument(
        "--sink", default="stdout", help="stdout | file:<path> | cloudwatch:<group>/<stream> | kinesis:<name>"
    )
    sim.set_defaults(func=cmd_simulate)

    train = sub.add_parser("train", help="fit the telemetry baseline model")
    train.add_argument("--events", help="baseline JSONL (default: simulate a clean run)")
    train.add_argument("--minutes", type=int, default=24 * 60)
    train.add_argument("--seed", type=int, default=43)
    train.add_argument("--quantile", type=float, default=0.999)
    train.add_argument("--out", default="models/telemetry.json")
    train.set_defaults(func=cmd_train)

    detect = sub.add_parser("detect", help="run the detection engine over an event file")
    detect.add_argument("--events", required=True)
    detect.add_argument("--model", help="telemetry model JSON (enables GS-TLM-002)")
    detect.add_argument("--out", help="write findings JSONL here")
    detect.set_defaults(func=cmd_detect)

    ev = sub.add_parser("evaluate", help="score findings against the injected ground truth")
    ev.add_argument("--events", required=True)
    ev.add_argument("--findings", required=True)
    ev.set_defaults(func=cmd_evaluate)

    asff = sub.add_parser("asff", help="render findings as ASFF / import into Security Hub")
    asff.add_argument("--findings", required=True)
    asff.add_argument("--out")
    asff.add_argument("--account-id")
    asff.add_argument("--region")
    asff.add_argument("--publish", action="store_true", help="call securityhub:BatchImportFindings")
    asff.set_defaults(func=cmd_asff)

    demo = sub.add_parser("demo", help="run the whole pipeline in memory and print a scorecard")
    demo.add_argument("--minutes", type=int, default=24 * 60)
    demo.add_argument("--seed", type=int, default=42)
    demo.set_defaults(func=cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
