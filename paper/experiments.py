"""Reproducible experiment harness for the paper.

Every number and figure in ``paper/main.tex`` is produced here. Nothing in the
manuscript is typed by hand: the script writes ``paper/data/results.json`` for
inspection and ``paper/data/macros.tex``, which the manuscript \\input's, so a
stale figure and a stale sentence are impossible.

    python paper/experiments.py [--seeds 20] [--minutes 1440]

Requires numpy, PyYAML and matplotlib (``pip install -e ".[paper]"``).
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics as stats
import sys
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gsd.detection.engine import DetectionEngine
from gsd.detection.evaluate import evaluate
from gsd.detection.finding import Finding
from gsd.detection.ml import TelemetryModel, fit_from_events, vectorise
from gsd.events import TELEMETRY
from gsd.simulator.scenario import run_scenario
from gsd.simulator.spacecraft import FEATURE_CHANNELS, ORBIT_PERIOD_S
from gsd.simulator.station import TELEMETRY_PERIOD_S

DATA_DIR = Path(__file__).parent / "data"
FIG_DIR = Path(__file__).parent / "figures"

ML_RULE = "GS-TLM-002"
LIMIT_RULE = "GS-TLM-001"
SCENARIOS = (
    "credential_compromise",
    "command_tampering",
    "replay",
    "anomalous_behavior",
    "exfiltration",
)
SCENARIO_LABELS = {
    "credential_compromise": "Credential\ncompromise",
    "command_tampering": "Command\ntampering",
    "replay": "Replay",
    "anomalous_behavior": "Anomalous\nbehaviour",
    "exfiltration": "Exfiltration",
}

# Validated palette (see references/palette.md); first three categorical slots
# clear the all-pairs CVD and normal-vision floors in light mode.
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
# Ordinal single-hue ramp for the ordered severity scale.
SEVERITY_RAMP = {
    "LOW": "#86b6ef",
    "MEDIUM": "#5598e7",
    "HIGH": "#2a78d6",
    "CRITICAL": "#184f95",
}
INK, INK_SOFT, GRID = "#0b0b0b", "#52514e", "#d9d8d4"


# --------------------------------------------------------------------------- #
# helpers                                                                       #
# --------------------------------------------------------------------------- #


def mean_sd(values: Iterable[float]) -> dict[str, float]:
    values = [float(v) for v in values]
    if not values:
        return {"mean": float("nan"), "sd": float("nan"), "n": 0}
    return {
        "mean": stats.fmean(values),
        "sd": stats.stdev(values) if len(values) > 1 else 0.0,
        "n": len(values),
        "min": min(values),
        "max": max(values),
    }


def trial(seed: int, minutes: int) -> dict[str, Any]:
    """One independent trial: fit on a clean run, detect on an attacked run."""
    baseline = run_scenario(minutes=minutes, seed=seed + 10_000, attacks=[])
    model = fit_from_events(baseline.events)
    attacked = run_scenario(minutes=minutes, seed=seed)
    findings = DetectionEngine(model=model).run(attacked.events)
    return {"model": model, "events": attacked.events, "findings": findings}


def subset(findings: list[Finding], mode: str) -> list[Finding]:
    if mode == "rules":
        return [f for f in findings if f.rule_id != ML_RULE]
    if mode == "ml":
        return [f for f in findings if f.rule_id == ML_RULE]
    return findings


def roc(scores: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray, float]:
    """ROC curve and AUC for a score where higher means more anomalous."""
    order = np.argsort(-scores, kind="mergesort")
    hits = labels[order]
    positives, negatives = hits.sum(), (~hits).sum()
    if positives == 0 or negatives == 0:
        return np.array([0.0, 1.0]), np.array([0.0, 1.0]), float("nan")
    tpr = np.concatenate([[0.0], np.cumsum(hits) / positives])
    fpr = np.concatenate([[0.0], np.cumsum(~hits) / negatives])
    integrate = getattr(np, "trapezoid", None) or np.trapz
    return fpr, tpr, float(integrate(tpr, fpr))


def univariate_scores(model: TelemetryModel, payloads: list[dict]) -> np.ndarray:
    """Best-case per-channel detector: the largest robust z-score of any channel.

    This is the strongest univariate strawman -- it already knows the robust
    centre and scale of every channel and takes the worst one. The only thing it
    lacks is the covariance between channels.
    """
    assert model.center is not None and model.scale is not None
    matrix = np.array([vectorise(p, model.channels) for p in payloads])
    return np.abs((matrix - model.center) / model.scale).max(axis=1)


# --------------------------------------------------------------------------- #
# experiments                                                                   #
# --------------------------------------------------------------------------- #


def experiment_dataset(minutes: int) -> dict[str, Any]:
    """E0: describe the generated corpus."""
    attacked = run_scenario(minutes=minutes, seed=1)
    by_type: dict[str, int] = {}
    by_truth: dict[str, int] = {}
    for event in attacked.events:
        by_type[event.type] = by_type.get(event.type, 0) + 1
        if event.truth:
            by_truth[event.truth] = by_truth.get(event.truth, 0) + 1
    return {
        "minutes": minutes,
        "events_total": len(attacked.events),
        "events_by_type": by_type,
        "events_by_attack": by_truth,
        "benign_events": len(attacked.events) - sum(by_truth.values()),
    }


def experiment_effectiveness(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """E1 + E2: per-scenario effectiveness and the rules/ML ablation."""
    modes = ("rules", "ml", "all")
    per_mode: dict[str, Any] = {}

    for mode in modes:
        detected: dict[str, list[float]] = {s: [] for s in SCENARIOS}
        recalls: dict[str, list[float]] = {s: [] for s in SCENARIOS}
        mttd: dict[str, list[float]] = {s: [] for s in SCENARIOS}
        precisions, fprs, counts = [], [], []

        for t in trials:
            report = evaluate(t["events"], subset(t["findings"], mode))
            precisions.append(report.precision)
            fprs.append(report.false_positive_rate)
            counts.append(report.true_positives + report.false_positives)
            for name in SCENARIOS:
                score = report.scenarios.get(name)
                detected[name].append(1.0 if score and score.detected else 0.0)
                recalls[name].append(score.recall if score else 0.0)
                if score and score.time_to_detect_s is not None:
                    mttd[name].append(score.time_to_detect_s)

        per_mode[mode] = {
            "precision": mean_sd(precisions),
            "false_positive_rate": mean_sd(fprs),
            "findings": mean_sd(counts),
            "scenarios": {
                name: {
                    "detection_rate": stats.fmean(detected[name]),
                    "recall": mean_sd(recalls[name]),
                    "mttd_s": mean_sd(mttd[name]),
                }
                for name in SCENARIOS
            },
        }
    return per_mode


def experiment_roc(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """E3: multivariate versus the best univariate detector on telemetry."""
    aucs = {"mahalanobis": [], "univariate": []}
    reference: dict[str, Any] = {}

    for index, t in enumerate(trials):
        model: TelemetryModel = t["model"]
        payloads, labels = [], []
        for event in t["events"]:
            if event.type == TELEMETRY:
                payloads.append(event.payload)
                labels.append(event.truth is not None)
        labels_arr = np.array(labels, dtype=bool)

        multi = np.array([model.score(p) for p in payloads])
        uni = univariate_scores(model, payloads)

        fpr_m, tpr_m, auc_m = roc(multi, labels_arr)
        fpr_u, tpr_u, auc_u = roc(uni, labels_arr)
        aucs["mahalanobis"].append(auc_m)
        aucs["univariate"].append(auc_u)

        if index == 0:  # keep one curve for plotting
            reference = {
                "mahalanobis": {"fpr": fpr_m.tolist(), "tpr": tpr_m.tolist(), "auc": auc_m},
                "univariate": {"fpr": fpr_u.tolist(), "tpr": tpr_u.tolist(), "auc": auc_u},
                "operating_point": operating_point(multi, labels_arr, model.threshold),
                "positives": int(labels_arr.sum()),
                "negatives": int((~labels_arr).sum()),
            }

    return {
        "auc_mahalanobis": mean_sd(aucs["mahalanobis"]),
        "auc_univariate": mean_sd(aucs["univariate"]),
        "reference": reference,
    }


def operating_point(scores: np.ndarray, labels: np.ndarray, threshold: float) -> dict[str, float]:
    flagged = scores > threshold
    tp = int((flagged & labels).sum())
    fp = int((flagged & ~labels).sum())
    return {
        "threshold": float(threshold),
        "tpr": tp / max(int(labels.sum()), 1),
        "fpr": fp / max(int((~labels).sum()), 1),
    }


def experiment_phase_swap(minutes: int, seeds: int) -> dict[str, Any]:
    """E3b: a probe that isolates the joint structure from the marginals.

    The drift injected by ``anomalous_behavior`` pushes several channels well
    outside their own robust scale, so a per-channel detector sees it too -- the
    comparison in E3 cannot separate "multivariate" from "well-calibrated
    univariate". This probe removes that confound. Each telemetry vector in a
    window is replaced by the vector observed exactly half an orbit earlier:
    every individual value is one the spacecraft genuinely produced, and lies
    inside its own learned marginal, but the combination (eclipse-era power with
    sunlit-era temperatures) is physically impossible.

    It models a real technique -- replaying recorded housekeeping frames to mask
    a fault or a malicious command -- but is kept here as a controlled probe
    rather than a sixth deployed scenario.
    """
    half_orbit_samples = int((ORBIT_PERIOD_S / 2) // TELEMETRY_PERIOD_S)
    window = 100  # 50 simulated minutes
    aucs = {"mahalanobis": [], "univariate": []}
    detected = {"mahalanobis": 0, "univariate": 0}
    reference: dict[str, Any] = {}

    for seed in range(1, seeds + 1):
        clean = run_scenario(minutes=minutes, seed=seed + 10_000, attacks=[])
        model = fit_from_events(clean.events)
        telemetry = [e for e in clean.events if e.type == TELEMETRY]

        start = len(telemetry) // 2
        payloads = [dict(e.payload) for e in telemetry]
        labels = np.zeros(len(payloads), dtype=bool)
        for i in range(start, min(start + window, len(payloads))):
            donor = payloads[i - half_orbit_samples]
            for channel in FEATURE_CHANNELS:
                payloads[i][channel] = donor[channel]
            labels[i] = True

        multi = np.array([model.score(p) for p in payloads])
        uni = univariate_scores(model, payloads)
        # The univariate detector needs its own operating point; use the same
        # training quantile on the clean run so the comparison is fair.
        uni_clean = univariate_scores(model, [e.payload for e in telemetry])
        uni_threshold = float(np.quantile(uni_clean, model.quantile))

        _, _, auc_m = roc(multi, labels)
        _, _, auc_u = roc(uni, labels)
        aucs["mahalanobis"].append(auc_m)
        aucs["univariate"].append(auc_u)
        detected["mahalanobis"] += int((multi[labels] > model.threshold).any())
        detected["univariate"] += int((uni[labels] > uni_threshold).any())

        if seed == 1:
            rng = np.random.default_rng(0)
            unlabelled = multi[~labels]
            reference = {
                "threshold": float(model.threshold),
                "scores_normal": sorted(
                    rng.choice(unlabelled, size=min(600, unlabelled.size), replace=False).tolist()
                ),
                "scores_swapped": sorted(multi[labels].tolist()),
                "tpr_mahalanobis": float((multi[labels] > model.threshold).mean()),
                "tpr_univariate": float((uni[labels] > uni_threshold).mean()),
                "median_normal": float(np.median(unlabelled)),
                "median_swapped": float(np.median(multi[labels])),
            }

    return {
        "auc_mahalanobis": mean_sd(aucs["mahalanobis"]),
        "auc_univariate": mean_sd(aucs["univariate"]),
        "trials_detected": detected,
        "trials": seeds,
        "window_samples": window,
        "shift_samples": half_orbit_samples,
        "reference": reference,
    }


def experiment_false_positives(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """Which rules produce the residual false positives, and how many."""
    per_rule: dict[str, list[int]] = {}
    for t in trials:
        truth = {e.id: e.truth for e in t["events"]}
        counts: dict[str, int] = {}
        for finding in t["findings"]:
            if not truth.get(finding.event_id):
                counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        for rule, count in counts.items():
            per_rule.setdefault(rule, []).append(count)
    return {
        rule: {"mean_per_trial": stats.fmean(counts), "trials_affected": len(counts)}
        for rule, counts in sorted(per_rule.items())
    }


def experiment_lead_time(trials: list[dict[str, Any]]) -> dict[str, Any]:
    """E4: how much warning the multivariate model buys over the ICD limits."""
    leads, ml_only = [], 0
    for t in trials:
        labelled = {e.id for e in t["events"] if e.truth == "anomalous_behavior"}
        ml = [f.ts for f in t["findings"] if f.rule_id == ML_RULE and f.event_id in labelled]
        limit = [f.ts for f in t["findings"] if f.rule_id == LIMIT_RULE and f.event_id in labelled]
        if not ml:
            continue
        if not limit:
            ml_only += 1
            continue
        leads.append((min(limit) - min(ml)).total_seconds() / 60.0)
    return {
        "lead_minutes": mean_sd(leads),
        "samples": leads,
        "trials_without_limit_breach": ml_only,
    }


def experiment_baseline_size(minutes: int, seed: int = 1) -> dict[str, Any]:
    """E5: how much clean telemetry the baseline model actually needs."""
    clean = run_scenario(minutes=minutes, seed=seed + 10_000, attacks=[])
    clean_telemetry = [e for e in clean.events if e.type == TELEMETRY]
    attacked = run_scenario(minutes=minutes, seed=seed)

    payloads, labels = [], []
    for event in attacked.events:
        if event.type == TELEMETRY:
            payloads.append(event.payload)
            labels.append(event.truth is not None)
    labels_arr = np.array(labels, dtype=bool)

    rows = []
    for hours in (1, 2, 4, 8, 12, 16, 20, 24):
        window = clean_telemetry[: int(hours * 120)]  # 30 s cadence
        if len(window) < len(FEATURE_CHANNELS) + 2:
            continue
        model = TelemetryModel().fit([e.payload for e in window])
        scores = np.array([model.score(p) for p in payloads])
        point = operating_point(scores, labels_arr, model.threshold)
        _, _, auc = roc(scores, labels_arr)
        rows.append(
            {
                "hours": hours,
                "samples": len(window),
                "threshold": model.threshold,
                "auc": auc,
                **point,
            }
        )
    return {"rows": rows}


def experiment_throughput(minutes: int, seed: int = 1, repeats: int = 5) -> dict[str, Any]:
    """E6: single-core detection cost, with and without the model."""
    baseline = run_scenario(minutes=minutes, seed=seed + 10_000, attacks=[])
    model = fit_from_events(baseline.events)
    attacked = run_scenario(minutes=minutes, seed=seed)
    events = attacked.events

    results = {}
    for label, engine_model in (("rules", None), ("rules+ml", model)):
        durations = []
        for _ in range(repeats):
            engine = DetectionEngine(model=engine_model)
            start = time.perf_counter()
            engine.run(events)
            durations.append(time.perf_counter() - start)
        best = min(durations)
        results[label] = {
            "events": len(events),
            "seconds": mean_sd(durations),
            "events_per_second": len(events) / best,
            "microseconds_per_event": best / len(events) * 1e6,
        }

    fit_durations = []
    for _ in range(repeats):
        start = time.perf_counter()
        fit_from_events(baseline.events)
        fit_durations.append(time.perf_counter() - start)
    results["model_fit"] = {
        "seconds": mean_sd(fit_durations),
        "samples": model.trained_on,
        "model_bytes": len(json.dumps(model.to_dict())),
    }
    return results


def experiment_alert_volume(trials: list[dict[str, Any]], minutes: int) -> dict[str, Any]:
    """E7: the analyst-facing load, by severity and by hour."""
    severities = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    hours = minutes // 60
    per_hour = {s: [0.0] * hours for s in severities}
    totals = {s: [] for s in severities}

    for t in trials:
        counts = {s: 0 for s in severities}
        start = min(e.ts for e in t["events"])
        for finding in t["findings"]:
            label = finding.severity.label
            if label not in counts:
                continue
            counts[label] += 1
            bucket = int((finding.ts - start).total_seconds() // 3600)
            if 0 <= bucket < hours:
                per_hour[label][bucket] += 1
        for s in severities:
            totals[s].append(counts[s])

    trial_count = len(trials)
    return {
        "per_severity_total": {s: mean_sd(totals[s]) for s in severities},
        "per_hour_mean": {s: [v / trial_count for v in per_hour[s]] for s in severities},
        "hours": hours,
    }

# --------------------------------------------------------------------------- #
# localisation                                                                  #
# --------------------------------------------------------------------------- #

#: Figure and table strings per language. The numbers are identical across
#: languages -- only the labels change -- because both are rendered from one
#: results object.
STRINGS: dict[str, dict[str, str]] = {
    "en": {
        "recall": "Event-level recall",
        "rules_only": "Rules only",
        "model_only": "Model only",
        "rules_model": "Rules + model",
        "fpr": "False positive rate",
        "tpr": "True positive rate",
        "multivariate": "Multivariate (Mahalanobis)",
        "univariate": "Best single channel",
        "operating": "deployed operating point",
        "leadtime_x": "Warning time before the first ICD limit breach (min)",
        "trials": "Trials",
        "mean": "mean",
        "min_unit": "min",
        "mahal": "Squared Mahalanobis distance",
        "density": "Density",
        "nominal": "Nominal telemetry",
        "swapped": "Phase-swapped (attack)",
        "threshold_note": "detection threshold\n(q=0.999) = ",
        "rate": "Rate",
        "baseline_x": "Clean telemetry used to fit the baseline (hours)",
        "auc": "AUC",
        "alerts_x": "Hour of the simulated day (UTC)",
        "alerts_y": "Findings (mean per trial)",
        "sev_low": "Low",
        "sev_medium": "Medium",
        "sev_high": "High",
        "sev_critical": "Critical",
    },
    "pt": {
        "recall": "Revocação por evento",
        "rules_only": "Apenas regras",
        "model_only": "Apenas modelo",
        "rules_model": "Regras + modelo",
        "fpr": "Taxa de falsos positivos",
        "tpr": "Taxa de verdadeiros positivos",
        "multivariate": "Multivariado (Mahalanobis)",
        "univariate": "Melhor canal isolado",
        "operating": "ponto de operação implantado",
        "leadtime_x": "Antecedência sobre a 1ª violação de limite do ICD (min)",
        "trials": "Execuções",
        "mean": "média",
        "min_unit": "min",
        "mahal": "Distância de Mahalanobis ao quadrado",
        "density": "Densidade",
        "nominal": "Telemetria nominal",
        "swapped": "Fase trocada (ataque)",
        "threshold_note": "limiar de detecção\n(q=0,999) = ",
        "rate": "Taxa",
        "baseline_x": "Telemetria limpa usada no ajuste da linha de base (horas)",
        "auc": "AUC",
        "alerts_x": "Hora do dia simulado (UTC)",
        "alerts_y": "Achados (média por execução)",
        "sev_low": "Baixa",
        "sev_medium": "Média",
        "sev_high": "Alta",
        "sev_critical": "Crítica",
    },
}

SCENARIO_LABELS_PT = {
    "credential_compromise": "Compromisso\nde credenciais",
    "command_tampering": "Adulteração\nde comandos",
    "replay": "Reprodução",
    "anomalous_behavior": "Comportamento\nanômalo",
    "exfiltration": "Exfiltração",
}


def scenario_labels(lang: str) -> dict[str, str]:
    return SCENARIO_LABELS if lang == "en" else SCENARIO_LABELS_PT


def suffix(lang: str) -> str:
    return "" if lang == "en" else "_pt"


def decimal(lang: str, text: str) -> str:
    """Portuguese uses a comma as the decimal separator."""
    return text if lang == "en" else text.replace(".", ",")


# --------------------------------------------------------------------------- #
# figures                                                                       #
# --------------------------------------------------------------------------- #

COL_W, FULL_W = 3.4, 7.0  # inches: one column and full width of the template


def _style() -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["DejaVu Serif"],
            "font.size": 8,
            "axes.titlesize": 8,
            "axes.labelsize": 8,
            "legend.fontsize": 7,
            "xtick.labelsize": 7,
            "ytick.labelsize": 7,
            "axes.edgecolor": INK_SOFT,
            "axes.labelcolor": INK,
            "text.color": INK,
            "xtick.color": INK_SOFT,
            "ytick.color": INK_SOFT,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "axes.grid": True,
            "grid.color": GRID,
            "grid.linewidth": 0.5,
            "figure.dpi": 200,
            "savefig.bbox": "tight",
            "savefig.pad_inches": 0.02,
            "pdf.fonttype": 42,
        }
    )


def save(fig, name: str) -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    path = FIG_DIR / name
    fig.savefig(path)
    fig.clf()
    print(f"  figure -> {path.relative_to(ROOT)}")


def figure_ablation(effectiveness: dict[str, Any], lang: str) -> None:
    import matplotlib.pyplot as plt

    L = STRINGS[lang]
    labels = scenario_labels(lang)
    fig, ax = plt.subplots(figsize=(FULL_W, 2.3))
    modes = (
        ("rules", L["rules_only"], BLUE),
        ("ml", L["model_only"], ORANGE),
        ("all", L["rules_model"], AQUA),
    )
    width = 0.26
    positions = np.arange(len(SCENARIOS))

    for offset, (mode, label, color) in enumerate(modes):
        values = [effectiveness[mode]["scenarios"][s]["recall"]["mean"] for s in SCENARIOS]
        errors = [effectiveness[mode]["scenarios"][s]["recall"]["sd"] for s in SCENARIOS]
        bars = ax.bar(
            positions + (offset - 1) * width,
            values,
            width - 0.02,  # surface gap between adjacent bars
            label=label,
            color=color,
            edgecolor="white",
            linewidth=0.6,
        )
        ax.errorbar(
            positions + (offset - 1) * width,
            values,
            yerr=errors,
            fmt="none",
            ecolor=INK_SOFT,
            elinewidth=0.7,
            capsize=1.8,
        )
        # Relief rule: aqua is under 3:1 on white, so every bar carries a label.
        for bar, value in zip(bars, values):
            if value > 0.015:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    value + 0.035,
                    decimal(lang, f"{value:.2f}"),
                    ha="center",
                    va="bottom",
                    fontsize=5.6,
                    color=INK_SOFT,
                )

    ax.set_xticks(positions)
    ax.set_xticklabels([labels[s] for s in SCENARIOS])
    ax.set_ylabel(L["recall"])
    ax.set_ylim(0, 1.16)
    ax.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    ax.grid(axis="x", visible=False)
    ax.legend(frameon=False, ncols=3, loc="upper center", bbox_to_anchor=(0.5, 1.16))
    save(fig, f"ablation{suffix(lang)}.pdf")


def figure_roc(roc_result: dict[str, Any], lang: str) -> None:
    import matplotlib.pyplot as plt

    L = STRINGS[lang]
    reference = roc_result["reference"]
    fig, ax = plt.subplots(figsize=(COL_W, 2.6))

    # Over the full range the two curves overplot each other; the zoom is the
    # only view in which a difference could be seen at all.
    ax.plot([0, 1], [0, 1], linestyle=":", linewidth=0.8, color=GRID, zorder=1)
    for key, label, color, dash in (
        ("mahalanobis", L["multivariate"], BLUE, None),
        ("univariate", L["univariate"], ORANGE, (3, 1.6)),
    ):
        auc = roc_result["auc_" + key]
        text = decimal(lang, f"AUC {auc['mean']:.3f} $\\pm$ {auc['sd']:.3f}")
        line = ax.plot(
            reference[key]["fpr"],
            reference[key]["tpr"],
            linewidth=2.0,
            color=color,
            label=f"{label}\n{text}",
            zorder=3,
        )[0]
        if dash:
            line.set_dashes(dash)  # secondary encoding for print and CVD

    point = reference["operating_point"]
    ax.plot(
        point["fpr"],
        point["tpr"],
        marker="o",
        markersize=5,
        color=BLUE,
        markeredgecolor="white",
        markeredgewidth=1.4,  # surface ring
        zorder=4,
        linestyle="none",
    )
    ax.annotate(
        L["operating"]
        + decimal(lang, f"\nq=0.999  ({point['fpr']:.3f}, {point['tpr']:.2f})"),
        xy=(point["fpr"], point["tpr"]),
        xytext=(0.009, 0.949),
        ha="left",
        fontsize=6,
        color=INK_SOFT,
        arrowprops={"arrowstyle": "-", "linewidth": 0.6, "color": INK_SOFT},
    )

    ax.set_xlabel(L["fpr"])
    ax.set_ylabel(L["tpr"])
    ax.set_xlim(-0.002, 0.055)
    ax.set_ylim(0.90, 1.004)
    ax.legend(frameon=False, loc="lower right", fontsize=6.2)
    save(fig, f"roc{suffix(lang)}.pdf")


def figure_lead_time(lead: dict[str, Any], lang: str) -> None:
    import matplotlib.pyplot as plt

    L = STRINGS[lang]
    samples = lead["samples"]
    fig, ax = plt.subplots(figsize=(COL_W, 2.0))
    ax.hist(
        samples,
        bins=min(12, max(4, len(samples) // 2)),
        color=BLUE,
        edgecolor="white",
        linewidth=0.7,
    )
    mean = lead["lead_minutes"]["mean"]
    ax.axvline(mean, color=ORANGE, linewidth=1.6)
    ax.annotate(
        f"{L['mean']} {mean:.0f} {L['min_unit']}",
        xy=(mean, ax.get_ylim()[1] * 0.99),
        xytext=(4, -4),
        textcoords="offset points",
        fontsize=6.5,
        color=ORANGE,
        va="top",
    )
    ax.set_xlabel(L["leadtime_x"])
    ax.set_ylabel(L["trials"])
    ax.grid(axis="x", visible=False)
    save(fig, f"leadtime{suffix(lang)}.pdf")


def figure_baseline(sensitivity: dict[str, Any], lang: str) -> None:
    """Two panels sharing one x axis -- never two y scales on one plot."""
    import matplotlib.pyplot as plt

    L = STRINGS[lang]
    rows = sensitivity["rows"]
    positions = np.arange(len(rows))  # ordinal sweep: equal spacing, no crowding

    fig, (top, bottom) = plt.subplots(
        2, 1, figsize=(COL_W, 3.0), sharex=True, gridspec_kw={"height_ratios": [1.25, 1]}
    )

    top.plot(
        positions,
        [r["fpr"] for r in rows],
        linewidth=2.0,
        color=ORANGE,
        marker="^",
        markersize=4.5,
        markeredgecolor="white",
        markeredgewidth=0.9,
    )
    for x, row in zip(positions, rows):
        if row["hours"] in (1, 16, 20, 24):
            top.annotate(
                decimal(lang, f"{row['fpr'] * 100:.1f}%"),
                xy=(x, row["fpr"]),
                xytext=(0, 5),
                textcoords="offset points",
                ha="center",
                fontsize=6,
                color=INK_SOFT,
            )
    top.set_ylabel(L["fpr"])
    top.set_ylim(-0.05, 0.95)
    top.grid(axis="x", visible=False)

    for key, label, color, dash, marker in (
        ("auc", L["auc"], BLUE, None, "o"),
        ("tpr", L["tpr"], AQUA, (4, 1.5), "s"),
    ):
        line = bottom.plot(
            positions,
            [r[key] for r in rows],
            linewidth=2.0,
            color=color,
            marker=marker,
            markersize=4,
            markeredgecolor="white",
            markeredgewidth=0.9,
            label=label,
        )[0]
        if dash:
            line.set_dashes(dash)
    bottom.set_ylabel(L["rate"])
    bottom.set_ylim(0.955, 1.008)
    bottom.set_xticks(positions)
    bottom.set_xticklabels([str(r["hours"]) for r in rows])
    bottom.set_xlabel(L["baseline_x"])
    bottom.grid(axis="x", visible=False)
    bottom.legend(frameon=False, fontsize=6.4, loc="lower left", ncols=2)

    fig.align_ylabels([top, bottom])
    save(fig, f"baseline{suffix(lang)}.pdf")


def figure_phase_swap(probe: dict[str, Any], lang: str) -> None:
    """Score distributions: the swapped vectors sit *inside* the normal cloud."""
    import matplotlib.pyplot as plt

    L = STRINGS[lang]
    reference = probe["reference"]
    normal = np.array(reference["scores_normal"])
    swapped = np.array(reference["scores_swapped"])
    threshold = reference["threshold"]

    fig, ax = plt.subplots(figsize=(COL_W, 2.3))
    upper = max(threshold * 1.25, float(np.percentile(normal, 99.5)))
    bins = np.linspace(0, upper, 40)

    ax.hist(
        normal,
        bins=bins,
        density=True,
        color=BLUE,
        edgecolor="white",
        linewidth=0.4,
        label=L["nominal"],
    )
    ax.hist(
        swapped,
        bins=bins,
        density=True,
        histtype="step",
        linewidth=2.0,
        color=ORANGE,
        label=L["swapped"],
        hatch="///",  # texture: survives grayscale printing
    )
    ax.axvline(threshold, color=INK, linewidth=1.2, linestyle=(0, (4, 2)))
    ax.annotate(
        decimal(lang, L["threshold_note"]) + f"{threshold:.0f}",
        xy=(threshold, ax.get_ylim()[1] * 0.45),
        xytext=(-6, 0),
        textcoords="offset points",
        ha="right",
        fontsize=6,
        color=INK_SOFT,
    )
    ax.set_xlabel(L["mahal"])
    ax.set_ylabel(L["density"])
    ax.set_xlim(0, upper)
    ax.grid(axis="x", visible=False)
    ax.legend(frameon=False, fontsize=6.4, loc="upper right")
    save(fig, f"phaseswap{suffix(lang)}.pdf")


def figure_alert_volume(volume: dict[str, Any], lang: str) -> None:
    import matplotlib.pyplot as plt

    L = STRINGS[lang]
    hours = np.arange(volume["hours"])
    fig, ax = plt.subplots(figsize=(FULL_W, 2.1))
    bottom = np.zeros(len(hours))

    for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        values = np.array(volume["per_hour_mean"][severity])
        ax.bar(
            hours,
            values,
            0.82,
            bottom=bottom,
            label=L[f"sev_{severity.lower()}"],
            color=SEVERITY_RAMP[severity],
            edgecolor="white",
            linewidth=0.5,  # surface gap between stacked segments
        )
        bottom += values

    ax.set_xlabel(L["alerts_x"])
    ax.set_ylabel(L["alerts_y"])
    ax.set_xticks(hours[::2])
    ax.grid(axis="x", visible=False)
    ax.legend(frameon=False, ncols=4, loc="upper center", bbox_to_anchor=(0.5, 1.2))
    save(fig, f"alerts{suffix(lang)}.pdf")


def render_figures(results: dict[str, Any], lang: str) -> None:
    figure_ablation(results["effectiveness"], lang)
    figure_roc(results["roc"], lang)
    figure_lead_time(results["lead_time"], lang)
    figure_phase_swap(results["phase_swap"], lang)
    figure_baseline(results["baseline_sensitivity"], lang)
    figure_alert_volume(results["alert_volume"], lang)


# --------------------------------------------------------------------------- #
# LaTeX macros                                                                  #
# --------------------------------------------------------------------------- #


def write_macros(results: dict[str, Any]) -> None:
    """Emit \\newcommand definitions so no manuscript hardcodes a number."""
    eff = results["effectiveness"]["all"]
    dataset = results["dataset"]
    roc_result = results["roc"]
    lead = results["lead_time"]
    tp = results["throughput"]

    macros: dict[str, str] = {
        "NumSeeds": str(results["config"]["seeds"]),
        "SimHours": f"{dataset['minutes'] // 60}",
        "EventsTotal": f"{dataset['events_total']}",
        "BenignEvents": f"{dataset['benign_events']}",
        "TelemetryEvents": f"{dataset['events_by_type'].get('telemetry', 0)}",
        "CommandEvents": f"{dataset['events_by_type'].get('telecommand', 0)}",
        "AuditEvents": f"{dataset['events_by_type'].get('audit', 0)}",
        "DownlinkEvents": f"{dataset['events_by_type'].get('downlink', 0)}",
        "Precision": f"{eff['precision']['mean']:.3f}",
        "PrecisionSD": f"{eff['precision']['sd']:.3f}",
        "FprOverall": f"{eff['false_positive_rate']['mean'] * 100:.2f}",
        "FindingsMean": f"{eff['findings']['mean']:.0f}",
        "AucMulti": f"{roc_result['auc_mahalanobis']['mean']:.3f}",
        "AucMultiSD": f"{roc_result['auc_mahalanobis']['sd']:.3f}",
        "AucUni": f"{roc_result['auc_univariate']['mean']:.3f}",
        "AucUniSD": f"{roc_result['auc_univariate']['sd']:.3f}",
        "LeadMean": f"{lead['lead_minutes']['mean']:.0f}",
        "LeadSD": f"{lead['lead_minutes']['sd']:.0f}",
        "LeadMin": f"{lead['lead_minutes']['min']:.0f}",
        "LeadMax": f"{lead['lead_minutes']['max']:.0f}",
        "ThroughputRules": f"{tp['rules']['events_per_second']:,.0f}".replace(",", "\\,"),
        "ThroughputMl": f"{tp['rules+ml']['events_per_second']:,.0f}".replace(",", "\\,"),
        "UsPerEventMl": f"{tp['rules+ml']['microseconds_per_event']:.1f}",
        "FitSeconds": f"{tp['model_fit']['seconds']['mean']:.2f}",
        "ModelKb": f"{tp['model_fit']['model_bytes'] / 1024:.1f}",
        "RuleCount": str(results["config"]["rule_count"]),
        "AucSwapMulti": f"{results['phase_swap']['auc_mahalanobis']['mean']:.3f}",
        "AucSwapMultiSD": f"{results['phase_swap']['auc_mahalanobis']['sd']:.3f}",
        "AucSwapUni": f"{results['phase_swap']['auc_univariate']['mean']:.3f}",
        "AucSwapUniSD": f"{results['phase_swap']['auc_univariate']['sd']:.3f}",
        "SwapDetectedMulti": str(results["phase_swap"]["trials_detected"]["mahalanobis"]),
        "SwapDetectedUni": str(results["phase_swap"]["trials_detected"]["univariate"]),
        "SwapMedianNormal": f"{results['phase_swap']['reference']['median_normal']:.1f}",
        "SwapMedianSwapped": f"{results['phase_swap']['reference']['median_swapped']:.1f}",
        "SwapWindowMin": f"{results['phase_swap']['window_samples'] // 2}",
        "AucBaselineMin": f"{results['baseline_sensitivity']['rows'][0]['auc']:.3f}",
        "AucBaselineMax": f"{results['baseline_sensitivity']['rows'][-1]['auc']:.3f}",
        "RecAnomalyRules": (
            f"{results['effectiveness']['rules']['scenarios']['anomalous_behavior']['recall']['mean']:.2f}"
        ),
        "MttdAnomalyRules": (
            f"{results['effectiveness']['rules']['scenarios']['anomalous_behavior']['mttd_s']['mean'] / 60:.0f}"
        ),
        "MttdAnomalyAll": (
            f"{results['effectiveness']['all']['scenarios']['anomalous_behavior']['mttd_s']['mean'] / 60:.0f}"
        ),
        "PrecisionRules": f"{results['effectiveness']['rules']['precision']['mean']:.3f}",
        "PrecisionMl": f"{results['effectiveness']['ml']['precision']['mean']:.3f}",
        "FprOneHour": f"{results['baseline_sensitivity']['rows'][0]['fpr'] * 100:.0f}",
        "FprFullDay": f"{results['baseline_sensitivity']['rows'][-1]['fpr'] * 100:.1f}",
        "FprTelemetryOp": f"{results['roc']['reference']['operating_point']['fpr'] * 100:.1f}",
        "AlertPeakHour": f"{max(sum(v) for v in zip(*results['alert_volume']['per_hour_mean'].values())):.0f}",
        "CriticalPerDay": f"{results['alert_volume']['per_severity_total']['CRITICAL']['mean']:.0f}",
        "FpAuthPerTrial": f"{results['false_positives'].get('GS-AUTH-005', {}).get('mean_per_trial', 0):.2f}",
        "FpRatePerTrial": f"{results['false_positives'].get('GS-CMD-004', {}).get('mean_per_trial', 0):.2f}",
    }

    for name in SCENARIOS:
        key = "".join(part.capitalize() for part in name.split("_"))
        scenario = eff["scenarios"][name]
        macros[f"Rec{key}"] = f"{scenario['recall']['mean']:.2f}"
        macros[f"RecSD{key}"] = f"{scenario['recall']['sd']:.2f}"
        macros[f"Det{key}"] = f"{scenario['detection_rate'] * 100:.0f}"
        macros[f"Mttd{key}"] = f"{scenario['mttd_s']['mean']:.0f}"

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for lang in ("en", "pt"):
        lines = [
            "% Generated by paper/experiments.py -- do not edit by hand.",
            f"% {results['config']['generated_at']}",
            "",
        ]
        for name, value in macros.items():
            rendered = value if lang == "en" else decimal(lang, value)
            lines.append(f"\\newcommand{{\\exp{name}}}{{{rendered}}}")
        path = DATA_DIR / f"macros{suffix(lang)}.tex"
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"  macros -> {path.relative_to(ROOT)} ({len(macros)} values)")


# --------------------------------------------------------------------------- #
# tables                                                                       #
# --------------------------------------------------------------------------- #

TEX_SCENARIO = {name: "\\texttt{" + name.replace("_", "\\_") + "}" for name in SCENARIOS}

TABLE_STRINGS = {
    "en": {
        "corpus_caption": (
            "One {hours}-hour corpus: events by plane, and events carrying each "
            "attack label. Labelled events overlap the planes they occur in."
        ),
        "events": "Events",
        "plane": "Evidence plane",
        "label": "Attack label",
        "benign": "Benign",
        "total": "Total",
        "eff_caption": (
            "Effectiveness over {seeds} independent trials. Detection rate is the "
            "percentage of trials in which the scenario produced at least one "
            "finding; recall is per labelled event. The last two columns give "
            "recall for the ablated configurations."
        ),
        "scenario": "Scenario",
        "det": "Det.",
        "recall": "Recall",
        "recall_ablated": "Recall (ablated)",
        "rules": "rules",
        "model": "model",
        "rules_model": "rules\\,+\\,model",
        "mttd": "MTTD",
        "precision_line": "Precision (rules\\,+\\,model)",
        "fp_line": "False positives",
        "of_benign": "of benign events",
        "base_caption": (
            "Baseline-size sensitivity at the deployed operating point "
            "($q = 0.999$). Discrimination (AUC) barely moves; the false-positive "
            "rate collapses only once the training window covers a full diurnal "
            "cycle."
        ),
        "hours": "Hours",
        "samples": "Samples",
        "cost_caption": (
            "Single-core detection cost, best of {repeats} runs over a {hours}-hour "
            "corpus of {events} events."
        ),
        "config": "Configuration",
        "eps": "Events/s",
        "us": "$\\mu$s/event",
        "rules_only": "Rules only",
        "rules_plus": "Rules $+$ model",
        "fit_line": "Baseline fit",
        "on_samples": "samples",
        "model_line": "Serialised model",
    },
    "pt": {
        "corpus_caption": (
            "Um corpus de {hours}~horas: eventos por plano de evidência e eventos "
            "que carregam cada rótulo de ataque. Eventos rotulados se sobrepõem "
            "aos planos em que ocorrem."
        ),
        "events": "Eventos",
        "plane": "Plano de evidência",
        "label": "Rótulo de ataque",
        "benign": "Benignos",
        "total": "Total",
        "eff_caption": (
            "Eficácia ao longo de {seeds} execuções independentes. A taxa de "
            "detecção é o percentual de execuções em que o cenário produziu ao "
            "menos um achado; a revocação é por evento rotulado. As duas últimas "
            "colunas dão a revocação das configurações ablacionadas."
        ),
        "scenario": "Cenário",
        "det": "Det.",
        "recall": "Revocação",
        "recall_ablated": "Revocação (ablação)",
        "rules": "regras",
        "model": "modelo",
        "rules_model": "regras\\,+\\,modelo",
        "mttd": "TMD",
        "precision_line": "Precisão (regras\\,+\\,modelo)",
        "fp_line": "Falsos positivos",
        "of_benign": "dos eventos benignos",
        "base_caption": (
            "Sensibilidade ao tamanho da linha de base no ponto de operação "
            "implantado ($q = 0{,}999$). A discriminação (AUC) quase não muda; a "
            "taxa de falsos positivos só desaba quando a janela de treino cobre um "
            "ciclo diurno completo."
        ),
        "hours": "Horas",
        "samples": "Amostras",
        "cost_caption": (
            "Custo de detecção em um núcleo, melhor de {repeats} execuções sobre um "
            "corpus de {hours}~horas com {events} eventos."
        ),
        "config": "Configuração",
        "eps": "Eventos/s",
        "us": "$\\mu$s/evento",
        "rules_only": "Apenas regras",
        "rules_plus": "Regras $+$ modelo",
        "fit_line": "Ajuste da linha de base",
        "on_samples": "amostras",
        "model_line": "Modelo serializado",
    },
}


def write_table(name: str, body: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / name).write_text(
        "% Generated by paper/experiments.py -- do not edit by hand.\n" + body, encoding="utf-8"
    )
    print(f"  table  -> {(DATA_DIR / name).relative_to(ROOT)}")


def table_corpus(results: dict[str, Any], lang: str) -> None:
    T = TABLE_STRINGS[lang]
    dataset = results["dataset"]
    total = dataset["events_total"]

    def pct(count: int) -> str:
        return decimal(lang, f"{count / total * 100:.1f}")

    rows = [
        f"\\texttt{{{plane}}} & {dataset['events_by_type'].get(plane, 0)} & "
        f"{pct(dataset['events_by_type'].get(plane, 0))} \\\\"
        for plane in ("telemetry", "telecommand", "audit", "downlink")
    ]
    attacks = [
        f"{TEX_SCENARIO[name]} & {dataset['events_by_attack'].get(name, 0)} & "
        f"{pct(dataset['events_by_attack'].get(name, 0))} \\\\"
        for name in SCENARIOS
    ]
    caption = T["corpus_caption"].format(hours=dataset["minutes"] // 60)
    body = f"""\\begin{{table}}[t]
\\caption{{{caption}}}
\\label{{tab:corpus}}
\\centering
\\begin{{tabular}}{{@{{}}lrr@{{}}}}
\\toprule
 & \\textbf{{{T['events']}}} & \\textbf{{\\%}} \\\\
\\midrule
\\multicolumn{{3}}{{@{{}}l}}{{\\emph{{{T['plane']}}}}} \\\\
{chr(10).join(rows)}
\\midrule
\\multicolumn{{3}}{{@{{}}l}}{{\\emph{{{T['label']}}}}} \\\\
{chr(10).join(attacks)}
\\midrule
{T['benign']} & {dataset['benign_events']} & {pct(dataset['benign_events'])} \\\\
\\textbf{{{T['total']}}} & \\textbf{{{total}}} & \\textbf{{{decimal(lang, '100.0')}}} \\\\
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
    write_table(f"table_corpus{suffix(lang)}.tex", body)


def table_effectiveness(results: dict[str, Any], lang: str) -> None:
    T = TABLE_STRINGS[lang]
    eff = results["effectiveness"]
    rows = []
    for name in SCENARIOS:
        combined = eff["all"]["scenarios"][name]
        rules = eff["rules"]["scenarios"][name]
        model = eff["ml"]["scenarios"][name]
        mttd = combined["mttd_s"]["mean"]
        rows.append(
            f"{TEX_SCENARIO[name]} & {combined['detection_rate'] * 100:.0f} & "
            + decimal(
                lang,
                f"${combined['recall']['mean']:.2f} \\pm {combined['recall']['sd']:.2f}$ & "
                f"{rules['recall']['mean']:.2f} & {model['recall']['mean']:.2f} & ",
            )
            + ("0" if mttd < 1 else f"{mttd:.0f}")
            + " \\\\"
        )
    caption = T["eff_caption"].format(seeds=results["config"]["seeds"])
    precision = decimal(
        lang,
        f"${eff['all']['precision']['mean']:.3f} \\pm {eff['all']['precision']['sd']:.3f}$",
    )
    fpr = decimal(lang, f"{eff['all']['false_positive_rate']['mean'] * 100:.2f}")
    body = f"""\\begin{{table}}[t]
\\caption{{{caption}}}
\\label{{tab:effectiveness}}
\\centering
\\begin{{tabular}}{{@{{}}lrcrrr@{{}}}}
\\toprule
 & \\textbf{{{T['det']}}} & \\textbf{{{T['recall']}}} & \\multicolumn{{2}}{{c}}{{\\textbf{{{T['recall_ablated']}}}}} & \\textbf{{{T['mttd']}}} \\\\
\\cmidrule(lr){{4-5}}
\\textbf{{{T['scenario']}}} & \\textbf{{\\%}} & \\textbf{{{T['rules_model']}}} & \\textbf{{{T['rules']}}} & \\textbf{{{T['model']}}} & \\textbf{{(s)}} \\\\
\\midrule
{chr(10).join(rows)}
\\midrule
\\multicolumn{{6}}{{@{{}}l}}{{{T['precision_line']}: {precision}}} \\\\
\\multicolumn{{6}}{{@{{}}l}}{{{T['fp_line']}: {fpr}\\% {T['of_benign']}}} \\\\
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
    write_table(f"table_effectiveness{suffix(lang)}.tex", body)


def table_baseline(results: dict[str, Any], lang: str) -> None:
    T = TABLE_STRINGS[lang]
    rows = [
        f"{row['hours']} & {row['samples']} & "
        + decimal(
            lang,
            f"{row['threshold']:.1f} & {row['auc']:.4f} & {row['tpr']:.3f} & "
            f"{row['fpr'] * 100:.1f}",
        )
        + " \\\\"
        for row in results["baseline_sensitivity"]["rows"]
    ]
    body = f"""\\begin{{table}}[t]
\\caption{{{T['base_caption']}}}
\\label{{tab:baseline}}
\\centering
\\begin{{tabular}}{{@{{}}rrrrrr@{{}}}}
\\toprule
\\textbf{{{T['hours']}}} & \\textbf{{{T['samples']}}} & \\textbf{{$\\tau$}} & \\textbf{{AUC}} & \\textbf{{TPR}} & \\textbf{{FPR (\\%)}} \\\\
\\midrule
{chr(10).join(rows)}
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
    write_table(f"table_baseline{suffix(lang)}.tex", body)


def table_cost(results: dict[str, Any], lang: str) -> None:
    T = TABLE_STRINGS[lang]
    tp = results["throughput"]
    caption = T["cost_caption"].format(
        repeats=tp["rules"]["seconds"]["n"],
        hours=results["dataset"]["minutes"] // 60,
        events=tp["rules"]["events"],
    )

    def thousands(value: float) -> str:
        return f"{value:,.0f}".replace(",", "\\,")

    body = f"""\\begin{{table}}[t]
\\caption{{{caption}}}
\\label{{tab:cost}}
\\centering
\\begin{{tabular}}{{@{{}}lrr@{{}}}}
\\toprule
\\textbf{{{T['config']}}} & \\textbf{{{T['eps']}}} & \\textbf{{{T['us']}}} \\\\
\\midrule
{T['rules_only']} & {thousands(tp['rules']['events_per_second'])} & \
{decimal(lang, f"{tp['rules']['microseconds_per_event']:.1f}")} \\\\
{T['rules_plus']} & {thousands(tp['rules+ml']['events_per_second'])} & \
{decimal(lang, f"{tp['rules+ml']['microseconds_per_event']:.1f}")} \\\\
\\midrule
\\multicolumn{{3}}{{@{{}}l}}{{{T['fit_line']}: \
{decimal(lang, f"{tp['model_fit']['seconds']['mean']:.3f}")}\\,s, \
{tp['model_fit']['samples']} {T['on_samples']}}} \\\\
\\multicolumn{{3}}{{@{{}}l}}{{{T['model_line']}: \
{decimal(lang, f"{tp['model_fit']['model_bytes'] / 1024:.1f}")}\\,KB}} \\\\
\\bottomrule
\\end{{tabular}}
\\end{{table}}
"""
    write_table(f"table_cost{suffix(lang)}.tex", body)


def render_tables(results: dict[str, Any], lang: str) -> None:
    table_corpus(results, lang)
    table_effectiveness(results, lang)
    table_baseline(results, lang)
    table_cost(results, lang)


# --------------------------------------------------------------------------- #
# driver                                                                       #
# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--minutes", type=int, default=24 * 60)
    parser.add_argument("--no-figures", action="store_true")
    parser.add_argument("--langs", nargs="+", default=["en", "pt"], choices=["en", "pt"])
    args = parser.parse_args(argv)

    from gsd.detection.engine import load_rules

    print(f"running {args.seeds} trials of {args.minutes} simulated minutes")
    started = time.perf_counter()
    trials = []
    for seed in range(1, args.seeds + 1):
        trials.append(trial(seed, args.minutes))
        print(f"  trial {seed}/{args.seeds}", end="\r", flush=True)
    print(f"  {args.seeds} trials in {time.perf_counter() - started:.1f}s")

    results: dict[str, Any] = {
        "config": {
            "seeds": args.seeds,
            "minutes": args.minutes,
            "rule_count": len(load_rules()["rules"]),
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "python": platform.python_version(),
            "numpy": np.__version__,
            "platform": platform.platform(),
        },
        "dataset": experiment_dataset(args.minutes),
        "effectiveness": experiment_effectiveness(trials),
        "roc": experiment_roc(trials),
        "phase_swap": experiment_phase_swap(args.minutes, args.seeds),
        "false_positives": experiment_false_positives(trials),
        "lead_time": experiment_lead_time(trials),
        "baseline_sensitivity": experiment_baseline_size(args.minutes),
        "throughput": experiment_throughput(args.minutes),
        "alert_volume": experiment_alert_volume(trials, args.minutes),
    }

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    (DATA_DIR / "results.json").write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"  results -> {(DATA_DIR / 'results.json').relative_to(ROOT)}")

    write_macros(results)
    for lang in args.langs:
        render_tables(results, lang)

    if not args.no_figures:
        _style()
        for lang in args.langs:
            render_figures(results, lang)

    print(f"done in {time.perf_counter() - started:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
