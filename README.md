# Cloud-Native Detection of Cyberattacks Against Satellite Ground Stations

A simulated satellite ground station, five emulated attack scenarios, and a
cloud-native detection pipeline that finds them — running end to end offline on
a laptop, and deployable to AWS with Terraform.

**📄 Paper:** [`paper/main.pdf`](paper/main.pdf) (English) ·
[`paper/main-pt.pdf`](paper/main-pt.pdf) (português) — *An Open, Labelled
Testbed and Two Negative Results.* Every number and figure in it is regenerated
by `make paper-experiments`.

The ground segment is the soft underbelly of a space mission: the spacecraft is
hard to reach, but the station that commands it is an ordinary cloud workload
with operators, credentials, APIs and buckets. This project makes that attack
surface concrete and measurable.

```
 simulator            transport              detection                response
┌───────────┐      ┌──────────────┐      ┌────────────────┐      ┌──────────────┐
│ telemetry │      │   Kinesis    │      │ rules engine   │      │ Security Hub │
│ telecmds  ├─────▶│   CloudWatch ├─────▶│ + Mahalanobis  ├─────▶│ CloudWatch   │
│ audit     │      │   Firehose→S3│      │   baseline     │      │ SNS / alarms │
│ downlink  │      └──────────────┘      └────────────────┘      └──────────────┘
└───────────┘             ▲                       ▲
                          │                       │
                     CloudTrail             GuardDuty findings
```

## Quickstart

```bash
python -m pip install -e ".[dev]"
make demo
```

```
events        : 3605
findings      : 612
precision     : 0.998
false positives: 1 over 3132 benign events

scenario                  detected   recall     MTTD  rules
anomalous_behavior             yes     0.96     240s  GS-TLM-001, GS-TLM-002
command_tampering              yes     1.00       0s  GS-CMD-001, GS-CMD-002, GS-CMD-003, GS-CMD-004, GS-CMD-005, GS-CMD-006
credential_compromise          yes     0.82      18s  GS-AUTH-001, GS-AUTH-002, GS-AUTH-003, GS-AUTH-004, GS-AUTH-006, GS-CMD-002, GS-CMD-005, GS-CMD-006
exfiltration                   yes     1.00       0s  GS-AUTH-001, GS-EXF-001, GS-EXF-002, GS-EXF-003
replay                         yes     1.00       0s  GS-CMD-006, GS-RPL-001, GS-RPL-002, GS-RPL-003
```

Or step by step, writing artefacts to `data/`:

```bash
make pipeline     # baseline -> model -> attacked run -> findings -> evaluation -> ASFF
```

## What is simulated

One ground station (`SENTINEL-GS`) operating one spacecraft (`SENTINEL-3X`) in a
95-minute LEO orbit. Four planes of evidence are produced as a single JSONL
event stream:

| Plane | Contents | Real-world counterpart |
|---|---|---|
| `telemetry` | bus voltage/current, battery SoC, PA and battery temperature, link SNR/BER, slew rate | spacecraft housekeeping downlink |
| `telecommand` | opcode, APID, params, sequence counter, HMAC, operator, source IP | CCSDS TC frames authenticated with SDLS |
| `audit` | `eventName`, `userIdentity`, `sourceIPAddress`, MFA state, outcome | CloudTrail management + data events |
| `downlink` | product size, object count, destination, protocol | payload data transfer to the mission archive |

The spacecraft model is small but *correlated*: illumination drives the power
budget, the power budget drives temperatures, and transmit duty drives the
amplifier. That coupling is what lets a multivariate detector notice an attack
whose individual channels are all still legal.

## Attack scenarios

Each scenario is mapped to SPARTA (space) and ATT&CK (enterprise) and labels the
events it injects, so detections can be scored rather than eyeballed.

| Scenario | What the adversary does | Primary detections |
|---|---|---|
| `credential_compromise` | password spray, MFA-less sign-in from an untrusted netblock at 03:00Z, new access key, `AdministratorAccess` attached, CloudTrail disabled | GS-AUTH-001…006 |
| `command_tampering` | rewrites opcode/params in flight, forges a MAC with the wrong key, issues an out-of-role command, floods the uplink | GS-CMD-001…006 |
| `replay` | retransmits captured frames verbatim hours later — the MAC still verifies | GS-RPL-001…003 |
| `anomalous_behavior` | post-tampering drift: current up, amplifier hot, link degraded — every channel still inside its ICD limit | GS-TLM-002, then GS-TLM-001 |
| `exfiltration` | enumerates the archive, bulk-reads 6 GB, copies it to an unapproved bucket at 03:00Z | GS-EXF-001…004 |

## Detection layer

21 rules in [`src/gsd/detection/rules.yaml`](src/gsd/detection/rules.yaml)
(thresholds and severities are data, logic is code) plus one unsupervised model:

* **Deterministic rules** — identity, commanding integrity, replay, ICD limits,
  exfiltration. Each carries a severity, an ATT&CK technique and a remediation.
* **Telemetry baseline** — robust (median/MAD) centring, shrunk covariance,
  squared Mahalanobis distance, threshold at the 99.9th percentile of a clean
  run. numpy only, serialises to JSON, loads inside Lambda without a SciPy
  layer. It flags the drift **before** any red line is crossed.
* **Replay memory** — the one piece of state that must be globally consistent
  lives behind an interface: a dict offline, a DynamoDB table with TTL and
  conditional writes in the cloud.

Findings are emitted in the AWS Security Finding Format, so `BatchImportFindings`
puts them in the same Security Hub queue as GuardDuty and the FSBP standard.

## Deploying to AWS

```bash
./infra/build_layer.sh                       # bundles gsd + numpy for Lambda
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars # set region, station, alert email
terraform init && terraform apply

# upload the baseline model the detector Lambda reads at cold start
aws s3 cp ../../models/telemetry.json "s3://$(terraform output -raw model_bucket)/models/telemetry.json"

# feed the deployed pipeline -- note the relative start: CloudWatch Logs rejects
# events older than 14 days, and Firehose partitions S3 by the event's own date
gsd simulate --start 24h --sink kinesis:$(terraform output -raw event_stream_name)
```

Terraform provisions: Kinesis + Firehose → S3 archive, the detector Lambda
(least-privilege role, no wildcard resources), the GuardDuty correlator behind
an EventBridge rule, a DynamoDB replay table, CloudTrail with S3 data events,
GuardDuty, Security Hub with FSBP, CloudWatch alarms (critical finding,
telemetry gap, detector errors), an SNS topic and a dashboard.

## Testing

```bash
make test              # 29 offline unit tests
make integration       # 8 tests against emulated AWS (moto): Kinesis batching,
                       # both Lambda envelopes, DynamoDB replay memory, ASFF
make demo              # the detection scorecard, which CI gates on
make paper-experiments # the full 20-trial evaluation behind the paper
```

The integration suite exists because a class of bugs only appears on the cloud
path — partial-batch failures, log-event rejection, state that has to survive a
cold start. It runs in-process with no credentials and no network.

## Paper

The evaluation is written up as a conference-format paper in [`paper/`](paper/),
in English and Portuguese. Its headline results over 20 independent trials:

| | |
|---|---|
| All five scenarios detected | in 20/20 trials, precision 0.997 ± 0.002 |
| False positives | 0.06% of benign events, concentrated in two named rules |
| Learned baseline vs. spacecraft limits | fires 42 ± 2 min earlier |
| Multivariate vs. best single channel | AUC 0.996 vs 0.998 — **no advantage** |
| Phase-swap probe (replayed telemetry) | AUC 0.32 — **below chance, both detectors** |
| Baseline shorter than one diurnal cycle | telemetry FPR 0.2% → 77% |
| Cost | ~9.5 µs/event single core, 1.5 KB model |

The last three are the interesting ones, and two of them contradict the design
rationale this project started from. The rules — not the model — carry the
high-impact scenarios; the model earns its place on exactly one of the five; and
an adversary who replays valid telemetry from a different orbit phase hides
*inside* the learned baseline and drives its anomaly score down. That last
failure is structural to any phase-marginal baseline, and
[the probe that finds it](paper/experiments.py) is a few lines long.

## Documentation

* [`paper/README.md`](paper/README.md) — the paper, the experiment harness, how to rebuild both PDFs
* [`docs/architecture.md`](docs/architecture.md) — components, data flow, why each AWS service is there
* [`docs/threat-model.md`](docs/threat-model.md) — assets, adversaries, attack paths, SPARTA/ATT&CK mapping
* [`docs/detections.md`](docs/detections.md) — the rule catalogue in detail, with evasion notes
* [`docs/runbook.md`](docs/runbook.md) — what to do when each finding fires
* [`docs/roadmap.md`](docs/roadmap.md) — what is deliberately not built yet

## Repository layout

```
paper/               the manuscript (en/pt), figures, and the experiment harness
src/gsd/simulator/   ground station: spacecraft model, commanding, identity, downlink
src/gsd/attacks/     five adversary-emulation scenarios
src/gsd/detection/   rules engine, baseline model, ASFF mapping, evaluation
src/gsd/emit/        stdout / file / CloudWatch Logs / Kinesis sinks
infra/lambda/        detector and GuardDuty-correlator handlers
infra/terraform/     the AWS deployment
tests/               unit tests plus the detection scorecard
```

## Scope and honesty

This is a lab. The MAC scheme stands in for CCSDS SDLS, the keys are hard-coded
lab constants, the orbit model is a sine wave, and the "attacks" are injected
into a synthetic timeline rather than executed against real infrastructure. The
detection logic, the AWS wiring and the evaluation methodology are the parts
meant to survive contact with reality.

**Verification status.** The Python pipeline and the cloud-path code are tested
(37 tests, including the emulated-AWS suite), and the paper's claims are
regenerated from the code on every build. The Terraform is
`fmt`-clean and reviewed, but has **not** been `terraform validate`d or applied
against a live account — treat the first `apply` as a review step, and expect to
pay for GuardDuty, Security Hub and CloudTrail data events while it is up.
