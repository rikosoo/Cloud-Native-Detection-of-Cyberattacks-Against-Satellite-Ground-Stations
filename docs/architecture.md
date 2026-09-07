# Architecture

## Design constraints

1. **One engine, three runtimes.** The exact same `DetectionEngine` runs in the
   CLI, in the test suite and inside Lambda. Nothing in `src/gsd/detection`
   imports boto3; AWS lives behind sinks and a state interface.
2. **Offline first.** The full pipeline runs with numpy and PyYAML only. AWS is
   a deployment target, not a prerequisite for development or grading.
3. **Measured, not asserted.** Every injected event is labelled, so precision,
   recall and mean time to detect are computed rather than claimed.

## Data flow

```
                      ┌──────────────────────────────────────────┐
                      │            gsd simulate                  │
                      │  spacecraft model + 3 ground-segment      │
                      │  planes + attack injectors               │
                      └───────────────┬──────────────────────────┘
                                      │ JSONL events
             ┌────────────────────────┼────────────────────────┐
             ▼                        ▼                        ▼
     file:data/events.jsonl   kinesis:<stream>        cloudwatch:<group>/<stream>
             │                        │                        │
             │                        ▼                        │
             │             ┌──────────────────────┐            │
             │             │ Firehose → S3 raw    │            │
             │             │ archive (GZIP, tiered│            │
             │             │ to Glacier)          │            │
             │             └──────────────────────┘            │
             │                        │                        │
             │                        ▼                        ▼
             │             ┌──────────────────────────────────────┐
             └────────────▶│         detector Lambda              │
                           │  DetectionEngine(model, DynamoDB)    │
                           └───────────────┬──────────────────────┘
                                           │ ASFF
                                           ▼
                              ┌────────────────────────┐
     GuardDuty ──EventBridge──▶│      Security Hub      │
     (enriched by the          └───────────┬────────────┘
      correlator Lambda)                   │
                                           ▼
                              CloudWatch alarms → SNS → on-call
```

## Components

### Simulator (`src/gsd/simulator`)

`GroundStation.run()` advances a `SpacecraftState` at 30-second cadence and, at
each step, decides whether the spacecraft is in a contact window (11 minutes out
of every 95). Inside a window it transmits, operators issue telecommands, and
the pass ends with a payload downlink. Outside it, the payload collects and the
bus recharges. Shift handovers produce console sign-ins; service identities
federate through `AssumeRole` instead.

The bus model is intentionally coupled — see `spacecraft.py`. `FEATURE_CHANNELS`
defines the seven channels the anomaly model consumes.

### Attacks (`src/gsd/attacks`)

Attacks are applied *after* the nominal run, so "normal" is defined in exactly
one place. Each receives an `AttackContext` (station, profile, window, RNG) plus
the timeline, and returns the timeline with its events injected or mutated,
labelled with `truth`. They compose: the credential compromise registers a
hijacked session that the tampering and exfiltration stages then reuse, which is
what makes the cross-plane correlation in the scorecard meaningful.

### Detection (`src/gsd/detection`)

* `rules.yaml` — severities, techniques, remediations and tunable parameters.
  Shipping this to SSM Parameter Store lets thresholds change without a deploy.
* `engine.py` — stateful, time-windowed, deque-bounded. Handlers per event type.
* `ml.py` — the baseline model (see below).
* `state.py` — `ReplayMemory`: in-memory or DynamoDB.
* `asff.py` — Security Hub mapping.
* `evaluate.py` — the scorecard.

### Why a Mahalanobis baseline and not an autoencoder

The interesting attack is the one that stays inside the limits. Detecting it
needs a model of how channels move *together*, not a bigger model. A shrunk
covariance over seven standardised channels:

* trains in milliseconds on 2 880 samples (one clean day),
* serialises to a 4 KB JSON blob that Lambda loads without a SciPy layer,
* gives a per-channel contribution breakdown for free, which is what an analyst
  actually needs during triage,
* and has one tunable knob (the training quantile).

An autoencoder or an Isolation Forest is a reasonable phase-2 comparison — that
is why `TelemetryModel` is behind a `score()`/`threshold` interface. But a model
nobody can explain at 03:00 is not an improvement.

### AWS services and their jobs

| Service | Role in the pipeline |
|---|---|
| Kinesis Data Streams | ordered, shard-partitioned ingestion of station events |
| Kinesis Firehose → S3 | immutable raw archive; every detection is re-runnable |
| Lambda (detector) | the rules engine + baseline model, per batch |
| DynamoDB (TTL) | replay memory that survives across batches and shards |
| CloudTrail | the identity plane, including S3 data events on the archive |
| GuardDuty | AWS-native behavioural detection we do not have to reimplement |
| Lambda (correlator) | re-scores GuardDuty findings against mission asset context |
| Security Hub | one queue for both halves, in ASFF |
| CloudWatch | embedded metrics, alarms (critical finding, telemetry gap, errors) |
| SNS | on-call notification |

## What the cloud path adds, and how it is tested

Three behaviours exist only once the code runs in AWS, and each one broke the
first time it was exercised against emulated services:

| Behaviour | Failure it caused | Fix |
|---|---|---|
| `PutLogEvents` rejects events older than 14 days *inside a 200 response* | the simulator's reproducible 2026-03-12 timeline vanished into an empty log group, exit code 0 | `CloudWatchLogsSink` raises `RejectedLogEvents`; `gsd simulate --start 24h` generates a timeline that ends now |
| CloudTrail advanced event selectors replace the default management selector | a data-events-only selector would have logged no `ConsoleLogin` or `CreateAccessKey` at all, silently disabling every `GS-AUTH-*` rule | an explicit `management-events` selector alongside the data one |
| `ReportBatchItemFailures` needs the handler to return `batchItemFailures` | one malformed record would have failed and retried the entire 200-record batch | per-record decode, failed sequence numbers reported individually |

`tests/test_integration_aws.py` covers all three plus the DynamoDB replay memory
across a simulated cold start. It runs in-process against moto, so it needs no
credentials and no network, and runs in CI on every push.

## State and scaling

The engine keeps three kinds of state:

| State | Window | Where it lives in AWS |
|---|---|---|
| failed logins, command rate, anomaly streak | seconds–minutes | Lambda execution environment (shard-sticky) |
| last login geo per operator | 1 hour | same, best-effort |
| accepted `(spacecraft, seq)` and MACs | 24 hours | DynamoDB, conditional write + TTL |

Only the last one is correctness-critical across invocations, which keeps the
per-record cost of the deployed detector to at most one conditional `PutItem`.
