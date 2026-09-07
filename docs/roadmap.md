# Roadmap

What exists today is a complete, measurable vertical slice: simulate → detect →
score → deploy. What follows is deliberately *not* built yet, with the reason.

## Next

* **Adaptive baselines.** The telemetry model is fitted once on a clean day. A
  slow-ramp attack across weeks would be absorbed. The fix is a rolling refit
  from an archive window plus a drift monitor comparing the current score
  distribution against the training one — but it needs a policy for "known
  clean", which is a mission decision, not a code change.
* **Model comparison.** `TelemetryModel` is behind a `score()`/`threshold`
  interface precisely so an Isolation Forest, an LSTM autoencoder or SageMaker
  Random Cut Forest can be dropped in and scored on the same labels. Worth doing
  as a measured comparison, not as an upgrade assumed in advance.
* **Multi-station, multi-spacecraft.** The event envelope already carries
  `station_id`; the engine's state keys do not all include it. Fixing that
  enables cross-station correlation (the same source IP touching two stations is
  a far stronger signal than either alone).
* **Real AWS Ground Station telemetry.** Replace the simulator's downlink plane
  with the actual contact schedule and dataflow-endpoint events.

## Considered and deferred

* **Step Functions response automation.** Auto-revoking a session on GS-AUTH-004
  is a two-hour change and a permanent operational risk: an automated response
  on the commanding path can ground a mission on a false positive. It belongs
  behind a human approval step, which is a design conversation first.
* **Detection-as-code with Sigma/OCSF.** Attractive for portability, but the
  rules here are stateful (rate windows, replay memory) in ways Sigma does not
  express. Worth revisiting if the catalogue grows past ~50 rules.
* **Real crypto (CCSDS SDLS).** The HMAC scheme has the same detection surface
  as SDLS for this purpose. Implementing the real thing adds fidelity to the
  *simulator*, not to the detections.

## Known limitations

1. The single "false positive" in the scorecard is a legitimate sign-in flagged
   as impossible travel because it followed the attacker's. Correct behaviour,
   scored as an error by label-based metrics.
2. `anomalous_behavior` labels ~400 telemetry events, so its recall dominates
   the aggregate. Per-scenario recall is the number to read, not the average.
3. Lambda per-container state (rate windows, anomaly streaks) is
   shard-sticky rather than guaranteed. A shard rebalance can reset a streak.
   Only the replay memory is made globally consistent, because only it must be.
4. Terraform has never been applied against a live account, and could not even
   be `terraform validate`d in the environment this repo was built in (the
   provider registry was unreachable). It is `fmt`-clean and reviewed by hand;
   CI runs `validate` where the registry is reachable. Treat the first `apply`
   as a review step.
5. The emulated-AWS suite uses moto, which is faithful about API shapes and
   about the behaviours this project depends on (conditional writes, rejected
   log events, ASFF acceptance) but is not AWS. It cannot catch IAM policy
   mistakes, service quotas, or eventual consistency.
