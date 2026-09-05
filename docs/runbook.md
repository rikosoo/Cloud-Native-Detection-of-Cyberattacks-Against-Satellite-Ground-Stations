# Runbook

What to do when a finding lands in Security Hub. Ordered by how fast you have to
move. "Safe" always means *the spacecraft stays powered, thermally stable and
commandable* — reflexes that protect the network but brick the vehicle are worse
than the attack.

## CRITICAL — act within minutes

### GS-CMD-001 · Telecommand authentication failure
1. **Inhibit the uplink** for the affected spacecraft at the gateway. Do not
   send a corrective command yet: you do not know what else is in flight.
2. Pull the frame from the S3 archive (`raw/station=…/dt=…`) by `event_id`.
   Compare `opcode`/`params` against the approved command plan.
3. Verify the SDLS key state on both ends. A mismatch after a legitimate key
   rotation looks identical to an attack — check for a recent `SEC_KEY_ROTATE`.
4. If the key is intact, this is tampering on the uplink path. Treat every
   command in the same session as suspect and rebuild the session.

### GS-CMD-003 · Prohibited opcode
Same as above, plus: confirm the on-board inhibit actually rejected it. If the
spacecraft executed it, move to the flight-safety procedure for that subsystem.

### GS-RPL-001 / GS-RPL-002 · Replay
1. The frame's *content* is legitimate, so the risk is a repeated action, not a
   malicious one — check whether the opcode is idempotent before panicking.
2. Confirm the on-board anti-replay window is enabled. A replay that the
   spacecraft *accepted* is a flight-software finding, not just a ground one.
3. Find the capture point: the replayed frame's original uplink tells you which
   session and which network path the adversary had visibility of.

### GS-AUTH-004 · Escalation / persistence
1. `DeleteTrail` or `StopLogging` first: restore logging before anything else,
   or you are investigating blind.
2. Delete the access key, detach the policy, revoke active sessions
   (`aws iam put-user-policy` with a `DenyAll` and `aws:TokenIssueTime`).
3. Enumerate everything that identity did between the sign-in and now — the
   archive holds the full stream, not just the alerted events.

### GS-EXF-001 · Downlink to an unapproved destination
1. Block the destination (bucket policy / egress rule) and preserve, do not
   delete, the transfer logs.
2. Scope the loss: `object_count` and `size_mb` in the finding evidence, then
   the CloudTrail data events for the exact keys.
3. Notify per the mission data-classification policy. Imagery has legal
   obligations that a security team cannot decide alone.

## HIGH — act within the hour

* **GS-AUTH-001 / GS-CMD-006 (untrusted source)** — confirm with the NOC whether
  the netblock is a new legitimate site before revoking. Correlate with
  GS-AUTH-002 and GS-AUTH-005 on the same identity: three together is a
  compromise, one alone is often a VPN change.
* **GS-AUTH-002 (no MFA)** — if it is a standing gap rather than an incident,
  fix it with an IAM condition (`aws:MultiFactorAuthPresent`), not a ticket.
* **GS-CMD-002 / GS-CMD-005 (role, dual authorisation)** — call the operator.
  These fire on insider action and on a mis-scoped role equally; the difference
  is a conversation, not a query.
* **GS-TLM-001 (ICD limit)** — this is a flight anomaly first and a security
  finding second. Run the subsystem's anomaly procedure, *then* check whether a
  command sequence preceded it.
* **GS-EXF-002 / GS-EXF-003 (volume, bulk reads)** — compare against the pass
  schedule and the expected product size before escalating.

## MEDIUM / LOW — triage in hours

* **GS-TLM-002 (multivariate anomaly)** — read the `channels` field first: it
  names what moved. Then look for a telecommand in the preceding pass that
  explains it. An unexplained drift with no command behind it is either a real
  bus fault or the interesting case.
* **GS-CMD-004 (rate)** — usually an automation loop. Check `svc-*` identities
  before assuming an adversary.
* **GS-AUTH-006 / GS-EXF-004 (off-hours)** — context only. They exist to raise
  the severity of whatever else is happening at the same time, not to page.

## Correlation shortcuts

The scenarios in this project are *chains*, and so are real intrusions:

| If you see | Look for | You are probably looking at |
|---|---|---|
| GS-AUTH-003 then GS-AUTH-001 on one identity | GS-AUTH-004 within 10 min | credential compromise in progress |
| GS-CMD-002 from a session with a GS-AUTH-001 | GS-EXF-001 later | stolen session being monetised |
| GS-TLM-002 with no preceding command | GS-CMD-001 in the same pass | tampering that the MAC check missed, or a genuine fault |
| GuardDuty `UnauthorizedAccess:IAMUser/*` escalated by the correlator | any GS-CMD-* in the same window | the AWS and mission halves of one intrusion |

## After the incident

1. Re-run detection over the archived window with the current rules:
   `gsd detect --events <archive-slice> --model models/telemetry.json`. If the
   rules would not have caught it, that is the finding.
2. Add the missed behaviour as a rule *and* as an attack scenario, so the
   regression is enforced by `make demo` in CI.
3. Refit the baseline only from a window you have confirmed clean. Refitting on
   the attack teaches the model that the attack is normal.
