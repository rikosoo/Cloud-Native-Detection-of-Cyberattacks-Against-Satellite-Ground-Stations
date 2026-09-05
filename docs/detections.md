# Detection catalogue

Severities and parameters live in
[`src/gsd/detection/rules.yaml`](../src/gsd/detection/rules.yaml); the logic is
in `engine.py`. Every finding carries evidence, an ATT&CK technique and a
remediation, and is exported as ASFF.

## Identity (`GS-AUTH-*`)

| ID | Severity | Fires when | Notes |
|---|---|---|---|
| GS-AUTH-001 | HIGH | a successful action comes from outside `trusted_cidrs` | the workhorse; also catches the exfiltration stage |
| GS-AUTH-002 | HIGH | console sign-in or a sensitive action without MFA | service identities use `AssumeRole`, so they do not trip it |
| GS-AUTH-003 | MEDIUM | ≥3 distinct users fail auth from one source in 300 s | classic spray shape |
| GS-AUTH-004 | CRITICAL | `CreateAccessKey`, `AttachUserPolicy`, `DeleteTrail`, `UpdateMissionProfile`… | persistence, escalation and anti-forensics in one rule |
| GS-AUTH-005 | HIGH | two sign-ins whose geo separation implies >900 km/h | coarse country-level distance table |
| GS-AUTH-006 | LOW | activity outside duty hours by someone not on the night roster | context, not a page |

## Commanding (`GS-CMD-*`)

| ID | Severity | Fires when |
|---|---|---|
| GS-CMD-001 | CRITICAL | the telecommand MAC does not verify — tampered, or signed with an unknown key |
| GS-CMD-002 | HIGH | the opcode is outside the issuing role's authorised set |
| GS-CMD-003 | CRITICAL | a globally inhibited opcode (`PWR_BUS_OFF`, `FSW_PATCH`) appears at all |
| GS-CMD-004 | MEDIUM | one operator exceeds 12 telecommands per minute |
| GS-CMD-005 | HIGH | a critical opcode carries fewer than two distinct approvals |
| GS-CMD-006 | HIGH | the frame's source address is outside the uplink allowlist |

GS-CMD-001 is the only rule that depends on key secrecy. The other five are what
remain when the key is already stolen — deliberately.

## Replay (`GS-RPL-*`)

| ID | Severity | Fires when |
|---|---|---|
| GS-RPL-001 | CRITICAL | a `(spacecraft, sequence counter)` pair is accepted twice inside 24 h |
| GS-RPL-002 | CRITICAL | the same authentication tag is seen twice |
| GS-RPL-003 | HIGH | the gap between `issued_at` and uplink exceeds 30 s |

These are the rules that need cross-batch state; see `state.py`.

## Telemetry (`GS-TLM-*`)

| ID | Severity | Fires when |
|---|---|---|
| GS-TLM-001 | HIGH | any channel leaves its ICD limits |
| GS-TLM-002 | MEDIUM | three consecutive samples exceed the learned Mahalanobis threshold |

In the reference run GS-TLM-002 fires **2 610 s (43 minutes) before** the first
ICD limit breach, and names the contributing channels (`slew_rate_dps`,
`snr_db`, `temp_battery_c`).
That gap is the whole argument for the model: the limit check tells you the
spacecraft is already in trouble, the baseline tells you it is heading there.

## Exfiltration (`GS-EXF-*`)

| ID | Severity | Fires when |
|---|---|---|
| GS-EXF-001 | CRITICAL | a transfer targets a destination outside the approved archives |
| GS-EXF-002 | HIGH | a single transfer exceeds 2 048 MB |
| GS-EXF-003 | HIGH | ≥500 objects or ≥1 GiB read in one call sequence (CloudTrail data events) |
| GS-EXF-004 | MEDIUM | a transfer happens outside the contact schedule |

## Tuning

* **Too noisy?** Raise `quantile` when training (`--quantile 0.9995`) and the
  `consecutive` parameter for GS-TLM-002. Both are the intended first knobs.
* **Duty hours and rosters** live in `MissionProfile`; a wrong roster produces
  GS-AUTH-006 noise every night shift.
* **Baseline drift.** The model is fitted on one clean day. Seasonal changes in
  the power budget (beta-angle drift) will eventually raise the distance floor.
  Refit monthly from an archive window known to be clean, and keep the previous
  model to diff thresholds.

## Evaluation methodology

`gsd evaluate` joins findings back to the injected labels:

* **recall** — labelled events that produced at least one finding,
* **precision** — findings on labelled events over all findings,
* **MTTD** — first finding minus first labelled event, per scenario.

One caveat, stated plainly: the single false positive in the reference run is
the *legitimate* sign-in that follows the attacker's, flagged as impossible
travel. It is correct behaviour scored as a miss by a label-based metric — the
kind of artefact worth reporting rather than tuning away.
