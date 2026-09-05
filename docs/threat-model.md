# Threat model

## Assets

| Asset | Why an adversary wants it | Loss scenario |
|---|---|---|
| Uplink commanding path | Direct control of the spacecraft | Slew to a power-negative attitude, disable the bus, brick the mission |
| Telecommand key material | Forge authenticated commands at will | Every other control becomes decorative |
| Operator identities | The cheapest way onto the commanding path | Legitimate-looking commands from a stolen session |
| Payload data archive | The mission's product | Exfiltration of imagery/ISR data; loss of customer trust |
| Telemetry stream | Situational awareness | Blinding the operators, or hiding the effects of an attack |
| Contact schedule | Timing | Knowing exactly when a command will be accepted |

## Adversaries

* **Opportunistic criminal** — credential stuffing, cryptomining on ground
  compute, ransoming the archive. Loud, high volume.
* **Insider** — a badged operator acting outside their role. Uses legitimate
  credentials from legitimate networks; only *what* they do is anomalous.
* **State-sponsored** — patient, targets key material and the commanding path,
  disables logging first, aims for degradation that looks like a bus fault.

## Trust boundaries

```
   operator laptops   │   AWS ground-segment account   │   RF / uplink   │  spacecraft
 ──────────────────── ┼ ───────────────────────────────┼─────────────────┼─────────────
  console, MFA        │  IAM, CloudTrail, S3, Lambda   │  SDLS-protected │  flight SW
                      │                                │  TC frames      │
        ▲ B1                        ▲ B2                      ▲ B3            ▲ B4
```

* **B1 — human to cloud.** Defended by MFA, network allowlists, duty-hour
  expectations. Broken by `credential_compromise`.
* **B2 — cloud control plane.** Defended by IAM least privilege and CloudTrail.
  Broken by the access key + `AdministratorAccess` + `DeleteTrail` sequence.
* **B3 — uplink.** Defended by the MAC and the sequence counter. Broken by
  `command_tampering` (integrity) and `replay` (freshness).
* **B4 — spacecraft.** Defended by on-board limit checks. The residual risk that
  `anomalous_behavior` targets: commands that are individually legal.

## Attack paths and their mapping

| # | Path | SPARTA | ATT&CK | Scenario |
|---|---|---|---|---|
| 1 | Spray operator credentials → sign in without MFA → create access key → attach admin | IA-0004 | T1110.003, T1078.004, T1098.001 | `credential_compromise` |
| 2 | Sit on the uplink path → rewrite opcode/params → uplink | EX-0012 | T1565.002 | `command_tampering` |
| 3 | Record valid frames → retransmit later | EX-0013 | T1557 | `replay` |
| 4 | Command a sub-threshold degradation that mimics a bus fault | IMP-0002 | T1565.001 | `anomalous_behavior` |
| 5 | Enumerate the archive → bulk read → copy to an outside bucket | EXF-0003 | T1530, T1537, T1567.002 | `exfiltration` |

## What the design assumes

* The event stream reaches the detector. An adversary who can silently drop
  telemetry defeats every rule — hence the `telemetry-gap` alarm, which treats
  missing data as breaching.
* CloudTrail is on. `DeleteTrail`/`StopLogging` are therefore themselves
  CRITICAL findings (GS-AUTH-004): the last thing the trail records is its own
  destruction.
* Key material is not already stolen. If it is, GS-CMD-001 goes quiet and only
  the behavioural rules (role, rate, window, telemetry drift) remain — which is
  the reason the catalogue does not lean on the MAC alone.

## Known evasions

| Evasion | Effect | Residual detection |
|---|---|---|
| Attack from inside the trusted CIDR (insider, or a compromised bastion) | GS-AUTH-001, GS-CMD-006 go silent | role violation, dual-authorisation, rate, telemetry drift |
| Stay under 12 commands/minute | GS-CMD-004 silent | integrity, role and replay rules are rate-independent |
| Exfiltrate in 100 MB slices to an approved bucket | GS-EXF-001/002 silent | GS-EXF-003 (object count) and GuardDuty `Exfiltration:S3` |
| Ramp the telemetry drift over days | Mahalanobis distance stays low as the baseline is static | requires baseline refresh discipline; see `docs/roadmap.md` |
| Compromise the detector's own role | Findings never reach Security Hub | detector-error alarm, and the role cannot write to the archive |
