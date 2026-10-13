# 05 — Run your own audit before anyone else does

Sanctir ran a simulated audit of its whole estate on the day it posted its score. It found fourteen issues. None of them was a control that was missing; most were **records that claimed more than the evidence showed**, and two were detection gaps that only showed up when the auditor read the raw logs instead of the summaries. All fourteen would have been found by a real assessor. Eleven were fixed the same day. This is the method.

## The stance

Audit as if you were trying to fail yourself. Read primary evidence (the tenant, the device, the logs), not your own documents. Where a document and the evidence disagree, the evidence wins and the document gets corrected with a dated note, never silently rewritten.

## The eleven reads, in order

| # | Read | Tool | What "pass" looks like |
|---|---|---|---|
| 1 | Tenant configuration vs the approved baseline | `Baseline-Snapshot.ps1 -Mode Compare` | Every ADDED / CHANGED / REMOVED matches a dated entry in the change register |
| 2 | Device vs a published benchmark | `Evaluate-STIG.ps1`, `Evaluate-NSA-SHB.ps1` | Every deviation is a recorded, reasoned decision, not an unknown |
| 3 | Policy state on each device | `Audit-Tenant.ps1` §4 | Everything succeeded; a "pending" is verified on the device before it is called lag |
| 4 | Remediations | `Audit-Tenant.ps1` §3 | No errors, no reoccurrences; retired objects are unassigned **and** documented as retired |
| 5 | Update and management channels | `Check-UpdateEndpoints.ps1` | Every endpoint reachable, nothing blocked by your own egress rules, signatures under a day old |
| 6 | Identity | `Audit-Tenant.ps1` §5 | Every member holds a FIDO2 key; weaker methods disabled in policy, not just unused; Conditional Access in the intended state (read the policy by id — list endpoints lag) |
| 7 | Open incidents | `Triage-NewIncidents.ps1` | Zero open, each closed with primary evidence in the comment |
| 8 | The alert queue, all of it | `Review-AlertQueue.ps1` | Zero older than your review interval; **a queue of unread alerts is a finding against 3.3.5 and 3.6.1 however good the rules are** |
| 9 | Privileged account use | audit logs: every PIM activation, every LAPS password retrieval, every break-glass sign-in | Each one matches a recorded admin session; break-glass use is recorded the same day, with the reason |
| 10 | Documents vs reality | read the SSP, the registers and the procedures against 1–9 | Every claim has an evidence file; every "every alert is reviewed" is true in the alert system, not only on paper |
| 11 | Power and physical | sleep study, BitLocker state, lid/power behaviour | Keys are not left in memory for hours on a locked, open laptop; if the hardware's standby ignores your hibernate timer, you know it and have a decision recorded |

## What Sanctir found (so you can look for the same)

- The Purview "break-glass sign-in" alert only sees interactive sign-ins; a Windows sign-in by that account reached the identity logs as *non-interactive* and raised nothing. Fixed with a log-alert rule covering interactive, non-interactive and Windows logon events.
- Nearly two thousand alerts, every one still "New". The rules were right; the review had never been recorded in the system that holds the alerts. Fixed by measuring each rule's actual matches, tuning six exclusions from the measurements, closing the backlog with the causes written in, and adding a daily queue review to the procedure.
- The admin tooling's consent applied to every user in the tenant. Fixed with "assignment required".
- A push-notification sign-in method was still enabled, and registered on the break-glass account, which sits outside Conditional Access by design. Fixed in the authentication-methods policy.
- A review record said the local administrator account was "last used 9 Oct"; the account itself said 6 Oct. A record said "every alert was read"; the alerts said otherwise. Both corrected with dated notes.
- A control change (token protection) was enforced before its own go/no-go read, and refused the admin sign-in for fourteen minutes. Reverted from a window that still held a token, re-scoped, re-enabled. Lesson recorded: the read comes before the switch, every time.

## Write it up

One document, dated: result by area (pass / pass with recorded deviations / fail), findings numbered with severity, owner and status, and what was fixed on the day. That document is your assessment record; the SPRS posting cites it. Keep it honest enough that you would be comfortable handing it to the assessor who comes after.

