# alerting/

Seventeen Azure Monitor log-alert rules, exported from a working Sentinel workspace, and the script that deploys them. Together they are the detection layer behind NIST SP 800-171 3.3.4 (alert on audit failure), 3.3.5 (correlate), 3.6.1–3.6.2 (incident handling), 3.14.6–3.14.7 (monitor).

| Rule | Sev | What it fires on |
|---|---|---|
| `ref-breakglass-any-signin` | 0 | Any interactive, non-interactive or Windows logon by the emergency-access account. Purview's own break-glass alert sees interactive sign-ins only; this one closed the gap |
| `ref-audit-tamper` | 0 | Audit log cleared, audit policy changed, event-log service stopped outside an orderly shutdown |
| `ref-malware` | 0 | Defender detection, remediation failure, or an attack-surface-reduction block other than the known LSASS/svchost one |
| `ref-service-drift` | 0 | A critical service (monitoring agent, Defender, Intune agent, time) stopped or changed outside a shutdown |
| `ref-privesc` | 1 | Account created, enabled, password reset, group membership or user-right change, by anything other than the machine's own routine (Web Sign-in account, LAPS rotation, policy refresh) |
| `ref-persistence` | 1 | New service, driver or scheduled task, or a start-type change, outside Windows' own self-management and known app updaters |
| `ref-defense-change` | 1 | Defender protection disabled or configuration changed, excluding the policy re-applying its own value |
| `ref-logon` | 3 | Every interactive logon by a human account (admin sessions are meant to be seen) |
| `ref-firewall-change` | 2 | Hourly summary of firewall rule and setting changes |
| `ref-silent-without-powerdown` | 1 | A workstation reports again after a gap with no sleep, hibernate or shutdown at its start, or its upload stalled while awake |
| `ref-silent-24h` | 2 | No heartbeat for 24 hours |
| `ref-audit-stream-lag` | 1 | The Security log stream from an online machine lags the heartbeat |
| `ref-consistency-check-failed`, `ref-consistency-scanner-silent` | 1 | The hourly device consistency scanner failed a check, or did not run on an online machine |
| `ref-high-incident` | 1 | Any new high-severity Sentinel incident (so e-mail/SMS fires for incidents too) |
| `ref-telemetry-silence`, `-escalation` | disabled | Kept for history: real-time silence rules replaced by the two above, because power-down events reach the workspace only after wake |

## The exclusions in these queries are examples, not a recommendation

Every `where not(...)` in these queries was added **after measuring what the rule actually matched for a week** in one tenant, using the rule's own query re-run over the period and grouped by cause (`scripts/Review-AlertQueue.ps1` shows you the same per alert). Some of them name specific products (two AI desktop apps, a Store app updater, an RMM-free laptop's routine). Yours will differ. The method is the thing to copy:

1. Deploy the rule with **no** exclusions.
2. Let it run for a week. Do not turn it off because it is noisy; noise is data.
3. Re-run the rule's query over the week, grouped by the row content with timestamps removed. The top five groups are usually 90 % of the volume.
4. For each group, decide: benign and recurring → one narrow `where not(...)` on the exact columns; benign once → close the alerts with the cause; not benign → that is why you have the rule.
5. Record the measurement file and the change. An exclusion without a measurement behind it is a blind spot nobody chose.

A rule that fires on something you then ignore is worse than no rule: it trains you to ignore the next one. Sanctir learned this with 1,896 unread alerts; `docs/explainers/05-run-your-own-audit.md` tells that story.

## Deploy

```powershell
. .\scripts\Connect-Tenant.ps1; Connect-Tenant
.\alerting\Deploy-AlertRules.ps1          # validates every query, shows the plan
.\alerting\Deploy-AlertRules.ps1 -Apply   # creates the missing rules against the workspace and action group in config.json
```

Prerequisites (built in `docs/explainers/02-build-order.md` §3): the workspace, the Azure Monitor agent and data collection rule on every device, the Entra and Office 365 connectors, and an action group that reaches a person.
