# 01 — Everything is owned by the tenant; a device never carries an individual setting

This is the premise of the whole repository. If you accept it, the rest follows; if you do not, the scripts will fight you.

## The rule

> Every security setting on every device is delivered and enforced by the organisation's tenant. A local machine carries no individual configuration beyond what a standard user is allowed to change. Anything set by hand on a device is drift, and drift is reversed automatically and recorded.

## Why

1. **Assessors assess the organisation, not a laptop.** "Is the screen lock configured?" is answered "yes, by policy X, assigned to group Y, reported compliant on N devices", not "I set it on my machine". The first answer is evidence; the second is an anecdote. Every requirement in NIST SP 800-171 reads better, and scores more safely, when the control is a tenant object you can export, hash and compare.
2. **A rebuilt or replaced machine is identical on first sign-in.** Sanctir wiped and re-enrolled a laptop mid-project; it came back with the full baseline in under an hour, because nothing lived on it that was not in the tenant. The alternative is a checklist nobody fully remembers.
3. **Drift is visible.** With the tenant as the single source, the question "has anything changed?" has a mechanical answer: compare the live tenant against the approved snapshot (`Baseline-Snapshot.ps1 -Mode Compare`), and compare each device against the tenant (the consistency scanner, hourly). Local tweaks have no such check.
4. **Privilege stays rare.** If no routine task needs local administrator rights, the daily account is a standard user all day, which is requirement 3.1.5/3.1.6 for free. Admin work happens in the tenant, from a separate account, with rights that expire.
5. **It survives you.** A tenant you can export is a system a successor, an assessor or an incident responder can understand without you in the room.

## What it looks like in practice

| Need | Where it lives | How it is held in place |
|---|---|---|
| Disk encryption, firewall, Defender, screen lock, lid/power behaviour, audit policy, user rights | Intune settings-catalog and compliance policies | Intune re-applies on every sync; the consistency scanner reports any divergence hourly |
| Services that must run (monitoring agent, Defender, Intune agent, time service) and services that must not (SMB server, WPAD, discovery) | An Intune **remediation** that checks every hour and corrects, plus a local watchdog task that the remediation itself installs and locks | Remediation re-installs the watchdog if it is missing or altered |
| Firewall rules for programs in version-numbered folders | A remediation that rewrites the allow rules to the current binary every five minutes | Same |
| Which programs may run | App Control (WDAC) policy from Intune | Code integrity enforcement; blocks are logged and alerted |
| Who may sign in and how | Entra Conditional Access + authentication-methods policy | Evaluated at every sign-in |
| Who has admin rights | PIM: eligible, not active; activation per session with a reason | Role assignment alerts on every activation |
| What the logs contain | Data collection rule → Sentinel, plus continuous export to a locked immutable archive | Alert if a machine goes silent without a shutdown; the archive policy is locked and cannot be shortened |

## What is NOT tenant-owned, and why that is fine

- The **hardware security key** and its PIN: that is the user's authenticator, by design.
- The **BitLocker pre-boot PIN**: set once at enrolment, required by policy, recovery key escrowed to the tenant.
- The **local administrator password**: generated and rotated by Windows LAPS, escrowed to the tenant, retrieved only for break-glass use and rotated after.

Everything else that looks like a local setting is either delivered by the tenant or is drift.

## The habit that makes it work

Before fixing anything on a device, **find the tenant object that owns the setting** and fix it there. If no object owns it, create one and assign it. The one exception is an active security hole, which is fixed on the spot and then moved into the tenant the same day, with the register entry saying so.
