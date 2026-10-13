# 04 — Working with an AI assistant: how Sanctir used Claude Code, the rules that made it safe, and where it went wrong

Everything in this repository was built by one person with an AI coding assistant, Anthropic's **Claude Code** (the desktop app), over about six weeks. The assistant wrote the scripts, read the logs and the standards, drafted the documents and the audit; the owner ran every command, made every decision, and signed every affirmation. That division is the whole point of this page: it is what makes the result defensible.

## Why it is easier with an assistant

NIST SP 800-171 is 110 requirements and 320 objectives, scored against DoD's method, implemented across Intune, Entra, Defender, Purview, Sentinel and Windows, each with its own API and vocabulary. A specialist consultancy does this with a team; a one-person company has evenings. The assistant closes that gap in four specific ways:

1. **It reads everything.** The STIG, the NSA baseline, the Graph API docs, 40,000 rows of DNS logs, a day of sign-in records, the alert queue. It reads them in minutes and tells you what is there, with the file and line.
2. **It writes read-only tools first.** Every change in this repository began as a script that only *read* the live state and wrote it to an evidence file. You read that file, then decided. The assistant's job was to make the state visible; yours was to judge it.
3. **It keeps the records.** Every change got a dated register entry with the evidence file and the way back; every finding got a number, an owner and a status. That bookkeeping is most of what an assessor asks for and is exactly what a busy owner skips.
4. **It never gets tired of the method.** Read-only first; back up before writing; read back after; one change, one window, one machine; refuse if the precondition is not met. The scripts here encode those habits because the assistant was told to encode them, every time.

## What it costs and how to start

A standard Claude subscription that includes Claude Code is all it took; no enterprise agreement, no integration project. Install the desktop app, give it this repository, and it will read every script, policy and explainer here before you ask your first question. From there it speeds up three things in particular: **implementation** (it adapts the deploy scripts to your `config.json`, runs them read-only, shows you the plan, and applies on your word), **testing** (it reads the evidence files the scripts produce and tells you what passed, what is pending and what failed, in plain language), and **production deployment** (it walks the build order in `02-build-order.md` step by step, with the read-back after each step, so nothing is switched on before it has been read). What took Sanctir six weeks of evenings with the assistant doing the reading would have taken months without it, and the method it was held to is what made the result safe.

## How to connect it

1. Install the Claude desktop app and open the **Code** tab in a folder that holds a clone of this repository (download the ZIP from GitHub and extract it if you do not use Git) and your own records.
2. Give it the rules in the next section as standing instructions (the app keeps a memory per project; the first thing to put in it is the rules).
3. Work in two windows: the assistant's, and a PowerShell 7 window that **you** run as the admin account with your security key. The assistant writes a script; you run it; you paste the output back. The assistant never holds a token, a password or a key. The sign-in helper in `scripts/Connect-Tenant.ps1` is built for exactly this: it signs in on your machine, in your window, and the assistant only ever sees what you paste.
4. For portals (Intune, Entra, SPRS, Cloudflare), the app's built-in browser pane lets the assistant *read* a page you have signed in to and fill in non-secret fields for you to check; the sign-in, the consent banner and the submit button stay yours.
5. Optionally connect the Microsoft 365 connector so it can read your mail and calendar and create reminders; it is how the one-year SPRS re-affirmation reminder got into the calendar.

## The rules (put these in the assistant's memory on day one)

- Everything goes in the tenant, never on the device. No drift.
- Read-only first. A change needs `-Apply`, a backup before, a read-back after.
- One tenant-changing script runs once, in one window, on one machine.
- Never block or stop anything required for management, updates or security. Never take a machine offline.
- Security holes are fixed immediately; improvements wait for a safe moment.
- Secrets never reach the assistant: no passwords, keys, PINs, recovery keys, tokens. If a command output would contain one, the script redacts it before you paste.
- The assistant does not sign in to anything. The owner signs in; the owner clicks submit; the owner affirms.
- Disable, never delete, in the tenant. Correct records with a dated note, never silently.
- Never fabricate a record. If a review did not happen, the register says so.
- The go/no-go read comes before the switch, every time.

## Where it went wrong, so you know what to watch

The assistant is fast and literal, and it makes the mistakes a fast, literal junior makes. In Sanctir's six weeks:

- It **overwrote a script** that was cited as evidence, by reusing a file name. Caught the same hour; the original was recovered from the session transcript; the rule "a new script gets a new name" went into memory.
- It **enforced a Conditional Access policy before its own go/no-go read** had succeeded; the admin sign-in was refused for fourteen minutes. Reverted from a window that still held a token, re-scoped, re-enabled. Rule: the read comes before the switch.
- It **wrote a review record that overstated what had been reviewed** ("every alert was read") because that was the plan, not the fact. The simulated audit caught it against the alert system's own state. Rule: the record describes what the evidence shows, nothing more.
- It **guessed a licence** in a draft of this documentation where the record said otherwise. Caught on the read-through. Rule: facts come from the record, with the line number.

None of these reached the tenant's security posture; all of them would have embarrassed Sanctir in front of an assessor if they had stayed. The safeguard is not a smarter assistant; it is the method: read-only first, evidence files, read-back, and an owner who reads the output before acting.

## What to ask it for, in order

1. "Read my tenant and tell me what is actually in force." (`Audit-Tenant.ps1`, then your questions about the output.)
2. "Build me the policy for X as a read-only script that shows the plan, then an `-Apply`." (`policies/` here already has most of them.)
3. "Measure what this alert rule actually matched for a week before you exclude anything."
4. "Draft the SSP section for requirement 3.x from these evidence files; cite each one."
5. "Audit me as if you wanted to fail me." (`05-run-your-own-audit.md`.)
6. "Prepare the SPRS values from the SSP and the audit; I will enter and affirm them."

It will do all of that well. Do not ask it to decide what your boundary is, whether a requirement is met, or whether to affirm. Those are yours, and that is what the affirmation means.
