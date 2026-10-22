# CMMC Level 2 reference implementation — a one-tenant, zero-local-settings baseline

Everything a small defence supplier needs to run NIST SP 800-171 Rev 2 / CMMC Level 2 controls from a single Microsoft 365 tenant: the policies, the scripts that build and audit them, the alerting, the evidence discipline, the document skeletons, and the method that took Sanctir LLC to a self-assessed score of 110 of 110 and a CMMC Level 2 (Self) affirmation in SPRS in October 2026.

Published by [Sanctir LLC](https://sanctir.com) as a working reference, not a product. Use it, fork it, improve it.

**Not technical? Read [docs/START-HERE.md](docs/START-HERE.md) first.** It explains, in plain language, what the requirement is, how the score works, how to score yourself honestly, how to post it in SPRS, which certificates and keys you need, and exactly which commands to run.

> **Read this first.** Nothing here guarantees a score. A NIST SP 800-171 score is produced by *your* assessment of *your* system boundary against *your* evidence. This repository gives you controls that are known to work, tooling that produces the evidence, and the method; the assessment is still yours to perform and affirm. Misrepresenting a CMMC status to the U.S. Government is a federal offence (18 U.S.C. §1001; False Claims Act). CMMC is a registered mark of the U.S. Department of Defense; this project is not affiliated with or endorsed by DoD, the Cyber AB, or Microsoft.

## Results (self-measured, 21–22 October 2026)

| | Result |
|---|---|
| NIST SP 800-171 Rev 2 self-assessment (SPRS) | **110 / 110**, posted 12 Oct 2026; CMMC Level 2 (Self) affirmed |
| DISA Windows 11 V2R11 | 208 / 209 |
| DISA Defender Antivirus V2R10 | 64 / 67 (22 Oct, after the fix in explainer 07) |
| DISA Windows Firewall V2R3 | 17 / 20 |
| DISA Office 365 ProPlus V3R8 | 122 / 125 |
| DISA Edge V2R5 | 53 / 54 |
| DISA OneDrive V2R4 | 12 / 12 |
| DISA Entra ID V1R2 + Intune MDM V1R2 | 11 pass, 0 fail, 2 documented emergency-access exceptions |
| DISA Defender for Endpoint V1R2 | 21 / 25 (4 features pending Microsoft) |

Both workstations measured, identical. Every rule not passed is accounted for: **10 are settings stricter than DISA** and 1 is a risk-accepted decision — no open finding. The full table, every exception with its reason, and the exact commands are in **[docs/explainers/07-disa-stig-results.md](docs/explainers/07-disa-stig-results.md)**. These are Sanctir's own measurements of Sanctir's system, not a certification — run the same tools on yours.

## The design in one paragraph

Every control is **owned by the tenant and enforced on the device by the tenant**: Intune settings-catalog policies, Conditional Access, Defender, App Control, BitLocker, LAPS, Windows Firewall, and a set of Intune *remediations* that detect and repair drift within minutes. Local machines carry **no individual settings** beyond what a standard user can change; anything set by hand is treated as drift and reversed. Identity is **phishing-resistant only**: a FIDO2 security key for the daily user and a CAC (certificate-based authentication) for the separate admin account — nothing else, in Windows, Microsoft 365 or any elevation; no password, push, SMS or Windows Hello paths; admin rights through PIM activation, a break-glass account that is alerted on *every* sign-in type. Telemetry goes to Microsoft Sentinel and to an immutable, locked archive, and **every alert is reviewed and closed with its cause** so the review itself is on record. A snapshot of the whole tenant is the approved baseline; a drift check compares the live tenant against it.

## What is in here

| Folder | Contents |
|---|---|
| `scripts/` | PowerShell for the admin side: a module-free Graph/Azure helper (browser PKCE sign-in, no device code), policy builders, the tenant audit, baseline snapshot and drift compare, the DISA STIG and NSA Secure Host Baseline evaluators, the daily alert-queue and incident review, SPRS preparation |
| `remediations/` | Intune remediation pairs (detect/remediate) and their builders: service baseline and watchdog, consistency scanner, firewall lockdown and versioned-path rules, discovery services off, hibernate-from-standby, and more |
| `policies/` | Settings-catalog, compliance, Conditional Access and authentication-method definitions as JSON, with the script that deploys each one |
| `alerting/` | Sentinel analytics rules, Azure Monitor log-alert rules and the data collection rule, with *generic* exclusion sets and the measurement method for tuning your own |
| `docs/templates/` | Full skeletons: System Security Plan, Plan of Action, policies (access control, configuration management, incident response, audit and accountability, …), procedures, the change register and review record formats |
| `docs/explainers/` | Why everything lives in the tenant; key-only sign-in and PIM; break-glass done properly; the evidence discipline; running your own audit; posting to SPRS, including the CMMC Level 2 self-assessment; **the DISA STIG results and every exception (07)**; **CAC-only admin and security-key-only user sign-in (08)** |
| `config.example.json` | Every tenant-specific value in one place. The scripts read it; nothing is embedded in code |

## What is deliberately **not** in here

- Sanctir's own tenant identifiers, account names, device names, CAGE code or SPRS records.
- Sanctir's filled documents, change log, incident register, evidence or configuration snapshots.
- The specific alert exclusions, firewall allow-lists and App Control rules in force at Sanctir. The *shape* is here; the contents are a blind-spot list and stay private. Measure your own.

A scrubber (`tools/scrub.ps1`) and a gitleaks configuration run before every commit so that stays true.

## How to use it

1. Read `docs/explainers/01-tenant-owned-everything.md`. If you disagree with the premise, the rest will fight you.
2. Copy `config.example.json` to `config.json`, fill in your tenant, subscription, workspace and group IDs, and your account names.
3. Deploy in the order in `docs/explainers/02-build-order.md`: identity first, then endpoint baseline, then logging and alerting, then the remediations that hold it all in place.
4. Take a baseline snapshot. From then on, every change is a recorded change and every drift check is a comparison against it.
5. Run the audit scripts as an assessor would, fix what they find, and only then score yourself.

## Status

Initial publication 12 October 2026. **Update 22 October 2026:** DISA STIG results for every product (explainer 07); CAC-only / security-key-only sign-in with Windows Hello removed (explainer 08); DISA's Edge, Defender and Office packages as tenant policies; new remediations — STIG registry closure, OneDrive sync health, DNS guard for VPN reconnects, vendor network-suite removal, a registry-writer audit; the cloud STIG evaluator; the Conditional Access deployer now creates custom authentication strengths. The scripts are the ones Sanctir runs; the templates are the structure of Sanctir's own documents with the contents removed. Expect rough edges and open issues; contributions welcome.

## Licence

Code (`scripts/`, `remediations/`, `policies/`, `alerting/`, `tools/`): [MIT](LICENSE). Documents and templates (`docs/`): [CC BY 4.0](docs/LICENSE). No warranty; this is not legal, contractual or assessment advice.
