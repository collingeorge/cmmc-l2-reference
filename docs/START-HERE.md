# Start here — how a small company gets to CMMC Level 2 on its own, and how we did it

This page is for the owner of a small defence supplier who is not an IT specialist. It explains what the requirement actually is, what you need to have in place, how to score yourself honestly, how to post that score where the Department of Defense looks for it, and how to use this repository to do it. The technical detail sits behind it in `docs/explainers/` and `scripts/`; you do not need it to understand the plan.

Sanctir LLC is a one-person company. In October 2026 it posted a NIST SP 800-171 score of 110 out of 110 and affirmed a CMMC Level 2 self-assessment in SPRS, from a single Microsoft 365 tenant and two laptops, with no consultant and no managed-service provider. Everything it used is in this repository, with its own identifiers removed. The method is repeatable; the score is yours to earn.

---

## 1. What is actually required

If you hold or will hold a DoD contract that involves Controlled Unclassified Information (CUI), your contract carries clauses that require three things:

| Clause | What it requires of you | Where it is checked |
|---|---|---|
| DFARS 252.204-7012 | Protect CUI to the 110 requirements of NIST SP 800-171, and **report a cyber incident to DoD within 72 hours** | Your contracting officer; the DIBNet incident portal |
| DFARS 252.204-7019 / 7020 | Have a **current NIST SP 800-171 self-assessment score** posted in SPRS (not older than three years) | SPRS, by CAGE code |
| DFARS 252.204-7021 | Hold the **CMMC status** the contract requires. For Level 2, that is a self-assessment with an annual affirmation by a senior company official (while DoD's certification phase is suspended, 2026) | SPRS, by CAGE code |

The 110 requirements are the same in all three. CMMC Level 2 *is* NIST SP 800-171 Rev 2, assessed with NIST's own assessment guide (SP 800-171A), scored with DoD's method. There is no second set of rules.

**Links (official sources):**
- NIST SP 800-171 Rev 2, the 110 requirements: https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final
- NIST SP 800-171A, the 320 assessment objectives you test yourself against: https://csrc.nist.gov/pubs/sp/800/171/a/final
- DoD's scoring method ("NIST SP 800-171 DoD Assessment Methodology"): https://www.acq.osd.mil/asda/dpc/cp/cyber/safeguarding.html
- The CMMC programme, rule (32 CFR Part 170), assessment and scoping guides: https://dodcio.defense.gov/CMMC/
- The DFARS clauses: https://www.acquisition.gov/dfars/part-252-solicitation-provisions-and-contract-clauses (search 252.204-7012, -7019, -7020, -7021)
- SPRS, where scores and CMMC status are posted: https://www.sprs.csd.disa.mil/ — guides: https://www.sprs.csd.disa.mil/nistsp.htm and https://www.sprs.csd.disa.mil/cmmc.htm
- PIEE, the login front door to SPRS: https://piee.eb.mil
- DIBNet, where cyber incidents are reported: https://dibnet.dod.mil/
- Your company record (CAGE code, UEI): https://sam.gov

---

## 2. How the score works

- Each of the 110 requirements is worth **1, 3 or 5 points** in DoD's method. You start at 110 and **subtract** the value of every requirement that is *not met*. (Two requirements, multi-factor authentication and encryption, can be partially credited; the method explains how.) The lowest possible score is −203.
- A requirement is **met only when every one of its assessment objectives in SP 800-171A is met**. "Mostly" is not met. If a sentence in the objective says "is defined" or "is identified", you need a written document that defines or identifies it.
- **Not applicable** is allowed only when the thing the requirement talks about genuinely does not exist in your system (for example, no wireless if you truly have no wireless). It is not a way to skip hard ones; a one-person company still "separates duties" by documenting who does what and that the daily and administrative accounts are different.
- A **Plan of Action** (POA&M) lists the requirements you have not met and when you will. For CMMC Level 2, a *conditional* status is possible at 88 points or more with a limited POA&M closed within 180 days; a *final* status requires all 110.
- The score is an **affirmation by you** that it is true. Misrepresenting it to the Government is a federal offence (18 U.S.C. §1001; False Claims Act). The point of this repository is that you never have to guess: every "met" is backed by something you can show.

---

## 3. What you need to have — the plain-language version

Sanctir's system is one Microsoft 365 tenant (Business Premium licensing with Entra ID P2, Intune, Defender), Microsoft Sentinel for logging, and company-owned Windows 11 laptops plus a managed iPhone. Everything below is enforced from the tenant; nothing depends on a setting someone remembered to make on a laptop.

1. **Identity.** Everyone signs in with a hardware security key (FIDO2; Sanctir uses FIPS-validated YubiKeys). No passwords in daily use, no "approve this sign-in" phone prompts, no codes from an app. Administration is done from a separate admin account that gets its rights for a few hours at a time (Privileged Identity Management) and loses them again. One sealed "break-glass" account exists for emergencies, and every sign-in by it raises an alert.
2. **Devices.** Laptops are enrolled in Intune and get their entire configuration from it: disk encryption, firewall, antivirus settings, what programs may run (App Control), screen lock, what happens when the lid closes, which ports and services are off. If anything is changed by hand on the laptop, a scheduled check puts it back within minutes and records that it did.
3. **Logging.** Every security event from every laptop and from the cloud goes to a central log (Sentinel) and, separately, to a locked archive nobody can shorten or delete, including an administrator. Alerts fire on the things that matter: a sign-in by the emergency account, a role being granted, auditing being turned off, malware, a new service or scheduled task.
4. **Review.** Alerts are read and closed with the cause written down, every working day. Incidents are triaged from evidence. A snapshot of the entire tenant configuration is the approved baseline, and a comparison against it shows any drift.
5. **Paper.** A System Security Plan that describes the system truthfully; policies and procedures for the fourteen families of requirements; a change register; an incident register; training records; a plan of action. Skeletons of every one are in `docs/templates/`.

---

## 4. Score yourself, honestly: the method we used

Do it in this order. It is the same order an assessor would follow, and it stops you from scoring things that are not actually in force.

1. **Write the boundary down.** Which devices, accounts, cloud services and people handle CUI. That is the "system" the SSP describes. If a device is not in the boundary, it must not be able to reach CUI.
2. **Read the live state, not the plan.** Run the audit scripts (section 6). They read the tenant and the devices and write what is *actually* in force into an `Evidence` folder with a timestamp. Compare that with what your SSP claims. Every difference is either a finding or a correction to the SSP.
3. **Go requirement by requirement with SP 800-171A open.** For each objective, write one line: what is in force, and where the evidence is (a policy name, an evidence file, a screenshot, a register entry). Sanctir keeps this in the SSP's control table. If you cannot name the evidence, it is not met.
4. **Score with DoD's table.** Subtract the points for every requirement that is not met. Write the Plan of Action for those, with dates.
5. **Fix what you can before you post.** Most "not met" items in a small company are paperwork (a procedure never written, a review never recorded) or a single tenant setting. The scripts here hold the settings; the templates hold the paperwork.
6. **Keep the evidence.** Everything the scripts write goes in `Evidence\<date>\`. Everything you change goes in the change register with the date and the evidence file. An assessor asks "show me"; the answer is a folder, not a memory.
7. **Have someone else read it.** Sanctir had two independent AI reviewers read a redacted copy of its self-assessment and name the thin evidence, then fixed each item. A peer company, a consultant for an hour, or a Cyber AB registered practitioner serve the same purpose. The score is only as good as the challenge it survived.

---

## 5. Post the score and the CMMC status (about twenty minutes)

You need: a PIEE account with the **SPRS Cyber Vendor User** role for your CAGE code (requested in PIEE, approved by your company's PIEE administrator), your SSP name, version and date, and your score.

1. Sign in at https://piee.eb.mil, open **Supplier Performance Risk System**, accept the DoD banner.
2. **Cyber Reports (CMMC & NIST)** → select your CAGE → **Run Cyber Reports**.
3. Tab **NIST SP 800-171 Assessments** → **Add New NIST Assessment** (Basic). Enter: assessment date, score, scope (*Enterprise* if the whole company is the system), Plan of Action completion date (blank at 110), SSP name, version and date, included CAGE(s). **Save.** SPRS gives you a DoD Unique Identifier; keep a screenshot in your evidence.
4. Tab **CMMC Assessments** → **CMMC Level 2 (Self)** → **Add New CMMC Level 2 Self-Assessment**. Acknowledge the misrepresentation warning (read it). Mark each of the 110 requirements Met / Not Met / N/A, family by family (it is a checklist; it takes ten minutes). Review → CAGEs → Score → **Affirm** as the senior official. SPRS gives you a CMMC UID, an affirmation expiry one year out, and a status expiry three years out. **Put the one-year date in your calendar now**: the affirmation lapses without it.

Both records are separate and both are needed: the NIST score satisfies clauses 7019/7020; the CMMC status satisfies 7021.

---

## 6. The tools in this repository, and the commands

All scripts are PowerShell 7 (free, from Microsoft: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-windows). They read `config.json` for your tenant's details and never contain them. They **read only** unless you add `-Apply`, and every run writes a timestamped file into `Evidence\`.

```powershell
# one-time: copy and fill in your tenant details
Copy-Item config.example.json config.json      # then edit config.json

# every admin session: sign in once (browser opens; use your admin account and security key)
. .\scripts\Connect-Tenant.ps1; Connect-Tenant

# the audit: devices, compliance, remediations, policy state, Conditional Access, auth methods, Sentinel health
.\scripts\Audit-Tenant.ps1

# the approved baseline: export once; compare whenever you want to prove nothing drifted
.\scripts\Baseline-Snapshot.ps1 -Mode Export
.\scripts\Baseline-Snapshot.ps1 -Mode Compare -Baseline .\ConfigBackup\BASELINE-<date>

# every working day: read the alert queue and the open incidents, close each with its cause
.\scripts\Review-AlertQueue.ps1
.\scripts\Triage-NewIncidents.ps1
```

`docs/explainers/02-build-order.md` lists the policies, remediations and alert rules in the order to deploy them, with the script for each.

---

## 7. The certificates and hardware you will be asked about

- **Security keys.** Any FIDO2 key works with Entra ID. For CUI, use keys whose cryptography is **FIPS 140 validated** (check the vendor's certificate number against https://csrc.nist.gov/projects/cryptographic-module-validation-program). Sanctir uses YubiKey 5 FIPS. Buy at least three: one per daily user, one for the administrator, and one kept locked away for the break-glass account. Never put the break-glass credential on the key you carry.
- **The DoD medium-assurance certificate (ECA).** Reporting an incident to DIBNet under clause 7012 requires a certificate from DoD's External Certification Authority programme (https://public.cyber.mil/eca/). It is issued in person after identity checks, can be loaded onto your own FIPS YubiKey, and costs a few hundred dollars a year. **Order it before you need it**: without it you cannot meet the 72-hour reporting clock. The same certificate can also serve as a smart-card sign-in to Entra ID.
- **FIPS-validated encryption.** Windows BitLocker and the TLS stack in Windows 11 are FIPS validated when the FIPS policy is on; the policy here turns it on from the tenant. Record the CMVP certificate numbers in your SSP; assessors ask.
- **Benchmarks worth running against yourself.** DISA's Windows 11 STIG (https://public.cyber.mil/stigs/) and NSA's Windows Secure Host Baseline (archived, still useful: https://github.com/nsacyber/Windows-Secure-Host-Baseline). The evaluators in `scripts/` score your device against both without installing anything.

---

## 8. Where this came from

Sanctir built this between September and October 2026, in the open, by one person with an AI assistant doing the scripting and the reading, and the owner making every decision and every affirmation. The guiding rule throughout was: **everything is organisational policy enforced by the tenant; a local machine never carries an individual setting; every change is recorded; every alert is reviewed.** The last step was a simulated audit of the whole estate, which found fourteen issues (most of them records that overstated what had been reviewed) and fixed eleven the same day before the score was posted. That audit's method is in `docs/explainers/05-run-your-own-audit.md`, and it is the part we would most like you to copy.

If you find an error, a gap or a better way, open an issue. If this helped you post a score you can stand behind, tell us.
