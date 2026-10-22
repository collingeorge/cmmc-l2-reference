# 07 — DISA STIG results: what we measured, how, and every rule we did not pass

Sanctir LLC posted a NIST SP 800-171 self-assessment of **110 of 110** and a **CMMC Level 2 (Self)** affirmation in SPRS in October 2026. A score is a claim; this page is the evidence behind the technical part of it, measured on **21 October 2026** against the current DISA Security Technical Implementation Guides, on both workstations and in the cloud tenant, with the tooling in this repository.

It is published so that any defence contractor can see exactly what "fully configured" looked like for a two-workstation Microsoft 365 company, reproduce the measurement on their own estate, and copy the policies that produced it.

> These are **self-measured** results — Sanctir's own run of DISA's published SCAP benchmark content through `scripts/Evaluate-STIG.ps1` (a PowerShell OVAL evaluator; DISA's SCC scanner is blocked by App Control, see below), plus manual checks for the STIGs DISA publishes without SCAP content. They are not an assessment by DISA, a C3PAO, or anyone else, and they describe Sanctir's system on the date shown. Your result is produced by your measurement of your system.

## Results — 21–22 October 2026

### Workstations (both measured, identical results; Defender re-measured after the 22 October fix)

| STIG (version) | Rules passed | Not passed | Why each one is not passed |
|---|---|---|---|
| Microsoft Windows 11 (V2R11) | **208 / 209** | 1 | Stricter than DISA (S1) |
| Microsoft Defender Antivirus (V2R10) | **64 / 67** | 3 | Stricter than DISA (S2–S4). Was 63/67 on 21 October; the 64th rule (V-278656) was fixed on 22 October — see "Fixed: an Intune conflict" below |
| Windows Defender Firewall with Advanced Security (V2R3) | **17 / 20** | 3 | Stricter than DISA (S5–S7) |
| Microsoft Office 365 ProPlus (V3R8) | **122 / 125** | 3 | Stricter than DISA (S8–S10) |
| Microsoft Edge (V2R5) | **53 / 54** | 1 | Risk-accepted decision (D1) |
| Microsoft OneDrive (V2R4) | **12 / 12** | 0 | — (no SCAP content from DISA; checked by hand against the registry, 20 October) |

10 of the 11 device rules not passed are settings **stricter** than DISA's expected value — the benchmark checks for one exact value, and a stricter one reads as "fail". The other is a recorded, risk-accepted business decision. **No open finding.**

### Cloud tenant

| STIG / SRG (version) | Result | Notes |
|---|---|---|
| Microsoft Entra ID (V1R2) + Microsoft Intune MDM Service (V1R2) | **11 PASS, 0 FAIL, 2 REVIEW** of 13 | Both REVIEW items concern the emergency-access ("break-glass") account: it is excluded from the MFA Conditional Access policy and holds a permanent Global Administrator role. That is Microsoft's own guidance for emergency access; it is a documented risk acceptance with compensating controls (FIDO2 hardware key, an alert on every sign-in of any kind) |
| Microsoft Defender for Endpoint (V1R2) | **21 / 25** | 19 met, 2 documented, 4 not offered by the portal yet (P1) |
| Central Log Server SRG (V3R5) | 127 requirements reviewed against Microsoft Sentinel; 4 gaps closed | Delete locks on the workspace and the immutable archive, Azure Activity log to Sentinel, query auditing, four more tables in the long-term archive |

### SPRS

NIST SP 800-171 Rev 2 self-assessment: **110 of 110**, posted 12 October 2026, re-affirmation due annually. CMMC Level 2 (Self) affirmation posted the same day. The STIG results above are part of the evidence for 3.4.1/3.4.2 (baseline configuration and security settings), 3.13.x (boundary and communications protection) and 3.14.x (system integrity).

## Every rule not passed, explained

### Stricter than DISA (10) — kept on purpose

| # | STIG | DISA expects | Sanctir sets | Why stricter |
|---|---|---|---|---|
| S1 | Windows 11 — UAC elevation prompt for administrators (WN11-SO-000250) | "Prompt for consent on the secure desktop" (2) | "Prompt for credentials on the secure desktop" (1) | Every elevation requires the administrator's smart card (CAC) and PIN, not a click |
| S2–S4 | Defender — three Attack Surface Reduction rules (process creation from PSExec/WMI, WMI event-subscription persistence, executables that don't meet a prevalence/age criterion) | Audit | **Block** | Audit mode only records the attack; on a two-person estate there is nobody to act on the record in time |
| S5–S7 | Firewall — default outbound action, Domain/Private/Public | Allow | **Block** (with tenant-managed allow rules) | NIST 3.13.6 "deny by default, permit by exception" applied to outbound as well as inbound |
| S8–S10 | Office — file validation / Protected View for three file classes | Open in Protected View | **Block** | Files that fail validation are not opened at all |

### Risk-accepted decision (1)

| # | STIG | Decision | Conditions |
|---|---|---|---|
| D1 | Edge — `SyncDisabled` must be 1 | Edge sync **on**, limited: favorites, settings, history, open tabs and collections sync for the **work account only**; passwords, addresses/autofill, payment data, extensions and apps never sync (`SyncTypesListDisabled`), and sync is forced on (`ForceSync`) so it never depends on the user | No CUI in favorites, collections or tab titles; only the Entra work account can sign in to Edge |

Two other Edge decisions sit **inside** the 54 passed rules and are recorded the same way, because they loosen DISA's intent even though the check passes:

- **One extension allowed.** DISA's model is "block all extensions, allow approved ones". Exactly one is allowed and force-installed: the company password manager (the policy is `ExtensionInstallAllowlist` + `ExtensionInstallForcelist`; the blocklist `*` stays). Edge's own password manager stays off.
- **Named sites stay signed in.** DISA requires cookies to be session-only (`DefaultCookiesSetting = 4`), which signs you out of every site whenever Edge closes. That stays. A short list of business services keeps its cookies: **both** `CookiesAllowedForUrls` *and* `SaveCookiesOnExit` are needed — with only the first, Edge still deletes the cookies on close (we learned that the hard way). See `policies/settings-catalog/REF-Edge-STIG.json`.

### Fixed: an Intune conflict that DISA's check caught (V-278656)

DISA's rule reads `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableLocalAdminMerge = 1`. The value kept returning to 0 although every tenant setting said 1, while Defender itself stayed at 1 (its own configuration-service-provider setting).

- **How it was found:** a temporary audit entry on that one registry key (`remediations/RegistryWriterAudit/`). Over two days Windows logged every write with the process name: each reset came from **Windows' own MDM client** (`DeviceEnroller.exe` / `omadmclient.exe`, SYSTEM) during an Intune sync — create the value as 1, then rewrite it to 0 in the same second. It began the minute DISA's Defender package was imported as a tenant policy, which set the same item a **second** way (its ADMX form) next to the Defender CSP setting that was already there.
- **Fix:** remove the ADMX copy from the DISA package policy; keep the Defender CSP setting (what Defender actually uses) and let the hourly STIG registry remediation be the one writer of the location DISA reads. Verified: no MDM write after the next sync, value 1 after a restart, Defender 64/67.
- **Lessons:** one owner per setting includes *different forms of the same setting* (CSP and ADMX). And our first guess — remove the CSP copy as the "duplicate" — made it worse: Defender then followed the reset value for eleven minutes. Find the writer before you remove anything.

### Pending Microsoft (P1)

Four Defender for Endpoint STIG features — automatically resolve alerts, download quarantined files, file content analysis, memory content analysis — are included in Microsoft 365 E5 (Defender for Endpoint Plan 2) but the portal did not offer them while the tenant also held an unused Defender for Business subscription. The subscription was cancelled; the remaining step is a Microsoft support request to move the portal to Plan 2 mode. Compensating controls: EDR in block mode, all ASR rules in Block, App Control allow-listing, tamper protection, every alert e-mailed and forwarded to Sentinel.

## How the measurement was done

1. **Download the benchmarks** from DISA (public.cyber.mil → STIGs → SCAP benchmarks). The evaluator reads them unchanged.
2. **Run elevated, with the daily user signed in.** Office and some Windows rules live in the daily user's registry hive; the evaluator loads it from the profile you name. Run it in the *administrator's* session (switch user), because the daily user cannot elevate — that is itself a STIG requirement.

   ```powershell
   # in the admin account's own elevated window, daily user signed in (switched away, not signed out)
   Get-ChildItem .\benchmarks -Recurse -Filter '*Benchmark.xml' | ForEach-Object {
       .\scripts\Evaluate-STIG.ps1 -Benchmark $_.FullName -UserProfile '<daily-user-profile-folder>'
   }
   ```
3. **Cloud STIGs** have no SCAP content; `scripts/Evaluate-CloudSTIG.ps1` checks the 13 Entra ID and Intune rules through Microsoft Graph and Azure Resource Manager, read-only.
4. **Every rule not passed gets a line** in a deviation register signed by the authorising official: stricter-than-DISA, risk-accepted decision, or a finding with a plan. Anything failing that is *not* in the register is a gap — that is the whole discipline.
5. **Freeze the result.** After the scans, take a tenant snapshot (`scripts/Baseline-Snapshot.ps1 -Mode Export`), compare it with the previous approved one, match every difference to the change log, and have it approved as the new baseline. Sanctir's 21 October snapshot holds 130 tenant objects; the comparison with 16 October showed 17 added and 12 changed objects, every one matched to a recorded change.

## Why SCC is not used

DISA's SCAP Compliance Checker ships about a hundred unsigned runtime libraries. Sanctir's App Control policy (allow-listing) blocks them, and allowing them one by one would weaken the control the STIG itself requires. The benchmark content is data — XCCDF rules pointing at OVAL definitions — so the evaluator reads DISA's file and evaluates the OVAL definitions in PowerShell, listing what it found for every rule so a person can check any result by hand. It is not SCC, and the results say so.

## What it took

The 20–21 October work that produced these numbers, in the order it was done — each step is a policy or remediation in this repository:

1. **Sign-in reduced to two methods**: administrator = CAC (certificate-based authentication) only; daily user = FIDO2 security key only; Windows Hello turned off and its keys purged; every other sign-in tile removed. See [08 — CAC and security-key-only sign-in](08-cac-and-security-key-only-sign-in.md).
2. **DISA's own packages as tenant policies**: `REF-DefenderAV-STIG`, `REF-M365Apps-STIG`, `REF-Edge-STIG`, plus `REF-STIGRegistry` for the handful of DISA registry values the settings catalog cannot express (OneDrive pop-up management, .NET strong crypto).
3. **Cloud STIGs**: lockout, banner, banned-password list, idle timeouts, Entra and Intune logs to Sentinel, multi-admin approval for device wipe.
4. **Central Log Server SRG** against Sentinel.
5. **Drift fixed at the source**: two settings each had two tenant owners (Office file validation; Defender local-admin merge, where the second owner was the same setting in another form and the MDM client itself wrote the wrong value). One owner per setting, always — and find the writer with an audit before removing anything.
6. **Operational holes found on the way** (and now held by remediations): a stalled OneDrive client that nothing noticed for 14 hours (`remediations/OneDriveHealth/`); DNS leaking to the router for about a second on VPN reconnect (`remediations/DNSGuard/`); a vendor network driver suite that Windows Update kept re-installing (`remediations/KillerSuite/` plus a declined driver in the Intune driver-update profile).
