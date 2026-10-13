# 06 — Tenant set-up and enrolment: from an empty tenant to enrolled, compliant devices

The commands below are the ones you type. Each script here prints its plan without `-Apply` and refuses to create a duplicate; run every one read-only first.

## 1. The tenant

1. Microsoft 365 **E5** (or your chosen plan with Entra ID P2, Intune, Defender for Endpoint P2 and Purview); one licence per person. Add the **Microsoft Sentinel** and **Azure** subscription for logging (pay-as-you-go).
2. In Entra: create the **admin account** (cloud-only, no mailbox needed), the **break-glass account** (cloud-only, long random password stored sealed, a FIDO2 key registered and locked away), and one **device group** that every policy will target. Put the ids and names into `config.json`.
3. Make the admin account **eligible** (not active) for Global Administrator in PIM; activation requires a reason and expires. The daily account holds no role.
4. Register a FIDO2 key for every account before step 8; the authentication-methods script refuses to run until every member has one.

## 2. The policies, from this repository

```powershell
# sign in once (admin account, security key)
. .\scripts\Connect-Tenant.ps1; Connect-Tenant

# compliance first: Conditional Access will require a compliant device
Get-ChildItem .\policies\compliance\*.json | ForEach-Object { .\policies\Deploy-CompliancePolicy.ps1 -Definition $_.FullName }          # read-only pass
Get-ChildItem .\policies\compliance\*.json | ForEach-Object { .\policies\Deploy-CompliancePolicy.ps1 -Definition $_.FullName -Apply }

# the endpoint baseline (41 settings-catalog policies) and the OMA-URI profiles
Get-ChildItem .\policies\settings-catalog\*.json | ForEach-Object { .\policies\Deploy-SettingsCatalogPolicy.ps1 -Definition $_.FullName }
Get-ChildItem .\policies\settings-catalog\*.json | ForEach-Object { .\policies\Deploy-SettingsCatalogPolicy.ps1 -Definition $_.FullName -Apply }
Get-ChildItem .\policies\device-configuration\*.json | ForEach-Object { .\policies\Deploy-DeviceConfiguration.ps1 -Definition $_.FullName -Apply }

# Conditional Access: created in REPORT-ONLY, always
Get-ChildItem .\policies\conditional-access\*.json | ForEach-Object { .\policies\Deploy-ConditionalAccessPolicy.ps1 -Definition $_.FullName -Apply }
```

Then, in this order, over days not minutes: enrol the devices (section 3), let them report compliant, read the report-only results of each Conditional Access policy in the sign-in logs, and enable them one at a time (compliant device → authentication strength → block legacy → sign-in frequency → block device code → token protection, with the admin account excluded → app protection). Last:

```powershell
.\policies\Set-AuthMethodsPolicy.ps1          # read-only: shows every member's keys and the current state
.\policies\Set-AuthMethodsPolicy.ps1 -Apply   # key-only sign-in from here on
```

## 3. Enrolling devices

Company-owned Windows 11 Pro/Enterprise laptops, **Entra-joined** (not hybrid, not registered), enrolled in Intune at first sign-in. Windows Autopilot makes a wiped or new laptop arrive at the sign-in screen already in the tenant's hands; without Autopilot, "Set up for work or school" during the out-of-box experience does the same by hand.

1. Sign in on the device with the daily account and its security key. Enrolment and the device-group membership happen automatically; within an hour every policy above is applied.
2. **BitLocker** asks for the pre-boot PIN at first policy application; the recovery key is escrowed to the tenant.
3. Check: Intune → Devices → the device → **Device configuration** (every policy Succeeded) and **Compliance** (Compliant). Anything Pending after two syncs is verified on the device before it is called a failure.
4. Run `scripts\Audit-Tenant.ps1` and read §3 and §4 for that device.
5. **App Control** goes on last, in audit mode first: read the Code Integrity events for two weeks (every program you actually use will appear), then switch to enforced. A machine with App Control enforced will not run installers that are not on the list, including some of your own tools; `Connect-Tenant.ps1` needs no module for that reason.

The phone: Intune company portal, supervised if it will hold CUI, the iOS compliance and app-protection policies here, Outlook and Teams as managed apps only.

## 4. Logging

Follow `02-build-order.md` §3: workspace, agent, data collection rule, the immutable export (lock it once it is proven live), the alert rules from `alerting/` with their generic exclusions, the action group. Measure for a week before tuning.

## 5. Freeze the baseline

```powershell
.\scripts\Baseline-Snapshot.ps1 -Mode Export
```

Approve the folder in your baseline standard (template in `docs/templates/`). From now on, every change is a register entry, and `-Mode Compare` is how you prove nothing else moved.

## 6. The network path (Cloudflare Zero Trust)

Create the Zero Trust organisation with Entra ID as its only identity provider; deploy the WARP client through Intune with the device profile set to always-on and locked (the user cannot disconnect); build the Gateway rules **allow-first, then log, then block**, with at least 24 hours of logs reviewed before any block is switched on. The rule set Sanctir runs is in the Gateway standard template; the order and the measurement method matter more than the exact list.

## 7. Verify you are where you think you are

`Audit-Tenant.ps1`, `Baseline-Snapshot.ps1 -Mode Compare`, `Evaluate-STIG.ps1`, `Review-AlertQueue.ps1` — all clean, all in `Evidence\`. Then, and only then, `START-HERE.md` §4.
