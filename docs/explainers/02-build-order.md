# 02 — Build order

Deploy in this order. Each layer assumes the one before it; doing it out of order is how you lock yourself out of your own tenant (Sanctir did, once, and the break-glass account was the way back in).

Every step below names the tenant object and the script or template in this repository that creates it. `-Apply` is required for any change; without it, every script reports what it would do.

## 0. Before anything

- Licensing with Entra ID P2 (PIM, Conditional Access, Identity Protection), Intune, Defender for Endpoint, Purview audit. Microsoft 365 Business Premium plus the Entra P2 add-on is the smallest set that works.
- Three hardware security keys minimum (daily, admin, break-glass), FIPS-validated for CUI.
- A second person, or at least a second channel, who can receive alerts. An alert nobody reads is the same as no alert.
- Fill in `config.json`. Everything from here reads it.

## 1. Identity (nothing else is safe until this is)

1. **Break-glass account**, cloud-only, excluded from every Conditional Access policy, with a FIDO2 key registered and kept locked away. Test it end to end once and record the test.
2. **Admin account**, separate from the daily user, with **eligible** (not active) Global Administrator through PIM; activation requires a reason and expires. The daily account holds no directory role at all.
3. **Authentication methods policy**: FIDO2 on with attestation enforced; Microsoft Authenticator push, SMS, voice, e-mail and software OATH **off**; Temporary Access Pass one-time use with a short lifetime, for enrolment and recovery only. Every member registers a key before this is enforced.
4. **Conditional Access**, in this order, each in report-only first: require compliant device; require phishing-resistant authentication strength; block legacy authentication; sign-in frequency; block the device-code flow and authentication transfer; token protection for Exchange, SharePoint and Teams on Windows (exclude the admin account: command-line tools cannot bind tokens); mobile app protection. Scripts: `policies/conditional-access/`.
5. **Admin tooling**: restrict the Microsoft Graph Command Line Tools service principal to the admin and break-glass accounts ("assignment required"). Sign in with `Connect-Tenant.ps1`, never with device code.

## 2. Endpoint baseline

6. **Enrol** devices in Intune as Entra-joined, company-owned. Create one device group that every policy targets.
7. **Settings-catalog policies**, each a separate object so it can be assigned, exported and compared on its own: security baseline (user rights, audit policy, security options), BitLocker (TPM + PIN, XTS-AES-256, recovery key escrow), Defender (real-time, cloud block level, ASR rules, tamper protection), firewall (all profiles on, inbound default block, outbound default block with named allows, logging), credential and network hardening, sign-in screen (no last user, Ctrl+Alt+Del), power (lid, power and sleep buttons shut down; standby disabled where the hardware allows), Windows Hello / passwordless, time source, update rings, LAPS. Scripts: `policies/settings-catalog/`.
8. **Compliance policy**: encryption, firewall, antivirus, secure boot, code integrity, minimum OS version. Non-compliant devices are blocked by Conditional Access from step 4.
9. **App Control (WDAC)**: audit mode first for two weeks, read the 3076/3077 events, then enforce. Template in `policies/app-control/`.
10. **Remediations** that hold the baseline in place (`remediations/`): service baseline and watchdog; discovery services off (SMB server, WPAD, LLMNR, mDNS, SSDP); firewall local-rule lockdown; versioned-path firewall rules; consistency scanner (hourly, writes to the event log); standby-hibernate guard; unmanaged-app removal. Deploy with `scripts/Deploy-Remediation.ps1`.

## 3. Logging and alerting

11. **Log Analytics workspace + Sentinel**, the Azure Monitor agent on every device, one **data collection rule** for Security, System, Application, Defender, Code Integrity and the custom event log the scanner writes to. Entra sign-in and audit logs, and Office 365 activity, connected.
12. **Immutable archive**: continuous export of the security tables to a storage account with a time-based immutability policy, **locked** once the export is proven live. A locked policy cannot be shortened by any administrator.
13. **Alert rules** (`alerting/`): break-glass sign-in of any kind; privileged role assignment; audit policy or log tampering; Defender detection or protection change; new service, task or driver (persistence); privilege or account change; firewall change (hourly summary); interactive logon; workstation silent without a shutdown; consistency scanner failed or silent; any new high-severity incident. Start with the generic exclusions here, then **measure** what fires for a week and tune from the measured rows, never from assumption.
14. **Action group**: e-mail and SMS to the Security Officer.

## 4. Baseline and operations

15. `Baseline-Snapshot.ps1 -Mode Export`. Approve the folder in your baseline standard. From now on every tenant change is a register entry and a new snapshot.
16. Daily: `Review-AlertQueue.ps1`, `Triage-NewIncidents.ps1`; close everything with its cause. Weekly: DLP matches. Monthly: sign-in review, App Control blocks. Annually: the full audit (`05-run-your-own-audit.md`).
17. Only now: score yourself (`START-HERE.md` §4) and post.
