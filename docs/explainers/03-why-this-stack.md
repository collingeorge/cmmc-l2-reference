# 03 — Why this stack: what each part does, which requirement it carries, and what it cost

A small supplier does not get to CMMC Level 2 by buying tools; it gets there by having **fewer** things, each of which does a lot, all configured from one place. This is what Sanctir runs, why, and what each piece gives you against NIST SP 800-171.

## Microsoft 365 E5 (commercial)

E5 is the smallest Microsoft plan that contains every component below without add-ons. Business Premium plus the Entra ID P2 add-on gets close, and Sanctir started there, but it misses Defender for Endpoint Plan 2's full investigation and the Purview features, and the add-on arithmetic ends up near E5 anyway. One licence per person, no server, no appliance.

| Component (in E5) | What it carries | Requirements it answers |
|---|---|---|
| **Entra ID P2** | Conditional Access (compliant device, phishing-resistant authentication strength, token protection, blocked legacy and device-code flows), Privileged Identity Management (admin rights that expire), Identity Protection, sign-in and audit logs | 3.1.1, 3.1.2, 3.1.5, 3.1.7, 3.1.12, 3.5.1–3.5.4, 3.5.11 |
| **Intune** | Every device setting as a tenant object: BitLocker, firewall, Defender, App Control, audit policy, user rights, screen lock, power, LAPS, updates; compliance; remediations that detect and repair drift; iOS management and app protection | 3.1.10, 3.1.18–3.1.19, 3.4.1–3.4.9, 3.7.x, 3.8.7–3.8.8, 3.13.11, 3.13.16, 3.14.1–3.14.2 |
| **Defender for Endpoint Plan 2** | Real-time protection, attack-surface-reduction rules (credential theft, Office child processes, script abuse), tamper protection, device control, vulnerability management, the detection events Sentinel alerts on | 3.14.1–3.14.7, 3.11.2 |
| **Purview** | Unified audit log (every admin and user action in the cloud), sensitivity labels and DLP for CUI, retention, the alert policies for audit-configuration and break-glass events | 3.1.3, 3.3.1–3.3.2, 3.8.4, 3.8.9 |
| **Exchange / SharePoint / OneDrive / Teams** | Where the CUI lives, inside the same boundary, with the same identity and device controls on every door | 3.1.20, 3.8.1–3.8.3, 3.13.8 |

**What E5 commercial does not give you:** a FedRAMP-equivalent cloud for the CUI itself, which DFARS 7012 paragraph (b)(2)(ii)(D) requires when a cloud service *stores or processes* covered defense information. Sanctir's SSP records the boundary and that question explicitly; GCC High is the Microsoft answer for suppliers whose contracts require it, and everything in this repository is built to move there unchanged (the same Intune, Entra, Defender and Sentinel APIs). Decide this with your contracting officer before you accept CUI into the tenant; do not assume.

## Microsoft Sentinel and Azure Monitor (pay-as-you-go, a few dollars a month at this size)

The audit trail has to leave the device, land somewhere an attacker who owns the device cannot reach, and stay there. Azure Monitor's agent sends the Windows Security, System, Application, Defender, Code Integrity and custom logs to a Log Analytics workspace; Entra and Office 365 connect natively; Sentinel runs the detection rules and holds incidents; a continuous export writes the security tables to a storage account whose immutability policy is **locked**, so no administrator, including you, can shorten it. Requirements 3.3.1–3.3.9 and 3.6.1–3.6.2 are mostly this one service, plus the discipline of reading it.

## Cloudflare Zero Trust (Standard plan) and WARP

Every device carries an always-on, locked WARP tunnel. DNS and network traffic goes through Cloudflare Gateway, where policies block security threats (malware, phishing, command-and-control, cryptomining, DGA domains, DNS rebinding), peer-to-peer, remote-control tools, parked domains, unapproved AI services, and consumer storage and file-transfer services, and allow the management, identity, security and approved services explicitly, before any block. Entra ID is the only identity provider for the tunnel. Gateway keeps 30 days of logs, and a daily job copies the DNS record into Sentinel for 90.

Why it is secure, and why it matters for a laptop that travels: the device never talks to the local network's DNS or gateway for anything but the tunnel itself. On an airport or hotel network the tunnel *is* the network: captive portals, hostile DNS, proxy auto-discovery and neighbouring devices never reach Windows, and every name the device resolves and every connection it opens passes a policy you wrote and a log you can read. The tunnel is locked so a user cannot switch it off, the identity provider is the same Entra ID that gates everything else, and the policies are allow-first so management, identity and security traffic can never be caught by a later block. That is what lets requirements 3.13.1, 3.13.5, 3.13.6 and 3.1.20 be true *everywhere*, not only in the office, with no appliance and no VPN concentrator to maintain. Cloudflare has been rolling out post-quantum hybrid key agreement across its network and the WARP client since 2024; Sanctir configured nothing for it and nothing needs to be, but if a contract asks, the WARP client's connection details show the key agreement in use. How the rules were built, measured and switched on is in the Gateway standard template in `docs/templates/`.

## Hardware security keys

FIDO2 keys with **FIPS 140 validated** cryptography (Sanctir: YubiKey 5 FIPS Series). Every sign-in, every account, including the break-glass account on its own key kept locked away. Verify the vendor's certificate on NIST's CMVP list: https://csrc.nist.gov/projects/cryptographic-module-validation-program. This is requirement 3.5.3 done in a way that cannot be phished, and it removes the entire password and push-notification attack surface from the identity.

## DoD certificates and PKI

- **ECA medium-assurance certificate** (DoD's External Certification Authority programme): https://public.cyber.mil/eca/. Required to file a cyber-incident report in DIBNet (https://dibnet.dod.mil/) within the 72 hours clause 7012 allows. Issued in person after identity proofing; can be loaded onto your own FIPS YubiKey; a few hundred dollars a year. Order it before you hold CUI, not after an incident.
- **DoD root and intermediate certificates** (InstallRoot), for trusting DoD-signed sites and documents: https://public.cyber.mil/pki-pke/tools-configuration-files/.
- **DoD Cyber Exchange** (public side): https://public.cyber.mil/ — STIGs, SCAP content, PKI tools, policy.

## Benchmarks and SCAP tools

- **DISA STIGs** for Windows 11, Edge, Office, Defender, and the **SCAP Compliance Checker (SCC)**: https://public.cyber.mil/stigs/scap/. SCC is the official scanner. On a machine with App Control enforced it will not run unless you allow its signer, so this repository carries `scripts/Evaluate-STIG.ps1`, which reads DISA's own benchmark and scores the effective state without installing anything; use SCC where you can, the evaluator where you cannot, and record which.
- **STIG Viewer**: same page; for reading the checks and recording your deviations.
- **NSA Windows Secure Host Baseline** (archived 2023, Windows 10-era, still a useful second opinion): https://github.com/nsacyber/Windows-Secure-Host-Baseline. `scripts/Evaluate-NSA-SHB.ps1` evaluates its declarative checks against Windows 11 without running NSA's installer scripts.
- **CIS Benchmarks** are a third option; Sanctir did not use them, DISA and NSA being the DoD-side references.

## What it cost, honestly

One E5 licence per person; Sentinel and storage at a few dollars a month for two laptops; Cloudflare Zero Trust Standard at the per-user rate; three FIPS keys; the ECA certificate; and the owner's time, which was the largest item by far and is what this repository is trying to give back.
