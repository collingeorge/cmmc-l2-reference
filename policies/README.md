# policies/

The tenant objects that make up the endpoint and identity baseline, exported from a working tenant with every tenant-specific identifier removed, plus one deploy script per object type. Each definition is a complete Graph payload; the deploy script adds the assignment (to `devices.deviceGroupId` in `config.json`) and refuses duplicates.

| Folder | Count | Deploy with | Notes |
|---|---|---|---|
| `settings-catalog/` | 41 | `Deploy-SettingsCatalogPolicy.ps1` | One policy per concern so each can be assigned, exported and compared on its own. Microsoft template ids are kept; a template-based policy only accepts settings from its template |
| `device-configuration/` | 5 | `Deploy-DeviceConfiguration.ps1` | Custom OMA-URI profiles for settings the catalog does not expose |
| `compliance/` | 2 | `Deploy-CompliancePolicy.ps1` | Windows and iOS. Conditional Access requires a compliant device, so deploy these first |
| `conditional-access/` | 9 | `Deploy-ConditionalAccessPolicy.ps1` | Always created report-only; account placeholders resolved from config; the break-glass account is excluded from every policy |
| `authentication-methods/` | 1 | `Set-AuthMethodsPolicy.ps1` | The exported policy is for reference; the script sets the key-only state directly and checks every member holds a key first |
| `app-protection/` | 1 | *(manual for now)* | iOS app-protection policy for a managed phone; deploy script in a later batch |

## Naming

`REF-<family>-<concern>`. The family prefixes follow NIST SP 800-171 (AC, AU, CM, IA, SC, SI, …) so an assessor can map a policy to a requirement by name. Rename as you like with `-Name`.

## Order

Compliance → settings catalog (security baseline, BitLocker, Defender, firewall, credential/network, sign-in screen, power, passwordless, time, updates, LAPS) → device configuration → Conditional Access (report-only, then enabled one by one after reading the results) → authentication methods last, once every member has a key. The full order with reasons is in `docs/explainers/02-build-order.md`.

## What was left out, and why

- The firewall **allow-lists** (which programs may talk out) and the **App Control** allow-list: they are the organisation's blind-spot map. Build your own from measured blocks (the firewall-blocks audit policy here logs every refusal so you can).
- One **device-control** policy that references an Intune *reusable setting* (a device group defined as its own tenant object); recreate the reusable setting in your tenant, then the policy.
- Assignments, scope tags and the source tenant's ids.

Every definition passed `tools/scrub.ps1` before publication. If you find an identifier we missed, open an issue.
