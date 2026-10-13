# scripts/

PowerShell 7. Every script dot-sources `_Common.ps1`, which loads `config.json` (your tenant's values; never committed) and gives every run a timestamped file under `Evidence\<date>\`. Nothing changes anything without `-Apply`; the review script needs an explicit `-Close` or `-CloseAll` with a comment.

| Script | Purpose | Changes anything? |
|---|---|---|
| `Connect-Tenant.ps1` | Module-free Graph and Azure sign-in (browser PKCE on this machine); defines `Invoke-MgGraphRequest`, `Get-MgContext`, `Get-ArmToken` | No |
| `Audit-Tenant.ps1` | The management-plane audit: devices, compliance, remediations, per-device policy state, Conditional Access, auth methods, Sentinel health | No |
| `Baseline-Snapshot.ps1` | Export the whole tenant configuration as the approved baseline; compare the live tenant against it | No (writes files locally) |
| `Review-AlertQueue.ps1` | Daily: every New alert with what its rule matched; close with the cause as the record | Only with `-Close` / `-CloseAll` |
| `Triage-NewIncidents.ps1` | Daily: closes two routine incident types on primary evidence; leaves everything else open | Only with `-Apply` |

Conventions, learned the hard way and worth keeping:
- **Read-only first, every time.** Run without `-Apply`, read the output, then apply in the same window.
- **Back up before writing, read back after.** Every applying script in this repository saves the object it is about to change under `ConfigBackup\<date>\` and prints the read-back; if the read-back does not match, it says so and stops.
- **One tenant change runs once, in one window, from one machine.** Two windows writing the same object produce etag conflicts and a false sense of what is live.
- **Sign in with a security key as the admin account; never with device code.** The flow in `Connect-Tenant.ps1` returns the token only to the machine that asked.
- **Deactivate the privileged role when the session is done.** The scripts do not need standing rights, and the alert rules will tell you about every activation.
