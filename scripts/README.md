# scripts/

PowerShell 7. Every script dot-sources `_Common.ps1`, which loads `config.json` (your tenant's values; never committed) and gives every run a timestamped file under `Evidence\<date>\`. Nothing changes anything without `-Apply`; the review script needs an explicit `-Close` or `-CloseAll` with a comment.

| Script | Purpose | Changes anything? |
|---|---|---|
| `Connect-Tenant.ps1` | Module-free Graph and Azure sign-in (browser PKCE on this machine); defines `Invoke-MgGraphRequest`, `Get-MgContext`, `Get-ArmToken` | No |
| `Audit-Tenant.ps1` | The management-plane audit: devices, compliance, remediations, per-device policy state, Conditional Access, auth methods, Sentinel health | No |
| `Baseline-Snapshot.ps1` | Export the whole tenant configuration as the approved baseline; compare the live tenant against it | No (writes files locally) |
| `Review-AlertQueue.ps1` | Daily: every New alert with what its rule matched; close with the cause as the record | Only with `-Close` / `-CloseAll` |
| `Triage-NewIncidents.ps1` | Daily: closes two routine incident types on primary evidence; leaves everything else open | Only with `-Apply` |
| `Evaluate-STIG.ps1` | Evaluates any DISA SCAP benchmark (Windows 11, Defender AV, Firewall, Office, Edge) on this machine in PowerShell, without SCC; reads the daily user's hive from `-UserProfile`; every rule result with what was found | No |
| `Evaluate-CloudSTIG.ps1` | The 13 Entra ID V1R2 and Intune MDM V1R2 rules (session lock, inactive accounts, lockout, banner, logs to the SIEM, MFA, password lifetime, PIM alerts and standing roles, banned passwords, idle timeout, multi-admin approval) through Graph and Azure | No |
| `Evaluate-NSA-SHB.ps1` | NSA Secure Host Baseline checks | No |

Conventions, learned the hard way and worth keeping:
- **Read-only first, every time.** Run without `-Apply`, read the output, then apply in the same window.
- **Back up before writing, read back after.** Every applying script in this repository saves the object it is about to change under `ConfigBackup\<date>\` and prints the read-back; if the read-back does not match, it says so and stops.
- **One tenant change runs once, in one window, from one machine.** Two windows writing the same object produce etag conflicts and a false sense of what is live.
- **Never name a helper function after a built-in alias.** `sv` is Set-Variable, `r` is Invoke-History, `h` is Get-History: a function called `SV` silently never runs (we sent Intune an empty list that way).
- **Never `exit` from a script you run as a scriptblock** — it closes the window and whatever was queued after it never runs. Return, and set `$LASTEXITCODE`.
- **Sign in with a security key (or CAC) as the admin account; never with device code.** The flow in `Connect-Tenant.ps1` returns the token only to the machine that asked.
- **Deactivate the privileged role when the session is done.** The scripts do not need standing rights, and the alert rules will tell you about every activation.
