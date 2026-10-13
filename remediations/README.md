# remediations/

Intune **remediations** (detection script + remediation script, run as SYSTEM on a schedule) are how the baseline stays in force on a device between policy syncs, and how anything that cannot be expressed as a policy is held in place. Each one here is either a ready pair (`Detect.ps1` / `Remediate.ps1`) or a **builder** (`Build.ps1`) that generates the pair from one shared core, so the detection, the remediation and any local runner they install can never disagree.

| Folder | Kind | What it holds in place |
|---|---|---|
| `ServiceBaseline/` | builder | Services that must run (monitoring agent, Defender, Intune agent, time, push) with recovery; services that must not; a local watchdog task that restarts a stopped critical service within a minute |
| `Consistency/` | builder | The hourly on-device scan of ~24 checks (remediation scheduler, Defender updates and scans, MDM check-in, service baseline, event-log sizes, time sync, BitLocker, local administrators, update channels, drift guards) writing results to a custom event log that Sentinel collects. **Edit the expectations block** (expected administrators, NTP peers, log sizes) for your tenant |
| `FWLocalLockdown/` | builder | Disables any local firewall rule that is not in the tenant's set within seconds of its creation |
| `FW-VersionedPaths/` | builder | Keeps outbound allow rules pointed at the current binary of programs installed in version-numbered folders (Store apps, WebView2, OneDrive), re-checked every five minutes |
| `StandbyHibernate/` | builder | Hibernates a machine that has been locked for N minutes so disk-encryption keys do not sit in memory during Modern Standby (observe mode first, then enforce) |
| `STIGGap/` | builder | Closes the DISA STIG items that have no settings-catalog equivalent, with a guard task that re-applies them |
| `DiscoveryOff/` | pair | SMB server, WPAD, LLMNR, mDNS, SSDP/UPnP, network discovery off |
| `AMA-Token/` | pair | Repairs the Azure Monitor agent's identity token when it stops reporting |
| `Defender-Signatures/` | pair | Forces a signature update when the age exceeds the threshold |
| `Consumer-Apps/` | pair | Removes consumer Store apps from a work device |
| `Office-Hardening/`, `Platform-Hardening/` | pair | Office macro and trust settings; platform settings (FIPS, SMB signing, etc.) that policy cannot reach |
| `UserExperience/` | pair | The user-facing settings a standard user is allowed to see, held consistent |
| `CodexRemoved/` | pair | Example of removing an unmanaged desktop app and disabling the local accounts it created; adapt the package name |
| `DiskHygiene/`, `EndpointHealth/`, `UpdateHealth/`, `DailyAudit/` | detect-only | Report into the event log; nothing to remediate |

## Deploy

```powershell
. .\scripts\Connect-Tenant.ps1; Connect-Tenant
# builders first: generate the pair next to the builder
.\remediations\ServiceBaseline\Build.ps1
.\remediations\Deploy-Remediation.ps1 -DisplayName 'REF-ServiceBaseline' -Description '...' -DetectPath .\remediations\ServiceBaseline\REF-ServiceBaseline-Detect.ps1 -RemediatePath .\remediations\ServiceBaseline\REF-ServiceBaseline-Remediate.ps1 -Schedule Hourly
# a ready pair
.\remediations\Deploy-Remediation.ps1 -DisplayName 'REF-DiscoveryOff' -Description 'SMB server, WPAD, LLMNR, mDNS, SSDP off' -DetectPath .\remediations\DiscoveryOff\Detect.ps1 -RemediatePath .\remediations\DiscoveryOff\Remediate.ps1
# change an existing one's scripts without touching its assignment or schedule
.\remediations\Update-Remediation.ps1 -DisplayName 'REF-DiscoveryOff' -DetectPath ... -RemediatePath ...
```

Conventions: every remediation refuses to run unelevated; every remediation writes one event per run to the custom event log (source named after the remediation) so Sentinel can alert on a failure; every change a remediation makes is a correction toward the tenant's stated state, never a new setting of its own.
