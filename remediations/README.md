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
| `STIGRegistry/` | builder | The DISA registry values no settings-catalog policy can set (OneDrive pop-up management, .NET strong crypto, Office values from the CSV), held hourly — one owner per value, never a second writer |
| `OneDriveHealth/` | builder | Hourly heartbeat upload test per signed-in user; a OneDrive that has stopped syncing (or is not running) is restarted **in that user's session** without admin rights; events 4301–4303. Waits 30 minutes after boot or wake |
| `DNSGuard/` | builder | Blocks the Windows DNS client from reaching anything but the VPN's local resolver, so a VPN reconnect cannot leak DNS to the router; releases after 3 minutes of real outage so a machine is never taken offline. Edit the pilot host list |
| `KillerSuite/` | pair | Removes a vendor network-utility suite (Killer/Rivet) and keeps the adapter on Microsoft's in-box driver. Pair it with a **declined** (or, if already approved, **suspended**) driver in an Intune driver-update profile, or Windows Update re-installs it |
| `RegistryWriterAudit/` | builder, temporary | Adds one audit entry to a registry key and reports every Security 4657 for it (process, account, old → new value) — how to find "what keeps resetting this setting". At Sanctir it showed that Windows' own MDM client rewrote a Defender value at every Intune sync because the same setting was deployed in two forms (CSP and ADMX). Rebuild with `-Mode Remove` to take it off |

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
