# REF-EndpointHealth-Detect - Intune remediation DETECTION script. Runs hourly as SYSTEM.
# Exit 0 = every control below is healthy. Exit 1 = at least one is not; the failing controls are
# named in the output (visible in Intune) and written to the SANCTIR event log as event 1330.
#
# WHY THIS EXISTS. Between 25 and 30 September 2026 this estate had, in sequence:
#   - Windows Update dead for four days on both endpoints, undetected
#   - an Intune enrolment stuck in failed certificate recovery, undetected for four days
#   - Defender's cloud path blocked for 2h50m by a firewall change, found by accident
#   - the EDR sensor blocked after a rebuild, found by accident
#   - no LAPS backup on one endpoint, discovered only when it caused a lockout
#   - the Sentinel telemetry agents missing after a rebuild, discovered only by a manual check
# Every one was survivable. What made each expensive was that the machine went on reporting
# healthy. The Security Officer's requirement: "we can't have a rule showing up a day or two
# weeks later and an update was stale or the time wasn't syncing or something else was broke."
# No script can promise nothing will break. This one guarantees it cannot break SILENTLY: the
# same controls that were verified by hand on 30 September are re-measured every hour.
#
# DESIGN RULES, each learned the hard way that week:
#   - DETECTION ONLY. It changes nothing. A fix applied blind by SYSTEM is how 42 rules got
#     deleted and Defender went dark.
#   - Every check here ran clean on BOTH endpoints before this was deployed. Checks that gave
#     false failures during verification (Get-AppxPackage under PowerShell 7, a fixed OS build
#     number, a Windows service that AMA does not have, self-stopping services read as drift)
#     were fixed or removed. An alarm that fires on a healthy machine trains its reader to
#     ignore it.
#   - Unknown is a failure. A check that cannot read its state reports FAIL, never OK.
#   - Decisions are not findings. Device-local firewall rules are accepted on these endpoints
#     and are deliberately not checked here.

$ErrorActionPreference = 'SilentlyContinue'
$fail = New-Object System.Collections.ArrayList
function Bad($m) { [void]$fail.Add($m) }
$info = New-Object System.Collections.ArrayList
function Note($m) { [void]$info.Add($m) }   # measured value, printed on every run so the Intune output shows numbers, not just OK

# ---------- identity and enrolment ----------
if (-not (dsregcmd /status | Select-String 'AzureAdJoined\s*:\s*YES')) { Bad 'device is not Entra joined' }
$enr = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' | Where-Object { (Get-ItemProperty $_.PSPath).ProviderID -eq 'MS DM Server' })
if ($enr.Count -ne 1) { Bad "Intune enrolments: $($enr.Count), expected 1" }
else {
    $ep = Get-ItemProperty $enr[0].PSPath
    Note "enrolment state=$($ep.EnrollmentState) recovery=$($ep.RecoveryStatus)"
    if ($ep.EnrollmentState -ne 1) { Bad "EnrollmentState=$($ep.EnrollmentState), expected 1 (6 = stuck in recovery)" }
    if ($ep.RecoveryErrorCode -and $ep.RecoveryErrorCode -ne 0) { Bad ("enrolment recovery error 0x{0:X8}, RecoveryStatus={1}" -f [uint32]$ep.RecoveryErrorCode, $ep.RecoveryStatus) }
}
$mc = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Issuer -match 'Intune MDM Device CA' } | Sort-Object NotAfter -Descending | Select-Object -First 1
if (-not $mc -or -not $mc.HasPrivateKey) { Bad 'MDM device certificate missing or has no private key' }
else { Note "MDM cert expires $($mc.NotAfter.ToString('yyyy-MM-dd'))" }
if ($mc -and $mc.NotAfter -lt (Get-Date).AddDays(14)) { Bad "MDM device certificate expires $($mc.NotAfter.ToString('yyyy-MM-dd'))" }

# ---------- LAPS: is the break-glass password actually recoverable? ----------
# Absence of this is what turned an enrolment repair into a full rebuild on 30 September.
if (-not (Get-LocalUser REF-la)) { Bad 'LAPS account REF-la does not exist' }
$lapsReg = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State').LastPasswordUpdateTime
$lapsEvt = Get-WinEvent -FilterHashtable @{ LogName = 'Microsoft-Windows-LAPS/Operational'; Id = 10029, 10020; StartTime = (Get-Date).AddDays(-35) } -MaxEvents 1
Note "LAPS last backup $(if($lapsEvt){$lapsEvt.TimeCreated.ToString('yyyy-MM-dd HH:mm')}elseif($lapsReg){'registry '+$lapsReg}else{'NONE'})"
if (-not $lapsReg -and -not $lapsEvt) { Bad 'no evidence of a LAPS password backup in the last 35 days - the local admin may be unrecoverable' }

# ---------- firewall posture ----------
foreach ($p in (Get-NetFirewallProfile -PolicyStore ActiveStore)) {
    if (-not $p.Enabled -or "$($p.DefaultOutboundAction)" -ne 'Block' -or "$($p.DefaultInboundAction)" -ne 'Block') { Bad "$($p.Name) firewall profile is not deny-by-default (enabled=$($p.Enabled) in=$($p.DefaultInboundAction) out=$($p.DefaultOutboundAction))" }
}
$mdmRules = @(Get-NetFirewallRule -PolicyStore ActiveStore -Direction Outbound | Where-Object { "$($_.PolicyStoreSourceType)" -eq 'MDM' }).Count
Note "tenant firewall rules=$mdmRules"
Note "Public inbound allows honoured=$((Get-NetFirewallProfile -PolicyStore ActiveStore -Name Public).AllowInboundRules) (False = Shielded)"
if ($mdmRules -lt 100) { Bad "only $mdmRules tenant firewall rules present - policy is not landing" }

# ---------- is anything that matters being refused by our own firewall? ----------
# This is the check that would have caught every firewall-caused failure that week within the
# hour, including the ones caused by a binary moving to a new version-numbered folder.
if (-not ((auditpol /get /subcategory:"Filtering Platform Connection") -match 'Failure')) { Bad 'firewall block auditing (5157) is not enabled - blocks are invisible' }
else {
    $crit = 'msmpeng|nissrv|mpdefendercoreservice|mssense|sensecm|senseir|\\monagent|amacoreagent|amaservice|fluent-bit|metricsextension|azcmagent|himds|gc_arc_service|gc_extension_service|agentexecutor|intunewindowsagent|omadmclient|deviceenroller|warp-svc\.exe \| port 443|lsass\.exe \| port 443|onedrive\.sync\.service|filesynchelper'
    # 1 Oct 2026: lsass and the OneDrive sync components added. The first hour of block auditing on the rebuilt
    # WS01 showed lsass.exe refused at every sign-in on its way to Microsoft Entra (no tenant rule named it; rule
    # 'CUI Allow lsass Entra-SignIn' added that day, scoped to Microsoft's published sign-in ranges - if those ranges
    # change, this is what reports it), and OneDrive's sync service refused 1,300 times after an update moved it to
    # a new version folder.
    # Properties by index (1 Application, 6 DestPort) - far faster than XML per event.
    $blkEv = @(Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 5157; StartTime = (Get-Date).AddMinutes(-60) } -MaxEvents 8000 | ForEach-Object {
        [pscustomobject]@{ Time = $_.TimeCreated; Key = (("$($_.Properties[1].Value)" -replace '.*\\', '') + ' | port ' + $_.Properties[6].Value) }
    } | Where-Object { $_.Key -match $crit })
    $blk = @($blkEv.Key)
    # A policy (re)application reloads the firewall's rules, and for a few seconds everything falls to
    # the default block. Measured on WS01 30 Sep 2026: 20 blocks on himds/warp-svc/msmpeng, all within
    # 16:22:03-16:22:08, none before or after. That is a known transient, not a fault, and must not
    # raise an alarm for an hour after every policy change. Blocks spread over more than two minutes,
    # or still arriving in the last ten, are the real thing.
    $span   = if ($blkEv.Count) { [int](($blkEv.Time | Measure-Object -Maximum).Maximum - ($blkEv.Time | Measure-Object -Minimum).Minimum).TotalSeconds } else { 0 }
    $recent = @($blkEv | Where-Object { $_.Time -gt (Get-Date).AddMinutes(-10) }).Count
    Note "5157 blocks on security/management binaries (60 min)=$($blk.Count)$(if ($blk.Count) { " span=${span}s last10min=$recent" })"
    if ($blk.Count -and ($span -gt 120 -or ($recent -gt 0 -and $span -gt 15))) { Bad ("security/management binaries blocked by firewall in last hour: " + (($blk | Group-Object | Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; ') + " (span ${span}s, $recent in last 10 min)") }
    elseif ($blk.Count) { Note "blocks were a single ${span}s burst (policy reload transient), not flagged" }
}

# ---------- services that must be resident ----------
# Self-stopping services (wuauserv, bits, dmwappushservice, DmEnrollmentSvc, gpsvc, sppsvc, ...)
# are deliberately absent: they stop when idle by design and are handled by STD-011's remediation.
$svcOk = 0
foreach ($s in 'MpsSvc','BFE','WinDefend','Sense','EventLog','Dnscache','Dhcp','W32Time','IntuneManagementExtension','cryptsvc','Schedule','UsoSvc','CloudflareWARP') {
    $c = Get-CimInstance Win32_Service -Filter "Name='$s'"
    if (-not $c) { Bad "service $s is absent" } elseif ($c.StartMode -eq 'Disabled') { Bad "service $s is DISABLED" } elseif ($c.State -ne 'Running') { Bad "service $s is $($c.State)" } else { $svcOk++ }
}

Note "resident services running=$svcOk/13"
# ---------- updates ----------
try { $sr = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'"); Note "Windows Update scan OK, applicable=$($sr.Updates.Count)" }
catch { Bad ('Windows Update scan FAILED 0x{0:X8} - nothing can install' -f $_.Exception.HResult) }
$up = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update'
if ($up.PauseQualityUpdates -eq 1) { Bad 'quality updates are PAUSED by policy' }

# ---------- Defender and the EDR sensor ----------
$m = Get-MpComputerStatus
if (-not $m) { Bad 'cannot read Defender status' }
else {
    Note "Defender sigs $($m.AntivirusSignatureVersion) age=$($m.AntivirusSignatureAge)d platform $($m.AMProductVersion) RTP=$($m.RealTimeProtectionEnabled) tamper=$($m.IsTamperProtected)"
    if (-not $m.RealTimeProtectionEnabled) { Bad 'Defender real-time protection is OFF' }
    if ($m.AntivirusSignatureAge -gt 2) { Bad "Defender signatures are $($m.AntivirusSignatureAge) days old" }
    if (-not $m.IsTamperProtected) { Bad 'Defender tamper protection is OFF' }
}
if ((Get-MpPreference).MAPSReporting -lt 1) { Bad 'Defender cloud-delivered protection is OFF' }
if ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status').OnboardingState -ne 1) { Bad 'device is not onboarded to Defender for Endpoint' }

# ---------- disk ----------
if ("$((Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus)" -ne 'On') { Bad 'BitLocker is not protecting the system drive' }

# ---------- network path and time ----------
$wc = 'C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe'
if (-not (Test-Path $wc)) { Bad 'Cloudflare WARP client is not installed' }
elseif ((($ws = (& $wc --accept-tos status 2>&1) -join ' ')) -notmatch 'Connected') { Bad 'Cloudflare WARP is not connected - egress is outside the Gateway boundary' }
if ($ws) { Note "WARP $(($ws -replace '\s+',' ').Trim())" }
$ts = (w32tm /query /status) -join ' '
if ($ts -match 'Last Successful Sync Time:\s*([\d/]+\s+[\d:]+\s*[AP]M)') {
    Note "time last sync $($Matches[1])"
    try { if (([datetime]::Parse($Matches[1])) -lt (Get-Date).AddHours(-26)) { Bad "time last synchronised $($Matches[1])" } } catch { }
} else { Bad 'time has never synchronised, or w32tm status is unreadable' }

# ---------- telemetry to Sentinel ----------
# Arc and the Monitor Agent are not Intune-deployed. A rebuilt machine comes back without them
# and reports nothing - which is how WS02 was silent after its rebuild on 30 September.
if ("$((Get-Service himds).Status)" -ne 'Running') { Bad 'Azure Arc agent (himds) is not running - this machine is not reporting to Sentinel' }
$ama = @(Get-Process MonAgentCore, MonAgentHost, MonAgentLauncher, MonAgentManager | Select-Object -ExpandProperty Name -Unique).Count
Note "Arc himds=$((Get-Service himds).Status) AMA processes=$ama/4"
if ($ama -lt 3) { Bad 'Azure Monitor Agent processes are not running - no logs are reaching Sentinel (check whether the extension upgraded and its firewall rules no longer match)' }

# ---------- verdict ----------
$measured = ($info -join ' | ')
if ($fail.Count -eq 0) { Write-Output ("OK on $env:COMPUTERNAME - " + $measured); exit 0 }

$msg = "ENDPOINT HEALTH FAILED on $env:COMPUTERNAME ($($fail.Count)): " + ($fail -join ' | ') + " || measured: " + $measured
Write-Output $msg
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('REF-EndpointHealth')) { New-EventLog -LogName 'SANCTIR' -Source 'REF-EndpointHealth' }
    Write-EventLog -LogName 'SANCTIR' -Source 'REF-EndpointHealth' -EventId 1330 -EntryType Error -Message $msg.Substring(0, [Math]::Min(30000, $msg.Length))
} catch { }
exit 1
