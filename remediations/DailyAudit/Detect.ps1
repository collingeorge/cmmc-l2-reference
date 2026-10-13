# REF-DailyAudit-Detect - Intune remediation DETECTION (report-only). Runs daily as SYSTEM.
# GENERATED from Scripts\REF-Audit-ServicesNetwork.ps1 by Scripts\REF-Build-DailyAudit.ps1 - edit the
# source, not this file. Always exits 0: it is a report, not a pass/fail; REF-EndpointHealth is the pass/fail.
#
# Every day: runs the full services / firewall-blocks / listeners / protocols / egress / update audit, writes
# the whole report to C:\ProgramData\REF\Reports\Audit-<date>.txt (last 30 kept), writes it to the SANCTIR
# event log as event 1340 in <=30 KB parts so it reaches Sentinel and can be diffed day-to-day and
# machine-to-machine, and prints the summary lines to Intune. Adopted 30 Sep 2026 after a week in which every
# fault had to be hunted by hand because no baseline existed to diff against.

$report = & {
$ErrorActionPreference = 'SilentlyContinue'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrators')) { Write-Output 'Run elevated. Nothing measured.'; exit 1 }
$sw = [Diagnostics.Stopwatch]::StartNew()
function H($t) { ''; "=== $t ==="; }

# ---------- A. services ----------
H "A. SERVICES ($env:COMPUTERNAME)"
$baseline = 'MpsSvc','BFE','WinDefend','WdNisSvc','MDCoreSvc','Sense','SecurityHealthService','wscsvc','EventLog','Dnscache','Dhcp','W32Time','NlaSvc','netprofm','dmwappushservice','DmEnrollmentSvc','IntuneManagementExtension','TokenBroker','wlidsvc','wuauserv','bits','UsoSvc','WaaSMedicSvc','DoSvc','cryptsvc','Schedule','WinHttpAutoProxySvc','gpsvc','LicenseManager','sppsvc','DiagTrack','CloudflareWARP','OneDrive Updater Service','TimeBrokerSvc','SENS','AppIDSvc','ClipSVC','CDPSvc','himds','ExtensionService','GCArcService'
$selfStop = 'dmwappushservice','sppsvc','DoSvc','wuauserv','bits','wlidsvc','WaaSMedicSvc','ClipSVC','OneDrive Updater Service','DmEnrollmentSvc','gpsvc'
$svcRows = foreach ($n in $baseline) {
    $c = Get-CimInstance Win32_Service -Filter "Name='$n'"
    if (-not $c) { [pscustomobject]@{ Service=$n; State='ABSENT'; Start=''; Account=''; Recovery=''; AdminsCanStop=''; Note='not installed' }; continue }
    $sd = (sc.exe sdshow $n) -join ''
    # WP = SERVICE_STOP, DC = SERVICE_CHANGE_CONFIG, in the DACL entries for BA (Administrators)
    # rights are two-letter pairs; WP = SERVICE_STOP, DC = SERVICE_CHANGE_CONFIG. Any ACE for BA (Administrators) counts.
    $baRights = @([regex]::Matches($sd, '\(A;[^;]*;([A-Z]+);;;BA\)') | ForEach-Object { $r=$_.Groups[1].Value; for ($i=0; $i -lt $r.Length; $i+=2) { $r.Substring($i,2) } })
    $adminsStop = if ($baRights -contains 'WP') { 'stop' + $(if ($baRights -contains 'DC') { '+config' } else { '' }) } elseif ($baRights.Count) { 'NO STOP (' + (($baRights | Select-Object -Unique) -join ' ') + ')' } else { 'no Administrators ACE' }
    $qf = (sc.exe qfailure $n) -join ' '
    $rec = if ($qf -match 'RESTART') { 'restart' } elseif ($qf -match 'FAILURE_ACTIONS\s*:\s*$|NONE') { 'none' } else { 'other' }
    $note = @(); if ($selfStop -contains $n) { $note += 'self-stops by design' }; if ($c.DelayedAutoStart) { $note += 'delayed' }
    [pscustomobject]@{ Service=$n; State=$c.State; Start=$c.StartMode; Account=$c.StartName; Recovery=$rec; AdminsCanStop=$adminsStop; Note=($note -join '; ') }
}
$svcRows | Format-Table -AutoSize | Out-String -Width 200
"stopped, not self-stopping: " + ((@($svcRows | Where-Object { $_.State -ne 'Running' -and $_.State -ne 'ABSENT' -and $_.Note -notmatch 'self-stops' }).Service -join ', ') -replace '^$','none')
"not Automatic:               " + ((@($svcRows | Where-Object { $_.Start -notin 'Auto','' }).Service -join ', ') -replace '^$','none')
"absent:                      " + ((@($svcRows | Where-Object { $_.State -eq 'ABSENT' }).Service -join ', ') -replace '^$','none')
"Administrators CANNOT stop:  " + ((@($svcRows | Where-Object { $_.AdminsCanStop -like 'NO STOP*' }).Service -join ', ') -replace '^$','none')

# ---------- B. firewall blocks, 24 h ----------
H 'B. FIREWALL BLOCKS, LAST 6 H (Security 5157, newest 8000 events)'
if (-not ((auditpol /get /subcategory:"Filtering Platform Connection") -match 'Failure')) { 'WARNING: 5157 auditing is OFF - blocks are invisible' }
# Properties by index is ~50x faster than parsing XML per event. 5157 layout: 0 ProcessID, 1 Application,
# 2 Direction (%%14592 in / %%14593 out), 3 SourceAddress, 4 SourcePort, 5 DestAddress, 6 DestPort, 7 Protocol.
$ev = @(Get-WinEvent -FilterHashtable @{ LogName='Security'; Id=5157; StartTime=(Get-Date).AddHours(-6) } -MaxEvents 8000)
"events read: $($ev.Count)$(if ($ev.Count -ge 8000) { ' (capped - the machine is blocking something very chatty; see the top rows)' })"
$rows = $ev | ForEach-Object { $v=$_.Properties; [pscustomobject]@{ App=("$($v[1].Value)" -replace '^\\device\\harddiskvolume\d+',''); Dir=$(if("$($v[2].Value)" -eq '%%14593'){'out'}else{'in'}); Proto=$v[7].Value; Port=$v[6].Value; Dest=$v[5].Value } }
$grouped = $rows | Group-Object App, Dir, Proto, Port | Sort-Object Count -Descending | Select-Object -First 40 | ForEach-Object { $f=$_.Group[0]; [pscustomobject]@{ Count=$_.Count; Dir=$f.Dir; Proto=$f.Proto; Port=$f.Port; App=$f.App; SampleDest=$f.Dest } }
$grouped | Format-Table -AutoSize | Out-String -Width 220
$critical = 'msmpeng|nissrv|mpdefendercore|mssense|senseir|sensecm|monagent|amacore|amaservice|fluent-bit|metricsext|azcmagent|himds|gc_arc|gc_ext|intune|agentexecutor|omadmclient|deviceenroller|dmclient|svchost|wuauclt|usoclient|mousocore|tiworker|warp-svc|onedrive|filesynchelper|officeclicktorun|appinstaller|winstore|wsappx|storeinstall|claude|terminal64|metaeditor'
$flag = $grouped | Where-Object { $_.App -match $critical }
"UPDATE/MANAGEMENT/APP BINARIES BLOCKED: " + $(if ($flag) { '' } else { 'none' })
$flag | Format-Table -AutoSize | Out-String -Width 220

# ---------- C. inbound exposure ----------
H 'C. LISTENING PORTS (TCP Listen + UDP bound, non-loopback)'
$procs = @{}; Get-Process | ForEach-Object { $procs[$_.Id] = $_.ProcessName }
$svcByPid = @{}; Get-CimInstance Win32_Service | Where-Object ProcessId | ForEach-Object { $svcByPid[[int]$_.ProcessId] = (($svcByPid[[int]$_.ProcessId], $_.Name) -join ',').Trim(',') }
$tcp = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } | ForEach-Object { [pscustomobject]@{ Proto='TCP'; Addr=$_.LocalAddress; Port=$_.LocalPort; Process=$procs[[int]$_.OwningProcess]; Services=$svcByPid[[int]$_.OwningProcess] } }
$udp = Get-NetUDPEndpoint | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } | ForEach-Object { [pscustomobject]@{ Proto='UDP'; Addr=$_.LocalAddress; Port=$_.LocalPort; Process=$procs[[int]$_.OwningProcess]; Services=$svcByPid[[int]$_.OwningProcess] } }
($tcp + $udp) | Sort-Object Proto, Port, Addr | Format-Table -AutoSize | Out-String -Width 200
H 'C2. INBOUND ALLOW RULES IN FORCE (enabled, Allow, any profile)'
$inRules = Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Enabled True -Action Allow
"count: $($inRules.Count)  (tenant: $(@($inRules | Where-Object { "$($_.PolicyStoreSourceType)" -eq 'MDM' }).Count), local: $(@($inRules | Where-Object { "$($_.PolicyStoreSourceType)" -ne 'MDM' }).Count))"
$inRules | ForEach-Object { $pf=$_ | Get-NetFirewallPortFilter; $af=$_ | Get-NetFirewallApplicationFilter; $ad=$_ | Get-NetFirewallAddressFilter; [pscustomobject]@{ Src="$($_.PolicyStoreSourceType)"; Profile="$($_.Profile)"; Proto=$pf.Protocol; LocalPort=($pf.LocalPort -join ','); Remote=($ad.RemoteAddress -join ','); Program=$af.Program; Svc=$_.ServiceName; Name=$_.DisplayName } } | Sort-Object Src, Name | Format-Table -AutoSize | Out-String -Width 240
foreach ($p in Get-NetFirewallProfile -PolicyStore ActiveStore) { "profile $($p.Name): enabled=$($p.Enabled) in=$($p.DefaultInboundAction) out=$($p.DefaultOutboundAction) localRulesMerge=$($p.AllowLocalFirewallRules) notify=$($p.NotifyOnListen)" }

# ---------- D. legacy / discovery protocols ----------
H 'D. LEGACY AND DISCOVERY PROTOCOLS (Copilot 30 Sep: recommended OFF for this estate)'
$lan = Get-CimInstance Win32_Service -Filter "Name='LanmanServer'"; "SMB server (LanmanServer):      $($lan.State) / $($lan.StartMode)   SMB1=$((Get-SmbServerConfiguration).EnableSMB1Protocol)  shares=$((Get-SmbShare | Where-Object Name -notmatch '^\w\$$|^IPC\$$|^ADMIN\$$').Count) non-admin"
"NetBIOS over TCP/IP:            " + ((Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | ForEach-Object { "$($_.Description -replace '\s+',' ')=$(switch($_.TcpipNetbiosOptions){0{'default(DHCP)'}1{'ENABLED'}2{'disabled'}})" }) -join '; ')
$llmnr = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient').EnableMulticast; "LLMNR (EnableMulticast policy):  $(if($null -eq $llmnr){'not set (LLMNR ON by default)'}elseif($llmnr -eq 0){'disabled'}else{'enabled'})"
$mdns = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters').EnableMDNS; "mDNS (EnableMDNS):               $(if($null -eq $mdns){'not set (mDNS ON by default)'}elseif($mdns -eq 0){'disabled'}else{'enabled'})"
# Listener count from the registry: the WSMan: drive would START WinRM to answer (it prompted on 30 Sep).
$wr = Get-CimInstance Win32_Service -Filter "Name='WinRM'"; "WinRM:                          $($wr.State) / $($wr.StartMode)   listeners=$(@(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener' -ErrorAction SilentlyContinue).Count)"
$rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections; "RDP (fDenyTSConnections):        $(if($rdp -eq 1){'disabled'}else{'ENABLED'})   TermService=$((Get-CimInstance Win32_Service -Filter "Name='TermService'").State)"
$fd = Get-CimInstance Win32_Service -Filter "Name='FDResPub'"; $fh = Get-CimInstance Win32_Service -Filter "Name='fdPHost'"; "Network discovery (FDResPub/fdPHost): $($fd.State)/$($fd.StartMode), $($fh.State)/$($fh.StartMode)"
$ssdp = Get-CimInstance Win32_Service -Filter "Name='SSDPSRV'"; $upnp = Get-CimInstance Win32_Service -Filter "Name='upnphost'"; "SSDP / UPnP host:               $($ssdp.State)/$($ssdp.StartMode), $($upnp.State)/$($upnp.StartMode)"
$wsd = Get-CimInstance Win32_Service -Filter "Name='WSDPrintDevice'"; "WS-Discovery (WSDPrintDevice):  $(if($wsd){"$($wsd.State)/$($wsd.StartMode)"}else{'absent'})   UDP 3702 bound: $(@($udp | Where-Object Port -eq 3702).Count -gt 0)"
$do = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization').DODownloadMode; $doCsp = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\DeliveryOptimization').DODownloadMode; "Delivery Optimization mode:      GPO=$(if($null -eq $do){'unset'}else{$do}) CSP=$(if($null -eq $doCsp){'unset'}else{$doCsp})   (0/99=HTTP only, no peering; 1=LAN peers; 2/3=wider)   TCP 7680 listening: $(@($tcp | Where-Object Port -eq 7680).Count -gt 0)"
"Bluetooth service:              $((Get-CimInstance Win32_Service -Filter "Name='bthserv'").State)"
"Remote Registry:                $((Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'").State) / $((Get-CimInstance Win32_Service -Filter "Name='RemoteRegistry'").StartMode)"

# ---------- E. egress path ----------
H 'E. EGRESS PATH'
$wc = 'C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe'; if (Test-Path $wc) { ((& $wc --accept-tos status 2>&1) -join ' | '); ((& $wc --accept-tos settings 2>&1) | Select-String 'Always On|Switch Locked|Mode|Gateway|DNS' | ForEach-Object { $_.Line.Trim() }) -join ' | ' } else { 'WARP client not installed' }
Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | ForEach-Object { "DNS on $($_.InterfaceAlias) ($($_.AddressFamily)): $($_.ServerAddresses -join ', ')" }
Get-NetConnectionProfile | ForEach-Object { "profile: $($_.InterfaceAlias) = $($_.NetworkCategory) ($($_.IPv4Connectivity)/$($_.IPv6Connectivity))" }
"proxy: " + ((netsh winhttp show proxy) -join ' ' -replace '\s+',' ')

# ---------- F. update / app health ----------
H 'F. UPDATE AND APP HEALTH'
try { $s=(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'"); "Windows Update scan: OK, $($s.Updates.Count) applicable ($(@($s.Updates | Where-Object { -not $_.BrowseOnly }).Count) non-optional)"; $s.Updates | ForEach-Object { "   - $($_.Title)" } } catch { "Windows Update scan FAILED 0x{0:X8}" -f $_.Exception.HResult }
$au=(New-Object -ComObject Microsoft.Update.AutoUpdate).Results; "last search $($au.LastSearchSuccessDate)  last install $($au.LastInstallationSuccessDate)"
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 3 | ForEach-Object { "   installed: $($_.HotFixID) $($_.InstalledOn.ToString('yyyy-MM-dd'))" }
$m=Get-MpComputerStatus; "Defender: platform $($m.AMProductVersion) engine $($m.AMEngineVersion) sigs $($m.AntivirusSignatureVersion) age $($m.AntivirusSignatureAge)d  RTP=$($m.RealTimeProtectionEnabled) tamper=$($m.IsTamperProtected) MAPS=$((Get-MpPreference).MAPSReporting)"
"MDE onboarding: $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection\Status').OnboardingState)  Sense=$((Get-Service Sense).Status)"
"Store/AppInstaller present: $(Test-Path 'C:\Program Files\WindowsApps\Microsoft.WindowsStore_*')/$(Test-Path 'C:\Program Files\WindowsApps\Microsoft.DesktopAppInstaller_*')"
"Intune apps expected: Claude=$(Test-Path 'C:\Program Files\WindowsApps\Claude_*') MT5=$(Test-Path 'C:\Program Files\MetaTrader 5\terminal64.exe') WARP=$(Test-Path $wc) Arc=$(Test-Path 'C:\Program Files\AzureConnectedMachineAgent\azcmagent.exe') PS7=$(Test-Path 'C:\Program Files\WindowsApps\Microsoft.PowerShell_7*') Office=$(Test-Path 'C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE')"
$os=Get-CimInstance Win32_OperatingSystem; "OS: $($os.Caption) $($os.Version) UBR $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR)  last boot $($os.LastBootUpTime)"
''; "audit complete in $([int]$sw.Elapsed.TotalSeconds)s - nothing was changed."

} *>&1 | Out-String -Width 220

$stamp = Get-Date -Format 'yyyy-MM-dd'
$dir = 'C:\ProgramData\REF\Reports'; New-Item -ItemType Directory -Force $dir | Out-Null
$path = Join-Path $dir "Audit-$stamp.txt"
Set-Content -Path $path -Value $report -Encoding UTF8
Get-ChildItem $dir -Filter 'Audit-*.txt' | Sort-Object Name -Descending | Select-Object -Skip 30 | ForEach-Object { $_.Delete() }

try {
    $src = 'REF-DailyAudit'
    if (-not [System.Diagnostics.EventLog]::SourceExists($src)) { New-EventLog -LogName 'SANCTIR' -Source $src }
    $parts = [math]::Ceiling($report.Length / 30000)
    for ($i = 0; $i -lt $parts; $i++) {
        $chunk = $report.Substring($i * 30000, [math]::Min(30000, $report.Length - $i * 30000))
        Write-EventLog -LogName 'SANCTIR' -Source $src -EventId 1340 -EntryType Information -Message ("DAILY AUDIT $env:COMPUTERNAME $stamp part $($i+1)/$parts`n" + $chunk)
    }
} catch { }

# Summary for Intune (about 2 KB is retained): service verdicts, flagged blocks, protocols, updates, Defender.
$lines = $report -split "`r?`n"
$summary = @(
    $lines | Where-Object { $_ -match '^(stopped, not self-stopping|not Automatic|absent|Administrators CANNOT stop|events read|UPDATE/MANAGEMENT/APP BINARIES BLOCKED|count: \d+ +\(tenant|SMB server|LLMNR|mDNS|WinRM|RDP|Delivery Optimization mode|Windows Update scan|Defender:|MDE onboarding|Intune apps expected|OS:)' }
) -join ' | '
Write-Output ("AUDIT $stamp $env:COMPUTERNAME -> $path | " + $summary)
exit 0