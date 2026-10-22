# REF-KillerSuite - REMEDIATION (SYSTEM). v1, 17 Oct 2026. See the detection script for the why.
# Removes the Killer SUITE from the Killer network adapter and keeps the adapter's own driver, so the machine stays online:
#   1. the four Killer services are stopped and set Disabled (disable, never delete);
#   2. every Rivet Networks driver package EXCEPT the one driving the adapter is exported to
#      C:\ProgramData\REF\DriverBackup\Killer-<date> and then uninstalled (pnputil /delete-driver /uninstall, no /force);
#   3. the adapter must be back Up with a real IPv4 address within 3 minutes - otherwise the exported packages are put back
#      (pnputil /add-driver /install) and the run reports failure. "Never take a machine offline."
# The software component is also blocked from coming back by REF-DeviceInstall-Block (SWC\VID_1A56&PID_1000&SID_0002).
$ErrorActionPreference = 'SilentlyContinue'
$svc = 'Killer Network Service', 'KNDBWM', 'KAPSService', 'Killer Analytics Service'
$log = @(); $fail = @()
foreach ($s in $svc) { $x = Get-Service -Name $s; if ($x -and $x.StartType -ne 'Disabled') { if ($x.Status -eq 'Running') { Stop-Service -Name $s -Force }; Set-Service -Name $s -StartupType Disabled; if ((Get-Service -Name $s).StartType -eq 'Disabled') { $log += "disabled $s" } else { $fail += "service $s" } } }

$nic = @(Get-PnpDevice -Class Net | Where-Object { $_.InstanceId -match '^PCI\\VEN_1969&' })
if (-not $nic.Count) { Write-Output ("No Killer adapter. " + ($log -join '; ')); if ($fail.Count) { exit 1 }; exit 0 }
$nicInf = @($nic | ForEach-Object { (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_DriverInfPath).Data })
# v2 (17 Oct 2026): suite = extension INFs attached to the adapter + packages whose provider/original name says
# Rivet/Killer; the adapter's own driver INF is always excluded (v1 matched provider "Rivet Networks" only and missed oem0.inf).
$ext = @($nic | ForEach-Object { @((Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_ExtendedConfigurationIds).Data) } | ForEach-Object { ($_ -split ':')[0] } | Where-Object { $_ -match '^oem\d+\.inf$' })
$enum = (pnputil /enum-drivers 2>&1) -join "`n"; $cand = @($ext)
foreach ($blk in ($enum -split "(?m)^\s*$")) {
    if ($blk -match '(?im)^\s*Published Name:\s*(\S+)') { $pub = $Matches[1] } else { continue }
    if ($blk -match '(?im)^\s*(Provider Name|Original Name):\s*.*(rivet|killer)') { $cand += $pub }
}
$suite = @(); foreach ($p in ($cand | Sort-Object -Unique)) { if ($nicInf -contains $p) { $log += "kept adapter driver $p"; continue }; if ($enum -match "(?im)^\s*Published Name:\s*$([regex]::Escape($p))\s*$") { $suite += $p } }
if ($suite.Count) {
    $bk = "C:\ProgramData\REF\DriverBackup\Killer-$(Get-Date -Format 'yyyyMMdd-HHmmss')"; New-Item -ItemType Directory -Force $bk | Out-Null
    foreach ($p in $suite) { $null = pnputil /export-driver $p $bk 2>&1 }
    $exported = @(Get-ChildItem $bk -Filter *.inf -Recurse)
    if ($exported.Count -lt $suite.Count) { Write-Output "Backup incomplete ($($exported.Count) of $($suite.Count) exported) - nothing uninstalled. $($log -join '; ')"; exit 1 }
    foreach ($p in $suite) { $r = (pnputil /delete-driver $p /uninstall 2>&1) -join ' '; if ($LASTEXITCODE -eq 0) { $log += "uninstalled $p" } else { $fail += "package $p ($r)" } }
    # the adapter must come back: Up, with a non-APIPA IPv4 address
    $ok = $false; foreach ($i in 1..36) { Start-Sleep 5; $a = Get-NetAdapter -Physical | Where-Object { $_.PnPDeviceID -match '^PCI\\VEN_1969&' -and $_.Status -eq 'Up' }; if ($a) { $ip = Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^169\.254\.' }; if ($ip) { $ok = $true; break } } }
    if (-not $ok) {
        foreach ($f in $exported) { $null = pnputil /add-driver $f.FullName /install 2>&1 }
        Start-Sleep 20; Get-NetAdapter -Physical | Where-Object PnPDeviceID -match '^PCI\\VEN_1969&' | Restart-NetAdapter -Confirm:$false
        Write-Output "ROLLED BACK: adapter not back within 3 min after removing $($suite -join ','); packages reinstalled from $bk. $($log -join '; ')"; exit 1
    }
    $log += "adapter Up with IPv4 after removal; backup $bk"
}
# --- v2: move the adapter to Windows' own (Microsoft) driver, owner: "I need a generic backup that supersedes this" ---
# Only when the in-box e2xw10x64.inf (Provider MSFT) exists. Rivet's package is exported, uninstalled, Windows rescans and
# binds its own driver; if the adapter is not Up with IPv4 within 3 minutes, Rivet's package is put back.
function Test-NicUp { foreach ($i in 1..36) { Start-Sleep 5; $a = Get-NetAdapter -Physical | Where-Object { $_.PnPDeviceID -match '^PCI\\VEN_1969&' -and $_.Status -eq 'Up' }; if ($a) { if (Get-NetIPAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notmatch '^169\.254\.' }) { return $true } } }; $false }
$inboxInf = "$env:SystemRoot\INF\e2xw10x64.inf"
# Owner, 17 Oct: "I'll lose internet before being able to install it". The swap needs NO download: the Microsoft package must
# already be in the local driver store, or the adapter driver is not touched at all.
$inboxStore = @(Get-ChildItem "$env:SystemRoot\System32\DriverStore\FileRepository" -Directory -Filter 'e2xw10x64.inf_amd64_*' | Where-Object { (Test-Path (Join-Path $_.FullName 'e2xw10x64.inf')) -and (Select-String -Path (Join-Path $_.FullName 'e2xw10x64.inf') -Pattern '^\s*Provider\s*=\s*%MSFT%' -Quiet) -and (Test-Path (Join-Path $_.FullName 'e2xw10x64.sys')) })
if (-not $inboxStore.Count) { $log += 'Microsoft e2xw10x64 package not in the local driver store - adapter driver NOT changed' }
elseif ((Test-Path $inboxInf) -and (Select-String -Path $inboxInf -Pattern '^\s*Provider\s*=\s*%MSFT%' -Quiet)) {
    foreach ($n in $nic) {
        $prov = (Get-PnpDeviceProperty -InstanceId $n.InstanceId -KeyName DEVPKEY_Device_DriverProvider).Data
        if ($prov -eq 'Microsoft') { $log += 'adapter already on the Microsoft driver'; continue }
        $cur = (Get-PnpDeviceProperty -InstanceId $n.InstanceId -KeyName DEVPKEY_Device_DriverInfPath).Data
        if ($cur -notmatch '^oem\d+\.inf$') { $fail += "adapter driver $cur is not an OEM package - not touched"; continue }
        $bk2 = "C:\ProgramData\REF\DriverBackup\KillerAdapter-$(Get-Date -Format 'yyyyMMdd-HHmmss')"; New-Item -ItemType Directory -Force $bk2 | Out-Null
        $null = pnputil /export-driver $cur $bk2 2>&1; $saved = @(Get-ChildItem $bk2 -Filter *.inf -Recurse)
        if (-not $saved.Count) { $fail += "could not back up $cur - adapter driver not changed"; continue }
        $r = (pnputil /delete-driver $cur /uninstall 2>&1) -join ' '
        if ($LASTEXITCODE -ne 0) { $fail += "uninstall $cur refused ($r)"; continue }
        $null = pnputil /scan-devices 2>&1
        if (Test-NicUp) { $now = (Get-PnpDeviceProperty -InstanceId $n.InstanceId -KeyName DEVPKEY_Device_DriverProvider).Data; $log += "adapter moved from $cur ($prov) to the $now driver; backup $bk2" }
        else { foreach ($f in $saved) { $null = pnputil /add-driver $f.FullName /install 2>&1 }; $null = pnputil /scan-devices 2>&1; Start-Sleep 20; Write-Output "ROLLED BACK: adapter not back on the Microsoft driver within 3 min; $cur reinstalled from $bk2. $($log -join '; ')"; exit 1 }
    }
}
# --- v4: never left disabled; not shown as "Killer" -------------------------------------------------------------------
$WantName = 'Onboard Ethernet (Microsoft driver)'
foreach ($n in @(Get-PnpDevice -Class Net | Where-Object { $_.InstanceId -match '^PCI\\VEN_1969&' })) {
    if ($n.Problem -eq 'CM_PROB_DISABLED' -or $n.Status -eq 'Error') { Enable-PnpDevice -InstanceId $n.InstanceId -Confirm:$false; $log += 'adapter was DISABLED - enabled (only network adapter)' }
    $a = Get-NetAdapter -Physical | Where-Object PnPDeviceID -eq $n.InstanceId; if ($a -and $a.AdminStatus -eq 'Down') { Enable-NetAdapter -Name $a.Name -Confirm:$false; $log += "network connection '$($a.Name)' was disabled - enabled" }
    $ek = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($n.InstanceId)"
    if ((Get-ItemProperty $ek).FriendlyName -ne $WantName) { Set-ItemProperty -Path $ek -Name FriendlyName -Value $WantName -Type String; $log += "device name -> $WantName" }
    $drvKey = (Get-PnpDeviceProperty -InstanceId $n.InstanceId -KeyName DEVPKEY_Device_Driver).Data
    if ($drvKey) { $ck = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$drvKey"; if ((Get-ItemProperty $ck).DriverDesc -ne $WantName) { Set-ItemProperty -Path $ck -Name DriverDesc -Value $WantName -Type String; $log += 'adapter description renamed (shown in network settings after the next restart)' } }
    if ((Get-ItemProperty $ek).FriendlyName -ne $WantName) { $fail += 'rename refused' }
}
Write-Output ("Killer suite removed: " + ($log -join '; ') + $(if ($fail.Count) { ' | FAILED: ' + ($fail -join '; ') }))
if ($fail.Count) { exit 1 }
exit 0
