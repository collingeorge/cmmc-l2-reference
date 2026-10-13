# REF-DiskHygiene-Detect - Intune remediation DETECTION script. Runs daily as SYSTEM.
# Exit 0 = the disk, the Windows image and the installed-software inventory are clean.
# Exit 1 = at least one finding; each is named in the output (visible in Intune) and written to the
# SANCTIR event log as event 1350.
#
# WHY THIS EXISTS. 1 October 2026, the morning after the WS01 rebuild:
#   - WS02 was found with TWO Microsoft 365 products installed side by side (business and
#     enterprise), because Intune deployed one and Office's licensing moved the machine to the
#     other. Nothing reported it; it was noticed only because a verification script happened to
#     print the product list.
#   - OneDrive on WS01 was a 2023 build that had not updated in 13 hours, also unreported.
#   - Installers, a previous Edge build, reset leftovers and update caches were sitting on the SSD.
# The Security Officer's instruction: no duplicate software, no stale or corrupt installations left
# on the disk, the SSD trimmed, and this checked continuously on every machine from the moment it
# joins - not once by hand.
#
# DESIGN RULES (the same ones REF-EndpointHealth was built on):
#   - DETECTION ONLY. This script deletes nothing, uninstalls nothing and repairs nothing. Which
#     of two installed products is the stray is a decision; a script that guesses, running blind as
#     SYSTEM, is how the wrong one gets removed. Cleanup of temporary files is Windows' own job
#     (Storage Sense, delivered as tenant policy), not this script's.
#   - Unknown is a failure. A check that cannot read its state reports it, never passes silently.
#   - Measured values are printed on every run, so the Intune output shows numbers, not just OK.
# Written 1 Oct 2026 and dry-run on WS01 that morning before deployment. It raised three
# findings there, all real: OneDrive still the 2023 build, the previous night's Azure Arc installer
# error, and no Storage Sense policy. It raised nothing false.

$ErrorActionPreference = 'SilentlyContinue'
$fail = New-Object System.Collections.ArrayList; function Bad($m) { [void]$fail.Add($m) }
$info = New-Object System.Collections.ArrayList; function Note($m) { [void]$info.Add($m) }
$day = (Get-Date).AddHours(-24)

# ---------- the SSD itself ----------
$pd = @(Get-PhysicalDisk)
if (-not $pd.Count) { Bad 'cannot read physical disk state' }
foreach ($d in $pd) {
    if ("$($d.HealthStatus)" -ne 'Healthy' -or "$($d.OperationalStatus)" -ne 'OK') { Bad "disk '$($d.FriendlyName)' is $($d.HealthStatus)/$($d.OperationalStatus)" }
    $rc = $d | Get-StorageReliabilityCounter
    if ($rc) {
        Note "disk '$($d.FriendlyName)' wear=$($rc.Wear)% temp=$($rc.Temperature)C uncorrected read/write=$($rc.ReadErrorsUncorrected)/$($rc.WriteErrorsUncorrected)"
        if ($rc.ReadErrorsUncorrected -gt 0 -or $rc.WriteErrorsUncorrected -gt 0) { Bad "disk '$($d.FriendlyName)' reports uncorrected errors (read $($rc.ReadErrorsUncorrected), write $($rc.WriteErrorsUncorrected))" }
        if ($rc.Wear -ge 80) { Bad "disk '$($d.FriendlyName)' is $($rc.Wear)% worn" }
    } else { Note "disk '$($d.FriendlyName)' $($d.HealthStatus); reliability counters not exposed by this drive" }
}

# ---------- TRIM ----------
# DisableDeleteNotify = 0 means Windows sends TRIM as files are deleted. The Optimize Drives task
# re-sends it for the whole volume; on a machine older than two weeks it must have run recently.
if (((fsutil behavior query DisableDeleteNotify) -join ' ') -notmatch 'NTFS DisableDeleteNotify = 0') { Bad 'TRIM is disabled for NTFS (DisableDeleteNotify is not 0)' }
$opt = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag'
if (-not $opt) { Bad 'Optimize Drives task is missing - the SSD is never re-trimmed' }
elseif ("$($opt.State)" -eq 'Disabled') { Bad 'Optimize Drives task is DISABLED - the SSD is never re-trimmed' }
else {
    $last = ($opt | Get-ScheduledTaskInfo).LastRunTime
    $osAgeD = [int]((Get-Date) - (Get-CimInstance Win32_OperatingSystem).InstallDate).TotalDays
    $ran = ($last -and $last.Year -gt 1999)
    Note "re-trim last ran $(if ($ran) { $last.ToString('yyyy-MM-dd') } else { 'never (OS is ' + $osAgeD + ' d old)' })"
    if ($osAgeD -gt 14 -and (-not $ran -or $last -lt (Get-Date).AddDays(-14))) { Bad 'the SSD has not been re-trimmed in over 14 days' }
}

# ---------- free space and file-system errors ----------
$v = Get-Volume -DriveLetter ($env:SystemDrive.TrimEnd(':'))
if (-not $v) { Bad 'cannot read the system volume' }
else {
    $pct = [int](100 * $v.SizeRemaining / $v.Size); Note "system volume free $pct% ($([math]::Round($v.SizeRemaining/1GB)) GB)"
    if ($pct -lt 15) { Bad "system volume is only $pct% free" }
    if ("$($v.HealthStatus)" -ne 'Healthy') { Bad "system volume health is $($v.HealthStatus)" }
}
$fsErr = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'volmgr', 'stornvme', 'storahci'; Level = 1, 2; StartTime = $day })
Note "disk/file-system errors (24 h)=$($fsErr.Count)"
if ($fsErr.Count) { Bad ("disk or file-system errors in the last 24 h: " + (($fsErr | Group-Object ProviderName, Id | Sort-Object Count -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) x$($_.Count)" }) -join '; ')) }

# ---------- the Windows image ----------
# CheckHealth reads the flag the servicing stack sets when it has found corruption; it takes
# seconds and changes nothing. (ScanHealth, which hunts for corruption, takes minutes and is run
# by hand when this says Repairable.)
try { $img = (Repair-WindowsImage -Online -CheckHealth -ErrorAction Stop).ImageHealthState; Note "Windows image $img"; if ("$img" -ne 'Healthy') { Bad "Windows component store is $img" } }
catch { Bad "cannot read Windows image health ($($_.Exception.Message))" }

# ---------- duplicate software ----------
$un = @(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object { $_.DisplayName -and -not $_.SystemComponent })
foreach ($hive in (Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-[\d-]+$' })) {
    $un += @(Get-ItemProperty ("Registry::HKEY_USERS\$($hive.PSChildName)\Software\Microsoft\Windows\CurrentVersion\Uninstall\*") | Where-Object { $_.DisplayName })
}
if (-not $un.Count) { Bad 'cannot read the installed-software inventory' }
# Same product name once the architecture and version are stripped. The Visual C++ runtimes are
# deliberately excluded: x86 and x64 of the same runtime side by side is how Microsoft ships them.
$dups = @($un | Group-Object { ($_.DisplayName -replace '\s*[\(\-]?\s*(x64|x86|64-bit|32-bit)\)?', '' -replace '\s+v?\d[\d\.]+.*$', '').Trim() } |
          Where-Object { $_.Count -gt 1 -and $_.Name -notmatch 'Visual C\+\+|Redistributable|Runtime' })
foreach ($g in $dups) { Bad ("duplicate install: '" + $g.Name + "' x" + $g.Count + ' (' + (($g.Group | ForEach-Object { $_.DisplayVersion }) -join ', ') + ')') }
$office = @("$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration').ProductReleaseIds)" -split ',' | Where-Object { $_ })
Note "installed programs=$($un.Count) Office products=$(if ($office.Count) { $office -join '+' } else { 'none' })"
if ($office.Count -gt 1) { Bad ("more than one Office product installed: " + ($office -join ', ')) }
$od = @('C:\Program Files\Microsoft OneDrive\OneDrive.exe', 'C:\Program Files (x86)\Microsoft OneDrive\OneDrive.exe' | Where-Object { Test-Path $_ })
$od += @(Get-ChildItem 'C:\Users\*\AppData\Local\Microsoft\OneDrive\OneDrive.exe' | ForEach-Object FullName)
if ($od.Count -gt 1) { Bad ("more than one OneDrive install: " + ($od -join '; ')) }
if ($od.Count -eq 1) { $odv = (Get-Item $od[0]).VersionInfo.ProductVersion; Note "OneDrive $odv"; if ($odv -match '^(\d+)\.' -and [int]$Matches[1] -lt ((Get-Date).Year - 2001)) { Bad "OneDrive $odv is more than a year old - its updater is not working" } }
if ((Test-Path 'C:\Program Files\PowerShell\7\pwsh.exe') -and (Get-ChildItem 'C:\Program Files\WindowsApps' -Directory | Where-Object Name -match '^Microsoft\.PowerShell_')) { Bad 'PowerShell 7 is installed twice (MSI and Store package)' }

# ---------- broken or half-removed installs ----------
$orph = @($un | Where-Object { $_.InstallLocation -and -not (Test-Path -LiteralPath ($_.InstallLocation.Trim('"'))) })
if ($orph.Count) { Bad ("uninstall entries whose program folder is gone: " + (($orph | Select-Object -First 4 | ForEach-Object DisplayName) -join '; ')) }
$appx = @(Get-AppxPackage -AllUsers | Where-Object { "$($_.Status)" -ne 'Ok' })
if ($appx.Count) { Bad ("packaged apps not in a healthy state: " + (($appx | Select-Object -First 4 | ForEach-Object { "$($_.Name) ($($_.Status))" }) -join '; ')) }
$msi = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'MsiInstaller'; Level = 1, 2; StartTime = $day })
Note "installer errors (24 h)=$($msi.Count)"
if ($msi.Count) { Bad ("installer errors in the last 24 h: " + (($msi | Select-Object -First 2 | ForEach-Object { ($_.Message -replace '\s+', ' ').Substring(0, [Math]::Min(110, ($_.Message -replace '\s+', ' ').Length)) }) -join ' || ')) }

# ---------- leftovers on the SSD ----------
function SizeMB($p) { if (-not (Test-Path -LiteralPath $p)) { return 0 }; [int](((Get-ChildItem -LiteralPath $p -Recurse -Force -File | Measure-Object Length -Sum).Sum) / 1MB) }
$left = [ordered]@{
    'previous Windows (Windows.old)'  = SizeMB 'C:\Windows.old'
    'upgrade staging ($WINDOWS.~BT)'  = SizeMB 'C:\$WINDOWS.~BT'
    'reset leftovers ($SysReset)'     = SizeMB 'C:\$SysReset'
    'Windows temp'                    = SizeMB 'C:\Windows\Temp'
    'SANCTIR installer staging'       = SizeMB 'C:\ProgramData\REF\Installers'
}
Note ('leftovers MB: ' + (($left.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', '))
foreach ($k in 'previous Windows (Windows.old)', 'upgrade staging ($WINDOWS.~BT)') { if ($left[$k] -gt 0) { Bad "$k is still on the disk ($($left[$k]) MB)" } }
if ($left['Windows temp'] -gt 2048) { Bad "Windows temp holds $($left['Windows temp']) MB - Storage Sense is not cleaning" }
if ($left['SANCTIR installer staging'] -gt 0) { Bad "installer files left in C:\ProgramData\REF\Installers ($($left['SANCTIR installer staging']) MB)" }
# Edge and WebView2 keep the previous build until the updater removes it. More than two is stale.
foreach ($root in 'C:\Program Files (x86)\Microsoft\Edge\Application', 'C:\Program Files (x86)\Microsoft\EdgeWebView\Application') {
    $vers = @(Get-ChildItem $root -Directory | Where-Object Name -match '^\d+\.')
    if ($vers.Count -gt 2) { Bad "$($vers.Count) builds kept under $root" }
}
# Read where MDM records it. The first version read the Group Policy key
# (HKLM\SOFTWARE\Policies\Microsoft\Windows\StorageSense), which Intune does not write: on WS01,
# 1 Oct 2026, the policy had arrived at 09:38 and that key was still empty - a check that would
# have failed on every healthy machine.
$ssOn = ((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Storage').AllowStorageSenseGlobal -eq 1) -or ((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense').AllowStorageSenseGlobal -eq 1)
if (-not $ssOn) { Bad 'Storage Sense is not enforced by policy - temporary files are not being cleaned automatically' }

# ---------- verdict ----------
$measured = ($info -join ' | ')
if ($fail.Count -eq 0) { Write-Output ("OK on $env:COMPUTERNAME - " + $measured); exit 0 }
$msg = "DISK HYGIENE FINDINGS on $env:COMPUTERNAME ($($fail.Count)): " + ($fail -join ' | ') + " || measured: " + $measured
Write-Output $msg
try {
    if (-not [System.Diagnostics.EventLog]::SourceExists('REF-DiskHygiene')) { New-EventLog -LogName 'SANCTIR' -Source 'REF-DiskHygiene' }
    Write-EventLog -LogName 'SANCTIR' -Source 'REF-DiskHygiene' -EventId 1350 -EntryType Warning -Message $msg.Substring(0, [Math]::Min(30000, $msg.Length))
} catch { }
exit 1
