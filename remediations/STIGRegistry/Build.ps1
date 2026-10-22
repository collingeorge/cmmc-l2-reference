# REF-STIGRegistry-Build.ps1 - 20 Oct 2026. Builds the "REF - STIG Registry Closure" remediation (detect + remediate).
# WHY. Security Officer, 20 Oct 2026: "close them all". After the DISA Intune package policies, the remaining DISA SCAP failures
# are settings whose required registry location Intune cannot write (DISA's own deviations sheet: "not present in Intune
# natively - implemented in the DSC application"):
#   - Defender AV V2R10: 10 newer settings DISA reads only at the Group Policy path (the tenant sets them through Defender's
#     CSP), threat-alert actions, and the 16 ASR rules at ...\ASR\Rules\<id> (the tenant sets ASR through the CSP);
#   - Firewall V2R3: logging in the LOCAL firewall store (Intune sets it in the MDM store; DISA's check reads GPO/local);
#   - Office V3R8: per-user values for ENABLED LOCAL accounts' profiles (la-admin): Intune never delivers user settings to
#     a local account, and DISA checks every enabled profile.
# Every value is taken from DISA's OVAL in the benchmark files (Compliance Library\DISA-STIG\...), not typed from memory. The
# Office table REF-STIGRegistry-Office-V3R8.csv was generated from the V3R8 benchmark's 132 ntuser tests (20 Oct 2026).
# Values equal what the tenant already enforces where it has one (ASR stays Block on the 3 rules DISA lets audit - stricter,
# recorded as a deviation; threat actions Quarantine = 2, DISA <= 3). Nothing here weakens a setting.
param([string]$OfficeCsv)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $OfficeCsv) { $OfficeCsv = Join-Path $here 'REF-STIGRegistry-Office-V3R8.csv' }
if (-not (Test-Path -LiteralPath $OfficeCsv)) { throw "Office requirement table not found: $OfficeCsv" }

$wd = 'SOFTWARE\Policies\Microsoft\Windows Defender'
$machine = New-Object Collections.ArrayList
function M($k, $n, $t, $v) { [void]$machine.Add("$k|$n|$t|$v") }
M $wd 'DisableLocalAdminMerge' 'DWord' 1;  M $wd 'HideExclusionsFromLocalAdmins' 'DWord' 1
M "$wd\Features" 'PassiveRemediation' 'DWord' 1
M "$wd\NIS" 'AllowSwitchToAsyncInspection' 'DWord' 1;  M "$wd\NIS" 'EnableConvertWarnToBlock' 'DWord' 1
M "$wd\Real-Time Protection" 'DisableScriptScanning' 'DWord' 0;  M "$wd\Real-Time Protection" 'OobeEnableRtpAndSigUpdate' 'DWord' 1
M "$wd\Reporting" 'EnableDynamicSignatureDroppedEventReporting' 'DWord' 1
M "$wd\Scan" 'QuickScanIncludeExclusions' 'DWord' 1
M "$wd\Windows Defender Exploit Guard\Network Protection" 'AllowNetworkProtectionOnWinServer' 'DWord' 1
M "$wd\Threats" 'Threats_ThreatSeverityDefaultAction' 'DWord' 1
foreach ($lvl in '1', '2', '4', '5') { M "$wd\Threats\ThreatSeverityDefaultAction" $lvl 'String' '2' }   # 2 = Quarantine (DISA: <= 3)
M "$wd\Windows Defender Exploit Guard\ASR" 'ExploitGuard_ASR_Rules' 'DWord' 1
foreach ($asr in '01443614-cd74-433a-b99e-2ecdc07bfc25', '26190899-1602-49e8-8b27-eb1d0a1ce869', '3B576869-A4EC-4529-8536-B80A7769E899', '56a863a9-875e-4185-98a7-b882c64b5ce5', '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC', '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84', '7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c', '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550', 'c1db55ab-c21a-4637-bb3f-a12568109d35', 'd1e49aac-8f56-4280-b9ba-993a6d77406c', 'D3E037E1-3EB8-44C8-A917-57927947596D', 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A', 'e6db77e5-3df2-4cf1-b95a-636979351e5b') {
    M "$wd\Windows Defender Exploit Guard\ASR\Rules" $asr 'String' '1' }   # 1 = Block (DISA: 1, or 2 for three audit rules - Block is stricter)

# 20 Oct 2026 (Security Officer: "apply the settings ... according to DISA"): DISA Intune Policy Package Oct 2026, script
# "DoD .NET Framework Disable RC4 Cipher STIG" - SchUseStrongCrypto = 1 in the 64-bit and 32-bit .NET 4 keys (strong crypto /
# TLS 1.2+, no RC4). Kept here (hourly detect + correct) instead of DISA's one-time script, so the value has one owner.
M 'SOFTWARE\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto' 'DWord' 1
M 'SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319' 'SchUseStrongCrypto' 'DWord' 1
# 20 Oct 2026: DISA OneDrive STIG V2R4 V-215535 (DTOO129) - Office IE Security "Block popups" with groove.exe checked. WS01:
# the other 8 groove.exe FeatureControl values (V-215529..38) are delivered by the tenant; this one was missing.
M 'SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT' 'groove.exe' 'DWord' 1

$office = New-Object Collections.ArrayList
foreach ($r in (Import-Csv -LiteralPath $OfficeCsv)) {
    if ($r.Exist -eq 'none_exist') { [void]$office.Add("$($r.Key)|$($r.Name)|Absent|"); continue }
    $t = if ($r.Type -eq 'reg_sz') { 'String' } else { 'DWord' }
    [void]$office.Add("$($r.Key)|$($r.Name)|$t|$($r.Value)")   # 'greater than or equal' (minenckey 168) is written at the minimum
}
$office = @($office | Sort-Object -Unique)

function Lit($arr) { '@(' + "`n  " + (($arr | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ",`n  ") + "`n)" }
$tables = "`$ErrorActionPreference = 'Continue'`n`$Machine = $(Lit $machine)`n`$Office = $(Lit $office)`n"
$functions = @'
function Test-Val($root, $line) { $k, $n, $t, $v = $line -split '\|', 4
    $key = $root.OpenSubKey($k); try { $cur = if ($key) { $key.GetValue($n, $null) } else { $null } } finally { if ($key) { $key.Close() } }
    if ($t -eq 'Absent') { return ($null -eq $cur) }
    if ($null -eq $cur) { return $false }
    if ($t -eq 'DWord') { return ([int64]$cur -eq [int64]$v) } else { return ("$cur" -eq "$v") } }
function Set-Val($root, $line) { $k, $n, $t, $v = $line -split '\|', 4
    if ($t -eq 'Absent') { $key = $root.OpenSubKey($k, $true); if ($key) { try { if ($null -ne $key.GetValue($n, $null)) { $key.DeleteValue($n) } } finally { $key.Close() } }; return }
    $key = $root.CreateSubKey($k); try { if ($t -eq 'DWord') { $key.SetValue($n, [int]$v, [Microsoft.Win32.RegistryValueKind]::DWord) } else { $key.SetValue($n, "$v", [Microsoft.Win32.RegistryValueKind]::String) } } finally { $key.Close() } }
function Get-LocalProfiles {
    # enabled LOCAL accounts with a profile on disk (Entra accounts get their Office values from the tenant)
    $dom = (Get-LocalUser | Select-Object -First 1).SID.AccountDomainSid.Value
    foreach ($p in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList') {
        $sid = $p.PSChildName; if ($sid -notlike "$dom-*") { continue }
        $u = Get-LocalUser -SID $sid -ErrorAction SilentlyContinue; if (-not $u -or -not $u.Enabled) { continue }
        $path = (Get-ItemProperty $p.PSPath).ProfileImagePath; if (-not (Test-Path -LiteralPath (Join-Path $path 'NTUSER.DAT'))) { continue }
        [pscustomobject]@{ Sid = $sid; Name = $u.Name; Dat = (Join-Path $path 'NTUSER.DAT') } }
}
function Use-Hive($prof, [scriptblock]$work) {
    $users = [Microsoft.Win32.Registry]::Users; $mount = $prof.Sid; $loaded = $false
    if (-not $users.OpenSubKey($prof.Sid)) { $mount = "REF_STIG_$($prof.Sid -replace '.*-', '')"; & reg.exe load "HKU\$mount" "$($prof.Dat)" 2>&1 | Out-Null; if ($LASTEXITCODE -ne 0) { return "hive of $($prof.Name) could not be loaded" }; $loaded = $true }
    $root = $users.OpenSubKey($mount, $true)
    try { & $work $root } finally { $root.Close(); if ($loaded) { [GC]::Collect(); [GC]::WaitForPendingFinalizers(); & reg.exe unload "HKU\$mount" 2>&1 | Out-Null } }
}
function Get-Drift {
    $d = New-Object Collections.ArrayList; $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64')
    foreach ($l in $Machine) { if (-not (Test-Val $hklm $l)) { [void]$d.Add("HKLM\$(($l -split '\|')[0])\$(($l -split '\|')[1])") } }
    foreach ($fp in Get-NetFirewallProfile -PolicyStore PersistentStore) { if ("$($fp.LogAllowed)" -ne 'True' -or "$($fp.LogBlocked)" -ne 'True' -or [int]$fp.LogMaxSizeKilobytes -lt 16384) { [void]$d.Add("local firewall logging $($fp.Name): allowed=$($fp.LogAllowed) blocked=$($fp.LogBlocked) size=$($fp.LogMaxSizeKilobytes)") } }
    foreach ($p in @(Get-LocalProfiles)) { $bad = Use-Hive $p { param($root) @($Office | Where-Object { -not (Test-Val $root $_) }).Count }; if ("$bad" -match '^\d+$') { if ([int]$bad) { [void]$d.Add("Office values for local account $($p.Name): $bad of $($Office.Count) not as DISA requires") } } else { [void]$d.Add("$bad") } }
    return , $d
}
'@
$common = $tables + $functions

$detectBody = @'
$d = Get-Drift
if ($d.Count) { Write-Output "$($d.Count) item(s) not as DISA requires: $(($d | Select-Object -First 8) -join '; ')"; exit 1 }
Write-Output "all $($Machine.Count) machine values, local firewall logging and Office values for $(@(Get-LocalProfiles).Count) local profile(s) as DISA requires"; exit 0
'@
$remediateBody = @'
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine', 'Registry64'); $err = @()
foreach ($l in $Machine) { try { if (-not (Test-Val $hklm $l)) { Set-Val $hklm $l } } catch { $err += "$(($l -split '\|')[1]): $($_.Exception.Message)" } }
try { Set-NetFirewallProfile -PolicyStore PersistentStore -Profile Domain, Private, Public -LogAllowed True -LogBlocked True -LogMaxSizeKilobytes 16384 -ErrorAction Stop } catch { $err += "firewall logging: $($_.Exception.Message)" }
foreach ($p in @(Get-LocalProfiles)) { $r = Use-Hive $p { param($root) foreach ($l in $Office) { if (-not (Test-Val $root $l)) { Set-Val $root $l } } }; if ($r -is [string]) { $err += $r } }
$d = Get-Drift
Write-Output "remediated; still not as required: $($d.Count)$(if ($d.Count) { ' - ' + (($d | Select-Object -First 6) -join '; ') })$(if ($err) { ' | errors: ' + (($err | Select-Object -First 4) -join '; ') })"
exit 0
'@
$detect = "# REF-STIGRegistry-Detect (20 Oct 2026). Generated by REF-STIGRegistry-Build.ps1 - do not edit by hand.`n# Exit 1 when any DISA-required value that Intune cannot write is missing: Defender Group Policy-path values and ASR rules,`n# local-store firewall logging, Office per-user values for enabled local accounts. Read-only.`n" + $common + $detectBody
$remediate = "# REF-STIGRegistry-Remediate (20 Oct 2026). Generated by REF-STIGRegistry-Build.ps1 - do not edit by hand.`n# Writes the DISA-required values Intune cannot write (see the build script), then re-checks and reports what is still off`n# (for example a Defender value refused by Tamper Protection). Deletes nothing except the two Outlook values DISA requires`n# to be absent (FileExtensionsRemoveLevel1/2) in local accounts' profiles.`n" + $common + $remediateBody

$enc = New-Object Text.UTF8Encoding($false)
[IO.File]::WriteAllText((Join-Path $here 'REF-STIGRegistry-Detect.ps1'), $detect, $enc)
[IO.File]::WriteAllText((Join-Path $here 'REF-STIGRegistry-Remediate.ps1'), $remediate, $enc)
"machine values: $($machine.Count) | Office values: $($office.Count)"
foreach ($n in 'Detect', 'Remediate') { $p = Join-Path $here "REF-STIGRegistry-$n.ps1"; $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$e); "{0,-10} {1} | {2:N0} bytes | sha8 {3}" -f $n, $(if ($e) { "PARSE ERROR: $($e[0].Message) line $($e[0].Extent.StartLineNumber)" } else { 'parse OK' }), (Get-Item $p).Length, (Get-FileHash $p -Algorithm SHA256).Hash.Substring(0, 8) }
