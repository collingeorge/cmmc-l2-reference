# Deploy-Remediation.ps1 - creates ONE Intune remediation from a detection script (and optionally a remediation script)
# and assigns it to the device group in config.json on a schedule. Refuses to create a duplicate display name. -WhatIfOnly
# shows the plan and stops. To change the scripts of an existing remediation, use Update-Remediation.ps1.
#   -Schedule Hourly   : every hour
#   -Schedule Daily    : once a day at -DailyTime (24h, device local time)
#   -RunAs system|user : user = "run with logged-on credentials" (HKCU work); system = default
#   -RemediatePath     : omit for detect-only (a no-op remediation body is supplied; remediation is left OFF)
# Example:
#   .\remediations\Deploy-Remediation.ps1 -DisplayName 'REF-DiscoveryOff' -Description 'SMB server, WPAD, LLMNR, mDNS, SSDP off' `
#       -DetectPath .\remediations\DiscoveryOff\Detect.ps1 -RemediatePath .\remediations\DiscoveryOff\Remediate.ps1 -Schedule Hourly
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Description,
    [Parameter(Mandatory)][string]$DetectPath,
    [string]$RemediatePath,
    [ValidateSet('Hourly', 'Daily')][string]$Schedule = 'Hourly',
    [string]$DailyTime = '06:30',
    [ValidateSet('system', 'user')][string]$RunAs = 'system',
    [switch]$WhatIfOnly
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\_Common.ps1"
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source scripts\Connect-Tenant.ps1 and run Connect-Tenant first.' }
$base = 'https://graph.microsoft.com/beta/deviceManagement'
if (-not (Test-Path $DetectPath)) { throw "Not found: $DetectPath" }
if ($RemediatePath -and -not (Test-Path $RemediatePath)) { throw "Not found: $RemediatePath" }
$gid = $global:Cfg.devices.deviceGroupId
if (-not $gid -or $gid -eq '00000000-0000-0000-0000-000000000000') { throw 'config.json devices.deviceGroupId is not set.' }
$detect = [Convert]::ToBase64String([IO.File]::ReadAllBytes($DetectPath))
$remediate = if ($RemediatePath) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($RemediatePath)) } else { [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("Write-Output 'detection-only; no remediation defined'; exit 0`n")) }
$runRemediation = [bool]$RemediatePath
$sha = { param($p) (Get-FileHash $p -Algorithm SHA256).Hash.Substring(0, 8) }
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "$base/deviceHealthScripts").value | Where-Object { $_.displayName -eq $DisplayName })
if ($existing.Count) { Write-Output ("Already exists: id={0}. Nothing created (Update-Remediation.ps1 changes an existing one)." -f $existing[0].id); return }
Write-Output ("'{0}': {1}, run as {2}, remediation {3}, group {4}; detect sha {5}{6}" -f $DisplayName, $Schedule, $RunAs, $(if ($runRemediation) { 'ON' } else { 'OFF' }), $gid, (& $sha $DetectPath), $(if ($RemediatePath) { ", remediate sha $(& $sha $RemediatePath)" }))
if ($WhatIfOnly) { Write-Output 'WhatIfOnly - nothing created.'; return }
$body = @{ '@odata.type' = '#microsoft.graph.deviceHealthScript'; displayName = $DisplayName; description = $Description; publisher = $global:Cfg.tenant.primaryDomain
           runAs32Bit = $false; runAsAccount = $RunAs; enforceSignatureCheck = $false; detectionScriptContent = $detect; remediationScriptContent = $remediate } | ConvertTo-Json -Depth 20
$r = Invoke-MgGraphRequest -Method POST -Uri "$base/deviceHealthScripts" -Body $body -ContentType 'application/json'
Write-Output ("CREATED: id={0}" -f $r.id)
# no useUtc in the daily schedule: the API returns 500 with it. "${DailyTime}:00" needs the braces, or PowerShell reads a scoped variable and sends an empty time.
$sched = if ($Schedule -eq 'Hourly') { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptHourlySchedule'; interval = 1 } } else { @{ '@odata.type' = '#microsoft.graph.deviceHealthScriptDailySchedule'; interval = 1; time = "${DailyTime}:00" } }
$assign = @{ deviceHealthScriptAssignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $gid }; runRemediationScript = $runRemediation; runSchedule = $sched }) } | ConvertTo-Json -Depth 20
Invoke-MgGraphRequest -Method POST -Uri "$base/deviceHealthScripts/$($r.id)/assign" -Body $assign -ContentType 'application/json' | Out-Null
Write-Output ("ASSIGNED: {0}, remediation {1}. Record it in your change register and take a new baseline snapshot." -f $Schedule, $(if ($runRemediation) { 'ON' } else { 'OFF' }))
