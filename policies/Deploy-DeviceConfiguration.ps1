# Deploy-DeviceConfiguration.ps1 - creates ONE Intune device configuration profile (custom OMA-URI and other classic
# profile types) from a JSON definition in policies/device-configuration/ and assigns it to the device group in
# config.json. Read-only without -Apply. Refuses duplicates by displayName.
#   .\policies\Deploy-DeviceConfiguration.ps1 -Definition .\policies\device-configuration\REF-IA-HelloNoAutoProvision.json -Apply
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Definition, [switch]$Apply, [string]$Name)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\_Common.ps1"
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source scripts\Connect-Tenant.ps1 and run Connect-Tenant first.' }
$g = 'https://graph.microsoft.com/beta/deviceManagement'
$def = Get-Content $Definition -Raw | ConvertFrom-Json -AsHashtable
if ($Name) { $def.displayName = $Name }
$gid = $global:Cfg.devices.deviceGroupId
if (-not $gid -or $gid -eq '00000000-0000-0000-0000-000000000000') { throw 'config.json devices.deviceGroupId is not set.' }
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "$g/deviceConfigurations?`$filter=displayName eq '$($def.displayName)'&`$select=id,displayName").value)
Write-Output ("'{0}': {1}, {2} OMA-URI setting(s), group {3}" -f $def.displayName, $def.'@odata.type', @($def.omaSettings).Count, $gid)
foreach ($s in @($def.omaSettings)) { Write-Output ("    {0,-60} = {1}" -f $s.omaUri, (Trunc $s.value 60)) }
if ($existing.Count) { Write-Output "ALREADY EXISTS: id=$($existing[0].id). Nothing created."; return }
if (-not $Apply) { Write-Output 'Read-only. Add -Apply to create.'; return }
$def.roleScopeTagIds = @('0')
$r = Invoke-MgGraphRequest -Method POST -Uri "$g/deviceConfigurations" -Body ($def | ConvertTo-Json -Depth 30) -ContentType 'application/json'
Write-Output "CREATED: id=$($r.id)"
Invoke-MgGraphRequest -Method POST -Uri "$g/deviceConfigurations/$($r.id)/assign" -Body (@{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $gid } }) } | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
Write-Output "ASSIGNED to $gid. Record it in your change register and take a new baseline snapshot."
