# Deploy-CompliancePolicy.ps1 - creates ONE Intune compliance policy from a JSON definition in policies/compliance/,
# with the "mark non-compliant immediately" action, and assigns it to the device group in config.json.
# Read-only without -Apply. Refuses duplicates by displayName.
# A compliance policy only matters because Conditional Access requires a compliant device (REF-CA-RequireCompliantDevice):
# deploy the policy, let devices report compliant, THEN switch that Conditional Access policy from report-only to on.
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
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "$g/deviceCompliancePolicies?`$filter=displayName eq '$($def.displayName)'&`$select=id,displayName").value)
Write-Output ("'{0}': {1}, group {2}" -f $def.displayName, $def.'@odata.type', $gid)
foreach ($k in ($def.Keys | Where-Object { $_ -notin '@odata.type', 'displayName', 'description', 'roleScopeTagIds' -and $null -ne $def[$_] -and "$($def[$_])" -ne '' -and "$($def[$_])" -ne 'False' } | Sort-Object)) { Write-Output ("    {0,-44} {1}" -f $k, (Trunc ($def[$k] | ConvertTo-Json -Compress -Depth 5) 60)) }
if ($existing.Count) { Write-Output "ALREADY EXISTS: id=$($existing[0].id). Nothing created."; return }
if (-not $Apply) { Write-Output 'Read-only. Add -Apply to create.'; return }
$def.roleScopeTagIds = @('0')
$def.scheduledActionsForRule = @(@{ ruleName = 'PasswordRequired'; scheduledActionConfigurations = @(@{ actionType = 'block'; gracePeriodHours = 0; notificationTemplateId = ''; notificationMessageCCList = @() }) })
$r = Invoke-MgGraphRequest -Method POST -Uri "$g/deviceCompliancePolicies" -Body ($def | ConvertTo-Json -Depth 30) -ContentType 'application/json'
Write-Output "CREATED: id=$($r.id)"
Invoke-MgGraphRequest -Method POST -Uri "$g/deviceCompliancePolicies/$($r.id)/assign" -Body (@{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $gid } }) } | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
Write-Output "ASSIGNED to $gid. Record it in your change register and take a new baseline snapshot."
