# Deploy-SettingsCatalogPolicy.ps1 - creates ONE Intune settings-catalog policy from a JSON definition in
# policies/settings-catalog/ and assigns it to the device group in config.json. Read-only without -Apply.
#   .\policies\Deploy-SettingsCatalogPolicy.ps1 -Definition .\policies\settings-catalog\REF-Firewall.json
#   .\policies\Deploy-SettingsCatalogPolicy.ps1 -Definition ... -Apply
# Refuses to create a duplicate name. Prints the id. Backs up nothing because it creates; to change an existing policy,
# export it, edit, and PUT the settings - see Update-SettingsCatalogPolicy.ps1 (batch 3).
# Template-based policies (a non-null templateReference) accept only settings that belong to the template; if Graph refuses
# a setting with "not applicable to the template", move that setting to a policy of your own without a template.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Definition, [switch]$Apply, [string]$Name)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\_Common.ps1"
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source scripts\Connect-Tenant.ps1 and run Connect-Tenant first.' }
$g = 'https://graph.microsoft.com/beta/deviceManagement'
$def = Get-Content $Definition -Raw | ConvertFrom-Json -AsHashtable
if ($Name) { $def.name = $Name }
$gid = $global:Cfg.devices.deviceGroupId
if (-not $gid -or $gid -eq '00000000-0000-0000-0000-000000000000') { throw 'config.json devices.deviceGroupId is not set.' }
$existing = @((Invoke-MgGraphRequest -Method GET -Uri "$g/configurationPolicies?`$filter=name eq '$($def.name)'&`$select=id,name").value)
Write-Output ("'{0}': {1} setting(s), platforms={2}, technologies={3}, template={4}, group {5}" -f $def.name, @($def.settings).Count, $def.platforms, $def.technologies, $(if ($def.templateReference.templateId) { $def.templateReference.templateId } else { 'none' }), $gid)
if ($existing.Count) { Write-Output "ALREADY EXISTS: id=$($existing[0].id). Nothing created."; return }
if (-not $Apply) { Write-Output 'Read-only. Add -Apply to create.'; return }
$body = @{ name = $def.name; description = $def.description; platforms = $def.platforms; technologies = $def.technologies; roleScopeTagIds = @('0'); settings = @($def.settings | ForEach-Object { @{ '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSetting'; settingInstance = $_ } }) }
if ($def.templateReference -and $def.templateReference.templateId) { $body.templateReference = @{ templateId = $def.templateReference.templateId } }
$r = Invoke-MgGraphRequest -Method POST -Uri "$g/configurationPolicies" -Body ($body | ConvertTo-Json -Depth 60) -ContentType 'application/json'
Write-Output "CREATED: id=$($r.id)"
Invoke-MgGraphRequest -Method POST -Uri "$g/configurationPolicies('$($r.id)')/assign" -Body (@{ assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = $gid } }) } | ConvertTo-Json -Depth 10) -ContentType 'application/json' | Out-Null
$rb = Invoke-MgGraphRequest -Method GET -Uri "$g/configurationPolicies('$($r.id)')?`$select=id,name,settingCount"
Write-Output "ASSIGNED to $gid; read back: $($rb.name), $($rb.settingCount) setting(s). Record it in your change register and take a new baseline snapshot."
