# Deploy-ConditionalAccessPolicy.ps1 - creates ONE Conditional Access policy from a JSON definition in
# policies/conditional-access/, ALWAYS in report-only, with the placeholders resolved from config.json:
#   <excludeUsers-from-config>              -> the break-glass account (always) and, where the definition had a second
#                                              exclusion, the admin account (token protection: command-line tools cannot bind tokens)
#   <excludeApplications-app-id-from-config> -> conditionalAccess.excludedAppIds in config.json (optional; empty if absent)
# Read-only without -Apply. Refuses duplicates by displayName. Switch a policy to 'enabled' only after reading the
# report-only results in the sign-in logs (every evaluated sign-in shows reportOnlySuccess), never before - a Conditional
# Access policy switched on before its own read is how you lock yourself out.
# WAY BACK from any policy: PATCH { "state": "enabledForReportingButNotEnforced" } from a window that still holds a token.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Definition, [switch]$Apply, [string]$Name)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\_Common.ps1"
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source scripts\Connect-Tenant.ps1 and run Connect-Tenant first.' }
$ca = 'https://graph.microsoft.com/beta/identity/conditionalAccess/policies'
$def = Get-Content $Definition -Raw | ConvertFrom-Json -AsHashtable
if ($Name) { $def.displayName = $Name }
function UserId($upn) { (Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$upn`?`$select=id").id }
$bg = UserId $global:Cfg.accounts.breakGlass; $adm = UserId $global:Cfg.accounts.admin
$u = $def.conditions.users
if ($u) {
    foreach ($k in 'includeUsers', 'excludeUsers', 'includeGroups', 'excludeGroups') {
        if (-not $u[$k]) { continue }
        $ph = @($u[$k] | Where-Object { $_ -like '<*' }).Count; $real = @($u[$k] | Where-Object { $_ -notlike '<*' })
        if ($k -eq 'excludeUsers' -and $ph) { $u[$k] = @($real + $bg + $(if ($ph -ge 2) { $adm })) }
        elseif ($ph) { $u[$k] = @($real) }
    }
    if (-not @($u.excludeUsers).Count -or $u.excludeUsers -notcontains $bg) { $u.excludeUsers = @(@($u.excludeUsers) + $bg) }   # the break-glass account is excluded from EVERY policy
}
$ap = $def.conditions.applications
if ($ap) { foreach ($k in 'includeApplications', 'excludeApplications') { if ($ap[$k]) { $ap[$k] = @($ap[$k] | ForEach-Object { if ($_ -like '<*') { @($global:Cfg.conditionalAccess.excludedAppIds) } else { $_ } } | Where-Object { $_ }) } } }
$def.state = 'enabledForReportingButNotEnforced'
$existing = @((Invoke-MgGraphRequest -Method GET -Uri $ca).value | Where-Object displayName -eq $def.displayName)
Write-Output ("'{0}': state={1} users={2} excludeUsers={3} apps={4} platforms={5} clients={6} grant={7} session={8}" -f $def.displayName, $def.state, ($u.includeUsers -join ','), ($u.excludeUsers -join ','), ($ap.includeApplications -join ','), ($def.conditions.platforms.includePlatforms -join ','), ($def.conditions.clientAppTypes -join ','), ($def.grantControls.builtInControls -join ','), ($def.sessionControls.Keys -join ','))
if ($existing.Count) { Write-Output "ALREADY EXISTS: id=$($existing[0].id) state=$($existing[0].state). Nothing created."; return }
if (-not $Apply) { Write-Output 'Read-only. Add -Apply to create (report-only).'; return }
$r = Invoke-MgGraphRequest -Method POST -Uri $ca -Body ($def | ConvertTo-Json -Depth 30) -ContentType 'application/json'
$rb = Invoke-MgGraphRequest -Method GET -Uri "$ca/$($r.id)"
Write-Output "CREATED: id=$($rb.id) state=$($rb.state) excludeUsers=$($rb.conditions.users.excludeUsers -join ','). Read the report-only results before enabling."
