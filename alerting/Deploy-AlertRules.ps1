# Deploy-AlertRules.ps1 - creates the Azure Monitor log-alert rules in alerting/rules/*.json against the Log Analytics
# workspace in config.json, wired to the action group in config.json. Read-only without -Apply; refuses to overwrite an
# existing rule of the same name (edit those with -Update, which backs up the live rule first).
#   .\alerting\Deploy-AlertRules.ps1                       # plan: which rules exist, which would be created
#   .\alerting\Deploy-AlertRules.ps1 -Apply                # create the missing ones
#   .\alerting\Deploy-AlertRules.ps1 -Only ref-logon -Apply -Update   # replace one rule's definition (backup first)
# Every query is validated against the workspace before anything is written.
[CmdletBinding()]
param([switch]$Apply, [switch]$Update, [string[]]$Only)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\_Common.ps1"
if (-not (Get-Command Get-ArmToken -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source scripts\Connect-Tenant.ps1 and run Connect-Tenant first.' }
$Hd = @{ Authorization = "Bearer $(Get-ArmToken)" }; $arm = 'https://management.azure.com'; $api = 'api-version=2023-03-15-preview'
$ws = Invoke-RestMethod -Headers $Hd -Uri "$arm$global:ArmWorkspace`?api-version=2022-10-01"
$ag = @((Invoke-RestMethod -Headers $Hd -Uri "$arm$global:ArmRg/providers/Microsoft.Insights/actionGroups?api-version=2023-01-01").value | Where-Object name -eq $global:Cfg.azure.actionGroupName)[0]
if (-not $ag) { throw "Action group '$($global:Cfg.azure.actionGroupName)' not found in $($global:Cfg.azure.resourceGroup). Create it first (e-mail + SMS to the Security Officer)." }
$existing = @((Invoke-RestMethod -Headers $Hd -Uri "$arm$global:ArmRg/providers/Microsoft.Insights/scheduledQueryRules?$api").value)
$bk = New-BackupDir; $stamp = Get-Date -Format 'HHmmss'
$defs = Get-ChildItem "$PSScriptRoot\rules" -Filter *.json | Where-Object { -not $Only -or $_.BaseName -in $Only }
Write-Output "workspace $($ws.name) ($($ws.location)); action group $($ag.name); $($defs.Count) definition(s); $($existing.Count) rule(s) live"
foreach ($f in $defs) {
    $d = Get-Content $f.FullName -Raw | ConvertFrom-Json -AsHashtable
    $live = @($existing | Where-Object name -eq $d.name)[0]
    $valid = try { $null = Invoke-Kql $d.criteria.query; 'query ok' } catch { "QUERY INVALID: $(Trunc $_.ErrorDetails.Message 120)" }
    $state = if ($live -and -not $Update) { 'exists - skipped (use -Update to replace)' } elseif ($live) { 'exists - will be REPLACED' } else { 'will be created' }
    Write-Output ("  {0,-36} sev{1} every {2} window {3}  {4}  {5}" -f $d.name, $d.severity, $d.evaluationFrequency, $d.windowSize, $valid, $state)
    if (-not $Apply -or $valid -notlike 'query ok' -or ($live -and -not $Update)) { continue }
    if ($live) { $live | ConvertTo-Json -Depth 30 | Set-Content (Join-Path $bk "alertrule-$($d.name)-before-$stamp.json") -Encoding UTF8 }
    $crit = @{ query = $d.criteria.query; timeAggregation = $d.criteria.timeAggregation; operator = $d.criteria.operator; threshold = $d.criteria.threshold; failingPeriods = $d.criteria.failingPeriods }
    if ($d.criteria.dimensions) { $crit.dimensions = $d.criteria.dimensions }
    $props = @{ displayName = $d.displayName; description = $d.description; severity = $d.severity; enabled = $d.enabled; evaluationFrequency = $d.evaluationFrequency; windowSize = $d.windowSize
                scopes = @($ws.id); criteria = @{ allOf = @($crit) }; autoMitigate = [bool]$d.autoMitigate; actions = @{ actionGroups = @($ag.id) } }
    if ($d.muteActionsDuration) { $props.muteActionsDuration = $d.muteActionsDuration }
    $uri = "$arm$global:ArmRg/providers/Microsoft.Insights/scheduledQueryRules/$($d.name)?$api"
    try { Invoke-RestMethod -Method PUT -Headers $Hd -ContentType 'application/json' -Uri $uri -Body (@{ location = $ws.location; kind = 'LogAlert'; properties = $props } | ConvertTo-Json -Depth 20) | Out-Null
          $rb = Invoke-RestMethod -Headers $Hd -Uri $uri; Write-Output ("      written; read-back enabled={0} sev={1} query matches={2}" -f $rb.properties.enabled, $rb.properties.severity, (@($rb.properties.criteria.allOf)[0].query.Trim() -eq $d.criteria.query.Trim())) }
    catch { Write-Output "      REFUSED: $(Trunc $_.ErrorDetails.Message 300)" }
}
if (-not $Apply) { Write-Output 'Read-only. Nothing changed.' }
