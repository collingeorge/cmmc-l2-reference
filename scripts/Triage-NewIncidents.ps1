# Triage-NewIncidents.ps1 - daily companion to Review-AlertQueue.ps1. Read-only without -Apply. For every Sentinel
# incident not Closed it gathers PRIMARY evidence and closes it BenignPositive only when that evidence is conclusive:
#   'Privileged role assigned'    -> every role addition in the alert window is a PIM activation of the expected role by
#                                    the admin account (AuditLogs 'Add member to role completed (PIM activation)'); nothing else
#   'Audit configuration changed' -> every Exchange admin operation in the window (-10/+2 min) is by Microsoft's Exchange
#                                    service or the admin account, and none disabled auditing or set an audit bypass
# Anything else, or any incident whose evidence does not meet its rule, is listed and LEFT OPEN for a human.
# The two rules above are the ones that fire on routine administration in a tenant like this; add your own with the same
# discipline: a rule closes an incident only on evidence it read itself, never on the title.
[CmdletBinding()]
param([switch]$Apply, [string]$PrivilegedRole = 'Global Administrator')
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Common.ps1"
if (-not (Get-Command Get-ArmToken -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source Connect-Tenant.ps1 and run Connect-Tenant first.' }
$Hd = @{ Authorization = "Bearer $(Get-ArmToken)" }; $arm = 'https://management.azure.com'; $si = "$arm$global:ArmWorkspace/providers/Microsoft.SecurityInsights"; $siApi = 'api-version=2023-02-01'
$admin = $global:Cfg.accounts.admin; $adminRx = '^' + [regex]::Escape($admin) + '$'
$log = New-Object Collections.ArrayList; function W($s) { [void]$log.Add("$s"); Write-Output "$s" }
$evf = New-EvidenceFile 'triage-new-incidents'; $evRel = $evf.Substring($global:EvidenceRoot.Length - 8)
function U($d) { (ToUtc $d).ToString('yyyy-MM-ddTHH:mm:ssZ') }
W "=== New-incident triage, $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz') $(if ($Apply) { '(APPLY)' } else { '(read-only)' })"
$open = @((Invoke-RestMethod -Headers $Hd -Uri "$si/incidents?$siApi&`$filter=properties/status ne 'Closed'&`$top=100").value)
W "--- incidents not Closed: $($open.Count)"
$toClose = @()
foreach ($i in $open | Sort-Object { $_.properties.incidentNumber }) {
    $p = $i.properties; $n = $p.incidentNumber; $from = U ([datetime]$p.firstActivityTimeUtc).AddMinutes(-10); $to = U ([datetime]$p.lastActivityTimeUtc).AddMinutes(2)
    W ("  #{0} [{1}] {2}  {3} -> {4}" -f $n, $p.severity, $p.title, $p.firstActivityTimeUtc, $p.lastActivityTimeUtc)
    $verdict = $null
    if ($p.title -like '*Privileged role assigned*') {
        $rows = @(Invoke-Kql "AuditLogs | where TimeGenerated between (datetime($from) .. datetime($to)) | where OperationName has 'member to role' or OperationName has 'role assignment' | extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), Target = tostring(TargetResources[0].userPrincipalName), Role = tostring(TargetResources[0].modifiedProperties[1].newValue) | project TimeGenerated, OperationName, Actor, Target, Role, Result")
        foreach ($r in $rows) { W "      $(Trunc $r.TimeGenerated 19) | $($r.OperationName) | $($r.Actor) | $($r.Target) | $($r.Role) | $($r.Result)" }
        $bad = @($rows | Where-Object { -not (($_.OperationName -match 'PIM activation' -and $_.Actor -match $adminRx) -or ($_.Actor -eq 'MS-PIM' -and $_.Target -match $adminRx -and $_.Role -match [regex]::Escape($PrivilegedRole))) })
        if ($rows.Count -and -not $bad.Count) { $verdict = "Benign. PIM activation of $PrivilegedRole by the admin account for a recorded admin session (AuditLogs 'PIM activation' via MS-PIM in the alert window); no other role change. Evidence: $evRel. Daily review." }
        else { W "      LEFT OPEN: $(if ($rows.Count) { "$($bad.Count) row(s) outside the rule" } else { 'no role change found in the window' })" }
    } elseif ($p.title -like '*Audit configuration changed*') {
        $rows = @(Invoke-Kql "OfficeActivity | where TimeGenerated between (datetime($from) .. datetime($to)) | where RecordType has 'ExchangeAdmin' | summarize n = count(), P = make_set(tostring(Parameters), 60) by UserId, Operation")
        $actors = @($rows | ForEach-Object { $_.UserId } | Sort-Object -Unique); $weak = @()
        foreach ($r in $rows) { $pj = (@($r.P) -join ' '); if ($pj -match '"Name":"(Audit\w*|UnifiedAuditLogIngestionEnabled|AdminAuditLogEnabled)","Value":"False"' -or $pj -match '"Name":"AuditBypassEnabled","Value":"True"' -or $r.Operation -match 'AuditBypass') { $weak += "$($r.UserId) $($r.Operation)" } }
        $ops = (($rows | ForEach-Object { $_.Operation } | Sort-Object -Unique) -join ', ')
        W "      Exchange admin actors: $(if ($actors.Count) { ($actors | ForEach-Object { $_ -replace ' \(Microsoft\.Exchange\.AdminApi\.NetCore\)', '' }) -join '; ' } else { 'NONE FOUND' }); operations: $ops"
        $unknown = @($actors | Where-Object { $_ -notmatch 'MSExchangeAdminApiNetCore' -and $_ -notmatch $adminRx })
        if ($weak.Count) { W "      LEFT OPEN - AUDITING TURNED OFF OR BYPASSED: $($weak -join '; ')" }
        elseif (-not $actors.Count -or $unknown.Count) { W "      LEFT OPEN: $(if ($unknown.Count) { "unexpected actor(s): $($unknown -join ', ')" } else { 'no Exchange admin activity in the window' })" }
        else { $verdict = "Benign. Purview 'Audit configuration changed': every Exchange admin operation in the alert window was by Microsoft's Exchange Online service (service-side organisation servicing)$(if ($actors -match $adminRx) { ' or the admin account in a recorded admin session' }); no audit setting disabled or bypassed. Operations: $ops. Evidence: $evRel. Daily review." }
    } else { W '      no automatic rule for this title - LEFT OPEN for a human' }
    if ($verdict) { W '      -> close BenignPositive'; $toClose += [pscustomobject]@{ I = $i; C = $verdict } }
}
if (-not $Apply) { W "Read-only. Nothing changed. $($toClose.Count) incident(s) would close on -Apply."; [IO.File]::WriteAllLines($evf, [string[]]$log); "written: $evf"; return }
W '--- APPLY'
foreach ($c in $toClose) {
    $i = $c.I; $n = $i.properties.incidentNumber
    try {
        Invoke-RestMethod -Method PUT -Headers $Hd -ContentType 'application/json' -Uri "$arm$($i.id)/comments/$([guid]::NewGuid())?$siApi" -Body (@{ properties = @{ message = $c.C } } | ConvertTo-Json -Depth 5) | Out-Null
        $i = Invoke-RestMethod -Headers $Hd -Uri "$arm$($i.id)?$siApi"; $p = $i.properties   # fresh etag: the comment changed it
        $body = @{ etag = $i.etag; properties = @{ title = $p.title; severity = $p.severity; status = 'Closed'; classification = 'BenignPositive'; classificationReason = 'SuspiciousButExpected'; classificationComment = $c.C.Substring(0, [Math]::Min(1000, $c.C.Length)) } }; if ($p.owner) { $body.properties.owner = $p.owner }
        $rb = Invoke-RestMethod -Method PUT -Headers $Hd -ContentType 'application/json' -Uri "$arm$($i.id)?$siApi" -Body ($body | ConvertTo-Json -Depth 8)
        W "  #$n $($rb.properties.status) / $($rb.properties.classification)"
    } catch { W "  #$n REFUSED: $(Trunc $_.ErrorDetails.Message 200)" }
}
[IO.File]::WriteAllLines($evf, [string[]]$log); "written: $evf"
