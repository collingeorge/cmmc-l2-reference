# Review-AlertQueue.ps1 - the DAILY alert-queue review (NIST SP 800-171 3.3.5, 3.6.1; CMMC AU.L2-3.3.5, IR.L2-3.6.1).
# Admin account with Azure read (and write to close). Read-only by default: lists every Azure Monitor alert still New,
# numbered, each with the rows its own rule query matched in the alert's window, and every Sentinel incident not Closed.
#   -Close 1,3,4 -Comment '...'   closes those numbered alerts with that comment (the comment IS the review record)
#   -CloseAll -Comment '...'      closes every alert listed in THIS run (only after reading the whole list)
# Never closes an incident (Triage-NewIncidents.ps1 does that on evidence rules) and never changes a rule.
# WHY the comment: "I read the e-mails" is not evidence. The alert's closed state with the cause written in is.
[CmdletBinding()]
param([int[]]$Close, [switch]$CloseAll, [string]$Comment)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Common.ps1"
if (($Close -or $CloseAll) -and -not $Comment) { throw 'A -Comment is required to close: it is the review record.' }
if (-not (Get-Command Get-ArmToken -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source Connect-Tenant.ps1 and run Connect-Tenant first.' }
$Hd = @{ Authorization = "Bearer $(Get-ArmToken)" }; $arm = 'https://management.azure.com'; $amApi = 'api-version=2019-05-05-preview'
$log = New-Object Collections.ArrayList; function W($s) { [void]$log.Add("$s"); Write-Output "$s" }
$evf = New-EvidenceFile 'alert-queue'
W "=== Alert queue review, $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz')"
$rules = @((Invoke-RestMethod -Headers $Hd -Uri "$arm$global:ArmSub/providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview").value)
$all = @(); $au = "$arm$global:ArmSub/providers/Microsoft.AlertsManagement/alerts?$amApi&timeRange=30d&pageCount=250&alertState=New"
while ($au) { $pg = Invoke-RestMethod -Headers $Hd -Uri $au; $all += @($pg.value); $au = $pg.nextLink }
$all = @($all | Sort-Object { ToUtc $_.properties.essentials.startDateTime })
W "--- Azure Monitor alerts New: $($all.Count)"
$i = 0
foreach ($a in $all) {
    $i++; $rn = ($a.properties.essentials.alertRule -split '/')[-1]; $st = ToUtc $a.properties.essentials.startDateTime
    W ("[{0,3}] {1:yyyy-MM-dd HH:mm:ss}Z {2,-5} {3}" -f $i, $st, $a.properties.essentials.severity, $rn)
    $ru = @($rules | Where-Object name -eq $rn)[0]; if (-not $ru) { continue }
    $q = "$(@($ru.properties.criteria.allOf)[0].query)".Trim()
    $w = "TimeGenerated between (datetime($($st.AddMinutes(-20).ToString('yyyy-MM-ddTHH:mm:ssZ'))) .. datetime($($st.AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ssZ'))))"
    $q2 = [regex]::Replace($q, 'ingestion_time\(\)\s*>\s*ago\(\s*\d+\s*[mhd]\s*\)', $w)
    try { $rows = @(Invoke-Kql $q2); foreach ($r in $rows | Select-Object -First 4) { W ("      " + (Trunc (($r.PSObject.Properties | ForEach-Object { "$($_.Value)" }) -join ' | ') 260)) }; if ($rows.Count -gt 4) { W "      (+$($rows.Count - 4) more)" }; if (-not $rows.Count) { W '      (query matches nothing now - a summary or stateful rule, or the rule was tuned since)' } }
    catch { W "      re-run refused: $(Trunc $_.ErrorDetails.Message 160)" }
}
W '--- Sentinel incidents not Closed'
$inc = @((Invoke-RestMethod -Headers $Hd -Uri "$arm$global:ArmWorkspace/providers/Microsoft.SecurityInsights/incidents?api-version=2023-02-01&`$filter=properties/status ne 'Closed'&`$top=50").value)
if (-not $inc.Count) { W '  none' } else { foreach ($x in $inc) { W ("  #{0} [{1}/{2}] {3}  first {4}" -f $x.properties.incidentNumber, $x.properties.severity, $x.properties.status, $x.properties.title, $x.properties.firstActivityTimeUtc) } }
$pick = @(); if ($CloseAll) { $pick = $all } elseif ($Close) { foreach ($n in $Close) { if ($n -ge 1 -and $n -le $all.Count) { $pick += $all[$n - 1] } else { W "  no alert numbered $n" } } }
if ($pick.Count) {
    W "--- closing $($pick.Count) alert(s) with: $Comment"
    $ok = 0; $bad = 0
    foreach ($a in $pick) { try { Invoke-RestMethod -Method POST -Headers $Hd -ContentType 'application/json' -Uri "$arm$($a.id)/changestate?$amApi&newState=Closed" -Body (@{ comments = "$Comment (reviewed $(Get-Date -Format 'yyyy-MM-dd HH:mm') by the Security Officer)" } | ConvertTo-Json) | Out-Null; $ok++ } catch { $bad++; W "  refused: $(Trunc $_.ErrorDetails.Message 160)" } }
    W "  closed $ok, refused $bad"
} else { W 'Read-only. Nothing changed.' }
[IO.File]::WriteAllLines($evf, [string[]]$log); "written: $evf"
