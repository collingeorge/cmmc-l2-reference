# Baseline-Snapshot.ps1 - READ-ONLY against the tenant. Admin account with Global Reader (or Global Administrator) active;
# Azure read access for the Sentinel part. NIST SP 800-171 3.4.1 (baseline configuration), 3.4.2, 3.4.3, 3.12.3.
#
# WHY. Devices self-correct (remediations, watchdog, consistency scan), but a change made IN THE TENANT - a policy edited, a
# remediation replaced, an assignment removed, an alert rule disabled - is visible only in audit logs. This freezes the
# approved tenant configuration and reports any difference from it. The exported folder, once the Security Officer approves
# it in the baseline standard, IS the approved baseline; every later difference is either a recorded change or drift.
#
#   -Mode Export                    writes ConfigBackup\BASELINE-<date>\ : one JSON per object plus manifest.json (normalised
#                                   SHA-256 per object)
#   -Mode Compare -Baseline <dir>   re-reads the tenant and lists ADDED / REMOVED / CHANGED objects (by name) with the changed
#                                   top-level fields; writes Evidence\<date>\baseline-drift-<time>.txt; exit code 1 if anything differs
# Captured: Intune settings-catalog policies (settings + assignments), device configuration profiles, compliance policies,
# app-protection policies, remediations (script hashes, schedule, assignments), platform scripts, endpoint-security intents;
# Entra Conditional Access and the authentication-methods policy; Azure data collection rules, log-alert rules, action
# groups, workspace retention. Volatile fields (timestamps, etags, version counters) are ignored.
[CmdletBinding()]
param([ValidateSet('Export', 'Compare')][string]$Mode = 'Export', [string]$Baseline)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\_Common.ps1"
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { . "$PSScriptRoot\Connect-Tenant.ps1"; Connect-Tenant }
$gb = 'https://graph.microsoft.com/beta'
function GGet($uri) { Invoke-Retry { Invoke-MgGraphRequest -Method GET -Uri $uri } }
function GAll($uri) { $o = @(); while ($uri) { $p = GGet $uri; $o += @($p.value); $uri = $p.'@odata.nextLink' }; $o }
$volatile = '^(lastModifiedDateTime|createdDateTime|modifiedDateTime|lastModified|@odata\.context|@odata\.etag|@odata\.nextLink|etag|version|settingCount|systemData|changedTime|createdTime|lastUpdated.*|deviceStatusOverview|userStatusOverview|isAssigned|provisioningState|lastSyncDateTime|.*@odata\.navigationLink)$'
function Norm($o) {
    if ($o -is [System.Collections.IDictionary]) { $h = [ordered]@{}; foreach ($k in ($o.Keys | Sort-Object)) { if ("$k" -notmatch $volatile) { $h[$k] = Norm $o[$k] } }; return $h }
    if ($o -is [System.Collections.IList] -and $o -isnot [string]) { return , @($o | ForEach-Object { Norm $_ }) }
    return $o
}
function Get-ObjHash($o) { $j = (Norm $o) | ConvertTo-Json -Depth 60 -Compress; $s = [Security.Cryptography.SHA256]::Create(); ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes($j))) -replace '-', '').Substring(0, 16) }
function ToHash($x) { $x | ConvertTo-Json -Depth 60 | ConvertFrom-Json -AsHashtable }
function SafeName($s) { ($s -replace '[^\w\.-]+', '_').Trim('_') }
function Sha8($b64) { if ($b64) { $x = [Security.Cryptography.SHA256]::Create(); ([BitConverter]::ToString($x.ComputeHash([Convert]::FromBase64String($b64))) -replace '-', '').Substring(0, 8) } }

$objs = New-Object Collections.ArrayList
function Add-Obj($kind, $id, $name, $data) { [void]$objs.Add(@{ Kind = $kind; Id = "$id"; Name = "$name"; Data = (ToHash $data) }) }
Write-Host 'Reading Intune...' -ForegroundColor Cyan
foreach ($p in @(GAll "$gb/deviceManagement/configurationPolicies?`$select=id,name,description,platforms,technologies,roleScopeTagIds,templateReference")) {
    $p.settings = @(GAll "$gb/deviceManagement/configurationPolicies('$($p.id)')/settings?`$top=1000" | ForEach-Object { $_.settingInstance })
    $p.assignments = @(GAll "$gb/deviceManagement/configurationPolicies('$($p.id)')/assignments" | ForEach-Object { $_.target })
    Add-Obj 'SettingsCatalogPolicy' $p.id $p.name $p }
foreach ($p in @(GAll "$gb/deviceManagement/deviceConfigurations?`$expand=assignments")) { $p.assignments = @($p.assignments | ForEach-Object { $_.target }); Add-Obj 'DeviceConfiguration' $p.id $p.displayName $p }
foreach ($p in @(GAll "$gb/deviceManagement/deviceCompliancePolicies?`$expand=assignments")) { $p.assignments = @($p.assignments | ForEach-Object { $_.target }); Add-Obj 'CompliancePolicy' $p.id $p.displayName $p }
foreach ($p in @(GAll "$gb/deviceAppManagement/iosManagedAppProtections?`$expand=apps,assignments")) { $p.assignments = @($p.assignments | ForEach-Object { $_.target }); $p.apps = @($p.apps | ForEach-Object { $_.mobileAppIdentifier.bundleId } | Sort-Object); Add-Obj 'AppProtectionIOS' $p.id $p.displayName $p }
foreach ($p in @(GAll "$gb/deviceAppManagement/androidManagedAppProtections?`$expand=apps,assignments")) { $p.assignments = @($p.assignments | ForEach-Object { $_.target }); $p.apps = @($p.apps | ForEach-Object { $_.mobileAppIdentifier.packageId } | Sort-Object); Add-Obj 'AppProtectionAndroid' $p.id $p.displayName $p }
foreach ($s in @(GAll "$gb/deviceManagement/deviceHealthScripts")) {
    $f = GGet "$gb/deviceManagement/deviceHealthScripts/$($s.id)"
    $a = @(GAll "$gb/deviceManagement/deviceHealthScripts/$($s.id)/assignments" | ForEach-Object { @{ target = $_.target; runSchedule = $_.runSchedule; runRemediationScript = $_.runRemediationScript } })
    Add-Obj 'Remediation' $s.id $s.displayName ([ordered]@{ displayName = $f.displayName; description = $f.description; runAsAccount = $f.runAsAccount; runAs32Bit = $f.runAs32Bit; enforceSignatureCheck = $f.enforceSignatureCheck; detectSha8 = (Sha8 $f.detectionScriptContent); remediateSha8 = (Sha8 $f.remediationScriptContent); assignments = $a }) }
foreach ($s in @(GAll "$gb/deviceManagement/deviceManagementScripts")) { $f = GGet "$gb/deviceManagement/deviceManagementScripts/$($s.id)"; Add-Obj 'PlatformScript' $s.id $s.displayName ([ordered]@{ displayName = $f.displayName; runAsAccount = $f.runAsAccount; fileName = $f.fileName; scriptSha8 = (Sha8 $f.scriptContent) }) }
try { foreach ($i in @(GAll "$gb/deviceManagement/intents")) { $i.settings = @(GAll "$gb/deviceManagement/intents/$($i.id)/settings"); $i.assignments = @(GAll "$gb/deviceManagement/intents/$($i.id)/assignments" | ForEach-Object { $_.target }); Add-Obj 'EndpointSecurityIntent' $i.id $i.displayName $i } } catch { Write-Host "  intents not read: $($_.Exception.Message)" -ForegroundColor DarkYellow }
Write-Host 'Reading Entra...' -ForegroundColor Cyan
try { foreach ($c in @(GAll 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies')) { Add-Obj 'ConditionalAccess' $c.id $c.displayName $c } } catch { Write-Host "  Conditional Access not read: $($_.Exception.Message)" -ForegroundColor DarkYellow }
try { $am = GGet 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy'; Add-Obj 'AuthMethodsPolicy' 'authenticationMethodsPolicy' 'Authentication methods policy' $am } catch { Write-Host "  auth methods not read: $($_.Exception.Message)" -ForegroundColor DarkYellow }
Write-Host 'Reading Azure...' -ForegroundColor Cyan
try {
    $Hd = @{ Authorization = "Bearer $(Get-ArmToken)" }; $arm = 'https://management.azure.com'
    $q = { param($t, $v) @((Invoke-Retry { Invoke-RestMethod -Headers $Hd -Uri "$arm$global:ArmSub/providers/$t`?api-version=$v" }).value) }
    foreach ($r in (& $q 'Microsoft.Insights/dataCollectionRules' '2022-06-01')) { Add-Obj 'DataCollectionRule' $r.id $r.name @{ location = $r.location; properties = $r.properties } }
    foreach ($r in (& $q 'Microsoft.Insights/scheduledQueryRules' '2023-03-15-preview')) { Add-Obj 'LogAlertRule' $r.id $r.name @{ properties = $r.properties } }
    foreach ($r in (& $q 'Microsoft.Insights/actionGroups' '2023-01-01')) { Add-Obj 'ActionGroup' $r.id $r.name @{ properties = $r.properties } }
    foreach ($r in (& $q 'Microsoft.OperationalInsights/workspaces' '2022-10-01')) { Add-Obj 'Workspace' $r.id $r.name @{ retentionInDays = $r.properties.retentionInDays; sku = $r.properties.sku; publicNetworkAccessForIngestion = $r.properties.publicNetworkAccessForIngestion } }
} catch { Write-Host "  Azure not read: $($_.Exception.Message)" -ForegroundColor DarkYellow }

$now = Get-Date
$cur = @{}; foreach ($o in $objs) { $cur["$($o.Kind)|$($o.Id)"] = @{ Kind = $o.Kind; Id = $o.Id; Name = $o.Name; Hash = (Get-ObjHash $o.Data); Data = $o.Data } }
Write-Output "Read $($objs.Count) objects: $(($objs | Group-Object { $_.Kind } | ForEach-Object { "$($_.Name) $($_.Count)" }) -join ', ')"

if ($Mode -eq 'Export') {
    $dir = Join-Path $global:BackupRoot ("BASELINE-" + $now.ToString('yyyy-MM-dd-HHmmss')); New-Item -ItemType Directory -Force $dir | Out-Null
    $man = foreach ($k in ($cur.Keys | Sort-Object)) { $o = $cur[$k]; $file = "$(SafeName $o.Kind)__$(SafeName $o.Name)__$((SafeName $o.Id).Substring(0, [Math]::Min(12, (SafeName $o.Id).Length))).json"
        (Norm $o.Data) | ConvertTo-Json -Depth 60 | Set-Content (Join-Path $dir $file) -Encoding UTF8
        [ordered]@{ kind = $o.Kind; id = $o.Id; name = $o.Name; hash = $o.Hash; file = $file } }
    @{ taken = $now.ToString('s'); tenant = $global:RefTenant; by = $global:RefGraph.Account; count = $objs.Count; objects = @($man) } | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $dir 'manifest.json') -Encoding UTF8
    Write-Output "BASELINE EXPORTED: $dir ($($objs.Count) objects). Approve it in your baseline standard; compare later with -Mode Compare -Baseline '$dir'"
    return
}
if (-not $Baseline -or -not (Test-Path (Join-Path $Baseline 'manifest.json'))) { throw 'Give -Baseline <ConfigBackup\BASELINE-... folder>.' }
$m = Get-Content (Join-Path $Baseline 'manifest.json') -Raw | ConvertFrom-Json
$base = @{}; foreach ($o in $m.objects) { $base["$($o.kind)|$($o.id)"] = $o }
$out = New-Object Collections.ArrayList; function W($s) { [void]$out.Add("$s"); Write-Output "$s" }
W "Baseline drift check - $($now.ToString('yyyy-MM-dd HH:mm zzz')) - against $(Split-Path $Baseline -Leaf) (taken $($m.taken))"
$added = @($cur.Keys | Where-Object { -not $base.ContainsKey($_) }); $removed = @($base.Keys | Where-Object { -not $cur.ContainsKey($_) })
$changed = @($cur.Keys | Where-Object { $base.ContainsKey($_) -and $base[$_].hash -ne $cur[$_].Hash })
foreach ($k in $added) { W "  ADDED    $($cur[$k].Kind): $($cur[$k].Name)" }
foreach ($k in $removed) { W "  REMOVED  $($base[$k].kind): $($base[$k].name)" }
foreach ($k in $changed) {
    $old = Get-Content (Join-Path $Baseline $base[$k].file) -Raw | ConvertFrom-Json -AsHashtable; $new = Norm $cur[$k].Data
    $fields = @(@($old.Keys) + @($new.Keys) | Sort-Object -Unique | Where-Object { ($old[$_] | ConvertTo-Json -Depth 60 -Compress) -ne ($new[$_] | ConvertTo-Json -Depth 60 -Compress) })
    W "  CHANGED  $($cur[$k].Kind): $($cur[$k].Name)  (fields: $($fields -join ', '))" }
W "RESULT: $($cur.Count) objects now, $($base.Count) in baseline | added $($added.Count) | removed $($removed.Count) | changed $($changed.Count)"
if ($added.Count + $removed.Count + $changed.Count) { W 'Every difference must match an approved entry in your change register; anything else is unauthorised drift and goes to incident response. Approved changes: export a new baseline and record it.' }
$f = New-EvidenceFile 'baseline-drift'; [IO.File]::WriteAllLines($f, [string[]]$out); "written: $f"
if ($added.Count + $removed.Count + $changed.Count) { exit 1 }
