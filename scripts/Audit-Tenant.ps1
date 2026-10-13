# Audit-Tenant.ps1 - READ-ONLY tenant-side audit: what an assessor asks of the management plane, in one run.
# Admin account with Global Reader (or Global Administrator) active; Azure read access. Changes nothing.
#
# Covers: every managed device and its compliance; every compliance policy's device results; every remediation and its
# per-device results; every configuration policy's state on one device (errors and conflicts); Conditional Access and
# authentication-method policy state, with registered methods per user; Sentinel - alert rules, telemetry freshness per
# machine, event volume, incidents by severity. Writes Evidence\<date>\audit-tenant-<time>.txt.
[CmdletBinding()]
param([string]$Device = $global:Cfg.devices.workstations[0])
$ErrorActionPreference = 'Continue'
. "$PSScriptRoot\_Common.ps1"
if (-not $Device) { $Device = $global:Cfg.devices.workstations[0] }
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source Connect-Tenant.ps1 and run Connect-Tenant first.' }
$g = 'https://graph.microsoft.com/beta'; function GAll($uri) { $o = @(); while ($uri) { $p = Invoke-MgGraphRequest -Method GET -Uri $uri; $o += @($p.value); $uri = $p.'@odata.nextLink' }; $o }
$log = New-Object Collections.ArrayList; function W($s) { [void]$log.Add("$s"); Write-Output "$s" }
$evf = New-EvidenceFile 'audit-tenant'
W "=== Tenant audit (read-only), $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz'), as $((Get-MgContext).Account)"

# ---------- 1. devices ----------
$devs = @(GAll "$g/deviceManagement/managedDevices?`$select=id,deviceName,operatingSystem,osVersion,complianceState,lastSyncDateTime,isEncrypted,managementAgent,userPrincipalName,isSupervised,jailBroken")
W "--- 1. managed devices: $($devs.Count)"
foreach ($d in $devs) { W ("  {0,-10} {1,-8} {2,-16} compliance={3,-13} encrypted={4,-5} lastSync={5} user={6}{7}" -f $d.deviceName, $d.operatingSystem, $d.osVersion, $d.complianceState, $d.isEncrypted, $d.lastSyncDateTime, $d.userPrincipalName, $(if ($d.operatingSystem -eq 'iOS') { " supervised=$($d.isSupervised) jailbroken=$($d.jailBroken)" })) }
$h = @($devs | Where-Object deviceName -eq $Device)[0]

# ---------- 2. compliance policies ----------
W '--- 2. compliance policies (device results)'
foreach ($cp in @(GAll "$g/deviceManagement/deviceCompliancePolicies?`$select=id,displayName")) {
    $s = Invoke-MgGraphRequest -Method GET -Uri "$g/deviceManagement/deviceCompliancePolicies/$($cp.id)/deviceStatusOverview"
    W ("  {0,-36} compliant={1} noncompliant={2} error={3} conflict={4} notApplicable={5}" -f $cp.displayName, $s.compliantCount, $s.nonCompliantCount, $s.errorCount, $s.conflictCount, $s.notApplicableCount)
}

# ---------- 3. remediations ----------
W '--- 3. remediations (all devices): ok / issue / fixed / reoccurred / errors / last run   (<< = needs a look)'
foreach ($r in @(GAll "$g/deviceManagement/deviceHealthScripts?`$select=id,displayName,version") | Sort-Object displayName) {
    try { $rs = Invoke-MgGraphRequest -Method GET -Uri "$g/deviceManagement/deviceHealthScripts/$($r.id)/runSummary"
          $flag = if ($rs.errorDeviceCount -or $rs.remediationScriptErrorDeviceCount -or $rs.issueReoccurredDeviceCount) { ' <<' } else { '' }
          W ("  {0,-46} v{1,-3} ok={2} issue={3} fixed={4} reoccurred={5} detErr={6} remErr={7} last={8}{9}" -f $r.displayName, $r.version, $rs.noIssueDetectedDeviceCount, $rs.issueDetectedDeviceCount, $rs.issueRemediatedDeviceCount, $rs.issueReoccurredDeviceCount, $rs.errorDeviceCount, $rs.remediationScriptErrorDeviceCount, $rs.lastScriptRunDateTime, $flag) }
    catch { W "  $($r.displayName): runSummary unavailable ($($_.Exception.Message))" }
}

# ---------- 4. configuration policy states on the device ----------
W "--- 4. configuration on $Device (settings catalog + profiles): anything not succeeded"
if ($h) {
    try {
        $body = @{ select = @('PolicyName', 'PolicyStatus', 'PolicyType', 'UPN'); filter = "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') or (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy') or (PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceManagementIntent')) and (IntuneDeviceId eq '$($h.id)')"; top = 500; skip = 0 } | ConvertTo-Json
        $rep = Invoke-MgGraphRequest -Method POST -Uri "$g/deviceManagement/reports/getConfigurationPoliciesReportForDevice" -Body $body
        $cols = @($rep.Schema | ForEach-Object { $_.Column }); $iN = [array]::IndexOf($cols, 'PolicyName'); $iS = [array]::IndexOf($cols, 'PolicyStatus')
        $rows = @($rep.Values); $bad = @($rows | Where-Object { "$($_[$iS])" -notin '2', 'Succeeded', 'Compliant' })
        W "  policies reported: $($rows.Count); not succeeded: $($bad.Count)   (a 'pending' here is often report lag - verify on the device before calling it a failure)"
        foreach ($b in $bad) { W ("    {0,-46} status={1}" -f $b[$iN], $b[$iS]) }
    } catch { W "  report unavailable ($($_.Exception.Message)); legacy profile states follow" }
    foreach ($st in @((Invoke-MgGraphRequest -Method GET -Uri "$g/deviceManagement/managedDevices('$($h.id)')/deviceConfigurationStates").value)) { if ($st.state -notin 'compliant', 'notApplicable') { W "    profile $($st.displayName): $($st.state)" } }
} else { W "  device '$Device' not found in Intune" }

# ---------- 5. identity ----------
W '--- 5. Conditional Access'
foreach ($p in @((Invoke-MgGraphRequest -Method GET -Uri "$g/identity/conditionalAccess/policies").value) | Sort-Object displayName) { W ("  {0,-46} {1}" -f $p.displayName, $p.state) }
$f = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2'
W "  FIDO2: state=$($f.state) attestationEnforced=$($f.isAttestationEnforced) keyRestrictions=$($f.keyRestrictions.isEnforced)/$($f.keyRestrictions.enforcementType)"
foreach ($m in 'MicrosoftAuthenticator', 'Sms', 'Voice', 'Email', 'TemporaryAccessPass', 'SoftwareOath', 'X509Certificate') { try { $c = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/$m"; $extra = if ($m -eq 'TemporaryAccessPass') { " (oneTimeUse=$($c.isUsableOnce) lifetime $($c.defaultLifetimeInMinutes)-$($c.maximumLifetimeInMinutes) min)" } else { '' }; W "  $($m): $($c.state)$extra" } catch { } }
W '  registered methods per user (types only):   <- every member should hold a FIDO2 key; anything else is a weaker path'
foreach ($u in @(GAll 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName&$top=999')) {
    try { $ms = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/authentication/methods").value | ForEach-Object { "$($_.'@odata.type')" -replace '#microsoft.graph.|AuthenticationMethod$', '' } | Group-Object | ForEach-Object { "$($_.Name) x$($_.Count)" }); W ("    {0,-44} {1}" -f $u.userPrincipalName, ($ms -join ', ')) } catch { W "    $($u.userPrincipalName): unreadable ($($_.Exception.Message))" }
}

# ---------- 6. Sentinel ----------
W '--- 6. Sentinel'
try {
    $rules = @((Invoke-RestMethod -Headers @{ Authorization = "Bearer $(Get-ArmToken)" } -Uri "https://management.azure.com$global:ArmRg/providers/Microsoft.Insights/scheduledQueryRules?api-version=2023-03-15-preview").value)
    W "  log-alert rules: $($rules.Count) total, $(@($rules | Where-Object { $_.properties.enabled }).Count) enabled"
    foreach ($ru in @($rules | Where-Object { -not $_.properties.enabled })) { W ("    DISABLED: {0} - {1}" -f $ru.name, (Trunc $ru.properties.description 160)) }
    foreach ($row in (Invoke-Kql 'Heartbeat | summarize lastSeen=max(TimeGenerated) by Computer')) { W "  heartbeat $($row.Computer): last seen $($row.lastSeen)" }
    foreach ($row in (Invoke-Kql 'union SecurityEvent, Event | where TimeGenerated > ago(24h) | summarize n=count() by Type, Computer')) { W "  24 h $($row.Type) on $($row.Computer): $($row.n)" }
    foreach ($row in (Invoke-Kql 'SecurityIncident | where TimeGenerated > ago(7d) | summarize n=dcount(IncidentNumber) by Severity, Status')) { W "  incidents 7 d: severity $($row.Severity) status $($row.Status): $($row.n)" }
} catch { W "  Sentinel read failed: $($_.Exception.Message)" }
[IO.File]::WriteAllLines($evf, [string[]]$log); "written: $evf"
