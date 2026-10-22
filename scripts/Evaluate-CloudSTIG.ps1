# REF-Eval-CloudSTIG.ps1 - 20 Oct 2026. ADMIN WINDOW. READ-ONLY (changes nothing).
# Connect first (sign in with the CAC; Global Reader or Global Administrator active):
#   Connect-Tenant -Scopes Policy.Read.All,Directory.Read.All,AuditLog.Read.All,RoleManagement.Read.Directory,RoleManagementPolicy.Read.Directory,Organization.Read.All,DeviceManagementRBAC.Read.All,User.Read
# WHY. Security Officer, 20 Oct 2026: "check the intune and entra DISA stigs and compliance there as well". DISA publishes these
# two as MANUAL STIGs (no SCAP content): Microsoft Entra ID V1R2 (10 rules) and Microsoft Intune MDM Service Desktop & Mobile
# V1R2 (Y26M07 package, 3 rules). This script performs each rule's check text through Graph / Azure Resource Manager and
# reports PASS / FAIL / REVIEW (REVIEW = DISA asks for a documented decision, e.g. exclusions documented with the AO).
# Evidence: Evidence\<today>\cloud-stig-<time>.txt
[CmdletBinding()]
param([string]$Subscription, [string]$Workspace, [string]$WorkspaceRg,
      [string]$BreakGlassUpn = '', [int]$InactiveDays = 35,
      [string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))
. "$PSScriptRoot\_Common.ps1"   # config.json: subscription, workspace, break-glass account
if (-not $Subscription) { $Subscription = $global:Cfg.azure.subscriptionId }; if (-not $Workspace) { $Workspace = $global:Cfg.azure.workspaceName }; if (-not $WorkspaceRg) { $WorkspaceRg = $global:Cfg.azure.resourceGroup }; if (-not $BreakGlassUpn) { $BreakGlassUpn = $global:Cfg.accounts.breakGlass }
$ErrorActionPreference = 'Stop'
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Helper not loaded. See the Connect line at the top.' }
$v1 = 'https://graph.microsoft.com/v1.0'; $beta = 'https://graph.microsoft.com/beta'; $arm = 'https://management.azure.com'
function G($u) { Invoke-MgGraphRequest -Method GET -Uri $u }
function GAll($uri) { $o = @(); while ($uri) { $p = Invoke-MgGraphRequest -Method GET -Uri $uri; $o += @($p.value); $uri = $p.'@odata.nextLink' }; $o }
$out = New-Object Collections.ArrayList; function W($s) { [void]$out.Add("$s"); Write-Output "$s" }
$cnt = @{ PASS = 0; FAIL = 0; REVIEW = 0; ERROR = 0 }
function Res($vuln, $id, $sev, $title, $state, $detail) { $cnt[$state]++; W ("{0,-6} {1} {2} [{3}] {4}" -f $state, $vuln, $id, $sev, $title); W "         $detail" }
function Try-Rule($vuln, $id, $sev, $title, [scriptblock]$body) { try { $r = & $body; Res $vuln $id $sev $title $r[0] $r[1] } catch { Res $vuln $id $sev $title 'ERROR' "check could not run: $($_.Exception.Message) $($_.ErrorDetails.Message)" } }
W "=== DISA cloud STIGs (Entra ID V1R2, Intune MDM V1R2), tenant $((G "$v1/organization?`$select=id,displayName").value[0].displayName), $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz') (read-only)"
$armH = $null; try { $armH = @{ Authorization = "Bearer $(Get-ArmToken)" } } catch { W "  (no Azure token: $($_.Exception.Message) - the two log-forwarding rules will report ERROR)" }
# 16:17 run: matched on displayName, which a created setting object does not carry - match the template id instead
$ruleSettings = $null; try { $tplId = @(GAll "$v1/groupSettingTemplates" | Where-Object displayName -eq 'Password Rule Settings')[0].id; $ruleSettings = @(GAll "$v1/groupSettings" | Where-Object templateId -eq $tplId)[0] } catch { }
function RS($name) { if ($ruleSettings) { (@($ruleSettings.values | Where-Object name -eq $name)[0]).value } }
$priv = @(GAll "$beta/roleManagement/directory/roleDefinitions?`$select=id,displayName,isPrivileged" | Where-Object isPrivileged)
$users = @(GAll "$beta/users?`$select=id,userPrincipalName,accountEnabled,userType,createdDateTime,signInActivity&`$top=999" | Where-Object accountEnabled)

W '--- Microsoft Entra ID V1R2'
Try-Rule 'V-270200' 'ENTR-ID-000030' 'medium' 'Session lock (idle sign-out) after 15 minutes' {
    $p = @(GAll "$v1/policies/activityBasedTimeoutPolicies"); if (-not $p) { return 'FAIL', 'no idle session timeout policy (activityBasedTimeoutPolicies is empty)' }
    $t = @($p | ForEach-Object { (($_.definition | Select-Object -First 1) | ConvertFrom-Json).ActivityBasedTimeoutPolicy.ApplicationPolicies } | Where-Object { $_.ApplicationId -eq 'default' } | ForEach-Object { [timespan]$_.WebSessionIdleTimeout })
    if ($t -and ($t | Measure-Object -Maximum).Maximum -le [timespan]'00:15:00') { 'PASS', "default web session idle timeout $($t -join ', ')" } else { 'FAIL', "default web session idle timeout $(if ($t) { $t -join ', ' } else { 'not set' }) (must be 00:15:00 or less)" } }
Try-Rule 'V-270204' 'ENTR-ID-000090' 'medium' "Accounts inactive $InactiveDays days are disabled" {
    $lim = (Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
    $bad = @($users | Where-Object { $last = $_.signInActivity.lastSuccessfulSignInDateTime; if (-not $last) { $last = $_.signInActivity.lastSignInDateTime }; if ($last) { [datetime]$last -lt $lim } else { [datetime]$_.createdDateTime -lt $lim } })
    if ($bad) { 'FAIL', "enabled accounts with no sign-in for $InactiveDays+ days: $(($bad | ForEach-Object { "$($_.userPrincipalName) (last $(if ($_.signInActivity.lastSignInDateTime) { ([datetime]$_.signInActivity.lastSignInDateTime).ToString('yyyy-MM-dd') } else { 'never' }))" }) -join '; ')" }
    else { 'PASS', "$($users.Count) enabled accounts, none inactive $InactiveDays+ days (note: Entra has no built-in auto-disable; the check passes on the result)" } }
Try-Rule 'V-270208' 'ENTR-ID-000140' 'medium' 'Lockout after 3 invalid attempts, 15 minutes' {
    $th = RS 'LockoutThreshold'; $du = RS 'LockoutDurationInSeconds'
    if ($th -and [int]$th -le 3 -and $du -and [int]$du -ge 900) { 'PASS', "threshold $th, duration $du s" } else { 'FAIL', "threshold $(if ($th) { $th } else { 'default 10' }), duration $(if ($du) { "$du s" } else { 'default 60 s' }) (must be 3 and 900 s or more)" } }
Try-Rule 'V-270209' 'ENTR-ID-000150' 'medium' 'Notice and consent banner on the sign-in page' {
    $org = (G "$v1/organization?`$select=id").value[0].id; $b = try { G "$v1/organization/$org/branding" } catch { $null }
    $txt = "$($b.signInPageText)"; $win = "$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -ErrorAction SilentlyContinue).LegalNoticeText)"
    if (-not $txt) { 'FAIL', "no sign-in page text in company branding (Windows logon banner on this PC starts: '$($win.Substring(0, [Math]::Min(80, $win.Length)))...')" }
    else { 'PASS', "sign-in page text present ($($txt.Length) chars): '$($txt.Substring(0, [Math]::Min(80, $txt.Length)))...'" } }
Try-Rule 'V-270227' 'ENTR-ID-000370' 'medium' 'Entra logs sent to a SIEM (8 categories, data within the hour)' {
    if (-not $armH) { throw 'no Azure token' }
    $ds = @((Invoke-RestMethod -Headers $armH -Uri "$arm/providers/microsoft.aadiam/diagnosticSettings?api-version=2017-04-01-preview").value)
    $need = 'SignInLogs', 'AuditLogs', 'ServicePrincipalSignInLogs', 'ManagedIdentitySignInLogs', 'UserRiskEvents', 'RiskyUsers', 'RiskyServicePrincipals', 'ServicePrincipalRiskEvents'
    $on = @($ds | Where-Object { $_.properties.workspaceId } | ForEach-Object { $_.properties.logs } | Where-Object enabled | ForEach-Object category | Select-Object -Unique)
    $miss = @($need | Where-Object { $_ -notin $on })
    $ws = "/subscriptions/$Subscription/resourceGroups/$WorkspaceRg/providers/Microsoft.OperationalInsights/workspaces/$Workspace"
    $last = try { (Invoke-RestMethod -Method POST -Headers $armH -ContentType 'application/json' -Uri "$arm$ws/api/query?api-version=2020-08-01" -Body (@{ query = 'SigninLogs | summarize max(TimeGenerated)' } | ConvertTo-Json)).tables[0].rows[0][0] } catch { $null }
    $fresh = $last -and ([datetime]$last -gt (Get-Date).ToUniversalTime().AddHours(-1))
    if (-not $miss -and $fresh) { 'PASS', "$($ds.Count) diagnostic setting(s) to a workspace; all 8 categories on; last SigninLogs record $last UTC" }
    else { 'FAIL', "missing categories: $(if ($miss) { $miss -join ', ' } else { 'none' }) | last SigninLogs record: $(if ($last) { "$last UTC" } else { 'none found' })$(if (-not $fresh) { ' (older than 1 hour)' })" } }
Try-Rule 'V-270233' 'ENTR-ID-000440' 'high' 'MFA for all users (Conditional Access)' {
    $ca = @(GAll "$v1/identity/conditionalAccess/policies" | Where-Object { $_.state -eq 'enabled' -and @($_.conditions.users.includeUsers) -contains 'All' -and @($_.conditions.applications.includeApplications) -contains 'All' -and (@($_.grantControls.builtInControls) -contains 'mfa' -or $_.grantControls.authenticationStrength.id) })
    if (-not $ca) { return 'FAIL', 'no enabled CA policy requiring MFA for All users / All resources' }
    $ex = @($ca | ForEach-Object { @($_.conditions.users.excludeUsers) + @($_.conditions.users.excludeGroups) + @($_.conditions.users.excludeRoles) } | Where-Object { $_ } | Select-Object -Unique)
    $names = @($ex | ForEach-Object { $id = $_; try { (G "$v1/directoryObjects/$id").userPrincipalName ?? (G "$v1/directoryObjects/$id").displayName } catch { $id } })
    if ($ex) { 'REVIEW', "ON: $(($ca | ForEach-Object displayName) -join ', ') | exclusions to be documented with the AO: $($names -join ', ')" } else { 'PASS', "ON, no exclusions: $(($ca | ForEach-Object displayName) -join ', ')" } }
Try-Rule 'V-270239' 'ENTR-ID-000610' 'medium' 'Password lifetime 180 days or less' {
    $d = @(GAll "$v1/domains" | Where-Object isVerified)
    $bad = @($d | Where-Object { -not $_.passwordValidityPeriodInDays -or [int64]$_.passwordValidityPeriodInDays -gt 180 })
    if ($bad) { 'FAIL', "domains over 180 days: $(($bad | ForEach-Object { "$($_.id)=$(if ([int64]$_.passwordValidityPeriodInDays -ge 2147483647) { 'never expires' } else { $_.passwordValidityPeriodInDays })" }) -join ', ')" } else { 'PASS', "all verified domains: $(($d | ForEach-Object { "$($_.id)=$($_.passwordValidityPeriodInDays)" }) -join ', ')" } }
Try-Rule 'V-270255' 'ENTR-ID-000835' 'medium' 'PIM role activation alerts to SA + ISSO' {
    $roleIds = @(@(GAll "$v1/roleManagement/directory/roleEligibilityScheduleInstances") + @(GAll "$v1/roleManagement/directory/roleAssignmentScheduleInstances") | ForEach-Object roleDefinitionId | Select-Object -Unique)
    $rows = @(foreach ($r in $roleIds) { $pa = @((G "$v1/policies/roleManagementPolicyAssignments?`$filter=scopeId eq '/' and scopeType eq 'DirectoryRole' and roleDefinitionId eq '$r'").value)[0]
        $rule = if ($pa) { try { G "$v1/policies/roleManagementPolicies/$($pa.policyId)/rules/Notification_Admin_EndUser_Assignment" } catch { $null } }
        $name = (G "$v1/roleManagement/directory/roleDefinitions/$r`?`$select=displayName").displayName
        [pscustomobject]@{ Role = $name; Recipients = @($rule.notificationRecipients) } })
    $bad = @($rows | Where-Object { -not $_.Recipients.Count })
    if ($bad) { 'FAIL', "roles with no additional recipient for 'role activation alert': $(($bad | ForEach-Object Role) -join ', ') | set: $(($rows | Where-Object { $_.Recipients.Count } | ForEach-Object { "$($_.Role) -> $($_.Recipients -join ',')" }) -join '; ')" }
    else { 'PASS', (($rows | ForEach-Object { "$($_.Role) -> $($_.Recipients -join ',')" }) -join '; ') } }   # inner parentheses: ',' binds before -join (16:17 printed "P / A")
Try-Rule 'V-270335' 'ENTR-ID-001900' 'medium' 'PIM: no permanent active privileged role' {
    $perm = @(GAll "$v1/roleManagement/directory/roleAssignmentScheduleInstances" | Where-Object { -not $_.endDateTime -and $_.roleDefinitionId -in $priv.id -and $_.assignmentType -eq 'Assigned' })
    $desc = @($perm | ForEach-Object { $u = try { (G "$v1/directoryObjects/$($_.principalId)").userPrincipalName } catch { $_.principalId }; "$u = $(@($priv | Where-Object id -eq $_.roleDefinitionId)[0].displayName)" })
    if ($perm) { $(if (@($desc | Where-Object { $_ -notmatch [regex]::Escape($BreakGlassUpn) }).Count) { 'FAIL' } else { 'REVIEW' }), "permanent active privileged assignments: $($desc -join '; ')$(if (-not @($desc | Where-Object { $_ -notmatch [regex]::Escape($BreakGlassUpn) }).Count) { ' (break-glass only - document with the AO)' })" }
    else { 'PASS', 'no permanent active assignment of a privileged role (all eligible / time-bound)' } }
Try-Rule 'V-270475' 'ENTR-ID-003350' 'medium' 'Custom banned password list enforced' {
    $on = RS 'EnableBannedPasswordCheck'; $list = "$(RS 'BannedPasswordList')"
    if ($on -eq 'True' -and $list.Trim()) { 'PASS', "enforced, $(($list -split "`t|,|`n" | Where-Object { $_.Trim() }).Count) custom terms" } else { 'FAIL', "enforce custom list: $(if ($on) { $on } else { 'not set' }); custom terms: $(if ($list.Trim()) { 'present' } else { 'none' })" } }

W '--- Microsoft Intune MDM Service V1R2'
Try-Rule 'V-273867' 'MSIN-25-000030' 'medium' 'M365 idle session timeout 15 minutes' {
    $p = @(GAll "$v1/policies/activityBasedTimeoutPolicies"); $t = @($p | ForEach-Object { (($_.definition | Select-Object -First 1) | ConvertFrom-Json).ActivityBasedTimeoutPolicy.ApplicationPolicies } | Where-Object { $_.ApplicationId -eq 'default' } | ForEach-Object { [timespan]$_.WebSessionIdleTimeout })
    if ($t -and ($t | Measure-Object -Maximum).Maximum -le [timespan]'00:15:00') { 'PASS', "idle session timeout $($t -join ', ')" } else { 'FAIL', "idle session timeout $(if ($t) { $t -join ', ' } else { 'not set' })" } }
Try-Rule 'V-273868' 'MSIN-25-000370' 'medium' 'Intune logs sent to a log service' {
    if (-not $armH) { throw 'no Azure token' }
    $ds = @((Invoke-RestMethod -Headers $armH -Uri "$arm/providers/microsoft.intune/diagnosticSettings?api-version=2017-04-01-preview").value)
    $on = @($ds | Where-Object { $_.properties.workspaceId -or $_.properties.storageAccountId -or $_.properties.eventHubAuthorizationRuleId } | ForEach-Object { $_.properties.logs } | Where-Object enabled | ForEach-Object category | Select-Object -Unique)
    if ($on -contains 'AuditLogs' -and $on -contains 'OperationalLogs') { 'PASS', "categories sent: $($on -join ', ')" } else { 'FAIL', "Intune diagnostic settings: $($ds.Count); categories sent: $(if ($on) { $on -join ', ' } else { 'none' }) (need at least AuditLogs + OperationalLogs)" } }
Try-Rule 'V-285327' 'MSIN-25-002000' 'high' 'Multi Admin Approval for device wipe' {
    $p = @(GAll "$beta/deviceManagement/operationApprovalPolicies")
    $wipe = @($p | Where-Object { "$($_.policyType)" -match '(?i)wipe' -or "$($_.policyPlatform)$($_.displayName)" -match '(?i)wipe' })
    if ($wipe) { 'PASS', "$(($wipe | ForEach-Object { "$($_.displayName) type $($_.policyType) approvers $(@($_.approverGroupIds) -join ',')" }) -join '; ')" } else { 'FAIL', "no Multi Admin Approval access policy for device wipe ($($p.Count) access policies in total)" } }

W "RESULT: PASS $($cnt.PASS) | FAIL $($cnt.FAIL) | REVIEW $($cnt.REVIEW) | ERROR $($cnt.ERROR) of 13"
$f = Join-Path $ProjectRoot ("Evidence\{0}\cloud-stig-{1}.txt" -f (Get-Date -Format 'yyyy-MM-dd'), (Get-Date -Format HHmmss)); New-Item -ItemType Directory -Force (Split-Path $f) | Out-Null; [IO.File]::WriteAllLines($f, [string[]]$out); "written: $f"
