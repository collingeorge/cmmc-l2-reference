# Set-AuthMethodsPolicy.ps1 - hardens the tenant authentication-methods policy to key-only sign-in. Read-only without -Apply.
# NIST SP 800-171 3.5.3 (multifactor), 3.5.2 (replay-resistant authentication).
#   FIDO2                     enabled, attestation enforced (only keys that prove their make and model)
#   Microsoft Authenticator   disabled  (push approval is a phishing and fatigue path; passkeys in Authenticator are governed
#                                        by the FIDO2 policy and are unaffected)
#   Software OATH, SMS, Voice, E-mail   disabled
#   Temporary Access Pass     enabled, ONE-TIME use, 60 min default, 120 min maximum (enrolment and recovery only)
# PRECONDITION (refused otherwise): every member account already holds at least one FIDO2 method - nobody is left without
# a phishing-resistant way in. The break-glass account counts: it needs its own key, kept locked away.
# WAY BACK: PATCH each method from the before-JSON this script saves under ConfigBackup\<date>\.
[CmdletBinding()]
param([switch]$Apply)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\..\scripts\_Common.ps1"
if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) { throw 'Not connected. Dot-source scripts\Connect-Tenant.ps1 and run Connect-Tenant first.' }
$am = 'https://graph.microsoft.com/v1.0/policies/authenticationMethodsPolicy/authenticationMethodConfigurations'
$log = New-Object Collections.ArrayList; function W($s) { [void]$log.Add("$s"); Write-Output "$s" }
$evf = New-EvidenceFile 'auth-methods'; $bk = New-BackupDir; $stamp = Get-Date -Format 'HHmmss'
W "=== Authentication methods policy, $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz') $(if ($Apply) { '(APPLY)' } else { '(read-only)' })"
$users = @((Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users?$select=id,userPrincipalName,userType&$top=999').value | Where-Object { $_.userType -ne 'Guest' })
$noKey = @()
foreach ($u in $users) { $f = @((Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/authentication/fido2Methods").value); W ("  {0,-44} FIDO2 methods: {1}" -f $u.userPrincipalName, $f.Count); if (-not $f.Count) { $noKey += $u.userPrincipalName } }
if ($noKey.Count) { W "  REFUSED: no FIDO2 method on $($noKey -join ', '). Register a key for each first. Nothing changed."; [IO.File]::WriteAllLines($evf, [string[]]$log); return }
$methods = 'Fido2', 'MicrosoftAuthenticator', 'SoftwareOath', 'Sms', 'Voice', 'Email', 'TemporaryAccessPass'
$cur = @{}; foreach ($m in $methods) { try { $cur[$m] = Invoke-MgGraphRequest -Method GET -Uri "$am/$m" } catch { $cur[$m] = @{ state = 'unreadable' } } }
$cur | ConvertTo-Json -Depth 20 | Set-Content (Join-Path $bk "auth-methods-before-$stamp.json")
W ("--- now:  " + (($methods | ForEach-Object { "$_=$($cur[$_].state)" }) -join ' ') + "; FIDO2 attestation=$($cur.Fido2.isAttestationEnforced); TAP oneTime=$($cur.TemporaryAccessPass.isUsableOnce) $($cur.TemporaryAccessPass.defaultLifetimeInMinutes)-$($cur.TemporaryAccessPass.maximumLifetimeInMinutes) min")
W '--- want: Fido2=enabled (attestation on); MicrosoftAuthenticator, SoftwareOath, Sms, Voice, Email = disabled; TAP enabled, one-time, 60-120 min'
if (-not $Apply) { W 'Read-only. Nothing changed.'; [IO.File]::WriteAllLines($evf, [string[]]$log); return }
$patches = [ordered]@{
    Fido2                  = @{ '@odata.type' = '#microsoft.graph.fido2AuthenticationMethodConfiguration'; state = 'enabled'; isAttestationEnforced = $true; isSelfServiceRegistrationEnabled = $true }
    MicrosoftAuthenticator = @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration'; state = 'disabled' }
    SoftwareOath           = @{ '@odata.type' = '#microsoft.graph.softwareOathAuthenticationMethodConfiguration'; state = 'disabled' }
    Sms                    = @{ '@odata.type' = '#microsoft.graph.smsAuthenticationMethodConfiguration'; state = 'disabled' }
    Voice                  = @{ '@odata.type' = '#microsoft.graph.voiceAuthenticationMethodConfiguration'; state = 'disabled' }
    Email                  = @{ '@odata.type' = '#microsoft.graph.emailAuthenticationMethodConfiguration'; state = 'disabled' }
    TemporaryAccessPass    = @{ '@odata.type' = '#microsoft.graph.temporaryAccessPassAuthenticationMethodConfiguration'; state = 'enabled'; isUsableOnce = $true; defaultLifetimeInMinutes = 60; maximumLifetimeInMinutes = 120; minimumLifetimeInMinutes = 60 }
}
foreach ($m in $patches.Keys) {
    try { Invoke-MgGraphRequest -Method PATCH -Uri "$am/$m" -Body ($patches[$m] | ConvertTo-Json -Depth 6) -ContentType 'application/json' | Out-Null; W "  PATCHED $m" }
    catch { W "  $m REFUSED: $($_.Exception.Message) $($_.ErrorDetails.Message)"; [IO.File]::WriteAllLines($evf, [string[]]$log); throw 'Stopped at the first refusal; earlier patches stand. Read back and decide.' }
}
$rb = @{}; foreach ($m in $methods) { $rb[$m] = Invoke-MgGraphRequest -Method GET -Uri "$am/$m" }
W ("READ BACK: " + (($methods | ForEach-Object { "$_=$($rb[$_].state)" }) -join ' ') + "; attestation=$($rb.Fido2.isAttestationEnforced); TAP oneTime=$($rb.TemporaryAccessPass.isUsableOnce)")
if ($rb.MicrosoftAuthenticator.state -ne 'disabled' -or $rb.Fido2.state -ne 'enabled' -or -not $rb.TemporaryAccessPass.isUsableOnce) { W 'READ-BACK DOES NOT MATCH. Revert from the before-JSON.' }
W 'Next: sign out and in once on each device and phone to confirm nothing asks for a push or a code.'
[IO.File]::WriteAllLines($evf, [string[]]$log); "written: $evf"
