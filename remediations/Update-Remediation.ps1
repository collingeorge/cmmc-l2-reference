# REF-Update-Remediation.ps1 - replaces the script content of ONE EXISTING Intune remediation.
#
# WHY. REF-Deploy-Remediation.ps1 only creates, and refuses a duplicate name, so there was no
# way to push a corrected script to a remediation that already exists. This is that way. It changes
# the detection (and optionally the remediation) script and NOTHING else: name, assignment, schedule
# and run-as account are left exactly as they are. Intune raises the version and devices pick the
# new content up at their next check-in.
#
# SAFETY.
#   - The project lives in OneDrive and is edited on one machine and run from another. -ExpectDetectSha
#     / -ExpectRemediateSha (first 8 hex of SHA-256) make the script refuse to upload a copy that has
#     not finished syncing.
#   - If the tenant already holds exactly this content, nothing is sent.
#   - -WhatIfOnly prints what would change and stops.
#   - After the update the remediation is read back and compared with what was uploaded.
# Written 1 Oct 2026. NOT YET PROVEN against the tenant: the first run is the test - read its output.

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Id,
    [Parameter(Mandatory)][string]$DetectPath,
    [string]$RemediatePath,
    [string]$ExpectDetectSha,
    [string]$ExpectRemediateSha,
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'
$base = 'https://graph.microsoft.com/beta/deviceManagement'
function Sha8($p) { (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.Substring(0, 8) }

if (-not (Test-Path -LiteralPath $DetectPath)) { throw "Not found: $DetectPath" }
if ($RemediatePath -and -not (Test-Path -LiteralPath $RemediatePath)) { throw "Not found: $RemediatePath" }
if ($ExpectDetectSha -and (Sha8 $DetectPath) -ne $ExpectDetectSha) { throw "Detection script is $(Sha8 $DetectPath), expected $ExpectDetectSha - this copy has not synced yet, or was changed. Nothing sent." }
if ($RemediatePath -and $ExpectRemediateSha -and (Sha8 $RemediatePath) -ne $ExpectRemediateSha) { throw "Remediation script is $(Sha8 $RemediatePath), expected $ExpectRemediateSha - this copy has not synced yet, or was changed. Nothing sent." }

$detect    = [Convert]::ToBase64String([IO.File]::ReadAllBytes($DetectPath))
$remediate = if ($RemediatePath) { [Convert]::ToBase64String([IO.File]::ReadAllBytes($RemediatePath)) } else { $null }

$cur = Invoke-MgGraphRequest -Method GET -Uri "$base/deviceHealthScripts/$Id"
$sameD = ($cur.detectionScriptContent -eq $detect)
$sameR = (-not $RemediatePath) -or ($cur.remediationScriptContent -eq $remediate)
Write-Output ("'{0}' ({1}) is v{2}. detection {3}; remediation {4}" -f $cur.displayName, $Id.Substring(0, 8), $cur.version,
    $(if ($sameD) { 'already current' } else { "CHANGES -> $(Sha8 $DetectPath)" }),
    $(if (-not $RemediatePath) { 'not touched' } elseif ($sameR) { 'already current' } else { "CHANGES -> $(Sha8 $RemediatePath)" }))
if ($sameD -and $sameR) { Write-Output 'Nothing to send.'; return }
if ($WhatIfOnly) { Write-Output 'WhatIfOnly - nothing sent.'; return }

$body = @{ '@odata.type' = '#microsoft.graph.deviceHealthScript'; detectionScriptContent = $detect }
if ($RemediatePath) { $body.remediationScriptContent = $remediate }
Invoke-MgGraphRequest -Method PATCH -Uri "$base/deviceHealthScripts/$Id" -Body ($body | ConvertTo-Json -Depth 5) -ContentType 'application/json' | Out-Null

$after = Invoke-MgGraphRequest -Method GET -Uri "$base/deviceHealthScripts/$Id"
$okD = ($after.detectionScriptContent -eq $detect)
$okR = (-not $RemediatePath) -or ($after.remediationScriptContent -eq $remediate)
$asg = @((Invoke-MgGraphRequest -Method GET -Uri "$base/deviceHealthScripts/$Id/assignments").value).Count
Write-Output ("UPDATED: v{0} -> v{1}; read-back matches upload: detection={2} remediation={3}; assignments still present: {4}" -f $cur.version, $after.version, $okD, $okR, $asg)
if (-not ($okD -and $okR)) { throw 'Read-back does NOT match what was uploaded. Stop and tell Claude.' }
