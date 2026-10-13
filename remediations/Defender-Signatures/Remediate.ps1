# REF-Defender-Signatures-Remediate - Intune remediation REMEDIATION script. Runs as SYSTEM.
#
# Restores Defender security intelligence currency while the Windows Update channel is broken
# (POAM-034). Ordered so that it stops using the workaround the moment the real channel recovers.
#
#   1. Try the NORMAL update path first. If Microsoft fixes the SLS service-registration defect,
#      or the tenant firewall work resolves it, this succeeds and the fallback never runs. The
#      remediation then quietly becomes a no-op rather than a permanent parallel update mechanism.
#   2. Only if that fails, download the signed standalone package and apply it.
#
# The package is roughly 212 MB per application. On a metered or slow link that matters, so the
# detection threshold is 2 days rather than hourly - this runs at most every couple of days per
# machine, not on every remediation cycle.
#
# Every outcome is written to the SANCTIR event log so it is collected off the device by the data
# collection rule and is queryable in the workspace. A repair that only writes to a file on the
# endpoint it repaired is not evidence (POAM-018).

$ErrorActionPreference = 'Continue'
$logName = 'SANCTIR'
$source  = 'REF-DefenderSignatures'
$url     = 'https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64'

function Write-SanctirEvent {
    param([int]$Id, [string]$EntryType, [string]$Message)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            New-EventLog -LogName $logName -Source $source -ErrorAction Stop
        }
        Write-EventLog -LogName $logName -Source $source -EventId $Id -EntryType $EntryType -Message $Message -ErrorAction Stop
    }
    catch { Write-Output "event log write failed: $($_.Exception.Message)" }
}

$before = (Get-MpComputerStatus -ErrorAction SilentlyContinue).AntivirusSignatureVersion

# --- Step 1: the normal channel ---------------------------------------------------------------
$normalWorked = $false
try {
    Update-MpSignature -ErrorAction Stop
    $normalWorked = $true
}
catch {
    $normalError = $_.Exception.Message
}

$now = (Get-MpComputerStatus -ErrorAction SilentlyContinue)
if ($normalWorked -and $null -ne $now.AntivirusSignatureAge -and $now.AntivirusSignatureAge -le 2) {
    $msg = "Defender signatures updated through the NORMAL channel. $before -> $($now.AntivirusSignatureVersion). The Windows Update path appears to have recovered; POAM-034 should be re-tested and this fallback may no longer be required."
    Write-Output $msg
    Write-SanctirEvent -Id 1100 -EntryType Information -Message $msg
    exit 0
}

# --- Step 2: the signed standalone package ------------------------------------------------------
$dl = Join-Path $env:TEMP 'mpam-fe.exe'
try {
    if (Test-Path $dl) { Remove-Item $dl -Force -ErrorAction SilentlyContinue }
    Invoke-WebRequest -Uri $url -OutFile $dl -UseBasicParsing -ErrorAction Stop
}
catch {
    $msg = "FAILED to download the Defender signature package. $($_.Exception.Message). Normal channel error was: $normalError"
    Write-Output $msg
    Write-SanctirEvent -Id 1102 -EntryType Error -Message $msg
    exit 1
}

$sizeMB = [math]::Round((Get-Item $dl).Length / 1MB, 1)

# Verify the package is Microsoft-signed before executing it. This script downloads an executable
# from the internet and runs it as SYSTEM on a machine inside the boundary; the signature check is
# not optional. App Control should also refuse an unsigned binary, but a remediation script must
# not depend on another control to be safe.
$sig = Get-AuthenticodeSignature -FilePath $dl -ErrorAction SilentlyContinue
if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
    $msg = "REFUSING TO RUN the downloaded package: signature status '$($sig.Status)', signer '$($sig.SignerCertificate.Subject)'. Expected a valid Microsoft Corporation signature."
    Write-Output $msg
    Write-SanctirEvent -Id 1103 -EntryType Error -Message $msg
    Remove-Item $dl -Force -ErrorAction SilentlyContinue
    exit 1
}

Start-Process -FilePath $dl -Wait -ErrorAction SilentlyContinue
Start-Sleep -Seconds 20
Remove-Item $dl -Force -ErrorAction SilentlyContinue

$after = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($null -ne $after.AntivirusSignatureAge -and $after.AntivirusSignatureAge -le 2) {
    $msg = "Defender signatures restored by the standalone package ($sizeMB MB). $before -> $($after.AntivirusSignatureVersion), age $($after.AntivirusSignatureAge) day(s). The normal update channel is STILL BROKEN - this is the POAM-034 workaround, not a fix. Normal channel error: $normalError"
    Write-Output $msg
    Write-SanctirEvent -Id 1101 -EntryType Warning -Message $msg
    exit 0
}

$msg = "FAILED to restore signatures. Package applied but age is still $($after.AntivirusSignatureAge). Normal channel error: $normalError"
Write-Output $msg
Write-SanctirEvent -Id 1102 -EntryType Error -Message $msg
exit 1
