# REF-UpdateHealth-Detect - Intune remediation DETECTION script.
# Exit 0 = update pipeline healthy, exit 1 = degraded (surfaces in Intune, logs to REF log).
#
# WHY THIS EXISTS. On 25 September 2026 the Windows Update client stopped working on BOTH
# endpoints and nothing reported it. It was found four days later, by accident, while
# investigating something else. Throughout that period both machines reported healthy in
# Intune and in Defender: real-time protection on, MDE connected, policies applied, compliant.
#
# The root cause was outbound TCP port 80 being blocked upstream of Windows (proven 29 Sep:
# every port-80 destination unreachable, 443 unaffected, zero Windows Firewall drops, zero WFP
# drop events, unchanged with the VPN connected or disconnected). The update SCAN is the first
# step of every update operation - it fails at 0x8024402F / 0x80072EFD before anything can be
# detected, downloaded or installed. Quality updates, feature updates, driver updates and
# Defender platform updates all stop. Signatures continued only because a separate remediation
# fetches them over HTTPS.
#
# THE ACTUAL FINDING was not the port block. It was that a total update outage produced NO
# signal for four days. This script is that signal.
#
# DESIGN NOTES, deliberate:
#   - It is DETECTION ONLY. There is no paired remediation script, because the fault is not on
#     the device and no device-local action can fix it. Pretending otherwise would produce a
#     remediation that "succeeds" while the machine stays broken.
#   - An error reading state is treated as DEGRADED, never as healthy. Unknown is not OK - that
#     assumption is precisely what let the original outage hide.
#   - It never changes anything, starts or stops a service, or touches the firewall.

$ErrorActionPreference = 'Stop'

$MaxScanAgeDays      = 3   # WU scans run daily; 3 days means several cycles have failed.
$MaxSignatureAgeDays = 2   # Defender updates several times a day.

$logName = 'SANCTIR'
$source  = 'REF-UpdateHealth'
$issues  = @()

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

# --- 1. When did a Windows Update SCAN last succeed? -------------------------------------
# This is the check that would have caught the September outage on day one.
try {
    $au   = New-Object -ComObject Microsoft.Update.AutoUpdate
    $last = $au.Results.LastSearchSuccessDate
    if (-not $last -or $last -eq [datetime]::MinValue) {
        $issues += 'Windows Update has NEVER recorded a successful scan.'
    }
    else {
        $age = [int]((Get-Date) - $last).TotalDays
        if ($age -gt $MaxScanAgeDays) {
            $issues += ("Last successful Windows Update scan was {0} day(s) ago ({1:yyyy-MM-dd HH:mm}); threshold is {2}." -f $age, $last, $MaxScanAgeDays)
        }
    }
}
catch {
    $issues += "Could not read Windows Update scan history: $($_.Exception.Message)"
}

# --- 2. Defender signature age -----------------------------------------------------------
try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
    if ($mp.AntivirusSignatureAge -gt $MaxSignatureAgeDays) {
        $issues += ("Defender signature age is {0} day(s) (version {1}); threshold is {2}." -f $mp.AntivirusSignatureAge, $mp.AntivirusSignatureVersion, $MaxSignatureAgeDays)
    }
    if (-not $mp.RealTimeProtectionEnabled) {
        $issues += 'Defender real-time protection is DISABLED.'
    }
}
catch {
    $issues += "Could not read Defender status: $($_.Exception.Message)"
}

# --- 3. Can the update client actually reach its service right now? ----------------------
# A live scan. This is what fails when port 80 is blocked, and it fails in seconds.
try {
    $s = New-Object -ComObject Microsoft.Update.Session
    $s.ClientApplicationID = 'REF-UpdateHealth'
    $null = $s.CreateUpdateSearcher().Search("IsInstalled=0 and Type='Software'")
}
catch {
    $hr = '0x{0:X8}' -f $_.Exception.HResult
    $issues += ("Live Windows Update scan FAILED with {0}. The update pipeline is down - no quality, feature or driver updates can install." -f $hr)
}

# --- 4. Services that must never be stopped ----------------------------------------------
# wuauserv and bits are deliberately NOT in this list. Both stop themselves when idle, and BITS
# resets its own start type to Manual when it has no jobs. Measured on WS02 the night of
# 29-30 Sep 2026: this check raised event 1310 "UPDATE PIPELINE DEGRADED - Service 'bits' is
# Stopped" every hour, all night, on a machine whose live scan (check 3) was succeeding. A
# detector that fires hourly on a healthy machine trains its reader to ignore it, which is the
# opposite of its purpose. Whether the update services WORK is proven by the live scan above;
# whether they are resident is REF-STD-011's concern and is handled by that remediation.
foreach ($svc in @('cryptsvc','UsoSvc','WinDefend')) {
    try {
        $st = (Get-Service $svc -ErrorAction Stop).Status
        if ($st -ne 'Running') { $issues += "Service '$svc' is $st, expected Running." }
    }
    catch { $issues += "Service '$svc' could not be read: $($_.Exception.Message)" }
}

# --- verdict -----------------------------------------------------------------------------

if ($issues.Count -eq 0) {
    Write-Output 'OK: update scan current, signatures current, services running, live scan succeeded.'
    exit 0
}

$msg = "UPDATE PIPELINE DEGRADED on $env:COMPUTERNAME. " + ($issues -join ' | ')
Write-Output $msg
Write-SanctirEvent -Id 1310 -EntryType Error -Message $msg
exit 1
