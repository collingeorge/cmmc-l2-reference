# REF-AMA-Token-Remediate - Intune remediation REMEDIATION script. Runs as SYSTEM.
#
# Forces the Azure Monitor Agent to re-acquire its managed identity token before expiry stops
# ingestion (POAM-033).
#
# METHOD, and it is measured rather than assumed. On 28 September 2026 three approaches were tried
# on WS01:
#   - Restart-Service ExtensionService   -> did NOT cycle the agent. Same PIDs, same start times,
#                                           token unchanged, cache still growing. Ineffective.
#   - Stop MonAgentCore and MonAgentManager, leaving MonAgentLauncher alive
#                                        -> both respawned with new PIDs within ~70 seconds and the
#                                           token timestamp advanced to the moment of respawn.
#   - The Launcher supervises those two. Evidence: on 27 September Core and Manager restarted on
#     their own at 07:45 while Host and Launcher had been up since 26 September.
#
# So this stops the two leaf processes and lets the supervisor rebuild them. MonAgentLauncher is
# NEVER touched - it is what performs the respawn, and killing it leaves nothing to restart them.
#
# DATA SAFETY. The .tsf cache is a persistence layer designed to survive process restarts; that is
# its entire purpose. After the 28 September restart the agent replayed 4.5 hours of backlog
# chronologically from 15:21:22, the exact second of its last delivered record, with no gap. This
# action does not lose buffered audit records.

$ErrorActionPreference = 'Continue'
$logName = 'SANCTIR'
$source  = 'REF-AMAToken'

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

$store = @(Get-ChildItem 'C:\Resources\Directory' -Directory -Filter 'AMADataStore*' -ErrorAction SilentlyContinue)
if ($store.Count -eq 0) { Write-Output 'No agent data store. Nothing to do.'; exit 0 }

$token  = Join-Path $store[0].FullName 'mcs\AuthToken-MSI.json'
$before = $(if (Test-Path $token) { (Get-Item $token).LastWriteTime } else { $null })
$pidsBefore = @(Get-Process MonAgentCore, MonAgentManager -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })

if (-not (Get-Process MonAgentLauncher -ErrorAction SilentlyContinue)) {
    $msg = 'REFUSING TO ACT: MonAgentLauncher is not running. It is the supervisor that respawns the leaf processes; stopping them without it would leave the agent down entirely.'
    Write-Output $msg
    Write-SanctirEvent -Id 1202 -EntryType Error -Message $msg
    exit 1
}

Get-Process MonAgentCore, MonAgentManager -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# The supervisor took about 70 seconds on the measured occasion. 150 gives margin without the
# remediation running long enough to be killed by the Intune extension.
$deadline = (Get-Date).AddSeconds(150)
$ok = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds 10
    $pidsAfter = @(Get-Process MonAgentCore, MonAgentManager -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })
    $tokenNow  = $(if (Test-Path $token) { (Get-Item $token).LastWriteTime } else { $null })
    if ($pidsAfter.Count -eq 2 -and $null -ne $tokenNow -and ($null -eq $before -or $tokenNow -gt $before)) { $ok = $true; break }
}

$tokenFinal = $(if (Test-Path $token) { (Get-Item $token).LastWriteTime } else { $null })
$pidsFinal  = @(Get-Process MonAgentCore, MonAgentManager -ErrorAction SilentlyContinue | ForEach-Object { $_.Id })

if ($ok) {
    $msg = "Azure Monitor Agent token renewed. Processes restarted (was $($pidsBefore -join ','), now $($pidsFinal -join ',')). Token $before -> $tokenFinal. Ingestion continues; any buffered records replay chronologically."
    Write-Output $msg
    Write-SanctirEvent -Id 1200 -EntryType Information -Message $msg
    exit 0
}

$msg = "FAILED to renew the agent token. Processes now: $($pidsFinal -join ','). Token timestamp: $tokenFinal (was $before). The supervisor did not rebuild the processes or the token did not advance - this machine will stop shipping audit records and needs attention. POAM-033."
Write-Output $msg
Write-SanctirEvent -Id 1201 -EntryType Error -Message $msg
exit 1
