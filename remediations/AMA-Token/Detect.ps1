# REF-AMA-Token-Detect - Intune remediation DETECTION script.
# Exit 0 = healthy, exit 1 = remediate.
#
# WHY THIS EXISTS (POAM-033). On 28 September 2026 WS01 delivered no audit records to Microsoft
# Sentinel for four and a half hours. The Azure Monitor Agent had acquired a managed identity token
# when its processes last restarted and NEVER RENEWED IT. Ingestion stopped almost exactly 24 hours
# later, when the token expired.
#
# Nothing on the endpoint looked wrong. All four agent processes were running. The extension health
# log wrote ErrorCode:0 every thirty seconds. The local cache was filling normally. The Arc agent
# reported Connected with a current heartbeat. THE ONLY ABNORMAL ARTEFACT ON THE ENTIRE MACHINE WAS
# ONE FILE TIMESTAMP.
#
# That timestamp is a LEADING indicator with roughly a day of warning before a single record is
# lost, and it is one read. This check exists to use that warning.
#
# THRESHOLD. 20 hours, not 24. The token is renewed only when the agent restarts, so remediating at
# 20 hours leaves four hours of margin before ingestion would stop. A machine that is asleep or off
# for part of the day still gets several remediation cycles inside that window.
#
# Arc-enabled machines only. The data store is C:\Resources\Directory, NOT C:\WindowsAzure\Resources
# - that is the Azure VM layout, and reading it on an Arc machine is what produced a false
# "NOT INSTALLED" on both workstations earlier the same day.

$ErrorActionPreference = 'Stop'
$maxAgeHours = 20

$store = @(Get-ChildItem 'C:\Resources\Directory' -Directory -Filter 'AMADataStore*' -ErrorAction SilentlyContinue)
if ($store.Count -eq 0) {
    Write-Output 'OK-SKIP: no Azure Monitor Agent data store on this machine. Nothing to remediate.'
    exit 0
}

$procWant = 'MonAgentCore', 'MonAgentHost', 'MonAgentLauncher', 'MonAgentManager'
$procHave = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $procWant -contains $_.Name } | ForEach-Object { $_.Name } | Sort-Object -Unique)
if ($procHave.Count -lt $procWant.Count) {
    Write-Output ("REMEDIATE: only {0} of {1} agent processes running ({2})." -f $procHave.Count, $procWant.Count, ($procHave -join ','))
    exit 1
}

$token = Join-Path $store[0].FullName 'mcs\AuthToken-MSI.json'
if (-not (Test-Path $token)) {
    # Unreadable is NOT healthy. A missing token file on a machine that has an agent data store and
    # four running processes is an abnormal state, and the whole point of this check is that the
    # abnormality is invisible everywhere else.
    Write-Output "REMEDIATE: token file not found at $token. Cannot confirm the agent can authenticate."
    exit 1
}

# The file's contents are a bearer credential and are NEVER read. The timestamp is the evidence.
$ageH = [math]::Round(((Get-Date) - (Get-Item $token).LastWriteTime).TotalHours, 1)

if ($ageH -gt $maxAgeHours) {
    Write-Output ("REMEDIATE: managed identity token is {0} hours old (limit {1}). Renewal has stopped; ingestion will halt at about 24 hours." -f $ageH, $maxAgeHours)
    exit 1
}

Write-Output ("OK: token {0} hours old, {1} of {2} agent processes running." -f $ageH, $procHave.Count, $procWant.Count)
exit 0
