# _Common.ps1 - shared prelude for every script in this repository. Dot-source it:  . "$PSScriptRoot\_Common.ps1"
# Loads config.json (copied from config.example.json and filled in by you), defines the paths every script writes to,
# and the small helpers they share. Nothing tenant-specific lives anywhere else.

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$cfgPath = Join-Path $script:RepoRoot 'config.json'
if (-not (Test-Path $cfgPath)) { throw "config.json not found at $cfgPath. Copy config.example.json to config.json and fill it in." }
$global:Cfg = Get-Content $cfgPath -Raw | ConvertFrom-Json
foreach ($k in 'tenant', 'accounts', 'devices', 'azure', 'graph') { if (-not $global:Cfg.$k) { throw "config.json is missing the '$k' section." } }
if ($global:Cfg.tenant.id -eq '00000000-0000-0000-0000-000000000000') { throw 'config.json still holds the placeholder tenant id.' }

# Output locations. Evidence is what you show an assessor; ConfigBackup is what you roll back from. Both are git-ignored.
$global:EvidenceRoot = Join-Path $script:RepoRoot 'Evidence'
$global:BackupRoot = Join-Path $script:RepoRoot 'ConfigBackup'
function New-EvidenceFile([string]$Name) {
    $day = Get-Date -Format 'yyyy-MM-dd'; $dir = Join-Path $global:EvidenceRoot $day; New-Item -ItemType Directory -Force $dir | Out-Null
    Join-Path $dir ("{0}-{1}.txt" -f $Name, (Get-Date -Format 'HHmmss'))
}
function New-BackupDir { $dir = Join-Path $global:BackupRoot (Get-Date -Format 'yyyy-MM-dd'); New-Item -ItemType Directory -Force $dir | Out-Null; $dir }

# Azure Resource Manager ids derived from config
$global:ArmSub = "/subscriptions/$($global:Cfg.azure.subscriptionId)"
$global:ArmRg = "$global:ArmSub/resourceGroups/$($global:Cfg.azure.resourceGroup)"
$global:ArmWorkspace = "$global:ArmRg/providers/Microsoft.OperationalInsights/workspaces/$($global:Cfg.azure.workspaceName)"

# Log Analytics query through the ARM proxy. The proxy returns columns as 'columnName'; one-line KQL only; avoid KQL
# reserved words (last, first) as column names.
function Invoke-Kql([string]$Kql) {
    $t = Get-ArmToken
    $r = Invoke-RestMethod -Method POST -Headers @{ Authorization = "Bearer $t" } -ContentType 'application/json' -Uri "https://management.azure.com$global:ArmWorkspace/api/query?api-version=2020-08-01" -Body (@{ query = $Kql } | ConvertTo-Json)
    $c = @($r.tables[0].columns | ForEach-Object { if ($_.name) { $_.name } else { $_.columnName } })
    @($r.tables[0].rows | ForEach-Object { $row = $_; $o = [ordered]@{}; for ($i = 0; $i -lt $c.Count; $i++) { $o[$c[$i]] = $row[$i] }; [pscustomobject]$o })
}
function Trunc([string]$s, [int]$n) { $s = "$s" -replace '\s+', ' '; $s.Substring(0, [Math]::Min($n, $s.Length)) }
function ToUtc($d) { $d = [datetime]$d; if ($d.Kind -eq 'Local') { $d.ToUniversalTime() } else { $d } }
# Transient-network retry (travel Wi-Fi, DNS drops): 5 tries, 3/6/9/12 s apart
function Invoke-Retry([scriptblock]$Do) {
    for ($i = 1; $i -le 5; $i++) {
        try { return (& $Do) } catch {
            $m = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
            if ($i -lt 5 -and $m -match 'No such host|forcibly closed|timed out|timeout|transport connection|SSL|name resolution|temporarily|503|502|504|429') { Write-Host "  network retry $i ($($_.Exception.Message))" -ForegroundColor DarkYellow; Start-Sleep -Seconds (3 * $i) } else { throw }
        }
    }
}
