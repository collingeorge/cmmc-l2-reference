# scrub.ps1 - run before every commit. Fails (exit 1) if any file in the tree carries something that looks like a live
# identifier: a GUID, a UPN or e-mail, an IP address, a CAGE-shaped code next to the word CAGE, an SPRS UID, or any term
# from the blocklist file named by $env:SCRUB_BLOCKLIST (your tenant's real account, device and workspace names) - keep that
# file OUTSIDE the repository tree; without it only the pattern checks run. Placeholders from config.example.json (all-zero GUIDs, example.com) are allowed.
#   .\tools\scrub.ps1            report
#   .\tools\scrub.ps1 -Fix       replace blocklist terms with their placeholders in place (GUIDs/IPs are reported, not rewritten)
[CmdletBinding()]
param([switch]$Fix, [string]$Root = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)), [string]$Blocklist = $env:SCRUB_BLOCKLIST)
$ErrorActionPreference = 'Stop'
$allowGuid = '00000000-0000-0000-0000-000000000000', '14d82eec-204b-4c2f-b7e8-296a70dab67e', '1950a258-227b-4e31-a9cf-717495945fc2'   # placeholders and Microsoft first-party public client ids
$patterns = [ordered]@{
    'GUID'   = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    'UPN/e-mail' = '[A-Za-z0-9._%+-]+@(?!example\.com|example\.onmicrosoft\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    'IPv4'   = '\b(?!127\.0\.0\.1|0\.0\.0\.0)(?:\d{1,3}\.){3}\d{1,3}\b'
    'IPv6'   = '\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b'
    'CAGE'   = '(?i)\bCAGE\b[^\n]{0,20}\b[0-9A-Z]{5}\b'
    'SPRS UID' = '\b(?:SB|S2)\d{8,9}\b'
}
$block = @{}
if (Test-Path $Blocklist) { foreach ($l in Get-Content $Blocklist | Where-Object { $_ -and $_ -notmatch '^\s*#' }) { $k, $v = $l -split '\s*=>\s*', 2; $block[$k.Trim()] = $(if ($v) { $v.Trim() } else { '<REDACTED>' }) } }
# the scrubber and the gitleaks config carry the patterns themselves and are skipped; the brand name 'Sanctir' is public by design and is not blocked
$files = Get-ChildItem $Root -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Extension -in '.ps1', '.psm1', '.md', '.json', '.yaml', '.yml', '.txt', '.kql', '.xml', '.sh', '.toml' -and $_.Name -notin 'blocklist.txt', 'scrub.ps1', '.gitleaks.toml' }
$hits = 0
foreach ($f in $files) {
    $t = Get-Content $f.FullName -Raw; $orig = $t
    foreach ($k in $block.Keys) { if ($t -match [regex]::Escape($k)) { $hits++; "{0}: blocklist '{1}'" -f $f.FullName.Substring($Root.Length + 1), $k; if ($Fix) { $t = $t -replace [regex]::Escape($k), $block[$k] } } }
    foreach ($p in $patterns.Keys) { foreach ($m in [regex]::Matches($t, $patterns[$p])) { if ($p -eq 'GUID' -and $allowGuid -contains $m.Value.ToLower()) { continue }; $hits++; "{0}: {1} {2}" -f $f.FullName.Substring($Root.Length + 1), $p, $m.Value } }
    if ($Fix -and $t -ne $orig) { [IO.File]::WriteAllText($f.FullName, $t, (New-Object Text.UTF8Encoding($false))) }
}
if ($hits) { Write-Output "SCRUB: $hits finding(s). Do not commit."; exit 1 } else { Write-Output 'SCRUB: clean.'; exit 0 }


