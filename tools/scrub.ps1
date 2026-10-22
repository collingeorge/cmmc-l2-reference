# scrub.ps1 - run before every commit. Fails (exit 1) if any file in the tree carries something that looks like a live
# identifier: a GUID, a UPN or e-mail, an IP address, a CAGE-shaped code next to the word CAGE, an SPRS UID, or any term
# from the blocklist file named by $env:SCRUB_BLOCKLIST (your tenant's real account, device and workspace names) - keep that
# file OUTSIDE the repository tree; without it only the pattern checks run. Placeholders from config.example.json (all-zero GUIDs, example.com) are allowed.
#   .\tools\scrub.ps1            report
#   .\tools\scrub.ps1 -Fix       replace blocklist terms with their placeholders in place (GUIDs/IPs are reported, not rewritten)
[CmdletBinding()]
param([switch]$Fix, [string]$Root = (Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)), [string]$Blocklist = $env:SCRUB_BLOCKLIST)
$ErrorActionPreference = 'Stop'
# placeholders, Microsoft first-party public client ids, well-known resource app ids (Exchange Online, SharePoint Online, Teams,
# Intune), the built-in passkey profile - none identifies a tenant
$allowGuid = '00000000-0000-0000-0000-000000000000', '00000000-0000-0000-0000-000000000001', '14d82eec-204b-4c2f-b7e8-296a70dab67e', '1950a258-227b-4e31-a9cf-717495945fc2',
             '00000002-0000-0ff1-ce00-000000000000', '00000003-0000-0ff1-ce00-000000000000', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe', '0000000a-0000-0000-c000-000000000000',
             '35378eac-683f-11d2-a89a-00c04fbbcfa2', '0e796bdb-100d-47d6-a2d5-f7d2daa51f51',   # Windows constants: Group Policy registry extension; 'password on wake' power setting
             '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2',   # Defender ASR rule id: block credential stealing from LSASS (public)
             '73bb0cd4-e502-49b8-9c6f-b59445bf720b', '85203421-48f9-4355-9bc8-8a53846e5083'   # FIDO2 AAGUIDs published by Yubico (YubiKey 5 FIPS series, 5Ci FIPS) - vendor model ids, not tenant objects
# a GUID on a line whose JSON key is a Microsoft settings-catalog template reference is a public template id, not a tenant id
$allowKeyRx = '"(settingInstanceTemplateId|settingValueTemplateId|templateId|templateFamily)"\s*:|(Group|PolicyRule) Id=\\"\{|"value":\s*"\{|"value":\s*"SWC\\\\|foreach \(\$asr in '   # ...or the public Defender ASR rule ids (Microsoft documentation)   # ...or a brace-wrapped GUID in a setting value (Windows device classes, device-control group ids): policy-local, never a tenant object id
$patterns = [ordered]@{
    'GUID'   = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    'UPN/e-mail' = '[A-Za-z0-9._%+-]+@(?!example\.com|example\.onmicrosoft\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    'IPv4'   = '(?<![\d.])(?!127\.0\.0\.1|0\.0\.0\.0)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])'   # valid octets only, not inside a longer dotted number (certificate OIDs 2.16.840.1.101.3.2.1, versions 88.0.705.23)
    'IPv6'   = '\b(?=\S*[a-fA-F])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b'   # needs a hex letter, so 22:00:00 (a time) does not match
    'CAGE'   = '\bCAGE\b[^\n]{0,20}\b(?=[0-9A-Z]{5}\b)(?=[A-Z]*\d)[0-9A-Z]{5}\b'   # five upper-case alphanumerics with at least one digit, near the word CAGE
    'SPRS UID' = '\b(?:SB|S2)\d{8,9}\b'
}
# address constants that identify no network: range bounds used to express 'everything except loopback', and the Cloudflare WARP
# client's documented local DNS proxy addresses
$allowIp = '126.255.255.255', '127.0.0.0', '128.0.0.0', '255.255.255.255', '127.0.2.2', '127.0.2.3',
           '9.0.0.50', '9.0.0.42'   # Killer/Rivet and Microsoft in-box Ethernet driver VERSION numbers (KillerSuite remediation)
$block = @{}
if (Test-Path $Blocklist) { foreach ($l in Get-Content $Blocklist | Where-Object { $_ -and $_ -notmatch '^\s*#' }) { $k, $v = $l -split '\s*=>\s*', 2; $block[$k.Trim()] = $(if ($v) { $v.Trim() } else { '<REDACTED>' }) } }
# the scrubber and the gitleaks config carry the patterns themselves and are skipped; the brand name 'Sanctir' is public by design and is not blocked
$files = Get-ChildItem $Root -Recurse -File | Where-Object { $_.FullName -notmatch '\\\.git\\' -and $_.Extension -in '.ps1', '.psm1', '.md', '.json', '.yaml', '.yml', '.txt', '.kql', '.xml', '.sh', '.toml' -and $_.Name -notin 'blocklist.txt', 'scrub.ps1', '.gitleaks.toml' }
$hits = 0
foreach ($f in $files) {
    $t = Get-Content $f.FullName -Raw; $orig = $t
    # blocklist terms longest first, so a full address is replaced before a shorter term inside it
    foreach ($k in @($block.Keys | Sort-Object Length -Descending)) { if ($t -match [regex]::Escape($k)) { $hits++; "{0}: blocklist '{1}'" -f $f.FullName.Substring($Root.Length + 1), $k; if ($Fix) { $t = $t -replace [regex]::Escape($k), $block[$k] } } }
    foreach ($p in $patterns.Keys) { foreach ($m in [regex]::Matches($t, $patterns[$p])) {
        if ($p -eq 'IPv4' -and $allowIp -contains $m.Value) { continue }
        if ($p -eq 'IPv6' -and $m.Value -match '^ffff:') { continue }   # IPv4-mapped range bounds (::ffff:...), not an address of anyone
        if ($p -eq 'GUID') { if ($allowGuid -contains $m.Value.ToLower()) { continue }; $ls = $t.LastIndexOf("`n", $m.Index); $lineText = $t.Substring($ls + 1, $m.Index - $ls - 1); if ($lineText -match $allowKeyRx) { continue } }
        $hits++; "{0}: {1} {2}" -f $f.FullName.Substring($Root.Length + 1), $p, $m.Value } }
    if ($Fix -and $t -ne $orig) { [IO.File]::WriteAllText($f.FullName, $t, (New-Object Text.UTF8Encoding($false))) }
}
if ($hits) { Write-Output "SCRUB: $hits finding(s). Do not commit."; exit 1 } else { Write-Output 'SCRUB: clean.'; exit 0 }




