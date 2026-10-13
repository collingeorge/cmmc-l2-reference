# REF-Read-UpdateEndpoints.ps1 - 10 Oct 2026. READ-ONLY; runs as a standard user; no sign-in needed.
# WHY. Security Officer, 10 Oct 2026: as Cloudflare Gateway blocks grow (cloud storage, unapproved AI, new domains), prove that
# nothing blocks the channels that keep the estate current and managed: Windows Update and Delivery Optimisation, Defender
# signatures and cloud protection, Defender for Endpoint, Edge, Intune/Entra, Microsoft Store, Microsoft 365 Apps, OneDrive,
# Azure Monitor and Arc (Sentinel feed), certificate revocation, Cloudflare WARP, Dell. NIST 3.14.1, 3.14.4, 3.7.1.
# HOW. Each endpoint is resolved through the system resolver (so through WARP and Gateway exactly as Windows Update would)
# and, if it resolves, a TCP connection to port 443 is attempted. BLOCKED = Gateway answered 0.0.0.0 / ::; UNREACHABLE =
# no DNS answer or no TCP connection after retries (often the local network). Also reports how current the machine is.
[CmdletBinding()]
param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot), [int]$TcpTimeoutMs = 4000)   # evidence goes under <repo>\Evidence\<date>
$ErrorActionPreference = 'Continue'
$ep = [ordered]@{
    'Windows Update'          = 'update.microsoft.com', 'windowsupdate.microsoft.com', 'fe2.update.microsoft.com', 'fe3.delivery.mp.microsoft.com', 'sls.update.microsoft.com', 'dl.delivery.mp.microsoft.com', 'tlu.dl.delivery.mp.microsoft.com', 'download.windowsupdate.com', 'ctldl.windowsupdate.com', 'settings-win.data.microsoft.com'   # emdl.ws.microsoft.com removed 10 Oct: NXDOMAIN (retired)
    'Delivery Optimisation'   = 'geo.prod.do.dsp.mp.microsoft.com', 'kv801.prod.do.dsp.mp.microsoft.com'
    'Defender signatures'     = 'definitionupdates.microsoft.com', 'go.microsoft.com', 'fe3cr.delivery.mp.microsoft.com'
    'Defender cloud / MDE'    = 'wdcp.microsoft.com', 'wdcpalt.microsoft.com', 'unitedstates.x.cp.wd.microsoft.com', 'us-v20.events.endpoint.security.microsoft.com', 'winatp-gw-cus.microsoft.com', 'smartscreen-prod.microsoft.com'
    'Edge'                    = 'msedge.api.cdp.microsoft.com', 'edge.microsoft.com', 'msedge.b.tlu.dl.delivery.mp.microsoft.com', 'msedge.f.tlu.dl.delivery.mp.microsoft.com', 'config.edge.skype.com'
    'Intune / Entra'          = 'manage.microsoft.com', 'enterpriseenrollment.manage.microsoft.com', 'enterpriseregistration.windows.net', 'login.microsoftonline.com', 'device.login.microsoftonline.com', 'graph.microsoft.com'
    'Microsoft Store'         = 'storeedgefd.dsx.mp.microsoft.com', 'displaycatalog.mp.microsoft.com'
    'Microsoft 365 Apps'      = 'officecdn.microsoft.com', 'officecdn.microsoft.com.edgesuite.net', 'clients.config.office.net', 'outlook.office365.com'
    'OneDrive / SharePoint'   = 'oneclient.sfx.ms', 'REF-my.sharepoint.com', 'sanctir.sharepoint.com'
    'Azure Monitor / Arc'     = 'global.handler.control.monitor.azure.com', 'westus2.handler.control.monitor.azure.com', 'gbl.his.arc.azure.com', 'management.azure.com'
    'Certificate revocation'  = 'crl.microsoft.com', 'oneocsp.microsoft.com', 'ocsp.digicert.com', 'crl3.digicert.com'
    'Cloudflare WARP'         = 'downloads.cloudflareclient.com'
    'Dell'                    = 'dl.dell.com', 'downloads.dell.com'
}
function Probe([string]$h) {
    $ips = @(); $err = $null
    foreach ($i in 1..3) { try { $ips = @(Resolve-DnsName $h -QuickTimeout -ErrorAction Stop | Where-Object { $_.IPAddress } | ForEach-Object IPAddress); $err = $null; break } catch { $err = $_.Exception.Message; Start-Sleep -Milliseconds 800 } }
    if (-not $ips.Count) { return [pscustomobject]@{ Host = $h; State = 'UNREACHABLE'; Detail = "no DNS answer ($err)" } }
    $real = @($ips | Where-Object { $_ -notin '0.0.0.0', '::' })
    if (-not $real.Count) { return [pscustomobject]@{ Host = $h; State = 'BLOCKED'; Detail = 'Gateway answered 0.0.0.0 / ::' } }
    foreach ($ip in ($real | Sort-Object { $_ -match ':' } | Select-Object -First 2)) {
        foreach ($i in 1..2) {
            $c = New-Object System.Net.Sockets.TcpClient
            try { $t = $c.ConnectAsync($ip, 443); if ($t.Wait($TcpTimeoutMs) -and $c.Connected) { return [pscustomobject]@{ Host = $h; State = 'OK'; Detail = $ip } } } catch { } finally { $c.Dispose() }
        }
    }
    [pscustomobject]@{ Host = $h; State = 'UNREACHABLE'; Detail = "resolves ($($real[0])) but no TCP 443 connection" }
}
$out = New-Object Collections.ArrayList; function W($s) { [void]$out.Add("$s"); Write-Output "$s" }
$now = Get-Date
W "Update and management channels - $env:COMPUTERNAME - $($now.ToString('yyyy-MM-dd HH:mm zzz')) - read-only"
$warp = (& 'C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe' --accept-tos status 2>$null | Select-Object -First 2) -join ' / '
W "WARP: $warp"
$all = New-Object Collections.ArrayList
foreach ($g in $ep.Keys) {
    $res = @($ep[$g] | ForEach-Object { Probe $_ })
    foreach ($r in $res) { [void]$all.Add([pscustomobject]@{ Group = $g; Host = $r.Host; State = $r.State; Detail = $r.Detail }) }
    $bad = @($res | Where-Object State -ne 'OK')
    W ("  {0,-24} {1}/{2} OK{3}" -f $g, ($res.Count - $bad.Count), $res.Count, $(if ($bad) { ' | ' + (($bad | ForEach-Object { "$($_.State) $($_.Host) ($($_.Detail))" }) -join '; ') } else { '' }))
}
$blocked = @($all | Where-Object State -eq 'BLOCKED'); $unreach = @($all | Where-Object State -eq 'UNREACHABLE')
W ''
W "RESULT: $(@($all | Where-Object State -eq 'OK').Count) of $($all.Count) endpoints OK | BLOCKED by Gateway: $($blocked.Count) | unreachable: $($unreach.Count)"
if ($blocked.Count) { W "  ACTION: a Gateway rule is blocking an update channel - fix before anything else: $(($blocked.Host) -join ', ')" }
if ($unreach.Count -and -not $blocked.Count) { W '  Unreachable without a block usually means the local network or a host that only answers on some ports; re-run on a stable connection before acting.' }
W ''
W 'How current WS01 is:'
try { $m = Get-MpComputerStatus -ErrorAction Stop; W ("  Defender signatures {0} ({1} d old), engine {2}, platform {3}" -f $m.AntivirusSignatureVersion, $m.AntivirusSignatureAge, $m.AMEngineVersion, $m.AMProductVersion) } catch { W '  Defender status not readable here' }
try { $s = New-Object -ComObject Microsoft.Update.Session; $h = $s.CreateUpdateSearcher(); $n = $h.GetTotalHistoryCount(); $last = @($h.QueryHistory(0, [Math]::Min($n, 100)) | Where-Object { $_.ResultCode -eq 2 -and $_.Title -notmatch 'Security Intelligence' } | Select-Object -First 1); if ($last) { W ("  last Windows Update install {0:yyyy-MM-dd}: {1}" -f $last[0].Date.ToLocalTime(), $last[0].Title) } } catch { W '  Windows Update history not readable' }
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'; W "  OS build $($cv.CurrentBuild).$($cv.UBR)"
$eu = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate' -ErrorAction SilentlyContinue
$edge = (Get-Item "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe" -ErrorAction SilentlyContinue).VersionInfo.ProductVersion
W ("  Edge {0}; updater last check {1}" -f $edge, $(if ($eu.LastChecked) { [DateTimeOffset]::FromUnixTimeSeconds($eu.LastChecked).LocalDateTime.ToString('yyyy-MM-dd HH:mm') } else { 'unknown' }))
$dir = Join-Path $ProjectRoot ('Evidence\' + $now.ToString('yyyy-MM-dd')); New-Item -ItemType Directory -Force $dir | Out-Null
$f = Join-Path $dir "update-endpoints-$($now.ToString('HHmmss')).txt"; $out | Set-Content $f -Encoding UTF8
$all | Export-Csv ($f -replace '\.txt$', '.csv') -NoTypeInformation -Encoding UTF8
Write-Output "written: $f"
