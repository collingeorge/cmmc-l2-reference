# Connect-Tenant.ps1 - a Microsoft Graph and Azure console that needs NO PowerShell module.
#
# WHY. Once an App Control (WDAC) allow-list is enforced on your admin workstation, the Microsoft Graph PowerShell module's
# DLLs are blocked unless you sign or allow every one of them, and you lose the ability to push the very change that would
# fix it. Graph and Azure Resource Manager are plain HTTPS. PowerShell's own web cmdlets are part of Windows and are never
# blocked, so this file signs in and defines the two commands the rest of the repository uses - Invoke-MgGraphRequest and
# Get-MgContext - on top of them. Nothing is installed, no DLL is loaded, it works identically on every machine.
#
# SIGN-IN. Authorization code + PKCE with a loopback redirect on THIS machine. Not device code: device-code sign-ins are
# phishable even with a FIDO2 key (the victim authenticates genuinely; the token goes to whoever holds the code), and this
# reference blocks the device-code flow tenant-wide in Conditional Access. Here the result can only be returned to
# http://localhost:<port> on the machine that started the sign-in, and the PKCE verifier never leaves this window.
#
# USE.   . "<repo>\scripts\Connect-Tenant.ps1";  Connect-Tenant
# It prints a sign-in address (also copied to the clipboard). Paste it into your browser, sign in as your ADMIN account with
# your security key; the browser hands the result back to this window. Sign in once per window; -Force signs in again.
#
# SECRETS. Tokens exist only in this PowerShell session's memory and are never printed or written. Close the window and they
# are gone. The client ids are Microsoft's public first-party apps (Graph Command Line Tools, Azure PowerShell).
# KNOWN LIMIT. This flow cannot bind tokens. If you enforce Conditional Access token protection, exclude the admin account
# from that policy (it has no mailbox or files to protect) or the admin sign-in is refused.
# Requires PowerShell 7.
. "$PSScriptRoot\_Common.ps1"
$global:RefTenant = $global:Cfg.tenant.id
$global:RefGraphClient = $global:Cfg.graph.clientApp
$global:RefArmClient = '1950a258-227b-4e31-a9cf-717495945fc2'   # Microsoft Azure PowerShell (public client)

function Invoke-BrowserSignIn([string]$Client, [string]$Scope, [string]$Label = 'Graph') {
    $auth = "https://login.microsoftonline.com/$global:RefTenant/oauth2/v2.0"
    function B64Url([byte[]]$b) { [Convert]::ToBase64String($b).TrimEnd('=').Replace('+', '-').Replace('/', '_') }
    $verifier = B64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
    $challenge = B64Url ([Security.Cryptography.SHA256]::HashData([Text.Encoding]::ASCII.GetBytes($verifier)))
    $state = B64Url ([Security.Cryptography.RandomNumberGenerator]::GetBytes(16))
    $l4 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $l4.Start(); $port = $l4.LocalEndpoint.Port
    $l6 = $null; try { $l6 = [Net.Sockets.TcpListener]::new([Net.IPAddress]::IPv6Loopback, $port); $l6.Start() } catch { $l6 = $null }
    $redirect = "http://localhost:$port/"
    $url = "$auth/authorize?client_id=$Client&response_type=code&response_mode=query&prompt=select_account" +
           "&redirect_uri=$([uri]::EscapeDataString($redirect))&scope=$([uri]::EscapeDataString($Scope))&state=$state" +
           "&code_challenge=$challenge&code_challenge_method=S256"
    try { Set-Clipboard -Value $url } catch { }
    Write-Host ''; Write-Host "[$Label] Sign in: paste the address below into your browser (it is on the clipboard), sign in as $($global:Cfg.accounts.admin) with your security key." -ForegroundColor Yellow
    Write-Host $url -ForegroundColor DarkGray; Write-Host ''
    $code = $null; $deadline = (Get-Date).AddMinutes(5)
    try {
        while (-not $code -and (Get-Date) -lt $deadline) {
            $c = $null
            if ($l4.Pending()) { $c = $l4.AcceptTcpClient() } elseif ($l6 -and $l6.Pending()) { $c = $l6.AcceptTcpClient() } else { Start-Sleep -Milliseconds 200; continue }
            try {
                $s = $c.GetStream(); $r = [IO.StreamReader]::new($s); $line = $r.ReadLine()
                $target = if ($line) { ($line -split ' ')[1] } else { '' }
                $ok = $target -like '/?*'
                $q = @{}   # plain hashtable: an if-expression would unroll a NameValueCollection into its keys
                if ($ok) { foreach ($pair in ((($target -split '\?', 2)[1]) -split '&')) { if (-not $pair) { continue }; $kv = $pair -split '=', 2; $q[[uri]::UnescapeDataString($kv[0])] = if ($kv.Count -gt 1) { [uri]::UnescapeDataString(($kv[1] -replace '\+', ' ')) } else { '' } } }
                $msg = if (-not $ok) { 'Not found.' } elseif ($q['error']) { "Sign-in failed: $($q['error_description'])" } elseif ($q['state'] -ne $state) { 'State mismatch - ignored.' } else { 'Signed in. You can close this tab and return to PowerShell.' }
                $html = "<html><body style='font-family:Segoe UI;padding:2em'><h3>Admin sign-in</h3><p>$([System.Net.WebUtility]::HtmlEncode($msg))</p></body></html>"
                $bytes = [Text.Encoding]::UTF8.GetBytes("HTTP/1.1 $(if ($ok) { '200 OK' } else { '404 Not Found' })`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $([Text.Encoding]::UTF8.GetByteCount($html))`r`nConnection: close`r`n`r`n$html")
                $s.Write($bytes, 0, $bytes.Length); $s.Flush()
                if ($ok -and $q['error']) { throw "sign-in failed: $($q['error']) $($q['error_description'])" }
                if ($ok -and $q['state'] -eq $state -and $q['code']) { $code = $q['code'] }
            } finally { $c.Close() }
        }
    } finally { $l4.Stop(); if ($l6) { $l6.Stop() } }
    if (-not $code) { throw 'sign-in was not completed within 5 minutes.' }
    Invoke-RestMethod -Method POST -Uri "$auth/token" -Body @{ grant_type = 'authorization_code'; client_id = $Client; code = $code; redirect_uri = $redirect; code_verifier = $verifier; scope = $Scope }
}

function Connect-Tenant {
    [CmdletBinding()]
    param([string[]]$Scopes = @('DeviceManagementConfiguration.ReadWrite.All', 'DeviceManagementManagedDevices.ReadWrite.All', 'DeviceManagementApps.ReadWrite.All',
                                'DeviceManagementServiceConfig.ReadWrite.All', 'Device.ReadWrite.All', 'Group.Read.All', 'DeviceLocalCredential.ReadBasic.All',
                                'BitLockerKey.ReadBasic.All', 'Policy.Read.All', 'User.Read'), [switch]$Force)
    if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Run this in PowerShell 7.' }
    if (-not $Force -and $global:RefGraph -and $global:RefGraph.Refresh) { "already connected as $($global:RefGraph.Account) - reusing this window's sign-in"; return }
    $scope = (($Scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) + 'offline_access', 'openid', 'profile') -join ' '
    try { $tok = Invoke-BrowserSignIn -Client $global:RefGraphClient -Scope $scope -Label 'Graph' }
    catch { throw ("sign-in failed: {0} {1}" -f $_.Exception.Message, (($_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue).error_description -replace '\s+', ' ')) }
    $global:RefGraph = @{ Access = $tok.access_token; Refresh = $tok.refresh_token; Expires = (Get-Date).AddSeconds([int]$tok.expires_in - 120); Account = $null; Scopes = "$($tok.scope)" }
    $me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=userPrincipalName'
    $global:RefGraph.Account = $me.userPrincipalName
    "connected as $($me.userPrincipalName) (no module; token held in this window only)"
}

# Azure Resource Manager token from the SAME sign-in where possible: cached token; else exchange the Graph refresh token
# (Microsoft's first-party apps can share a sign-in); else one browser sign-in for Azure, cached for the rest of the window.
function Get-ArmToken {
    $tokUri = "https://login.microsoftonline.com/$global:RefTenant/oauth2/v2.0/token"
    $scope = 'https://management.azure.com/user_impersonation offline_access openid profile'
    if ($global:RefArm -and $global:RefArm.Access) {
        if ((Get-Date) -lt $global:RefArm.Expires) { return $global:RefArm.Access }
        try { $t = Invoke-RestMethod -Method POST -Uri $tokUri -Body @{ grant_type = 'refresh_token'; client_id = $global:RefArm.Client; refresh_token = $global:RefArm.Refresh; scope = $scope }
              $global:RefArm = @{ Access = $t.access_token; Refresh = $(if ($t.refresh_token) { $t.refresh_token } else { $global:RefArm.Refresh }); Expires = (Get-Date).AddSeconds([int]$t.expires_in - 120); Client = $global:RefArm.Client }
              return $global:RefArm.Access } catch { }
    }
    if ($global:RefGraph -and $global:RefGraph.Refresh) {
        foreach ($cid in $global:RefGraphClient, $global:RefArmClient) {
            try { $t = Invoke-RestMethod -Method POST -Uri $tokUri -Body @{ grant_type = 'refresh_token'; client_id = $cid; refresh_token = $global:RefGraph.Refresh; scope = $scope }
                  $global:RefArm = @{ Access = $t.access_token; Refresh = $t.refresh_token; Expires = (Get-Date).AddSeconds([int]$t.expires_in - 120); Client = $cid }
                  Write-Host 'Azure: reusing this window''s sign-in.' -ForegroundColor DarkGray
                  return $global:RefArm.Access } catch { }
        }
    }
    try { $t = Invoke-BrowserSignIn -Client $global:RefArmClient -Scope $scope -Label 'Azure - once per window' }
    catch { throw "Azure sign-in failed: $($_.Exception.Message) $($_.ErrorDetails.Message)" }
    $global:RefArm = @{ Access = $t.access_token; Refresh = $t.refresh_token; Expires = (Get-Date).AddSeconds([int]$t.expires_in - 120); Client = $global:RefArmClient }
    return $global:RefArm.Access
}

function Get-MgContext {
    if ($global:RefGraph -and $global:RefGraph.Access) { [pscustomobject]@{ Account = $global:RefGraph.Account; Scopes = ($global:RefGraph.Scopes -split ' '); AuthType = 'Delegated (browser sign-in on this machine, PKCE; no module)' } }
}

function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string]$Method = 'GET', [Parameter(Mandatory)][string]$Uri, $Body, [string]$ContentType = 'application/json')
    if (-not $global:RefGraph -or -not $global:RefGraph.Access) { throw 'Not connected. Run Connect-Tenant first.' }
    if ((Get-Date) -ge $global:RefGraph.Expires) {
        if (-not $global:RefGraph.Refresh) { throw 'The sign-in has expired. Run Connect-Tenant again.' }
        $t = Invoke-RestMethod -Method POST -Uri "https://login.microsoftonline.com/$global:RefTenant/oauth2/v2.0/token" -Body @{ grant_type = 'refresh_token'; client_id = $global:RefGraphClient; refresh_token = $global:RefGraph.Refresh }
        $global:RefGraph.Access = $t.access_token; if ($t.refresh_token) { $global:RefGraph.Refresh = $t.refresh_token }; $global:RefGraph.Expires = (Get-Date).AddSeconds([int]$t.expires_in - 120)
    }
    $p = @{ Method = $Method; Uri = $Uri; Headers = @{ Authorization = "Bearer $($global:RefGraph.Access)" }; ErrorAction = 'Stop' }
    if ($PSBoundParameters.ContainsKey('Body') -and $null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 50 }
        $p.Body = [Text.Encoding]::UTF8.GetBytes($json); $p.ContentType = "$ContentType; charset=utf-8"
    }
    $resp = Invoke-WebRequest @p
    if ($resp.Content -and "$($resp.Content)".Trim()) { "$($resp.Content)" | ConvertFrom-Json -AsHashtable -Depth 100 }
}
