# REF-STIGGap-Common.ps1 - shared body of the "SANCTIR - STIG Gap Closure" remediation.
# NOT deployed on its own: REF-STIGGap-Detect.ps1 and REF-STIGGap-Remediate.ps1 are built from
# this file by REF-STIGGap-Build.ps1 so that detection and remediation check exactly the same list.
#
# SOURCE. Every path and value below is DISA's requirement as read from the Windows 11 STIG V2R8 SCAP
# benchmark (U_MS_Windows_11_V2R8_STIG_SCAP_1-3_Benchmark.xml) on 6 Oct 2026, not typed from memory.
# SCOPE. Only settings that no tenant policy delivers (checked against the MDM store on WS01, 6 Oct).
# Settings a tenant policy owns (audit subcategories, user rights, event log size, UAC) are NOT here:
# writing them locally would fight the policy. They are changed in their own policies.

$Machine = @(
    # V-253359 WN11-CC-000039  Run as different user removed from context menus
    @{ V = 'V-253359'; K = 'SOFTWARE\Classes\batfile\shell\runasuser'; N = 'SuppressionPolicy'; D = 4096 }
    @{ V = 'V-253359'; K = 'SOFTWARE\Classes\cmdfile\shell\runasuser'; N = 'SuppressionPolicy'; D = 4096 }
    @{ V = 'V-253359'; K = 'SOFTWARE\Classes\exefile\shell\runasuser'; N = 'SuppressionPolicy'; D = 4096 }
    @{ V = 'V-253359'; K = 'SOFTWARE\Classes\mscfile\shell\runasuser'; N = 'SuppressionPolicy'; D = 4096 }
    # V-253376 WN11-CC-000110  Printing over HTTP prevented (the office printer uses IPP over HTTPS/443, not HTTP printing)
    @{ V = 'V-253376'; K = 'SOFTWARE\Policies\Microsoft\Windows NT\Printers'; N = 'DisableHTTPPrinting'; D = 1 }
    # V-253378 WN11-CC-000120  Network selection UI not shown on the logon screen
    @{ V = 'V-253378'; K = 'SOFTWARE\Policies\Microsoft\Windows\System'; N = 'DontDisplayNetworkSelectionUI'; D = 1 }
    # V-253385 WN11-CC-000175  Application Compatibility inventory collector off
    @{ V = 'V-253385'; K = 'SOFTWARE\Policies\Microsoft\Windows\AppCompat'; N = 'DisableInventory'; D = 1 }
    # V-253393 WN11-CC-000205  Diagnostic data not Full: 1 = Required (the level Intune and Windows Update reporting need)
    @{ V = 'V-253393'; K = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'; N = 'AllowTelemetry'; D = 1 }
    # V-253415 WN11-CC-000327  PowerShell transcription on, written to an admin-protected folder outside OneDrive
    @{ V = 'V-253415'; K = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; N = 'EnableTranscripting'; D = 1 }
    @{ V = 'V-253415'; K = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; N = 'EnableInvocationHeader'; D = 1 }
    @{ V = 'V-253415'; K = 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; N = 'OutputDirectory'; S = 'C:\ProgramData\REF\PSTranscripts' }
    # V-253423 WN11-CC-000370  Convenience PIN sign-in off (Windows Hello for Business is a different setting and is unaffected)
    @{ V = 'V-253423'; K = 'SOFTWARE\Policies\Microsoft\Windows\System'; N = 'AllowDomainPINLogon'; D = 0 }
    # V-253437 WN11-SO-000030  Audit subcategories take precedence over legacy categories
    @{ V = 'V-253437'; K = 'SYSTEM\CurrentControlSet\Control\Lsa'; N = 'SCENoApplyLegacyAuditPolicy'; D = 1 }
    # V-253458 WN11-SO-000180  NTLM may not fall back to a null session
    @{ V = 'V-253458'; K = 'SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0'; N = 'allownullsessionfallback'; D = 0 }
    # V-253459 WN11-SO-000185  PKU2U online identities refused (used only for Entra-to-Entra RDP/SMB, which is not in use)
    @{ V = 'V-253459'; K = 'SYSTEM\CurrentControlSet\Control\Lsa\pku2u'; N = 'AllowOnlineID'; D = 0 }
    # V-253460 WN11-SO-000190  Kerberos: AES128, AES256 and future types only - no DES, no RC4
    @{ V = 'V-253460'; K = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'; N = 'SupportedEncryptionTypes'; D = 2147483640 }
    # V-279688 WN11-00-000126  Consumer (Microsoft account) user authentication blocked
    @{ V = 'V-279688'; K = 'SOFTWARE\Policies\Microsoft\MicrosoftAccount'; N = 'DisableUserAuth'; D = 1 }

    # --- Added 6 Oct 2026: the Group Policy paths DISA's benchmark reads for nine settings that Intune ALREADY
    # enforces through its own (MDM) setting. The benchmark reads only these paths, so the MDM setting is invisible
    # to it. Each value below is the SAME value the MDM setting applies; nothing changes on the device's behaviour.
    # The MDM settings stay in their policies; this is the second registry location of the same control, written
    # because the STIG measures that location. Recorded as a deliberate exception to the no-duplicates rule (PLN-006).
    # V-253366 WN11-CC-000065  Wi-Fi Sense off            (MDM: Wifi/AllowAutoConnectToWiFiSenseHotspots = 0)
    @{ V = 'V-253366'; K = 'SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; N = 'AutoConnectAllowedOEM'; D = 0 }
    # V-253389 WN11-CC-000195  Enhanced face anti-spoofing (MDM: PassportForWork FacialFeaturesUseEnhancedAntiSpoofing = 1)
    @{ V = 'V-253389'; K = 'SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures'; N = 'EnhancedAntiSpoofing'; D = 1 }
    # V-253390 WN11-CC-000197  Consumer experiences off    (MDM: Experience/AllowWindowsConsumerFeatures = 0)
    @{ V = 'V-253390'; K = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'; N = 'DisableWindowsConsumerFeatures'; D = 1 }
    # V-253394 WN11-CC-000206  Delivery Optimization HTTP only (MDM: DeliveryOptimization/DODownloadMode = 0)
    @{ V = 'V-253394'; K = 'SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; N = 'DODownloadMode'; D = 0 }
    # V-253399 WN11-CC-000252  Game recording off          (MDM: ApplicationManagement/AllowGameDVR = 0)
    @{ V = 'V-253399'; K = 'SOFTWARE\Policies\Microsoft\Windows\GameDVR'; N = 'AllowGameDVR'; D = 0 }
    # V-253401 WN11-CC-000260  Windows Hello PIN at least 6 (MDM: PassportForWork MinimumPINLength = 6). Same minimum;
    # the Hello enablement value (PassportForWork\Enabled) is deliberately NOT written, so Intune stays in control of Hello.
    @{ V = 'V-253401'; K = 'SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity'; N = 'MinimumPINLength'; D = 6 }
    # V-253409 WN11-CC-000305  Encrypted files not indexed (MDM: Search/AllowIndexingEncryptedStoresOrItems = 0)
    @{ V = 'V-253409'; K = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'; N = 'AllowIndexingEncryptedStoresOrItems'; D = 0 }
    # V-253422 WN11-CC-000365  Apps may not activate by voice, locked or not (MDM sets the above-lock half to 2 = Force Deny)
    @{ V = 'V-253422'; K = 'SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; N = 'LetAppsActivateWithVoice'; D = 2 }
    @{ V = 'V-253422'; K = 'SOFTWARE\Policies\Microsoft\Windows\AppPrivacy'; N = 'LetAppsActivateWithVoiceAboveLock'; D = 2 }
    # V-253424 WN11-CC-000385  Ink Workspace not above lock (MDM: WindowsInkWorkspace/AllowWindowsInkWorkspace = 1)
    @{ V = 'V-253424'; K = 'SOFTWARE\Policies\Microsoft\WindowsInkWorkspace'; N = 'AllowWindowsInkWorkspace'; D = 1 }
)
# V-253289 WN11-00-000175  Secondary Logon service disabled. Checked 6 Oct 2026: it has not started once in 30 days
# (System log 7036), which covers every Codex sandbox session since 2 Oct, so nothing in use depends on it.
# It is not in the STD-011 service baseline, so this does not contradict the Service Baseline remediation.
$DisabledServices = @(@{ V = 'V-253289'; Name = 'seclogon' })
$PerUser = @(
    # V-253425 WN11-CC-000390  No third-party suggestions in Windows spotlight - every user profile, including REF-la
    @{ V = 'V-253425'; K = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'; N = 'DisableThirdPartySuggestions'; D = 1 }
    # V-253477 WN11-UC-000015  No toast notifications on the lock screen - every user profile
    @{ V = 'V-253477'; K = 'Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications'; N = 'NoToastApplicationNotificationOnLockScreen'; D = 1 }
    # V-253478 WN11-UC-000020  Preserve zone information in attachments - every user profile (10 Oct 2026: the user-targeted
    # Intune policy reaches cgeorge only; admin and REF-la profiles were missing it in the 10 Oct scan)
    @{ V = 'V-253478'; K = 'Software\Microsoft\Windows\CurrentVersion\Policies\Attachments'; N = 'SaveZoneInformation'; D = 2 }
)
# V-253435 / V-253436  Built-in accounts renamed. Both stay DISABLED (tenant policy). LAPS manages REF-la, not these.
$Renames = @(@{ V = 'V-253435'; Rid = 500; To = 'snc-builtin-disabled' }, @{ V = 'V-253436'; Rid = 501; To = 'snc-guest-disabled' })
# V-253302  Minimum password age 1 day for LOCAL accounts (REF-la). LAPS rotation ignores minimum age.
# V-253298 (lockout threshold 3) is NOT set here: the tenant owns it (DeviceLock/AccountLockoutPolicy) and put 10 back at the
# next sync on 6 Oct, so it is changed in that policy instead (REF-Set-PolicyValue.ps1).
$Lockout = 3; $MinPwAge = 1
$TranscriptDir = 'C:\ProgramData\REF\PSTranscripts'; $TranscriptKeepDays = 90

$script:Gaps = New-Object Collections.ArrayList
function Note($v, $what) { [void]$script:Gaps.Add("$v $what") }

function Test-OrSet-Value($root, $k, $n, $want, $isString, [switch]$Write) {
    $key = $root.OpenSubKey($k, $Write.IsPresent)
    if (-not $key -and $Write) { $key = $root.CreateSubKey($k) }
    try {
        $cur = if ($key) { $key.GetValue($n, $null) } else { $null }
        $ok = if ($isString) { "$cur" -eq $want } else { $null -ne $cur -and $key.GetValueKind($n) -eq 'DWord' -and ([long]$cur -band 0xFFFFFFFFL) -eq ([long]$want -band 0xFFFFFFFFL) }
        if (-not $ok -and $Write) {
            if ($isString) { $key.SetValue($n, $want, [Microsoft.Win32.RegistryValueKind]::String) }
            else { $key.SetValue($n, [BitConverter]::ToInt32([BitConverter]::GetBytes([uint32]([long]$want -band 0xFFFFFFFFL)), 0), [Microsoft.Win32.RegistryValueKind]::DWord) }
        }
        return @{ Ok = $ok; Cur = $cur }
    } finally { if ($key) { $key.Close() } }
}

function Invoke-StigGap([switch]$Write) {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        foreach ($s in $Machine) {
            $isStr = $s.ContainsKey('S'); $want = if ($isStr) { $s.S } else { $s.D }
            $r = Test-OrSet-Value $hklm $s.K $s.N $want $isStr -Write:$Write
            if (-not $r.Ok) { Note $s.V "HKLM\$($s.K)\$($s.N) is '$($r.Cur)', wants '$want'" }
        }
    } finally { $hklm.Close() }

    # Transcript folder: SYSTEM and Administrators full; users may create and write their own transcripts but not list others'.
    if (-not (Test-Path $TranscriptDir)) { Note 'V-253415' "folder $TranscriptDir missing"; if ($Write) { New-Item -ItemType Directory -Force $TranscriptDir | Out-Null } }
    if ($Write -and (Test-Path $TranscriptDir)) {
        & icacls.exe $TranscriptDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-3-0:(OI)(CI)(IO)F' '*S-1-5-11:(CI)(AD,WD,X,RA,REA)' | Out-Null
        Get-ChildItem $TranscriptDir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$TranscriptKeepDays) } | Remove-Item -Force -ErrorAction SilentlyContinue
    }

    # Per-user values: every local and Entra profile. Loaded hives are written in place; others are loaded briefly.
    $profiles = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' }
    $users = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        foreach ($p in $profiles) {
            $sid = $p.PSChildName; $dir = (Get-ItemProperty $p.PSPath).ProfileImagePath; $dat = Join-Path $dir 'NTUSER.DAT'; $who = Split-Path $dir -Leaf
            $mount = $sid; $loadedHere = $false
            try {
                $probe = $users.OpenSubKey($sid); $isLoaded = [bool]$probe; if ($probe) { $probe.Close() }
                if (-not $isLoaded) {
                    if (-not (Test-Path -LiteralPath $dat -ErrorAction Stop)) { continue }
                    $mount = "SANCTIR_STIG_$($sid -replace '[^0-9]', '')"
                    & reg.exe load "HKU\$mount" "$dat" 2>&1 | Out-Null
                    if ($LASTEXITCODE -ne 0) { Note 'V-253425/V-253477' "profile $who could not be loaded"; continue }
                    $loadedHere = $true
                }
                $hive = $users.OpenSubKey($mount, $Write.IsPresent)
                try { foreach ($s in $PerUser) { $r = Test-OrSet-Value $hive $s.K $s.N $s.D $false -Write:$Write; if (-not $r.Ok) { Note $s.V "user $who $($s.N) is '$($r.Cur)', wants $($s.D)" } } } finally { if ($hive) { $hive.Close() } }
            } catch { Note 'V-253425/V-253477' "profile $who could not be read: $($_.Exception.Message)" }
            finally {
                if ($loadedHere) { [GC]::Collect(); [GC]::WaitForPendingFinalizers(); & reg.exe unload "HKU\$mount" 2>&1 | Out-Null }
            }
        }
    } finally { $users.Close() }

    # Built-in account names (the accounts themselves stay disabled by tenant policy).
    foreach ($rn in $Renames) {
        $u = Get-LocalUser | Where-Object { $_.SID.Value -match "-$($rn.Rid)$" } | Select-Object -First 1
        if ($u -and $u.Name -ne $rn.To) { Note $rn.V "built-in account RID $($rn.Rid) is named '$($u.Name)'"; if ($Write) { Rename-LocalUser -InputObject $u -NewName $rn.To } }
    }

    # DoD / ECA trust anchors (V-253427, V-253428) and untrusted cross-certificates (V-253429, V-253430).
    # Each certificate is re-checked against its DISA thumbprint before it is added; a mismatch is never installed.
    if (Get-Variable -Name TrustCerts -ErrorAction SilentlyContinue) {
        foreach ($tc in $TrustCerts) {
            $store = New-Object Security.Cryptography.X509Certificates.X509Store($tc.Store, 'LocalMachine')
            $store.Open($(if ($Write) { 'ReadWrite' } else { 'ReadOnly' }))
            try {
                if ($store.Certificates.Find('FindByThumbprint', $tc.T, $false).Count -eq 0) {
                    Note $tc.V "$($tc.Name) ($($tc.T)) not in LocalMachine\$($tc.Store)"
                    if ($Write) {
                        $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, [Convert]::FromBase64String($tc.B64))
                        if ($c.Thumbprint -ne $tc.T) { Note $tc.V "embedded certificate for $($tc.Name) does not match its thumbprint - NOT installed" } else { $store.Add($c) }
                    }
                }
            } finally { $store.Close() }
        }
    }

    # Services DISA requires disabled.
    foreach ($svc in $DisabledServices) {
        $s = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction SilentlyContinue
        if ($s -and $s.StartMode -ne 'Disabled') {
            Note $svc.V "service $($svc.Name) start mode is $($s.StartMode), wants Disabled"
            if ($Write) { Stop-Service -Name $svc.Name -Force -ErrorAction SilentlyContinue; Set-Service -Name $svc.Name -StartupType Disabled }
        }
    }

    # Local account policy.
    $na = & net.exe accounts 2>&1
    $thr = [regex]::Match(($na -join "`n"), '(?im)^Lockout threshold:\s+(\S+)').Groups[1].Value
    $min = [regex]::Match(($na -join "`n"), '(?im)^Minimum password age \(days\):\s+(\d+)').Groups[1].Value
    # lockout threshold: tenant-owned (DeviceLock/AccountLockoutPolicy) - deliberately not touched here
    if ($min -notmatch '^\d+$' -or [int]$min -lt $MinPwAge) { Note 'V-253302' "minimum password age is '$min' days, wants $MinPwAge"; if ($Write) { & net.exe accounts /minpwage:$MinPwAge | Out-Null } }
}
