# REF-DiscoveryOff-Remediate - Intune remediation REMEDIATION. Runs as SYSTEM. (v2, 12 Oct 2026)
# Sets FDResPub, fdPHost and LanmanServer (SMB server) to Disabled and stops them; sets DisableWpad=1.
# See the detection script for why these, and only these. The SMB client and the WinHTTP service are not touched.

$failed = @()
foreach ($n in 'FDResPub','fdPHost','LanmanServer') {
    if (-not (Get-Service $n -ErrorAction SilentlyContinue)) { continue }
    try {
        Set-Service -Name $n -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name $n -Force -ErrorAction Stop
    } catch { $failed += "${n}: $($_.Exception.Message)" }
}
try {
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
    New-ItemProperty -Path $k -Name DisableWpad -PropertyType DWord -Value 1 -Force | Out-Null
} catch { $failed += "DisableWpad: $($_.Exception.Message)" }
if ($failed.Count) { Write-Output ('could not set: ' + ($failed -join '; ')); exit 1 }
Write-Output 'FDResPub, fdPHost, LanmanServer disabled and stopped; WPAD disabled.'; exit 0
