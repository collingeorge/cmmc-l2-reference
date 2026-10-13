# REF-DiscoveryOff-Detect - Intune remediation DETECTION. Runs as SYSTEM. (v2, 12 Oct 2026)
# Exit 0 = discovery and file-serving exposure is off. Exit 1 = remediate.
#
# FDResPub (Function Discovery Resource Publication) and fdPHost (Function Discovery Provider Host)
# advertise this computer and hunt for printers/NAS/devices by WS-Discovery and SSDP. On this estate
# (two Entra-only workstations, no shares, no auto-discovered printers, WARP always-on) they have
# nothing to find and were producing ~700 blocked WS-Discovery packets per 6 hours on WS01
# (audit, 30 Sep 2026). Copilot, 30 Sep: disable both. These two are NOT in the STD-011 baseline,
# which is why a Disabled state is correct for them and for nothing in that list.
# What it costs: automatic printer/scanner discovery and Explorer's Network view.
#
# v2 (RA-025 finding 7, Security Officer 12 Oct 2026):
#  - LanmanServer (the SMB *server*): a laptop shares nothing; it listened on 445 (blocked by the firewall). Disabled and
#    stopped. The SMB *client* (LanmanWorkstation) is untouched, so OneDrive, printing and drive mapping still work.
#    Not in any baseline must-run list (checked against ServiceBaseline/Egress lists).
#  - WPAD: proxy auto-discovery is a classic credential-relay and traffic-hijack vector on hostile networks. Turned off
#    with Microsoft's documented value DisableWpad=1 (HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet
#    Settings\WinHttp). The WinHTTP service itself stays running - the Service Baseline and Egress lists require it.

$bad = foreach ($n in 'FDResPub','fdPHost','LanmanServer') {
    $s = Get-CimInstance Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue
    if (-not $s) { continue }
    if ($s.StartMode -ne 'Disabled' -or $s.State -ne 'Stopped') { "$n $($s.StartMode)/$($s.State)" }
}
$w = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp' -Name DisableWpad -ErrorAction SilentlyContinue).DisableWpad
if ($w -ne 1) { $bad = @($bad) + "DisableWpad=$w" }
if ($bad) { Write-Output ('discovery/serving exposure on: ' + ($bad -join '; ')); exit 1 }
Write-Output 'OK: FDResPub, fdPHost, LanmanServer disabled and stopped; WPAD disabled.'; exit 0
