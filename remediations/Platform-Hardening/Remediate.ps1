# REF-Platform-Hardening - REMEDIATION (SYSTEM). Sets WSH off, mDNS off, NetBIOS over TCP/IP off on all interfaces.
$log = @()
$k = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'; if(-not (Test-Path $k)){ New-Item -Path $k -Force | Out-Null }
New-ItemProperty -Path $k -Name Enabled -Value 0 -PropertyType DWord -Force | Out-Null; $log += 'WSH Enabled=0'
$k = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
New-ItemProperty -Path $k -Name EnableMDNS -Value 0 -PropertyType DWord -Force | Out-Null; $log += 'EnableMDNS=0'
$n = 0
foreach($i in (Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue)){
    New-ItemProperty -Path $i.PSPath -Name NetbiosOptions -Value 2 -PropertyType DWord -Force | Out-Null; $n++
}
$log += ('NetbiosOptions=2 on ' + $n + ' interface(s)')
# FIPS-validated cryptography mode (CMMC 3.13.11). Added 2026-09-21. Takes effect at next reboot; no forced restart here.
$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy'; if(-not (Test-Path $k)){ New-Item -Path $k -Force | Out-Null }
New-ItemProperty -Path $k -Name Enabled -Value 1 -PropertyType DWord -Force | Out-Null; $log += 'FIPS Enabled=1'
# Network protection in block mode (CMMC 3.13.1, 3.14.6). Added 2026-09-24. See POAM-011.
# Written as a POLICY value deliberately. Set-MpPreference is silently refused while tamper protection is on, and a
# stale value already on the endpoint is not overwritten by the tenant. The policy value is accepted and outranks both.
# Verified by behaviour on both machines: a request to a known malicious test address was refused by Defender.
$k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection'
if(-not (Test-Path $k)){ New-Item -Path $k -Force | Out-Null }
New-ItemProperty -Path $k -Name EnableNetworkProtection -Value 1 -PropertyType DWord -Force | Out-Null
$log += 'NetworkProtection policy=1'
$log += ('NetworkProtection effective=' + (Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection)
# Fast Startup off (CMMC 3.1.19 / 3.13.16, data at rest). Added 2026-09-25. Makes a shutdown a real shutdown, so the
# BitLocker key is not retained in a hibernation image and pending updates apply on the way down.
$k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power'
New-ItemProperty -Path $k -Name HiberbootEnabled -Value 0 -PropertyType DWord -Force | Out-Null
$log += 'HiberbootEnabled=0'
Write-Output ($log -join '; ')
exit 0
