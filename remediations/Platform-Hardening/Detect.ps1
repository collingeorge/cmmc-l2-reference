# REF-Platform-Hardening - DETECTION (SYSTEM). Legacy name-resolution and script-host attack surface.
# CMMC 3.4.6 (least functionality), 3.13.1 / 3.13.6 (boundary), 3.14.2 (malicious code).
$bad = @()
# 1. Windows Script Host off (machine-wide)
$v = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name Enabled -ErrorAction SilentlyContinue).Enabled
if($null -eq $v -or $v -ne 0){ $bad += 'WSH Enabled != 0' }
# 2. mDNS off in DNS client
$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name EnableMDNS -ErrorAction SilentlyContinue).EnableMDNS
if($null -eq $v -or $v -ne 0){ $bad += 'EnableMDNS != 0' }
# 3. NetBIOS over TCP/IP disabled on every interface (NetbiosOptions 2 = disable)
$ifs = Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' -ErrorAction SilentlyContinue
foreach($i in $ifs){ $n = (Get-ItemProperty $i.PSPath -Name NetbiosOptions -ErrorAction SilentlyContinue).NetbiosOptions; if($null -eq $n -or $n -ne 2){ $bad += ('NetBIOS on ' + $i.PSChildName) } }
# 4. FIPS-validated cryptography mode (CMMC 3.13.11). Added 2026-09-21 after WS01 soak; effective at next reboot.
$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\FipsAlgorithmPolicy' -Name Enabled -ErrorAction SilentlyContinue).Enabled
if($null -eq $v -or $v -ne 1){ $bad += 'FIPS Enabled != 1' }
# 5. Network protection in BLOCK mode. Added 2026-09-24, see POAM-011. Enforcement is delivered by a POLICY value
#    because preference-level writes are silently refused while tamper protection is on. Checked on the EFFECTIVE
#    state, not the registry key - the key existing proves nothing about what Defender is actually doing.
$v = (Get-MpPreference -ErrorAction SilentlyContinue).EnableNetworkProtection
if($v -ne 1){ $bad += ('Network protection = ' + $v + ' (want 1 = block)') }
# 6. Fast Startup off (HiberbootEnabled 0). Added 2026-09-25. Both machines are shut down when not in use - that is
#    the intended posture, since a powered-off BitLocker volume holds no key in memory. Fast Startup makes a shutdown
#    a partial hibernation instead, which both weakens that and makes update installation at shutdown unreliable.
$v = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled
if($null -eq $v -or $v -ne 0){ $bad += 'HiberbootEnabled != 0 (Fast Startup on)' }
if($bad.Count){ Write-Output ('Platform hardening drift: ' + ($bad -join '; ')); exit 1 }
Write-Output 'Platform hardening compliant (WSH off, mDNS off, NetBIOS off on all interfaces, FIPS on, network protection blocking, Fast Startup off)'
exit 0
