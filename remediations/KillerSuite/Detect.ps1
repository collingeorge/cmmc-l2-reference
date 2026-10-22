# REF-KillerSuite - DETECTION (SYSTEM). v1, 17 Oct 2026. CMMC 3.4.6, 3.4.8.
# Security Officer, 17 Oct 2026: "can we uninstall the driver for killer network then just use a generic one?" / "finish the
# killer driver removal". Measured on WS02 (REF-Check-NetworkDriver.ps1, 17 Oct): the adapter (Killer E2400,
# PCI\VEN_1969&DEV_E0A1) runs the plain WHQL miniport e2xw10x64 9.0.0.50 (oem5.inf); ON TOP of it the Killer suite arrived
# as an extension INF (KillerNetwork_Install 3.1423.712.2, oem0.inf) plus a software component ("Killer Networking
# Software", SWC\VID_1A56&PID_1000&SID_0002) carrying four services: Killer Network Service (running), KNDBWM (running),
# KAPSService, Killer Analytics Service (disabled since v8 of Consumer-Apps). Killer Control Center was removed 16 Oct.
# The miniport itself is KEPT: it is the adapter's driver (Windows' own copy, 9.0.0.42 from 2015, is older; and Windows
# Update re-offers 9.0.0.50 because drivers come through Windows Update - a swap would be undone and flap the network).
# Exit 1 = any Killer suite piece present (service not disabled, suite driver package, software component). WS01: nothing.
$ErrorActionPreference = 'SilentlyContinue'
$svc = 'Killer Network Service', 'KNDBWM', 'KAPSService', 'Killer Analytics Service'
$nic = @(Get-PnpDevice -Class Net | Where-Object { $_.InstanceId -match '^PCI\\VEN_1969&' })
$nicInf = @($nic | ForEach-Object { (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_DriverInfPath).Data })
$drift = @()
foreach ($s in $svc) { $x = Get-Service -Name $s; if ($x -and $x.StartType -ne 'Disabled') { $drift += "service:$s=$($x.StartType)/$($x.Status)" } }
# v2 (17 Oct 2026): v1 found suite packages by provider "Rivet Networks" only and missed the extension INF oem0.inf
# (KillerNetwork_Install 3.1423.712.2, published after Intel bought Killer). Suite packages are now: every extension INF
# attached to the Killer adapter, plus any package whose provider or original name says Rivet/Killer - never the adapter's
# own driver INF.
$ext = @($nic | ForEach-Object { @((Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName DEVPKEY_Device_ExtendedConfigurationIds).Data) } | ForEach-Object { ($_ -split ':')[0] } | Where-Object { $_ -match '^oem\d+\.inf$' })
$enum = (pnputil /enum-drivers 2>&1) -join "`n"; $suite = @($ext)
foreach ($blk in ($enum -split "(?m)^\s*$")) {
    $pub = if ($blk -match '(?im)^\s*Published Name:\s*(\S+)') { $Matches[1] } else { continue }
    if ($blk -match '(?im)^\s*(Provider Name|Original Name):\s*.*(rivet|killer)') { $suite += $pub }
}
foreach ($p in ($suite | Where-Object { $nicInf -notcontains $_ } | Sort-Object -Unique)) { if ($enum -match "(?im)^\s*Published Name:\s*$([regex]::Escape($p))\s*$") { $drift += "package:$p" } }
# v2 (17 Oct 2026), owner: "I need a generic backup that supersedes this". Windows ships its own Microsoft-published driver
# for this chip (C:\Windows\INF\e2xw10x64.inf, Provider MSFT, 9.0.0.42). When it is present, the adapter must run on it,
# not on Rivet's package: an adapter whose driver provider is not Microsoft is drift.
$inbox = Test-Path "$env:SystemRoot\INF\e2xw10x64.inf"
if ($inbox -and (Select-String -Path "$env:SystemRoot\INF\e2xw10x64.inf" -Pattern '^\s*Provider\s*=\s*%MSFT%' -Quiet)) {
    foreach ($n in $nic) { $prov = (Get-PnpDeviceProperty -InstanceId $n.InstanceId -KeyName DEVPKEY_Device_DriverProvider).Data; if ($prov -ne 'Microsoft') { $drift += "adapter driver provider '$prov' (Microsoft in-box driver available)" } }
}
# v4 (17 Oct 2026), owner: "change the name or the driver get rid of this" - the chip keeps its only driver (Microsoft's), but
# it is no longer shown as "Killer": Device Manager name and adapter description = 'Onboard Ethernet (Microsoft driver)'.
# And "I disable the killer ethernet controller I lose internet and nothing comes back on": a disabled adapter is drift.
$WantName = 'Onboard Ethernet (Microsoft driver)'
foreach ($n in $nic) {
    if ($n.Problem -eq 'CM_PROB_DISABLED' -or $n.Status -eq 'Error') { $drift += 'adapter DISABLED (only network adapter)' }
    $fn = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\$($n.InstanceId)").FriendlyName
    $drvKey = (Get-PnpDeviceProperty -InstanceId $n.InstanceId -KeyName DEVPKEY_Device_Driver).Data
    $dd = if ($drvKey) { (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Class\$drvKey").DriverDesc }
    if ($fn -ne $WantName -or $dd -ne $WantName) { $drift += "adapter name '$fn' / '$dd'" }
}
foreach ($d in Get-PnpDevice -Class SoftwareComponent | Where-Object { $_.FriendlyName -match '(?i)killer' -and $_.Status -eq 'OK' }) { $drift += "component:$($d.FriendlyName)" }
if ($drift.Count) { Write-Output ('Killer suite present: ' + ($drift -join '; ')); exit 1 }
Write-Output "No Killer suite. Adapter driver kept: $(if ($nicInf.Count) { $nicInf -join ',' } else { 'no Killer adapter on this machine' })"
exit 0
