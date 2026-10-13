# REF-Defender-Signatures-Detect - Intune remediation DETECTION script.
# Exit 0 = healthy, exit 1 = remediate.
#
# WHY THIS EXISTS (POAM-034). Defender security intelligence stopped updating on both workstations
# on 25 September 2026. The cause is a Windows Update client defect at Service Locator Service
# registration - `Update-MpSignature` and `MpCmdRun.exe -SignatureUpdate` both return 0x80072efd,
# from BOTH the MicrosoftUpdateServer and MMPC sources, while the endpoint is demonstrably able to
# reach every update host. Firewall, WFP callout drivers, policy redirection, proxy, WPAD, address
# family and FIPS were each eliminated by direct experiment. It is a Microsoft support case.
#
# The exposure was closed by applying the signed standalone package by hand. THAT IS NOT A FIX -
# it is a one-time action on a fault that recurs every few days. This pair makes the workaround
# permanent and tenant-managed, so currency no longer depends on someone noticing an age counter.
#
# DESIGN NOTE, and it is the lesson of 28 September. This check must FAIL when it cannot read the
# signature age. PowerShell coerces $null to 0 in a numeric comparison, so `$null -le 2` is TRUE -
# an earlier version of the device verification check passed on exactly that and reported
# "age  day(s)" while Get-MpComputerStatus had returned nothing. Every limb below is explicit.

$ErrorActionPreference = 'Stop'
$maxAgeDays = 2

try {
    $mp = Get-MpComputerStatus -ErrorAction Stop
}
catch {
    Write-Output "REMEDIATE: Get-MpComputerStatus failed - $($_.Exception.Message)"
    exit 1
}

if ($null -eq $mp) {
    Write-Output 'REMEDIATE: Get-MpComputerStatus returned nothing. Signature age is UNKNOWN, not zero.'
    exit 1
}

$age = $mp.AntivirusSignatureAge
if ($null -eq $age) {
    Write-Output 'REMEDIATE: AntivirusSignatureAge is null. Unreadable, not current.'
    exit 1
}

if ($age -gt $maxAgeDays) {
    Write-Output ("REMEDIATE: signatures are {0} day(s) old (limit {1}). Version {2}." -f $age, $maxAgeDays, $mp.AntivirusSignatureVersion)
    exit 1
}

Write-Output ("OK: signatures {0} day(s) old, version {1}, engine {2}." -f $age, $mp.AntivirusSignatureVersion, $mp.AMEngineVersion)
exit 0
