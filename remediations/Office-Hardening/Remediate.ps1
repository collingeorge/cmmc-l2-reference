# REF-Office-Hardening - REMEDIATION (runs as SYSTEM via Intune remediation)
# 2026-09-21: also writes/checks the per-user PREFERENCE path (HKU<sid>SoftwareMicrosoftOffice16.0) because Microsoft 365 Apps for business (O365BusinessRetail) does not process Policies; preferences are re-asserted hourly.
# Writes the Office security policy values to HKLM and every loaded user hive, then re-verifies.

function Get-OfficeHardeningTargets {
    $script:t = @()
    function Add($key,$name,$value){ $script:t += @{ Key=$key; Name=$name; Value=[int]$value } }
    Add 'Common' 'VBAOff' 1
    Add 'Common\Security' 'AutomationSecurity' 3
    Add 'Common\TrustCenter' 'TrustBar' 1
    Add 'Common\Security\Trusted Locations' 'Allow User Locations' 0
    foreach($app in 'word','excel','powerpoint','access','visio','publisher','ms project'){
        Add "$app\Security" 'VBAWarnings' 4
        Add "$app\Security" 'blockcontentexecutionfrominternet' 1
        Add "$app\Security\Trusted Locations" 'AllLocationsDisabled' 1
    }
    foreach($app in 'word','excel','powerpoint','access','visio'){
        Add "$app\Security\Trusted Documents" 'DisableTrustedDocuments' 1
        Add "$app\Security\Trusted Documents" 'DisableNetworkTrustedDocuments' 1
    }
    foreach($app in 'word','excel','powerpoint'){
        Add "$app\Security\ProtectedView" 'DisableInternetFilesInPV' 0
        Add "$app\Security\ProtectedView" 'DisableUnsafeLocationsInPV' 0
        Add "$app\Security\ProtectedView" 'DisableAttachmentsInPV' 0
        Add "$app\Security\FileValidation" 'EnableOnLoad' 1
        Add "$app\Security\FileValidation" 'OpenInProtectedView' 0
    }
    Add 'excel\Security' 'xl4macrooff' 1
    Add 'excel\Security' 'excelbypassencryptedmacroscan' 0
    Add 'excel\Security\External Content' 'DisableDDEServerLaunch' 1
    Add 'excel\Security\External Content' 'DisableDDEServerLookup' 1
    foreach($fmt in 'XL4Workbooks','XL4Worksheets','XL4Macros','XL3Workbooks','XL3Worksheets','XL3Macros','XL2Worksheets','XL2Macros','XL95Workbooks'){ Add 'excel\Security\FileBlock' $fmt 2 }
    Add 'excel\Security\FileBlock' 'XL9597WorkbooksandTemplates' 5
    Add 'outlook\Security' 'AdminSecurityMode' 3
    Add 'outlook\Security' 'ShowOLEPackageObj' 0
    Add 'outlook\Security' 'EnableOneOffFormScripts' 0
    Add 'outlook\Security' 'SharedFolderScript' 0
    Add 'outlook\Security' 'ObjectModelGuard' 2
    return $script:t
}
function Get-OfficePolicyRoots {
    $roots = @('HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0')
    foreach($sid in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-\d+-\d+-\d+-\d+$' })){
        $roots += ('Registry::HKEY_USERS\' + $sid.PSChildName + '\Software\Policies\Microsoft\Office\16.0')
        # 2026-09-21: preference path too. Microsoft 365 Apps for business (O365BusinessRetail) ignores Policies; it honors preferences.
        $roots += ('Registry::HKEY_USERS\' + $sid.PSChildName + '\Software\Microsoft\Office\16.0')
    }
    return $roots
}

$targets = Get-OfficeHardeningTargets
$roots   = Get-OfficePolicyRoots
$written = 0; $failed = @()
foreach($root in $roots){
    foreach($x in $targets){
        $path = Join-Path $root $x.Key
        try {
            if(-not (Test-Path $path)){ New-Item -Path $path -Force | Out-Null }
            $cur = (Get-ItemProperty -Path $path -Name $x.Name -ErrorAction SilentlyContinue).($x.Name)
            if($null -eq $cur -or [int]$cur -ne $x.Value){ New-ItemProperty -Path $path -Name $x.Name -Value $x.Value -PropertyType DWord -Force | Out-Null; $written++ }
        } catch { $failed += ('{0}\{1}: {2}' -f $path,$x.Name,$_.Exception.Message) }
    }
}
# re-verify
$bad = 0
foreach($root in $roots){ foreach($x in $targets){ $cur = (Get-ItemProperty -Path (Join-Path $root $x.Key) -Name $x.Name -ErrorAction SilentlyContinue).($x.Name); if($null -eq $cur -or [int]$cur -ne $x.Value){ $bad++ } } }
Write-Output ("Office hardening: wrote {0} value(s) across {1} hive(s); {2} failure(s); {3} still non-compliant" -f $written,$roots.Count,$failed.Count,$bad)
if($failed.Count){ Write-Output (($failed | Select-Object -First 5) -join '; ') }
if($bad -gt 0 -or $failed.Count -gt 0){ exit 1 }
exit 0
