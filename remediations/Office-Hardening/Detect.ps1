# REF-Office-Hardening - DETECTION (runs as SYSTEM via Intune remediation)
# 2026-09-21: also writes/checks the per-user PREFERENCE path (HKU<sid>SoftwareMicrosoftOffice16.0) because Microsoft 365 Apps for business (O365BusinessRetail) does not process Policies; preferences are re-asserted hourly.
# Exit 1 if any Office security policy value is missing or drifted in HKLM or any loaded user hive.

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
$bad = @()
foreach($root in $roots){
    foreach($x in $targets){
        $path = Join-Path $root $x.Key
        $cur = (Get-ItemProperty -Path $path -Name $x.Name -ErrorAction SilentlyContinue).($x.Name)
        if($null -eq $cur -or [int]$cur -ne $x.Value){ $bad += ('{0}\{1}={2} (is {3})' -f ($root -replace '^Registry::HKEY_USERS\\','HKU:' -replace '^HKLM:.*','HKLM'),$x.Name,$x.Value,$(if($null -eq $cur){'missing'}else{$cur})) }
    }
}
if($bad.Count -gt 0){ Write-Output ("{0} Office policy value(s) missing/drifted across {1} hive(s): {2}" -f $bad.Count,$roots.Count,(($bad | Select-Object -First 8) -join '; ')); exit 1 }
Write-Output ("Office hardening compliant: {0} values x {1} hive(s)" -f $targets.Count,$roots.Count)
exit 0
