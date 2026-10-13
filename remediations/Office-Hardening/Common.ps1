# REF-Office-Hardening - shared definitions (inlined into Detect and Remediate; kept here as the reference copy)
# Registry policy values for Microsoft 365 Apps (Office 16.0). Sources: Office ADMX (office16/word16/excel16/ppt16/
# outlk16/access16/visio16/pub16/proj16), Microsoft 365 Apps security baseline, Excel XLM control (xl4macrooff).
# Written to HKLM\Software\Policies\Microsoft\Office\16.0 and to every loaded user hive's Software\Policies\...\16.0.
# CMMC 3.14.2 / 3.14.4 / 3.13.13 (malicious code protection, mobile code) and 3.4.6 (least functionality).

function Get-OfficeHardeningTargets {
    $t = @()
    function Add($key,$name,$value){ $script:t += @{ Key=$key; Name=$name; Value=[int]$value } }

    # --- Microsoft Office (Security Settings) ---
    Add 'Common'                                   'VBAOff'                 1   # Disable VBA for Office applications
    Add 'Common\Security'                          'AutomationSecurity'     3   # Automation Security: disable macros by default
    Add 'Common\TrustCenter'                       'TrustBar'               1   # Disable all Trust Bar notifications for security issues
    Add 'Common\Security\Trusted Locations'        'Allow User Locations'   0   # Allow mix of policy and user locations: disabled

    # --- Per application ---
    foreach($app in 'word','excel','powerpoint','access','visio','publisher','ms project'){
        Add "$app\Security"                        'VBAWarnings'                        4   # Disable all without notification
        Add "$app\Security"                        'blockcontentexecutionfrominternet'  1   # Block macros from the Internet
        Add "$app\Security\Trusted Locations"      'AllLocationsDisabled'               1   # Disable all Trusted Locations
    }
    foreach($app in 'word','excel','powerpoint','access','visio'){
        Add "$app\Security\Trusted Documents"      'DisableTrustedDocuments'            1
        Add "$app\Security\Trusted Documents"      'DisableNetworkTrustedDocuments'     1
    }

    # --- Protected View + file validation (Word, Excel, PowerPoint) ---
    foreach($app in 'word','excel','powerpoint'){
        Add "$app\Security\ProtectedView"          'DisableInternetFilesInPV'    0   # 0 = Protected View ON for Internet files
        Add "$app\Security\ProtectedView"          'DisableUnsafeLocationsInPV'  0   # 0 = Protected View ON for unsafe locations
        Add "$app\Security\ProtectedView"          'DisableAttachmentsInPV'      0   # 0 = Protected View ON for Outlook attachments
        Add "$app\Security\FileValidation"         'EnableOnLoad'                1   # File validation on
        Add "$app\Security\FileValidation"         'OpenInProtectedView'         0   # If validation fails: Block
    }

    # --- Excel specifics ---
    Add 'excel\Security'                           'xl4macrooff'                     1   # Prevent Excel from running XLM macros
    Add 'excel\Security'                           'excelbypassencryptedmacroscan'   0   # Scan encrypted macros
    Add 'excel\Security\External Content'          'DisableDDEServerLaunch'          1
    Add 'excel\Security\External Content'          'DisableDDEServerLookup'          1
    foreach($fmt in 'XL4Workbooks','XL4Worksheets','XL4Macros','XL3Workbooks','XL3Worksheets','XL3Macros','XL2Worksheets','XL2Macros','XL95Workbooks'){
        Add 'excel\Security\FileBlock'             $fmt                              2   # Block open and save
    }
    Add 'excel\Security\FileBlock'                 'XL9597WorkbooksandTemplates'     5   # Open in Protected View

    # --- Outlook ---
    Add 'outlook\Security'                         'AdminSecurityMode'       3   # Use Outlook Security Group Policy (required for the rest)
    Add 'outlook\Security'                         'ShowOLEPackageObj'       0   # Block OLE package activation
    Add 'outlook\Security'                         'EnableOneOffFormScripts' 0   # No scripts in one-off forms
    Add 'outlook\Security'                         'SharedFolderScript'      0   # No scripts in shared folders
    Add 'outlook\Security'                         'ObjectModelGuard'        2   # Programmatic access: automatically deny

    return $t
}

function Get-OfficePolicyRoots {
    $roots = @('HKLM:\SOFTWARE\Policies\Microsoft\Office\16.0')
    foreach($sid in (Get-ChildItem 'Registry::HKEY_USERS' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-\d+-\d+-\d+-\d+$' })){
        $roots += ('Registry::HKEY_USERS\' + $sid.PSChildName + '\Software\Policies\Microsoft\Office\16.0')
    }
    return $roots
}
