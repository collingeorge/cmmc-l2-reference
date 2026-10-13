# REF-Consumer-Apps - REMEDIATION (SYSTEM). Removes consumer/phone/game inbox apps for all users and deprovisions them; disables wireless/consumer services.
# 2026-09-23: added removal of unauthorised cloud sync clients (Google Drive et al) via the vendor uninstaller.
# Residual local data stores are REPORTED, NOT DELETED. A SYSTEM script doing recursive deletes inside user profiles
# is one bad path away from destroying real data; residue is surfaced by detection and removed by a human who can
# see what is in it. Only OneDrive for Business is a permitted sync client - it is the one covered by our DLP,
# sensitivity labels and conditional access.
# 2026-09-30: MSTeams REMOVED from the list at the owner's direction (decision reversed). Microsoft 365 Apps deploys the
# Teams client and this control was removing it every morning while Intune reinstalled it. Teams client is now standard.
# 2026-09-28: MSTeams added at the owner's direction. Deprovisioning is the part that makes it
# stick - MSTeams is a default store package, reprovisioned on feature updates and for every new
# user profile. Removal alone lasts until the next update. The Teams SERVICE is untouched and
# remains reachable by browser.
$apps = 'Microsoft.YourPhone','Microsoft.GamingApp','Microsoft.XboxGameOverlay','Microsoft.XboxGamingOverlay','Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay','Microsoft.Xbox.TCUI','Microsoft.MicrosoftSolitaireCollection','Microsoft.BingNews','Microsoft.BingWeather','Microsoft.BingSearch','Clipchamp.Clipchamp','Microsoft.ZuneMusic','Microsoft.ZuneVideo','Microsoft.WindowsMaps','Microsoft.People','Microsoft.GetHelp','Microsoft.WindowsFeedbackHub','Microsoft.Todos','Microsoft.Windows.DevHome','Microsoft.PowerAutomateDesktop','Microsoft.WindowsCommunicationsApps','Microsoft.WindowsAlarms','Microsoft.WindowsSoundRecorder'
$removed = 0; $deprov = 0; $svcs = 0; $fail = @(); $startupRemoved = 0
foreach($p in (Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $apps -contains $_.Name })){ try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop; $removed++ } catch { $fail += $p.Name } }
foreach($p in (Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $apps -contains $_.DisplayName })){ try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null; $deprov++ } catch { $fail += ('prov:' + $p.DisplayName) } }
foreach($s in 'bthserv','BthAvctpSvc','BTAGService','WwanSvc','icssvc','WFDSConMgrSvc','SSDPSRV','upnphost','SharedAccess','lfsvc'){ $x = Get-Service $s -ErrorAction SilentlyContinue; if($x -and $x.StartType -ne 'Disabled'){ if($x.Status -eq 'Running'){ Stop-Service $s -Force -ErrorAction SilentlyContinue }; Set-Service $s -StartupType Disabled -ErrorAction SilentlyContinue; $svcs++ } }
# --- unauthorised cloud sync clients ---
$syncRemoved = 0; $residue = @()
foreach($proc in 'GoogleDriveFS','Dropbox','Box','MEGAsync','iCloudDrive'){ Get-Process -Name $proc -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue }
$banned = 'Google Drive','Dropbox','Box','iCloud','MEGAsync','pCloud','Amazon Drive','Sync.com','Nextcloud','Resilio Sync'
foreach($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'){
    foreach($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)){
        $i = Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue
        if(-not $i.DisplayName){ continue }
        $hit = $false; foreach($b in $banned){ if($i.DisplayName -like ('*' + $b + '*')){ $hit = $true } }
        if(-not $hit){ continue }
        $cmd = if($i.QuietUninstallString){ $i.QuietUninstallString } else { $i.UninstallString }
        if(-not $cmd){ $fail += ('nouninstall:' + $i.DisplayName); continue }
        try {
            if($cmd -match '^"([^"]+)"\s*(.*)$'){ $exe = $matches[1]; $arg = $matches[2] } else { $parts = $cmd -split ' ',2; $exe = $parts[0]; $arg = if($parts.Count -gt 1){ $parts[1] } else { '' } }
            if($exe -like '*msiexec*'){ $arg = ($arg -replace '/I','/X') + ' /quiet /norestart' }
            elseif($arg -notmatch 'silent|/S|quiet'){ $arg = ($arg + ' --silent --force_stop').Trim() }
            Start-Process -FilePath $exe -ArgumentList $arg -Wait -NoNewWindow -ErrorAction Stop
            $syncRemoved++
        } catch { $fail += ('uninstall:' + $i.DisplayName) }
    }
}
$userPaths = 'Google\DriveFS','Google\Drive File Stream','Dropbox','Box','MEGAsync','iCloudDrive'
foreach($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)){
    foreach($rel in $userPaths){
        $p = Join-Path $u.FullName ('AppData\Local\' + $rel)
        if(Test-Path $p){ $residue += $p }
    }
}
# --- unwanted vendor startup entries -------------------------------------------------
# 2026-09-28: Logitech Download Assistant. Two distinct Run values, both machine-scope, and
# vendor driver updates recreate them - hence a recurring removal rather than a one-off.
# LogiLDA.dll in System32 is deliberately NOT deleted: TrustedInstaller-owned, restored by
# Windows Update, and removing system files to suppress a startup entry trades a nuisance for
# a supportability problem. Deleting the Run value stops it executing, which is the requirement.
$startupValues = 'Logi Download Assistant','Logitech Download Assistant'
foreach($rk in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'){
    if(-not (Test-Path $rk)){ continue }
    foreach($v in $startupValues){
        $cur = (Get-ItemProperty $rk -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -eq $v }
        if(-not $cur){ continue }
        try { Remove-ItemProperty -Path $rk -Name $v -Force -ErrorAction Stop; $startupRemoved++ }
        catch { $fail += ('startup:' + $v) }
    }
}
# The Logitech Download Assistant program itself is REPORTED, not uninstalled. It ships with
# mouse and keyboard driver packages; a silent uninstall by a SYSTEM script risks removing
# device functionality the owner relies on. Surfaced for a human decision.
$vendorResidue = @()
foreach($p in 'C:\Program Files\LogiDownloadAssistant','C:\Program Files (x86)\LogiDownloadAssistant'){ if(Test-Path $p){ $vendorResidue += $p } }
Write-Output ("Consumer cleanup: removed {0} app(s), deprovisioned {1}, disabled {2} service(s), sync clients uninstalled {3}, startup entries removed {4}, residual stores needing manual review: {5}, vendor residue: {6}, failures: {7}" -f $removed,$deprov,$svcs,$syncRemoved,$startupRemoved,($residue -join ';'),($vendorResidue -join ';'),($fail -join ','))
if($fail.Count){ exit 1 }
exit 0
