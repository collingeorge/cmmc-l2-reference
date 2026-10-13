# REF-Consumer-Apps - DETECTION (SYSTEM). Consumer/phone/game inbox apps must be absent for all users. CMMC 3.4.6.
# 2026-09-23: added unauthorised cloud sync clients (Google Drive et al). Only OneDrive for Business is permitted,
# because it is the only sync path covered by our DLP, labels and conditional access.
# 2026-09-30: MSTeams REMOVED from the list at the owner's direction (decision reversed). Microsoft 365 Apps deploys the
# Teams client and this control was removing it every morning while Intune reinstalled it. Teams client is now standard.
# 2026-09-28: MSTeams added. Removed at the owner's direction; the Teams SERVICE remains in the
# tenant and is reachable by browser, so this is client removal, not a workload decision.
# Deprovisioning matters more than removal here - MSTeams is a default store package and is
# reprovisioned on feature updates and for every new user profile unless it is deprovisioned.
$apps = 'Microsoft.YourPhone','Microsoft.GamingApp','Microsoft.XboxGameOverlay','Microsoft.XboxGamingOverlay','Microsoft.XboxIdentityProvider','Microsoft.XboxSpeechToTextOverlay','Microsoft.Xbox.TCUI','Microsoft.MicrosoftSolitaireCollection','Microsoft.BingNews','Microsoft.BingWeather','Microsoft.BingSearch','Clipchamp.Clipchamp','Microsoft.ZuneMusic','Microsoft.ZuneVideo','Microsoft.WindowsMaps','Microsoft.People','Microsoft.GetHelp','Microsoft.WindowsFeedbackHub','Microsoft.Todos','Microsoft.Windows.DevHome','Microsoft.PowerAutomateDesktop','Microsoft.WindowsCommunicationsApps','Microsoft.WindowsAlarms','Microsoft.WindowsSoundRecorder'
$present = @(Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $apps -contains $_.Name } | Select-Object -ExpandProperty Name -Unique)
$prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object { $apps -contains $_.DisplayName } | Select-Object -ExpandProperty DisplayName -Unique)
$svc = @()
foreach($s in 'bthserv','BthAvctpSvc','BTAGService','WwanSvc','icssvc','WFDSConMgrSvc','SSDPSRV','upnphost','SharedAccess','lfsvc'){ $x = Get-Service $s -ErrorAction SilentlyContinue; if($x -and $x.StartType -ne 'Disabled'){ $svc += $s } }
# --- unauthorised cloud sync clients ---
$sync = @()
$banned = 'Google Drive','Dropbox','Box','iCloud','MEGAsync','pCloud','Amazon Drive','Sync.com','Nextcloud','Resilio Sync'
foreach($root in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'){
    foreach($k in (Get-ChildItem $root -ErrorAction SilentlyContinue)){
        $d = (Get-ItemProperty $k.PSPath -ErrorAction SilentlyContinue).DisplayName
        if($d){ foreach($b in $banned){ if($d -like ('*' + $b + '*')){ $sync += ('installed:' + $d) } } }
    }
}
$machinePaths = 'C:\Program Files\Google\Drive File Stream','C:\Program Files\Dropbox','C:\Program Files\Box\Box','C:\Program Files (x86)\Google\Drive File Stream','C:\Program Files\Common Files\Apple\Internet Services'
foreach($p in $machinePaths){ if(Test-Path $p){ $sync += ('path:' + $p) } }
$userPaths = 'Google\DriveFS','Google\Drive File Stream','Dropbox','Box','MEGAsync','iCloudDrive'
foreach($u in (Get-ChildItem 'C:\Users' -Directory -ErrorAction SilentlyContinue)){
    foreach($rel in $userPaths){
        $p = Join-Path $u.FullName ('AppData\Local\' + $rel)
        if(Test-Path $p){ $sync += ('userdata:' + $u.Name + '\' + $rel) }
    }
}
foreach($proc in 'GoogleDriveFS','Dropbox','Box','MEGAsync','iCloudDrive'){ if(Get-Process -Name $proc -ErrorAction SilentlyContinue){ $sync += ('running:' + $proc) } }
$sync = @($sync | Select-Object -Unique)
# --- unwanted vendor startup entries -------------------------------------------------
# 2026-09-28: Logitech Download Assistant. Two separate Run values, both machine-scope, and
# vendor driver updates recreate them - which is why this is a recurring check rather than a
# one-time deletion. The LogiLDA.dll in System32 is NOT deleted: it is TrustedInstaller-owned,
# Windows Update restores it, and removing system files to suppress a startup entry trades a
# small nuisance for a supportability problem. Removing the Run values stops it executing,
# which is the actual requirement.
$startupValues = 'Logi Download Assistant','Logitech Download Assistant'
$runKeys = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
$startup = @()
foreach($rk in $runKeys){
    if(-not (Test-Path $rk)){ continue }
    $props = (Get-ItemProperty $rk -ErrorAction SilentlyContinue).PSObject.Properties
    foreach($v in $startupValues){ if($props | Where-Object { $_.Name -eq $v }){ $startup += ($rk.Split('\')[-2] + ':' + $v) } }
}
$startup = @($startup | Select-Object -Unique)
if($present.Count -or $prov.Count -or $svc.Count -or $sync.Count -or $startup.Count){ Write-Output ('Consumer drift: installed=' + ($present -join ',') + ' provisioned=' + ($prov -join ',') + ' services=' + ($svc -join ',') + ' sync=' + ($sync -join ',') + ' startup=' + ($startup -join ',')); exit 1 }
Write-Output 'Consumer apps absent, wireless/consumer services disabled, no unauthorised sync clients, no unwanted startup entries'
exit 0
