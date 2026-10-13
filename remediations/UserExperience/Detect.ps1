# REF-UserExperience-Detect - Intune remediation DETECTION script.
# MUST be deployed with "Run this script using the logged-on credentials" = Yes (these are HKCU values).
# Exit 0 = the signed-in user's desktop matches the Sanctir standard. Exit 1 = it does not; remediate.
#
# Only the two settings Windows has no policy for live here (Copilot, 30 Sep 2026: "not supported
# by policy" for both). Widgets-off and the taskbar search box are real policies and are delivered
# by the Settings Catalog instead - they do not belong in a script.

$want = @(
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'SystemUsesLightTheme'; Value = 0 }   # Windows dark mode
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'AppsUseLightTheme';    Value = 0 }   # apps dark mode
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';  Name = 'TaskbarAl';            Value = 0 }   # taskbar left
)

$drift = foreach ($w in $want) {
    $cur = (Get-ItemProperty -Path $w.Path -Name $w.Name -ErrorAction SilentlyContinue).($w.Name)
    if ($cur -ne $w.Value) { "$($w.Name)=$cur (want $($w.Value))" }
}

if (-not $drift) { Write-Output 'OK: dark mode and left taskbar set.'; exit 0 }
Write-Output ('DRIFT: ' + ($drift -join '; '))
exit 1
