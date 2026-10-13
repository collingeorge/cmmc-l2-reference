# REF-UserExperience-Remediate - Intune remediation REMEDIATION script.
# MUST be deployed with "Run this script using the logged-on credentials" = Yes (these are HKCU values).
#
# Sets dark mode (Windows and apps) and a left-aligned taskbar for the signed-in user. It writes
# three HKCU values and nothing else: no services, no restarts of Explorer, nothing machine-wide.
# The taskbar moves at once; dark mode is picked up by windows as they open, fully at next sign-in.

$want = @(
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'SystemUsesLightTheme'; Value = 0 }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize'; Name = 'AppsUseLightTheme';    Value = 0 }
    @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced';  Name = 'TaskbarAl';            Value = 0 }
)

$failed = @()
foreach ($w in $want) {
    try {
        if (-not (Test-Path $w.Path)) { New-Item -Path $w.Path -Force -ErrorAction Stop | Out-Null }
        Set-ItemProperty -Path $w.Path -Name $w.Name -Value $w.Value -Type DWord -ErrorAction Stop
    } catch { $failed += "$($w.Name): $($_.Exception.Message)" }
}

# Tell Explorer the settings changed. Without this the values sit in the registry and the screen
# does not change until the next sign-in (seen on WS01, 30 Sep 2026). This is the same
# notification the Settings app sends; it restarts nothing and closes nothing.
try {
    Add-Type -Namespace SanctirUX -Name Native -MemberDefinition '[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern bool SendNotifyMessage(IntPtr hWnd, uint Msg, UIntPtr wParam, string lParam);'
    $HWND_BROADCAST = [IntPtr]0xffff; $WM_SETTINGCHANGE = 0x001A
    foreach ($area in 'ImmersiveColorSet', 'TraySettings', 'WindowsThemeElement') { [void][SanctirUX.Native]::SendNotifyMessage($HWND_BROADCAST, $WM_SETTINGCHANGE, [UIntPtr]::Zero, $area) }
} catch { Write-Output "settings written; refresh notification failed ($($_.Exception.Message)) - applies at next sign-in" }

if ($failed.Count) { Write-Output ('could not set: ' + ($failed -join '; ')); exit 1 }
Write-Output 'Set: dark mode (Windows and apps), taskbar left.'
exit 0
