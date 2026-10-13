# REF-CodexRemoved-Remediate - Intune remediation REMEDIATION. Runs as SYSTEM. (v1, 12 Oct 2026)
# Removes the OpenAI Codex desktop app for all users and de-provisions it; DISABLES (does not delete) its sandbox
# accounts CodexSandboxOffline / CodexSandboxOnline. Touches nothing else. See the detection script for why.

$failed = @(); $done = @()
foreach ($p in @(Get-AppxPackage -AllUsers -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue)) {
    try { Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop; $done += "removed $($p.PackageFullName)" }
    catch { $failed += "remove $($p.PackageFullName): $($_.Exception.Message)" }
}
foreach ($p in @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'OpenAI.Codex')) {
    try { Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null; $done += "de-provisioned $($p.PackageName)" }
    catch { $failed += "de-provision $($p.PackageName): $($_.Exception.Message)" }
}
foreach ($u in @(Get-LocalUser -Name 'CodexSandbox*' -ErrorAction SilentlyContinue | Where-Object Enabled)) {
    try { Disable-LocalUser -Name $u.Name -ErrorAction Stop; $done += "disabled $($u.Name)" }
    catch { $failed += "disable $($u.Name): $($_.Exception.Message)" }
}
if ($failed.Count) { Write-Output ('done: ' + ($done -join '; ') + ' | FAILED: ' + ($failed -join '; ')); exit 1 }
Write-Output ('Codex removed: ' + $(if ($done.Count) { $done -join '; ' } else { 'nothing to do' })); exit 0
