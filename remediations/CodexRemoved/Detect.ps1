# REF-CodexRemoved-Detect - Intune remediation DETECTION. Runs as SYSTEM. (v1, 12 Oct 2026)
# Exit 0 = the OpenAI Codex desktop app is not installed or provisioned, and its sandbox accounts are disabled.
# Exit 1 = remediate.
#
# WHY. RA-025 finding 3 (12 Oct 2026): the Codex app (MSIX OpenAI.Codex) created two enabled local password accounts,
# CodexSandboxOffline and CodexSandboxOnline, on WS01 and WS02 on 2 Oct 2026 for its sandbox; no tenant policy
# governed them. Security Officer, 12 Oct 2026: "Remove". Held from the tenant so WS02 is cleaned on first boot and
# a reinstall cannot bring the accounts back. Accounts are DISABLED, not deleted (disable, never delete).

$found = @()
$pkg = @(Get-AppxPackage -AllUsers -Name 'OpenAI.Codex' -ErrorAction SilentlyContinue)
if ($pkg.Count) { $found += "installed: $(($pkg | ForEach-Object { $_.PackageFullName }) -join ', ')" }
$prov = @(Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object DisplayName -eq 'OpenAI.Codex')
if ($prov.Count) { $found += 'provisioned for new users' }
foreach ($u in @(Get-LocalUser -Name 'CodexSandbox*' -ErrorAction SilentlyContinue | Where-Object Enabled)) { $found += "account enabled: $($u.Name)" }
if ($found.Count) { Write-Output ('Codex present: ' + ($found -join '; ')); exit 1 }
Write-Output 'OK: Codex not installed; sandbox accounts absent or disabled.'; exit 0
