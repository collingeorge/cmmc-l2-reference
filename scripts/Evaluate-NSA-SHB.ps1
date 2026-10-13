# REF-Eval-NSA-SHB.ps1 - 12 Oct 2026. READ-ONLY. Scores this machine against the NSA Windows Secure Host Baseline
# compliance checks WITHOUT running NSA's code.
#
# WHY. Security Officer, 12 Oct 2026: "run these scripts from the Windows Secure Host Baseline to ensure we are meeting
# even NSA security protocols." The NSA repository (github.com/nsacyber/Windows-Secure-Host-Baseline) is ARCHIVED (13 Jun
# 2023) and targets Windows 10 1607 / Server 2016. Its apply script writes LOCAL Group Policy via LGPO (would fight the
# tenant baseline and the drift guards) and its Test-Compliance module EXECUTES PowerShell embedded in the downloaded
# .audit files as administrator (27 AUDIT_POWERSHELL items). Neither is run here.
# WHAT. The declarative checks were read as data from NSA's Windows10.audit (header: "DISA STIG: Windows 10 STIG version
# 1 release 7") and WindowsFirewall.audit ("Windows Firewall STIG Version 1 Release 5") on 12 Oct 2026 and are embedded
# below (US Government work). Each is evaluated against the EFFECTIVE state: the registry path NSA names, then the Intune
# PolicyManager store, and for the firewall the active firewall profile. Results: PASS / FAIL / DEVIATION (a recorded
# Sanctir decision that is stricter or deliberately different) / N/A (obsolete on Windows 11 or domain/DoD-only).
# The remaining NSA items (user rights, audit subcategories, password/lockout policy, file permissions, PowerShell
# checks) are the same STIG content that REF-Eval-STIG.ps1 already scores against the CURRENT Windows 11 STIG.
[CmdletBinding()]
param([string]$ProjectRoot = (Split-Path -Parent $PSScriptRoot))   # evidence goes under <repo>\Evidence\<date>
$ErrorActionPreference = 'Stop'

# id | value_type | value_data | reg_key | reg_item | reg_option | check_type   (REGISTRY_SETTING unless key MUST_NOT_EXIST)
$win = @'
WN10-00-000005|POLICY_TEXT|Windows 10 Enterprise|HKLM\Software\Microsoft\Windows NT\CurrentVersion|ProductName||
WN10-00-000040|POLICY_TEXT|1511|HKLM\Software\Microsoft\Windows NT\CurrentVersion|ReleaseID||CHECK_GREATER_THAN_OR_EQUAL
WN10-00-000100|MUST_NOT_EXIST||HKLM\SOFTWARE\Microsoft\Inetstp\Components|||
WN10-00-000150|POLICY_DWORD|0|HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel|DisableExceptionChainValidation||
WN10-00-000155|MUST_NOT_EXIST||HKLM\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine|||
WN10-00-000160|MUST_NOT_EXIST||HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10|||
WN10-AU-000500|POLICY_DWORD|32768|HKLM\Software\Policies\Microsoft\Windows\EventLog\Application|MaxSize|CAN_NOT_BE_NULL|CHECK_GREATER_THAN_OR_EQUAL
WN10-AU-000505|POLICY_DWORD|196608|HKLM\Software\Policies\Microsoft\Windows\EventLog\Security|MaxSize|CAN_NOT_BE_NULL|CHECK_GREATER_THAN_OR_EQUAL
WN10-AU-000510|POLICY_DWORD|32768|HKLM\Software\Policies\Microsoft\Windows\EventLog\System|MaxSize|CAN_NOT_BE_NULL|CHECK_GREATER_THAN_OR_EQUAL
WN10-CC-000005|POLICY_DWORD|1|HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization|NoLockScreenCamera||
WN10-CC-000010|POLICY_DWORD|1|HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization|NoLockScreenSlideshow||
WN10-CC-000015|POLICY_TEXT|0|HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon|AutoAdminLogon|CAN_BE_NULL|
WN10-CC-000020|POLICY_DWORD|2|HKLM\System\CurrentControlSet\Services\Tcpip6\Parameters|DisableIpSourceRouting||
WN10-CC-000025|POLICY_DWORD|2|HKLM\System\CurrentControlSet\Services\Tcpip\Parameters|DisableIpSourceRouting||
WN10-CC-000030|POLICY_DWORD|0|HKLM\System\CurrentControlSet\Services\Tcpip\Parameters|EnableICMPRedirect||
WN10-CC-000035|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\Netbt\Parameters|NoNameReleaseOnDemand||
WN10-CC-000040|POLICY_DWORD|0|HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation|AllowInsecureGuestAuth||
HardenedUNC-SYSVOL|POLICY_TEXT|RequireMutualAuthentication=1,RequireIntegrity=1|HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths|\\*\SYSVOL||
HardenedUNC-NETLOGON|POLICY_TEXT|RequireMutualAuthentication=1,RequireIntegrity=1|HKLM\Software\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths|\\*\NETLOGON||
WN10-CC-000055|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy|fMinimizeConnections|CAN_BE_NULL|
WN10-CC-000060|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\WcmSvc\GroupPolicy|fBlockNonDomain||
WN10-CC-000065|POLICY_DWORD|0|HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config|AutoConnectAllowedOEM||
WN10-CC-000066|POLICY_DWORD|1|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit|ProcessCreationIncludeCmdLine_Enabled||
WN10-CC-000085|POLICY_DWORD|1,3,8|HKLM\System\CurrentControlSet\Policies\EarlyLaunch|DriverLoadPolicy|CAN_BE_NULL|
WN10-CC-000090|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}|NoGPOListChanges||
WN10-CC-000095|POLICY_DWORD|0|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\system|DisableBkGndGroupPolicy|CAN_BE_NULL|
WN10-CC-000100|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Printers|DisableWebPnPDownload||
WN10-CC-000105|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoWebServices||
WN10-CC-000110|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Printers|DisableHTTPPrinting||
WN10-CC-000115|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|DevicePKInitEnabled|CAN_BE_NULL|
WN10-CC-000120|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\System|DontDisplayNetworkSelectionUI||
WN10-CC-000130|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\System|EnumerateLocalUsers||
WN10-CC-000135|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\System|AllowDomainPINLogon||
WN10-CC-000140|POLICY_TEXT|1000000000000|HKLM\SOFTWARE\Policies\Microsoft\Windows NT\MitigationOptions|MitigationOptions_FontBocking||
WN10-CC-000145|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|DCSettingIndex||
WN10-CC-000150|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51|ACSettingIndex||
WN10-CC-000155|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services|fAllowToGetHelp||
WN10-CC-000165|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Rpc|RestrictRemoteClients||
WN10-CC-000170|POLICY_DWORD|1|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|MSAOptional||
WN10-CC-000175|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\AppCompat|DisableInventory||
WN10-CC-000180|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\Explorer|NoAutoplayfornonVolume||
WN10-CC-000185|POLICY_DWORD|1|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer|NoAutorun||
WN10-CC-000190|POLICY_DWORD|255|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer|NoDriveTypeAutorun||
WN10-CC-000195|POLICY_DWORD|1|HKLM\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures|EnhancedAntiSpoofing||
WN10-CC-000200|POLICY_DWORD|0|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI|EnumerateAdministrators||
WN10-CC-000205|POLICY_DWORD|0,1|HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection|AllowTelemetry||
WN10-CC-000206|POLICY_DWORD|0,1,2|HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization|DODownloadMode|CAN_BE_NULL|
WN10-CC-000210|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\System|EnableSmartScreen||
WN10-CC-000215|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Explorer|NoDataExecutionPrevention|CAN_BE_NULL|
WN10-CC-000220|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Explorer|NoHeapTerminationOnCorruption|CAN_BE_NULL|
WN10-CC-000225|POLICY_DWORD|0|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer|PreXPSP2ShellProtocolBehavior|CAN_BE_NULL|
WN10-CC-000230|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter|PreventOverride||
WN10-CC-000235|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter|PreventOverrideAppRepUnknown||
WN10-CC-000240|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main|AllowInPrivate||
WN10-CC-000245|POLICY_TEXT|no|HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main|FormSuggest Passwords||
WN10-CC-000250|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\MicrosoftEdge\PhishingFilter|EnabledV9||
WN10-CC-000255|POLICY_DWORD|1|HKLM\SOFTWARE\Policies\Microsoft\PassportForWork|RequireSecurityDevice||
WN10-CC-000260|POLICY_DWORD|6|HKLM\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity|MinimumPINLength||CHECK_GREATER_THAN_OR_EQUAL
WN10-CC-000265|POLICY_DWORD|1|HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive|DisableFileSyncNGSC||
WN10-CC-000270|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services|DisablePasswordSaving||
WN10-CC-000275|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services|fDisableCdm||
WN10-CC-000280|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services|fPromptForPassword||
WN10-CC-000285|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services|fEncryptRPCTraffic||
WN10-CC-000290|POLICY_DWORD|3|HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services|MinEncryptionLevel||
WN10-CC-000295|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds|DisableEnclosureDownload||
WN10-CC-000300|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Internet Explorer\Feeds|AllowBasicAuthInClear|CAN_BE_NULL|
WN10-CC-000305|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Windows Search|AllowIndexingEncryptedStoresOrItems||
WN10-CC-000310|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Installer|EnableUserControl||
WN10-CC-000315|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Installer|AlwaysInstallElevated||
WN10-CC-000320|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\Installer|SafeForScripting|CAN_BE_NULL|
WN10-CC-000325|POLICY_DWORD|1|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|DisableAutomaticRestartSignOn||
WN10-CC-000326|POLICY_DWORD|1|HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging|EnableScriptBlockLogging||
WN10-CC-000330|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\WinRM\client|AllowBasic||
WN10-CC-000335|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\WinRM\Client|AllowUnencryptedTraffic||
WN10-CC-000340|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\WinRM\Client|AllowDigest||
WN10-CC-000345|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\WinRM\Service|AllowBasic||
WN10-CC-000350|POLICY_DWORD|0|HKLM\Software\Policies\Microsoft\Windows\WinRM\Service|AllowUnencryptedTraffic||
WN10-CC-000355|POLICY_DWORD|1|HKLM\Software\Policies\Microsoft\Windows\WinRM\Service|DisableRunAs||
WN10-RG-000010|POLICY_DWORD|0|HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System|LocalAccountTokenFilterPolicy|CAN_BE_NULL|
WN10-SO-000015|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Control\Lsa|LimitBlankPasswordUse||
WN10-SO-000030|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Control\Lsa|scenoapplylegacyauditpolicy|CAN_NOT_BE_NULL|
WN10-SO-000035|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\Netlogon\Parameters|RequireSignOrSeal||
WN10-SO-000040|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\Netlogon\Parameters|SealSecureChannel||
WN10-SO-000045|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\Netlogon\Parameters|SignSecureChannel||
WN10-SO-000050|POLICY_DWORD|0|HKLM\System\CurrentControlSet\Services\Netlogon\Parameters|DisablePasswordChange||
WN10-SO-000055|POLICY_DWORD|1..30|HKLM\System\CurrentControlSet\Services\Netlogon\Parameters|MaximumPasswordAge||
WN10-SO-000060|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\Netlogon\Parameters|RequireStrongKey||
WN10-SO-000070|POLICY_DWORD|1..900|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|InactivityTimeoutSecs||
WN10-SO-000075|POLICY_MULTI_TEXT|You are accessing a U.S. Government (USG) Information System|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|LegalNoticeText|CAN_NOT_BE_NULL|
WN10-SO-000080|POLICY_MULTI_TEXT|DoD Notice and Consent Banner|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|LegalNoticeCaption|CAN_NOT_BE_NULL|
WN10-SO-000085|POLICY_DWORD|1..10|HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon|cachedlogonscount|CAN_NOT_BE_NULL|
WN10-SO-000090|POLICY_DWORD|0|HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon|ForceUnlockLogon|CAN_NOT_BE_NULL|
WN10-SO-000095|POLICY_TEXT|1,2|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon|SCRemoveOption||
WN10-SO-000100|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|RequireSecuritySignature||
WN10-SO-000105|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters|EnableSecuritySignature||
WN10-SO-000110|POLICY_DWORD|0|HKLM\System\CurrentControlSet\Services\LanmanWorkstation\Parameters|EnablePlainTextPassword||
WN10-SO-000115|POLICY_DWORD|1..15|HKLM\System\CurrentControlSet\Services\LanManServer\Parameters|AutoDisconnect||
WN10-SO-000120|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RequireSecuritySignature||
WN10-SO-000125|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|EnableSecuritySignature||
WN10-SO-000130|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|EnableForcedLogoff||
WN10-SO-000135|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\LanManServer\Parameters|SmbServerNameHardeningLevel|CAN_NOT_BE_NULL|
WN10-SO-000145|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymousSAM||
WN10-SO-000150|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Control\Lsa|RestrictAnonymous||
WN10-SO-000155|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Control\Lsa|DisableDomainCreds||
WN10-SO-000160|POLICY_DWORD|0|HKLM\System\CurrentControlSet\Control\Lsa|EveryoneIncludesAnonymous||
WN10-SO-000165|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters|RestrictNullSessAccess||
WN10-SO-000167|POLICY_TEXT|O:BAG:BAD:(A;;RC;;;BA)|HKLM\SYSTEM\CurrentControlSet\Control\Lsa|RestrictRemoteSAM||
WN10-SO-000170|POLICY_DWORD|0|HKLM\SYSTEM\CurrentControlSet\Control\Lsa|ForceGuest||
WN10-SO-000175|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Control\LSA|UseMachineId||
WN10-SO-000180|POLICY_DWORD|0|HKLM\System\CurrentControlSet\Control\LSA\MSV1_0|allownullsessionfallback||
WN10-SO-000185|POLICY_DWORD|0|HKLM\System\CurrentControlSet\Control\LSA\pku2u|AllowOnlineID||
WN10-SO-000190|POLICY_DWORD|2147483640|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters|SupportedEncryptionTypes||
WN10-SO-000195|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Control\Lsa|NoLMHash||
WN10-SO-000205|POLICY_DWORD|5|HKLM\System\CurrentControlSet\Control\Lsa|LmCompatibilityLevel||
WN10-SO-000210|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Services\LDAP|LDAPClientIntegrity||
WN10-SO-000215|POLICY_DWORD|537395200|HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinClientSec||
WN10-SO-000220|POLICY_DWORD|537395200|HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0|NTLMMinServerSec||
WN10-SO-000225|POLICY_DWORD|0|HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole|SecurityLevel|CAN_BE_NULL|
WN10-SO-000230|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Control\Lsa\FIPSAlgorithmPolicy|Enabled||
WN10-SO-000235|POLICY_DWORD|1|HKLM\System\CurrentControlSet\Control\Session Manager\Kernel|ObCaseInsensitive||
WN10-SO-000240|POLICY_DWORD|1|HKLM\SYSTEM\CurrentControlSet\Control\Session Manager|ProtectionMode||
WN10-SO-000245|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|FilterAdministratorToken|CAN_NOT_BE_NULL|
WN10-SO-000250|POLICY_DWORD|2|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorAdmin|CAN_NOT_BE_NULL|
WN10-SO-000255|POLICY_DWORD|0|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|ConsentPromptBehaviorUser|CAN_NOT_BE_NULL|
WN10-SO-000260|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|EnableInstallerDetection|CAN_NOT_BE_NULL|
WN10-SO-000265|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|EnableSecureUIAPaths|CAN_NOT_BE_NULL|
WN10-SO-000270|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|EnableLUA|CAN_NOT_BE_NULL|
WN10-SO-000275|POLICY_DWORD|1|HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System|EnableVirtualization||
'@
# NSA's firewall checks, as the effective active-store property each one governs (NSA: per profile, policy + local path)
$fw = @'
WNFWA-000001/2/3|Enabled|True|profile firewall on
WNFWA-000004/12/20|DefaultInboundAction|Block|unsolicited inbound blocked
WNFWA-000005/13/21|DefaultOutboundAction|Allow|outbound allowed (NSA default)
WNFWA-000006/14/22|NotifyOnListen|True|display notifications
WNFWA-000007/15/23|AllowUnicastResponseToMulticast|False|block unicast responses to multicast
WNFWA-000009/17/27|LogMaxSizeKilobytes|>=16384|log size >= 16 MB
WNFWA-000010/18/28|LogBlocked|True|log dropped packets
WNFWA-000011/19/29|LogAllowed|True|log successful connections
WNFWA-000024|AllowLocalFirewallRules|False|public: no local rule merge
WNFWA-000025|AllowLocalIPsecRules|False|public: no local IPsec merge
'@

# Sanctir dispositions for items where Windows 11 / Entra-only / the approved baseline legitimately differ
$na = @{
    'WN10-00-000005' = 'Windows 11 Enterprise also reports ProductName "Windows 10 Enterprise"; edition checked, not a control'
    'WN10-00-000040' = 'ReleaseID frozen at 2009 since 20H2; currency judged by build (26200 = 25H2) and patch level instead'
    'HardenedUNC-SYSVOL' = 'Domain-only (SYSVOL); WS01 is Entra-joined, no domain controller'
    'HardenedUNC-NETLOGON' = 'Domain-only (NETLOGON); WS01 is Entra-joined, no domain controller'
    'WN10-CC-000140' = 'Untrusted-font blocking was removed from Windows (Win10 1703+ isolates fonts in AppContainer); setting has no effect on Windows 11'
    'WN10-CC-000230' = 'Legacy Edge (EdgeHTML) removed from Windows 11; Chromium Edge is governed by Edge policies'
    'WN10-CC-000235' = 'Legacy Edge (EdgeHTML) removed from Windows 11'
    'WN10-CC-000240' = 'Legacy Edge (EdgeHTML) removed from Windows 11'
    'WN10-CC-000245' = 'Legacy Edge (EdgeHTML) removed from Windows 11'
    'WN10-CC-000250' = 'Legacy Edge (EdgeHTML) removed from Windows 11'
    'WN10-CC-000295' = 'Internet Explorer 11 retired and removed (Feeds)'
    'WN10-CC-000300' = 'Internet Explorer 11 retired and removed (Feeds)'
    'WN10-SO-000075' = 'DoD-specific banner text; Sanctir is not DoD (organisation banner, if any, is judged by the current STIG)'
    'WN10-SO-000080' = 'DoD-specific banner caption; Sanctir is not DoD'
    'WN10-SO-000225' = 'Recovery Console (Windows XP era) does not exist'
    'WN10-SO-000035' = 'Netlogon secure channel: domain-only'; 'WN10-SO-000040' = 'Netlogon secure channel: domain-only'; 'WN10-SO-000045' = 'Netlogon secure channel: domain-only'
    'WN10-SO-000050' = 'Netlogon machine password: domain-only'; 'WN10-SO-000055' = 'Netlogon machine password: domain-only'; 'WN10-SO-000060' = 'Netlogon secure channel: domain-only'
    'WN10-CC-000135' = 'Domain PIN logon applies to domain accounts; Entra-joined with Windows Hello for Business policy instead'
}
$dev = @{
    'WN10-CC-000265' = 'OneDrive is the organisation''s sanctioned CUI-free storage (POL-008/STD-021); NSA 2016 disabled it'
    'WN10-SO-000255' = 'UAC standard-user prompt for credentials on the secure desktop: recorded deviation (POL-003 §2, 10 Oct 2026) so admin elevates with Windows Hello; no password provider'
    'WNFWA-000005/13/21' = 'STRICTER: outbound default BLOCK with ~127 approved allows (GAP-022 §5, STD-023)'
    'WNFWA-000006/14/22' = 'Notifications off: user cannot authorise new listeners anyway (inbound default block, lockdown remediation)'
    'WNFWA-000024' = 'Local rule merge kept ON by design: the tenant''s versioned-path rules live in the local store; the Firewall Local Rule Lockdown disables every unapproved local rule within seconds (memory: never set merge off)'
}

$mdm = @{}
foreach ($area in Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device' -ErrorAction SilentlyContinue) {
    $p = Get-ItemProperty $area.PSPath -ErrorAction SilentlyContinue
    foreach ($prop in $p.PSObject.Properties) { if ($prop.Name -notmatch '^PS|_ProviderSet$|_WinningProvider$|_ADMXInstanceData$|_LastWrite') { $mdm["$($area.PSChildName)/$($prop.Name)".ToLower()] = $prop.Value } }
}
function RegVal($key, $item) {
    $path = 'Registry::' + ($key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\')
    try { $k = Get-Item -LiteralPath $path -ErrorAction Stop } catch { return @{ KeyExists = $false; Exists = $false } }
    $v = $k.GetValue($item, $null); if ($null -eq $v) { return @{ KeyExists = $true; Exists = $false } }
    if ($v -is [string[]]) { $v = $v -join "`n" }
    @{ KeyExists = $true; Exists = $true; Value = $v }
}
function Match($v, $want, $check) {
    if ($want -match '^(\d+)\.\.(\d+)$') { return ([long]$v -ge [long]$Matches[1] -and [long]$v -le [long]$Matches[2]) }
    if ($check -eq 'CHECK_GREATER_THAN_OR_EQUAL') { try { return ([long]$v -ge [long]$want) } catch { return ("$v" -ge "$want") } }
    foreach ($w in ($want -split ',')) { if ("$v".Trim() -eq $w.Trim()) { return $true } }
    $false
}

$rows = New-Object Collections.ArrayList
foreach ($line in ($win -split "`r?`n" | Where-Object { $_ })) {
    $f = $line -split '\|'; $id, $type, $want, $key, $item, $opt, $check = $f[0], $f[1], $f[2], $f[3], $f[4], $f[5], $f[6]
    $res = $null; $seen = ''
    if ($type -eq 'MUST_NOT_EXIST') { $r = RegVal $key '(none)'; $seen = if ($r.KeyExists) { 'key present' } else { 'key absent' }; $res = if ($r.KeyExists) { 'FAIL' } else { 'PASS' } }
    else {
        $r = RegVal $key $item
        if ($r.Exists) { $seen = "$($r.Value)"; $res = if (Match $r.Value $want $check) { 'PASS' } else { 'FAIL' } }
        elseif ($opt -eq 'CAN_BE_NULL') { $seen = 'not set (allowed)'; $res = 'PASS' }
        else {
            $hit = @($mdm.Keys | Where-Object { $_ -like "*/$($item.ToLower())" })
            if ($hit.Count) { $seen = "MDM: $(($hit | ForEach-Object { "$_=$($mdm[$_])" }) -join '; ')"; $res = 'REVIEW' } else { $seen = 'not set'; $res = 'FAIL' }
        }
    }
    # Windows 11 / Intune equivalents established 12 Oct 2026 (the 2016 checks look in one place only)
    if ($id -eq 'WN10-00-000160' -and $res -eq 'FAIL') { $st = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -ErrorAction SilentlyContinue).Start; if ($st -eq 4) { $res = 'PASS'; $seen = 'driver present but Start=4 (disabled) - the current Windows 11 STIG check' } }
    if ($id -eq 'WN10-CC-000255' -and $res -ne 'PASS') { $v = @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Policies\PassportForWork' -Recurse -ErrorAction SilentlyContinue | ForEach-Object { (Get-ItemProperty $_.PSPath).RequireSecurityDevice } | Where-Object { $null -ne $_ }); if ($v -contains 1) { $res = 'PASS'; $seen = 'RequireSecurityDevice=1 via Intune (PassportForWork\<tenant>\Device\Policies)' } }
    if ($id -in 'WN10-SO-000115', 'WN10-SO-000125', 'WN10-SO-000130', 'WN10-SO-000135', 'WN10-SO-000165' -and $res -ne 'PASS') { $srv = Get-CimInstance Win32_Service -Filter "Name='LanmanServer'" -ErrorAction SilentlyContinue; if ($srv.StartMode -eq 'Disabled') { $res = 'N/A'; $seen = "$seen | SMB server (LanmanServer) disabled - nothing to sign or harden (RA-025)" } }
    if ($na.ContainsKey($id)) { $res = 'N/A'; $seen = "$seen | $($na[$id])" }
    elseif ($dev.ContainsKey($id) -and $res -ne 'PASS') { $res = 'DEVIATION'; $seen = "$seen | $($dev[$id])" }
    [void]$rows.Add([pscustomobject]@{ Set = 'Windows'; Id = $id; Result = $res; Want = "$want"; Seen = $seen; Where = "$key\$item" })
}
$prof = @(Get-NetFirewallProfile -PolicyStore ActiveStore)
foreach ($line in ($fw -split "`r?`n" | Where-Object { $_ })) {
    $id, $prop, $want, $what = $line -split '\|'
    $profiles = if ($id -in 'WNFWA-000024', 'WNFWA-000025') { @($prof | Where-Object Name -eq 'Public') } else { $prof }
    $vals = @($profiles | ForEach-Object { "$($_.Name)=$($_.$prop)" })
    $ok = @($profiles | Where-Object { $v = "$($_.$prop)"; if ($want -like '>=*') { [long]$v -ge [long]($want.Substring(2)) } else { $v -eq $want } }).Count -eq $profiles.Count
    $res = if ($ok) { 'PASS' } elseif ($dev.ContainsKey($id)) { 'DEVIATION' } else { 'FAIL' }
    $seen = ($vals -join ' ') + $(if (-not $ok -and $dev.ContainsKey($id)) { " | $($dev[$id])" })
    [void]$rows.Add([pscustomobject]@{ Set = 'Firewall'; Id = $id; Result = $res; Want = "$prop $want"; Seen = $seen; Where = "active firewall profile ($what)" })
}

$day = Get-Date -Format 'yyyy-MM-dd'; $ev = Join-Path $ProjectRoot "Evidence\$day"; New-Item -ItemType Directory -Force $ev | Out-Null
$out = Join-Path $ev "nsa-shb-eval-$(Get-Date -Format 'HHmmss').txt"
$sum = $rows | Group-Object Set, Result | Sort-Object Name | ForEach-Object { "{0,-24} {1}" -f $_.Name, $_.Count }
$report = @("=== NSA Windows Secure Host Baseline (declarative checks, read-only) on $env:COMPUTERNAME, $(Get-Date -Format 'yyyy-MM-dd HH:mm zzz')", 'Source: nsacyber/Windows-Secure-Host-Baseline (archived 2023): Windows10.audit = DISA Win10 STIG V1R7; WindowsFirewall.audit = Firewall STIG V1R5', '--- summary') + $sum + @('--- FAIL and REVIEW') + ($rows | Where-Object { $_.Result -in 'FAIL', 'REVIEW' } | ForEach-Object { "{0,-8} {1,-20} want {2,-18} seen {3}  [{4}]" -f $_.Result, $_.Id, $_.Want, $_.Seen, $_.Where }) + @('--- DEVIATION (recorded Sanctir decisions)') + ($rows | Where-Object Result -eq 'DEVIATION' | ForEach-Object { "{0,-20} want {1,-18} seen {2}" -f $_.Id, $_.Want, $_.Seen }) + @('--- N/A on Windows 11 / Entra-only') + ($rows | Where-Object Result -eq 'N/A' | ForEach-Object { "{0,-20} {1}" -f $_.Id, $_.Seen }) + @('--- PASS') + ($rows | Where-Object Result -eq 'PASS' | ForEach-Object { "{0,-20} {1}" -f $_.Id, $_.Seen })
[IO.File]::WriteAllLines($out, [string[]]$report)
$report | Select-Object -First 80
"written: $out"
