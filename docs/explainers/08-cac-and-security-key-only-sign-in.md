# 08 — CAC for the administrator, a security key for the user, nothing else

On 20 October 2026 Sanctir cut sign-in down to exactly two methods, everywhere — Windows, Microsoft 365, the Azure and Intune portals, and every elevation:

| Account | Signs in with | Nothing else works |
|---|---|---|
| **Administrator** (separate admin-only account) | A **CAC** — an ECA certificate on a smart card, PIN-protected — through Entra **certificate-based authentication** | No password, no passkey, no Authenticator, no SMS, no Temporary Access Pass, no Windows Hello |
| **Daily user** | A **FIDO2 security key** (YubiKey 5 FIPS series, attested, model allow-listed) with its PIN | No password, no CAC, no Authenticator, no Windows Hello |

This is the most phishing-resistant arrangement a small Microsoft 365 company can run without federation: both methods are hardware-bound and PIN-protected, neither can be phished or replayed, and the two accounts cannot be confused with each other because they do not even share a method.

## The pieces (all in `policies/`)

1. **Authentication strengths** — custom `REF-CAC-Only` (certificate-based authentication, multi-factor) and `REF-YubiKey-Only` (FIDO2 with the AAGUID allow-list). The CA deployer creates them from the policy definition if they do not exist.
2. **Conditional Access** — `REF-CA-Admin-CAC-Only` (admin account, all apps, strength CAC-only) and `REF-CA-User-YubiKey-Only` (daily user, all apps, strength YubiKey-only). Deploy **report-only** first and read the sign-in log.
3. **Authentication methods policy** — FIDO2 restricted to the allow-listed AAGUIDs with attestation enforced and self-service registration off (open a short registration window when a key is added, then close it); certificate-based authentication scoped to the admin group with the certificate bound by Subject Key Identifier; Temporary Access Pass, SMS, voice, e-mail, software OATH and Authenticator disabled.
4. **Windows sign-in** — `REF-SmartCard-Logon` (smart card sign-in with username hint), `REF-IA-HelloOff` (Windows Hello for Business and biometrics off), `REF-IA-SignInTiles` (every credential provider except the security key and the smart card hidden; web sign-in off; the password tile hidden).
5. **Elevation** — the security baseline sets UAC to *prompt for credentials on the secure desktop* (stricter than DISA's "consent"), so every elevation asks for the card and its PIN. The daily user cannot elevate at all (automatic deny, a DISA requirement); admin work is done by switching to the admin account's own session.

## Order — this is how you avoid locking yourself out

1. Get the card and the keys **first**, and prove them: the card reader works on **every** PC (install the smart-card minidriver your card needs through Intune before anything else), the admin can sign in to Windows and to Entra with the card, the user with the key.
2. Register the **backup** security key for the daily user, and keep it apart from the primary.
3. Keep the emergency-access account **outside** every one of these policies, on its own hardware key, alerted on every sign-in.
4. Deploy the authentication strengths and the two Conditional Access policies **report-only**; read a day of sign-ins; then enable.
5. Only then switch off the other methods, hide the Windows tiles, turn Hello off — and **purge** Hello's existing keys and biometric data on the devices (turning the policy off does not delete what is already enrolled). The TPM itself is never cleared.

## Things that bit us (so they do not bite you)

- **Deleting an administrator's authentication methods needs a fresh sign-in with an "ngcmfa" claim** — Graph refuses with `actionRequiresNgcMfaClaim` otherwise. Request the token with `prompt=login` and the claims parameter.
- **A browser will happily reuse yesterday's session.** Testing "card only" in a browser that still holds a key-based session proves nothing; sign in fresh.
- **Windows Hello settings hide in a nested group** inside account-protection policies; a top-level search misses them.
- **"Hello off" is not "Hello gone"**: existing Hello keys and fingerprints survive the policy. A remediation removes the keys per user and purges the biometric database as SYSTEM.
- **Web sign-in option 0 means "default", not "off"** in the settings catalog — use the explicit disabled option.
- **The password tile is a credential provider like any other** — hide it by its CLSID, or users keep seeing a password option that no longer works.

## What it cost in daily use — and the fixes

Moving to session-only cookies, no Edge password manager and key-only sign-in made the first morning slow: every site asked to sign in again. The fixes, all tenant policy and all inside the DISA rules (see [07](07-disa-stig-results.md)):

- The company password manager as the **one** allowed, force-installed Edge extension.
- A short list of business sites in **both** `CookiesAllowedForUrls` and `SaveCookiesOnExit`.
- Edge sync on for the work account, with passwords and payment data excluded (a recorded deviation).
- **A sign-in-frequency policy will keep prompting — exclude your own compliant PCs from it.** Unlocking Windows with a FIDO2 key renews the device's sign-in token but does **not** reset the authentication time Conditional Access checks (Windows Hello did, and it is gone). After a boot or wake the VPN may still be reconnecting, so the sign-in itself can be offline. The result was OneDrive, Office and Edge asking to sign in after every reboot and sleep (`AADSTS70043` in the `Microsoft-Windows-AAD/Operational` log). The fix: keep the 12-hour policy, with a device filter that **excludes** `device.isCompliant -eq True -and device.trustType -eq "AzureAD"`. Every unmanaged device and browser still re-authenticates; your own PCs rely on the key unlock, screen lock and idle sign-out. See `policies/conditional-access/REF-CA-SignInFrequency.json`.
- **Lock or sleep, don't sign out.** Signing out ends every session by design.
