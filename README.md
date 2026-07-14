# Enterprise Files for Android

An Android Enterprise app for Active Directory/Kerberos with two components in one APK:

- a Kerberos authenticator for SSO and ticket management
- an enterprise file browser for SMB 2/3 shares with Kerberos-only access

The app is based on the existing [android-kerberos-authenticator](https://github.com/google/android-kerberos-authenticator) codebase and has been extended with an integrated enterprise file experience. Chrome can still use the same Kerberos account for HTTP Negotiate.

## HTTP Negotiate: Kerberos and managed NTLMv2

The authenticator stores the user password after the first successful login only when the
device has a secure screen lock and a hardware-backed Android Keystore. This allows the app
to renew TGTs without additional input.

For HTTP, the app uses Android AccountManager and SPNEGO. Chrome supplies the original URL host;
the app then offers Kerberos first and can additionally advertise NTLMSSP when an administrator
explicitly enables HTTP NTLMv2. The Kerberos path requests a ticket for an exact MDM mapping, the
original host, and then each name in the DNS CNAME chain. Only
`KDC_ERR_S_PRINCIPAL_UNKNOWN` advances to the next Kerberos candidate.

NTLMv2 is used only if the server explicitly selects NTLMSSP in a
`WWW-Authenticate: Negotiate` exchange. A Kerberos error never causes an NTLM downgrade. A direct
`WWW-Authenticate: NTLM` challenge is not passed to this Android authenticator by Chrome and is
therefore unsupported. Internal Kerberos/JGSS debugging is permanently disabled; passwords,
tickets, hashes, challenges, MICs, session keys, and SPNEGO token bytes are never logged.

## Enterprise files

- MDM determines which shares are visible; users cannot add their own SMB server.
- SMB uses Kerberos GSS/SPNEGO, signing, and at least SMB 2.1. There is no NTLM, guest, or anonymous fallback.
- Managed DFS namespaces and referrals are followed directly with Kerberos-only SMB.
- Browsing, downloading/opening, uploading, creating folders, renaming, and deleting are available within the user's AD permissions.
- The user enters their own AD username and password. MDM never supplies credentials.
- On a device with a secure screen lock, the password is device-bound encrypted with a hardware-backed Android Keystore key. The app uses this to request a completely new TGT every day. Storage no longer requires the realm to be supplied through one specific Android RestrictionsManager source.
- If secure hardware storage is unavailable, sign-in remains possible but the password is not stored persistently.
- Screenshots are blocked by default and SMB 3 encryption can be required by MDM.

## Differences from the original

- **Bazel → Gradle** with AGP 8.7.3
- **Package**: `com.poelbos.kerberosauthenticator` (originally `com.google.android.apps.work.kerberosauthenticator`)
- **Support Library → AndroidX**
- **CompileSDK 35, MinSDK 26, TargetSDK 35**
- `openjdk-kerberos` included as a local library module (cloned from [google/openjdk-kerberos](https://github.com/google/openjdk-kerberos))
- Manual config UI for testing without MDM
- DNS-based KDC discovery from SRV records (`_kerberos._udp.<realm>`)
- App version, TGT validity, and service ticket info shown in the status UI
- Integrated enterprise file browser with managed shares, FileProvider-based external opening, and Kerberos-only SMB sessions
- GitHub Actions release workflow that publishes APKs on push to `main`
- Logout button that removes the account and clears local config

## Prerequisites

- JDK 17
- Android SDK (API 35 + build-tools 35.0.0)
- Android device or emulator running API 26+

## Building

```bash
./gradlew assembleDebug
```

APK at `app/build/outputs/apk/debug/app-debug.apk`.

```bash
./gradlew assembleRelease -PreleaseVersion=1.0
```

Release APK at `app/build/outputs/apk/release/app-release.apk`. Requires `release.keystore` in the project root.

## Testing

```bash
./gradlew test
```

Unit tests use Robolectric 4.16.1. JDK 17 is required because the openjdk-kerberos library uses `sun.security.*` internal classes that need `--add-exports` JVM flags.

## Releasing

Pushing to the `main` branch triggers the serialized [Build and Publish Release](.github/workflows/release.yml) workflow:

1. Runs lint and all debug unit tests under JDK 17.
2. Restores the signing keystore and passwords from GitHub secrets.
3. Determines the next version by incrementing the latest GitHub release tag (e.g. `v1.0` → `v1.1`).
4. Builds the signed release APK.
5. Creates or resumes a draft release and publishes it after the APK upload succeeds.

To set up the release keystore secret:

```bash
base64 -i release.keystore | pbcopy
```

Add the clipboard contents as `RELEASE_KEYSTORE_B64`. Also configure
`RELEASE_STORE_PASSWORD` and `RELEASE_KEY_PASSWORD`; `RELEASE_KEY_ALIAS` is optional and defaults
to `kerberos`.

## Installing on device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Testing without MDM

Local configuration supports interactive sign-in only. Persistent credential storage and daily
TGT refresh require an Android Enterprise managed profile or fully managed device, an `ad_realm`
delivered through managed configuration, a screen lock, and hardware-backed Android Keystore.

## MDM Deployment

The app reads its configuration from Android's [managed configuration](https://developer.android.com/work/managed-configurations), pushed by an EMM/MDM.

### Omnissa Workspace ONE UEM

Create one application configuration for this app and one for Chrome. MDM provides the Kerberos realm and share definitions; the user enters their own username and password. The Chrome configuration tells Chrome which Android account type to use for HTTP Negotiate/Kerberos.

#### Kerberos Authenticator app

1. In Workspace ONE UEM, add the APK as an internal Android application, or publish it as a private Managed Google Play application.
2. Assign the app to the Android Enterprise smart group that contains the target devices.
3. In the app assignment, enable **Application Configuration** / managed configuration.
4. Enter the managed configuration keys below. If Workspace ONE UEM discovers the app restriction schema from the APK, use the generated fields. Otherwise, add the keys manually as custom key-value pairs.

For the integrated file app, for example:

```json
{
  "ad_realm": "EXAMPLE.COM",
  "enable_http_ntlm": true,
  "ntlm_domain": "EXAMPLE",
  "require_smb_encryption": true,
  "allow_local_cache": true,
  "allow_screenshots": false,
  "shares": [
    {
      "id": "documents",
      "display_name": "Documents",
      "host": "files.example.com",
      "port": 445,
      "share_name": "Documents",
      "start_path": "users/${username:last:1}/${username:full}"
    }
  ]
}
```

Always use a DNS hostname with a valid `cifs/<host>` SPN; IP addresses are rejected. `kdc_hosts` is optional; otherwise the app uses DNS SRV discovery. The schema is in `app/src/main/res/xml/app_restrictions.xml` and can be read from the APK by an MDM.

`start_path` may be a static relative path or a user template. Templates are resolved from the
authenticated Kerberos account, not from a UEM enrollment lookup value. The supported tokens are:

- `${username}` — the complete Kerberos username.
- `${username:full}` — UEM-safe alias for the complete Kerberos username.
- `${username:last:1}` — the final digit of the Kerberos username.

For UEM systems that consume `{username}` as their own lookup value, use
`users/${username:last:1}/${username:full}`. It resolves to `users/2/user12342` for account
`user12342`; forward slashes are normalized to SMB separators. Templates are accepted only in `start_path`;
`host` and `share_name` remain fixed administrator-controlled values. Static paths continue to
work unchanged.

The user signs in to the app with their own AD username and password. After a successful login, the app requests a new TGT daily through WorkManager. Android may delay the exact execution time because of Doze. The app discovers KDCs through DNS SRV records such as `_kerberos._udp.example.com`.

#### Chrome app

Chrome must also be managed. Add or edit the managed Google Play assignment for `com.android.chrome`, then set these application configuration values:

| Key | Type | Example | Description |
|---|---|---|---|
| `AuthAndroidNegotiateAccountType` | string | `AndroidEnterpriseKerberos` | Account type exposed by this authenticator app. Without this, Chrome disables HTTP Negotiate on Android. |
| `AuthServerAllowlist` | string | `*.example.com,example.com` | Internal sites where Chrome may answer Kerberos/Negotiate challenges. |
| `AuthSchemes` | string | `negotiate` | Optional. Include `negotiate` if you restrict authentication schemes. |
| `AuthNegotiateDelegateAllowlist` | string | `*.example.com` | Optional. Only needed if credential delegation is required. |
| `DisableAuthNegotiateCnameLookup` | bool | `true` | Preserve the original URL host for the Kerberos request. The app can then try that host before its CNAME chain. |

After the assignment syncs, fully stop and restart Chrome, then open `chrome://policy` on the
device to confirm the policies are present. This policy does not refresh dynamically.

### Testing managed config

**Option 1** — Use the built-in debug UI: install the APK and enter username and domain. Without managed configuration, the password is not stored persistently.

**Option 2** — Use [Test DPC](https://play.google.com/store/apps/details?id=com.afwsamples.testdpc) from Google Play. After installing:
1. Set Test DPC as device owner
2. Navigate to **Managed Configurations** → find the Kerberos Authenticator
3. Enter the configuration values as key-value pairs using the keys below

**Option 3** — Via `adb` with Test DPC:

```bash
adb shell dpm set-test-device-owner com.afwsamples.testdpc/.DeviceAdminReceiver
```

Then use the Test DPC UI to set managed configuration for the app.

### Managed configuration keys

| Key | Type | Required | Description |
|---|---|---|---|
| `ad_realm` | string | yes | Kerberos realm (e.g. `EXAMPLE.COM`) |
| `shares` | bundle array | yes | Managed SMB shares with ID, label, DNS host, port, share and static or username-templated start path |
| `kdc_hosts` | string | no | Comma-separated KDC hosts; omit for DNS SRV discovery |
| `http_spn_mappings` | bundle array | no | Exact HTTP request-host to SPN-host overrides for exceptional web aliases |
| `enable_http_ntlm` | bool | no | Advertise NTLMSSP inside HTTP Negotiate when secure credentials are available; default `false` |
| `ntlm_domain` | string | when HTTP NTLM is enabled | NetBIOS domain, 1–15 characters, for example `EXAMPLE` |
| `require_smb_encryption` | bool | no | Require SMB 3 encryption; default `true` |
| `allow_local_cache` | bool | no | Permit short-lived app-private files for external viewers; default `false` |
| `allow_screenshots` | bool | no | Permit screenshots; default `false` |
| `support_contact` | string | no | IT support text or URL |

When no domain controller is specified, the app automatically discovers KDCs through DNS SRV lookups (`_kerberos._udp.<domain>` and `_kerberos._tcp.<domain>`).

HTTP Kerberos tries an exact managed override, the original host supplied by Chrome and then its
complete DNS CNAME chain. The app does not use LDAP, certificate SAN or reverse-DNS names to invent
additional targets. For an exceptional alias, configure an exact override; wildcards, IP addresses
and URLs are rejected. A Kerberos realm and DNS namespace do not have to be identical:

```json
{
  "http_spn_mappings": [
    {
      "request_host": "portal.example.com",
      "spn_host": "web01.example.com"
    }
  ]
}
```

This requests `HTTP/web01.example.com` when Chrome asks for `portal.example.com`; the app never
creates or changes SPNs in Active Directory.

### HTTP NTLMv2 policy and limitations

HTTP NTLMv2 becomes ready only when all of the following are true:

- `enable_http_ntlm` is `true` and `ntlm_domain` is a valid NetBIOS domain;
- the account was created successfully through Kerberos;
- the password is available from the device-bound, hardware-backed credential vault;
- Chrome allows the host through `AuthServerAllowlist` and has `negotiate` in `AuthSchemes`.

The app accepts the stored identity as `user`, `DOMAIN\user` when the domain matches
`ntlm_domain`, or `user@realm` when the realm matches `ad_realm`. It supports NTLMv2 only. NTLMv1,
LM responses, guest, anonymous, proxy authentication, direct HTTP NTLM, and NTLM for SMB are not
implemented. SMB remains Kerberos-only.

Chrome's Android AccountManager adapter does not provide TLS channel-binding data. The app sends
the protocol-defined zero channel-binding value; sites that require non-zero channel binding
(strict Extended Protection) remain unsupported. The status screen shows this limitation whenever
NTLM is explicitly enabled.

### HTTP authentication troubleshooting

The status screen shows whether HTTP NTLMv2 is disabled, ready, or unavailable and records only
the last host, mechanism, time, and safe result category. Relevant Chrome result codes are:

| Code | Meaning | Check |
|---:|---|---|
| `0` | Token round succeeded | Continue with the next server round if requested |
| `4` | Invalid server response or negotiation context | Check the server's SPNEGO/NTLM Type-2 response and whether the host changed between rounds |
| `5` | NTLM credentials rejected | Verify the user's current password; the app deliberately keeps the vault record |
| `6` | Mechanism unavailable | Confirm the server selected a mechanism the managed policy permits |
| `7` | Secure credentials missing | Confirm screen lock and hardware-backed Android Keystore availability, then sign in again |
| `9` | Malformed or conflicting identity | Match `DOMAIN` to `ntlm_domain` or the UPN realm to `ad_realm` |

If a site sends `WWW-Authenticate: NTLM` instead of `Negotiate`, change the server to offer NTLMSSP
inside SPNEGO; the app cannot intercept Chrome's direct NTLM path. A strict Extended Protection
failure is expected when the server requires a real TLS channel-binding hash.

### Credential and ticket policy

- The app supports one AD account per Android profile.
- Ciphertext is stored in app-private storage; the AES-256-GCM key is non-exportable and hardware-backed. Android backup and device transfer are disabled.
- Long-lived credentials are refused outside a managed profile or fully managed device with an MDM-provided `ad_realm`.
- A new TGT is requested every 24 hours with a network constraint and a two-hour flex window. Temporary network, VPN, DNS, and KDC failures receive increasing retries.
- If the password changes or is incorrect, or the account expires or is revoked, the password and tickets are cleared and the app requests sign-in again.
- Logout, a changed or removed MDM realm, and clearing app or work-profile data remove credentials, tickets, and scheduled refreshes.

## License

Apache 2.0 — see [LICENSE](LICENSE). The implementation uses the same provider-oriented design evaluated in Material Files, but does not copy its GPL-licensed source code.
