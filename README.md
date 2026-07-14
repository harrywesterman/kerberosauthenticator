# Enterprise Files for Android

An Android Enterprise app for Active Directory/Kerberos with two components in one APK:

- a Kerberos authenticator for SSO and ticket management
- an enterprise file browser for SMB 2/3 shares with Kerberos-only access

The app is based on the existing [android-kerberos-authenticator](https://github.com/google/android-kerberos-authenticator) codebase and has been extended with an integrated enterprise file experience. Chrome can still use the same Kerberos account for HTTP Negotiate.

## Current HTTP Kerberos status

The authenticator stores the user password after the first successful login only when the
device has a secure screen lock and a hardware-backed Android Keystore. This allows the app
to renew TGTs without additional input.

For HTTP, the app uses Android AccountManager and GSS-SPNEGO. Chrome supplies the original
URL host; the app then requests a ticket directly from the KDC for an exact MDM mapping, the
original host, and then each name in the DNS CNAME chain. Only `KDC_ERR_S_PRINCIPAL_UNKNOWN`
advances to the next candidate.

The browser path uses no LDAP or NTLM fallback. This keeps a missing SPN visible and makes a
failed request stop quickly. Internal Kerberos/JGSS debugging is permanently disabled;
passwords, tickets, session keys, and SPNEGO token bytes are never logged.

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

Pushing to the `main` branch triggers the [Build and Publish Release](.github/workflows/release.yml) workflow:

1. Restores the signing keystore from the GitHub secret `RELEASE_KEYSTORE_B64`.
2. Determines the next version by incrementing the latest GitHub release tag (e.g. `v1.0` → `v1.1`).
3. Builds the release APK signed with the keystore.
4. Creates a git tag and publishes a GitHub release with the APK attached.

To set up the release keystore secret:

```bash
base64 -i release.keystore | pbcopy
```

Add the clipboard contents as the repository secret `RELEASE_KEYSTORE_B64` in GitHub.

## Installing on device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Testing without MDM

Persistent credential storage works only when the device is protected by a screen lock and
hardware-backed Android Keystore. Without secure hardware storage, sign-in remains possible but
the password is not stored persistently.

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
      "start_path": ""
    }
  ]
}
```

Always use a DNS hostname with a valid `cifs/<host>` SPN; IP addresses are rejected. `kdc_hosts` is optional; otherwise the app uses DNS SRV discovery. The schema is in `app/src/main/res/xml/app_restrictions.xml` and can be read from the APK by an MDM.

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
| `shares` | bundle array | yes | Managed SMB shares with ID, label, DNS host, port, share and start path |
| `kdc_hosts` | string | no | Comma-separated KDC hosts; omit for DNS SRV discovery |
| `http_spn_mappings` | bundle array | no | Exact HTTP request-host to SPN-host overrides for exceptional web aliases |
| `require_smb_encryption` | bool | no | Require SMB 3 encryption; default `false` |
| `allow_local_cache` | bool | no | Permit app-private temporary files for external viewers; default `true` |
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

### Credential and ticket policy

- The app supports one AD account per Android profile.
- Ciphertext is stored in app-private storage; the AES-256-GCM key is non-exportable and hardware-backed. Android backup and device transfer are disabled.
- A new TGT is requested every 24 hours with a network constraint and a two-hour flex window. Temporary network, VPN, DNS, and KDC failures receive increasing retries.
- If the password changes or is incorrect, or the account expires or is revoked, the password and tickets are cleared and the app requests sign-in again.
- Logout, a changed or removed MDM realm, and clearing app or work-profile data remove credentials, tickets, and scheduled refreshes.

## License

Apache 2.0 — see [LICENSE](LICENSE). The implementation uses the same provider-oriented design evaluated in Material Files, but does not copy its GPL-licensed source code.
