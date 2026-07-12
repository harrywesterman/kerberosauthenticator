# Bedrijfsbestanden voor Android

Een Android Enterprise-app voor Active Directory/Kerberos met twee delen in één APK:

- een Kerberos-authenticator voor SSO en ticketbeheer
- een bedrijfsbestanden-browser voor SMB 2/3-shares met Kerberos-only toegang

De app is gebaseerd op de bestaande [android-kerberos-authenticator](https://github.com/google/android-kerberos-authenticator)-codebasis en is uitgebreid met een geïntegreerde enterprise-bestandenervaring. Chrome kan nog steeds dezelfde Kerberos-account gebruiken voor HTTP Negotiate.

## Bedrijfsbestanden

- MDM bepaalt welke shares zichtbaar zijn; gebruikers kunnen geen eigen SMB-server toevoegen.
- SMB gebruikt Kerberos GSS/SPNEGO, signing en minimaal SMB 2.1. Er is geen NTLM-, guest- of anonymous-fallback.
- Browsen, downloaden/openen, uploaden, mappen maken, hernoemen en verwijderen zijn beschikbaar binnen de AD-rechten van de gebruiker.
- De gebruiker voert zelf zijn AD-gebruikersnaam en wachtwoord in. MDM levert nooit credentials.
- Op een beheerd toestel met veilige schermvergrendeling wordt het wachtwoord apparaatgebonden versleuteld met een hardware-backed Android Keystore-sleutel. Daarmee vraagt de app dagelijks een volledig nieuw TGT aan.
- Als veilige hardware-opslag niet beschikbaar is, blijft aanmelden mogelijk maar wordt het wachtwoord niet langdurig bewaard.
- Screenshots zijn standaard geblokkeerd en SMB 3-encryptie kan door MDM verplicht worden.

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

Langdurige credential-opslag werkt uitsluitend met managed configuration. Zonder MDM kan het legacy testscherm gebruikersnaam en domein bewaren, maar nooit het wachtwoord.

## MDM Deployment

The app reads its configuration from Android's [managed configuration](https://developer.android.com/work/managed-configurations), pushed by an EMM/MDM.

### Omnissa Workspace ONE UEM

Create one application configuration for this app and one for Chrome. MDM provides the Kerberos realm and share definitions; the user enters their own username and password. The Chrome configuration tells Chrome which Android account type to use for HTTP Negotiate/Kerberos.

#### Kerberos Authenticator app

1. In Workspace ONE UEM, add the APK as an internal Android application, or publish it as a private Managed Google Play application.
2. Assign the app to the Android Enterprise smart group that contains the target devices.
3. In the app assignment, enable **Application Configuration** / managed configuration.
4. Enter the managed configuration keys below. If Workspace ONE UEM discovers the app restriction schema from the APK, use the generated fields. Otherwise, add the keys manually as custom key-value pairs.

Voor de geïntegreerde bestandenapp gebruikt u bijvoorbeeld:

```json
{
  "ad_realm": "EXAMPLE.COM",
  "require_smb_encryption": true,
  "allow_local_cache": true,
  "allow_screenshots": false,
  "shares": [
    {
      "id": "documents",
      "display_name": "Documenten",
      "host": "files.example.com",
      "port": 445,
      "share_name": "Documents",
      "start_path": ""
    }
  ]
}
```

Gebruik altijd een DNS-hostnaam met een geldige `cifs/<host>`-SPN; IP-adressen worden geweigerd. `kdc_hosts` is optioneel, anders gebruikt de app DNS SRV-discovery. Het schema staat in `app/src/main/res/xml/app_restrictions.xml` en kan door een MDM uit de APK worden ingelezen.

De gebruiker meldt zich in de app aan met zijn eigen AD-gebruikersnaam en wachtwoord. Na een succesvolle login vraagt de app dagelijks via WorkManager een nieuw TGT aan. Android kan door Doze het exacte uitvoeringstijdstip uitstellen. De app ontdekt KDC's via DNS SRV-records zoals `_kerberos._udp.example.com`.

#### Chrome app

Chrome must also be managed. Add or edit the managed Google Play assignment for `com.android.chrome`, then set these application configuration values:

| Key | Type | Example | Description |
|---|---|---|---|
| `AuthAndroidNegotiateAccountType` | string | `AndroidEnterpriseKerberos` | Account type exposed by this authenticator app. Without this, Chrome disables HTTP Negotiate on Android. |
| `AuthServerAllowlist` | string | `*.example.com,example.com` | Internal sites where Chrome may answer Kerberos/Negotiate challenges. |
| `AuthSchemes` | string | `basic,digest,ntlm,negotiate` | Optional. Include `negotiate` if you restrict authentication schemes. |
| `AuthNegotiateDelegateAllowlist` | string | `*.example.com` | Optional. Only needed if credential delegation is required. |
| `DisableAuthNegotiateCnameLookup` | bool | `false` | Use the canonical DNS CNAME target when Chrome constructs the Kerberos SPN. |

After the assignment syncs, open `chrome://policy` on the device to confirm the Chrome policies are present.

### Testing managed config

**Option 1** — Use the built-in debug UI: install the APK and enter username and domain. Zonder managed configuration wordt het wachtwoord niet langdurig opgeslagen.

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

HTTP Kerberos normally tries the requested host, its complete DNS CNAME chain and exact
`HTTP/` or `HOST/` matches found in Active Directory. Certificate SAN and reverse-DNS names are
diagnostic only and are never trusted as SPN targets. For an exceptional alias, configure an exact
realm-local override; wildcards, IP addresses, URLs and cross-realm targets are rejected:

```json
{
  "http_spn_mappings": [
    {
      "request_host": "mobiel.int.politie",
      "spn_host": "werkelijke-webserver.int.politie"
    }
  ]
}
```

This requests `HTTP/werkelijke-webserver.int.politie` when Chrome asks for
`mobiel.int.politie`; the app never creates or changes SPNs in Active Directory.

### Credential- en ticketbeleid

- De app ondersteunt één AD-account per Android-profiel.
- Ciphertext staat in app-private opslag; de AES-256-GCM-sleutel is niet exporteerbaar en hardware-backed. Android-backup en device-transfer zijn uitgeschakeld.
- Iedere 24 uur wordt met een netwerkconstraint en een flexvenster van twee uur een nieuw TGT aangevraagd. Tijdelijke netwerk-, VPN-, DNS- en KDC-storingen krijgen oplopende retries.
- Bij een gewijzigd/fout wachtwoord, verlopen of ingetrokken account worden wachtwoord en tickets gewist en vraagt de app om opnieuw aanmelden.
- Logout, een gewijzigde/verwijderde MDM-realm en het wissen van app- of work-profiledata verwijderen credentials, tickets en geplande vernieuwing.

## License

Apache 2.0 — see [LICENSE](LICENSE). The implementation uses the same provider-oriented design evaluated in Material Files, but does not copy its GPL-licensed source code.
