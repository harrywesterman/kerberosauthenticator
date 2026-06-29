# Android Kerberos Authenticator

A port of Google's archived [android-kerberos-authenticator](https://github.com/google/android-kerberos-authenticator) from Bazel to Gradle, with updated dependencies for modern Android.

This app provides Kerberos/SPNEGO authentication for Chrome on Android Enterprise devices. It obtains Ticket Granting Tickets (TGT) from an Active Directory domain controller and exchanges them for SPNEGO service tickets.

## Differences from the original

- **Bazel → Gradle** with AGP 8.7.3
- **Package**: `com.poelbos.kerberosauthenticator` (originally `com.google.android.apps.work.kerberosauthenticator`)
- **Support Library → AndroidX**
- **CompileSDK 35, MinSDK 26, TargetSDK 35**
- `openjdk-kerberos` included as a local library module (cloned from [google/openjdk-kerberos](https://github.com/google/openjdk-kerberos))
- Debug config UI for testing without MDM

## Prerequisites

- JDK 17
- Android SDK (API 35 + build-tools 35.0.0)
- Android device or emulator running API 26+

## Building

```bash
./gradlew assembleDebug
```

APK at `app/build/outputs/apk/debug/app-debug.apk`.

## Testing

```bash
./gradlew test
```

35 unit tests (Robolectric 4.16.1). Requires JDK 17 — the openjdk-kerberos library uses `sun.security.*` internal classes that need `--add-exports` JVM flags.

## Installing on device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Testing without MDM

On first launch, the app shows a debug screen where you can enter AD credentials manually (username, password, domain, domain controller). These are saved to SharedPreferences as fallback when no managed configuration is available.

## MDM Deployment

The app reads its configuration from Android's [managed configuration](https://developer.android.com/work/managed-configurations), pushed by an EMM/MDM.

### Android Management API / Google Play Managed Config

```json
{
  "username": "john.doe",
  "password": "s3cret",
  "adDomain": "example.com",
  "adController": "dc01",
  "sensitiveDebugData": false
}
```

### Microsoft Intune

In the Intune admin center, create an app configuration policy for managed Android devices with configuration values as key-value pairs using the keys below.

### Testing managed config

**Option 1** — Use the built-in debug UI (simplest): install the APK and launch the app. It shows a form to enter AD credentials manually. Credentials are stored in SharedPreferences and used as fallback when no MDM-managed config exists.

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
| `username` | string | yes | AD username |
| `password` | string | no | AD password. If omitted, the user is prompted to enter it on first login |
| `adDomain` | string | yes | Active Directory domain (e.g. `example.com`) |
| `adController` | string | yes | Domain controller hostname (not FQDN) |
| `sensitiveDebugData` | bool | no | Enable debug logging that includes credentials (`true`/`false`, default `false`) |

## License

Apache 2.0 — see [LICENSE](https://github.com/google/android-kerberos-authenticator/blob/master/LICENSE) in the original repository.
