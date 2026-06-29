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

## Managed configuration keys

| Key | Description |
|---|---|
| `username` | AD username |
| `password` | AD password (optional — user will be prompted if missing) |
| `adDomain` | Active Directory domain (e.g. `example.com`) |
| `adController` | Domain controller hostname |
| `sensitiveDebugData` | Enable debug logging with credentials (`true`/`false`) |

## License

Apache 2.0 — see [LICENSE](https://github.com/google/android-kerberos-authenticator/blob/master/LICENSE) in the original repository.
