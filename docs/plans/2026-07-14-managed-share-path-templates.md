# Managed Share Path Templates Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Resolve a managed SMB `start_path` from the authenticated Kerberos username so one UEM configuration can address per-user directories.

**Architecture:** Keep managed configuration vendor-neutral by storing a restricted inline template in the existing `start_path`. A new pure resolver expands only `${username}` and `${username:last:1}`; `ManagedShare` then normalizes and validates the expanded value, and `KerberosSmbClient` resolves the share once before connecting.

**Tech Stack:** Java 8, Android Enterprise managed restrictions, JUnit 4, Robolectric/Gradle, SMBJ.

---

### Task 1: Pure managed path template resolver

**Files:**
- Create: `app/src/main/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplate.java`
- Create: `app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplateTest.java`

**Step 1: Write the failing expansion tests**

Add tests that call `ManagedPathTemplate.resolve(template, username)` and expect:

```java
assertEquals(
    "users\\2\\isc36512",
    ManagedPathTemplate.resolve(
        "users\\${username:last:1}\\${username}", "isc36512"));
assertEquals("Public\\Policies", ManagedPathTemplate.resolve("Public\\Policies", "isc36512"));
```

Also assert that an empty username, an unknown placeholder, an unterminated placeholder, and a non-numeric final character for `${username:last:1}` throw `IllegalArgumentException` with safe messages that do not include the username.

**Step 2: Run the focused test and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
./gradlew :app:testDebugUnitTest \
  --tests com.poelbos.kerberosauthenticator.files.ManagedPathTemplateTest
```

Expected: compilation fails because `ManagedPathTemplate` does not exist.

**Step 3: Implement the minimal resolver**

Create a package-private utility with:

```java
static String resolve(String template, String username)
```

Scan `${...}` tokens without evaluating arbitrary expressions. Replace exactly `username` and `username:last:1`. Reject every other token and any unmatched `${`. Require an ASCII digit for the last-character token. Never log either input.

**Step 4: Run the focused test and verify GREEN**

Run the command from Step 2.

Expected: all `ManagedPathTemplateTest` tests pass.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplate.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplateTest.java
git commit -m "feat: resolve managed username path templates"
```

### Task 2: Resolve and revalidate managed shares

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/ManagedShare.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedShareTest.java`

**Step 1: Write failing share-resolution tests**

Add tests for:

```java
ManagedShare resolved = templated.resolveForUsername("isc36512");
assertEquals("users\\2\\isc36512", resolved.getStartPath());
```

Verify the original share remains unchanged and that an expanded username containing traversal syntax is rejected by the existing `normalizePath` validation.

**Step 2: Run the focused test and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
./gradlew :app:testDebugUnitTest \
  --tests com.poelbos.kerberosauthenticator.files.ManagedShareTest
```

Expected: compilation fails because `resolveForUsername` does not exist.

**Step 3: Implement immutable share resolution**

Add:

```java
public ManagedShare resolveForUsername(String username) {
  return new ManagedShare(
      id, displayName, host, port, shareName,
      ManagedPathTemplate.resolve(startPath, username));
}
```

Constructing a new `ManagedShare` ensures normalization and traversal checks run after expansion.

**Step 4: Run the focused tests and verify GREEN**

Run both `ManagedShareTest` and `ManagedPathTemplateTest`.

Expected: all tests pass.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/ManagedShare.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedShareTest.java
git commit -m "feat: resolve managed shares for Kerberos users"
```

### Task 3: Connect SMB with the resolved share

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java`

**Step 1: Write a failing connection-boundary test**

Add a package-private pure helper to the intended API through a failing test:

```java
ManagedShare resolved = KerberosSmbClient.resolveManagedShare(template, "isc36512");
assertEquals("users\\2\\isc36512", resolved.getStartPath());
```

Assert an invalid template becomes an `IOException` with a safe configuration message and preserves the original cause.

**Step 2: Run the focused test and verify RED**

Run `KerberosSmbClientTest` with the focused Gradle command.

Expected: compilation fails because `resolveManagedShare` does not exist.

**Step 3: Implement the connection boundary**

Add:

```java
static ManagedShare resolveManagedShare(ManagedShare share, String username) throws IOException
```

Wrap template validation failures in `IOException("The managed share path is invalid", cause)`. At the start of `connect`, after validating the account, resolve with `account.getName()` and use the resolved share for host, port, share name, and the returned client instance.

**Step 4: Run focused and complete tests**

Run `KerberosSmbClientTest`, then:

```bash
./gradlew test
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java
git commit -m "feat: apply user paths before SMB connection"
```

### Task 4: Document the UEM syntax

**Files:**
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `README.md`
- Test: `app/src/test/java/com/poelbos/kerberosauthenticator/files/EnterpriseConfigurationTest.java`

**Step 1: Add a managed-configuration compatibility test**

Verify `EnterpriseConfiguration` preserves `users\\${username:last:1}\\${username}` as the configured `ManagedShare` template.

**Step 2: Run the test and verify current compatibility**

Run `EnterpriseConfigurationTest` and confirm it passes; this is a characterization test because parsing must remain backward-compatible.

**Step 3: Update administrator documentation**

Document that templates are accepted only in `start_path`, list the two tokens, include an organization-neutral example, and explain that static paths are unchanged. Update the managed restriction description to point administrators to the supported syntax.

**Step 4: Run all tests and build release locally**

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
./gradlew test assembleRelease -PreleaseVersion=1.55
```

Expected: `BUILD SUCCESSFUL`.

**Step 5: Commit**

```bash
git add README.md app/src/main/res/values/strings.xml \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/EnterpriseConfigurationTest.java
git commit -m "docs: explain managed share path templates"
```

### Task 5: Publish and verify the managed-device release

**Files:**
- No source changes expected.

**Step 1: Push verified commits to `main`**

```bash
git push origin main
```

**Step 2: Wait for `Build and Publish Release`**

Use `gh run watch <run-id> --exit-status` and require success.

**Step 3: Download and install the signed release**

Download `kerberosauthenticator-1.55.apk` from GitHub release `v1.55`, verify its checksum, and install with:

```bash
adb install -r kerberosauthenticator-1.55.apk
```

Do not install the local debug APK.

**Step 4: Verify the managed share and Chrome regression**

After UEM delivers a template such as `users\\${username:last:1}\\${username}`, clear logcat and open the share. Confirm from sanitized UI state that it opens without exposing directory names. Then force-stop Chrome, clear logcat, reproduce the managed URL, and confirm `SPNEGO_REQUEST` and the expected `SPNEGO_SELECTED` candidate from non-sensitive logs.

**Step 5: Verify repository and device state**

Require a clean `main` synchronized with `origin/main`, version 1.55 on device, and preserved account credentials.
