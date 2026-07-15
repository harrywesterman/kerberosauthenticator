# SMB DFS Domain Controller Failover Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Open managed domain-based DFS shares even when the first discovered server is unreachable or has no CIFS service principal.

**Architecture:** Discover concrete Active Directory domain controllers separately from Kerberos KDCs, build an ordered and deduplicated SMB bootstrap list, and create a fresh SMBJ client per attempt. Retry only failures explicitly classified as candidate-specific; preserve the current direct behavior for ordinary share hosts and the current safe error mapping.

**Tech Stack:** Java 8, Android Enterprise, DNS SRV, Kerberos/JGSS, SMBJ 0.14.0, JUnit 4, Robolectric, Gradle, ADB, GitHub Actions.

---

### Task 1: Active Directory domain-controller discovery

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/internal/DnsKdcDiscovery.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/internal/DnsKdcDiscoveryTest.java`

**Step 1: Write the failing test**

Add a pure lookup-plan test for a new package-private helper:

```java
assertThat(DnsKdcDiscovery.domainControllerLookupPlan("EXAMPLE.TEST"))
    .containsExactly(
        new DnsKdcDiscovery.SrvLookup("_ldap._tcp.dc._msdcs.example.test", 389),
        new DnsKdcDiscovery.SrvLookup("_ldap._tcp.example.test", 389))
    .inOrder();
```

Use value equality on `SrvLookup` so the production discovery path and the test share the same query/port definition.

**Step 2: Run the focused test and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
./gradlew :app:testDebugUnitTest \
  --tests com.poelbos.kerberosauthenticator.internal.DnsKdcDiscoveryTest
```

Expected: compilation fails because `domainControllerLookupPlan` and `SrvLookup` do not exist.

**Step 3: Implement the minimal discovery API**

Add:

```java
public static String discoverDomainControllers(Context context, String realm)
```

It obtains the active network DNS servers, runs the LDAP DC-locator plan in order, and returns the first non-empty priority-ordered host list using the existing `joinHosts`. It returns `null` if no DNS server or locator answer exists. Do not alter `discover`, which remains the Kerberos KDC path.

**Step 4: Run the focused test and verify GREEN**

Run the command from Step 2 and require all `DnsKdcDiscoveryTest` tests to pass.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/internal/DnsKdcDiscovery.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/internal/DnsKdcDiscoveryTest.java
git commit -m "feat: discover SMB bootstrap domain controllers"
```

### Task 2: Candidate selection and retry policy

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java`

**Step 1: Write failing candidate tests**

Replace the single-host expectation with tests for:

```java
assertEquals(
    Arrays.asList("dc01.example.test", "dc02.example.test"),
    KerberosSmbClient.initialConnectionHosts(
        "example.test", "EXAMPLE.TEST",
        "dc01.example.test dc02.example.test", "kdc01.example.test"));
```

Also test case-insensitive deduplication, trailing-dot normalization, KDC fallback when the DC list is empty, and the unchanged singleton list for `files.example.test`.

**Step 2: Write failing retry-classification tests**

Add tests showing that a candidate-specific connection wrapper and nested `KrbException(7)` are retryable, while `KrbException(6)` and SMB access-denied errors are not.

**Step 3: Run the focused test and verify RED**

Run `KerberosSmbClientTest` with the focused Gradle command. Expected: compilation fails because `initialConnectionHosts` and the retry API do not exist.

**Step 4: Implement the pure policy**

Add ordered candidate parsing/normalization and a cause-chain classifier. Domain namespaces prefer AD DC candidates and fall back to KDC candidates only when the DC list is empty. Ordinary hosts return only their managed host. KRB code matching must inspect nested causes without parsing exception messages.

**Step 5: Run the focused test and verify GREEN**

Require all `KerberosSmbClientTest` tests to pass.

**Step 6: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java
git commit -m "feat: select resilient SMB bootstrap candidates"
```

### Task 3: Fresh SMB session per candidate

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java`

**Step 1: Write the failing failover test**

Introduce a package-private candidate-attempt seam and test real orchestration behavior: the first attempt throws a retryable bootstrap failure, the second returns a sentinel, and the result is the second value with attempts recorded in order. Add a second test proving a non-retryable failure stops after one attempt.

**Step 2: Run the focused test and verify RED**

Run `KerberosSmbClientTest`. Expected: compilation fails because candidate orchestration does not exist.

**Step 3: Implement the minimal failover loop**

Configure Kerberos once, discover AD DCs, build candidates, then create a new `SmbConfig`, `SMBClient`, `Connection`, `Session`, and `DiskShare` for each candidate. Close both connection and client after every failed attempt. Classify raw socket/connect failures as candidate-specific and retry nested KRB 7 during authentication. Do not retry failures after a session has authenticated and share connection begins. Log only candidate host and safe numeric/category outcomes.

**Step 4: Run focused and full unit tests**

Run `KerberosSmbClientTest`, then:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
./gradlew test
```

Expected: all tests pass.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClient.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/KerberosSmbClientTest.java
git commit -m "fix: fail over SMB DFS bootstrap controllers"
```

### Task 4: Build, publish, and verify release 1.65

**Files:**
- No source changes expected.

**Step 1: Verify repository and build with JDK 17**

```bash
git diff --check
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
./gradlew test assembleRelease -PreleaseVersion=1.65
```

Require `BUILD SUCCESSFUL`, a clean `main`, and no uncommitted files.

**Step 2: Push verified commits to `main`**

```bash
git push origin main
```

**Step 3: Wait for `Build and Publish Release`**

Find the workflow run for the pushed commit and use `gh run watch <run-id> --exit-status`. Require success and release tag `v1.65` with asset `kerberosauthenticator-1.65.apk`.

**Step 4: Download and install only the signed release APK**

Download the release asset to a temporary directory, verify its SHA-256, and install in place:

```bash
adb install -r /tmp/kerberosauthenticator-1.65.apk
```

Confirm device `versionName=1.65`; do not clear app data and do not install a local debug APK.

**Step 5: Verify all managed drives**

Force-stop the app, clear logcat, launch it, and open each of the four managed drives. Read only sanitized UI status and safe app logs. Require successful directory display for every drive, no credential prompt, and evidence that candidate failover selected a working concrete domain controller.

**Step 6: Verify Chrome SPNEGO regression**

Force-stop Chrome, clear logcat, reproduce the target managed URL, and require non-sensitive `SPNEGO_REQUEST`, `SPN_RESOLUTION`, and successful `SPNEGO_SELECTED`/result logs for the expected host candidate.

**Step 7: Verify final state**

Require `main` synchronized with `origin/main`, a clean worktree, the signed 1.65 release installed, preserved account data, accessible drives, and successful Chrome SPNEGO.
