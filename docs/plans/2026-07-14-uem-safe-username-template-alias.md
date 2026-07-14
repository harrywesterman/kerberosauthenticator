# UEM-safe Username Template Alias Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Support `${username:full}` as a UEM-safe alias for the authenticated username in managed SMB starting-folder templates.

**Architecture:** Extend the existing deliberately small `ManagedPathTemplate` allowlist with one alias that resolves through the same username branch as `${username}`. Preserve every existing placeholder and validation rule, and document forward-slash UEM syntax because `ManagedShare` already normalizes it to SMB separators.

**Tech Stack:** Android Java, JUnit 4, Gradle with JDK 17, GitHub Actions release workflow, ADB.

---

### Task 1: Prove the missing alias

**Files:**
- Test: `app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplateTest.java`

**Step 1: Write the failing test**

Add a test that resolves `users/${username:last:1}/${username:full}` for `isc36512` and expects `users/2/isc36512`.

**Step 2: Run the focused test to verify it fails**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home ./gradlew testDebugUnitTest --tests com.poelbos.kerberosauthenticator.files.ManagedPathTemplateTest
```

Expected: FAIL because `username:full` is unsupported.

### Task 2: Implement the alias

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplate.java`
- Test: `app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplateTest.java`

**Step 1: Add the alias constant and allow it**

Add `username:full` to the explicit allowlist and resolve it through the existing full-username branch.

**Step 2: Run the focused test**

Run the Task 1 command.

Expected: PASS.

**Step 3: Run all unit tests**

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home ./gradlew testDebugUnitTest
```

Expected: BUILD SUCCESSFUL with no failing tests.

### Task 3: Document and build

**Files:**
- Modify: `README.md`

**Step 1: Document the UEM-safe template**

Document `users/${username:last:1}/${username:full}`, the resolved example, and backward compatibility with `${username}`.

**Step 2: Assemble the release with JDK 17**

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home ./gradlew assembleRelease -PreleaseVersion=1.60
```

Expected: BUILD SUCCESSFUL.

**Step 3: Commit the verified implementation**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplate.java app/src/test/java/com/poelbos/kerberosauthenticator/files/ManagedPathTemplateTest.java README.md docs/plans/2026-07-14-uem-safe-username-template-alias.md
git commit -m "feat: add UEM-safe username template alias"
```

### Task 4: Publish and test the managed release

**Files:**
- No repository files.

**Step 1: Push `main` and wait for `Build and Publish Release`**

Push the verified commits to `main`, monitor the workflow to success, and identify the newly generated version from the release.

**Step 2: Download and install the signed release asset**

Download `kerberosauthenticator-<version>.apk` from the GitHub release and install it with `adb install -r` so stored credentials remain intact.

**Step 3: Update the UEM H-share template**

Use `users/${username:last:1}/${username:full}`, synchronize Intelligent Hub, and verify Android received the intact template.

**Step 4: Verify H and Chrome**

Open H and confirm its directory rows load. Force-stop Chrome, clear logcat, reproduce the managed URL, and confirm the non-sensitive SPNEGO request/candidate behavior expected for the current policy.
