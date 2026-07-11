# Account Password Refresh Implementation Plan

> **For Codex:** Use the executing-plans workflow task-by-task.

**Goal:** Persist a password entered for an existing Kerberos account before renewing its TGT and querying LDAP for SPN aliases.

**Architecture:** Add a small `KerberosAccount` operation that returns an account with a replacement password while retaining the current realm, controller and serialized TGT. `LoginActivity` will use it when it receives credentials from the password form. No host, realm, or organization-specific behavior is added.

**Tech Stack:** Android AccountManager, Java, Robolectric, Gradle with JDK 17.

---

### Task 1: Cover password replacement without losing the TGT

**Files:**
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/KerberosAccountTest.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/KerberosAccount.java`

**Step 1: Write the failing test**

Add a test that creates an account with a known password and TGT, replaces its password, saves it, then asserts the replacement password and original TGT are stored in Account Manager.

**Step 2: Run the focused test to verify it fails**

Run: `./gradlew test --tests com.poelbos.kerberosauthenticator.KerberosAccountTest`

Expected: the test does not compile because `withPassword` does not exist.

**Step 3: Implement the minimal code**

Add `KerberosAccount withPassword(String password)` which retains account name, domain, controller, and serialized TGT.

**Step 4: Run the focused test to verify it passes**

Run the same Gradle command and expect success.

### Task 2: Use the replacement password in the login flow

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/LoginActivity.java`

**Step 1: Apply the minimal login change**

When a password was passed into `initiateUserAuthenticationTask` for an existing account, replace that account's password before saving and creating `UserAuthenticationTask`.

**Step 2: Run all unit tests**

Run: `./gradlew test --no-daemon` with JDK 17.

### Task 3: Verify on the device

**Step 1: Build and install the debug APK**

Run `assembleDebug`, install using adb, then log in once with the current AD password.

**Step 2: Test the browser ticket flow**

Open the working reference host and the failing virtual host. Check Android logs for a successful LDAP bind or a distinct, server-side SPN failure. The release keystore remains untracked.
