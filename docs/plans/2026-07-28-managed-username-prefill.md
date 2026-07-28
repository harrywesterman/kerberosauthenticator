# Managed Username Prefill Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restore an editable UEM-managed username default in every login flow and open sign-in automatically when the launcher starts without an account.

**Architecture:** Keep `RestrictionsManager` access centralized in `AccountConfiguration`, which
normalizes the optional `username` restriction and exposes it through `KerberosAccountDetails`.
`LoginActivity` applies the precedence existing account > managed username > empty, while guarding
legacy retries from overwriting an edited field and replacing an existing account only when the
submitted identity changes. `EnterpriseFilesActivity` offers account sign-in once for a cold
launcher instance when a managed realm exists but no Kerberos account does, and preserves that
one-time guard across activity recreation.

**Tech Stack:** Android Java 17, Android managed app restrictions, AccountManager, Robolectric, JUnit 4, Truth, Gradle.

---

### Task 1: Restore the managed username restriction

**Files:**
- Modify: `app/src/main/res/xml/app_restrictions.xml`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/AccountConfiguration.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/AccountConfigurationTest.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivityTest.java`

**Step 1: Write failing configuration tests**

Replace the test that expects a managed username to be ignored and add whitespace coverage:

```java
@Test
public void managedUsernameIsTrimmedAndPreconfigured() {
  restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, "  managed-user  ");
  shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

  accConfig = new AccountConfiguration(context);

  assertThat(accConfig.getAccountDetails().getUsername()).isEqualTo("managed-user");
}

@Test
public void blankManagedUsernameRemainsOptional() {
  restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, "   ");
  shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

  accConfig = new AccountConfiguration(context);

  assertThat(accConfig.hasManagedConfigs()).isTrue();
  assertThat(accConfig.getAccountDetails().getUsername()).isNull();
}
```

Update the existing `BaseAuthenticatorActivityTest` assertions so the initial value and broadcast
update are expected to equal the values in `TestHelper.makeRestrictionsBundle()`.

**Step 2: Run the focused tests and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest \
  --tests com.poelbos.kerberosauthenticator.AccountConfigurationTest \
  --tests com.poelbos.kerberosauthenticator.BaseAuthenticatorActivityTest
```

Expected: FAIL because `AccountConfiguration` still returns a null username.

**Step 3: Read and normalize the managed value**

In `AccountConfiguration.setManagedConfigs()`, after reading the realm, add:

```java
String configuredUsername = restrictionsBundle.getString(USERNAME_KEY);
if (!Strings.isNullOrEmpty(configuredUsername)) {
  String normalizedUsername = configuredUsername.trim();
  if (!normalizedUsername.isEmpty()) username = normalizedUsername;
}
```

Keep `hasManagedConfigs()` dependent only on `ad_realm`; the username remains optional.

**Step 4: Publish the key in the restriction schema**

Immediately after `ad_realm` in `app_restrictions.xml`, add:

```xml
<restriction
    android:key="username"
    android:title="@string/username"
    android:description="@string/mdm_username_description"
    android:restrictionType="string" />
```

Do not add a managed password restriction.

**Step 5: Run the focused tests and verify GREEN**

Run the command from Step 2.

Expected: PASS.

**Step 6: Commit**

```bash
git add app/src/main/res/xml/app_restrictions.xml \
  app/src/main/java/com/poelbos/kerberosauthenticator/AccountConfiguration.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/AccountConfigurationTest.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivityTest.java
git commit -m "feat: restore managed username configuration"
```

### Task 2: Prefill every editable login field

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/LoginActivity.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/LoginActivityTest.java`

**Step 1: Write failing account-login tests**

Add a test helper that installs a restriction bundle containing the realm and a managed username.
Then add:

```java
@Test
public void accountModePrefillsEditableManagedUsername() {
  setManagedUsername("managed-user");
  Intent intent = LoginActivity.getAccountSignInIntent(context);

  LoginActivity activity = Robolectric.buildActivity(LoginActivity.class, intent).setup().get();
  TextInputEditText username = activity.findViewById(resourceId(activity, "accountUsername"));

  assertThat(username.getText().toString()).isEqualTo("managed-user");
  assertThat(username.isEnabled()).isTrue();
  username.setText("test-user");
  assertThat(username.getText().toString()).isEqualTo("test-user");
}
```

Add a second test that launches `LoginActivity.getAuthenticateIntent(context, null)` and asserts
that `editTextUser` contains `managed-user`. This covers the Android/Chrome authenticator
presentation. Add these regression tests as well:

- `accountModeSubmitsEditedUsernameInsteadOfExistingAccountName` edits the account-mode username
  and verifies that authentication uses the edited identity rather than the existing account name.
- `authenticatorModeKeepsEditedUsernameWhenLoginUiIsShownAgain` edits the legacy authenticator
  field and verifies that showing the login UI again does not restore the managed default.

Add a focused pure precedence test by extracting the following package-visible helper:

```java
static String preferredUsername(KerberosAccount existing, KerberosAccountDetails configured) {
  if (existing != null) return existing.getName();
  if (configured == null || configured.getUsername() == null) return "";
  return configured.getUsername();
}
```

Assert that an existing account name wins over a different managed username.

**Step 2: Run the focused tests and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest \
  --tests com.poelbos.kerberosauthenticator.LoginActivityTest
```

Expected: FAIL because both login presentations currently start with an empty username when no
account exists, and the editable-identity safeguards are not implemented.

**Step 3: Implement the precedence and editable-field safeguards**

Add `preferredUsername(...)` to `LoginActivity` with the precedence existing account > managed
username > empty. Add a package-visible helper that writes the preferred value only when the
current field is empty:

```java
static void prefillUsername(
    TextView username, KerberosAccount existing, KerberosAccountDetails configured) {
  if (TextUtils.isEmpty(username.getText())) {
    username.setText(preferredUsername(existing, configured));
  }
}
```

Use it in the legacy `showUserLoginUI()` path so a failed authentication that shows the UI again
does not overwrite a manually edited username:

```java
prefillUsername(
    username, KerberosAccount.getAccount(this), accountConfiguration.getAccountDetails());
```

In `showAccountSignIn()`, initialize the new account-mode field directly from the same precedence
rule:

```java
((TextView) findViewById(R.id.accountUsername)).setText(preferredUsername(
    KerberosAccount.getAccount(this), accountConfiguration.getAccountDetails()));
```

Leave both XML fields enabled and editable. Keep `saveUserCredentials()` unchanged. In
`saveAccountCredentials()`, compare the trimmed submitted username with the existing account and
remove the existing account before initiating authentication when the names differ:

```java
KerberosAccount existing = KerberosAccount.getAccount(this);
if (existing != null && !existing.getName().equals(username)) {
  KerberosAccount.removeAccount(this);
}
```

This ensures that an account-mode edit selects the submitted identity instead of reusing the
previous account name.

**Step 4: Run the focused tests and verify GREEN**

Run the command from Step 2.

Expected: PASS.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/LoginActivity.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/LoginActivityTest.java
git commit -m "feat: prefill managed username in login flows"
```

### Task 3: Offer sign-in automatically from the launcher

**Files:**
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivity.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivityTest.java`

**Step 1: Write failing launcher tests**

Give `EnterpriseFilesActivityTest` a setup method that removes all Kerberos accounts and resets
application restrictions. Add tests for the initial offer, missing realm, pause/resume, recreation,
and an existing account. The recreation regression is:

```java
@Test
public void launcherOffersAccountSignInWithoutAccountWhenRealmIsManaged() {
  setManagedRealm("EXAMPLE.COM");

  EnterpriseFilesActivity activity =
      Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

  Intent started = shadowOf(activity).getNextStartedActivity();
  assertThat(started.getComponent().getClassName()).isEqualTo(LoginActivity.class.getName());
  assertThat(started.getBooleanExtra(LoginActivity.RETURN_TO_ACCOUNT, false)).isTrue();
}

@Test
public void launcherDoesNotOfferSignInWithoutManagedRealm() {
  setManagedRealm("");

  EnterpriseFilesActivity activity =
      Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

  assertThat(shadowOf(activity).getNextStartedActivity()).isNull();
}

@Test
public void launcherOffersSignInOnlyOncePerActivityInstance() {
  setManagedRealm("EXAMPLE.COM");
  ActivityController<EnterpriseFilesActivity> controller =
      Robolectric.buildActivity(EnterpriseFilesActivity.class).setup();
  EnterpriseFilesActivity activity = controller.get();
  shadowOf(activity).getNextStartedActivity();

  controller.pause().resume();

  assertThat(shadowOf(activity).getNextStartedActivity()).isNull();
}

@Test
public void accountSignInIsNotOfferedAgainAfterActivityRecreation() {
  setManagedRealm("EXAMPLE.COM");
  ActivityController<EnterpriseFilesActivity> controller =
      Robolectric.buildActivity(EnterpriseFilesActivity.class).setup();
  EnterpriseFilesActivity activity = controller.get();
  assertThat(shadowOf(activity).getNextStartedActivity()).isNotNull();

  controller.recreate();
  EnterpriseFilesActivity recreatedActivity = controller.get();

  assertThat(shadowOf(recreatedActivity).getNextStartedActivity()).isNull();
}
```

A cold newly created activity without saved state starts with a clear one-time guard and therefore
offers sign-in again. Also add a test with an AccountManager Kerberos account and assert that no
login intent starts.

**Step 2: Run the focused tests and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest \
  --tests com.poelbos.kerberosauthenticator.files.EnterpriseFilesActivityTest
```

Expected: FAIL because the launcher does not start `LoginActivity` and does not yet preserve the
one-time offer across recreation.

**Step 3: Add the guarded launcher redirect**

Add a private saved-state key and an instance field:

```java
private static final String STATE_ACCOUNT_SIGN_IN_OFFERED = "account_sign_in_offered";
private boolean accountSignInOffered;
```

Restore the guard in `onCreate()` and save it in `onSaveInstanceState()`:

```java
accountSignInOffered =
    state != null && state.getBoolean(STATE_ACCOUNT_SIGN_IN_OFFERED, false);

@Override protected void onSaveInstanceState(@NonNull Bundle outState) {
  outState.putBoolean(STATE_ACCOUNT_SIGN_IN_OFFERED, accountSignInOffered);
  super.onSaveInstanceState(outState);
}
```

In `onResume()`, after assigning `configuration` and removing any account whose realm no longer
matches, add:

```java
if (!accountSignInOffered
    && KerberosAccount.getAccount(this) == null
    && !configuration.getRealm().isEmpty()) {
  accountSignInOffered = true;
  startActivity(LoginActivity.getAccountSignInIntent(this));
  return;
}
```

Import `LoginActivity`. Setting the guard before `startActivity` prevents a back-navigation loop;
saved instance state also prevents a configuration-change recreation from offering sign-in again.
A cold new activity without saved state starts with a clear guard and can offer sign-in again.
Checking only the managed realm preserves the current configuration error handling for missing
shares while still making the account login usable.

**Step 4: Run the focused tests and verify GREEN**

Run the command from Step 2.

Expected: PASS.

**Step 5: Commit**

```bash
git add \
  app/src/main/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivity.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivityTest.java
git commit -m "feat: offer sign-in when opening app"
```

### Task 4: Verify the complete change locally

**Files:**
- Modify if needed: `README.md`

**Step 1: Document the optional managed key**

In the managed-configuration section of `README.md`, document:

```text
username (optional): editable default for every Active Directory sign-in field.
```

State that the password is never supplied through this restriction.

**Step 2: Run all unit tests**

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest
```

Expected: `BUILD SUCCESSFUL` with no failing tests.

**Step 3: Assemble the local APK**

```bash
JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home \
  ./gradlew assembleDebug
```

Expected: `BUILD SUCCESSFUL` and
`app/build/outputs/apk/debug/app-debug.apk`.

**Step 4: Inspect the final diff**

```bash
git diff --check
git status --short
git log --oneline -6
```

Expected: only the intended README and implementation-plan changes remain uncommitted; no
whitespace errors are reported.

**Step 5: Commit documentation and plan**

```bash
git add README.md docs/plans/2026-07-28-managed-username-prefill.md
git commit -m "docs: explain managed username prefill"
```

### Task 5: Publish and verify the managed release

**Files:**
- No repository files.

**Step 1: Push the verified commits on `main`**

```bash
git push origin main
```

Expected: `main` updates successfully. Do not create or switch branches.

**Step 2: Wait for the release workflow**

Monitor `Build and Publish Release` until it succeeds. Confirm that the workflow derived the next
`major.minor` release version and published exactly:

```text
kerberosauthenticator-<version>.apk
```

**Step 3: Install the signed release in place**

Download the APK asset from that GitHub release and run:

```bash
adb install -r kerberosauthenticator-<version>.apk
```

Do not substitute the local debug APK. The in-place update must preserve existing app data and
stored credentials.

**Step 4: Verify managed-device behavior**

Configure UEM `username` with the enrolled AD username and synchronize the device. Verify:

- a signed-out cold app start opens account sign-in;
- both login presentations show the managed username;
- the username remains editable and a test override is used for authentication;
- going back, resuming, or recreating the same launcher does not immediately reopen sign-in;
- a cold new launcher instance without saved state offers sign-in again when still signed out;
- an existing signed-in account is not replaced by the managed default.

**Step 5: Verify Chrome SPNEGO**

Force-stop Chrome, clear logcat, reproduce the managed target URL, and use only non-sensitive logs
to confirm that Chrome requested SPNEGO and the expected SPN candidate was selected.
