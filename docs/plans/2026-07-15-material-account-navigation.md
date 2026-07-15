# Material Account Navigation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the files-screen account button with a Material 3 overflow-menu destination and provide a polished account flow where users enter username and password while the AD realm comes only from MDM.

**Architecture:** Keep `EnterpriseFilesActivity` as the launcher and expose `AuthenticatorStatusActivity` as the single logical Account destination. The destination delegates to `LoginActivity` only for credential entry, returning to account status after successful user-initiated authentication. Remove all local realm fallback and domain-entry UI while preserving the existing Kerberos, Chrome SPNEGO, SMB/DFS, credential-vault, and authenticator-response paths.

**Tech Stack:** Android Java, Material Components 1.12 / Material 3 XML views, View Binding, Android AccountManager, RestrictionsManager, Robolectric, JUnit 4, Gradle with JDK 17.

---

### Task 1: Make the managed realm the only domain source

**Files:**
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/AccountConfigurationTest.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivityTest.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/AccountConfiguration.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/EditConfigurationActivity.java`

**Step 1: Write failing configuration tests**

Replace the legacy-local-config expectation with tests that prove an empty RestrictionsManager bundle is invalid even when local preferences contain a username and domain, and that a managed `username` restriction is not used for a new account:

```java
@Test
public void localUsernameAndDomainDoNotReplaceManagedRealm() {
  shadowOf(restrictionsManager).setApplicationRestrictions(new Bundle());
  context.getSharedPreferences(EditConfigurationActivity.LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(AccountConfiguration.USERNAME_KEY, "previous-user")
      .putString(AccountConfiguration.AD_DOMAIN_KEY, TestHelper.TEST_AD_DOMAIN)
      .apply();

  accConfig = new AccountConfiguration(context);

  assertThat(accConfig.hasManagedConfigs()).isFalse();
  assertThat(accConfig.getAccountDetails()).isNull();
}

@Test
public void managedRealmDoesNotPreconfigureUsername() {
  restrictionsBundle.putString(AccountConfiguration.AD_REALM_KEY, TestHelper.TEST_AD_DOMAIN);
  restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, "managed-user");
  shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

  accConfig = new AccountConfiguration(context);

  assertThat(accConfig.getAccountDetails().getUsername()).isNull();
}
```

Update the base-activity managed-config assertions to expect a null username and the managed realm.

**Step 2: Run the tests and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest --tests '*AccountConfigurationTest' \
  --tests '*BaseAuthenticatorActivityTest' --console=plain
```

Expected: FAIL because local preferences still provide the domain and the managed username is still copied.

**Step 3: Implement the managed-realm-only policy**

In `AccountConfiguration.setManagedConfigs()`:

- delete the block that copies `username` and `adDomain` from `kerberos_local_config`;
- accept `ad_realm` as the account realm and stop falling back to `adDomain`;
- do not copy `USERNAME_KEY` into `username` for managed enterprise sign-in;
- keep the legacy password key behavior only where an external authenticator request explicitly requires backward compatibility and no managed shares exist;
- clear obsolete local identity preferences when detected.

Leave `getAccountDetails()` returning `new KerberosAccountDetails(null, password, adDomain, adDomainController)` until the user-entered username is combined in `LoginActivity`.

Reduce `EditConfigurationActivity` to a non-editable managed-configuration-missing route temporarily; Task 3 removes it from user navigation.

**Step 4: Run the focused tests and verify GREEN**

Run the command from Step 2. Expected: PASS.

**Step 5: Commit**

```bash
git add app/src/main/java/com/poelbos/kerberosauthenticator/AccountConfiguration.java \
  app/src/main/java/com/poelbos/kerberosauthenticator/EditConfigurationActivity.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/AccountConfigurationTest.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivityTest.java
git commit -m "fix: require managed realm for account sign-in"
```

### Task 2: Add the Material top app bar and Account menu

**Files:**
- Create: `app/src/main/res/menu/menu_enterprise_files.xml`
- Create: `app/src/main/res/drawable/ic_more_vert_24dp.xml`
- Modify: `app/src/main/res/layout/activity_enterprise_files.xml`
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivity.java`
- Create: `app/src/test/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivityTest.java`

**Step 1: Write a failing navigation test**

Use Robolectric to create the activity, locate `R.id.topAppBar`, invoke `R.id.action_account`, and assert that the next started activity targets `AuthenticatorStatusActivity`:

```java
@Test
public void accountOverflowItemOpensAccountDestination() {
  EnterpriseFilesActivity activity =
      Robolectric.buildActivity(EnterpriseFilesActivity.class).setup().get();

  MaterialToolbar toolbar = activity.findViewById(R.id.topAppBar);
  assertThat(toolbar.getMenu().findItem(R.id.action_account)).isNotNull();
  toolbar.getMenu().performIdentifierAction(R.id.action_account, 0);

  Intent started = shadowOf(activity).getNextStartedActivity();
  assertThat(started.getComponent().getClassName())
      .isEqualTo(AuthenticatorStatusActivity.class.getName());
}
```

Add a layout assertion that `signInButton` no longer exists and that the file action row contains only contextual file actions.

**Step 2: Run the test and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest --tests '*EnterpriseFilesActivityTest' --console=plain
```

Expected: test compilation or assertion failure because the toolbar and menu resources do not exist.

**Step 3: Implement the top app bar**

Create a menu with a single item:

```xml
<item
    android:id="@+id/action_account"
    android:title="@string/account"
    app:showAsAction="never" />
```

Replace the oversized decorative header with `MaterialToolbar` `@+id/topAppBar`, using the Material 3 surface/on-surface palette, title `Enterprise Files`, and `app:menu="@menu/menu_enterprise_files"`. Retain the subtitle as a compact supporting `TextView` immediately below the bar. Remove `signInButton` from XML and all button text/listener updates from Java.

Configure navigation in `onCreate()`:

```java
binding.topAppBar.setOnMenuItemClickListener(item -> {
  if (item.getItemId() == R.id.action_account) {
    startActivity(new Intent(this, AuthenticatorStatusActivity.class));
    return true;
  }
  return false;
});
```

**Step 4: Run the focused test and verify GREEN**

Run the command from Step 2. Expected: PASS.

**Step 5: Commit**

```bash
git add app/src/main/res/menu/menu_enterprise_files.xml \
  app/src/main/res/drawable/ic_more_vert_24dp.xml \
  app/src/main/res/layout/activity_enterprise_files.xml \
  app/src/main/res/values/strings.xml \
  app/src/main/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivity.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/files/EnterpriseFilesActivityTest.java
git commit -m "feat: move account access into files menu"
```

### Task 3: Build the signed-out account destination

**Files:**
- Create: `app/src/main/res/layout/activity_account_login.xml`
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/AuthenticatorStatusActivity.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/LoginActivity.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivity.java`
- Modify: `app/src/main/AndroidManifest.xml`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/LoginActivityTest.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/AuthenticatorStatusActivityTest.java`

**Step 1: Write failing account-state tests**

Add Robolectric tests proving:

- menu-originated account access with no account opens `LoginActivity` in account mode;
- the username and password fields are both visible and empty;
- no `edit_domain` or managed-realm field exists in the account layout;
- blank username/password submission keeps the activity open and sets field-level Material errors;
- missing `ad_realm` stays on an account screen with a managed-configuration error instead of opening `EditConfigurationActivity`.

Use an explicit extra exposed through a helper:

```java
Intent intent = LoginActivity.getAccountSignInIntent(context);
assertThat(intent.getBooleanExtra(LoginActivity.RETURN_TO_ACCOUNT, false)).isTrue();
```

**Step 2: Run the tests and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest --tests '*LoginActivityTest' \
  --tests '*AuthenticatorStatusActivityTest' --console=plain
```

Expected: FAIL because account mode, the new Material fields, and the missing-policy state do not exist.

**Step 3: Implement account-mode sign-in**

Create `activity_account_login.xml` with:

- a Material top app bar titled `Account`;
- a concise sign-in heading and supporting text;
- `TextInputLayout` / `TextInputEditText` controls for username and password;
- a full-width Material primary `Sign in` button;
- an inline managed-configuration error state.

Do not render the realm or a domain input. Start every user-initiated signed-out session with both fields empty. Add `getAccountSignInIntent()` and `RETURN_TO_ACCOUNT`; after a successful TGT in account mode, navigate to `AuthenticatorStatusActivity` with clear-top semantics. Keep AccountManager/Chrome-initiated intents on their existing result path.

Change `AuthenticatorStatusActivity` so:

- missing MDM realm renders the inline administrator-facing error;
- no account starts `getAccountSignInIntent()`;
- an existing account renders status.

Remove `EditConfigurationActivity` from the manifest and ensure no user path launches it. Keep only any constants still required to clear data migrated from old releases, or replace them with a narrowly named legacy preference constant.

**Step 4: Run the focused tests and verify GREEN**

Run the command from Step 2. Expected: PASS.

**Step 5: Commit**

```bash
git add app/src/main/res/layout/activity_account_login.xml \
  app/src/main/res/values/strings.xml app/src/main/AndroidManifest.xml \
  app/src/main/java/com/poelbos/kerberosauthenticator/AuthenticatorStatusActivity.java \
  app/src/main/java/com/poelbos/kerberosauthenticator/LoginActivity.java \
  app/src/main/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivity.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/LoginActivityTest.java \
  app/src/test/java/com/poelbos/kerberosauthenticator/AuthenticatorStatusActivityTest.java
git commit -m "feat: add managed account sign-in destination"
```

### Task 4: Restyle the signed-in account status with Material 3

**Files:**
- Replace: `app/src/main/res/layout/authenticator.xml`
- Remove: `app/src/main/res/layout/authenticator_header.xml`
- Remove: `app/src/main/res/layout/authenticator_footer.xml`
- Modify: `app/src/main/res/values/colors_enterprise.xml`
- Modify: `app/src/main/res/values/dimensions.xml`
- Modify: `app/src/main/res/values/strings.xml`
- Modify: `app/src/main/res/values/styles.xml`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/BaseAuthenticatorActivity.java`
- Modify: `app/src/main/java/com/poelbos/kerberosauthenticator/AuthenticatorStatusActivity.java`
- Modify: `app/src/test/java/com/poelbos/kerberosauthenticator/AuthenticatorStatusActivityTest.java`

**Step 1: Write failing status-layout tests**

Create an account in Robolectric and assert that the status screen contains:

- a top app bar titled `Account`;
- the signed-in username;
- ticket and refresh status cards/sections;
- Material `Refresh` and outlined `Sign out` buttons;
- no dismiss footer, no editable username/password, and no visible realm/domain control.

Add a sign-out test that clicks `Sign out` and proves the Android account, credential vault, legacy local identity preferences, and file cache are cleared, then verifies the next signed-out login fields are empty.

**Step 2: Run the status tests and verify RED**

Run:

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
  ./gradlew testDebugUnitTest --tests '*AuthenticatorStatusActivityTest' --console=plain
```

Expected: FAIL against the legacy AppCompat header/footer layout.

**Step 3: Implement the signed-in Material layout**

Replace the include-based layout with a scrollable Material 3 screen using a compact top app bar, account summary, status sections, and bottom actions. Move all user-visible strings from Java/XML literals into `strings.xml`, use sentence case, and use theme colors instead of literal hex colors where practical.

Update `showAccountInfo()`, button helpers, status bindings, and logout navigation for the new IDs. `onLogoutRequested()` must:

```java
KerberosAccount.removeAccount(this);
new EnterpriseFileCache(this).cleanup();
getSharedPreferences(LEGACY_LOCAL_CONFIG_PREFS_NAME, MODE_PRIVATE).edit().clear().apply();
startActivity(LoginActivity.getAccountSignInIntent(this)
    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP));
finish();
```

Do not display the MDM realm as a field or account attribute.

**Step 4: Run focused account tests and verify GREEN**

Run the command from Step 2, then also run `*BaseAuthenticatorActivityTest` and `*LoginActivityTest`. Expected: PASS.

**Step 5: Commit**

```bash
git add app/src/main/res app/src/main/java/com/poelbos/kerberosauthenticator \
  app/src/test/java/com/poelbos/kerberosauthenticator
git commit -m "style: modernize account screens with material design"
```

### Task 5: Verify regressions and build locally

**Files:**
- Modify only files required by failures found during verification.

**Step 1: Run formatting and repository checks**

```bash
git diff --check
git status --short
git branch --show-current
```

Expected: no whitespace errors and branch `main`.

**Step 2: Run the complete unit suite and assemble the APK with JDK 17**

```bash
JAVA_HOME=/opt/homebrew/Cellar/openjdk@17/17.0.19/libexec/openjdk.jdk/Contents/Home \
ANDROID_HOME=/opt/homebrew/share/android-commandlinetools \
  ./gradlew test assembleDebug -PreleaseVersion=1.71 --console=plain
```

Expected: `BUILD SUCCESSFUL`, including all app variants and `openjdk-kerberos` tests.

**Step 3: Fix failures with a RED/GREEN regression test**

For every discovered defect, add or tighten the smallest failing test, observe the failure, implement the minimum correction, and rerun the focused and full suites.

**Step 4: Commit verification fixes if needed**

```bash
git add <only-the-files-changed-for-the-fix>
git commit -m "fix: complete account navigation verification"
```

### Task 6: Publish and validate the signed managed-device release

**Files:**
- No source files unless device validation reveals a defect, in which case return to TDD before publishing another release.

**Step 1: Push verified `main`**

```bash
git push origin main
```

**Step 2: Wait for the release workflow**

Use `gh run list` / `gh run watch` to require a successful `Build and Publish Release` run for the exact pushed commit. Derive the resulting version from the release; do not assume the example `1.71` if intervening releases exist.

**Step 3: Download and verify the signed release asset**

Download the exact `kerberosauthenticator-<version>.apk` GitHub release asset and verify its SHA-256 against release metadata when available. Do not install the local debug APK.

**Step 4: Install in place**

```bash
adb install -r /absolute/path/to/kerberosauthenticator-<version>.apk
```

Confirm the installed `versionName` and that the existing managed restrictions remain present.

**Step 5: Validate the account UI on device**

Verify:

1. files screen has the compact Material app bar and no account button in the action row;
2. `⋮` → `Account` opens the signed-in status screen;
3. sign-out removes identity and opens a form with empty username and password;
4. no domain field is present anywhere;
5. invalid blank submission shows field errors;
6. entering the user-provided credentials signs in and returns to account status.

Never print credentials, usernames, realms, share names, or internal hosts in command output.

**Step 6: Validate managed shares and Chrome SPNEGO**

Open all managed shares in sequence. Then force-stop Chrome, clear logcat, reproduce the target URL, and verify from redacted logs that:

- Chrome requested SPNEGO;
- at least one SPN candidate was produced;
- the expected candidate was selected;
- HTTP Kerberos authentication returned code `0`.

**Step 7: Final repository verification**

```bash
git fetch origin main
git rev-list --left-right --count origin/main...HEAD
git status --short
git diff --check
git branch --show-current
```

Expected: `0 0`, clean worktree, no whitespace errors, branch `main`.
