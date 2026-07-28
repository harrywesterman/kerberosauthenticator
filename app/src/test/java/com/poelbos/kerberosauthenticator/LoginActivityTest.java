package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;
import static com.poelbos.kerberosauthenticator.TestHelper.AD_DC;
import static com.poelbos.kerberosauthenticator.TestHelper.AD_DOMAIN;
import static com.poelbos.kerberosauthenticator.TestHelper.PASSWORD;
import static com.poelbos.kerberosauthenticator.TestHelper.TGT;
import static com.poelbos.kerberosauthenticator.TestHelper.USERNAME;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.AccountManager;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.widget.TextView;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public final class LoginActivityTest {
  private Context context;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    shadowOf(AccountManager.get(context)).removeAllAccounts();
    KerberosAccount.setAccountVisibilitySetterForTesting(
        (accountManager, account, packageName, visibility) -> true);
    RestrictionsManager restrictions =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    Bundle managed = new Bundle();
    managed.putString(AccountConfiguration.AD_REALM_KEY, AD_DOMAIN);
    shadowOf(restrictions).setApplicationRestrictions(managed);
  }

  @After
  public void tearDown() {
    KerberosAccount.resetAccountVisibilitySetterForTesting();
  }

  @Test
  public void accountForAuthenticationUsesNewPasswordAndRetainsTicket() {
    KerberosAccount existing = TestHelper.createKerberosAccount();
    KerberosAccountDetails details =
        new KerberosAccountDetails(USERNAME, "new-password", AD_DOMAIN, AD_DC);

    KerberosAccount updated = LoginActivity.accountForAuthentication(existing, details);

    assertThat(new String(updated.copyPassword())).isEqualTo("new-password");
    assertThat(updated.getTicketGrantingTicket()).isEqualTo(TGT);
  }

  @Test
  public void accountForAuthenticationCreatesAccountWhenNoneExists() {
    KerberosAccountDetails details =
        new KerberosAccountDetails(USERNAME, PASSWORD, AD_DOMAIN, AD_DC);

    KerberosAccount account = LoginActivity.accountForAuthentication(null, details);

    assertThat(account.getName()).isEqualTo(USERNAME);
    assertThat(new String(account.copyPassword())).isEqualTo(PASSWORD);
  }

  @Test
  public void accountModeStartsWithEmptyUsernameAndPassword() {
    Intent intent = new Intent(context, LoginActivity.class)
        .putExtra("return_to_account", true);

    LoginActivity activity = Robolectric.buildActivity(LoginActivity.class, intent).setup().get();
    int usernameId = resourceId(activity, "accountUsername");
    int passwordId = resourceId(activity, "accountPassword");

    assertThat(usernameId).isNotEqualTo(0);
    assertThat(passwordId).isNotEqualTo(0);
    assertThat(((TextInputEditText) activity.findViewById(usernameId)).getText().toString())
        .isEmpty();
    assertThat(((TextInputEditText) activity.findViewById(passwordId)).getText().toString())
        .isEmpty();
  }

  @Test
  public void accountModePrefillsManagedUsernameAndKeepsItEditable() {
    setManagedRestrictionsWithUsername("managed-user");

    LoginActivity activity = Robolectric.buildActivity(
        LoginActivity.class, LoginActivity.getAccountSignInIntent(context)).setup().get();
    TextInputEditText username = activity.findViewById(resourceId(activity, "accountUsername"));

    assertThat(username.getText().toString()).isEqualTo("managed-user");
    assertThat(username.isEnabled()).isTrue();

    username.setText("test-user");

    assertThat(username.getText().toString()).isEqualTo("test-user");
  }

  @Test
  public void accountModeSubmitsEditedUsernameInsteadOfExistingAccountName() {
    TestHelper.createKerberosAccount().save(context);
    setManagedRestrictionsWithUsername("managed-user");
    LoginActivity activity = Robolectric.buildActivity(
        LoginActivity.class, LoginActivity.getAccountSignInIntent(context)).setup().get();
    TextInputEditText username = activity.findViewById(resourceId(activity, "accountUsername"));
    TextInputEditText password = activity.findViewById(resourceId(activity, "accountPassword"));

    username.setText("test-user");
    password.setText("test-password");
    activity.findViewById(resourceId(activity, "accountSignInButton")).performClick();

    assertThat(KerberosAccount.getAccount(context).getName()).isEqualTo("test-user");
  }

  @Test
  public void authenticatorModePrefillsManagedUsername() {
    setManagedRestrictionsWithUsername("managed-user");

    LoginActivity activity = Robolectric.buildActivity(
        LoginActivity.class, LoginActivity.getAuthenticateIntent(context, null)).setup().get();
    TextView username = activity.findViewById(resourceId(activity, "editTextUser"));

    assertThat(username.getText().toString()).isEqualTo("managed-user");
  }

  @Test
  public void authenticatorModeKeepsEditedUsernameWhenLoginUiIsShownAgain() {
    setManagedRestrictionsWithUsername("managed-user");
    LoginActivity activity = Robolectric.buildActivity(
        LoginActivity.class, LoginActivity.getAuthenticateIntent(context, null)).setup().get();
    TextView username = activity.findViewById(resourceId(activity, "editTextUser"));
    KerberosAccountDetails configured =
        new KerberosAccountDetails("managed-user", PASSWORD, AD_DOMAIN, AD_DC);

    username.setText("test-user");
    LoginActivity.prefillUsername(username, null, configured);

    assertThat(username.getText().toString()).isEqualTo("test-user");
  }

  @Test
  public void preferredUsernameUsesExistingAccountBeforeManagedUsername() {
    KerberosAccount existing = TestHelper.createKerberosAccount();
    KerberosAccountDetails configured =
        new KerberosAccountDetails("managed-user", PASSWORD, AD_DOMAIN, AD_DC);

    assertThat(LoginActivity.preferredUsername(existing, configured)).isEqualTo(USERNAME);
  }

  @Test
  public void accountModeRequiresUsernameAndPassword() {
    Intent intent = new Intent(context, LoginActivity.class)
        .putExtra("return_to_account", true);
    LoginActivity activity = Robolectric.buildActivity(LoginActivity.class, intent).setup().get();
    int signInId = resourceId(activity, "accountSignInButton");
    int usernameLayoutId = resourceId(activity, "accountUsernameLayout");
    int passwordLayoutId = resourceId(activity, "accountPasswordLayout");

    assertThat(signInId).isNotEqualTo(0);
    activity.findViewById(signInId).performClick();

    assertThat(((TextInputLayout) activity.findViewById(usernameLayoutId)).getError())
        .isNotNull();
    assertThat(((TextInputLayout) activity.findViewById(passwordLayoutId)).getError())
        .isNotNull();
    assertThat(activity.isFinishing()).isFalse();
  }

  @Test
  public void domainEntryResourceIsRemoved() {
    assertThat(context.getResources().getIdentifier(
        "edit_domain", "id", context.getPackageName())).isEqualTo(0);
  }

  private static int resourceId(LoginActivity activity, String name) {
    return activity.getResources().getIdentifier(name, "id", activity.getPackageName());
  }

  private void setManagedRestrictionsWithUsername(String username) {
    RestrictionsManager restrictions =
        (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    Bundle managed = new Bundle();
    managed.putString(AccountConfiguration.AD_REALM_KEY, AD_DOMAIN);
    managed.putString(AccountConfiguration.USERNAME_KEY, username);
    shadowOf(restrictions).setApplicationRestrictions(managed);
  }
}
