package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.AccountManager;
import android.accounts.Account;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import androidx.test.core.app.ApplicationProvider;
import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 35)
public final class AuthenticatorStatusActivityTest {
  private Context context;
  private RestrictionsManager restrictions;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    restrictions = (RestrictionsManager) context.getSystemService(Context.RESTRICTIONS_SERVICE);
    shadowOf(AccountManager.get(context)).removeAllAccounts();
    shadowOf(restrictions).setApplicationRestrictions(new Bundle());
  }

  @Test
  public void httpNtlmStatusExplainsPolicyAndCredentialReadiness() {
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(false, false, false))
        .isEqualTo("HTTP NTLMv2: disabled by policy");
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(true, false, false))
        .isEqualTo("HTTP NTLMv2: unavailable (invalid NTLM domain)");
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(true, true, false))
        .isEqualTo("HTTP NTLMv2: unavailable (secure credentials missing)");
    assertThat(AuthenticatorStatusActivity.httpNtlmStatus(true, true, true))
        .isEqualTo(
            "HTTP NTLMv2: ready; TLS channel binding unavailable (Extended Protection unsupported)");
  }

  @Test
  public void httpKerberosStatusExplainsManagedPolicy() {
    assertThat(AuthenticatorStatusActivity.httpKerberosStatus(false))
        .isEqualTo("HTTP Kerberos: disabled by policy");
    assertThat(AuthenticatorStatusActivity.httpKerberosStatus(true))
        .isEqualTo("HTTP Kerberos: ready");
  }

  @Test
  public void signedOutAccountDestinationStartsAccountModeLogin() {
    Bundle managed = new Bundle();
    managed.putString(AccountConfiguration.AD_REALM_KEY, TestHelper.TEST_AD_DOMAIN);
    shadowOf(restrictions).setApplicationRestrictions(managed);

    AuthenticatorStatusActivity activity =
        Robolectric.buildActivity(AuthenticatorStatusActivity.class).setup().get();

    Intent started = shadowOf(activity).getNextStartedActivity();
    assertThat(started.getComponent().getClassName()).isEqualTo(LoginActivity.class.getName());
    assertThat(started.getBooleanExtra("return_to_account", false)).isTrue();
  }

  @Test
  public void missingManagedRealmShowsAdministratorMessageInAccountDestination() {
    AuthenticatorStatusActivity activity =
        Robolectric.buildActivity(AuthenticatorStatusActivity.class).setup().get();

    assertThat(shadowOf(activity).getNextStartedActivity()).isNull();
    int errorId = activity.getResources().getIdentifier(
        "managedConfigurationError", "id", activity.getPackageName());
    assertThat(errorId).isNotEqualTo(0);
    assertThat(activity.findViewById(errorId).getVisibility()).isEqualTo(View.VISIBLE);
  }

  @Test
  public void signedInAccountUsesMaterialStatusLayout() {
    configureManagedRealm();
    addSignedInAccount();

    AuthenticatorStatusActivity activity =
        Robolectric.buildActivity(AuthenticatorStatusActivity.class).setup().get();
    int toolbarId = resourceId(activity, "accountStatusTopAppBar");
    int accountNameId = resourceId(activity, "accountName");
    int kerberosStatusId = resourceId(activity, "http_kerberos_status");

    assertThat(toolbarId).isNotEqualTo(0);
    assertThat(((MaterialToolbar) activity.findViewById(toolbarId)).getTitle().toString())
        .isEqualTo("Account");
    assertThat(((TextView) activity.findViewById(accountNameId)).getText().toString())
        .isEqualTo(TestHelper.USERNAME);
    assertThat(((TextView) activity.findViewById(kerberosStatusId)).getText().toString())
        .isEqualTo("HTTP Kerberos: ready");
    assertThat((View) activity.findViewById(R.id.refresh_btn))
        .isInstanceOf(MaterialButton.class);
    assertThat((View) activity.findViewById(R.id.logout_btn))
        .isInstanceOf(MaterialButton.class);
    assertThat((View) activity.findViewById(R.id.ok_btn)).isNull();
    assertThat((View) activity.findViewById(R.id.editTextUser)).isNull();
    assertThat((View) activity.findViewById(R.id.editTextPw)).isNull();
  }

  @Test
  public void signOutClearsIdentityAndOpensEmptyAccountSignIn() {
    configureManagedRealm();
    addSignedInAccount();
    context.getSharedPreferences(
            AccountConfiguration.LEGACY_LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .putString(AccountConfiguration.USERNAME_KEY, "previous-user")
        .putString(AccountConfiguration.AD_DOMAIN_KEY, TestHelper.TEST_AD_DOMAIN)
        .apply();
    AuthenticatorStatusActivity activity =
        Robolectric.buildActivity(AuthenticatorStatusActivity.class).setup().get();

    activity.findViewById(R.id.logout_btn).performClick();

    assertThat(KerberosAccount.getAccount(context)).isNull();
    assertThat(context.getSharedPreferences(
            AccountConfiguration.LEGACY_LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE).getAll())
        .isEmpty();
    Intent started = shadowOf(activity).getNextStartedActivity();
    assertThat(started.getComponent().getClassName()).isEqualTo(LoginActivity.class.getName());
    assertThat(started.getBooleanExtra(LoginActivity.RETURN_TO_ACCOUNT, false)).isTrue();
  }

  private void configureManagedRealm() {
    Bundle managed = new Bundle();
    managed.putString(AccountConfiguration.AD_REALM_KEY, TestHelper.TEST_AD_DOMAIN);
    shadowOf(restrictions).setApplicationRestrictions(managed);
  }

  private void addSignedInAccount() {
    Bundle data = new Bundle();
    data.putString(KerberosAccount.KEY_AD_DOMAIN, TestHelper.TEST_AD_DOMAIN);
    data.putString(KerberosAccount.KEY_AD_DC, TestHelper.AD_DC);
    data.putString(KerberosAccount.KEY_TGT, TestHelper.TGT_B64);
    AccountManager.get(context).addAccountExplicitly(
        new Account(TestHelper.USERNAME, Constants.KERBEROS_ACCOUNT_TYPE), null, data);
  }

  private static int resourceId(AuthenticatorStatusActivity activity, String name) {
    return activity.getResources().getIdentifier(name, "id", activity.getPackageName());
  }
}
