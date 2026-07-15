package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.AccountManager;
import android.content.Context;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.view.View;
import androidx.test.core.app.ApplicationProvider;
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
}
