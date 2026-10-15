package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;
import android.content.Context;
import android.content.Intent;
import androidx.test.core.app.ApplicationProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public final class AuthenticatorActivityAccessTest {
  private Context context;

  @Before public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    context.getSharedPreferences("authenticator_activity_requests", Context.MODE_PRIVATE)
        .edit().clear().commit();
  }

  @Test public void missingAndForgedCapabilitiesAreRejected() {
    Intent intent = new Intent(context, LoginActivity.class);
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isFalse();
    intent.putExtra("authenticator_activity_capability", "forged");
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isFalse();
  }

  @Test public void issuedCapabilityWorksOnlyOnce() {
    Intent intent = LoginActivity.getAuthenticateIntent(context, null, "portal.example.com");
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isTrue();
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isFalse();
  }

  @Test public void accountCreationCannotBeChangedIntoTicketRequest() {
    Intent intent = LoginActivity.getAuthenticateIntent(context, null);
    intent.putExtra(Constants.SERVICE_NAME, "portal.example.com");
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isFalse();
  }

  @Test public void changingLoginModeInvalidatesCapability() {
    Intent intent = LoginActivity.getAccountSignInIntent(context);
    intent.putExtra(LoginActivity.RETURN_TO_ACCOUNT, false);
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isFalse();
  }

  @Test public void expiredCapabilityIsRejected() {
    Intent intent = LoginActivity.getAccountSignInIntent(context);
    String token = intent.getStringExtra("authenticator_activity_capability");
    context.getSharedPreferences("authenticator_activity_requests", Context.MODE_PRIVATE)
        .edit().putString(token, "0|expired").commit();
    assertThat(AuthenticatorActivityAccess.consume(context, intent)).isFalse();
  }
}
