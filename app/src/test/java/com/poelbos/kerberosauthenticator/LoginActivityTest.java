package com.poelbos.kerberosauthenticator;

import static com.google.common.truth.Truth.assertThat;
import static com.poelbos.kerberosauthenticator.TestHelper.AD_DC;
import static com.poelbos.kerberosauthenticator.TestHelper.AD_DOMAIN;
import static com.poelbos.kerberosauthenticator.TestHelper.PASSWORD;
import static com.poelbos.kerberosauthenticator.TestHelper.TGT;
import static com.poelbos.kerberosauthenticator.TestHelper.USERNAME;

import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public final class LoginActivityTest {
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
}
