/*
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.poelbos.kerberosauthenticator;

import static junit.framework.TestCase.assertTrue;
import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertFalse;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.test.core.app.ApplicationProvider;
import com.google.common.collect.Sets;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/**
 * Tests {@link AccountConfiguration}.
 */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 26)
public class AccountConfigurationTest {

  private RestrictionsManager restrictionsManager;
  private Bundle restrictionsBundle;
  private ContextWrapper context;
  private AccountConfiguration accConfig;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    restrictionsManager = (RestrictionsManager) context.getSystemService(
        context.getSystemServiceName(RestrictionsManager.class));
    restrictionsBundle = TestHelper.makeRestrictionsBundle();
    context.getSharedPreferences(
            AccountConfiguration.LEGACY_LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .apply();
  }

  @Test
  public void testHasConfigs() {
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertTrue(accConfig.hasManagedConfigs());
  }

  @Test
  public void managedDeploymentRequiresRealmFromRestrictionsManager() {
    restrictionsBundle.putString(AccountConfiguration.AD_REALM_KEY, TestHelper.TEST_AD_DOMAIN);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.isManagedDeployment()).isTrue();
  }

  @Test
  public void testHasNoConfigs() {
    restrictionsBundle.clear();
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertFalse(accConfig.hasManagedConfigs());
  }

  @Test
  public void testPartialConfigSetupIsConsideredFalse() {
    Set<String> testKeys = Sets.newHashSet(AccountConfiguration.AD_REALM_KEY);
    for (String key : testKeys) {
      restrictionsBundle = TestHelper.makeRestrictionsBundle();
      restrictionsBundle.remove(key);
      shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
      accConfig = new AccountConfiguration(context);
      assertFalse(accConfig.hasManagedConfigs());
    }
  }

  @Test
  public void testManagedRealmDoesNotRequireUsername() {
    restrictionsBundle.remove(AccountConfiguration.USERNAME_KEY);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertTrue(accConfig.hasManagedConfigs());
  }

  @Test
  public void localUsernameAndDomainDoNotReplaceManagedRealm() {
    shadowOf(restrictionsManager).setApplicationRestrictions(new Bundle());
    SharedPreferences prefs =
        context.getSharedPreferences(
            AccountConfiguration.LEGACY_LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE);
    prefs
        .edit()
        .putString(AccountConfiguration.USERNAME_KEY, TestHelper.TEST_USERNAME)
        .putString(AccountConfiguration.PASSWORD_KEY, TestHelper.TEST_PASSWORD)
        .putString(AccountConfiguration.AD_DOMAIN_KEY, TestHelper.TEST_AD_DOMAIN)
        .apply();
    accConfig = new AccountConfiguration(context);
    assertFalse(accConfig.hasManagedConfigs());
    assertThat(accConfig.getAccountDetails()).isNull();
    assertThat(prefs.contains(AccountConfiguration.PASSWORD_KEY)).isFalse();
  }

  @Test
  public void managedRealmDoesNotPreconfigureUsername() {
    restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, "managed-user");
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.getAccountDetails().getUsername()).isNull();
  }

  @Test
  public void testNoPasswordConfigIsValid() {
    restrictionsBundle.remove("password");
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertTrue(accConfig.hasManagedConfigs());
    assertFalse(accConfig.hasManagedConfigPassword());
  }

  @Test
  public void httpNtlmIsDisabledByDefault() {
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.isHttpNtlmEnabled()).isFalse();
    assertThat(accConfig.getNtlmDomain()).isNull();
    assertThat(accConfig.isHttpNtlmConfigured()).isFalse();
  }

  @Test
  public void httpKerberosIsEnabledByDefaultForExistingDeployments() {
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.isHttpKerberosEnabled()).isTrue();
  }

  @Test
  public void httpKerberosCanBeDisabledByManagedPolicy() {
    restrictionsBundle.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.isHttpKerberosEnabled()).isFalse();
  }

  @Test
  public void managedConfigurationBroadcastRefreshesHttpKerberosPolicy() {
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertThat(accConfig.isHttpKerberosEnabled()).isTrue();

    restrictionsBundle.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig
        .getReceiver()
        .onReceive(context, new Intent(Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED));

    assertThat(accConfig.isHttpKerberosEnabled()).isFalse();
  }

  @Test
  public void httpNtlmRequiresValidNetbiosDomain() {
    restrictionsBundle.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, true);
    restrictionsBundle.putString(AccountConfiguration.NTLM_DOMAIN_KEY, "corp.example.com");
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.isHttpNtlmEnabled()).isTrue();
    assertThat(accConfig.getNtlmDomain()).isNull();
    assertThat(accConfig.isHttpNtlmConfigured()).isFalse();
    assertThat(accConfig.hasManagedConfigs()).isTrue();
  }

  @Test
  public void httpNtlmNormalizesManagedNetbiosDomain() {
    restrictionsBundle.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, true);
    restrictionsBundle.putString(AccountConfiguration.NTLM_DOMAIN_KEY, " corp ");
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    accConfig = new AccountConfiguration(context);

    assertThat(accConfig.isHttpNtlmEnabled()).isTrue();
    assertThat(accConfig.getNtlmDomain()).isEqualTo("CORP");
    assertThat(accConfig.isHttpNtlmConfigured()).isTrue();
  }

}
