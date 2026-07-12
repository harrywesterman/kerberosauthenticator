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
import static org.junit.Assert.assertFalse;
import static org.robolectric.Shadows.shadowOf;

import android.content.Context;
import android.content.ContextWrapper;
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
            EditConfigurationActivity.LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE)
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
  public void testHasNoConfigs() {
    restrictionsBundle.clear();
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertFalse(accConfig.hasManagedConfigs());
  }

  @Test
  public void testPartialConfigSetupIsConsideredFalse() {
    Set<String> testKeys = Sets.newHashSet("adDomain");
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
  public void testLocalConfigIsUsedWhenManagedConfigMissing() {
    shadowOf(restrictionsManager).setApplicationRestrictions(new Bundle());
    SharedPreferences prefs =
        context.getSharedPreferences(
            EditConfigurationActivity.LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE);
    prefs
        .edit()
        .putString(AccountConfiguration.USERNAME_KEY, TestHelper.TEST_USERNAME)
        .putString(AccountConfiguration.PASSWORD_KEY, TestHelper.TEST_PASSWORD)
        .putString(AccountConfiguration.AD_DOMAIN_KEY, TestHelper.TEST_AD_DOMAIN)
        .apply();
    accConfig = new AccountConfiguration(context);
    assertTrue(accConfig.hasManagedConfigs());
  }

  @Test
  public void testNoPasswordConfigIsValid() {
    restrictionsBundle.remove("password");
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    accConfig = new AccountConfiguration(context);
    assertTrue(accConfig.hasManagedConfigs());
    assertFalse(accConfig.hasManagedConfigPassword());
  }

}
