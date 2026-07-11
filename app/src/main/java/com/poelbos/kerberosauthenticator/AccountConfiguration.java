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

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.RestrictionsManager;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.VisibleForTesting;
import android.util.Log;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import com.google.common.base.Strings;

/**
 * This class obtains and updates Kerberos account details from managed restrictions.
 *
 * <p>When a password is not supplied through managed restrictions, this class will obtain it from
 * the user interface, which will prompt the user to enter a password.
 *
 * <p>A DPC can set account details in managed restrictions and this is the only way through which
 * the Kerberos Authenticator will obtain credentials to generate tickets. Users cannot add their
 * own authentication credentials.
 */
public class AccountConfiguration {

  // Managed configs keys
  static final String AD_DOMAIN_KEY = "adDomain";
  static final String AD_REALM_KEY = "ad_realm";
  static final String USERNAME_KEY = "username";
  static final String PASSWORD_KEY = "password";
  static final String SENSITIVE_DEBUG_DATA_KEY = "sensitiveDebugData";
  // Managed configuration
  private final Context context;
  private final RestrictionsManager restrictionsManager;
  private final ManagedConfigsBroadcastReceiver restrictionsReceiver;
  // Manage configs fields
  private String username;
  private String password;
  private String adDomain;
  private String adDomainController;
  private boolean debugWithSensitiveData = false;

  AccountConfiguration(@NonNull Context context) {
    // Managed configs initialisation and listener definition
    this.context = context;
    restrictionsManager = (RestrictionsManager) context.getSystemService(
        Context.RESTRICTIONS_SERVICE);
    IntentFilter restrictionsFilter =
        new IntentFilter(Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED);
    restrictionsReceiver = new ManagedConfigsBroadcastReceiver();
    context.registerReceiver(restrictionsReceiver, restrictionsFilter);
    setManagedConfigs();
  }

  private void setManagedConfigs() {
    username = null;
    password = null;
    adDomain = null;
    adDomainController = "";
    debugWithSensitiveData = false;

    Bundle restrictionsBundle = restrictionsManager.getApplicationRestrictions();
    if (restrictionsBundle == null) {
      restrictionsBundle = new Bundle();
    }
    if (restrictionsBundle.isEmpty()) {
      SharedPreferences localPrefs = context
          .getSharedPreferences(EditConfigurationActivity.LOCAL_CONFIG_PREFS_NAME, Context.MODE_PRIVATE);
      String localUser = localPrefs.getString(USERNAME_KEY, null);
      String localDomain = localPrefs.getString(AD_DOMAIN_KEY, null);
      if (localUser != null && localDomain != null) {
        restrictionsBundle.putString(USERNAME_KEY, localUser);
        restrictionsBundle.putString(PASSWORD_KEY, localPrefs.getString(PASSWORD_KEY, ""));
        restrictionsBundle.putString(AD_DOMAIN_KEY, localDomain);
      }
    }
    // Obtain managed configs.
    String configuredDomain = restrictionsBundle.getString(AD_REALM_KEY);
    if (Strings.isNullOrEmpty(configuredDomain)) {
      configuredDomain = restrictionsBundle.getString(AD_DOMAIN_KEY);
    }
    if (!Strings.isNullOrEmpty(configuredDomain)
        && restrictionsBundle.containsKey(USERNAME_KEY)) {
      adDomain = configuredDomain;
      username = restrictionsBundle.getString(USERNAME_KEY);
    }
    // Enterprise file deployments deliberately never accept a password through MDM. Retain the
    // legacy key only for existing authenticator-only deployments without managed shares.
    if (!restrictionsBundle.containsKey("shares") && restrictionsBundle.containsKey(PASSWORD_KEY)) {
      // Password may either be supplied by managed config or user input.
      password = restrictionsBundle.getString(PASSWORD_KEY);
    }
    String[] configuredKdcs = restrictionsBundle.getStringArray("kdc_hosts");
    if (configuredKdcs != null && configuredKdcs.length > 0
        && !Strings.isNullOrEmpty(configuredKdcs[0])) {
      adDomainController = configuredKdcs[0].trim();
    } else {
      String configuredKdcList = restrictionsBundle.getString("kdc_hosts");
      if (!Strings.isNullOrEmpty(configuredKdcList)) {
        adDomainController = configuredKdcList.split(",", 2)[0].trim();
      }
    }

    debugWithSensitiveData = restrictionsBundle.getBoolean(SENSITIVE_DEBUG_DATA_KEY, false);
  }

  KerberosAccountDetails getAccountDetails() {
    if (!hasManagedConfigs()) {
      return null;
    }
    return new KerberosAccountDetails(username, password, adDomain, adDomainController);
  }

  boolean getDebugWithSensitiveData() {
    return debugWithSensitiveData;
  }

  @VisibleForTesting
  BroadcastReceiver getReceiver() {
    return restrictionsReceiver;
  }

  void unregisterReceiver(@NonNull Context context) {
    context.unregisterReceiver(restrictionsReceiver);
  }

  boolean hasManagedConfigs() {
    // If any restriction string is empty, the configs are assumed to be missing.
    boolean emptyUsername = Strings.isNullOrEmpty(username);
    boolean emptyDomain = Strings.isNullOrEmpty(adDomain);
    boolean hasManagedConfigs = !(emptyUsername || emptyDomain);
    if (!hasManagedConfigs) {
      Log.d(
          Constants.TAG,
          String.format(
              "Missing managed configuration: username? %s, domain? %s.",
              emptyUsername, emptyDomain));
    }
    return hasManagedConfigs;
  }

  boolean hasManagedConfigPassword() {
    return !Strings.isNullOrEmpty(password);
  }

  class ManagedConfigsBroadcastReceiver extends BroadcastReceiver {
    @Override
    public void onReceive(@NonNull Context context, Intent intent) {
      Log.d(Constants.TAG, "New managed configuration received.");
      setManagedConfigs();
    }
  }
}
