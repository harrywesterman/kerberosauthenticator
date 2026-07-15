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

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Intent;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import android.Manifest;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.provider.Settings;
import java.text.DateFormat;
import java.util.Date;
import com.poelbos.kerberosauthenticator.internal.ntlm.NtlmCredentialProvider;

/** Show the authentication status for the current account. */
public class AuthenticatorStatusActivity extends BaseAuthenticatorActivity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    if (!accountConfiguration.hasManagedConfigs()) {
      setContentView(R.layout.activity_account_login);
      SystemBarInsets.applyToTopAppBar(findViewById(R.id.accountTopAppBar));
      findViewById(R.id.accountForm).setVisibility(View.GONE);
      findViewById(R.id.managedConfigurationError).setVisibility(View.VISIBLE);
      ((com.google.android.material.appbar.MaterialToolbar) findViewById(R.id.accountTopAppBar))
          .setNavigationOnClickListener(view -> finish());
      return;
    }

    setContentView(R.layout.activity_account_status);
    SystemBarInsets.applyToTopAppBar(findViewById(R.id.accountStatusTopAppBar));

    if (KerberosAccount.getAccount(this) == null) {
      startActivity(LoginActivity.getAccountSignInIntent(this));
      finish();
      return;
    }

    ((com.google.android.material.appbar.MaterialToolbar)
        findViewById(R.id.accountStatusTopAppBar)).setNavigationOnClickListener(view -> finish());
    initUI(true, "");
    showRefreshBtn(accountConfiguration.hasManagedConfigs());
    showLogoutBtn(accountConfiguration.hasManagedConfigs());
    long lastRefresh = getSharedPreferences(TgtRefreshWorker.STATUS_PREFS, MODE_PRIVATE)
        .getLong(TgtRefreshWorker.LAST_SUCCESS, 0L);
    TextView refreshStatus = findViewById(R.id.automatic_refresh_status);
    refreshStatus.setVisibility(View.VISIBLE);
    String category = getSharedPreferences(TgtRefreshWorker.STATUS_PREFS, MODE_PRIVATE)
        .getString(TgtRefreshWorker.LAST_CATEGORY, "not run yet");
    refreshStatus.setText(lastRefresh == 0L
        ? getString(R.string.automatic_refresh_not_run, category)
        : getString(
            R.string.automatic_refresh_last_success,
            DateFormat.getDateTimeInstance().format(new Date(lastRefresh))));
    KerberosAccount account = KerberosAccount.getAccount(this);
    boolean ntlmCredentialsAvailable =
        account != null
            && accountConfiguration.isHttpNtlmConfigured()
            && new NtlmCredentialProvider(this)
                .isAvailable(account.getName(), account.getDomain());
    TextView ntlmStatus = findViewById(R.id.http_ntlm_status);
    ntlmStatus.setVisibility(View.VISIBLE);
    ntlmStatus.setText(
        httpNtlmStatus(
            accountConfiguration.isHttpNtlmEnabled(),
            accountConfiguration.isHttpNtlmConfigured(),
            ntlmCredentialsAvailable));

    TextView notificationStatus = findViewById(R.id.notification_status);
    if (accountConfiguration.isManagedDeployment()
        && new CredentialVault(this).hasCredentials()
        && !NotificationPermissionController.isAllowed(this)) {
      notificationStatus.setVisibility(View.VISIBLE);
      notificationStatus.setText(R.string.notification_permission_missing);
      notificationStatus.setOnClickListener(view -> startActivity(
          new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
              .putExtra(Settings.EXTRA_APP_PACKAGE, getPackageName())
              .setData(Uri.parse("package:" + getPackageName()))));
    }

    // If only the status is shown, the activity remains open until the user taps the dismiss
    // button to finish it.
    Log.d(TAG, "Finished creating status activity.");
  }

  static String httpNtlmStatus(boolean enabled, boolean configured, boolean credentialsAvailable) {
    if (!enabled) return "HTTP NTLMv2: disabled by policy";
    if (!configured) return "HTTP NTLMv2: unavailable (invalid NTLM domain)";
    if (!credentialsAvailable) {
      return "HTTP NTLMv2: unavailable (secure credentials missing)";
    }
    return "HTTP NTLMv2: ready; TLS channel binding unavailable (Extended Protection unsupported)";
  }
}
