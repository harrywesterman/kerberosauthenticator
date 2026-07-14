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

import android.accounts.AccountAuthenticatorActivity;
import android.accounts.AccountManager;
import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager.NameNotFoundException;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import java.text.DateFormat;
import java.util.Date;

/** Base class for authenticator activities. */
public class BaseAuthenticatorActivity extends AccountAuthenticatorActivity {
  protected AccountConfiguration accountConfiguration;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.authenticator);
    accountConfiguration = new AccountConfiguration(getApplicationContext());
    KerberosAccount account = KerberosAccount.getAccount(this);
    if (account == null) {
      // The account could be removed programmatically by calling KerberosAccount.remove()
      // or manually in Account Manager. For the second option we will only know the account is
      // null after being removed.
      ServiceTicketInfo.clearServiceTicketInfo(
          getSharedPreferences(Constants.PREFERENCE_NAME, Activity.MODE_PRIVATE));
    }
  }

  @Override
  protected void onDestroy() {
    super.onDestroy();
    if (accountConfiguration != null) {
      accountConfiguration.unregisterReceiver(getApplicationContext());
    }
  }

  /** UI Helper methods. */
  protected void showAccountInfo() {
    if (accountConfiguration.hasManagedConfigs()) {
      KerberosAccountDetails accountDetails = accountConfiguration.getAccountDetails();
      ((TextView) findViewById(R.id.subtitle))
          .setText(
              getResources()
                  .getString(
                      R.string.subtitle_user_creds,
                      accountDetails.getUsername(),
                      accountDetails.getActiveDirectoryDomain()));
    }
  }

  void initUI(boolean isUserInitiated, String serviceName) {
    showAccountInfo();
    showTGTInfo();
    showVersion();
    showOkBtn(isUserInitiated);

    int tgtTimestampViewId = getTGTTimestampTextViewId();
    int serviceTicketTimestampViewId = getServiceTimestampTextviewId();

    KerberosAccount account = KerberosAccount.getAccount(this);
    if (isUserInitiated) {
      // The call is user initiated so get most recent status from account manager.
      if (account != null) {
        setOkStatus(tgtTimestampViewId);
      } else {
        setErrorStatus(tgtTimestampViewId);
        // If there is no TGT the service ticket also has an error.
        setErrorStatus(serviceTicketTimestampViewId);
      }
      showLastServiceAuth();
      return;
    }

    setText(serviceTicketTimestampViewId, serviceName);
    if (account != null) {
      // If the TGT is being renewed for the same account, check if there is any service ticket
      // information available already.
      // showLastServiceAuth() sets the "OK" status icon on anything that has data, so call before
      // setting the refreshing status appropriately.
      showLastServiceAuth();
    } else {
      // If there is no account available, both the TGT and the service ticket show an error.
      setErrorStatus(tgtTimestampViewId);
      setText(getServiceTimestampTextviewId(), getString(R.string.not_available));
      setErrorStatus(serviceTicketTimestampViewId);
    }
  }

  private void showTGTInfo() {
    KerberosAccount account = KerberosAccount.getAccount(this);
    if (account == null) {
      // No account, no TGT info to display.
      return;
    }

    // Is there a valid TGT to display?
    TicketGrantingTicket tgt = TicketGrantingTicket.fromSerializedSubject(
        account.getTicketGrantingTicket());
    if (tgt == null) {
      // Do not change UI.
      return;
    }

    StringBuilder validityInfo = new StringBuilder();
    // Gather issuance date.
    Date issuanceDate = tgt.getIssuanceDate();
    if (issuanceDate != null) {
      validityInfo.append(
          String.format(
              "%s %s ",
              getText(R.string.from), DateFormat.getDateTimeInstance().format(issuanceDate)));
    }

    // Gather expiry date.
    Date expiryDate = tgt.getExpiryDate();
    if (expiryDate != null) {
      validityInfo.append(
          String.format(
              "%s %s",
              getText(R.string.until), DateFormat.getDateTimeInstance().format(expiryDate)));
    }

    String validityText = validityInfo.toString();

    if (!TextUtils.isEmpty(validityText)) {
      setText(
          getTGTTimestampTextViewId(),
          String.format(
              "%s %s.",
              getText(R.string.valid), validityText));
    }
  }

  void showLastServiceAuth() {
    // Checks if there is a service ticket for this account and displays available info.
    int serviceTicketTimestampViewId = getServiceTimestampTextviewId();
    ServiceTicketInfo serviceTicketInfo =
        ServiceTicketInfo.getServiceTicketInfo(
            getSharedPreferences(Constants.PREFERENCE_NAME, Activity.MODE_PRIVATE));
    long serviceTicketInfoTimestamp = serviceTicketInfo.getObtainedAtMillis();
    String serviceTicketName = serviceTicketInfo.getServiceName();
    String serviceTicketError = serviceTicketInfo.getError();
    String resultCode = serviceTicketInfo.getResultCode();

    if (TextUtils.isEmpty(serviceTicketError)
        && (TextUtils.isEmpty(resultCode) || "SUCCESS".equals(resultCode))) {
      try {
        final boolean hasAttemptedServiceTicket =
            !TextUtils.isEmpty(serviceTicketName) && serviceTicketInfoTimestamp != -1;
        if (hasAttemptedServiceTicket) {
          setServiceTicketInfoText(
              serviceTicketName, serviceTicketInfoTimestamp, serviceTicketInfo.getMechanism());
          setOkStatus(serviceTicketTimestampViewId);
        } else {
          setErrorStatus(serviceTicketTimestampViewId);
          setText(serviceTicketTimestampViewId, getString(R.string.not_available));
        }
      } catch (IllegalStateException e) {
        // This will happen if there is no account available.
        Log.e(
            TAG,
            "Failure to get Kerberos account when trying to display service ticket info. "
                + e.getMessage());
      }
    } else {
      setErrorStatus(serviceTicketTimestampViewId);
      setText(
          serviceTicketTimestampViewId,
          TextUtils.isEmpty(serviceTicketError) ? resultCode : serviceTicketError);
    }
  }

  void showVersion() {
    try {
      String versionName = BuildConfig.VERSION_NAME;
      if (TextUtils.isEmpty(versionName)) {
        PackageInfo packageInfo = getPackageManager().getPackageInfo(getPackageName(), 0);
        versionName = packageInfo.versionName;
      }
      ((TextView) findViewById(R.id.version_no))
          .setText(String.format("v%s", versionName));
    } catch (NameNotFoundException e) {
      ((TextView) findViewById(R.id.version_no)).setText(R.string.version_error);
      Log.e(TAG, "Incorrect package name.");
    }
  }

  protected void showOkBtn(boolean isUserVisible) {
    if (isUserVisible) {
      findViewById(R.id.ok_btn).setVisibility(View.VISIBLE);
      findViewById(R.id.ok_btn).setOnClickListener(v -> finish());
    } else {
      findViewById(R.id.ok_btn).setVisibility(View.GONE);
    }
  }

  protected void showLogoutBtn(boolean isVisible) {
    if (isVisible) {
      findViewById(R.id.logout_btn).setVisibility(View.VISIBLE);
      findViewById(R.id.logout_btn).setOnClickListener(v -> onLogoutRequested());
    } else {
      findViewById(R.id.logout_btn).setVisibility(View.GONE);
    }
  }

  protected void showRefreshBtn(boolean isVisible) {
    if (isVisible) {
      findViewById(R.id.refresh_btn).setVisibility(View.VISIBLE);
      findViewById(R.id.refresh_btn).setOnClickListener(v -> onRefreshRequested());
    } else {
      findViewById(R.id.refresh_btn).setVisibility(View.GONE);
    }
  }

  protected void onLogoutRequested() {
    KerberosAccount.removeAccount(this);
    getSharedPreferences(EditConfigurationActivity.LOCAL_CONFIG_PREFS_NAME, MODE_PRIVATE)
        .edit()
        .clear()
        .apply();
    Intent intent =
        EditConfigurationActivity.getEditIntent(
            this,
            getIntent().getParcelableExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE),
            getIntent().getStringExtra(Constants.SERVICE_NAME));
    intent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
    startActivity(intent);
    finish();
  }

  protected void onRefreshRequested() {
    Intent intent = LoginActivity.getRefreshIntent(this);
    startActivity(intent);
  }

  protected void setErrorStatus(int textviewId) {
    Drawable error = getDrawable(R.drawable.ic_error_outline_red_24dp);
    ((TextView) findViewById(textviewId))
        .setCompoundDrawablesWithIntrinsicBounds(error, null, null, null);
  }

  protected void setOkStatus(int textviewId) {
    Drawable ok = getDrawable(R.drawable.ic_check_primary_24dp);
    ((TextView) findViewById(textviewId))
        .setCompoundDrawablesWithIntrinsicBounds(ok, null, null, null);
  }

  protected void setRefreshingStatus(int textviewId) {
    Drawable refresh = getDrawable(R.drawable.ic_autorenew_primary_24dp);
    ((TextView) findViewById(textviewId))
        .setCompoundDrawablesWithIntrinsicBounds(refresh, null, null, null);
  }

  protected void setText(int textviewId, String text) {
    ((TextView) findViewById(textviewId)).setText(text);
  }

  private void setServiceTicketInfoText(String name, Long timestamp, String mechanism) {
    String formattedIssuanceTime =
        timestamp == -1 ? null : DateFormat.getDateTimeInstance().format(timestamp);
    setText(
        getServiceTimestampTextviewId(),
        String.format("%s • %s@%s", mechanism, name, formattedIssuanceTime));
  }

  int getTGTTimestampTextViewId() {
    return findViewById(R.id.last_user_auth_timestamp).getId();
  }

  int getServiceTimestampTextviewId() {
    return findViewById(R.id.last_service_auth_time).getId();
  }

  /** Finishing helper methods with error handling. */
  protected void setErrorResultAndFinish(int errorCode, String errorMessage) {
    Bundle result = new Bundle();
    result.putInt(AccountManager.KEY_ERROR_CODE, errorCode);
    result.putString(AccountManager.KEY_ERROR_MESSAGE, errorMessage);
    setResultAndFinish(result);
  }

  protected void setResultAndFinish(Bundle result) {
    setAccountAuthenticatorResult(result);
    finish();
  }

  /**
   * Reads and writes securely to disk information about the most recently issued service ticket.
   */
  static class ServiceTicketInfo {
    private final String serviceName;
    private final long obtainedAtMillis;
    private final String error;
    private final String mechanism;
    private final String resultCode;

    // Keys for storing service ticket information on disk.
    private static final String KEY_SERVICE_TICKET_TIMESTAMP = "service_ticket_issuance_time";
    private static final String KEY_SERVICE_TICKET_NAME = "service_ticket_name";
    private static final String KEY_SERVICE_TICKET_ERROR = "servicet_ticket_error";
    private static final String KEY_HTTP_AUTH_MECHANISM = "http_auth_mechanism";
    private static final String KEY_HTTP_AUTH_RESULT = "http_auth_result";

    static void saveServiceTicketInfo(
        SharedPreferences sharedPref, String serviceName, long timestamp, String error) {
      // Save data to disk.
      SharedPreferences.Editor editor = sharedPref.edit();
      editor.putString(KEY_SERVICE_TICKET_NAME, serviceName);
      editor.putLong(KEY_SERVICE_TICKET_TIMESTAMP, timestamp);
      editor.putString(KEY_SERVICE_TICKET_ERROR, error);
      editor.putString(KEY_HTTP_AUTH_MECHANISM, "KERBEROS");
      editor.putString(KEY_HTTP_AUTH_RESULT, error == null ? "SUCCESS" : "ERROR");
      editor.apply();
    }

    static void saveHttpAuthInfo(
        SharedPreferences sharedPref,
        String host,
        long timestamp,
        String mechanism,
        String resultCode) {
      sharedPref
          .edit()
          .putString(KEY_SERVICE_TICKET_NAME, host)
          .putLong(KEY_SERVICE_TICKET_TIMESTAMP, timestamp)
          .remove(KEY_SERVICE_TICKET_ERROR)
          .putString(KEY_HTTP_AUTH_MECHANISM, mechanism)
          .putString(KEY_HTTP_AUTH_RESULT, resultCode)
          .apply();
    }

    static ServiceTicketInfo getServiceTicketInfo(SharedPreferences sharedPref) {
      return new ServiceTicketInfo(sharedPref);
    }

    static void clearServiceTicketInfo(SharedPreferences sharedPref) {
      SharedPreferences.Editor editor = sharedPref.edit();
      editor.clear();
      editor.apply();
    }

    private ServiceTicketInfo(SharedPreferences sharedPref) {
      this.serviceName = sharedPref.getString(KEY_SERVICE_TICKET_NAME, "");
      this.obtainedAtMillis = sharedPref.getLong(KEY_SERVICE_TICKET_TIMESTAMP, -1);
      this.error = sharedPref.getString(KEY_SERVICE_TICKET_ERROR, "");
      this.mechanism = sharedPref.getString(KEY_HTTP_AUTH_MECHANISM, "KERBEROS");
      this.resultCode = sharedPref.getString(KEY_HTTP_AUTH_RESULT, null);
    }

    String getServiceName() {
      return serviceName;
    }

    long getObtainedAtMillis() {
      return obtainedAtMillis;
    }

    String getError() {
      return error;
    }

    String getMechanism() {
      return mechanism;
    }

    String getResultCode() {
      return resultCode;
    }
  }
}
