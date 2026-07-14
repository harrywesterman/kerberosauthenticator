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

import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.TextUtils;
import android.text.Editable;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult;
import com.poelbos.kerberosauthenticator.internal.kinit.UserAuthenticationResultListener;
import com.poelbos.kerberosauthenticator.internal.kinit.UserAuthenticationTask;
import javax.security.auth.Subject;

/** Obtains a ticket granting ticket for the user, while displaying authentication status and
 * details on the most recently issued tickets.
 * If the user launches the Kerberos authenticator via the launcher manually, this activity will
 * only show status.
 */
public class LoginActivity extends BaseAuthenticatorActivity implements
    UserAuthenticationResultListener {

  boolean isPasswordRetry = false;
  private boolean refreshStatusAfterAuth = false;
  private char[] pendingPassword;

  /** Returns an intent that can be used to authenticate an account. */
  public static Intent getAuthenticateIntent(
      Context context, AccountAuthenticatorResponse response) {
    return getAuthenticateIntent(context, response, null);
  }

  /** Returns an intent that can be used to authenticate an account. */
  public static Intent getAuthenticateIntent(
      Context context, AccountAuthenticatorResponse response, String serviceName) {
    Intent intent = new Intent(context, LoginActivity.class);
    intent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
    if (serviceName != null) {
      intent.putExtra(Constants.SERVICE_NAME, serviceName);
    }
    return intent;
  }

  public static Intent getRefreshIntent(Context context) {
    Intent intent = new Intent(context, LoginActivity.class);
    intent.putExtra(Constants.REFRESH_STATUS_AFTER_AUTH, true);
    return intent;
  }

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);

    // Let the user know an account cannot be added because managed config is missing.
    if (!accountConfiguration.hasManagedConfigs()) {
      Intent intent = EditConfigurationActivity.getEditIntent(
          this,
          getIntent().getParcelableExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE),
          getIntent().getStringExtra(Constants.SERVICE_NAME));
      startActivity(intent);
      finish();
      return;
    }

    isPasswordRetry = false;
    Intent intent = getIntent();
    refreshStatusAfterAuth = intent.getBooleanExtra(Constants.REFRESH_STATUS_AFTER_AUTH, false);

    setContentView(R.layout.authenticator);

    String serviceName = intent.getStringExtra(Constants.SERVICE_NAME);
    boolean shouldAddAccount = TextUtils.isEmpty(serviceName);
    Log.d(
        Constants.TAG,
        String.format(
            "Starting login activity, service name? %s, add new account? %s.",
            serviceName, shouldAddAccount));

    // Initialise the UI with corresponding values.
    initUI(false /*isUserInitiated*/, serviceName);
    showLogoutBtn(KerberosAccount.getAccount(this) != null);

    // Generate or renew a TGT. Do not attempt recovering from a bad password if we are in the
    // process of adding a new account.
    authenticateAccount(shouldAddAccount);

    // If only the status is shown, the activity remains open until the user taps the dismiss
    // button to finish it.
    Log.d(Constants.TAG, "Finished creating login activity.");
  }

  @Override
  public void onTicketGrantingTicketResult(
      TicketRequestResult ticketRequestResult, Subject ticket) {
    Log.i(TAG, String.format("TGT_RESULT code=%s valid=%s",
        ticketRequestResult.getResultCode(), ticket != null));
    Bundle result = new Bundle();
    KerberosAccount account = KerberosAccount.getAccount(this);
    boolean successGettingTgt = ticketRequestResult.successful() && ticket != null;

    if (successGettingTgt && account != null) {
      TicketGrantingTicket tgt = new TicketGrantingTicket(ticket);
      account.setTicketGrantingTicket(tgt.asSerialized());
      boolean stored;
      try {
        stored = pendingPassword != null && new CredentialVault(this).store(
            account.getName(), account.getDomain(), pendingPassword);
      } finally {
        clearPendingPassword();
      }
      account.save(this);
      if (stored) {
        TgtRefreshScheduler.schedule(this);
        NotificationPermissionController.requestIfNeeded(this);
      } else {
        TgtRefreshScheduler.cancel(this);
        Toast.makeText(this,
            "Automatic refresh is not securely available on this device",
            Toast.LENGTH_LONG).show();
      }
      isPasswordRetry = false;
    } else {
      clearPendingPassword();
      if (ticketRequestResult.isCredentialRejected() && !isPasswordRetry) {
        Log.i(
            Constants.TAG,
            String.format(
                "Credentials rejected for user %s, removing and attempting re-authentication.",
            account == null ? "unknown" : account.getName()));
        KerberosAccount.removeAccount(this);
        isPasswordRetry = true;
        showUserLoginUI();
      } else {
        setErrorResultAndFinish(
            AccountManager.ERROR_CODE_BAD_AUTHENTICATION, ticketRequestResult.toString());
      }
      return;
    }

    String serviceName = getIntent().getStringExtra(Constants.SERVICE_NAME);
    if (serviceName == null) {
      result.putString(AccountManager.KEY_ACCOUNT_NAME, account.getName());
      result.putString(AccountManager.KEY_ACCOUNT_TYPE, Constants.KERBEROS_ACCOUNT_TYPE);
      if (refreshStatusAfterAuth) {
        Intent statusIntent = new Intent(this, AuthenticatorStatusActivity.class);
        statusIntent.setFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(statusIntent);
        finish();
      } else {
        // Change UI to show the TGT is obtained correctly.
        setResultAndFinish(result);
      }
    } else {
      // A service name was provided - meaning the TGT had to be renewed before getting a service
      // ticket. As the TGT was renewed successfully, launch the service ticket activity.
      AccountAuthenticatorResponse response =
          getIntent().getParcelableExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE);
      Intent serviceTicketIntent =
          ServiceTicketActivity.getServiceTicketIntent(this, serviceName, response);
      serviceTicketIntent.putExtra(AccountManager.KEY_ACCOUNT_AUTHENTICATOR_RESPONSE, response);
      startActivity(serviceTicketIntent);
      finish();
    }
  }

  private void authenticateAccount(boolean shouldAddAccount) {
    KerberosAccountDetails accountDetails = accountConfiguration.getAccountDetails();
    if (accountDetails == null) {
      Log.e(TAG, "Missing details for new account, erroring out.");
      setErrorResultAndFinish(AccountManager.ERROR_CODE_BAD_ARGUMENTS, "Account details missing");
      return;
    }

    KerberosAccount account = KerberosAccount.getAccount(this);
    if (account != null && !account.getDomain().equalsIgnoreCase(accountDetails.getActiveDirectoryDomain())) {
      Log.i(Constants.TAG, "Managed realm changed; removing the obsolete work account.");
      KerberosAccount.removeAccount(this);
      account = null;
    }
    if (account != null) {
      char[] stored = new CredentialVault(this).load(account.getName(), account.getDomain());
      if (stored != null) {
        try {
          initiateUserAuthenticationTask(account.withPassword(stored), accountDetails);
          return;
        } finally {
          java.util.Arrays.fill(stored, '\0');
        }
      }
    }
    showPasswordEntryPrompt(account);
  }

  private void saveUserCredentials() {
    hideUserLoginUI();
    KerberosAccountDetails configured = accountConfiguration.getAccountDetails();
    KerberosAccount existing = KerberosAccount.getAccount(this);
    String username = ((TextView) findViewById(R.id.editTextUser)).getText().toString().trim();
    if (username.isEmpty() && existing != null) username = existing.getName();
    if (username.isEmpty() && configured != null) username = configured.getUsername();
    Editable passwordInput = ((android.widget.EditText) findViewById(R.id.editTextPw)).getText();
    char[] password = copyCharacters(passwordInput);
    passwordInput.clear();
    if (TextUtils.isEmpty(username) || password.length == 0) {
      java.util.Arrays.fill(password, '\0');
      Toast.makeText(this, "Enter your username and password", Toast.LENGTH_LONG).show();
      showUserLoginUI();
      return;
    }
    if (existing != null && !existing.getName().equals(username)) {
      KerberosAccount.removeAccount(this);
    }
    hideUserLoginUI();
    try {
      KerberosAccountDetails detailsWithPassword =
          new KerberosAccountDetails(
              username,
              password,
              configured.getActiveDirectoryDomain(),
              configured.getAdDomainController());
      initiateUserAuthenticationTask(detailsWithPassword);
    } finally {
      java.util.Arrays.fill(password, '\0');
    }
  }

  private void initiateUserAuthenticationTask(
      KerberosAccount account, KerberosAccountDetails configured) {
    char[] password = account.copyPassword();
    try {
      initiateUserAuthenticationTask(new KerberosAccountDetails(
          account.getName(), password, configured.getActiveDirectoryDomain(),
          configured.getAdDomainController()));
    } finally {
      if (password != null) java.util.Arrays.fill(password, '\0');
    }
  }

  private void initiateUserAuthenticationTask(KerberosAccountDetails accountDetails) {
    setRefreshingStatus(getTGTTimestampTextViewId());
    clearPendingPassword();
    pendingPassword = accountDetails.copyPassword();
    KerberosAccount account = KerberosAccount.getAccount(this);
    account = accountForAuthentication(account, accountDetails);

    account.save(this);
    char[] password = account.copyPassword();
    try {
      UserAuthenticationTask kinit =
          new UserAuthenticationTask(
              this,
              this,
              new KerberosAccountDetails(
                  account.getName(),
                  password,
                  account.getDomain(),
                  account.getDomainController()));
      kinit.execute();
    } finally {
      if (password != null) java.util.Arrays.fill(password, '\0');
    }
  }

  private void clearPendingPassword() {
    if (pendingPassword != null) {
      java.util.Arrays.fill(pendingPassword, '\0');
      pendingPassword = null;
    }
  }

  @Override
  protected void onDestroy() {
    clearPendingPassword();
    super.onDestroy();
  }

  static KerberosAccount accountForAuthentication(
      KerberosAccount account, KerberosAccountDetails accountDetails) {
    if (account == null) {
      char[] initialPassword = accountDetails.copyPassword();
      try {
        return new KerberosAccount(
            accountDetails.getUsername(),
            initialPassword,
            accountDetails.getActiveDirectoryDomain(),
            accountDetails.getAdDomainController());
      } finally {
        if (initialPassword != null) java.util.Arrays.fill(initialPassword, '\0');
      }
    }
    char[] accountPassword = account.copyPassword();
    char[] requestedPassword = accountDetails.copyPassword();
    try {
      if (!java.util.Arrays.equals(accountPassword, requestedPassword)) {
        return account.withPassword(requestedPassword);
      }
    } finally {
      if (accountPassword != null) java.util.Arrays.fill(accountPassword, '\0');
      if (requestedPassword != null) java.util.Arrays.fill(requestedPassword, '\0');
    }
    return account;
  }

  private void showUserLoginUI() {
    TextView username = findViewById(R.id.editTextUser);
    KerberosAccount existing = KerberosAccount.getAccount(this);
    if (existing != null) username.setText(existing.getName());
    username.setVisibility(View.VISIBLE);
    TextView realm = findViewById(R.id.managedRealm);
    realm.setText("Work environment: " + accountConfiguration.getRealm());
    realm.setVisibility(View.VISIBLE);
    View pwField = findViewById(R.id.editTextPw);
    pwField.setVisibility(View.VISIBLE);
    Button loginBtn = findViewById(R.id.ok_btn);
    loginBtn.setText(R.string.login_btn);
    loginBtn.setVisibility(View.VISIBLE);
    loginBtn.setOnClickListener(v -> saveUserCredentials());
  }

  private void hideUserLoginUI() {
    findViewById(R.id.editTextUser).setVisibility(View.GONE);
    findViewById(R.id.managedRealm).setVisibility(View.GONE);
    findViewById(R.id.editTextPw).setVisibility(View.GONE);
    findViewById(R.id.ok_btn).setVisibility(View.GONE);
    setText(getTGTTimestampTextViewId(), getText(R.string.not_available).toString());
    setRefreshingStatus(getTGTTimestampTextViewId());
  }

  private void showPasswordEntryPrompt(KerberosAccount account) {
    // Activity was created to generate a TGT.
    // Prepare to check if we have the user password available.
    showUserLoginUI();
    if (account != null) {
      // If the TGT is being renewed for the same account, check if there is any service ticket
      // information available already.
      showLastServiceAuth();
    }
  }

  private static char[] copyCharacters(CharSequence value) {
    char[] result = new char[value == null ? 0 : value.length()];
    for (int index = 0; index < result.length; index++) result[index] = value.charAt(index);
    return result;
  }
}
