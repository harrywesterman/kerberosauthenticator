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

import android.accounts.AbstractAccountAuthenticator;
import android.accounts.Account;
import android.accounts.AccountAuthenticatorResponse;
import android.accounts.AccountManager;
import android.accounts.NetworkErrorException;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import com.poelbos.kerberosauthenticator.internal.spnego.GetSpnegoTicketTask;
import java.util.Arrays;
import java.util.Date;
import java.util.regex.Matcher;

/** Kerberos account authenticator. */
public class KerberosAuthenticator extends AbstractAccountAuthenticator {
  private final Context context;
  private static ServiceTicketProvider serviceTicketProvider =
      KerberosAuthenticator::requestServiceTicket;
  private static TgtValidityChecker tgtValidityChecker =
      KerberosAuthenticator::hasValidTicketGrantingTicket;
  private static TgtRenewer tgtRenewer = KerberosAuthenticator::renewTicketGrantingTicket;
  private static ChromeCallerValidator chromeCallerValidator =
      KerberosAuthenticator::isAuthorizedChromeCaller;

  KerberosAuthenticator(Context context) {
    super(context);
    this.context = context;
  }

  interface ServiceTicketProvider {
    GetSpnegoTicketTask.SpnegoTicketResult getServiceTicket(
        Context context,
        String serviceName,
        KerberosAccount account,
        boolean debugWithSensitiveData,
        byte[] incomingAuthToken,
        byte[] spnegoContext);
  }

  interface ChromeCallerValidator {
    boolean isAuthorized(Context context, Bundle options);
  }

  interface TgtValidityChecker {
    boolean hasValidTgt(KerberosAccount account);
  }

  interface TgtRenewer {
    boolean renew(Context context, KerberosAccount account);
  }

  static void setServiceTicketProviderForTesting(ServiceTicketProvider provider) {
    serviceTicketProvider = provider;
  }

  static void resetServiceTicketProviderForTesting() {
    serviceTicketProvider = KerberosAuthenticator::requestServiceTicket;
  }

  static void setTgtValidityCheckerForTesting(TgtValidityChecker checker) {
    tgtValidityChecker = checker;
  }

  static void resetTgtValidityCheckerForTesting() {
    tgtValidityChecker = KerberosAuthenticator::hasValidTicketGrantingTicket;
  }

  static void setTgtRenewerForTesting(TgtRenewer renewer) {
    tgtRenewer = renewer;
  }

  static void resetTgtRenewerForTesting() {
    tgtRenewer = KerberosAuthenticator::renewTicketGrantingTicket;
  }

  static void setChromeCallerValidatorForTesting(ChromeCallerValidator validator) {
    chromeCallerValidator = validator;
  }

  static void resetChromeCallerValidatorForTesting() {
    chromeCallerValidator = KerberosAuthenticator::isAuthorizedChromeCaller;
  }

  @Override
  public Bundle editProperties(AccountAuthenticatorResponse response, String accountType) {
    return unsupportedOperationBundle("editProperties");
  }

  private Bundle unsupportedOperationBundle(String opName) {
    Bundle result = new Bundle();
    result.putInt(
        AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION);
    result.putString(AccountManager.KEY_ERROR_MESSAGE, "Unsupported method: " + opName);
    return result;
  }

  @Override
  public Bundle addAccount(AccountAuthenticatorResponse response, String accountType,
      String authTokenType, String[] requiredFeatures, Bundle options) {
    Bundle bundle = new Bundle();

    Intent intentToReturn;

    // Request comes from Chrome, add account.
    if (requiredFeatures != null && Arrays.asList(requiredFeatures).contains(Constants.SPNEGO)) {
      if (hasValidAccountConfiguration()) {
        intentToReturn = LoginActivity.getAuthenticateIntent(context, response);
      } else {
        intentToReturn = EditConfigurationActivity.getEditIntent(context, response, null);
      }
    } else {
      // User cannot add account themselves.
      intentToReturn =
          DeclineAddingAccountActivity.getDeclineIntentDueToUserAdded(context, response);
    }
    bundle.putParcelable(AccountManager.KEY_INTENT, intentToReturn);

    return bundle;
  }

  @Override
  public Bundle confirmCredentials(AccountAuthenticatorResponse response, Account account,
      Bundle options) {
    return unsupportedOperationBundle("confirmCredentials");
  }

  @Override
  public Bundle getAuthToken(AccountAuthenticatorResponse response, Account account,
      String authTokenType, Bundle options) {
    Log.d(
        TAG,
        String.format(
            "Received request to obtain token %s with account %s.", authTokenType, account));

    // Request does not come from Chrome, deny access.
    if (!chromeCallerValidator.isAuthorized(context, options)) {
      return unsupportedOperationBundle("Unsupported caller app.");
    }

    Bundle result = new Bundle();
    Matcher matcher = Constants.AUTH_TOKEN_PATTERN.matcher(authTokenType);
    String serviceName;
    if (matcher.matches() && matcher.groupCount() == 2) {
      serviceName = matcher.group(2).trim();
      if (serviceName.endsWith(".")) {
        serviceName = serviceName.substring(0, serviceName.length() - 1);
      }
    } else {
      // Cannot obtain service name.
      result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_BAD_ARGUMENTS);
      result.putString(
          AccountManager.KEY_ERROR_MESSAGE,
          String.format("Invalid auth token format for %s.", authTokenType));
      return result;
    }
    if (serviceName.isEmpty() || serviceName.startsWith(".")) {
      result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_BAD_ARGUMENTS);
      result.putString(
          AccountManager.KEY_ERROR_MESSAGE,
          String.format("Invalid auth token format for %s.", authTokenType));
      return result;
    }

    KerberosAccount krbAccount = KerberosAccount.getAccount(context);
    // No account, this is a deviation from the protocol, return an error.
    if (krbAccount == null) {
      result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_BAD_REQUEST);
      result.putString(AccountManager.KEY_ERROR_MESSAGE, "No account configured?");
      return result;
    }

    // Mismatch between the username in the account provided and the existing Kerberos account,
    // this is a deviation from the protocol, return an error.
    if (!krbAccount.getName().equals(account.name)) {
      result.putInt(AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_BAD_REQUEST);
      result.putString(AccountManager.KEY_ERROR_MESSAGE,
          String.format("Account names mismatch: %s vs %s", krbAccount.getName(), account.name));
      return result;
    }

    // Check if the account details via managed config have changed from what's stored in the
    // AccountManager. If there's a mismatch and the account needs to be updated, also call
    // getAuthenticateIntent as it will remove the old account and add a new one.
    boolean needReAuthentication = !krbAccount.getName().equals(getManagedConfigurationUsername());

    if (!needReAuthentication && !tgtValidityChecker.hasValidTgt(krbAccount)) {
      if (tgtRenewer.renew(context, krbAccount)) {
        Log.i(TAG, String.format("Renewed ticket-granting-ticket for %s.", krbAccount.getName()));
      } else {
        needReAuthentication = true;
      }
    }
    if (needReAuthentication) {
      Log.d(
          TAG,
          String.format("Ticket-granting-ticket for %s will be renewed.", krbAccount.getName()));
      Intent intent =
          LoginActivity.getAuthenticateIntent(context, response, serviceName);
      result.putParcelable(AccountManager.KEY_INTENT, intent);
      return result;
    }

    Log.d(TAG, String.format("Will request service ticket for %s, account %s.",
        serviceName, krbAccount.getName()));
    byte[] incomingAuthToken = incomingAuthToken(options);
    byte[] spnegoContext = spnegoContext(options);
    GetSpnegoTicketTask.SpnegoTicketResult serviceTicketResult =
        serviceTicketProvider.getServiceTicket(
            context,
            serviceName,
            krbAccount,
            getFromAccountConfiguration(AccountConfiguration::getDebugWithSensitiveData),
            incomingAuthToken,
            spnegoContext);
    if (!serviceTicketResult.getRequestResult().successful()
        || serviceTicketResult.getServiceTicket() == null) {
      SharedPreferences sharedPref =
          context.getSharedPreferences(Constants.PREFERENCE_NAME, Context.MODE_PRIVATE);
      BaseAuthenticatorActivity.ServiceTicketInfo.saveServiceTicketInfo(
          sharedPref,
          serviceName,
          new Date().getTime(),
          serviceTicketResult.getRequestResult().toString());
      result.putInt(
          AccountManager.KEY_ERROR_CODE, AccountManager.ERROR_CODE_BAD_AUTHENTICATION);
      result.putString(
          AccountManager.KEY_ERROR_MESSAGE, serviceTicketResult.getRequestResult().toString());
      return result;
    }

    result.putString(AccountManager.KEY_ACCOUNT_NAME, krbAccount.getName());
    result.putString(AccountManager.KEY_ACCOUNT_TYPE, Constants.KERBEROS_ACCOUNT_TYPE);
    result.putString(AccountManager.KEY_AUTHTOKEN, serviceTicketResult.getServiceTicket());
    result.putInt(Constants.KEY_SPNEGO_RESULT, 0);
    if (serviceTicketResult.getSpnegoContext() != null) {
      Bundle contextBundle = new Bundle();
      contextBundle.putByteArray(
          Constants.KEY_GSS_CONTEXT_BYTES, serviceTicketResult.getSpnegoContext());
      result.putBundle(Constants.KEY_SPNEGO_CONTEXT, contextBundle);
    }
    krbAccount.save(context);
    SharedPreferences sharedPref =
        context.getSharedPreferences(Constants.PREFERENCE_NAME, Context.MODE_PRIVATE);
    BaseAuthenticatorActivity.ServiceTicketInfo.saveServiceTicketInfo(
        sharedPref,
        serviceTicketResult.getSelectedService() == null
            ? serviceName
            : serviceTicketResult.getSelectedService(),
        new Date().getTime(),
        null);
    return result;
  }

  private static GetSpnegoTicketTask.SpnegoTicketResult requestServiceTicket(
      Context context,
      String serviceName,
      KerberosAccount account,
      boolean debugWithSensitiveData,
      byte[] incomingAuthToken,
      byte[] spnegoContext) {
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    return GetSpnegoTicketTask.getServiceTicket(
        context,
        tgt.asSubject(),
        account.getDomain(),
        account.getDomainController(),
        account.getName(),
        account.getPassword(),
        debugWithSensitiveData,
        serviceName,
        incomingAuthToken,
        spnegoContext);
  }

  static boolean isAuthorizedChromeCaller(Context context, Bundle options) {
    if (options == null
        || !Constants.CHROME_PACKAGE_NAME.equals(
            options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME))) {
      return false;
    }
    int callerUid = options.getInt(AccountManager.KEY_CALLER_UID, -1);
    if (callerUid < 0) {
      return false;
    }
    String[] packages = context.getPackageManager().getPackagesForUid(callerUid);
    if (packages == null) {
      return false;
    }
    for (String packageName : packages) {
      if (Constants.CHROME_PACKAGE_NAME.equals(packageName)) {
        return true;
      }
    }
    return false;
  }

  private static byte[] incomingAuthToken(Bundle options) {
    String encoded = options.getString(Constants.KEY_INCOMING_AUTH_TOKEN);
    if (encoded != null) {
      try {
        return Base64.decode(encoded, Base64.DEFAULT);
      } catch (IllegalArgumentException e) {
        Log.w(TAG, "Chrome supplied an invalid incoming SPNEGO token.", e);
        return null;
      }
    }
    return options.getByteArray(Constants.KEY_INCOMING_AUTH_TOKEN);
  }

  private static byte[] spnegoContext(Bundle options) {
    Bundle contextBundle = options.getBundle(Constants.KEY_SPNEGO_CONTEXT);
    return contextBundle == null
        ? null
        : contextBundle.getByteArray(Constants.KEY_GSS_CONTEXT_BYTES);
  }

  private static boolean hasValidTicketGrantingTicket(KerberosAccount account) {
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    return tgt != null && tgt.getExpiryDate() != null && tgt.getExpiryDate().after(new Date());
  }

  private static boolean renewTicketGrantingTicket(Context context, KerberosAccount account) {
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    if (tgt == null || !tgt.renew()) {
      return false;
    }
    account.setTicketGrantingTicket(tgt.asSerialized());
    account.save(context);
    return hasValidTicketGrantingTicket(account);
  }

  @Override
  public String getAuthTokenLabel(String authTokenType) {
    return "Spnego" + authTokenType;
  }

  @Override
  public Bundle updateCredentials(AccountAuthenticatorResponse response, Account account,
      String authTokenType, Bundle options) {
    return unsupportedOperationBundle("updateCredentials");
  }

  @Override
  public Bundle hasFeatures(AccountAuthenticatorResponse response, Account account,
      String[] features) {
    Bundle result = new Bundle();
    for (String feature : features) {
      if (!feature.equals("SPNEGO")) {
        result.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, false);
        return result;
      }
    }
    result.putBoolean(AccountManager.KEY_BOOLEAN_RESULT, true);
    return result;
  }

  @Override
  public Bundle addAccountFromCredentials(AccountAuthenticatorResponse response, Account account,
      Bundle accountCredentials)
      throws NetworkErrorException {
    return super.addAccountFromCredentials(response, account, accountCredentials);
  }

  /**
   * An interface to operate on an {@code AccountConfiguration} instance and get some data
   * out ot it.
   * @param <T> return type for the data extracted.
   */
  interface AccountConfigurationOperator<T> {
    T operate(AccountConfiguration config);
  }

  // Runs the provided operator on an AccountConfiguration instance, unregistering it when
  // done.
  private <T> T getFromAccountConfiguration(AccountConfigurationOperator<T> operator) {
    AccountConfiguration config = null;
    try {
      config = new AccountConfiguration(context);
      return operator.operate(config);
    } finally {
      config.unregisterReceiver(context);
    }
  }

  private boolean hasValidAccountConfiguration() {
    return getFromAccountConfiguration(AccountConfiguration::hasManagedConfigs);
  }

  private String getManagedConfigurationUsername() {
    return getFromAccountConfiguration(
        (config) -> {
          if (!config.hasManagedConfigs()) {
            return "";
          }

          return config.getAccountDetails().getUsername();
        });
  }
}
