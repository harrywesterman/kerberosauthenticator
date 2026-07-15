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
import com.poelbos.kerberosauthenticator.internal.ntlm.HttpNtlmV2Engine;
import com.poelbos.kerberosauthenticator.internal.ntlm.NtlmCredentialProvider;
import com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoCoordinator;
import com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoResult;
import com.poelbos.kerberosauthenticator.internal.spnego.SpnegoNegotiationState;
import com.poelbos.kerberosauthenticator.internal.spnego.SpnegoStateCodec;
import com.hierynomus.smbj.SmbConfig;
import java.security.SecureRandom;
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
      if (hasValidAccountConfiguration() && getHttpAuthenticationPolicy().hasEnabledMechanism()) {
        intentToReturn = LoginActivity.getAuthenticateIntent(context, response);
      } else {
        intentToReturn =
            DeclineAddingAccountActivity.getDeclineIntentDueToConfigMissing(context, response);
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
    Log.i(TAG, "SPNEGO_REQUEST host=" + serviceName + " caller=chrome");

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

    HttpAuthenticationPolicy httpPolicy = getHttpAuthenticationPolicy();
    if (!httpPolicy.hasEnabledMechanism()) {
      result.putInt(
          Constants.KEY_SPNEGO_RESULT, HttpSpnegoResult.ERR_UNSUPPORTED_AUTH_SCHEME);
      Log.i(TAG, "HTTP_AUTH_RESULT mechanism=NONE code=6");
      return result;
    }

    // Check if the account details via managed config have changed from what's stored in the
    // AccountManager. If there's a mismatch and the account needs to be updated, also call
    // getAuthenticateIntent as it will remove the old account and add a new one.
    String configuredRealm = getManagedConfigurationRealm();
    boolean needReAuthentication = configuredRealm == null
        || !krbAccount.getDomain().equalsIgnoreCase(configuredRealm);

    if (httpPolicy.kerberosEnabled
        && !needReAuthentication
        && !tgtValidityChecker.hasValidTgt(krbAccount)) {
      if (tgtRenewer.renew(context, krbAccount)) {
        Log.i(TAG, "TGT_RENEWAL result=success");
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

    Log.i(
        TAG,
        "HTTP_AUTH_REQUEST host="
            + serviceName
            + " phase="
            + (options.getBundle(Constants.KEY_SPNEGO_CONTEXT) == null
                ? "INITIAL"
                : "CONTINUE"));
    byte[] incomingAuthToken;
    SpnegoNegotiationState negotiationState;
    try {
      incomingAuthToken = incomingAuthToken(options);
      negotiationState = negotiationState(options, serviceName);
    } catch (IllegalArgumentException error) {
      Log.w(TAG, "HTTP_AUTH_RESULT code=4 reason=invalid_context");
      result.putInt(Constants.KEY_SPNEGO_RESULT, HttpSpnegoResult.ERR_INVALID_RESPONSE);
      return result;
    }

    NtlmCredentialProvider ntlmCredentials = new NtlmCredentialProvider(context);
    if (negotiationState == null) {
      boolean ntlmEligible =
          httpPolicy.ntlmEnabled
              && httpPolicy.ntlmDomain != null
              && ntlmCredentials.isAvailable(krbAccount.getName(), krbAccount.getDomain());
      Log.i(TAG, "SPNEGO_OFFER ntlmEligible=" + ntlmEligible);
    }
    HttpSpnegoCoordinator coordinator =
        new HttpSpnegoCoordinator(
            (host, incoming, exportedContext, selectedService) -> {
              String ticketHost = selectedService == null ? host : selectedService;
              GetSpnegoTicketTask.SpnegoTicketResult ticket =
                  serviceTicketProvider.getServiceTicket(
                      context, ticketHost, krbAccount, incoming, exportedContext);
              if (!ticket.getRequestResult().successful() || ticket.getServiceTicket() == null) {
                return HttpSpnegoCoordinator.KerberosRound.failure(
                    ticket.getRequestResult().toString());
              }
              try {
                return HttpSpnegoCoordinator.KerberosRound.success(
                    Base64.decode(ticket.getServiceTicket(), Base64.DEFAULT),
                    ticket.getSpnegoContext(),
                    ticket.getSelectedService() == null ? ticketHost : ticket.getSelectedService());
              } catch (IllegalArgumentException error) {
                return HttpSpnegoCoordinator.KerberosRound.failure("Invalid Kerberos token");
              }
            },
            new HttpNtlmV2Engine(
                new SecureRandom(),
                System::currentTimeMillis,
                SmbConfig.createDefaultConfig().getSecurityProvider()),
            ntlmCredentials);
    HttpSpnegoResult authResult =
        coordinator.nextToken(
            serviceName,
            krbAccount.getName(),
            krbAccount.getDomain(),
            httpPolicy.ntlmDomain,
            httpPolicy.kerberosEnabled,
            httpPolicy.ntlmEnabled,
            incomingAuthToken,
            negotiationState);
    if (negotiationState != null) {
      Log.i(
          TAG,
          "SPNEGO_SELECTED mechanism="
              + mechanismName(negotiationState, authResult, httpPolicy));
    }
    if (authResult.getStatus() != HttpSpnegoResult.OK || authResult.getToken() == null) {
      SharedPreferences sharedPref =
          context.getSharedPreferences(Constants.PREFERENCE_NAME, Context.MODE_PRIVATE);
      BaseAuthenticatorActivity.ServiceTicketInfo.saveHttpAuthInfo(
          sharedPref,
          serviceName,
          new Date().getTime(),
          mechanismName(negotiationState, authResult, httpPolicy),
          "ERROR_" + authResult.getStatus());
      result.putInt(Constants.KEY_SPNEGO_RESULT, authResult.getStatus());
      Log.i(TAG, "HTTP_AUTH_RESULT code=" + authResult.getStatus());
      return result;
    }

    result.putString(AccountManager.KEY_ACCOUNT_NAME, krbAccount.getName());
    result.putString(AccountManager.KEY_ACCOUNT_TYPE, Constants.KERBEROS_ACCOUNT_TYPE);
    result.putString(
        AccountManager.KEY_AUTHTOKEN,
        Base64.encodeToString(authResult.getToken(), Base64.NO_WRAP));
    result.putInt(Constants.KEY_SPNEGO_RESULT, 0);
    if (authResult.getState() != null) {
      result.putBundle(
          Constants.KEY_SPNEGO_CONTEXT, SpnegoStateCodec.encode(authResult.getState()));
    }
    krbAccount.save(context);
    SharedPreferences sharedPref =
        context.getSharedPreferences(Constants.PREFERENCE_NAME, Context.MODE_PRIVATE);
    BaseAuthenticatorActivity.ServiceTicketInfo.saveHttpAuthInfo(
        sharedPref,
        authResult.getSelectedService() == null
            ? serviceName
            : authResult.getSelectedService(),
        new Date().getTime(),
        mechanismName(negotiationState, authResult, httpPolicy),
        "SUCCESS");
    String mechanism = mechanismName(negotiationState, authResult, httpPolicy);
    Log.i(TAG, "HTTP_AUTH_RESULT mechanism=" + mechanism + " code=0");
    return result;
  }

  private static GetSpnegoTicketTask.SpnegoTicketResult requestServiceTicket(
      Context context,
      String serviceName,
      KerberosAccount account,
      byte[] incomingAuthToken,
      byte[] spnegoContext) {
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    return GetSpnegoTicketTask.getServiceTicket(
        context,
        tgt.asSubject(),
        account.getDomain(),
        account.getDomainController(),
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
      return normalizeIncomingAuthToken(java.util.Base64.getDecoder().decode(encoded));
    }
    return normalizeIncomingAuthToken(options.getByteArray(Constants.KEY_INCOMING_AUTH_TOKEN));
  }

  static byte[] normalizeIncomingAuthToken(byte[] token) {
    return token == null || token.length == 0 ? null : token;
  }

  private static SpnegoNegotiationState negotiationState(Bundle options, String host) {
    Bundle contextBundle = options.getBundle(Constants.KEY_SPNEGO_CONTEXT);
    if (contextBundle == null) return null;
    if (contextBundle.containsKey("version")) {
      return SpnegoStateCodec.decode(contextBundle, host);
    }
    byte[] legacy = contextBundle.getByteArray(Constants.KEY_GSS_CONTEXT_BYTES);
    return legacy == null ? null : SpnegoNegotiationState.kerberos(host, host, legacy);
  }

  private static String mechanismName(
      SpnegoNegotiationState previousState,
      HttpSpnegoResult result,
      HttpAuthenticationPolicy policy) {
    if (result.getSelectedMechanism() == SpnegoNegotiationState.Mechanism.NTLM) {
      return "NTLM";
    }
    if (previousState != null
        && previousState.getMechanism() == SpnegoNegotiationState.Mechanism.NTLM) {
      return "NTLM";
    }
    if (!policy.kerberosEnabled && policy.ntlmEnabled) return "NTLM";
    return "KERBEROS";
  }

  private HttpAuthenticationPolicy getHttpAuthenticationPolicy() {
    return getFromAccountConfiguration(
        config ->
            new HttpAuthenticationPolicy(
                config.isHttpKerberosEnabled(),
                config.isHttpNtlmConfigured(),
                config.getNtlmDomain()));
  }

  private static final class HttpAuthenticationPolicy {
    final boolean kerberosEnabled;
    final boolean ntlmEnabled;
    final String ntlmDomain;

    HttpAuthenticationPolicy(
        boolean kerberosEnabled, boolean ntlmEnabled, String ntlmDomain) {
      this.kerberosEnabled = kerberosEnabled;
      this.ntlmEnabled = ntlmEnabled;
      this.ntlmDomain = ntlmDomain;
    }

    boolean hasEnabledMechanism() {
      return kerberosEnabled || ntlmEnabled;
    }
  }


  private static boolean hasValidTicketGrantingTicket(KerberosAccount account) {
    TicketGrantingTicket tgt =
        TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
    return tgt != null && tgt.getExpiryDate() != null
        && tgt.getExpiryDate().after(new Date(System.currentTimeMillis() + 15 * 60 * 1000L));
  }

  private static boolean renewTicketGrantingTicket(Context context, KerberosAccount account) {
    char[] stored = new CredentialVault(context).load(account.getName(), account.getDomain());
    if (stored != null) {
      try {
        com.poelbos.kerberosauthenticator.internal.kinit.UserAuthenticationTask.AuthenticationOutcome
            outcome = com.poelbos.kerberosauthenticator.internal.kinit.UserAuthenticationTask.authenticate(
                context,
                new com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails(
                    account.getName(), stored, account.getDomain(),
                    account.getDomainController()));
        if (outcome.getResult().successful() && outcome.getSubject() != null) {
          account.setTicketGrantingTicket(
              new TicketGrantingTicket(outcome.getSubject()).asSerialized());
          account.save(context);
          return true;
        }
        if (outcome.getResult().isCredentialRejected()) {
          KerberosAccount.removeAccount(context);
          TgtRefreshWorker.markReauthenticationRequired(context);
          return false;
        }
      } finally {
        Arrays.fill(stored, '\0');
      }
    } else {
      TgtRefreshWorker.markReauthenticationRequired(context);
    }
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
    result.putBoolean(
        AccountManager.KEY_BOOLEAN_RESULT,
        features.length == 0 || getHttpAuthenticationPolicy().hasEnabledMechanism());
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

  private String getManagedConfigurationRealm() {
    return getFromAccountConfiguration(
        (config) -> {
          if (!config.hasManagedConfigs()) {
            return null;
          }
          return config.getRealm();
        });
  }
}
