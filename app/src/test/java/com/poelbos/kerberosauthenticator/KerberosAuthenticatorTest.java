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

import static com.poelbos.kerberosauthenticator.Constants.KERBEROS_ACCOUNT_TYPE;
import static com.poelbos.kerberosauthenticator.TestHelper.AD_DC;
import static com.poelbos.kerberosauthenticator.TestHelper.AD_DOMAIN;
import static com.poelbos.kerberosauthenticator.TestHelper.PASSWORD;
import static com.poelbos.kerberosauthenticator.TestHelper.TEST_AD_DOMAIN;
import static com.poelbos.kerberosauthenticator.TestHelper.TGT_B64;
import static com.poelbos.kerberosauthenticator.TestHelper.USERNAME;
import static com.google.common.truth.Truth.assertThat;
import static org.robolectric.Shadows.shadowOf;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.RestrictionsManager;
import android.os.Bundle;
import android.util.Base64;
import androidx.test.core.app.ApplicationProvider;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.ResultCode;
import com.poelbos.kerberosauthenticator.internal.spnego.GetSpnegoTicketTask;
import com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoResult;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;
import org.robolectric.shadows.ShadowAccountManager;

@RunWith(RobolectricTestRunner.class)
@Config(
    sdk = 26,
    shadows = {ShadowAccountManager.class})
public class KerberosAuthenticatorTest {
  private static final String TEST_SPNEGO_TOKEN = "dGVzdC1zcG5lZ28tdG9rZW4=";

  private ContextWrapper context;
  private AccountManager accountManager;
  private KerberosAuthenticator authenticator;

  @Before
  public void setUp() {
    context = ApplicationProvider.getApplicationContext();
    accountManager = AccountManager.get(context);
    authenticator = new KerberosAuthenticator(context);
    KerberosAuthenticator.setChromeCallerValidatorForTesting(
        (callerContext, options) ->
            options != null
                && Constants.CHROME_PACKAGE_NAME.equals(
                    options.getString(AccountManager.KEY_ANDROID_PACKAGE_NAME)));
  }

  @After
  public void tearDown() {
    KerberosAuthenticator.resetServiceTicketProviderForTesting();
    KerberosAuthenticator.resetTgtValidityCheckerForTesting();
    KerberosAuthenticator.resetTgtRenewerForTesting();
    KerberosAuthenticator.resetChromeCallerValidatorForTesting();
    KerberosAccount.resetAccountVisibilitySetterForTesting();
    shadowOf(accountManager).removeAllAccounts();
  }

  @Test
  public void testAuthenticatorUnsupportedOperationError() {
    Bundle result = authenticator.editProperties(null, null);
    assertThat(result.get(AccountManager.KEY_ERROR_CODE)).isEqualTo(6);
    assertThat(result.get(AccountManager.KEY_ERROR_MESSAGE))
        .isEqualTo("Unsupported method: editProperties");
  }

  @Test
  public void testAddAccount() {
    RestrictionsManager restrictionsManager =
        (RestrictionsManager)
            context.getSystemService(context.getSystemServiceName(RestrictionsManager.class));
    Bundle restrictionsBundle = TestHelper.makeRestrictionsBundle();
    restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, USERNAME);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
    Bundle result =
        authenticator.addAccount(
            null, null, null, new String[] {Constants.SPNEGO}, getTestOptions());
    assertIsAuthenticationActivity((Intent) result.get("intent"));
  }

  @Test
  public void testDeclineAddAccountWhenMissingManagedConfigs() {
    // SPNEGO requests are approved.
    Bundle result =
        authenticator.addAccount(
            null, null, null, new String[] {Constants.SPNEGO}, getTestOptions());
    assertThat(((Intent) result.get("intent")).getComponent().getClassName())
        .isEqualTo(DeclineAddingAccountActivity.class.getName());
  }

  @Test
  public void testDeclineAddAccountWhenNotSPNEGORequest() {
    // Other request types except for SPNEGO are declined as users should not add Kerberos accounts
    // manually.
    authenticator = new KerberosAuthenticator(context);
    Bundle result = authenticator.addAccount(null, null, null, new String[] {}, getTestOptions());
    assertThat(((Intent) result.get("intent")).getComponent().getClassName())
        .isEqualTo(DeclineAddingAccountActivity.class.getName());
  }

  @Test
  public void addAccountDeclinesSpnegoWhenAllHttpMechanismsAreDisabled() {
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, false);
    setTestRestrictions(restrictions);

    Bundle result =
        authenticator.addAccount(
            null, null, null, new String[] {Constants.SPNEGO}, getTestOptions());

    assertThat(((Intent) result.get(AccountManager.KEY_INTENT)).getComponent().getClassName())
        .isEqualTo(DeclineAddingAccountActivity.class.getName());
  }

  @Test
  public void testDeclineCallerNotChrome() {
    setTestRestrictions();

    Bundle options = new Bundle();
    options.putString(AccountManager.KEY_ANDROID_PACKAGE_NAME, "test_wrong_caller_app");
    Bundle result =
        authenticator.getAuthToken(
            null, null, "SPNEGO:HOSTBASED:HTTP@test-server.example.com", options);
    assertThat(result.get("errorCode")).isEqualTo(AccountManager.ERROR_CODE_UNSUPPORTED_OPERATION);
    assertThat(result.get("errorMessage")).isEqualTo("Unsupported method: Unsupported caller app.");
  }

  @Test
  public void testRejectsChromeCallerWithoutCallingUid() {
    Bundle options = new Bundle();
    options.putString(AccountManager.KEY_ANDROID_PACKAGE_NAME, Constants.CHROME_PACKAGE_NAME);

    assertThat(KerberosAuthenticator.isAuthorizedChromeCaller(context, options)).isFalse();
  }

  @Test
  public void emptyIncomingSpnegoTokenStartsFirstRound() {
    assertThat(KerberosAuthenticator.normalizeIncomingAuthToken(new byte[0])).isNull();
    assertThat(KerberosAuthenticator.normalizeIncomingAuthToken(new byte[] {0x01}))
        .isEqualTo(new byte[] {0x01});
  }

  @Test
  public void testGetAuthTokenBadServiceName() {
    String badTestToken = "SPNEGO:HOSTBASED:HTTP@.com";
    authenticator = new KerberosAuthenticator(context);
    Bundle result = authenticator.getAuthToken(null, null, badTestToken, getTestOptions());
    assertThat(result.get(AccountManager.KEY_ERROR_CODE))
        .isEqualTo(AccountManager.ERROR_CODE_BAD_ARGUMENTS);
    assertThat(result.get(AccountManager.KEY_ERROR_MESSAGE))
        .isEqualTo(String.format("Invalid auth token format for %s.", badTestToken));
  }

  @Test
  public void testGetAuthTokenNoKerberosAccount() {
    authenticator = new KerberosAuthenticator(context);

    Bundle result =
        authenticator.getAuthToken(
            null, null, "SPNEGO:HOSTBASED:HTTP@test-server.example.com", getTestOptions());
    assertThat(result.get(AccountManager.KEY_ERROR_CODE))
        .isEqualTo(AccountManager.ERROR_CODE_BAD_REQUEST);
    assertThat(result.get(AccountManager.KEY_ERROR_MESSAGE)).isEqualTo("No account configured?");
  }

  @Test
  public void testGetAuthTokenRenewTGT() {
    Account testAccount = new Account(TestHelper.USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_TGT, TGT_B64);

    Account[] accounts = AccountManager.get(context).getAccounts();
    // There should be exactly one account.
    assertThat(accounts.length).isEqualTo(1);
    Account account = accounts[0];
    Bundle result =
        authenticator.getAuthToken(
            null, account, "SPNEGO:HOSTBASED:HTTP@test-server.example.com", getTestOptions());
    // The auth token is invalid so we renew the TGT.
    Intent resultIntent = result.getParcelable(AccountManager.KEY_INTENT);
    assertThat(resultIntent.getExtras().getString(Constants.SERVICE_NAME))
        .isEqualTo("test-server.example.com");
    assertIsAuthenticationActivity(resultIntent);
  }

  @Test
  public void testGetAuthTokenValidTGT() {
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, serviceName, krbAccount, incoming, contextBytes, approvedTarget) ->
            new GetSpnegoTicketTask.SpnegoTicketResult(
                new TicketRequestResult(ResultCode.SUCCESS, "test service ticket"),
                TEST_SPNEGO_TOKEN));
    KerberosAuthenticator.setTgtValidityCheckerForTesting(krbAccount -> true);
    KerberosAccount.setAccountVisibilitySetterForTesting(
        (accountManager, account, packageName, visibility) -> true);
    Account testAccount = new Account(TestHelper.USERNAME, Constants.KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(
        testAccount, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);

    // Set application restrictions to match the account added to the account manager so that the
    // flow of triggering a change will not be invoked.
    RestrictionsManager restrictionsManager =
        (RestrictionsManager)
            context.getSystemService(context.getSystemServiceName(RestrictionsManager.class));
    Bundle restrictionsBundle = TestHelper.makeRestrictionsBundle();
    restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, USERNAME);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    Account[] accounts = AccountManager.get(context).getAccounts();
    // There should be exactly one account.
    assertThat(accounts).hasLength(1);
    Account account = accounts[0];
    Bundle result =
        authenticator.getAuthToken(
            null, account, "SPNEGO:HOSTBASED:HTTP@test-server.example.com", getTestOptions());

    assertThat(result.getString(AccountManager.KEY_ACCOUNT_NAME)).isEqualTo(USERNAME);
    assertThat(result.getString(AccountManager.KEY_ACCOUNT_TYPE))
        .isEqualTo(Constants.KERBEROS_ACCOUNT_TYPE);
    assertThat(result.getString(AccountManager.KEY_AUTHTOKEN)).isEqualTo(TEST_SPNEGO_TOKEN);
    assertThat(result.containsKey(AccountManager.KEY_INTENT)).isFalse();
  }

  @Test
  public void initialTokenReturnsContextAndRecoversDroppedBundle() throws Exception {
    String encodedToken =
        Base64.encodeToString(new byte[] {1, 2, 3}, Base64.NO_WRAP);
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, serviceName, krbAccount, incoming, contextBytes, approvedTarget) ->
            new GetSpnegoTicketTask.SpnegoTicketResult(
                new TicketRequestResult(ResultCode.SUCCESS, "test service ticket"),
                encodedToken,
                new byte[] {9, 8, 7},
                "backend.example.com"));
    KerberosAuthenticator.setTgtValidityCheckerForTesting(krbAccount -> true);
    KerberosAccount.setAccountVisibilitySetterForTesting(
        (manager, visibleAccount, packageName, visibility) -> {
          throw new AssertionError("HTTP token requests must not mutate account visibility");
        });
    Account testAccount = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);
    accountManager.setPassword(testAccount, "synthetic-legacy-password");
    setTestRestrictions();

    Bundle result =
        authenticator.getAuthToken(
            null,
            testAccount,
            "SPNEGO:HOSTBASED:HTTP@portal.example.com",
            getTestOptions());

    Bundle chromeContext = result.getBundle(Constants.KEY_SPNEGO_CONTEXT);
    assertThat(chromeContext).isNotNull();
    com.poelbos.kerberosauthenticator.internal.spnego.SpnegoNegotiationState state =
        com.poelbos.kerberosauthenticator.internal.spnego.SpnegoStateCodec.decode(
            chromeContext, "portal.example.com");
    assertThat(state.getPhase())
        .isEqualTo(
            com.poelbos.kerberosauthenticator.internal.spnego.SpnegoNegotiationState.Phase.OFFERED);
    assertThat(state.getSelectedService()).isEqualTo("backend.example.com");
    assertThat(state.getKerberosContext()).isEqualTo(new byte[] {9, 8, 7});
    assertThat(accountManager.getPassword(testAccount)).isEqualTo("synthetic-legacy-password");
    com.hierynomus.spnego.NegTokenTarg server = new com.hierynomus.spnego.NegTokenTarg();
    server.setSupportedMech(new com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier("1.2.840.113554.1.2.2"));
    com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer encoded =
        new com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer(
            com.hierynomus.protocol.commons.buffer.Endian.LE);
    server.write(encoded);
    AtomicInteger continuations = new AtomicInteger();
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, serviceName, krbAccount, incoming, contextBytes, approvedTarget) -> {
          assertThat(serviceName).isEqualTo("backend.example.com");
          assertThat(contextBytes).isEqualTo(new byte[] {9, 8, 7});
          continuations.incrementAndGet();
          return new GetSpnegoTicketTask.SpnegoTicketResult(
              new TicketRequestResult(ResultCode.SUCCESS, "synthetic continuation"), encodedToken);
        });
    Bundle continuationOptions = getTestOptions();
    continuationOptions.putString(Constants.KEY_INCOMING_AUTH_TOKEN,
        Base64.encodeToString(encoded.getCompactData(), Base64.NO_WRAP));
    Bundle continuation = authenticator.getAuthToken(null, testAccount,
        "SPNEGO:HOSTBASED:HTTP@portal.example.com", continuationOptions);
    assertThat(continuation.getInt(Constants.KEY_SPNEGO_RESULT)).isEqualTo(HttpSpnegoResult.OK);
    assertThat(continuations.get()).isEqualTo(1);
  }

  @Test
  public void approvedFarmRetryRequiresPendingRequestAndPinsItsTarget() throws Exception {
    Account account = addTestAccount();
    accountManager.setUserData(account, KerberosAccount.KEY_AD_DOMAIN, "EXAMPLE.COM");
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putString(AccountConfiguration.AD_REALM_KEY, "EXAMPLE.COM");
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, false);
    setTestRestrictions(restrictions);
    com.poelbos.kerberosauthenticator.internal.HttpSpnSettings.setForShell(context,
        "EXAMPLE.COM", "portal.example.com", "web1.example.com", true,
        "web2.example.com,web3.example.com");
    KerberosAuthenticator.setTgtValidityCheckerForTesting(ignored -> true);
    AtomicInteger calls = new AtomicInteger();
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, serviceName, krbAccount, incoming, contextBytes, approvedTarget) -> {
          assertThat(serviceName).isEqualTo("portal.example.com");
          assertThat(incoming).isNull();
          assertThat(contextBytes).isNull();
          if (calls.getAndIncrement() == 0) assertThat(approvedTarget).isNull();
          else {
            assertThat(approvedTarget).isEqualTo("web2.example.com");
            // A concurrent origin preference update must not change this request's target.
            com.poelbos.kerberosauthenticator.internal.HttpSpnSettings.Mapping mapping =
                com.poelbos.kerberosauthenticator.internal.HttpSpnSettings.get(context, "EXAMPLE.COM", serviceName);
            com.poelbos.kerberosauthenticator.internal.HttpSpnRetryPolicy.INSTANCE.retry(
                "EXAMPLE.COM", serviceName, mapping, 41, "web3$@EXAMPLE.COM");
            assertThat(approvedTarget).isEqualTo("web2.example.com");
          }
          return new GetSpnegoTicketTask.SpnegoTicketResult(
              new TicketRequestResult(ResultCode.SUCCESS, "synthetic ticket"),
              Base64.encodeToString(new byte[]{1,2,3}, Base64.NO_WRAP), new byte[]{9,8,7},
              approvedTarget == null ? "web1.example.com" : approvedTarget);
        });
    // Synthetic KRB-ERROR 41 for web2$@EXAMPLE.COM; contains no real credentials.
    byte[] error = Base64.decode("fkwwSqADAgEFoQMCAR6kERgPMjAyNjEwMTQxNDAwMDBapQMCAQCmAwIBKakNGwtFWEFNUExFLkNPTaoSMBCgAwIBAaEJMAcbBXdlYjIk", Base64.NO_WRAP);
    com.hierynomus.spnego.NegTokenTarg server = new com.hierynomus.spnego.NegTokenTarg();
    server.setResponseToken(error);
    com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer encoded =
        new com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer(com.hierynomus.protocol.commons.buffer.Endian.LE);
    server.write(encoded);
    Bundle options = getTestOptions();
    options.putString(Constants.KEY_INCOMING_AUTH_TOKEN, Base64.encodeToString(encoded.getCompactData(), Base64.NO_WRAP));
    assertThat(authenticator.getAuthToken(null, account, "SPNEGO:HOSTBASED:HTTP@portal.example.com", options)
        .getInt(Constants.KEY_SPNEGO_RESULT)).isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
    assertThat(calls.get()).isEqualTo(0);
    authenticator.getAuthToken(null, account, "SPNEGO:HOSTBASED:HTTP@portal.example.com", getTestOptions());
    Bundle retry = authenticator.getAuthToken(null, account, "SPNEGO:HOSTBASED:HTTP@portal.example.com", options);
    assertThat(retry.getInt(Constants.KEY_SPNEGO_RESULT)).isEqualTo(HttpSpnegoResult.OK);
    assertThat(calls.get()).isEqualTo(2);
    com.poelbos.kerberosauthenticator.internal.HttpSpnSettings.clearForShell(context, "EXAMPLE.COM", "portal.example.com");
  }

  @Test
  public void malformedContinuationContextReturnsChromeProtocolError() {
    KerberosAuthenticator.setTgtValidityCheckerForTesting(krbAccount -> true);
    Account testAccount = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);
    setTestRestrictions();
    Bundle options = getTestOptions();
    Bundle invalid = new Bundle();
    invalid.putInt("version", 99);
    options.putBundle(Constants.KEY_SPNEGO_CONTEXT, invalid);
    options.putString(Constants.KEY_INCOMING_AUTH_TOKEN, "AQ==");

    Bundle result =
        authenticator.getAuthToken(
            null,
            testAccount,
            "SPNEGO:HOSTBASED:HTTP@portal.example.com",
            options);

    assertThat(result.getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(
            com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoResult.ERR_INVALID_RESPONSE);
    assertThat(result.containsKey(AccountManager.KEY_AUTHTOKEN)).isFalse();
  }

  @Test
  public void malformedIncomingTokenReturnsChromeProtocolError() {
    KerberosAuthenticator.setTgtValidityCheckerForTesting(krbAccount -> true);
    Account testAccount = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);
    setTestRestrictions();
    Bundle options = getTestOptions();
    options.putString(Constants.KEY_INCOMING_AUTH_TOKEN, "not valid base64!");

    Bundle result =
        authenticator.getAuthToken(
            null,
            testAccount,
            "SPNEGO:HOSTBASED:HTTP@portal.example.com",
            options);

    assertThat(result.getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(
            com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoResult.ERR_INVALID_RESPONSE);
    assertThat(result.containsKey(AccountManager.KEY_AUTHTOKEN)).isFalse();
  }

  @Test
  public void testGetAuthTokenRenewsExpiredTgtBeforePromptingForPassword() {
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, serviceName, krbAccount, incoming, contextBytes, approvedTarget) ->
            new GetSpnegoTicketTask.SpnegoTicketResult(
                new TicketRequestResult(ResultCode.SUCCESS, "test service ticket"),
                TEST_SPNEGO_TOKEN));
    KerberosAuthenticator.setTgtValidityCheckerForTesting(krbAccount -> false);
    KerberosAuthenticator.setTgtRenewerForTesting((renewalContext, krbAccount) -> true);
    KerberosAccount.setAccountVisibilitySetterForTesting(
        (accountManager, account, packageName, visibility) -> true);
    Account testAccount = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);
    RestrictionsManager restrictionsManager =
        (RestrictionsManager)
            context.getSystemService(context.getSystemServiceName(RestrictionsManager.class));
    Bundle restrictionsBundle = TestHelper.makeRestrictionsBundle();
    restrictionsBundle.putString(AccountConfiguration.USERNAME_KEY, USERNAME);
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    Bundle result =
        authenticator.getAuthToken(
            null,
            testAccount,
            "SPNEGO:HOSTBASED:HTTP@test-server.example.com",
            getTestOptions());

    assertThat(result.getString(AccountManager.KEY_AUTHTOKEN)).isEqualTo(TEST_SPNEGO_TOKEN);
    assertThat(result.containsKey(AccountManager.KEY_INTENT)).isFalse();
  }

  @Test
  public void testGetAuthTokenAccountDetailsChange() {
    Account testAccount = new Account(TestHelper.USERNAME, Constants.KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(testAccount);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(testAccount, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(
        testAccount, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);

    // Set application restrictions with a different account name to test that re-authentication
    // flow is triggered.
    RestrictionsManager restrictionsManager =
        (RestrictionsManager)
            context.getSystemService(context.getSystemServiceName(RestrictionsManager.class));
    Bundle restrictionsBundle = TestHelper.makeRestrictionsBundle();
    restrictionsBundle.putString(AccountConfiguration.AD_REALM_KEY, "CHANGED.EXAMPLE.COM");
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);

    Account[] accounts = AccountManager.get(context).getAccounts();
    // There should be exactly one account.
    assertThat(accounts).hasLength(1);
    Account account = accounts[0];
    Bundle result =
        authenticator.getAuthToken(
            null, account, "SPNEGO:HOSTBASED:HTTP@test-server.example.com", getTestOptions());

    // The auth token is invalid so we renew the TGT.
    Intent resultIntent = result.getParcelable(AccountManager.KEY_INTENT);
    assertThat(resultIntent.getExtras().getString("ServiceName"))
        .isEqualTo("test-server.example.com");
    assertIsAuthenticationActivity(resultIntent);
  }

  @Test
  public void allHttpMechanismsDisabledRejectsTokenWithoutCheckingTgt() {
    AtomicInteger tgtChecks = new AtomicInteger();
    KerberosAuthenticator.setTgtValidityCheckerForTesting(
        account -> {
          tgtChecks.incrementAndGet();
          return false;
        });
    Account account = addTestAccount();
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, false);
    setTestRestrictions(restrictions);

    Bundle result =
        authenticator.getAuthToken(
            null,
            account,
            "SPNEGO:HOSTBASED:HTTP@portal.example.com",
            getTestOptions());

    assertThat(result.getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_UNSUPPORTED_AUTH_SCHEME);
    assertThat(tgtChecks.get()).isEqualTo(0);
    assertThat(result.containsKey(AccountManager.KEY_INTENT)).isFalse();
  }

  @Test
  public void ntlmOnlyDoesNotCheckTgtOrRequestKerberosTicket() {
    AtomicInteger tgtChecks = new AtomicInteger();
    AtomicInteger kerberosRequests = new AtomicInteger();
    KerberosAuthenticator.setTgtValidityCheckerForTesting(
        account -> {
          tgtChecks.incrementAndGet();
          return false;
        });
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, serviceName, account, incoming, contextBytes, approvedTarget) -> {
          kerberosRequests.incrementAndGet();
          return new GetSpnegoTicketTask.SpnegoTicketResult(
              new TicketRequestResult(ResultCode.ERROR_GSS_FAILURE, "must not be called"), null);
        });
    Account account = addTestAccount();
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, true);
    restrictions.putString(AccountConfiguration.NTLM_DOMAIN_KEY, "EXAMPLE");
    setTestRestrictions(restrictions);

    Bundle result =
        authenticator.getAuthToken(
            null,
            account,
            "SPNEGO:HOSTBASED:HTTP@portal.example.com",
            getTestOptions());

    assertThat(result.getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_MISSING_AUTH_CREDENTIALS);
    assertThat(tgtChecks.get()).isEqualTo(0);
    assertThat(kerberosRequests.get()).isEqualTo(0);
    assertThat(result.containsKey(AccountManager.KEY_INTENT)).isFalse();
  }

  @Test
  public void ntlmContinuationRecoversDroppedContextAndConsumesItOnce() throws Exception {
    Account account = prepareNtlm();
    Bundle first = httpRound(account, getTestOptions());
    assertThat(first.getBundle(Constants.KEY_SPNEGO_CONTEXT).getString("phase"))
        .isEqualTo("NTLM_TYPE1_SENT");
    Bundle third = httpRound(account, ntlmChallenge());
    assertType3(third);
    assertThat(httpRound(account, ntlmChallenge()).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
    Bundle explicit = ntlmChallenge();
    explicit.putBundle(Constants.KEY_SPNEGO_CONTEXT, third.getBundle(Constants.KEY_SPNEGO_CONTEXT));
    assertThat(httpRound(account, explicit).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_AUTH_CREDENTIALS);
  }

  @Test
  public void ntlmExplicitContextClearsRecoveryCopy() throws Exception {
    Account account = prepareNtlm();
    Bundle first = httpRound(account, getTestOptions());
    Bundle options = ntlmChallenge();
    options.putBundle(Constants.KEY_SPNEGO_CONTEXT, first.getBundle(Constants.KEY_SPNEGO_CONTEXT));
    assertType3(httpRound(account, options));
    assertThat(httpRound(account, ntlmChallenge()).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
  }

  @Test
  public void concurrentNtlmNegotiationsAreNotGuessed() throws Exception {
    Account account = prepareNtlm();
    httpRound(account, getTestOptions());
    httpRound(account, getTestOptions());
    assertThat(httpRound(account, ntlmChallenge()).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
  }

  @Test
  public void malformedContextDiscardsPendingNtlmState() throws Exception {
    Account account = prepareNtlm();
    httpRound(account, getTestOptions());
    Bundle options = ntlmChallenge();
    Bundle invalid = new Bundle();
    invalid.putInt("version", 99);
    options.putBundle(Constants.KEY_SPNEGO_CONTEXT, invalid);
    assertThat(httpRound(account, options).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
    assertThat(httpRound(account, ntlmChallenge()).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
  }

  @Test
  public void ntlmRecoveryDoesNotCrossHosts() throws Exception {
    Account account = prepareNtlm();
    httpRound(account, getTestOptions());
    Bundle other = authenticator.getAuthToken(null, account,
        "SPNEGO:HOSTBASED:HTTP@other.example.com", ntlmChallenge());
    assertThat(other.getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
    assertType3(httpRound(account, ntlmChallenge()));
  }

  @Test
  public void credentialDeletionDiscardsPendingNtlmState() throws Exception {
    Account account = prepareNtlm();
    httpRound(account, getTestOptions());
    context.getSharedPreferences("encrypted_enterprise_credentials", 0).edit()
        .putString("ciphertext", "synthetic").commit();
    new CredentialVault(context).delete();
    assertThat(httpRound(account, ntlmChallenge()).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
  }

  @Test
  public void combinedOfferRecoversThenSelectsNtlm() throws Exception {
    Account account = prepareNtlm();
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, true);
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, true);
    restrictions.putString(AccountConfiguration.NTLM_DOMAIN_KEY, "EXAMPLE");
    setTestRestrictions(restrictions);
    KerberosAuthenticator.setTgtValidityCheckerForTesting(ignored -> true);
    com.hierynomus.spnego.NegTokenInit offer = new com.hierynomus.spnego.NegTokenInit();
    offer.addSupportedMech(new com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier("1.2.840.113554.1.2.2"));
    offer.setMechToken(new byte[] {1, 2, 3});
    com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer encoded =
        new com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer(
            com.hierynomus.protocol.commons.buffer.Endian.LE);
    offer.write(encoded);
    KerberosAuthenticator.setServiceTicketProviderForTesting(
        (requestContext, host, krbAccount, incoming, contextBytes, retry) ->
            new GetSpnegoTicketTask.SpnegoTicketResult(
                new TicketRequestResult(ResultCode.SUCCESS, "synthetic"),
                Base64.encodeToString(encoded.getCompactData(), Base64.NO_WRAP)));
    Bundle first = httpRound(account, getTestOptions());
    assertThat(first.getBundle(Constants.KEY_SPNEGO_CONTEXT).getBoolean("ntlmOffered")).isTrue();
    assertType3(httpRound(account, ntlmChallenge()));
  }

  @Test
  public void managedPolicyChangeDiscardsPendingState() throws Exception {
    Account account = prepareNtlm();
    httpRound(account, getTestOptions());
    new com.poelbos.kerberosauthenticator.files.ManagedSharesChangedReceiver().onReceive(
        context, new Intent(Intent.ACTION_APPLICATION_RESTRICTIONS_CHANGED));
    assertThat(httpRound(account, ntlmChallenge()).getInt(Constants.KEY_SPNEGO_RESULT))
        .isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
  }

  private Account prepareNtlm() {
    Account account = addTestAccount();
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, true);
    restrictions.putString(AccountConfiguration.NTLM_DOMAIN_KEY, "EXAMPLE");
    setTestRestrictions(restrictions);
    authenticator = new KerberosAuthenticator(context,
        new com.poelbos.kerberosauthenticator.internal.spnego.HttpSpnegoCoordinator.CredentialProvider() {
          public boolean isAvailable(String username, String realm) { return true; }
          public char[] load(String username, String realm) { return "synthetic-password".toCharArray(); }
        });
    return account;
  }

  private Bundle httpRound(Account account, Bundle options) {
    return authenticator.getAuthToken(null, account,
        "SPNEGO:HOSTBASED:HTTP@portal.example.com", options);
  }

  private static void assertType3(Bundle result) throws Exception {
    assertThat(result.getInt(Constants.KEY_SPNEGO_RESULT)).isEqualTo(HttpSpnegoResult.OK);
    byte[] wrapped = Base64.decode(result.getString(AccountManager.KEY_AUTHTOKEN), Base64.NO_WRAP);
    byte[] raw = new com.hierynomus.spnego.NegTokenTarg().read(wrapped).getResponseToken();
    assertThat(java.util.Arrays.copyOf(raw, 12))
        .isEqualTo(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0, 3, 0, 0, 0});
  }

  private static Bundle ntlmChallenge() throws Exception {
    // Synthetic Type 2: Unicode, NTLM, extended session security and target info.
    com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer raw =
        new com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer(
            com.hierynomus.protocol.commons.buffer.Endian.LE);
    raw.putRawBytes(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}).putUInt32(2);
    raw.putUInt16(0).putUInt16(0).putUInt32(48);
    raw.putUInt32(0x20888205L);
    raw.putRawBytes(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}).putLong(0);
    raw.putUInt16(16).putUInt16(16).putUInt32(48);
    raw.putUInt16(7).putUInt16(8).putLong(0L);
    raw.putUInt16(0).putUInt16(0);
    com.hierynomus.spnego.NegTokenTarg server = new com.hierynomus.spnego.NegTokenTarg();
    server.setSupportedMech(com.poelbos.kerberosauthenticator.internal.ntlm.HttpNtlmV2Engine.NTLMSSP_OID);
    server.setResponseToken(raw.getCompactData());
    com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer wrapped =
        new com.hierynomus.protocol.commons.buffer.Buffer.PlainBuffer(
            com.hierynomus.protocol.commons.buffer.Endian.LE);
    server.write(wrapped);
    Bundle options = getTestOptions();
    options.putString(Constants.KEY_INCOMING_AUTH_TOKEN,
        Base64.encodeToString(wrapped.getCompactData(), Base64.NO_WRAP));
    return options;
  }

  @Test
  public void testHasFeatures() {
    Account account = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(account);
    accountManager.setPassword(account, PASSWORD);
    accountManager.setUserData(account, "ad_domain", AD_DOMAIN);
    accountManager.setUserData(account, "domain_controller", AD_DC);
    accountManager.setUserData(account, "ticket_granting_ticket", TGT_B64);
    accountManager.setUserData(account, "service_ticket_name", Constants.SERVICE_NAME);

    Bundle response = authenticator.hasFeatures(null, account, new String[] {});
    assertThat(response.get(AccountManager.KEY_BOOLEAN_RESULT)).isEqualTo(true);
    response = authenticator.hasFeatures(null, account, new String[] {"SPNEGO"});
    assertThat(response.get(AccountManager.KEY_BOOLEAN_RESULT)).isEqualTo(true);
  }

  @Test
  public void hasFeaturesRejectsSpnegoWhenAllHttpMechanismsAreDisabled() {
    Bundle restrictions = TestHelper.makeRestrictionsBundle();
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_KERBEROS_KEY, false);
    restrictions.putBoolean(AccountConfiguration.ENABLE_HTTP_NTLM_KEY, false);
    setTestRestrictions(restrictions);
    Account account = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);

    Bundle response = authenticator.hasFeatures(null, account, new String[] {Constants.SPNEGO});

    assertThat(response.getBoolean(AccountManager.KEY_BOOLEAN_RESULT)).isFalse();
  }

  private void setTestRestrictions() {
    RestrictionsManager restrictionsManager =
        (RestrictionsManager)
            context.getSystemService(context.getSystemServiceName(RestrictionsManager.class));
    Bundle restrictionsBundle = TestHelper.makeRestrictionsBundle();
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
  }

  private void setTestRestrictions(Bundle restrictionsBundle) {
    RestrictionsManager restrictionsManager =
        (RestrictionsManager)
            context.getSystemService(context.getSystemServiceName(RestrictionsManager.class));
    shadowOf(restrictionsManager).setApplicationRestrictions(restrictionsBundle);
  }

  private Account addTestAccount() {
    KerberosAccount.setAccountVisibilitySetterForTesting(
        (manager, account, packageName, visibility) -> true);
    Account account = new Account(USERNAME, KERBEROS_ACCOUNT_TYPE);
    shadowOf(accountManager).addAccount(account);
    accountManager.setUserData(account, KerberosAccount.KEY_AD_DC, AD_DC);
    accountManager.setUserData(account, KerberosAccount.KEY_AD_DOMAIN, TEST_AD_DOMAIN);
    accountManager.setUserData(account, KerberosAccount.KEY_TGT, TestHelper.B64_SUBJECT);
    return account;
  }

  private static void assertIsAuthenticationActivity(Intent intent) {
    assertThat(intent.getComponent().getClassName()).isEqualTo(LoginActivity.class.getName());
  }

  private static Bundle getTestOptions() {
    Bundle options = new Bundle();
    options.putString(AccountManager.KEY_ANDROID_PACKAGE_NAME, Constants.CHROME_PACKAGE_NAME);
    return options;
  }
}
