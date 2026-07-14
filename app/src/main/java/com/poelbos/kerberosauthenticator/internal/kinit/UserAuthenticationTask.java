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
package com.poelbos.kerberosauthenticator.internal.kinit;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.os.AsyncTask;
import android.util.Log;
import com.poelbos.kerberosauthenticator.internal.KerberosAccountDetails;
import com.poelbos.kerberosauthenticator.internal.KerberosEnvironment;
import com.poelbos.kerberosauthenticator.internal.KerberosRuntimeCoordinator;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.ResultCode;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.AuthenticationDisposition;
import com.sun.security.auth.module.Krb5LoginModule;
import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;
import java.util.Arrays;
import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.LoginException;
import sun.security.krb5.KrbException;

/**
 * Performs the equivalent of kinit - logging in the user to the Kerberos KDC, producing a
 * ticket-granting-ticket for the user.
 */
public class UserAuthenticationTask extends AsyncTask<Void, Void, TicketRequestResult> {
  public static final class AuthenticationOutcome {
    private final TicketRequestResult result;
    private final Subject subject;

    AuthenticationOutcome(TicketRequestResult result, Subject subject) {
      this.result = result;
      this.subject = subject;
    }

    public TicketRequestResult getResult() { return result; }
    public Subject getSubject() { return subject; }
  }
  private static final String REFRESH_KRB5_CONFIG = "refreshKrb5Config";
  private static final String STORE_KEY = "storeKey";
  private static final String USE_FIRST_PASS = "useFirstPass";
  private static final String DEBUG = "debug";

  private final String username;
  private final char[] password;
  private final String adDomain;
  private final String domainController;
  private final UserAuthenticationResultListener listener;
  private final Context context;
  private Subject subject = null;

  public UserAuthenticationTask(
      Context context,
      UserAuthenticationResultListener listener,
      KerberosAccountDetails accountDetails) {
    this.context = context.getApplicationContext();
    this.listener = listener;
    this.username = accountDetails.getUsername();
    this.password = accountDetails.copyPassword();
    this.adDomain = accountDetails.getActiveDirectoryDomain();
    this.domainController = accountDetails.getAdDomainController();
  }

  @Override
  protected TicketRequestResult doInBackground(Void... voids) {
    try {
      AuthenticationOutcome outcome = authenticate(
          context, new KerberosAccountDetails(username, password, adDomain, domainController));
      subject = outcome.getSubject();
      return outcome.getResult();
    } finally {
      if (password != null) Arrays.fill(password, '\0');
    }
  }

  /** Performs a synchronous kinit. Intended for WorkManager and tests. */
  public static AuthenticationOutcome authenticate(
      Context context, KerberosAccountDetails details) {
    String username = details.getUsername();
    char[] password = details.copyPassword();
    String adDomain = details.getActiveDirectoryDomain();
    String domainController = details.getAdDomainController();
    Log.i(TAG, String.format("TGT_REQUEST realm=%s configuredKdc=%s",
        adDomain, domainController != null && !domainController.isEmpty()));
    try {
      return KerberosRuntimeCoordinator.run(
          context, adDomain, domainController, null, null,
          configured -> authenticateConfigured(username, password));
    } catch (IOException e) {
      Log.w(TAG, "Failure configuring Kerberos environment", e);
      return new AuthenticationOutcome(
          new TicketRequestResult(ResultCode.ERROR_LOGIN_FAILED, e.getMessage()), null);
    } finally {
      if (password != null) Arrays.fill(password, '\0');
    }
  }

  private static AuthenticationOutcome authenticateConfigured(String username, char[] password) {
    Krb5LoginModule lm = new Krb5LoginModule();
    Subject subject = new Subject();
    UsernamePasswordCallbackHandler handler = new UsernamePasswordCallbackHandler(username, password);
    Map<String, String> sharedState = new HashMap<>();
    sharedState.put(REFRESH_KRB5_CONFIG, "true");
    sharedState.put(STORE_KEY, "true");
    sharedState.put(USE_FIRST_PASS, "true");
    sharedState.put(DEBUG, "false");

    Map<String, Object> options = new HashMap<>();

    lm.initialize(subject, handler, sharedState, options);
    try {
      if (!lm.login()) {
        return new AuthenticationOutcome(
            new TicketRequestResult(ResultCode.ERROR_LOGIN_FAILED, "Login failed"), null);
      }

      if (!lm.commit()) {
        return new AuthenticationOutcome(
            new TicketRequestResult(ResultCode.ERROR_COMMIT_FAILED, "Commit failed"), null);
      }

      Log.i(TAG, "Kerberos authentication succeeded.");
      // Never stringify a Subject: it contains the TGT and session key material.
    } catch (LoginException e) {
      Log.w(TAG, "Failure logging in", e);
      int kerberosCode = kerberosErrorCode(e);
      String message = e.getMessage() == null ? "Kerberos login failed" : e.getMessage();
      if (kerberosCode == 24 || message.contains("Pre-authentication information was invalid")) {
        return new AuthenticationOutcome(
            new TicketRequestResult(
                ResultCode.ERROR_BAD_PASSWORD,
                message,
                AuthenticationDisposition.PERMANENT_CREDENTIAL_REJECTION),
            null);
      } else if (kerberosCode == 6 || kerberosCode == 12 || kerberosCode == 18
          || kerberosCode == 23) {
        return new AuthenticationOutcome(
            new TicketRequestResult(
                ResultCode.ERROR_LOGIN_FAILED,
                message,
                AuthenticationDisposition.PERMANENT_CREDENTIAL_REJECTION),
            null);
      } else {
        return new AuthenticationOutcome(
            new TicketRequestResult(
                ResultCode.ERROR_LOGIN_FAILED,
                message,
                AuthenticationDisposition.TRANSIENT_FAILURE),
            null);
      }
    } finally {
      handler.clear();
    }

    StringBuilder infoBuilder = new StringBuilder();

    for (Principal principal : subject.getPrincipals()) {
      infoBuilder.append("Principal: ").append(principal.getName()).append("\n");
    }

    for (Object credential : subject.getPrivateCredentials()) {
      infoBuilder.append("Credential type: ").append(credential.getClass()).append("\n");
    }

    return new AuthenticationOutcome(
        new TicketRequestResult(ResultCode.SUCCESS, infoBuilder.toString()), subject);
  }

  private static int kerberosErrorCode(Throwable error) {
    for (Throwable cause = error; cause != null; cause = cause.getCause()) {
      if (cause instanceof KrbException) return ((KrbException) cause).returnCode();
    }
    return -1;
  }

  @Override
  protected void onPostExecute(TicketRequestResult result) {
    super.onPostExecute(result);
    listener.onTicketGrantingTicketResult(result, subject);
  }

  @Override
  protected void onCancelled(TicketRequestResult result) {
    if (password != null) Arrays.fill(password, '\0');
    super.onCancelled(result);
  }

  @Override
  protected void onCancelled() {
    if (password != null) Arrays.fill(password, '\0');
    super.onCancelled();
  }
}
