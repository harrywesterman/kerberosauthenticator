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
package com.poelbos.kerberosauthenticator.internal.spnego;

import static com.poelbos.kerberosauthenticator.Constants.TAG;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.AsyncTask;
import android.util.Base64;
import android.util.Log;
import com.poelbos.kerberosauthenticator.internal.DnsKdcDiscovery;
import com.poelbos.kerberosauthenticator.internal.KerberosEnvironment;
import com.poelbos.kerberosauthenticator.internal.SpnResolver;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.ResultCode;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import javax.security.auth.Subject;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.GSSManagerImpl;
import sun.security.jgss.GSSUtil;

/** Task for getting a SPNEGO ticket for the provided service. */
public class GetSpnegoTicketTask extends AsyncTask<String, Void, TicketRequestResult> {
  private final Subject subject;
  private final ServiceTicketResultListener listener;
  private final String domain;
  private final String domainController;
  private final Context context;
  private String service = null;
  private String serviceSpnegoTicket = null;

  public static final class SpnegoTicketResult {
    private final TicketRequestResult requestResult;
    private final String serviceTicket;
    private final byte[] spnegoContext;
    private final String selectedService;

    public SpnegoTicketResult(TicketRequestResult requestResult, String serviceTicket) {
      this(requestResult, serviceTicket, null);
    }

    public SpnegoTicketResult(
        TicketRequestResult requestResult, String serviceTicket, byte[] spnegoContext) {
      this(requestResult, serviceTicket, spnegoContext, null);
    }

    public SpnegoTicketResult(
        TicketRequestResult requestResult,
        String serviceTicket,
        byte[] spnegoContext,
        String selectedService) {
      this.requestResult = requestResult;
      this.serviceTicket = serviceTicket;
      this.spnegoContext = spnegoContext;
      this.selectedService = selectedService;
    }

    public TicketRequestResult getRequestResult() {
      return requestResult;
    }

    public String getServiceTicket() {
      return serviceTicket;
    }

    public byte[] getSpnegoContext() {
      return spnegoContext;
    }

    public String getSelectedService() {
      return selectedService;
    }
  }

  public GetSpnegoTicketTask(
      Context context,
      Subject subject,
      String domain,
      String domainController,
      ServiceTicketResultListener listener) {
    this.context = context.getApplicationContext();
    this.subject = subject;
    this.domain = domain;
    this.domainController = domainController;
    this.listener = listener;
  }

  @Override
  protected TicketRequestResult doInBackground(String... services) {
    service = services[0];
    SpnegoTicketResult result =
        getServiceTicket(
            context,
            subject,
            domain,
            domainController,
            service);
    serviceSpnegoTicket = result.getServiceTicket();
    return result.getRequestResult();
  }

  public static SpnegoTicketResult getServiceTicket(
      Context context,
      Subject subject,
      String domain,
      String domainController,
      String service) {
    return getServiceTicket(
        context,
        subject,
        domain,
        domainController,
        service,
        null,
        null);
  }

  public static SpnegoTicketResult getServiceTicket(
      Context context,
      Subject subject,
      String domain,
      String domainController,
      String service,
    byte[] incomingAuthToken,
    byte[] exportedContext) {
    GSSUtil.setGlobalSubject(subject);
    try {
      KerberosEnvironment.configure(context, domain, domainController, service);
    } catch (IOException e) {
      Log.e(TAG, "Failure configuring Kerberos environment", e);
      return new SpnegoTicketResult(
          new TicketRequestResult(ResultCode.ERROR_GSS_FAILURE, e.getMessage()), null);
    }

    GSSManager manager = new GSSManagerImpl(GSSCaller.CALLER_INITIATE, false);

    try {
      Oid spnegoOid = new Oid("1.3.6.1.5.5.2");
      boolean serviceResolvable = logServiceResolution(context, service);
      String normalizedService = normalizeService(service);
      if (!serviceResolvable && normalizedService != null && !isIpv4Address(normalizedService)) {
        Log.w(TAG, "Service host could not be resolved: " + service);
        return new SpnegoTicketResult(
            new TicketRequestResult(
                ResultCode.ERROR_DNS_FAILURE, "DNS resolution failed for " + service),
            null);
      }
      List<String> dnsAliasCandidates = getDnsAliasCandidates(context, service);
      GSSException lastException = null;
      boolean continuation = incomingAuthToken != null || exportedContext != null;
      List<String> candidates =
          SpnResolver.resolve(context, domain, service, dnsAliasCandidates);
      candidates =
          candidatesForRound(
              candidates,
              continuation ? SpnResolver.normalizeHost(service, domain) : null,
              continuation);
      Log.i(TAG, "Direct SPNEGO candidates for " + service + ": " + candidates);
      for (String ticketService : candidates) {
        try {
          return requestCandidate(
              manager,
              spnegoOid,
              ticketService,
              service,
              incomingAuthToken,
              exportedContext);
        } catch (GSSException e) {
          lastException = e;
          Log.w(
              TAG,
              String.format(
                  "SPN_TICKET_FAILED host=%s major=%d minor=%d unknownPrincipal=%s",
                  ticketService, e.getMajor(), e.getMinor(), isUnknownPrincipal(e)));
          if (!isUnknownPrincipal(e)) {
            return new SpnegoTicketResult(
                new TicketRequestResult(ResultCode.ERROR_GSS_FAILURE, e.getMessage()), null);
          }
        }
      }
      if (lastException != null) {
        ResultCode resultCode =
            isUnknownPrincipal(lastException)
                ? ResultCode.ERROR_NO_SPN
                : ResultCode.ERROR_GSS_FAILURE;
        return new SpnegoTicketResult(
            new TicketRequestResult(resultCode, lastException.getMessage()), null);
      }
      return new SpnegoTicketResult(
          new TicketRequestResult(ResultCode.ERROR_NO_SPN, "No valid HTTP SPN candidates."),
          null);
    } catch (GSSException e) {
      Log.e(TAG, "Error while getting service ticket", e);
      return new SpnegoTicketResult(
          new TicketRequestResult(ResultCode.ERROR_GSS_FAILURE, e.getMessage()), null);
    }
  }

  static boolean isUnknownPrincipal(Throwable error) {
    for (Throwable current = error; current != null; current = current.getCause()) {
      String message = current.getMessage();
      if (message != null) {
        String normalized = message.toLowerCase(Locale.US);
        if (normalized.contains("server not found in kerberos database")
            || normalized.contains("kdc_err_s_principal_unknown")
            || normalized.contains("s_principal_unknown")) {
          return true;
        }
      }
    }
    return false;
  }

  static List<String> candidatesForRound(
      List<String> candidates, String previousCandidate, boolean continuation) {
    if (candidates == null) {
      return new ArrayList<>();
    }
    if (continuation && previousCandidate != null && candidates.contains(previousCandidate)) {
      return java.util.Collections.singletonList(previousCandidate);
    }
    return new ArrayList<>(candidates);
  }

  private static SpnegoTicketResult requestCandidate(
      GSSManager manager,
      Oid spnegoOid,
      String ticketService,
      String requestedService,
      byte[] incomingAuthToken,
      byte[] exportedContext)
      throws GSSException {
    GSSName serverName =
        manager.createName("HTTP@" + ticketService, GSSName.NT_HOSTBASED_SERVICE, spnegoOid);
    GSSContext gssContext =
        exportedContext == null
            ? manager.createContext(serverName, spnegoOid, null, GSSContext.DEFAULT_LIFETIME)
            : manager.createContext(exportedContext);
    byte[] spnegoToken = incomingAuthToken == null ? new byte[0] : incomingAuthToken;
    spnegoToken = gssContext.initSecContext(spnegoToken, 0, spnegoToken.length);

    Log.i(
        TAG,
        String.format(
            "SPNEGO_SELECTED host=%s contextEstablished=%s",
            ticketService, gssContext.isEstablished()));

    String encodedTicket =
        spnegoToken == null ? null : Base64.encodeToString(spnegoToken, Base64.NO_WRAP);
    byte[] nextContext = null;
    if (spnegoToken != null && !gssContext.isEstablished()) {
      nextContext = gssContext.export();
    }
    if (!ticketService.equals(requestedService)) {
      Log.i(
          TAG,
          String.format(
              "Using fallback SPNEGO service %s for requested service %s.",
              ticketService, requestedService));
    }
    return new SpnegoTicketResult(
        new TicketRequestResult(ResultCode.SUCCESS, "HTTP ticket for " + serverName),
        encodedTicket,
        nextContext,
        ticketService);
  }

  @Override
  protected void onPostExecute(TicketRequestResult result) {
    super.onPostExecute(result);
    listener.onServiceTicketResult(service, result, serviceSpnegoTicket);
  }

  @Override
  protected void onCancelled(TicketRequestResult result) {
    super.onCancelled();
    listener.onServiceTicketResult(service, result, null);
  }

  private static boolean logServiceResolution(Context context, String service) {
    ConnectivityManager connectivityManager =
        (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    Network activeNetwork =
        connectivityManager == null ? null : connectivityManager.getActiveNetwork();
    if (activeNetwork != null) {
      try {
        for (InetAddress address : activeNetwork.getAllByName(service)) {
          Log.i(
              TAG,
              String.format(
                  "Active network resolved %s to %s with canonical host %s",
                  service, address.getHostAddress(), address.getCanonicalHostName()));
        }
        return true;
      } catch (IOException e) {
        Log.w(TAG, "Active network could not resolve service " + service, e);
      }
    }
    try {
      InetAddress address = InetAddress.getByName(service);
      Log.i(
          TAG,
              String.format(
                  "Default resolver resolved %s to %s with canonical host %s",
                  service, address.getHostAddress(), address.getCanonicalHostName()));
      return true;
    } catch (IOException e) {
      Log.w(TAG, "Default resolver could not resolve service " + service, e);
    }
    return false;
  }

  private static List<String> getDnsAliasCandidates(Context context, String service) {
    List<String> aliases = DnsKdcDiscovery.discoverCnameChain(context, service);
    if (aliases.isEmpty()) {
      Log.i(TAG, "DNS did not discover a CNAME alias for " + service);
      return aliases;
    }
    Log.i(TAG, "DNS discovered CNAME aliases " + aliases + " for " + service);
    return aliases;
  }

  private static String normalizeService(String service) {
    if (service == null) {
      return null;
    }
    String normalized = service.trim().toLowerCase(Locale.US);
    while (normalized.endsWith(".")) {
      normalized = normalized.substring(0, normalized.length() - 1);
    }
    return normalized.isEmpty() ? null : normalized;
  }

  private static boolean isIpv4Address(String value) {
    return value.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
  }

}
