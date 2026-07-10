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
import com.poelbos.kerberosauthenticator.internal.LdapSpnDiscovery;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult;
import com.poelbos.kerberosauthenticator.internal.TicketRequestResult.ResultCode;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.security.auth.Subject;
import javax.net.ssl.HttpsURLConnection;
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
  private final String username;
  private final String password;
  private final boolean debugWithSensitiveData;
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
      String username,
      String password,
      boolean debugWithSensitiveData, ServiceTicketResultListener listener) {
    this.context = context.getApplicationContext();
    this.subject = subject;
    this.domain = domain;
    this.domainController = domainController;
    this.username = username;
    this.password = password;
    this.debugWithSensitiveData = debugWithSensitiveData;
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
            username,
            password,
            debugWithSensitiveData,
            service);
    serviceSpnegoTicket = result.getServiceTicket();
    return result.getRequestResult();
  }

  public static SpnegoTicketResult getServiceTicket(
      Context context,
      Subject subject,
      String domain,
      String domainController,
      String username,
      String password,
      boolean debugWithSensitiveData,
      String service) {
    return getServiceTicket(
        context,
        subject,
        domain,
        domainController,
        username,
        password,
        debugWithSensitiveData,
        service,
        null,
        null);
  }

  public static SpnegoTicketResult getServiceTicket(
      Context context,
      Subject subject,
      String domain,
      String domainController,
      String username,
      String password,
      boolean debugWithSensitiveData,
      String service,
      byte[] incomingAuthToken,
      byte[] exportedContext) {
    GSSUtil.setGlobalSubject(subject);
    String serviceSpnegoTicket = null;
    String activeDomainControllers;
    try {
      activeDomainControllers =
          KerberosEnvironment.configure(
          context, domain, domainController, debugWithSensitiveData, service);
    } catch (IOException e) {
      Log.e(TAG, "Failure configuring Kerberos environment", e);
      return new SpnegoTicketResult(
          new TicketRequestResult(ResultCode.ERROR_GSS_FAILURE, e.getMessage()), null);
    }

    GSSManager manager = new GSSManagerImpl(GSSCaller.CALLER_INITIATE, false);

    if (debugWithSensitiveData) {
      StringBuilder mechanismsSupported = new StringBuilder();
      for (Oid oid : manager.getMechs()) {
        mechanismsSupported.append(oid).append("   ");
      }
      Log.i(TAG, "Mechanisms supported: " + mechanismsSupported);
    }

    GSSName serverName = null;
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
      List<String> certificateDnsNames =
          getServerCertificateDnsNames(service, debugWithSensitiveData);
      List<String> ldapCandidates =
          getLdapServiceCandidates(
              context,
              domain,
              activeDomainControllers,
              subject,
              service,
              debugWithSensitiveData);

      GSSException lastException = null;
      List<String> candidates =
          exportedContext != null
              ? java.util.Collections.singletonList(normalizedService)
              : serviceTicketCandidates(
                  service, dnsAliasCandidates, certificateDnsNames, ldapCandidates);
      if (incomingAuthToken != null && exportedContext == null) {
        String previousService =
            context
                .getSharedPreferences("service_ticket_info_storage", Context.MODE_PRIVATE)
                .getString("service_ticket_name", null);
        candidates = resumeCandidatesAfter(candidates, previousService);
      }
      Log.i(TAG, "SPNEGO candidates for " + service + ": " + candidates);
      for (String ticketService : candidates) {
        try {
          serverName =
              manager.createName("HTTP@" + ticketService, GSSName.NT_HOSTBASED_SERVICE, spnegoOid);
          if (debugWithSensitiveData) {
            Log.i(TAG, "Created SPNEGO GSSName: " + serverName);
          }

          GSSContext gssContext =
              exportedContext == null
                  ? manager.createContext(serverName, spnegoOid, null, GSSContext.DEFAULT_LIFETIME)
                  : manager.createContext(exportedContext);
          byte[] spnegoToken = incomingAuthToken == null ? new byte[0] : incomingAuthToken;
          spnegoToken = gssContext.initSecContext(spnegoToken, 0, spnegoToken.length);

          Log.d(
              TAG,
              String.format(
                  "GSS context established? %s service ticket is null? %s",
                  gssContext.isEstablished(), spnegoToken != null));

          if (spnegoToken != null) {
            serviceSpnegoTicket = Base64.encodeToString(spnegoToken, Base64.NO_WRAP);
          }
          byte[] nextContext = null;
          if (spnegoToken != null && !gssContext.isEstablished()) {
            nextContext = gssContext.export();
          }
          if (!ticketService.equals(service)) {
            Log.i(
                TAG,
                String.format(
                    "Using fallback SPNEGO service %s for requested service %s.",
                    ticketService, service));
          }
          return new SpnegoTicketResult(
              new TicketRequestResult(ResultCode.SUCCESS, "HTTP ticket for " + serverName),
              serviceSpnegoTicket,
              nextContext,
              ticketService);
        } catch (GSSException e) {
          lastException = e;
          Log.w(
              TAG,
              String.format("SPNEGO service ticket failed for HTTP@%s.", ticketService),
              e);
        }
      }
      if (serviceSpnegoTicket == null && lastException != null) {
        ResultCode resultCode =
            lastException.getMessage() != null
                    && lastException.getMessage().contains("Server not found in Kerberos database")
                ? ResultCode.ERROR_NO_SPN
                : ResultCode.ERROR_GSS_FAILURE;
        return new SpnegoTicketResult(
            new TicketRequestResult(resultCode, lastException.getMessage()), null);
      }
    } catch (GSSException e) {
      Log.e(TAG, "Error while getting service ticket", e);
      return new SpnegoTicketResult(
          new TicketRequestResult(ResultCode.ERROR_GSS_FAILURE, e.getMessage()), null);
    }

    if (debugWithSensitiveData) {
      Log.i(TAG, "Spnego ticket: " + serviceSpnegoTicket);
    }

    return new SpnegoTicketResult(
        new TicketRequestResult(ResultCode.SUCCESS, "HTTP ticket for " + serverName),
        serviceSpnegoTicket);
  }

  static List<String> serviceTicketCandidates(String service) {
    return serviceTicketCandidates(service, new ArrayList<String>());
  }

  static List<String> serviceTicketCandidates(String service, List<String> certificateDnsNames) {
    return serviceTicketCandidates(
        service, new ArrayList<String>(), certificateDnsNames, new ArrayList<String>());
  }

  static List<String> serviceTicketCandidates(
      String service, List<String> dnsAliasNames, List<String> certificateDnsNames) {
    return serviceTicketCandidates(service, dnsAliasNames, certificateDnsNames, new ArrayList<String>());
  }

  static List<String> serviceTicketCandidates(
      String service,
      List<String> dnsAliasNames,
      List<String> certificateDnsNames,
      List<String> ldapDnsNames) {
    String normalizedService = normalizeService(service);
    if (normalizedService == null) {
      return new ArrayList<>();
    }

    Set<String> candidates = new LinkedHashSet<>();
    candidates.add(normalizedService);
    if (isIpv4Address(normalizedService)) {
      return new ArrayList<>(candidates);
    }

    for (String dnsAliasName : dnsAliasNames) {
      String normalizedDnsAliasName = normalizeService(dnsAliasName);
      if (normalizedDnsAliasName != null && !isWildcardHost(normalizedDnsAliasName)) {
        candidates.add(normalizedDnsAliasName);
      }
    }

    for (String certificateDnsName : certificateDnsNames) {
      String normalizedCertificateDnsName = normalizeService(certificateDnsName);
      if (normalizedCertificateDnsName != null && !isWildcardHost(normalizedCertificateDnsName)) {
        candidates.add(normalizedCertificateDnsName);
      }
    }

    for (String ldapDnsName : ldapDnsNames) {
      String normalizedLdapDnsName = normalizeService(ldapDnsName);
      if (normalizedLdapDnsName != null) {
        candidates.add(normalizedLdapDnsName);
      }
    }

    return new ArrayList<>(candidates);
  }

  static List<String> resumeCandidatesAfter(List<String> candidates, String previousCandidate) {
    if (candidates == null || candidates.isEmpty() || previousCandidate == null) {
      return candidates == null ? new ArrayList<String>() : new ArrayList<>(candidates);
    }
    int previousIndex = candidates.indexOf(previousCandidate);
    if (previousIndex < 0) {
      return new ArrayList<>(candidates);
    }
    List<String> resumed = new ArrayList<>(candidates.size());
    for (int offset = 1; offset <= candidates.size(); offset++) {
      resumed.add(candidates.get((previousIndex + offset) % candidates.size()));
    }
    return resumed;
  }

  private static boolean isWildcardHost(String host) {
    return host.startsWith("*.");
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
          logReverseDns(context, address);
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
      logReverseDns(context, address);
      return true;
    } catch (IOException e) {
      Log.w(TAG, "Default resolver could not resolve service " + service, e);
    }
    return false;
  }

  private void logLdapSpnMatches(String domainControllers) {
    List<LdapSpnDiscovery.SearchResult> results =
        LdapSpnDiscovery.findHttpServicePrincipalNames(
            context, domain, domainControllers, subject, service);
    if (results.isEmpty()) {
      Log.i(TAG, "LDAP SPN lookup found no HTTP service principal names for " + service);
      return;
    }
    for (LdapSpnDiscovery.SearchResult result : results) {
      Log.i(
          TAG,
          String.format(
              "LDAP SPN match account=%s dns=%s spns=%s",
              result.getAccountName(), result.getDnsHostName(), result.getServicePrincipalNames()));
    }
  }

  private static List<String> getLdapServiceCandidates(
      Context context,
      String domain,
      String domainControllers,
      Subject subject,
      String service,
      boolean debugWithSensitiveData) {
    Log.i(
        TAG,
        String.format(
            "Starting LDAP SPN lookup for %s using controllers %s.", service, domainControllers));
    List<LdapSpnDiscovery.SearchResult> results =
        LdapSpnDiscovery.findHttpServicePrincipalNames(
            context, domain, domainControllers, subject, service);
    if (debugWithSensitiveData) {
      if (results.isEmpty()) {
        Log.i(TAG, "LDAP SPN lookup found no HTTP service principal names for " + service);
      } else {
        for (LdapSpnDiscovery.SearchResult result : results) {
          Log.i(
              TAG,
              String.format(
                  "LDAP SPN match account=%s dns=%s spns=%s",
                  result.getAccountName(), result.getDnsHostName(), result.getServicePrincipalNames()));
        }
      }
    }
    LinkedHashSet<String> candidates = new LinkedHashSet<>();
    for (LdapSpnDiscovery.SearchResult result : results) {
      String dnsHostName = result.getDnsHostName();
      if (dnsHostName != null) {
        candidates.add(dnsHostName);
      }
      for (String servicePrincipalName : result.getServicePrincipalNames()) {
        String candidate = ldapServiceCandidateFromPrincipal(servicePrincipalName);
        if (candidate != null) {
          candidates.add(candidate);
        }
      }
    }
    Log.i(
        TAG,
        String.format(
            "LDAP SPN lookup produced %d candidate host(s) for %s.",
            candidates.size(), service));
    return new ArrayList<>(candidates);
  }

  private static String ldapServiceCandidateFromPrincipal(String servicePrincipalName) {
    if (servicePrincipalName == null) {
      return null;
    }
    String normalized = servicePrincipalName.trim();
    if (!normalized.regionMatches(true, 0, "HTTP/", 0, 5)) {
      return null;
    }
    normalized = normalized.substring(5);
    int at = normalized.indexOf('@');
    if (at > 0) {
      normalized = normalized.substring(0, at);
    }
    return normalizeService(normalized);
  }

  private static void logReverseDns(Context context, InetAddress address) {
    String reverseName = DnsKdcDiscovery.discoverPtr(context, address);
    if (reverseName == null) {
      Log.i(TAG, "DNS did not discover a PTR host for " + address.getHostAddress());
      return;
    }
    Log.i(TAG, "DNS discovered PTR host " + reverseName + " for " + address.getHostAddress());
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

  private static List<String> getServerCertificateDnsNames(String service, boolean logNames) {
    List<String> dnsNames = new ArrayList<>();
    HttpsURLConnection connection = null;
    try {
      URL url = new URL("https://" + service + "/");
      connection = (HttpsURLConnection) url.openConnection();
      connection.setConnectTimeout(3000);
      connection.setReadTimeout(3000);
      connection.connect();
      if (logNames) {
        Log.i(
            TAG,
            String.format(
                "HTTPS pre-auth response for %s: HTTP %d, WWW-Authenticate=%s",
                service, connection.getResponseCode(), connection.getHeaderField("WWW-Authenticate")));
      }
      Certificate[] certificates = connection.getServerCertificates();
      if (certificates.length == 0 || !(certificates[0] instanceof X509Certificate)) {
        if (logNames) {
          Log.i(TAG, "HTTPS server presented no X509 certificate for " + service);
        }
        return dnsNames;
      }
      X509Certificate certificate = (X509Certificate) certificates[0];
      if (logNames) {
        Log.i(TAG, "HTTPS certificate subject for " + service + ": " + certificate.getSubjectDN());
      }
      Collection<List<?>> alternativeNames = certificate.getSubjectAlternativeNames();
      if (alternativeNames == null) {
        if (logNames) {
          Log.i(TAG, "HTTPS certificate has no subject alternative names for " + service);
        }
        return dnsNames;
      }
      for (List<?> alternativeName : alternativeNames) {
        if (alternativeName.size() >= 2 && Integer.valueOf(2).equals(alternativeName.get(0))) {
          String dnsName = String.valueOf(alternativeName.get(1));
          dnsNames.add(dnsName);
          if (logNames) {
            Log.i(TAG, "HTTPS certificate DNS name for " + service + ": " + dnsName);
          }
        }
      }
    } catch (Exception e) {
      if (logNames) {
        Log.w(TAG, "Could not inspect HTTPS certificate for " + service, e);
      }
    } finally {
      if (connection != null) {
        connection.disconnect();
      }
    }
    return dnsNames;
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
