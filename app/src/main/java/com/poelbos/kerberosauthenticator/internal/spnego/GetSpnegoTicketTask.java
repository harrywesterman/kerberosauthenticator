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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.security.auth.Subject;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
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

    public SpnegoTicketResult(TicketRequestResult requestResult, String serviceTicket) {
      this.requestResult = requestResult;
      this.serviceTicket = serviceTicket;
    }

    public TicketRequestResult getRequestResult() {
      return requestResult;
    }

    public String getServiceTicket() {
      return serviceTicket;
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
      if (debugWithSensitiveData) {
        logServiceResolution(context, service);
        logDnsAlias(context, service);
      }
      List<String> certificateDnsNames =
          getServerCertificateDnsNames(service, debugWithSensitiveData);

      GSSException lastException = null;
      for (String ticketService : serviceTicketCandidates(service, certificateDnsNames)) {
        try {
          serverName =
              manager.createName("HTTP@" + ticketService, GSSName.NT_HOSTBASED_SERVICE, spnegoOid);
          if (debugWithSensitiveData) {
            Log.i(TAG, "Created SPNEGO GSSName: " + serverName);
          }

          GSSContext gssContext =
              manager.createContext(serverName, spnegoOid, null, GSSContext.DEFAULT_LIFETIME);
          byte[] spnegoToken = new byte[0];
          spnegoToken = gssContext.initSecContext(spnegoToken, 0, spnegoToken.length);

          Log.d(
              TAG,
              String.format(
                  "GSS context established? %s service ticket is null? %s",
                  gssContext.isEstablished(), spnegoToken != null));

          if (spnegoToken != null) {
            serviceSpnegoTicket = Base64.encodeToString(spnegoToken, Base64.NO_WRAP);
          }
          if (!ticketService.equals(service)) {
            Log.i(
                TAG,
                String.format(
                    "Using fallback SPNEGO service %s for requested service %s.",
                    ticketService, service));
          }
          break;
        } catch (GSSException e) {
          lastException = e;
          Log.w(
              TAG,
              String.format("SPNEGO service ticket failed for HTTP@%s.", ticketService),
              e);
        }
      }
      if (serviceSpnegoTicket == null && lastException != null) {
        throw lastException;
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
    String normalizedService = normalizeService(service);
    if (normalizedService == null) {
      return new ArrayList<>();
    }

    Set<String> candidates = new LinkedHashSet<>();
    candidates.add(normalizedService);
    if (isIpv4Address(normalizedService)) {
      return new ArrayList<>(candidates);
    }

    for (String certificateDnsName : certificateDnsNames) {
      String normalizedCertificateDnsName = normalizeService(certificateDnsName);
      if (normalizedCertificateDnsName != null) {
        candidates.add(normalizedCertificateDnsName);
      }
    }

    int dot = normalizedService.indexOf('.');
    if (dot > 0) {
      String firstLabel = normalizedService.substring(0, dot);
      if (!normalizedService.endsWith(".local")) {
        candidates.add(normalizedService + ".local");
      }
      candidates.add(firstLabel);
    }
    return new ArrayList<>(candidates);
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

  private static void logServiceResolution(Context context, String service) {
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
        return;
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
    } catch (IOException e) {
      Log.w(TAG, "Default resolver could not resolve service " + service, e);
    }
  }

  private void logLdapSpnMatches(String domainControllers) {
    List<LdapSpnDiscovery.SearchResult> results =
        LdapSpnDiscovery.findHttpServicePrincipalNames(
            context, domain, domainControllers, username, password, service);
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

  private static void logReverseDns(Context context, InetAddress address) {
    String reverseName = DnsKdcDiscovery.discoverPtr(context, address);
    if (reverseName == null) {
      Log.i(TAG, "DNS did not discover a PTR host for " + address.getHostAddress());
      return;
    }
    Log.i(TAG, "DNS discovered PTR host " + reverseName + " for " + address.getHostAddress());
  }

  private static void logDnsAlias(Context context, String service) {
    String alias = DnsKdcDiscovery.discoverCname(context, service);
    if (alias == null) {
      Log.i(TAG, "DNS did not discover a CNAME alias for " + service);
      return;
    }
    Log.i(TAG, "DNS discovered CNAME alias " + alias + " for " + service);
  }

  private static List<String> getServerCertificateDnsNames(String service, boolean logNames) {
    List<String> dnsNames = new ArrayList<>();
    HttpsURLConnection connection = null;
    try {
      URL url = new URL("https://" + service + "/");
      connection = (HttpsURLConnection) url.openConnection();
      connection.setSSLSocketFactory(trustAllSocketFactory());
      connection.setHostnameVerifier(
          new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
              return true;
            }
          });
      connection.setConnectTimeout(3000);
      connection.setReadTimeout(3000);
      connection.connect();
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

  private static SSLSocketFactory trustAllSocketFactory() throws GeneralSecurityException {
    TrustManager[] trustManagers =
        new TrustManager[] {
          new X509TrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) {}

            @Override
            public X509Certificate[] getAcceptedIssuers() {
              return new X509Certificate[0];
            }
          }
        };
    SSLContext sslContext = SSLContext.getInstance("TLS");
    sslContext.init(null, trustManagers, new SecureRandom());
    return sslContext.getSocketFactory();
  }
}
