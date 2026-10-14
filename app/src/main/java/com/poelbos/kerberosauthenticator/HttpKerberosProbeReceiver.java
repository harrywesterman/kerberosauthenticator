package com.poelbos.kerberosauthenticator;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.util.Log;
import com.poelbos.kerberosauthenticator.internal.SpnResolver;
import com.poelbos.kerberosauthenticator.internal.TicketGrantingTicket;
import com.poelbos.kerberosauthenticator.internal.spnego.GetSpnegoTicketTask;
import com.poelbos.kerberosauthenticator.internal.spnego.TlsEndpointBinding;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Locale;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/** Shell-only HTTPS diagnostic. No credentials, tokens or response bodies are returned or logged. */
public final class HttpKerberosProbeReceiver extends BroadcastReceiver {
  private static final java.util.concurrent.atomic.AtomicBoolean RUNNING =
      new java.util.concurrent.atomic.AtomicBoolean();

  @Override public void onReceive(Context context, Intent intent) {
    if (!RUNNING.compareAndSet(false, true)) return;
    PendingResult pending = goAsync();
    new Thread(() -> {
      try { probe(context.getApplicationContext(), intent); }
      catch (Exception error) {
        Log.i(Constants.TAG, "HTTP_TLS_PROBE result=unavailable category=" + error.getClass().getSimpleName());
      } finally { RUNNING.set(false); pending.finish(); }
    }, "kerberos-https-probe").start();
  }

  private void probe(Context context, Intent intent) throws Exception {
    KerberosAccount account = KerberosAccount.getAccount(context);
    AccountConfiguration policy = new AccountConfiguration(context);
    if (account == null || !policy.isHttpKerberosEnabled()) throw new IllegalStateException();
    String realm = account.getDomain();
    String host = SpnResolver.normalizeHost(intent.getStringExtra("request_host"), realm);
    String spn = SpnResolver.normalizeHost(intent.getStringExtra("spn_host"), realm);
    String suffix = "." + realm.toLowerCase(Locale.ROOT);
    if (host == null || spn == null || !host.endsWith(suffix) || !spn.endsWith(suffix))
      throw new IllegalArgumentException();
    boolean bindingEnabled = intent.getBooleanExtra("channel_binding", false);
    String operation = intent.getStringExtra("operation");
    if ("set_mapping".equals(operation)) {
      com.poelbos.kerberosauthenticator.internal.HttpSpnSettings.setForShell(context, realm, host, spn, bindingEnabled, intent.getStringExtra("approved_spn_hosts"));
      Log.i(Constants.TAG, "HTTP_SPN_ADMIN host=" + host + " spn=" + spn + " binding=" + bindingEnabled + " result=saved");
      return;
    }
    if ("clear_mapping".equals(operation)) {
      com.poelbos.kerberosauthenticator.internal.HttpSpnSettings.clearForShell(context, realm, host);
      Log.i(Constants.TAG, "HTTP_SPN_ADMIN host=" + host + " result=cleared");
      return;
    }

    ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
    Network network = cm.getActiveNetwork();
    if (network == null) throw new IllegalStateException();
    try (Socket raw = network.getSocketFactory().createSocket()) {
      raw.connect(new InetSocketAddress(network.getAllByName(host)[0], 443), 4000);
      raw.setSoTimeout(5000);
      try (SSLSocket tls = (SSLSocket) ((SSLSocketFactory) SSLSocketFactory.getDefault()).createSocket(raw, host, 443, true)) {
        SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(java.util.Collections.singletonList(new javax.net.ssl.SNIHostName(host)));
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        X509Certificate certificate = (X509Certificate) tls.getSession().getPeerCertificates()[0];
        byte[] binding = bindingEnabled ? TlsEndpointBinding.fromCertificate(certificate) : null;
        StringBuilder fingerprint = new StringBuilder();
        for (byte value : java.security.MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()))
          fingerprint.append(String.format(java.util.Locale.ROOT, "%02x", value));
        TicketGrantingTicket tgt = TicketGrantingTicket.fromSerializedSubject(account.getTicketGrantingTicket());
        GetSpnegoTicketTask.SpnegoTicketResult ticket =
            GetSpnegoTicketTask.getServiceTicketWithChannelBinding(context, tgt.asSubject(), realm,
                account.getDomainController(), spn, null, null, binding);
        if (!ticket.getRequestResult().successful() || ticket.getServiceTicket() == null) {
          Log.i(Constants.TAG, "HTTP_TLS_PROBE host=" + host + " spn=" + spn
              + " binding=" + bindingEnabled + " result=ticket_unavailable");
          return;
        }
        // One request on the very TLS connection from which the binding was derived.
        String request = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n"
            + "Authorization: Negotiate " + ticket.getServiceTicket() + "\r\n\r\n";
        tls.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
        tls.getOutputStream().flush();
        BufferedReader reader = new BufferedReader(new InputStreamReader(tls.getInputStream(), StandardCharsets.ISO_8859_1));
        String status = reader.readLine();
        int httpStatus = status == null ? 0 : Integer.parseInt(status.split(" ")[1]);
        int kerberosCode = 0;
        String reportedPrincipal = "none";
        int size = 0;
        String line;
        while ((line = reader.readLine()) != null && !line.isEmpty()) {
          if ((size += line.length()) > 65536) throw new IllegalStateException();
          if (line.regionMatches(true, 0, "WWW-Authenticate: Negotiate ", 0, 28)) {
            try {
              byte[] response = android.util.Base64.decode(line.substring(28).trim(), android.util.Base64.DEFAULT);
              byte[] mechanism = new com.hierynomus.spnego.NegTokenTarg().read(response).getResponseToken();
              if (mechanism != null) {
                sun.security.krb5.internal.KRBError error = kerberosError(mechanism);
                if (error != null) {
                  kerberosCode = error.getErrorCode();
                  String name = String.valueOf(error.getServerPrincipal());
                  if (name.matches("[a-zA-Z0-9._$/@-]{1,255}")) reportedPrincipal = name;
                }
              }
            } catch (Exception ignored) { }
          }
        }
        Log.i(Constants.TAG, "HTTP_TLS_PROBE host=" + host + " spn=" + spn
            + " selectedSpn=" + ticket.getSelectedService()
            + " binding=" + bindingEnabled + " httpStatus=" + httpStatus + " kerberosCode=" + kerberosCode
            + " peerCertificateSha256=" + fingerprint
            + " remoteAddress=" + raw.getInetAddress().getHostAddress()
            + " reportedPrincipal=" + reportedPrincipal);
      }
    }
  }

  static sun.security.krb5.internal.KRBError kerberosError(byte[] token) {
    for (int i = 0; i + 2 < token.length; i++) {
      if ((token[i] & 255) != 0x7e) continue;
      try {
        krb.sun.security.util.DerValue value = new krb.sun.security.util.DerValue(
            new java.io.ByteArrayInputStream(token, i, token.length - i));
        return new sun.security.krb5.internal.KRBError(value.toByteArray());
      } catch (Exception ignored) { }
    }
    return null;
  }
}
