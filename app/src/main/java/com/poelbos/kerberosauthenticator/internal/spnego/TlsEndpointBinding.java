package com.poelbos.kerberosauthenticator.internal.spnego;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Locale;

/** RFC 5929 tls-server-end-point application data, derived from the authenticated TLS peer. */
public final class TlsEndpointBinding {
  private TlsEndpointBinding() {}
  /** Authenticated certificate discovery for an explicitly configured HTTPS/443 origin. */
  public static byte[] discover(android.content.Context context, String host) throws java.io.IOException {
    android.net.ConnectivityManager cm = (android.net.ConnectivityManager)
        context.getSystemService(android.content.Context.CONNECTIVITY_SERVICE);
    android.net.Network network = cm.getActiveNetwork();
    if (network == null) throw new java.io.IOException("No active network");
    try (java.net.Socket raw = network.getSocketFactory().createSocket()) {
      raw.connect(new java.net.InetSocketAddress(network.getAllByName(host)[0], 443), 4000);
      raw.setSoTimeout(5000);
      try (javax.net.ssl.SSLSocket tls = (javax.net.ssl.SSLSocket)
          ((javax.net.ssl.SSLSocketFactory) javax.net.ssl.SSLSocketFactory.getDefault())
              .createSocket(raw, host, 443, true)) {
        javax.net.ssl.SSLParameters parameters = tls.getSSLParameters();
        parameters.setEndpointIdentificationAlgorithm("HTTPS");
        parameters.setServerNames(java.util.Collections.singletonList(new javax.net.ssl.SNIHostName(host)));
        tls.setSSLParameters(parameters);
        tls.startHandshake();
        return fromCertificate((X509Certificate) tls.getSession().getPeerCertificates()[0]);
      }
    } catch (java.io.IOException error) { throw error; }
    catch (Exception error) { throw new java.io.IOException("HTTPS endpoint binding unavailable", error); }
  }
  public static byte[] fromCertificate(X509Certificate certificate) throws Exception {
    String signature = certificate.getSigAlgName().toUpperCase(Locale.ROOT).replace("-", "");
    String digest;
    if (signature.contains("SHA512")) digest = "SHA-512";
    else if (signature.contains("SHA384")) digest = "SHA-384";
    else if (signature.contains("SHA256")) digest = "SHA-256";
    else if (signature.contains("SHA224")) digest = "SHA-224";
    else if (signature.contains("SHA1") || signature.contains("MD5")) digest = "SHA-256";
    else throw new IllegalArgumentException("Unsupported TLS certificate signature hash");
    byte[] prefix = "tls-server-end-point:".getBytes(StandardCharsets.US_ASCII);
    byte[] hash = MessageDigest.getInstance(digest).digest(certificate.getEncoded());
    byte[] binding = java.util.Arrays.copyOf(prefix, prefix.length + hash.length);
    System.arraycopy(hash, 0, binding, prefix.length, hash.length);
    return binding;
  }
}
