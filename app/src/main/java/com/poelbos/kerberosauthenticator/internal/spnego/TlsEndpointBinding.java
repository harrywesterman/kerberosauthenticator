package com.poelbos.kerberosauthenticator.internal.spnego;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Locale;

/** RFC 5929 tls-server-end-point application data, derived from the authenticated TLS peer. */
public final class TlsEndpointBinding {
  private TlsEndpointBinding() {}
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
