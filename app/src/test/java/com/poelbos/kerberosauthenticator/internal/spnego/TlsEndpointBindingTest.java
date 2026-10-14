package com.poelbos.kerberosauthenticator.internal.spnego;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import org.junit.Test;

public class TlsEndpointBindingTest {
 @Test public void sha256CertificateUsesSha256EndpointHash() throws Exception {
  check("tls-binding-sha256.der", "8cb80f43c07a25c016d1d3b5934f9b9a8fd40fc6adcb11995a2e1ebf3b822536");
 }
 @Test public void sha1CertificateUpgradesBindingDigestToSha256() throws Exception {
  check("tls-binding-sha1.der", "f22ba9c4d2fd6207d9c2c28e1cce29d2f244b4f13f3986d27c7413c257d55f84");
 }
 private void check(String resource, String expectedHash) throws Exception {
  X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
      .generateCertificate(getClass().getClassLoader().getResourceAsStream(resource));
  byte[] value = TlsEndpointBinding.fromCertificate(cert);
  byte[] prefix = "tls-server-end-point:".getBytes(StandardCharsets.US_ASCII);
  assertArrayEquals(prefix, java.util.Arrays.copyOf(value,prefix.length));
  StringBuilder hash=new StringBuilder();for(int i=prefix.length;i<value.length;i++)hash.append(String.format("%02x",value[i]));
  assertEquals(expectedHash,hash.toString());
 }
}
