package com.poelbos.kerberosauthenticator.files;

import static com.hierynomus.mssmb2.SMB2Dialect.SMB_2_1;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_1_1;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import java.io.IOException;
import org.junit.Test;
import org.ietf.jgss.GSSException;
import sun.security.krb5.KrbException;

public final class KerberosSmbClientTest {
  @Test public void createsDfsReadySignedConfiguration() {
    SmbConfig config = KerberosSmbClient.createConfig(false);

    assertTrue(config.isDfsEnabled());
    assertTrue(config.isSigningRequired());
    assertTrue(config.getSupportedDialects().contains(SMB_3_1_1));
    assertTrue(config.getSupportedDialects().contains(SMB_2_1));
    assertEquals(1, config.getSupportedAuthenticators().size());
    assertTrue(config.getSupportedAuthenticators().get(0) instanceof SpnegoAuthenticator.Factory);
  }

  @Test public void enablesEncryptionWhenRequired() {
    assertTrue(KerberosSmbClient.createConfig(true).isEncryptData());
  }

  @Test public void usesConcreteDomainControllerForDomainBasedDfsNamespace() {
    assertEquals(
        "dc01.politie.local",
        KerberosSmbClient.initialConnectionHost(
            "politie.local", "POLITIE.LOCAL", "dc01.politie.local"));
  }

  @Test public void keepsShareHostForNonDomainNamespace() {
    assertEquals(
        "files.politie.local",
        KerberosSmbClient.initialConnectionHost(
            "files.politie.local", "POLITIE.LOCAL", "dc01.politie.local"));
  }

  @Test public void reportsOnlyNumericGssStatusForNestedGssException() {
    GSSException gssException = new GSSException(GSSException.FAILURE, 7, null);
    RuntimeException exception = new RuntimeException(gssException);

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals("Kerberos-aanmelding bij de share is mislukt (GSS 11/7)", failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void reportsGssStatusWhenTransportIOExceptionWrapsIt() {
    GSSException gssException = new GSSException(GSSException.BAD_NAME, 13, null);
    IOException exception = new IOException(gssException);

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals("Kerberos-aanmelding bij de share is mislukt (GSS 3/13)", failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void reportsNestedKerberosCodeWithGssStatus() {
    GSSException gssException = new GSSException(GSSException.FAILURE, -1, null);
    gssException.initCause(new KrbException(7));
    RuntimeException exception = new RuntimeException(gssException);

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals(
        "Kerberos-aanmelding bij de share is mislukt (GSS 11/-1, KRB 7)",
        failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void returnsExistingIOExceptionUnchanged() {
    IOException exception = new IOException("netwerkfout");

    assertSame(exception, KerberosSmbClient.connectionFailure(exception));
  }

  @Test public void reportsOnlyExceptionTypesForUnknownRuntimeFailure() {
    RuntimeException exception =
        new RuntimeException("gevoelige tekst", new IllegalStateException("ook gevoelig"));

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals(
        "Kerberos-aanmelding bij de share is mislukt (RuntimeException>IllegalStateException)",
        failure.getMessage());
    assertSame(exception, failure.getCause());
  }
}
