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
        "dc01.example.test",
        KerberosSmbClient.initialConnectionHost(
            "example.test", "EXAMPLE.TEST",
            "dc01.example.test dc02.example.test"));
  }

  @Test public void keepsShareHostForNonDomainNamespace() {
    assertEquals(
        "files.example.test",
        KerberosSmbClient.initialConnectionHost(
            "files.example.test", "EXAMPLE.TEST", "dc01.example.test"));
  }

  @Test public void reportsOnlyNumericGssStatusForNestedGssException() {
    GSSException gssException = new GSSException(GSSException.FAILURE, 7, null);
    RuntimeException exception = new RuntimeException(gssException);

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals("Kerberos sign-in to the share failed (GSS 11/7)", failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void reportsGssStatusWhenTransportIOExceptionWrapsIt() {
    GSSException gssException = new GSSException(GSSException.BAD_NAME, 13, null);
    IOException exception = new IOException(gssException);

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals("Kerberos sign-in to the share failed (GSS 3/13)", failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void reportsNestedKerberosCodeWithGssStatus() {
    GSSException gssException = new GSSException(GSSException.FAILURE, -1, null);
    gssException.initCause(new KrbException(7));
    RuntimeException exception = new RuntimeException(gssException);

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals(
        "Kerberos sign-in to the share failed (GSS 11/-1, KRB 7)",
        failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void returnsExistingIOExceptionUnchanged() {
    IOException exception = new IOException("network failure");

    assertSame(exception, KerberosSmbClient.connectionFailure(exception));
  }

  @Test public void reportsOnlyExceptionTypesForUnknownRuntimeFailure() {
    RuntimeException exception =
        new RuntimeException("gevoelige tekst", new IllegalStateException("ook gevoelig"));

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals(
        "Kerberos sign-in to the share failed (RuntimeException>IllegalStateException)",
        failure.getMessage());
    assertSame(exception, failure.getCause());
  }

  @Test public void reportsOnlySafeSmbjFailureLocation() {
    NullPointerException exception = new NullPointerException("gevoelige tekst");
    exception.setStackTrace(new StackTraceElement[] {
        new StackTraceElement(
            "com.hierynomus.smbj.connection.SMBSessionBuilder",
            "validateAndSetSigning", "SMBSessionBuilder.java", 251)
    });

    IOException failure = KerberosSmbClient.connectionFailure(exception);

    assertEquals(
        "Kerberos sign-in to the share failed "
            + "(NullPointerException@SMBSessionBuilder.validateAndSetSigning)",
        failure.getMessage());
  }
}
