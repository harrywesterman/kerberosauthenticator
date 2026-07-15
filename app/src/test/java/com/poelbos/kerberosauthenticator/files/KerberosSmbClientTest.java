package com.poelbos.kerberosauthenticator.files;

import static com.hierynomus.mssmb2.SMB2Dialect.SMB_2_1;
import static com.hierynomus.mssmb2.SMB2Dialect.SMB_3_1_1;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.SpnegoAuthenticator;
import com.hierynomus.smbj.common.SmbPath;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;
import org.ietf.jgss.GSSException;
import sun.security.krb5.KrbException;

public final class KerberosSmbClientTest {
  @Test public void resolvesManagedShareAtConnectionBoundary() throws Exception {
    ManagedShare template = new ManagedShare(
        "home", "Home", "files.example.test", 445, "Data",
        "users/${username:last:1}/${username}");

    ManagedShare resolved = KerberosSmbClient.resolveManagedShare(template, "isc36512");

    assertEquals("users\\2\\isc36512", resolved.getStartPath());
  }

  @Test public void reportsSafeManagedPathConfigurationFailure() {
    ManagedShare template = new ManagedShare(
        "home", "Home", "files.example.test", 445, "Data", "users/${unknown}");

    IOException failure = assertThrows(
        IOException.class,
        () -> KerberosSmbClient.resolveManagedShare(template, "isc36512"));

    assertEquals("The managed share path is invalid", failure.getMessage());
    assertTrue(failure.getCause() instanceof IllegalArgumentException);
  }

  @Test public void rejectsTrailingTraversalAtConnectionBoundary() {
    ManagedShare template = new ManagedShare(
        "home", "Home", "files.example.test", 445, "Data", "users/${username}");

    IOException failure = assertThrows(
        IOException.class,
        () -> KerberosSmbClient.resolveManagedShare(template, "member/.."));

    assertEquals("The managed share path is invalid", failure.getMessage());
    assertTrue(failure.getCause() instanceof IllegalArgumentException);
  }

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

  @Test public void usesDomainControllersForDomainBasedDfsNamespace() {
    assertEquals(
        Arrays.asList("dc01.example.test", "dc02.example.test"),
        KerberosSmbClient.initialConnectionHosts(
            "example.test", "EXAMPLE.TEST",
            "dc01.example.test dc02.example.test", "kdc01.example.test"));
  }

  @Test public void normalizesAndDeduplicatesDomainControllers() {
    assertEquals(
        Arrays.asList("dc01.example.test", "dc02.example.test"),
        KerberosSmbClient.initialConnectionHosts(
            "example.test.", "EXAMPLE.TEST",
            "DC01.EXAMPLE.TEST. dc01.example.test dc02.example.test.",
            "kdc01.example.test"));
  }

  @Test public void fallsBackToKerberosServersWithoutDomainControllers() {
    assertEquals(
        Arrays.asList("kdc01.example.test", "kdc02.example.test"),
        KerberosSmbClient.initialConnectionHosts(
            "example.test", "EXAMPLE.TEST", null,
            "kdc01.example.test kdc02.example.test"));
  }

  @Test public void keepsShareHostForNonDomainNamespace() {
    assertEquals(
        Collections.singletonList("Files.EXAMPLE.TEST."),
        KerberosSmbClient.initialConnectionHosts(
            "Files.EXAMPLE.TEST.", "OTHER.EXAMPLE.TEST",
            "dc01.example.test", "kdc01.example.test"));
  }

  @Test public void sendsProactiveDfsReferralThroughAuthenticatedBootstrapHost() {
    ManagedShare share = new ManagedShare(
        "home", "Home", "example.test", 445, "Data", "users\\member");

    SmbPath request = KerberosSmbClient.proactiveDfsRequestPath(
        share, "dc02.example.test", "users\\member");

    assertEquals("dc02.example.test", request.getHostname());
    assertEquals("Data", request.getShareName());
    assertEquals("users\\member", request.getPath());
  }

  @Test public void configuresKerberosForResolvedDfsTargetHost() {
    SmbPath requested = new SmbPath("dc02.example.test", "Data", "users\\member");
    SmbPath resolved = new SmbPath("files.other.test", "Profiles", "member");

    assertEquals(
        "files.other.test",
        KerberosSmbClient.resolvedTargetServiceHost(requested, resolved));
  }

  @Test public void retriesOnlyIoFailuresFromInitialConnect() {
    IOException networkFailure = new IOException("unreachable");
    IOException retryable = KerberosSmbClient.bootstrapConnectFailure(networkFailure);

    assertTrue(retryable instanceof KerberosSmbClient.RetryableBootstrapException);
    assertSame(networkFailure, retryable.getCause());

    RuntimeException programmingFailure = new IllegalStateException("sensitive");
    IOException mapped = KerberosSmbClient.bootstrapConnectFailure(programmingFailure);

    assertFalse(mapped instanceof KerberosSmbClient.RetryableBootstrapException);
    assertEquals(
        "Kerberos sign-in to the share failed (IllegalStateException)", mapped.getMessage());
    assertSame(programmingFailure, mapped.getCause());
  }

  @Test public void retriesNetworkFailureBeforeSessionEstablishment() {
    assertTrue(KerberosSmbClient.shouldRetryBootstrap(new IOException("unreachable"), false));
    assertTrue(KerberosSmbClient.shouldRetryBootstrap(
        new RuntimeException(new IOException("connection dropped")), false));
    assertFalse(KerberosSmbClient.shouldRetryBootstrap(new IOException("access denied"), true));
  }

  @Test public void retriesUnknownServicePrincipalAfterConnecting() {
    GSSException gssException = new GSSException(GSSException.FAILURE, -1, null);
    gssException.initCause(new KrbException(7));

    assertTrue(KerberosSmbClient.shouldRetryBootstrap(gssException, true));
  }

  @Test public void stopsForOtherKerberosFailures() {
    GSSException gssException = new GSSException(GSSException.FAILURE, -1, null);
    gssException.initCause(new KrbException(6));

    assertFalse(KerberosSmbClient.shouldRetryBootstrap(gssException, true));
  }

  @Test public void triesNextBootstrapCandidateAfterRetryableFailure() throws Exception {
    List<String> attempts = new ArrayList<>();

    String selected = KerberosSmbClient.tryBootstrapCandidates(
        Arrays.asList("dc01.example.test", "dc02.example.test"),
        host -> {
          attempts.add(host);
          if (host.equals("dc01.example.test")) {
            throw new KerberosSmbClient.RetryableBootstrapException(
                new IOException("unreachable"));
          }
          return host;
        });

    assertEquals("dc02.example.test", selected);
    assertEquals(Arrays.asList("dc01.example.test", "dc02.example.test"), attempts);
  }

  @Test public void stopsBootstrapFailoverAfterNonRetryableFailure() {
    List<String> attempts = new ArrayList<>();

    IOException failure = assertThrows(
        IOException.class,
        () -> KerberosSmbClient.tryBootstrapCandidates(
            Arrays.asList("dc01.example.test", "dc02.example.test"),
            host -> {
              attempts.add(host);
              throw new IOException("access denied");
            }));

    assertEquals("access denied", failure.getMessage());
    assertEquals(Collections.singletonList("dc01.example.test"), attempts);
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

  @Test public void recognizesLazyDfsAuthenticationFailure() {
    NullPointerException exception = new NullPointerException("sensitive");
    exception.setStackTrace(new StackTraceElement[] {
        new StackTraceElement(
            "com.hierynomus.smbj.share.DiskShare",
            "getDiskEntry", "DiskShare.java", 212)
    });

    assertTrue(KerberosSmbClient.isLazyDfsAuthenticationFailure(exception));
  }
}
