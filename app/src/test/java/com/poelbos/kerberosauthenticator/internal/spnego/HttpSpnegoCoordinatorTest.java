package com.poelbos.kerberosauthenticator.internal.spnego;

import static com.google.common.truth.Truth.assertThat;

import com.hierynomus.asn1.types.primitive.ASN1ObjectIdentifier;
import com.hierynomus.ntlm.messages.NtlmNegotiateFlag;
import com.hierynomus.protocol.commons.buffer.Buffer;
import com.hierynomus.protocol.commons.buffer.Endian;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.spnego.NegTokenInit;
import com.hierynomus.spnego.NegTokenTarg;
import com.poelbos.kerberosauthenticator.internal.ntlm.HttpNtlmV2Engine;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Random;
import org.junit.Test;

public final class HttpSpnegoCoordinatorTest {
  private static final ASN1ObjectIdentifier KERBEROS =
      new ASN1ObjectIdentifier("1.2.840.113554.1.2.2");

  @Test
  public void initialOfferKeepsKerberosFirstAndAppendsNtlm() throws Exception {
    byte[] optimistic = new byte[] {10, 11, 12};
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(optimistic), true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com", "alex", "EXAMPLE.COM", "EXAMPLE", true, true, null, null);

    InspectableNegTokenInit offer = new InspectableNegTokenInit();
    offer.read(result.getToken());
    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.OK);
    assertThat(offer.getSupportedMechTypes())
        .containsExactly(KERBEROS, HttpNtlmV2Engine.NTLMSSP_OID)
        .inOrder();
    assertThat(offer.optimisticToken()).isEqualTo(optimistic);
    assertThat(result.getState().getPhase())
        .isEqualTo(SpnegoNegotiationState.Phase.OFFERED);
    assertThat(result.getState().getSelectedService()).isEqualTo("backend.example.com");
    assertThat(result.getState().wasNtlmOffered()).isTrue();
    assertThat(result.getSelectedService()).isEqualTo("backend.example.com");
    assertThat(result.getSelectedMechanism())
        .isEqualTo(SpnegoNegotiationState.Mechanism.UNSELECTED);
  }

  @Test
  public void disabledNtlmLeavesKerberosOfferUnchanged() throws Exception {
    byte[] optimistic = new byte[] {10, 11, 12};
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(optimistic), true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com", "alex", "EXAMPLE.COM", null, true, false, null, null);

    InspectableNegTokenInit offer = new InspectableNegTokenInit();
    offer.read(result.getToken());
    assertThat(offer.getSupportedMechTypes()).containsExactly(KERBEROS);
    assertThat(result.getState().wasNtlmOffered()).isFalse();
  }

  @Test
  public void establishedInitialKerberosTokenCanStillOfferNtlmWithoutContext() {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccessWithoutContext(), true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            true,
            true,
            null,
            null);

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.OK);
    assertThat(result.getState().getSelectedService()).isNull();
    assertThat(result.getState().getKerberosContext()).isNull();
    assertThat(result.getState().wasNtlmOffered()).isTrue();
  }

  @Test
  public void establishedInitialKerberosTokenWithoutNtlmKeepsContextlessState() {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccessWithoutContext(), true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            null,
            true,
            false,
            null,
            null);

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.OK);
    assertThat(result.getState().getSelectedService()).isNull();
    assertThat(result.getState().getKerberosContext()).isNull();
    assertThat(result.getState().wasNtlmOffered()).isFalse();
  }

  @Test
  public void kerberosFailureDoesNotStartNtlm() {
    HttpSpnegoCoordinator coordinator =
        coordinator(
            (host, incoming, context, selectedService) ->
                HttpSpnegoCoordinator.KerberosRound.failure("no service principal"),
            true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com", "alex", "EXAMPLE.COM", "EXAMPLE", true, true, null, null);

    assertThat(result.getStatus())
        .isEqualTo(HttpSpnegoResult.ERR_UNEXPECTED_SECURITY_LIBRARY_STATUS);
    assertThat(result.getToken()).isNull();
  }

  @Test
  public void explicitNtlmSelectionStartsType1Round() throws Exception {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(new byte[] {1}), true);
    SpnegoNegotiationState state =
        SpnegoNegotiationState.offered(
            "portal.example.com", "backend.example.com", new byte[] {2}, true);
    NegTokenTarg selection = new NegTokenTarg();
    selection.setSupportedMech(HttpNtlmV2Engine.NTLMSSP_OID);
    Buffer.PlainBuffer encoded = new Buffer.PlainBuffer(Endian.LE);
    selection.write(encoded);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            true,
            true,
            encoded.getCompactData(),
            state);

    byte[] type1 = new NegTokenTarg().read(result.getToken()).getResponseToken();
    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.OK);
    assertThat(Arrays.copyOf(type1, 8))
        .isEqualTo(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0});
    assertThat(result.getState().getPhase())
        .isEqualTo(SpnegoNegotiationState.Phase.NTLM_TYPE1_SENT);
  }

  @Test
  public void serverCannotSelectNtlmWhenCredentialsUnavailable() throws Exception {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(new byte[] {1}), false);
    NegTokenTarg selection = new NegTokenTarg();
    selection.setSupportedMech(HttpNtlmV2Engine.NTLMSSP_OID);
    Buffer.PlainBuffer encoded = new Buffer.PlainBuffer(Endian.LE);
    selection.write(encoded);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            true,
            true,
            encoded.getCompactData(),
            SpnegoNegotiationState.offered(
                "portal.example.com", "backend.example.com", new byte[] {2}, true));

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.ERR_MISSING_AUTH_CREDENTIALS);
  }

  @Test
  public void challengeAfterType3IsReportedAsRejectedCredentials() {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(new byte[] {1}), true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            true,
            true,
            new byte[] {1},
            SpnegoNegotiationState.ntlmType3Sent("portal.example.com"));

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.ERR_INVALID_AUTH_CREDENTIALS);
    assertThat(result.getToken()).isNull();
  }

  @Test
  public void ntlmOnlyInitialOfferDoesNotCallKerberos() throws Exception {
    int[] kerberosCalls = {0};
    HttpSpnegoCoordinator coordinator =
        coordinator(
            (host, incoming, context, selectedService) -> {
              kerberosCalls[0]++;
              return HttpSpnegoCoordinator.KerberosRound.failure("must not be called");
            },
            true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            false,
            true,
            null,
            null);

    InspectableNegTokenInit offer = new InspectableNegTokenInit();
    offer.read(result.getToken());
    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.OK);
    assertThat(kerberosCalls[0]).isEqualTo(0);
    assertThat(offer.getSupportedMechTypes()).containsExactly(HttpNtlmV2Engine.NTLMSSP_OID);
    assertThat(Arrays.copyOf(offer.optimisticToken(), 8))
        .isEqualTo(new byte[] {'N', 'T', 'L', 'M', 'S', 'S', 'P', 0});
    assertThat(result.getState().getMechanism())
        .isEqualTo(SpnegoNegotiationState.Mechanism.NTLM);
    assertThat(result.getState().getPhase())
        .isEqualTo(SpnegoNegotiationState.Phase.NTLM_TYPE1_SENT);
  }

  @Test
  public void allHttpMechanismsDisabledReturnsUnsupportedScheme() {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(new byte[] {1}), true);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            false,
            false,
            null,
            null);

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.ERR_UNSUPPORTED_AUTH_SCHEME);
    assertThat(result.getToken()).isNull();
  }

  @Test
  public void disablingSelectedMechanismDuringContinuationIsRejected() throws Exception {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(new byte[] {1}), true);
    NegTokenTarg continuation = new NegTokenTarg();
    continuation.setSupportedMech(KERBEROS);
    Buffer.PlainBuffer encoded = new Buffer.PlainBuffer(Endian.LE);
    continuation.write(encoded);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            false,
            true,
            encoded.getCompactData(),
            SpnegoNegotiationState.kerberos(
                "portal.example.com", "portal.example.com", new byte[] {1}));

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.ERR_UNSUPPORTED_AUTH_SCHEME);
  }

  @Test
  public void enablingNtlmDuringKerberosOnlyContinuationDoesNotPermitSelection() throws Exception {
    HttpSpnegoCoordinator coordinator = coordinator(kerberosSuccess(new byte[] {1}), true);
    NegTokenTarg selection = new NegTokenTarg();
    selection.setSupportedMech(HttpNtlmV2Engine.NTLMSSP_OID);
    Buffer.PlainBuffer encoded = new Buffer.PlainBuffer(Endian.LE);
    selection.write(encoded);

    HttpSpnegoResult result =
        coordinator.nextToken(
            "portal.example.com",
            "alex",
            "EXAMPLE.COM",
            "EXAMPLE",
            true,
            true,
            encoded.getCompactData(),
            SpnegoNegotiationState.offered(
                "portal.example.com", "backend.example.com", new byte[] {2}));

    assertThat(result.getStatus()).isEqualTo(HttpSpnegoResult.ERR_INVALID_RESPONSE);
    assertThat(result.getToken()).isNull();
  }

  private static HttpSpnegoCoordinator.KerberosProvider kerberosSuccess(byte[] optimistic) {
    return (host, incoming, context, selectedService) ->
        HttpSpnegoCoordinator.KerberosRound.success(
            initialKerberosToken(optimistic), new byte[] {42}, "backend.example.com");
  }

  private static HttpSpnegoCoordinator.KerberosProvider kerberosSuccessWithoutContext() {
    return (host, incoming, context, selectedService) ->
        HttpSpnegoCoordinator.KerberosRound.success(
            initialKerberosToken(new byte[] {1}), null, "backend.example.com");
  }

  private static HttpSpnegoCoordinator coordinator(
      HttpSpnegoCoordinator.KerberosProvider kerberos, boolean credentialsAvailable) {
    HttpNtlmV2Engine engine =
        new HttpNtlmV2Engine(
            new Random(1), () -> 0L, SmbConfig.createDefaultConfig().getSecurityProvider());
    return new HttpSpnegoCoordinator(
        kerberos,
        engine,
        new HttpSpnegoCoordinator.CredentialProvider() {
          @Override public boolean isAvailable(String username, String realm) {
            return credentialsAvailable;
          }

          @Override public char[] load(String username, String realm) {
            return credentialsAvailable ? "Password".toCharArray() : null;
          }
        });
  }

  private static byte[] initialKerberosToken(byte[] optimistic) {
    try {
      NegTokenInit init = new NegTokenInit();
      init.addSupportedMech(KERBEROS);
      init.setMechToken(optimistic);
      Buffer.PlainBuffer encoded = new Buffer.PlainBuffer(Endian.LE);
      init.write(encoded);
      return encoded.getCompactData();
    } catch (Exception error) {
      throw new AssertionError(error);
    }
  }

  private static final class InspectableNegTokenInit extends NegTokenInit {
    byte[] optimisticToken() { return mechToken; }
  }
}
